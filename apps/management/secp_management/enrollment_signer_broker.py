"""Root-gated controller-enrollment offer SIGNER BROKER (SECP-PR5H-B1, Phase 3).

The privileged boundary that lets the NON-ROOT controller API obtain an internally-signed controller
offer WITHOUT ever reaching the enrollment private key, running as root, or gaining a generic
signing capability. It is a root-owned service listening on a FIXED, code-owned Unix-domain socket
(no TCP
listener, path not caller-configurable) that:

* verifies the connecting peer's kernel credentials (``SO_PEERCRED``) against a fixed NON-ROOT
  API uid/gid allowlist and refuses everyone else, closed;
* accepts ONE bounded operation only — sign one authorized controller-enrollment offer — with a
  strict request/response and bounded byte limits (no generic bytes/digest/domain/kind/path signing,
  no shell/subprocess, no provider op, no arbitrary filesystem read);
* independently CONSTRUCTS the live signing lease (it never trusts a lease or a signer key id from
  the caller) via the injected :class:`ActiveControllerSigningIdentityProvider`, and
* re-verifies its own generated attestation before returning it.

It lives in the MANAGEMENT plane: it may compose the commissioning-plane signer + hardened
filesystem reader and the least-privilege DB identity provider, but it NEVER imports ``secp_api``
and the API never imports it — the two planes speak only this pure JSON contract over the socket.
Every
failure is a bounded reason code; no private material, peer identity, path, or raw exception ever
enters a response, log, or repr.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Protocol

from secp_commissioning.controller_enrollment_signer import (
    AuthorizedControllerOfferContext,
    ControllerEnrollmentSignerError,
    SignedControllerOffer,
)
from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    OFFER_KIND,
    AttestationError,
    claim_digest,
    verify_detached,
)

from secp_management import ManagementError

#: The fixed, code-owned socket location. Root owns the directory; the socket is group-readable by
#: the API's service group only. NOT caller-configurable and NOT a TCP endpoint.
ENROLLMENT_SIGNER_SOCKET_DIR = "/run/secp"
ENROLLMENT_SIGNER_SOCKET_PATH = "/run/secp/enrollment-signer.sock"

_MAX_REQUEST_BYTES = 8192
_MAX_RESPONSE_BYTES = 16384
_CONN_TIMEOUT_SECONDS = 5.0
_BACKLOG = 8

# The wire request's ``context`` carries EXACTLY the AuthorizedControllerOfferContext fields, so the
# API client and the broker cannot drift: both derive the field set from the SHARED dataclass (the
# API imports the same class from the commissioning plane). All PUBLIC material — no secrets.
_CONTEXT_FIELDS = tuple(f.name for f in dataclasses.fields(AuthorizedControllerOfferContext))


class _OfferSigner(Protocol):
    """The one capability the broker invokes: sign one authorized controller offer. Satisfied by the
    commissioning-plane :class:`ControllerEnrollmentOfferSigner` and its sealed default."""

    def sign_offer(
        self, context: AuthorizedControllerOfferContext, *, now: str
    ) -> SignedControllerOffer: ...


class EnrollmentSignerBrokerError(ManagementError):
    """A bounded, closed broker refusal — carries ONLY a reason code, never a peer identity, path,
    request body, private material, or raw exception."""


@dataclass(frozen=True)
class PeerCredentials:
    """The connecting peer's kernel-reported credentials (``SO_PEERCRED``)."""

    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class PeerCredentialPolicy:
    """A fixed NON-ROOT allowlist of API uid/gid pairs permitted to request a signature. Root is
    deliberately NOT allowlistable — the caller is the non-root API service, never root."""

    allowed_uids: tuple[int, ...]
    allowed_gids: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.allowed_uids or not self.allowed_gids:
            raise EnrollmentSignerBrokerError("enrollment_signer_peer_policy_empty")
        if any(u <= 0 for u in self.allowed_uids) or any(g <= 0 for g in self.allowed_gids):
            raise EnrollmentSignerBrokerError("enrollment_signer_peer_policy_root_forbidden")

    def authorize(self, creds: PeerCredentials) -> None:
        if creds.uid not in self.allowed_uids or creds.gid not in self.allowed_gids:
            raise EnrollmentSignerBrokerError("enrollment_signer_peer_unauthorized")


def read_peer_credentials(conn: object) -> PeerCredentials:
    """Read the connected peer's ``SO_PEERCRED`` (Linux). Any failure (non-Linux, closed socket)
    is a bounded closed refusal — the broker never signs for an unidentifiable peer."""
    import socket
    import struct

    try:
        so_peercred = getattr(socket, "SO_PEERCRED")  # noqa: B009 - Linux-only; raises off-Linux
        raw = conn.getsockopt(  # type: ignore[attr-defined]
            socket.SOL_SOCKET, so_peercred, struct.calcsize("iII")
        )
        pid, uid, gid = struct.unpack("iII", raw)
    except (OSError, AttributeError, struct.error):
        raise EnrollmentSignerBrokerError(
            "enrollment_signer_peer_credentials_unavailable"
        ) from None
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def _attestation_payload(offer: SignedControllerOffer) -> dict:
    att = offer.attestation
    return {
        "claim": offer.claim,
        "attestation": {
            "algorithm": att.algorithm,
            "key_id": att.key_id,
            "public_key_hex": att.public_key_hex,
            "signature": att.signature,
        },
    }


class EnrollmentSignerBroker:
    """The bounded one-operation broker. Holds the composed signer (which owns the hardened key
    reader + the live identity lease) and the peer-credential policy; every connection is one
    authorize -> read bounded request -> sign under the live lease -> self-verify -> respond."""

    __slots__ = ("_signer", "_peer_policy", "_peer_reader", "_max_request_bytes")

    def __init__(
        self,
        *,
        signer: _OfferSigner,
        peer_policy: PeerCredentialPolicy,
        peer_reader=read_peer_credentials,
        max_request_bytes: int = _MAX_REQUEST_BYTES,
    ) -> None:
        self._signer = signer
        self._peer_policy = peer_policy
        self._peer_reader = peer_reader
        self._max_request_bytes = max_request_bytes

    def __repr__(self) -> str:
        return "EnrollmentSignerBroker(<redacted>)"

    def handle_connection(self, conn: object) -> None:
        """Serve exactly one request on ``conn`` and always write a bounded response. Never raises
        to the caller and never leaks: every failure collapses to ``{"error": <bounded code>}``."""
        try:
            self._peer_policy.authorize(self._peer_reader(conn))
            offer = self._sign_request(_recv_all(conn, self._max_request_bytes))
            payload: dict = {"offer": _attestation_payload(offer)}
        except (EnrollmentSignerBrokerError, ControllerEnrollmentSignerError) as exc:
            payload = {"error": exc.reason_code}
        except Exception:  # noqa: BLE001 - any unexpected failure is a bounded closed refusal
            payload = {"error": "internal"}
        _send(conn, payload)

    def _sign_request(self, raw: bytes) -> SignedControllerOffer:
        try:
            request = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            raise EnrollmentSignerBrokerError("enrollment_signer_request_invalid") from None
        if not isinstance(request, dict) or request.get("op") != "sign_offer":
            raise EnrollmentSignerBrokerError("enrollment_signer_request_invalid")
        now = request.get("now")
        context_fields = request.get("context")
        if (
            not isinstance(now, str)
            or not isinstance(context_fields, dict)
            or set(context_fields) != set(_CONTEXT_FIELDS)
        ):
            raise EnrollmentSignerBrokerError("enrollment_signer_request_invalid")
        # reconstruction RE-VALIDATES every field (strict grammar / digest shape) before the signer
        # reads the key; a bad field is a bounded controller_enrollment_offer_invalid.
        context = AuthorizedControllerOfferContext(
            **{name: context_fields[name] for name in _CONTEXT_FIELDS}
        )
        # the signer independently constructs + holds the LIVE identity lease; the caller supplies
        # neither a lease nor a signer key id (context.controller_* is cross-checked against it).
        offer = self._signer.sign_offer(context, now=now)
        self._self_verify(offer)
        return offer

    def _self_verify(self, offer: SignedControllerOffer) -> None:
        try:
            verify_detached(
                offer.attestation,
                expected_key_id=offer.claim["controller_key_id"],
                domain=ENROLLMENT_ATTESTATION_DOMAIN,
                kind=OFFER_KIND,
                digest=claim_digest(offer.claim),
            )
        except (AttestationError, KeyError):
            raise EnrollmentSignerBrokerError(
                "controller_enrollment_offer_self_verify_failed"
            ) from None

    def serve_forever(self, listener: object) -> None:  # pragma: no cover - production accept loop
        while True:
            conn, _ = listener.accept()  # type: ignore[attr-defined]
            try:
                conn.settimeout(_CONN_TIMEOUT_SECONDS)
                self.handle_connection(conn)
            finally:
                conn.close()


def _recv_all(conn: object, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = conn.recv(4096)  # type: ignore[attr-defined]
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise EnrollmentSignerBrokerError("enrollment_signer_request_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _send(conn: object, payload: dict) -> None:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    if len(data) > _MAX_RESPONSE_BYTES:  # our own response; bounded by construction
        data = json.dumps({"error": "internal"}).encode("utf-8")
    try:
        conn.sendall(data)  # type: ignore[attr-defined]
    except OSError:
        pass


# ------------------------------------------------------------ hardened socket + composition


def _assert_root_owned_dir(path: str) -> None:
    import os
    import stat

    try:
        st = os.lstat(path)
    except OSError:
        raise EnrollmentSignerBrokerError("enrollment_signer_socket_dir_unsafe") from None
    if (
        not stat.S_ISDIR(st.st_mode)
        or stat.S_ISLNK(st.st_mode)
        or st.st_uid != 0
        or st.st_gid != 0
        or (st.st_mode & 0o022)  # no group/other write on the socket's parent
    ):
        raise EnrollmentSignerBrokerError("enrollment_signer_socket_dir_unsafe")


def bind_broker_socket(*, socket_group_gid: int, path: str = ENROLLMENT_SIGNER_SOCKET_PATH):
    """Create the fixed broker socket under a validated root-owned directory (root-only, prod).
    The parent dir must be a real, root-owned, non-group/other-writable directory (never a symlink);
    a pre-existing path is removed ONLY when it is a root-owned socket; the bound socket is
    ``root:<api-group>`` mode ``0o660`` so only the API service group can connect."""
    import os
    import socket
    import stat

    _assert_root_owned_dir(os.path.dirname(path))
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != 0:
            raise EnrollmentSignerBrokerError("enrollment_signer_socket_path_unsafe")
        os.unlink(path)
    af_unix = getattr(socket, "AF_UNIX")  # noqa: B009 - POSIX only; no TCP family, ever
    sock = socket.socket(af_unix, socket.SOCK_STREAM)
    sock.bind(path)
    os.chmod(path, 0o660)
    getattr(os, "chown")(path, 0, socket_group_gid)  # noqa: B009 - POSIX only; root:<api-group>
    sock.listen(_BACKLOG)
    return sock


def build_production_broker(
    *, engine: object, allowed_uids: tuple[int, ...], allowed_gids: tuple[int, ...]
) -> EnrollmentSignerBroker:
    """Compose the production broker (root only): the hardened root-controlled filesystem key reader
    + the DB least-privilege ACTIVE-identity lease provider + the commissioning-plane offer signer,
    behind the fixed non-root peer-credential allowlist. Constructing the RealFilesystem refuses
    off-POSIX, so this can never be built in a non-root/dev context by accident."""
    from secp_commissioning.controller_enrollment_signer import ControllerEnrollmentOfferSigner
    from secp_commissioning.runtime import RealFilesystem

    from secp_management.enrollment_signer_identity import (
        DbActiveControllerSigningIdentityProvider,
    )

    signer = ControllerEnrollmentOfferSigner(
        RealFilesystem(),
        DbActiveControllerSigningIdentityProvider(engine),  # type: ignore[arg-type]
    )
    policy = PeerCredentialPolicy(allowed_uids=allowed_uids, allowed_gids=allowed_gids)
    return EnrollmentSignerBroker(signer=signer, peer_policy=policy)


__all__ = [
    "ENROLLMENT_SIGNER_SOCKET_DIR",
    "ENROLLMENT_SIGNER_SOCKET_PATH",
    "EnrollmentSignerBroker",
    "EnrollmentSignerBrokerError",
    "PeerCredentialPolicy",
    "PeerCredentials",
    "bind_broker_socket",
    "build_production_broker",
    "read_peer_credentials",
]
