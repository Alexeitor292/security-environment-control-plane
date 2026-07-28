"""API-side client for the root-gated controller-enrollment offer signer broker (SECP-PR5H-B1).

The NON-ROOT controller API never holds the enrollment private key, never runs as root, and never
instantiates the concrete root filesystem signer. To obtain an internally-signed controller offer it
speaks a pure JSON contract to the root broker over its FIXED Unix-domain socket. This module is
that client seam:

* :class:`EnrollmentOfferSignerClient` — the Protocol the enrollment service depends on (satisfied
  structurally by the concrete UDS client AND, in tests, by an in-process signer);
* :class:`SealedEnrollmentOfferSignerClient` — the SHIPPED DEFAULT: every attempt fails closed with
  ``enrollment_signer_unavailable`` (the exchange is sealed by the ABSENCE of a wired signer);
* :class:`UnixSocketEnrollmentOfferSignerClient` — the concrete client, bound to a FIXED socket path
  at construction (no per-call override, no ambient proxy/env networking, no TCP);
* :func:`build_enrollment_offer_signer` — the production composition that returns the UDS client
  ONLY when the reviewed deployment contract (a configured broker socket path) holds, else sealed.

The wire request's ``context`` carries EXACTLY the shared :class:`AuthorizedControllerOfferContext`
fields, so this client and the broker can never drift. The client is redacted and non-serializable,
and it collapses every failure (unreachable / timeout / bounded broker error / malformed response)
to a single ``enrollment_signer_unavailable`` — it never leaks the socket path, a broker code, or a
raw exception. The service still independently re-verifies the returned offer.
"""

from __future__ import annotations

import dataclasses
import json
import socket
from typing import NoReturn, Protocol

from secp_commissioning.controller_enrollment_signer import (
    ENROLLMENT_SIGNER_SOCKET_PATH,
    AuthorizedControllerOfferContext,
    SignedControllerOffer,
)
from secp_commissioning.enrollment_attestation import DetachedAttestation

from secp_api.enrollment_signer_binding import (
    EnrollmentSignerRuntimeBinding,
    marker_matches_binding,
)
from secp_api.enrollment_signer_marker import MARKER_PATH, load_valid_marker
from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError

_CONTEXT_FIELDS = tuple(f.name for f in dataclasses.fields(AuthorizedControllerOfferContext))
_MAX_RESPONSE_BYTES = 16384
_DEFAULT_TIMEOUT = 5.0


class EnrollmentOfferSignerClient(Protocol):
    """The single capability the enrollment service depends on: obtain a signed controller offer for
    an authorized context. The service builds the context from authoritative state and re-verifies
    the returned offer; it never learns the socket path or the signer key material."""

    def sign_offer(
        self, context: AuthorizedControllerOfferContext, *, now: str
    ) -> SignedControllerOffer: ...


class _NonSerializable:
    """Refuses every serialization/copy path so a signer client can never be pickled or asdict-ed
    into a log, plan, event or audit record."""

    def __reduce__(self) -> NoReturn:
        raise WorkerEnrollmentError(EC.signer_unavailable)

    def __getstate__(self) -> NoReturn:
        raise WorkerEnrollmentError(EC.signer_unavailable)


class SealedEnrollmentOfferSignerClient(_NonSerializable):
    """The shipped default: no broker is wired, so every sign attempt fails closed. The
    evidence-driven exchange stays sealed by the ABSENCE of a real signer client."""

    def __repr__(self) -> str:
        return "SealedEnrollmentOfferSignerClient(<sealed>)"

    def sign_offer(
        self, context: AuthorizedControllerOfferContext, *, now: str
    ) -> SignedControllerOffer:
        raise WorkerEnrollmentError(EC.signer_unavailable)


def _parse_offer_response(payload: object) -> SignedControllerOffer:
    """Reconstruct a :class:`SignedControllerOffer` from a broker response, or fail closed. A
    bounded broker ``{"error": ...}`` and any malformed/oversized/short response all collapse to
    ``enrollment_signer_unavailable`` — the broker's internal code is never surfaced."""
    if not isinstance(payload, dict) or not isinstance(payload.get("offer"), dict):
        raise WorkerEnrollmentError(EC.signer_unavailable)
    offer = payload["offer"]
    claim = offer.get("claim")
    att = offer.get("attestation")
    if not isinstance(claim, dict) or not isinstance(att, dict):
        raise WorkerEnrollmentError(EC.signer_unavailable)
    try:
        attestation = DetachedAttestation(
            algorithm=att["algorithm"],
            key_id=att["key_id"],
            public_key_hex=att["public_key_hex"],
            signature=att["signature"],
        )
    except (KeyError, TypeError):
        raise WorkerEnrollmentError(EC.signer_unavailable) from None
    return SignedControllerOffer(claim=claim, attestation=attestation)


class UnixSocketEnrollmentOfferSignerClient(_NonSerializable):
    """Concrete client bound to the ONE FIXED, code-owned broker socket
    (``ENROLLMENT_SIGNER_SOCKET_PATH``). It takes NO socket/path argument — there is no
    per-instance, per-call, config, env, or descriptor way to point it at a different local socket
    (C5). It uses ONLY a Unix-domain stream socket (no TCP, no ambient proxy/env), enforces bounded
    deadlines and a bounded response, and never leaks the path or a raw exception."""

    __slots__ = ("_socket_path", "_timeout")

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        # the location is a code constant, never a caller/config/env input — read it here so a test
        # double may patch the module constant, but no production surface can select a path.
        self._socket_path = ENROLLMENT_SIGNER_SOCKET_PATH
        self._timeout = timeout

    def __repr__(self) -> str:  # never the socket path
        return "UnixSocketEnrollmentOfferSignerClient(<redacted>)"

    def sign_offer(
        self, context: AuthorizedControllerOfferContext, *, now: str
    ) -> SignedControllerOffer:
        request = {
            "op": "sign_offer",
            "now": now,
            "context": {name: getattr(context, name) for name in _CONTEXT_FIELDS},
        }
        raw = self._roundtrip(
            json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001 - a malformed response is a bounded closed refusal
            raise WorkerEnrollmentError(EC.signer_unavailable) from None
        return _parse_offer_response(payload)

    def _roundtrip(self, request: bytes) -> bytes:
        sock = None
        try:
            af_unix = getattr(socket, "AF_UNIX")  # noqa: B009 - POSIX only; AttributeError elsewhere
            sock = socket.socket(af_unix, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect(self._socket_path)
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_RESPONSE_BYTES:
                    raise WorkerEnrollmentError(EC.signer_unavailable)
                chunks.append(chunk)
            return b"".join(chunks)
        except WorkerEnrollmentError:
            raise
        except Exception:  # noqa: BLE001 - no AF_UNIX / unreachable / timeout all fail closed
            raise WorkerEnrollmentError(EC.signer_unavailable) from None
        finally:
            if sock is not None:
                sock.close()


def build_enrollment_offer_signer(
    settings: object,
    *,
    runtime_binding: EnrollmentSignerRuntimeBinding | None = None,
    marker_path: str = MARKER_PATH,
) -> EnrollmentOfferSignerClient:
    """Production composition: return the fixed-UDS client (bound to the code-owned
    ``ENROLLMENT_SIGNER_SOCKET_PATH``) ONLY when the deployment ENABLES it; otherwise the sealed
    default. Production may never select the socket or key location (C5), and — SECP-PR5H-B2 — in
    PRODUCTION the SOLE positive enabling authority is the root-owned enablement MARKER whose
    complete binding EXACTLY equals the authoritative ``runtime_binding`` (built from the verified
    active identity + process + fixed contracts + CA digest): no environment variable / Compose
    value / database field / HTTP request can enable the signer, and an absent / unsafe / malformed
    marker, an unavailable binding, or ANY binding mismatch (stale release / identity / key /
    installation /
    uid-gid / role / UDS / CA) keeps it sealed. Off production (dev/test) the env flag enables, for
    compatibility only. (``marker_path`` is overridable only for the tests.)"""
    if bool(getattr(settings, "is_production", False)):
        marker = load_valid_marker(path=marker_path)
        if (
            marker is None
            or runtime_binding is None
            or not marker_matches_binding(marker, runtime_binding)
        ):
            return (
                SealedEnrollmentOfferSignerClient()
            )  # marker + exact binding are the sole authority
        return UnixSocketEnrollmentOfferSignerClient()
    if not bool(getattr(settings, "enrollment_signer_enabled", False)):
        return SealedEnrollmentOfferSignerClient()
    return UnixSocketEnrollmentOfferSignerClient()


__all__ = [
    "EnrollmentOfferSignerClient",
    "SealedEnrollmentOfferSignerClient",
    "UnixSocketEnrollmentOfferSignerClient",
    "build_enrollment_offer_signer",
]
