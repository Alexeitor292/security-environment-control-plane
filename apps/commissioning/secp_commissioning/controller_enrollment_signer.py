"""Root-gated controller enrollment offer signer (SECP-PR5H-B1, Phase 2 + signer review S1-S4).

The controller's dedicated ENROLLMENT key — separate from the management-evidence, release-signing,
admission-TLS, provider and operator keys — signs the canonical ControllerOffer that will unseal the
authenticated worker exchange. The signer lives in the commissioning plane: it owns BOTH the
hardened root-controlled filesystem reader (``secp_commissioning.runtime`` trusted-dirfd /
no-symlink / ownership / mode / hard-link protections) AND the pure Ed25519 primitive
(``secp_commissioning.enrollment_attestation``). It is injected into the API through a sealed
dependency seam; it imports NO API persistence, and the API never touches the private key.

Security posture (review S1-S4):

* S1 — the signing input is a STRICT, validated :class:`AuthorizedControllerOfferContext`: every
  field's grammar / digest shape / canonical-UTC form / bound is proven on construction, and
  secret-like / path-shaped / control-character values are refused, BEFORE the private key is ever
  read. The signer never signs a caller-assembled bag of strings.
* S2 — the ACTIVE controller identity is proven at SIGN time through an injected
  :class:`ActiveControllerSigningIdentityProvider` lease held across signing (a superseded / revoked
  / unverified / ambiguous / absent / changed identity refuses); the loaded key is validated against
  the LIVE lease identity, never a cached snapshot.
* S3 — the key is a SINGLE atomic root-owned file: all public material is DERIVED from it, so there
  is no two-file atomicity gap. Preparation creates-or-adopts with read-back verification and
  receipt-matched compensation; rotation is a recoverable atomic replace — never delete-then-create.
* S4 — the signer representation is a constant ``<redacted>``: no key id, anchor, proof id, digest,
  path or private material appears in any repr / log / exception / serialization.
"""

from __future__ import annotations

import re
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NoReturn, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secp_commissioning.canonical import is_sha256_digest
from secp_commissioning.descriptor import scan_forbidden
from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    OFFER_KIND,
    DetachedAttestation,
    claim_digest,
    controller_offer_claim,
    enrollment_key_proof_id_for,
    key_id_for,
    sign_detached,
)
from secp_commissioning.errors import CommissioningError
from secp_commissioning.runtime import FilesystemBackend, FilesystemError

#: The fixed, code-owned on-disk location for the dedicated controller enrollment key — a single
#: atomic root-owned file (all public material is derived from it), a sibling of the management
#: evidence key under the bootstrap-state root with a DISTINCT filename so it never overlaps the
#: evidence / release / admission / provider / operator key material.
CONTROLLER_ENROLLMENT_KEY_PATH = "/var/lib/secp/bootstrap/controller-enrollment-signing.key"

#: The fixed, code-owned runtime location of the root-gated signer broker's Unix-domain socket. It
#: is a single code constant shared by ALL three participants — the broker that binds it, the
#: systemd unit that provisions its ``RuntimeDirectory``, and the NON-ROOT API client that connects
#: to it — so the two planes can never drift AND a deployment can never redirect the trusted client
#: to another local socket. It is NEVER a config / env / HTTP / constructor input; production may
#: only enable or disable the client. There is no TCP endpoint. This constant lives in the
#: commissioning plane precisely because it is the ONE module both the API plane and the management
#: plane may import (the API plane may not import the management-plane broker).
ENROLLMENT_SIGNER_SOCKET_DIR = "/run/secp"
ENROLLMENT_SIGNER_SOCKET_PATH = "/run/secp/enrollment-signer.sock"

_KEY_MODE = 0o600
_MAX_KEY_BYTES = 1024
_MAX_FIELD_LEN = 512
_MAX_TS_LEN = 40
_MAX_ORIGIN_LEN = 269
_RAW = serialization.Encoding.Raw
_PUBLIC = serialization.PublicFormat.Raw
_PRIVATE = serialization.PrivateFormat.Raw
_NO_ENCRYPTION = serialization.NoEncryption()

# Grammars mirrored (never imported — commissioning may not depend on the API) from the enrollment
# contract, so the API's authoritative persisted values pass and nothing looser is accepted.
_INSTALLATION_ID = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")
_HTTPS_ORIGIN = re.compile(r"https://[a-z0-9.-]{1,253}(?::[1-9][0-9]{0,4})?")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_TRUST_ANCHOR_HEX = re.compile(r"[0-9a-f]{64}")
_ENRKP_PROOF_ID = re.compile(r"enrkp:[0-9a-f]{64}")


class ControllerEnrollmentSignerError(CommissioningError):
    """A bounded, closed controller-enrollment-signer refusal — carries ONLY a reason code, never
    the private key, a path, an identity value or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise ControllerEnrollmentSignerError(reason_code)


# --------------------------------------------------------------------------- S1: strict input


class _NonSerializable:
    """Refuses every serialization/copy path — an object that can carry the private key or the live
    identity can never be pickled, copied, or asdict-ed into a log, plan, event or audit record."""

    def __reduce__(self) -> NoReturn:
        _reject("controller_enrollment_signer_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("controller_enrollment_signer_not_serializable")


def _no_control(value: str) -> None:
    if _CONTROL.search(value):
        _reject("controller_enrollment_offer_invalid")


def _v_digest(value: object) -> None:
    if not is_sha256_digest(value):
        _reject("controller_enrollment_offer_invalid")


def _v_installation(value: object) -> None:
    if not isinstance(value, str) or not _INSTALLATION_ID.fullmatch(value):
        _reject("controller_enrollment_offer_invalid")


def _v_origin(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_ORIGIN_LEN
        or not _HTTPS_ORIGIN.fullmatch(value)
    ):
        _reject("controller_enrollment_offer_invalid")
    _no_control(value)


def _v_bounded(value: object) -> None:
    if not isinstance(value, str) or not (1 <= len(value) <= _MAX_FIELD_LEN):
        _reject("controller_enrollment_offer_invalid")
    _no_control(value)


def _v_timestamp(value: object) -> datetime:
    parsed = _parse_utc(value)
    if parsed is None:
        _reject("controller_enrollment_offer_invalid")
    return parsed


def _parse_utc(value: object) -> datetime | None:
    """Canonical explicit-UTC parse: a string no longer than ``MAX_TS_LEN`` with an explicit
    zero UTC offset. Anything else (naive, non-UTC, oversized, malformed) is None."""
    if not isinstance(value, str) or not (1 <= len(value) <= _MAX_TS_LEN):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed


@dataclass(frozen=True)
class AuthorizedControllerOfferContext:
    """A STRICT, validated offer context. Construction proves every field's grammar / digest shape /
    canonical form / bound and refuses secret-like / path-shaped / control-character values BEFORE a
    signer can read the private key — so the signer never signs a caller-assembled bag of strings.
    The API builds this ONLY from authoritative persisted data (invitation row, locked enrollment
    head, verified worker binding, active controller identity, current release, predecessor)."""

    enrollment_id: str
    invitation_id: str
    controller_installation_id: str
    controller_key_id: str
    controller_origin: str
    controller_transaction_id: str
    worker_installation_id: str
    worker_key_id: str
    release_digest: str
    expires_at: str
    predecessor_digest: str

    def __post_init__(self) -> None:
        _v_digest(self.enrollment_id)
        _v_digest(self.invitation_id)
        _v_installation(self.controller_installation_id)
        _v_digest(self.controller_key_id)
        _v_origin(self.controller_origin)
        _v_bounded(self.controller_transaction_id)
        _v_installation(self.worker_installation_id)
        _v_digest(self.worker_key_id)
        _v_digest(self.release_digest)
        _v_timestamp(self.expires_at)
        _v_digest(self.predecessor_digest)
        # a final secret-like / secret-shaped scan over the whole bounded field set
        try:
            scan_forbidden(
                {
                    "enrollment_id": self.enrollment_id,
                    "invitation_id": self.invitation_id,
                    "controller_installation_id": self.controller_installation_id,
                    "controller_key_id": self.controller_key_id,
                    "controller_origin": self.controller_origin,
                    "controller_transaction_id": self.controller_transaction_id,
                    "worker_installation_id": self.worker_installation_id,
                    "worker_key_id": self.worker_key_id,
                    "release_digest": self.release_digest,
                    "expires_at": self.expires_at,
                    "predecessor_digest": self.predecessor_digest,
                }
            )
        except Exception:  # noqa: BLE001 - any secret-shaped input is a bounded refusal
            _reject("controller_enrollment_offer_invalid")


# --------------------------------------------------------------------------- S2: live signing lease


def _v_anchor(value: object) -> None:
    if not isinstance(value, str) or not _TRUST_ANCHOR_HEX.fullmatch(value):
        _reject("controller_enrollment_identity_malformed")


def _v_proof_id(value: object) -> None:
    if not isinstance(value, str) or not _ENRKP_PROOF_ID.fullmatch(value):
        _reject("controller_enrollment_identity_malformed")


def _v_bounded_identity(value: object) -> None:
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= _MAX_FIELD_LEN)
        or _CONTROL.search(value)
    ):
        _reject("controller_enrollment_identity_malformed")


@dataclass(frozen=True, repr=False)
class SigningIdentityLease(_NonSerializable):
    """The authoritative ACTIVE controller identity observed under a HELD lock at sign time, plus an
    immutable per-activation rotation token. The signer validates the loaded key against THIS live
    identity — never a cached snapshot — so a signer that outlived rotation cannot keep signing.

    It is a STRICT validated type: construction proves each field's grammar / digest shape and
    refuses a malformed / control-character value (a corrupt identity row can never yield a usable
    lease). Its repr is a constant ``<redacted>`` and it refuses every serialization/copy path, so
    identity material never lands in a log, plan, event, audit record or pickle."""

    row_id: str
    activation_token: str  # immutable per-activation token (row id + activated_at + generation)
    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    management_identity_digest: str
    bootstrap_evidence_digest: str
    enrollment_key_proof_id: str

    def __post_init__(self) -> None:
        _v_bounded_identity(self.row_id)
        _v_bounded_identity(self.activation_token)
        _v_installation(self.controller_installation_id)
        _v_digest(self.controller_key_id)
        _v_anchor(self.controller_trust_anchor_hex)
        _v_origin(self.controller_origin)
        _v_digest(self.release_digest)
        _v_digest(self.management_identity_digest)
        _v_digest(self.bootstrap_evidence_digest)
        _v_proof_id(self.enrollment_key_proof_id)

    def __repr__(self) -> str:  # constant — never a key id / anchor / origin / proof id / token
        return "SigningIdentityLease(<redacted>)"


class ActiveControllerSigningIdentityProvider(Protocol):
    """Acquires the authoritative ACTIVE controller identity under a held identity/enrollment lock
    for the duration of ONE signing operation. The production adapter (wired by the API composition,
    NOT this plane) opens a locked transaction, re-reads the single verified ACTIVE row, and refuses
    a missing / ambiguous / superseded / revoked / unverified / malformed / changed identity."""

    def lease(self) -> AbstractContextManager[SigningIdentityLease]: ...


class SealedControllerEnrollmentSigner(_NonSerializable):
    """The shipped default: no root-gated controller enrollment signer is activated. Every attempt
    fails closed — the evidence-driven exchange stays sealed by the ABSENCE of a real signer until
    the root-gated bootstrap injects the concrete one at deploy time."""

    def __repr__(self) -> str:
        return "SealedControllerEnrollmentSigner(<sealed>)"

    def sign_offer(
        self, context: AuthorizedControllerOfferContext, *, now: str
    ) -> SignedControllerOffer:
        _reject("controller_enrollment_signer_unavailable")


@dataclass(frozen=True)
class SignedControllerOffer:
    """The controller-signed offer the worker verifies against the invitation's pinned controller
    key: the canonical claim plus its detached Ed25519 attestation. No private material."""

    claim: dict[str, str]
    attestation: DetachedAttestation


class ControllerEnrollmentOfferSigner(_NonSerializable):
    """Signs a controller offer with the dedicated enrollment key. On EVERY sign it (1) validates
    the ``now`` timestamp, (2) acquires the LIVE active-identity lease and holds it across signing,
    (3) cross-checks the authorized context's identity-bound fields against that live identity,
    (4) checks expiry, (5) re-reads + re-validates the root-owned key against the LIVE identity
    (caching no private material), and only then (6) mints + signs the offer. A superseded / revoked
    / unverified / ambiguous / absent / changed identity, a key that derives a historical (not the
    current) identity, or an expired / cross-bound offer, refuses closed BEFORE signing."""

    __slots__ = ("_fs", "_identity_provider")

    def __init__(
        self, fs: FilesystemBackend, identity_provider: ActiveControllerSigningIdentityProvider
    ) -> None:
        self._fs = fs
        self._identity_provider = identity_provider

    def __repr__(self) -> str:  # S4: constant — no key id / anchor / proof id / digest / path
        return "ControllerEnrollmentOfferSigner(<redacted>)"

    def sign_offer(
        self, context: AuthorizedControllerOfferContext, *, now: str
    ) -> SignedControllerOffer:
        now_ts = _v_timestamp(now)
        expires_ts = _parse_utc(context.expires_at)
        # the lease is acquired and HELD across signing (the adapter holds the DB identity lock). A
        # bounded provider refusal propagates; any unexpected provider failure fails closed.
        try:
            with self._identity_provider.lease() as lease:
                return self._sign_under_lease(context, lease, now_ts, expires_ts)
        except ControllerEnrollmentSignerError:
            raise
        except Exception:  # noqa: BLE001 - a provider failure is a bounded closed refusal
            _reject("controller_enrollment_identity_unavailable")

    def _sign_under_lease(
        self,
        context: AuthorizedControllerOfferContext,
        lease: SigningIdentityLease,
        now_ts: datetime,
        expires_ts: datetime | None,
    ) -> SignedControllerOffer:
        if context.controller_key_id != lease.controller_key_id:
            _reject("controller_enrollment_offer_cross_key")
        if context.controller_installation_id != lease.controller_installation_id:
            _reject("controller_enrollment_offer_cross_installation")
        if context.controller_origin != lease.controller_origin:
            _reject("controller_enrollment_offer_cross_origin")
        if context.release_digest != lease.release_digest:
            _reject("controller_enrollment_offer_cross_release")
        if expires_ts is None or expires_ts <= now_ts:
            _reject("controller_enrollment_offer_expired")
        private_hex = _load_validated_key(self._fs, lease)
        claim = controller_offer_claim(
            enrollment_id=context.enrollment_id,
            invitation_id=context.invitation_id,
            controller_installation_id=lease.controller_installation_id,
            controller_key_id=lease.controller_key_id,
            controller_origin=lease.controller_origin,
            controller_transaction_id=context.controller_transaction_id,
            worker_installation_id=context.worker_installation_id,
            worker_key_id=context.worker_key_id,
            release_digest=lease.release_digest,
            expires_at=context.expires_at,
            predecessor_digest=context.predecessor_digest,
        )
        attestation = sign_detached(
            private_hex,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=OFFER_KIND,
            digest=claim_digest(claim),
        )
        return SignedControllerOffer(claim=claim, attestation=attestation)


def _load_validated_key(fs: FilesystemBackend, lease: SigningIdentityLease) -> str:
    raw = _read_root_key(fs)
    try:
        key = Ed25519PrivateKey.from_private_bytes(raw)
        public_hex = key.public_key().public_bytes(_RAW, _PUBLIC).hex()
    except Exception:  # noqa: BLE001 - a malformed key is a bounded refusal
        _reject("controller_enrollment_key_invalid")
    # the loaded key MUST derive exactly the LIVE active identity (never a cached / historical one)
    if lease.controller_trust_anchor_hex != public_hex:
        _reject("controller_enrollment_trust_anchor_mismatch")
    if lease.controller_key_id != key_id_for(public_hex):
        _reject("controller_enrollment_key_id_mismatch")
    if lease.enrollment_key_proof_id != enrollment_key_proof_id_for(public_hex):
        _reject("controller_enrollment_proof_id_mismatch")
    return raw.hex()


# ----------------------------------------------------------------------- S3: crash-safe key file


def _require_root_regular(fs: FilesystemBackend, path: str, *, reason: str) -> None:
    st = fs.lstat(path)
    if (
        st is None
        or st.is_dir
        or st.is_symlink
        or st.is_special
        or not st.is_regular
        or st.uid != 0
        or st.gid != 0
        or st.nlink != 1
        or (st.mode & 0o777) != _KEY_MODE
    ):
        _reject(reason)


def _read_root_key(fs: FilesystemBackend) -> bytes:
    _require_root_regular(
        fs, CONTROLLER_ENROLLMENT_KEY_PATH, reason="controller_enrollment_key_unsafe"
    )
    try:
        raw = fs.safe_read(CONTROLLER_ENROLLMENT_KEY_PATH, max_bytes=_MAX_KEY_BYTES, expected_uid=0)
    except FilesystemError:
        _reject("controller_enrollment_key_unsafe")
    if len(raw) != 32:
        _reject("controller_enrollment_key_unsafe")
    return raw


def _identity_from_key(raw: bytes) -> dict[str, str]:
    """Derive the full PUBLIC identity from the single private-key file — the sole source of the key
    id, public key and proof id (S3: no separate sidecar to fall out of sync)."""
    try:
        key = Ed25519PrivateKey.from_private_bytes(raw)
        public_hex = key.public_key().public_bytes(_RAW, _PUBLIC).hex()
    except Exception:  # noqa: BLE001
        _reject("controller_enrollment_key_invalid")
    return {
        "key_id": key_id_for(public_hex),
        "public_key_hex": public_hex,
        "enrollment_key_proof_id": enrollment_key_proof_id_for(public_hex),
    }


def _adopt_existing_key(fs: FilesystemBackend) -> dict[str, str]:
    """Validate and derive the identity of an already-present key (idempotent adoption)."""
    return _identity_from_key(_read_root_key(fs))


def _compensate(fs: FilesystemBackend, receipt: object) -> None:
    try:
        removed = fs.remove_created_file(receipt)  # type: ignore[arg-type]
    except FilesystemError:
        removed = False
    if not removed:
        _reject("controller_enrollment_key_compensation_failed")


def prepare_controller_enrollment_key(
    fs: FilesystemBackend, *, write: bool, confirm: bool
) -> dict[str, str]:
    """The reviewed root-gated CREATE-OR-ADOPT for the dedicated controller enrollment key. Single
    atomic file (S3): if the key is ABSENT it is generated and ``exclusive_install``-ed root-owned
    ``0o600``, then re-read + receipt-matched + re-derived before success is reported; a present
    valid key is safely adopted (idempotent), a present malformed/unsafe key refuses; on any
    creation exception every created artifact is compensated (a failed compensation raises a
    distinct code), so a crash never leaves an untracked partial pair and a retry is safe."""
    if not (write and confirm):
        _reject("controller_enrollment_key_prepare_unconfirmed")
    if fs.lstat(CONTROLLER_ENROLLMENT_KEY_PATH) is not None:
        return _adopt_existing_key(fs)  # crash-after-create / retry: adopt the valid key or refuse
    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(_RAW, _PRIVATE, _NO_ENCRYPTION)
    try:
        receipt = fs.exclusive_install(
            CONTROLLER_ENROLLMENT_KEY_PATH, private_raw, uid=0, gid=0, mode=_KEY_MODE
        )
    except FilesystemError:
        _reject("controller_enrollment_key_prepare_failed")
    try:
        if not fs.created_file_matches(receipt):
            _compensate(fs, receipt)
            _reject("controller_enrollment_key_prepare_readback_failed")
        identity = _adopt_existing_key(fs)  # read-back: re-read + re-derive + validate the pair
    except ControllerEnrollmentSignerError:
        _compensate(fs, receipt)
        raise
    except FilesystemError:
        _compensate(fs, receipt)
        _reject("controller_enrollment_key_prepare_failed")
    return identity


def rotate_controller_enrollment_key(
    fs: FilesystemBackend, *, write: bool, confirm: bool
) -> dict[str, str]:
    """A recoverable root-gated ROTATION: it requires a present, valid current key, then ATOMICALLY
    replaces the single file with a freshly generated key (``atomic_install`` — a crash leaves
    either the prior usable key or the new one, not a partial replacement), and re-reads the result
    reporting the new identity. It is NOT an undocumented delete-then-create sequence."""
    if not (write and confirm):
        _reject("controller_enrollment_key_prepare_unconfirmed")
    _read_root_key(fs)  # a rotation requires a present, valid key to rotate FROM
    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(_RAW, _PRIVATE, _NO_ENCRYPTION)
    try:
        fs.atomic_install(CONTROLLER_ENROLLMENT_KEY_PATH, private_raw, uid=0, gid=0, mode=_KEY_MODE)
    except FilesystemError:
        _reject("controller_enrollment_key_rotate_failed")
    return _adopt_existing_key(fs)  # read-back the new key


__all__ = [
    "CONTROLLER_ENROLLMENT_KEY_PATH",
    "ENROLLMENT_SIGNER_SOCKET_DIR",
    "ENROLLMENT_SIGNER_SOCKET_PATH",
    "ActiveControllerSigningIdentityProvider",
    "AuthorizedControllerOfferContext",
    "ControllerEnrollmentOfferSigner",
    "ControllerEnrollmentSignerError",
    "SealedControllerEnrollmentSigner",
    "SignedControllerOffer",
    "SigningIdentityLease",
    "prepare_controller_enrollment_key",
    "rotate_controller_enrollment_key",
]
