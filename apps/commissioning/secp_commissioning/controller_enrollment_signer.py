"""Root-gated controller enrollment offer signer (SECP-PR5H-B1, Phase 2).

The controller's dedicated ENROLLMENT key — separate from the management-evidence, release-signing,
admission-TLS, provider and operator keys — signs the canonical ControllerOffer that unseals the
authenticated worker exchange. This module lives in the commissioning plane because it owns BOTH the
hardened root-controlled filesystem reader (``secp_commissioning.runtime`` trusted-dirfd /
no-symlink / ownership / mode / hard-link protections) AND the pure Ed25519 signing primitive
(``secp_commissioning.enrollment_attestation``). It is injected into the API through a sealed
dependency seam; the API never imports it directly and never touches the private key.

Key lifecycle (all through the hardened ``FilesystemBackend`` seam — never ad-hoc open/chmod):

* created ONLY through :func:`prepare_controller_enrollment_key` (the reviewed root-gated
  bootstrap/upgrade path): generate Ed25519, ``exclusive_install`` the raw 32-byte private key
  root-owned ``0o600`` plus a pinned public ``.pub.json`` sidecar; compensating cleanup on failure;
* stored ONLY at the fixed :data:`CONTROLLER_ENROLLMENT_KEY_PATH` (never a caller-supplied path,
  never an env var); never in PostgreSQL, never returned by the API, never logged or serialized;
* the public key + key id + proof id are DERIVED from the private key at load time and must match
  the pinned sidecar AND the active persisted controller identity;
* any absence, mismatch, wrong owner, wrong mode, symlink, hard link, untrusted ancestor, malformed
  key, key reuse or identity mismatch refuses closed with a bounded reason code BEFORE signing;
* only the current ACTIVE identity's key may sign — rotation replaces the on-disk key + sidecar, and
  a signer constructed for a superseded identity refuses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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

#: The fixed, code-owned on-disk locations for the dedicated controller enrollment key — a sibling
#: of the management evidence key under the bootstrap-state root, with a DISTINCT filename so it
#: never overlaps the evidence / release / admission / provider / operator key material.
CONTROLLER_ENROLLMENT_KEY_PATH = "/var/lib/secp/bootstrap/controller-enrollment-signing.key"
CONTROLLER_ENROLLMENT_PUB_PATH = "/var/lib/secp/bootstrap/controller-enrollment-signing.pub.json"

_KEY_MODE = 0o600
_PUB_MODE = 0o640
_MAX_KEY_BYTES = 1024
_MAX_PUB_BYTES = 4096
_RAW = serialization.Encoding.Raw
_PUBLIC = serialization.PublicFormat.Raw
_PRIVATE = serialization.PrivateFormat.Raw
_NO_ENCRYPTION = serialization.NoEncryption()


class ControllerEnrollmentSignerError(CommissioningError):
    """A bounded, closed controller-enrollment-signer refusal — carries ONLY a reason code, never
    the private key, a path, an identity value or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise ControllerEnrollmentSignerError(reason_code)


@dataclass(frozen=True)
class ExpectedControllerIdentity:
    """The active persisted controller identity the loaded key MUST correspond to (public material
    only). The API builds this from the single ACTIVE ``ControllerEnrollmentIdentity`` row; the
    signer refuses if the on-disk key does not derive exactly this identity."""

    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    enrollment_key_proof_id: str


@dataclass(frozen=True)
class ControllerOfferRequest:
    """The exact, already-authorized offer context the controller mints for one enrollment. The
    identity-bound fields are cross-checked against the active identity before signing; the
    enrollment/worker/transaction/expiry/predecessor bindings come from the controller's
    authoritative invitation + the verified worker proof-of-possession."""

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


@dataclass(frozen=True)
class SignedControllerOffer:
    """The controller-signed offer the worker verifies against the invitation's pinned controller
    key: the canonical claim plus its detached Ed25519 attestation. No private material."""

    claim: dict[str, str]
    attestation: DetachedAttestation


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not (1 <= len(value) <= 64):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


class _NonSerializable:
    """Refuses every serialization/copy path — a signer that can read a private key can never be
    pickled, copied, or asdict-ed into a log, plan, event or audit record."""

    def __reduce__(self) -> NoReturn:
        _reject("controller_enrollment_signer_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("controller_enrollment_signer_not_serializable")


class SealedControllerEnrollmentSigner(_NonSerializable):
    """The shipped default: no root-gated controller enrollment signer is activated. Every attempt
    fails closed. The concrete signer is provided at deploy time by the root-gated bootstrap
    composition; until then the evidence-driven exchange stays sealed by the ABSENCE of a signer."""

    def __repr__(self) -> str:
        return "SealedControllerEnrollmentSigner(<sealed>)"

    def sign_offer(self, request: ControllerOfferRequest, *, now: str) -> SignedControllerOffer:
        _reject("controller_enrollment_signer_unavailable")


class ControllerEnrollmentOfferSigner(_NonSerializable):
    """Signs a controller offer with the dedicated enrollment key, re-reading + re-validating the
    root-owned key on EVERY sign (it caches NO private material). The signer is bound to ONE
    expected active identity; a key that does not derive that identity, or an offer whose
    identity-bound fields disagree with it, or an expired offer, refuses closed before signing."""

    __slots__ = ("_fs", "_expected")

    def __init__(self, fs: FilesystemBackend, expected: ExpectedControllerIdentity) -> None:
        self._fs = fs
        self._expected = expected

    def __repr__(self) -> str:  # never the private key / path
        return f"ControllerEnrollmentOfferSigner(key_id={self._expected.controller_key_id!r})"

    def sign_offer(self, request: ControllerOfferRequest, *, now: str) -> SignedControllerOffer:
        exp = self._expected
        # 1. the offer's identity-bound fields must equal the ACTIVE identity (never caller-chosen)
        if request.controller_key_id != exp.controller_key_id:
            _reject("controller_enrollment_offer_cross_key")
        if request.controller_installation_id != exp.controller_installation_id:
            _reject("controller_enrollment_offer_cross_installation")
        if request.controller_origin != exp.controller_origin:
            _reject("controller_enrollment_offer_cross_origin")
        if request.release_digest != exp.release_digest:
            _reject("controller_enrollment_offer_cross_release")
        # 2. the offer must not be expired
        now_ts = _parse_utc(now)
        expires_ts = _parse_utc(request.expires_at)
        if now_ts is None or expires_ts is None:
            _reject("controller_enrollment_offer_invalid")
        if expires_ts <= now_ts:
            _reject("controller_enrollment_offer_expired")
        # 3. load + fully validate the root-owned key corresponds to the ACTIVE identity
        private_hex = self._load_validated_key()
        # 4. build the canonical claim from the ACTIVE identity + authorized context, and sign
        claim = controller_offer_claim(
            enrollment_id=request.enrollment_id,
            invitation_id=request.invitation_id,
            controller_installation_id=exp.controller_installation_id,
            controller_key_id=exp.controller_key_id,
            controller_origin=exp.controller_origin,
            controller_transaction_id=request.controller_transaction_id,
            worker_installation_id=request.worker_installation_id,
            worker_key_id=request.worker_key_id,
            release_digest=exp.release_digest,
            expires_at=request.expires_at,
            predecessor_digest=request.predecessor_digest,
        )
        attestation = sign_detached(
            private_hex,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=OFFER_KIND,
            digest=claim_digest(claim),
        )
        return SignedControllerOffer(claim=claim, attestation=attestation)

    def _load_validated_key(self) -> str:
        raw = _read_root_key(self._fs)
        try:
            key = Ed25519PrivateKey.from_private_bytes(raw)
            public_hex = key.public_key().public_bytes(_RAW, _PUBLIC).hex()
        except Exception:
            _reject("controller_enrollment_key_invalid")
        derived_key_id = key_id_for(public_hex)
        derived_proof_id = enrollment_key_proof_id_for(public_hex)
        # independent on-disk pin (a sidecar can never disagree with the derived material)
        pin = _read_pub_pin(self._fs)
        if (
            pin.get("public_key_hex") != public_hex
            or pin.get("key_id") != derived_key_id
            or pin.get("enrollment_key_proof_id") != derived_proof_id
        ):
            _reject("controller_enrollment_key_pin_mismatch")
        # the loaded key MUST derive exactly the active persisted controller identity
        exp = self._expected
        if exp.controller_trust_anchor_hex != public_hex:
            _reject("controller_enrollment_trust_anchor_mismatch")
        if exp.controller_key_id != derived_key_id:
            _reject("controller_enrollment_key_id_mismatch")
        if exp.enrollment_key_proof_id != derived_proof_id:
            _reject("controller_enrollment_proof_id_mismatch")
        return raw.hex()


def _require_root_regular(fs: FilesystemBackend, path: str, *, mode: int, reason: str) -> None:
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
        or (st.mode & 0o777) != mode
    ):
        _reject(reason)


def _read_root_key(fs: FilesystemBackend) -> bytes:
    _require_root_regular(
        fs,
        CONTROLLER_ENROLLMENT_KEY_PATH,
        mode=_KEY_MODE,
        reason="controller_enrollment_key_unsafe",
    )
    try:
        raw = fs.safe_read(CONTROLLER_ENROLLMENT_KEY_PATH, max_bytes=_MAX_KEY_BYTES, expected_uid=0)
    except FilesystemError:
        _reject("controller_enrollment_key_unsafe")
    if len(raw) != 32:
        _reject("controller_enrollment_key_unsafe")
    return raw


def _read_pub_pin(fs: FilesystemBackend) -> dict[str, str]:
    _require_root_regular(
        fs,
        CONTROLLER_ENROLLMENT_PUB_PATH,
        mode=_PUB_MODE,
        reason="controller_enrollment_pin_unsafe",
    )
    try:
        raw = fs.safe_read(CONTROLLER_ENROLLMENT_PUB_PATH, max_bytes=_MAX_PUB_BYTES, expected_uid=0)
    except FilesystemError:
        _reject("controller_enrollment_pin_unsafe")
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        _reject("controller_enrollment_pin_invalid")
    if not isinstance(doc, dict) or set(doc) != {
        "key_id",
        "public_key_hex",
        "enrollment_key_proof_id",
    }:
        _reject("controller_enrollment_pin_invalid")
    return doc


def prepare_controller_enrollment_key(
    fs: FilesystemBackend, *, write: bool, confirm: bool
) -> dict[str, str]:
    """The reviewed root-gated CREATOR for the dedicated controller enrollment key. Dry-run gated
    (requires ``write and confirm``); generates an Ed25519 key, exclusively installs the raw 32-byte
    private key root-owned ``0o600`` and the pinned public sidecar ``0o640``, and returns the PUBLIC
    identity ``{key_id, public_key_hex, enrollment_key_proof_id}``. Compensates (removes exactly
    what it created) on any failure so a partial pair is never left behind."""
    if not (write and confirm):
        _reject("controller_enrollment_key_prepare_unconfirmed")
    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(_RAW, _PRIVATE, _NO_ENCRYPTION)
    public_hex = key.public_key().public_bytes(_RAW, _PUBLIC).hex()
    identity = {
        "key_id": key_id_for(public_hex),
        "public_key_hex": public_hex,
        "enrollment_key_proof_id": enrollment_key_proof_id_for(public_hex),
    }
    pub_bytes = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")
    try:
        key_receipt = fs.exclusive_install(
            CONTROLLER_ENROLLMENT_KEY_PATH, private_raw, uid=0, gid=0, mode=_KEY_MODE
        )
    except FilesystemError:
        _reject("controller_enrollment_key_prepare_failed")
    try:
        fs.exclusive_install(
            CONTROLLER_ENROLLMENT_PUB_PATH, pub_bytes, uid=0, gid=0, mode=_PUB_MODE
        )
    except FilesystemError:
        fs.remove_created_file(key_receipt)  # compensate: never leave a private key without its pin
        _reject("controller_enrollment_key_prepare_failed")
    return identity


__all__ = [
    "CONTROLLER_ENROLLMENT_KEY_PATH",
    "CONTROLLER_ENROLLMENT_PUB_PATH",
    "ControllerEnrollmentOfferSigner",
    "ControllerEnrollmentSignerError",
    "ControllerOfferRequest",
    "ExpectedControllerIdentity",
    "SealedControllerEnrollmentSigner",
    "SignedControllerOffer",
    "prepare_controller_enrollment_key",
]
