"""Fixed-path host-local Ed25519 authenticator for activation evidence.

Provisioning is an explicit write-gated local action.  Existing objects are adopted only after
type/link/owner/mode and key-pair coherence checks; an incomplete pair is never repaired.  Public
results contain only the anchor fingerprint/key id and created/adopted classification.  The private
key is never returned, represented, logged, or included in evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from secp_commissioning.runtime import ExclusiveFileReceipt, FileStat, FilesystemBackend

from secp_discovery_activation import DiscoveryActivationError
from secp_discovery_activation.evidence import (
    EvidenceAuthenticator,
    EvidenceTrustAnchor,
    EvidenceTrustRoot,
)
from secp_discovery_activation.layout import PRODUCTION_LAYOUT

_KEY_BYTES = 64  # raw 32-byte Ed25519 key encoded as 64 lowercase hex bytes
_ANCHOR_BYTES = 64
_MAX_MESSAGE_BYTES = 1024 * 1024
_HEX64 = re.compile(rb"^[0-9a-f]{64}$")
_ROOT = "/var/lib/secp/discovery-activation"
_RUNTIME_BINDING_SALT = b"secp-pr5f/root-local-runtime-binding/hkdf-salt/v1"
_RUNTIME_BINDING_INFO = b"secp-pr5f/root-local-runtime-binding/v1"


class EvidenceKeyError(DiscoveryActivationError):
    """The fixed evidence signing identity was unsafe or unavailable."""


@dataclass(frozen=True)
class EvidenceKeyPreparation:
    key_id: str
    classification: str

    def canonical(self) -> dict[str, str]:
        return {"key_id": self.key_id, "classification": self.classification}


def _reject(reason: str) -> None:
    raise EvidenceKeyError(reason)


def _require_stat(st: FileStat | None, *, mode: int, reason: str) -> None:
    if st is None:
        _reject(reason + "_missing")
    assert st is not None
    if st.is_symlink:
        _reject(reason + "_symlink")
    if not st.is_regular or st.is_dir or st.is_special:
        _reject(reason + "_not_regular")
    if st.nlink != 1:
        _reject(reason + "_hardlinked")
    if st.uid != 0 or st.gid != 0 or st.mode != mode:
        _reject(reason + "_metadata_invalid")


def _decode_pair(fs: FilesystemBackend) -> tuple[bytes, bytes]:
    key_path = PRODUCTION_LAYOUT.evidence_signing_key_path
    anchor_path = PRODUCTION_LAYOUT.evidence_trust_anchor_path
    _require_stat(fs.lstat(key_path), mode=0o600, reason="evidence_signing_key")
    _require_stat(fs.lstat(anchor_path), mode=0o644, reason="evidence_trust_anchor")
    try:
        private_raw = fs.safe_read(key_path, max_bytes=_KEY_BYTES, expected_uid=0)
        public_raw = fs.safe_read(anchor_path, max_bytes=_ANCHOR_BYTES, expected_uid=0)
    except Exception:
        raise EvidenceKeyError("evidence_key_read_failed") from None
    if not _HEX64.fullmatch(private_raw) or not _HEX64.fullmatch(public_raw):
        _reject("evidence_key_encoding_invalid")
    try:
        private = bytes.fromhex(private_raw.decode("ascii"))
        public = bytes.fromhex(public_raw.decode("ascii"))
        derived = (
            Ed25519PrivateKey.from_private_bytes(private)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
    except (ValueError, UnicodeDecodeError):
        raise EvidenceKeyError("evidence_key_encoding_invalid") from None
    if derived != public:
        _reject("evidence_key_pair_mismatch")
    return private, public


def _key_id(public: bytes) -> str:
    return "sha256:" + hashlib.sha256(public).hexdigest()


def prepare_local_evidence_key(
    fs: FilesystemBackend, *, write: bool, confirm: bool
) -> EvidenceKeyPreparation:
    """Generate or validate the fixed pair.  No alternate path or key bytes can be supplied."""

    if not write:
        raise EvidenceKeyError("write_authority_required")
    if not confirm:
        raise EvidenceKeyError("explicit_confirmation_required")
    root_stat = fs.lstat(_ROOT)
    if root_stat is None:
        fs.makedir(_ROOT, uid=0, gid=0, mode=0o700)
    # Re-observe even after creation.  An idempotent makedir must not let a concurrently planted
    # directory bypass the same ownership/type/mode contract applied to a pre-existing root.
    root_stat = fs.lstat(_ROOT)
    if (
        root_stat is None
        or not root_stat.is_dir
        or root_stat.is_symlink
        or root_stat.uid != 0
        or root_stat.gid != 0
        or root_stat.mode != 0o700
    ):
        _reject("evidence_key_root_unsafe")
    key_path = PRODUCTION_LAYOUT.evidence_signing_key_path
    anchor_path = PRODUCTION_LAYOUT.evidence_trust_anchor_path
    key_present = fs.lstat(key_path) is not None
    anchor_present = fs.lstat(anchor_path) is not None
    if key_present != anchor_present:
        _reject("evidence_key_pair_incomplete")
    if key_present:
        _private, public = _decode_pair(fs)
        return EvidenceKeyPreparation(_key_id(public), "adopted")

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    installed_key: ExclusiveFileReceipt | None = None
    installed_anchor: ExclusiveFileReceipt | None = None
    try:
        installed_key = fs.exclusive_install(
            key_path, private.hex().encode("ascii"), uid=0, gid=0, mode=0o600
        )
        installed_anchor = fs.exclusive_install(
            anchor_path, public.hex().encode("ascii"), uid=0, gid=0, mode=0o644
        )
        _decode_pair(fs)
        if not fs.created_file_matches(installed_key) or not fs.created_file_matches(
            installed_anchor
        ):
            _reject("evidence_key_install_changed")
    except Exception as exc:
        compensated = True
        for receipt in (installed_anchor, installed_key):
            if receipt is None:
                continue
            try:
                if not fs.remove_created_file(receipt):
                    compensated = False
            except Exception:
                compensated = False
        if not compensated:
            raise EvidenceKeyError("evidence_key_compensation_failed") from None
        if isinstance(exc, EvidenceKeyError):
            raise
        raise EvidenceKeyError("evidence_key_install_failed") from None
    return EvidenceKeyPreparation(_key_id(public), "created")


class LocalEvidenceAuthenticator(EvidenceAuthenticator):
    """Reads/signs with the exact validated root-controlled key on every operation."""

    __slots__ = ("_fs",)

    def __init__(self, fs: FilesystemBackend) -> None:
        self._fs = fs

    def __repr__(self) -> str:
        return "LocalEvidenceAuthenticator(<redacted>)"

    def key_id(self) -> str:
        _private, public = _decode_pair(self._fs)
        return _key_id(public)

    def public_key_hex(self) -> str:
        """Return the safe public anchor for a cross-host detached attestation.

        Peers still trust it only after matching its digest to the independently reviewed profile
        pin; including it in a handoff is not itself a trust decision.
        """

        _private, public = _decode_pair(self._fs)
        return public.hex()

    def attest(self, message: bytes) -> str:
        if not isinstance(message, bytes) or not (1 <= len(message) <= _MAX_MESSAGE_BYTES):
            raise EvidenceKeyError("evidence_message_size_invalid")
        private, _public = _decode_pair(self._fs)
        try:
            return Ed25519PrivateKey.from_private_bytes(private).sign(message).hex()
        except ValueError:
            raise EvidenceKeyError("evidence_signing_failed") from None

    def bind_runtime_configuration(self, message: bytes) -> str:
        """Return a root-local, non-exportable binding for credential-bearing runtime state."""

        if not isinstance(message, bytes) or not (1 <= len(message) <= _MAX_MESSAGE_BYTES):
            raise EvidenceKeyError("runtime_binding_message_size_invalid")
        private, _public = _decode_pair(self._fs)
        try:
            binding_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=_RUNTIME_BINDING_SALT,
                info=_RUNTIME_BINDING_INFO,
            ).derive(private)
            return "hmac-sha256:" + hmac.new(binding_key, message, hashlib.sha256).hexdigest()
        except (TypeError, ValueError):
            raise EvidenceKeyError("runtime_binding_failed") from None


def local_evidence_trust_root(fs: FilesystemBackend) -> EvidenceTrustRoot:
    _private, public = _decode_pair(fs)
    return EvidenceTrustRoot(
        anchors=(EvidenceTrustAnchor(key_id=_key_id(public), public_key_hex=public.hex()),)
    )


__all__ = [
    "EvidenceKeyError",
    "EvidenceKeyPreparation",
    "prepare_local_evidence_key",
    "LocalEvidenceAuthenticator",
    "local_evidence_trust_root",
]
