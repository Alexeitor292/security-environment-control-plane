"""Fixed-path host-local Ed25519 enrollment key for the worker-enrollment exchange (SECP WS-B, W1).

The production :class:`~secp_worker.enrollment_driver.WorkerEnrollmentKeySeam` the shipped
:class:`~secp_worker.enrollment_driver.SealedWorkerEnrollmentKeySeam` stands in for. It provisions
and loads the worker's DEDICATED enrollment signing key — a THIRD key, never the SSH keypair and
never the admission keypair — behind a code-owned fixed path, and returns a
:class:`~secp_worker.enrollment_http_transport.WorkerEnrollmentSigner` that never exposes the
private half.

The posture mirrors the reviewed root-local evidence authenticator
(``secp_discovery_activation.evidence_key``), deliberately, rather than inventing a second idiom:

* the paths are reviewed CODE constants — never a CLI argument, an environment variable, or a
  descriptor-selected value, so no caller can point the seam at another key;
* provisioning is an EXPLICIT write-gated local action (``write`` + ``confirm``); merely loading an
  already-provisioned key needs no write authority, and an ABSENT key without write authority fails
  closed rather than being silently created;
* an existing pair is adopted only after type / link / owner / mode and key-pair coherence checks;
  an INCOMPLETE pair is never repaired — it fails closed;
* creation is exclusive (no destination is ever adopted or replaced) and compensates its own
  partial writes; an uncompensated partial install fails closed rather than leaving a half key;
* the private key is never returned, represented, logged, serialized, or placed in evidence — only
  the public anchor and the derived key id are ever surfaced.

Every refusal is a bounded :class:`~secp_worker.enrollment_driver.WorkerEnrollmentDriverError`
reason code (never a path, key byte, or raw exception), so the driver's closed refusal contract —
and the ``secpctl`` exit mapping built on it — is preserved unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secp_commissioning.enrollment_attestation import key_id_for
from secp_commissioning.runtime import ExclusiveFileReceipt, FileStat, FilesystemBackend

from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
from secp_worker.enrollment_http_transport import (
    EnrollmentTransportError,
    WorkerEnrollmentSigner,
)

#: The code-owned root for ALL host-local worker-enrollment state (the key pair and, alongside it,
#: the durable restart-step markers). A sibling of the existing ``/var/lib/secp`` roots
#: (``bootstrap``, ``commissioning``, ``discovery-activation``); root-owned and 0700.
WORKER_ENROLLMENT_ROOT = "/var/lib/secp/worker-enrollment"
#: The EXACT protected private key (raw 32-byte Ed25519 key, lowercase-hex encoded), 0600 root:root.
WORKER_ENROLLMENT_KEY_PATH = f"{WORKER_ENROLLMENT_ROOT}/enrollment-signing-key"
#: The EXACT public anchor (raw 32-byte public key, lowercase-hex encoded), 0644 root:root. Safe to
#: read; the authoritative worker identity is the key id derived from these bytes.
WORKER_ENROLLMENT_PUBLIC_PATH = f"{WORKER_ENROLLMENT_ROOT}/enrollment-key.pub"

_ROOT_MODE = 0o700
_KEY_MODE = 0o600
_PUBLIC_MODE = 0o644
_KEY_BYTES = 64  # a raw 32-byte Ed25519 key encoded as exactly 64 lowercase hex bytes
_PUBLIC_BYTES = 64
_HEX64 = re.compile(rb"^[0-9a-f]{64}$")


def _reject(reason_code: str) -> None:
    raise WorkerEnrollmentDriverError(reason_code)


@dataclass(frozen=True)
class WorkerEnrollmentKeyPreparation:
    """The bounded, PUBLIC result of one preparation: the derived key id and whether this call
    created the pair or adopted an already-provisioned one. It carries no private material."""

    key_id: str
    classification: str

    def canonical(self) -> dict[str, str]:
        return {"key_id": self.key_id, "classification": self.classification}


def require_protected_file_stat(st: FileStat | None, *, mode: int, reason: str) -> None:
    """Refuse anything that is not a plain, unlinked, root-owned file at the EXACT reviewed mode —
    so a symlink, hardlink, device node, or a file another uid can rewrite is never trusted.

    Public because :mod:`secp_worker.worker_ownership` stores its document under this same root and
    must be held to the identical contract. One checker with two callers; a second copy is how the
    two drift and one of them ends up trusting a hardlink.
    """
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


def _decode_pair(fs: FilesystemBackend) -> tuple[str, str]:
    """Read + fully validate the fixed pair, returning ``(private_hex, public_hex)``. The private
    half is returned ONLY to the in-process signer construction below; it is never logged or
    surfaced. A pair whose public half does not derive from the private half fails closed."""
    require_protected_file_stat(
        fs.lstat(WORKER_ENROLLMENT_KEY_PATH), mode=_KEY_MODE, reason="enrollment_worker_key"
    )
    require_protected_file_stat(
        fs.lstat(WORKER_ENROLLMENT_PUBLIC_PATH),
        mode=_PUBLIC_MODE,
        reason="enrollment_worker_key_anchor",
    )
    try:
        private_raw = fs.safe_read(WORKER_ENROLLMENT_KEY_PATH, max_bytes=_KEY_BYTES, expected_uid=0)
        public_raw = fs.safe_read(
            WORKER_ENROLLMENT_PUBLIC_PATH, max_bytes=_PUBLIC_BYTES, expected_uid=0
        )
    except Exception:
        raise WorkerEnrollmentDriverError("enrollment_worker_key_read_failed") from None
    if not _HEX64.fullmatch(private_raw) or not _HEX64.fullmatch(public_raw):
        _reject("enrollment_worker_key_encoding_invalid")
    try:
        private_hex = private_raw.decode("ascii")
        public_hex = public_raw.decode("ascii")
        derived = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
    except (ValueError, UnicodeDecodeError):
        raise WorkerEnrollmentDriverError("enrollment_worker_key_encoding_invalid") from None
    if derived != public_hex:
        _reject("enrollment_worker_key_pair_mismatch")
    return private_hex, public_hex


def _pair_presence(fs: FilesystemBackend) -> bool:
    """True when BOTH halves are present, False when both are absent. A half-present pair is a
    corrupted provisioning state and is refused here — it is never silently repaired."""
    key_present = fs.lstat(WORKER_ENROLLMENT_KEY_PATH) is not None
    public_present = fs.lstat(WORKER_ENROLLMENT_PUBLIC_PATH) is not None
    if key_present != public_present:
        _reject("enrollment_worker_key_pair_incomplete")
    return key_present


def _ensure_root(fs: FilesystemBackend) -> None:
    """Create the root when absent, then RE-OBSERVE it. An idempotent makedir must not let a
    concurrently planted directory bypass the ownership/type/mode contract a pre-existing root is
    held to."""
    if fs.lstat(WORKER_ENROLLMENT_ROOT) is None:
        fs.makedir(WORKER_ENROLLMENT_ROOT, uid=0, gid=0, mode=_ROOT_MODE)
    st = fs.lstat(WORKER_ENROLLMENT_ROOT)
    if (
        st is None
        or not st.is_dir
        or st.is_symlink
        or st.uid != 0
        or st.gid != 0
        or st.mode != _ROOT_MODE
    ):
        _reject("enrollment_worker_key_root_unsafe")


def prepare_local_worker_enrollment_key(
    fs: FilesystemBackend, *, write: bool, confirm: bool
) -> WorkerEnrollmentKeyPreparation:
    """Generate or validate the fixed enrollment pair. No alternate path or caller-supplied key
    bytes can ever be provided; the only inputs are the two explicit write gates."""

    if not write:
        raise WorkerEnrollmentDriverError("enrollment_worker_key_write_authority_required")
    if not confirm:
        raise WorkerEnrollmentDriverError("enrollment_worker_key_confirmation_required")
    _ensure_root(fs)
    if _pair_presence(fs):
        _private_hex, public_hex = _decode_pair(fs)
        return WorkerEnrollmentKeyPreparation(key_id_for(public_hex), "adopted")

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
    installed_public: ExclusiveFileReceipt | None = None
    try:
        installed_key = fs.exclusive_install(
            WORKER_ENROLLMENT_KEY_PATH, private.hex().encode("ascii"), uid=0, gid=0, mode=_KEY_MODE
        )
        installed_public = fs.exclusive_install(
            WORKER_ENROLLMENT_PUBLIC_PATH,
            public.hex().encode("ascii"),
            uid=0,
            gid=0,
            mode=_PUBLIC_MODE,
        )
        _decode_pair(fs)  # prove what is ON DISK is the coherent pair, not what we held in memory
        if not fs.created_file_matches(installed_key) or not fs.created_file_matches(
            installed_public
        ):
            _reject("enrollment_worker_key_install_changed")
    except Exception as exc:
        compensated = True
        for receipt in (installed_public, installed_key):
            if receipt is None:
                continue
            try:
                if not fs.remove_created_file(receipt):
                    compensated = False
            except Exception:
                compensated = False
        if not compensated:
            raise WorkerEnrollmentDriverError("enrollment_worker_key_compensation_failed") from None
        if isinstance(exc, WorkerEnrollmentDriverError):
            raise
        raise WorkerEnrollmentDriverError("enrollment_worker_key_install_failed") from None
    return WorkerEnrollmentKeyPreparation(key_id_for(public.hex()), "created")


def observe_local_worker_enrollment_key(fs: FilesystemBackend) -> str:
    """The bounded HOST-LOCAL observation of the protected key: its key id when a coherent pair
    exists at the reviewed path with the reviewed ownership/mode, else ``""``.

    This is the only read a health probe needs — it proves the key is PROTECTED (root-owned, 0600,
    a real unlinked regular file) and IDENTIFIES it, without the caller ever touching private
    material. A missing, drifted, or incoherent pair is an empty observation, never an exception.
    """
    try:
        _private_hex, public_hex = _decode_pair(fs)
    except WorkerEnrollmentDriverError:
        return ""
    except Exception:  # noqa: BLE001 - an unavailable filesystem is an empty observation
        return ""
    return key_id_for(public_hex)


class LocalWorkerEnrollmentKeySeam:
    """The production key seam: loads the protected fixed-path pair on every call and returns a
    signer holding the private key IN MEMORY only.

    ``write``/``confirm`` gate CREATION only. With an already-provisioned key the seam is a pure
    read (no write authority required); with no key AND no write authority it fails closed
    (``enrollment_worker_key_absent``) rather than provisioning a key an operator never authorized.
    The seam itself caches nothing — every call re-proves the on-disk pair.
    """

    __slots__ = ("_fs", "_write", "_confirm")

    def __init__(
        self, fs: FilesystemBackend, *, write: bool = False, confirm: bool = False
    ) -> None:
        self._fs = fs
        self._write = bool(write)
        self._confirm = bool(confirm)

    def __repr__(self) -> str:  # never the path, key material, or the gates
        return "LocalWorkerEnrollmentKeySeam(<redacted>)"

    def load_or_create(self) -> WorkerEnrollmentSigner:
        if not _pair_presence(self._fs):
            if not (self._write and self._confirm):
                _reject("enrollment_worker_key_absent")
            prepare_local_worker_enrollment_key(self._fs, write=self._write, confirm=self._confirm)
        private_hex, _public_hex = _decode_pair(self._fs)
        try:
            return WorkerEnrollmentSigner(private_hex)
        except EnrollmentTransportError:
            # keep the driver's closed refusal contract: a bounded key reason, not a transport one
            raise WorkerEnrollmentDriverError("enrollment_worker_key_signer_invalid") from None


__all__ = [
    "WORKER_ENROLLMENT_KEY_PATH",
    "WORKER_ENROLLMENT_PUBLIC_PATH",
    "WORKER_ENROLLMENT_ROOT",
    "require_protected_file_stat",
    "LocalWorkerEnrollmentKeySeam",
    "WorkerEnrollmentKeyPreparation",
    "observe_local_worker_enrollment_key",
    "prepare_local_worker_enrollment_key",
]
