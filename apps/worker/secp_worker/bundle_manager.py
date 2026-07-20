"""Worker-owned live discovery bundle manager (SECP-B8).

Worker-side ONLY. Completes the first-time product flow so the worker — not the operator — owns and
generates the SSH/admission key material and assembles the mounted discovery bundle from the
control plane's SECRET-FREE descriptor.

It:
  * generates + owns TWO keypairs (private halves NEVER leave the worker filesystem):
      - an SSH Ed25519 keypair — the private half becomes the bundle ``id_key``; the PUBLIC half is
        what the operator's Proxmox bootstrap script authorizes;
      - an Ed25519 ADMISSION keypair — the private hex signs the control-plane admission nonce; the
        PUBLIC anchor hex is registered as the worker identity;
  * given a secret-free bundle descriptor (target host/port/account, host PUBLIC key + fingerprint,
    and the binding IDs + endpoint digest), writes the four-file mounted bundle
    (``manifest.json`` / ``id_key`` / ``known_hosts`` / ``binding.json``) ATOMICALLY into the
    worker-owned bundle directory with ``0700``/``0600`` permissions.

It fails closed on any invalid descriptor (root/reserved account, malformed/ mismatched host-key
fingerprint, missing field). It NEVER uploads or transmits a private key, contacts no Proxmox host,
and runs no probe — it composes local files only. The public material it RETURNS (SSH public key,
admission anchor hex + fingerprint) is the only thing the control plane ever receives.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass

_IS_POSIX = os.name == "posix"
_GETUID = getattr(os, "getuid", None)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

# Fixed, deliberately small read bounds. No worker key or generated bundle component is allowed to
# turn an ordinary startup/status pass into an unbounded filesystem read.
_MAX_ADMISSION_KEY_BYTES = 256
_MAX_SSH_PRIVATE_KEY_BYTES = 64 * 1024
_MAX_SSH_PUBLIC_KEY_BYTES = 8 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_KNOWN_HOSTS_BYTES = 256 * 1024
_MAX_BINDING_BYTES = 64 * 1024

# Fixed worker-local filenames (inside the worker-owned key directory + the bundle directory).
_ADMISSION_PRIVATE = "admission_key"  # Ed25519 admission private key (hex)
_ADMISSION_ANCHOR = "admission_anchor"  # Ed25519 admission public anchor (hex)
_SSH_PRIVATE = "ssh_id_ed25519"  # OpenSSH Ed25519 private key (worker-owned)
_SSH_PUBLIC = "ssh_id_ed25519.pub"  # OpenSSH public key line
_KEY_FILE_NAMES = frozenset({_ADMISSION_PRIVATE, _ADMISSION_ANCHOR, _SSH_PRIVATE, _SSH_PUBLIC})

_MANIFEST_NAME = "manifest.json"
_KEY_NAME = "id_key"
_KNOWN_HOSTS_NAME = "known_hosts"
_BINDING_NAME = "binding.json"

# Mirror the mounted-bundle validator's grammar so a bundle we write always validates.
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
_SAFE_ACCOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_ENDPOINT_BINDING_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESERVED_ACCOUNTS = frozenset({"root", "admin", "administrator", "toor", "sysadmin", "superuser"})
_SSH_KEYTYPES = frozenset(
    {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
)
_MANIFEST_FIELDS = ("ssh_host", "ssh_port", "account", "host_key_fingerprint")
_BINDING_FIELDS = (
    "organization_id",
    "execution_target_id",
    "onboarding_id",
    "enrollment_id",
    "authorization_id",
    "authorization_version",
    "endpoint_binding_hash",
)
_BUNDLE_FILE_LIMITS = {
    _MANIFEST_NAME: _MAX_MANIFEST_BYTES,
    _KEY_NAME: _MAX_SSH_PRIVATE_KEY_BYTES,
    _KNOWN_HOSTS_NAME: _MAX_KNOWN_HOSTS_BYTES,
    _BINDING_NAME: _MAX_BINDING_BYTES,
}


class BundleManagerError(Exception):
    """Fail-closed bundle error carrying ONLY a closed reason code (no secret/raw value)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class WorkerPublicMaterial:
    """The ONLY worker material the control plane ever receives — all PUBLIC.

    ``ssh_public_key`` authorizes the worker on Proxmox (via the bootstrap script); ``admission_
    anchor_hex`` / ``admission_anchor_fingerprint`` register + pin the worker identity. No private
    key is present."""

    ssh_public_key: str
    admission_anchor_hex: str
    admission_anchor_fingerprint: str


def _entry_stat(path: str, reason: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise BundleManagerError(f"{reason}_stat_failed") from None


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _require_private_directory(path: str, reason: str, *, create: bool = False) -> os.stat_result:
    """Require one real worker-owned 0700 directory; never chmod/repair an existing path."""
    st = _entry_stat(path, reason)
    if st is None and create:
        try:
            os.mkdir(path, 0o700)
        except OSError:
            raise BundleManagerError(f"{reason}_create_failed") from None
        st = _entry_stat(path, reason)
    if st is None:
        raise BundleManagerError(f"{reason}_missing")
    if stat.S_ISLNK(st.st_mode):
        raise BundleManagerError(f"{reason}_symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise BundleManagerError(f"{reason}_not_directory")
    if _IS_POSIX:
        if _GETUID is not None and st.st_uid != _GETUID():
            raise BundleManagerError(f"{reason}_not_owned")
        if stat.S_IMODE(st.st_mode) != 0o700:
            raise BundleManagerError(f"{reason}_bad_permissions")
    return st


def _open_validated_directory(path: str, reason: str) -> tuple[int, os.stat_result]:
    expected = _require_private_directory(path, reason)
    try:
        fd = os.open(path, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError:
        raise BundleManagerError(f"{reason}_open_failed") from None
    actual = os.fstat(fd)
    if not _same_inode(expected, actual) or not stat.S_ISDIR(actual.st_mode):
        os.close(fd)
        raise BundleManagerError(f"{reason}_changed")
    return fd, actual


def _read_bounded_regular_file(path: str, *, max_bytes: int, reason: str) -> bytes:
    """Read one inode-pinned 0600 regular, single-link worker file under a private directory."""
    directory = os.path.dirname(os.path.abspath(path))
    name = os.path.basename(path)
    dir_fd: int | None = None
    fd: int | None = None
    expected: os.stat_result | None = None
    try:
        if _IS_POSIX:
            dir_fd, parent_st = _open_validated_directory(directory, f"{reason}_parent")
            try:
                expected = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                raise BundleManagerError(f"{reason}_missing") from None
            except OSError:
                raise BundleManagerError(f"{reason}_stat_failed") from None
            if stat.S_ISLNK(expected.st_mode):
                raise BundleManagerError(f"{reason}_symlink")
            if not stat.S_ISREG(expected.st_mode):
                raise BundleManagerError(f"{reason}_not_regular")
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=dir_fd,
                )
            except FileNotFoundError:
                raise BundleManagerError(f"{reason}_missing") from None
            except OSError:
                raise BundleManagerError(f"{reason}_open_failed") from None
        else:
            parent_st = _require_private_directory(directory, f"{reason}_parent")
            expected = _entry_stat(path, reason)
            if expected is None:
                raise BundleManagerError(f"{reason}_missing")
            if stat.S_ISLNK(expected.st_mode):
                raise BundleManagerError(f"{reason}_symlink")
            if not stat.S_ISREG(expected.st_mode):
                raise BundleManagerError(f"{reason}_not_regular")
            try:
                fd = os.open(path, os.O_RDONLY | _O_CLOEXEC)
            except OSError:
                raise BundleManagerError(f"{reason}_open_failed") from None
        assert expected is not None
        st = os.fstat(fd)
        if not _same_inode(expected, st):
            raise BundleManagerError(f"{reason}_changed")
        if not stat.S_ISREG(st.st_mode):
            raise BundleManagerError(f"{reason}_not_regular")
        if st.st_nlink != 1:
            raise BundleManagerError(f"{reason}_hardlinked")
        if st.st_dev != parent_st.st_dev:
            raise BundleManagerError(f"{reason}_cross_device")
        if _IS_POSIX:
            if _GETUID is not None and st.st_uid != _GETUID():
                raise BundleManagerError(f"{reason}_not_owned")
            if stat.S_IMODE(st.st_mode) != 0o600:
                raise BundleManagerError(f"{reason}_bad_permissions")
        if st.st_size <= 0 or st.st_size > max_bytes:
            raise BundleManagerError(f"{reason}_size_invalid")
        chunks = bytearray()
        while len(chunks) <= max_bytes:
            chunk = os.read(fd, min(8192, max_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if not chunks or len(chunks) > max_bytes:
            raise BundleManagerError(f"{reason}_size_invalid")
        return bytes(chunks)
    except BundleManagerError:
        raise
    except OSError:
        raise BundleManagerError(f"{reason}_read_failed") from None
    finally:
        if fd is not None:
            os.close(fd)
        if dir_fd is not None:
            os.close(dir_fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _stage_private_file(directory: str, data: bytes) -> tuple[str, os.stat_result]:
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".secp-key-")
    created_st = os.fstat(fd)
    try:
        _write_all(fd, data)
        os.fsync(fd)
        st = os.fstat(fd)
    except Exception:
        os.close(fd)
        if not _unlink_if_inode(tmp, created_st):
            raise BundleManagerError("key_staging_recovery_required") from None
        raise
    os.close(fd)
    return tmp, st


def _fsync_directory(path: str, reason: str) -> None:
    if not _IS_POSIX:
        return
    fd: int | None = None
    try:
        fd, _ = _open_validated_directory(path, reason)
        os.fsync(fd)
    except BundleManagerError:
        raise
    except OSError:
        raise BundleManagerError(f"{reason}_fsync_failed") from None
    finally:
        if fd is not None:
            os.close(fd)


def _rename_noreplace(src: str, dst: str) -> None:
    """Atomically rename within one validated private directory without clobbering ``dst``."""

    source = os.path.abspath(src)
    destination = os.path.abspath(dst)
    parent = os.path.dirname(source)
    if parent != os.path.dirname(destination):
        raise OSError("cross-directory atomic rename refused")
    if os.name == "nt":
        # Windows rename already refuses an existing destination.
        os.rename(source, destination)
        return
    if not sys.platform.startswith("linux"):
        # Production is Linux. Never degrade to POSIX rename's clobbering semantics elsewhere.
        raise OSError("atomic no-replace rename unavailable")

    import ctypes

    dir_fd, _parent_st = _open_validated_directory(parent, "rename_parent")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renameat2 = libc.renameat2
        except AttributeError:
            raise OSError("atomic no-replace rename unavailable") from None
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            dir_fd,
            os.fsencode(os.path.basename(source)),
            dir_fd,
            os.fsencode(os.path.basename(destination)),
            1,  # RENAME_NOREPLACE
        )
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number), destination)
    finally:
        os.close(dir_fd)


def _replace_path(src: str, dst: str) -> None:
    """No-clobber rename seam used by transactional fault/race tests."""

    _rename_noreplace(src, dst)


def _quarantine_if_inode(path: str, expected: os.stat_result) -> str | None:
    """Move an entry aside before cleanup, restoring any inode substituted by a racer."""

    current = _entry_stat(path, "cleanup")
    if current is None:
        return ""
    parent = os.path.dirname(os.path.abspath(path))
    quarantine = os.path.join(parent, f".secp-quarantine-{secrets.token_hex(16)}")
    try:
        _rename_noreplace(path, quarantine)
    except FileNotFoundError:
        return ""
    except OSError:
        return None
    moved = _entry_stat(quarantine, "cleanup_quarantine")
    if moved is not None and _same_inode(moved, expected):
        return quarantine

    # A foreign inode won the source-name race. Restore it without overwriting a new occupant.
    try:
        if moved is not None and _entry_stat(path, "cleanup_restore") is None:
            _rename_noreplace(quarantine, path)
    except OSError:
        return None
    return None


def _unlink_if_inode(path: str, expected: os.stat_result) -> bool:
    quarantined = _quarantine_if_inode(path, expected)
    if quarantined == "":
        return True
    if quarantined is None:
        return False
    try:
        os.unlink(quarantined)
    except OSError:
        return False
    return True


def _write_new_files(
    directory: str,
    files: tuple[tuple[str, bytes], ...],
    *,
    reason: str,
) -> None:
    """Install fresh files without overwriting anything; compensate any partial local commit."""
    _require_private_directory(directory, f"{reason}_parent")
    destinations = [os.path.join(directory, name) for name, _ in files]
    if any(_entry_stat(path, reason) is not None for path in destinations):
        raise BundleManagerError(f"{reason}_already_present")
    staged: list[tuple[str, os.stat_result]] = []
    installed: list[tuple[str, os.stat_result]] = []
    try:
        for _name, data in files:
            staged.append(_stage_private_file(directory, data))
        if any(_entry_stat(path, reason) is not None for path in destinations):
            raise BundleManagerError(f"{reason}_appeared")
        for (tmp, tmp_st), dst in zip(staged, destinations, strict=True):
            _replace_path(tmp, dst)
            installed_st = _entry_stat(dst, reason)
            if installed_st is None or not _same_inode(installed_st, tmp_st):
                raise BundleManagerError(f"{reason}_install_changed")
            installed.append((dst, tmp_st))
        _fsync_directory(directory, f"{reason}_parent")
    except Exception as exc:
        cleanup_ok = True
        for dst, installed_st in installed:
            cleanup_ok = _unlink_if_inode(dst, installed_st) and cleanup_ok
        try:
            _fsync_directory(directory, f"{reason}_parent")
        except BundleManagerError:
            cleanup_ok = False
        if not cleanup_ok:
            raise BundleManagerError(f"{reason}_recovery_required") from None
        if isinstance(exc, BundleManagerError):
            raise
        raise BundleManagerError(f"{reason}_write_failed") from None
    finally:
        staged_cleanup_ok = True
        for tmp, tmp_st in staged:
            staged_cleanup_ok = _unlink_if_inode(tmp, tmp_st) and staged_cleanup_ok
        if not staged_cleanup_ok:
            raise BundleManagerError(f"{reason}_recovery_required") from None


def _write_new_pair(
    directory: str,
    files: tuple[tuple[str, bytes], tuple[str, bytes]],
    *,
    reason: str,
) -> None:
    """Compatibility wrapper; production key generation commits all four files together."""

    _write_new_files(directory, files, reason=reason)


def _decode_ascii(raw: bytes, reason: str) -> str:
    try:
        return raw.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        raise BundleManagerError(f"{reason}_malformed") from None


def _validate_admission_pair(private_hex: str, anchor_hex: str) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not re.fullmatch(r"[0-9a-f]{64}", private_hex):
        raise BundleManagerError("admission_private_key_malformed")
    if not re.fullmatch(r"[0-9a-f]{64}", anchor_hex):
        raise BundleManagerError("admission_anchor_malformed")
    try:
        derived = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
    except (ValueError, TypeError):
        raise BundleManagerError("admission_private_key_malformed") from None
    if derived != anchor_hex:
        raise BundleManagerError("admission_key_pair_mismatch")


def _validate_ssh_pair(private_pem: bytes, public_line: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    try:
        private_key = serialization.load_ssh_private_key(private_pem, password=None)
    except (TypeError, ValueError):
        raise BundleManagerError("ssh_private_key_malformed") from None
    if not isinstance(private_key, Ed25519PrivateKey):
        raise BundleManagerError("ssh_private_key_type_invalid")
    parts = public_line.split()
    if len(parts) < 2:
        raise BundleManagerError("ssh_public_key_malformed")
    derived = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )
    if parts[:2] != derived.split()[:2]:
        raise BundleManagerError("ssh_key_pair_mismatch")
    return public_line


def read_worker_admission_identity(key_path: str, anchor_path: str) -> tuple[str, str]:
    """Read one co-located admission pair under strict inode/owner/mode/link/size checks.

    B8 generation always uses the fixed ``admission_key``/``admission_anchor`` names. Accepting a
    co-located legacy B6 pair here preserves that deployment seam; the production activation
    configuration independently pins the exact B8 paths.
    """
    if not (
        isinstance(key_path, str)
        and isinstance(anchor_path, str)
        and os.path.isabs(key_path)
        and os.path.isabs(anchor_path)
        and os.path.basename(key_path) not in ("", ".", "..")
        and os.path.basename(anchor_path) not in ("", ".", "..")
        and os.path.dirname(os.path.abspath(key_path))
        == os.path.dirname(os.path.abspath(anchor_path))
    ):
        raise BundleManagerError("admission_identity_path_invalid")
    private_hex = _decode_ascii(
        _read_bounded_regular_file(
            key_path, max_bytes=_MAX_ADMISSION_KEY_BYTES, reason="admission_private_key"
        ),
        "admission_private_key",
    )
    anchor_hex = _decode_ascii(
        _read_bounded_regular_file(
            anchor_path, max_bytes=_MAX_ADMISSION_KEY_BYTES, reason="admission_anchor"
        ),
        "admission_anchor",
    )
    _validate_admission_pair(private_hex, anchor_hex)
    return private_hex, anchor_hex


def _require_key_directory_layout(key_dir: str) -> None:
    try:
        key_names = set(os.listdir(key_dir))
    except OSError:
        raise BundleManagerError("key_dir_list_failed") from None
    if not key_names.issubset(_KEY_FILE_NAMES):
        raise BundleManagerError("key_dir_foreign_entry")


def inspect_worker_keys(key_dir: str) -> WorkerPublicMaterial:
    """Read and validate one complete persisted worker key set without creating or changing it.

    The result is public material only.  Both private/public pairs are nevertheless checked for
    exact coherence under the same inode/link/owner/mode bounds as generation, which lets the
    activation probe bind a published database node to the keys in the recreated worker.
    """

    from secp_api.worker_admission_contract import compute_verification_anchor_fingerprint

    if not (isinstance(key_dir, str) and key_dir.strip() and os.path.isabs(key_dir)):
        raise BundleManagerError("key_dir_unset")
    _require_private_directory(key_dir, "key_dir")
    _require_key_directory_layout(key_dir)
    try:
        names = set(os.listdir(key_dir))
    except OSError:
        raise BundleManagerError("key_dir_list_failed") from None
    if names != set(_KEY_FILE_NAMES):
        raise BundleManagerError("worker_key_set_incomplete")

    _private_hex, anchor_hex = read_worker_admission_identity(
        os.path.join(key_dir, _ADMISSION_PRIVATE),
        os.path.join(key_dir, _ADMISSION_ANCHOR),
    )
    ssh_private = _read_bounded_regular_file(
        os.path.join(key_dir, _SSH_PRIVATE),
        max_bytes=_MAX_SSH_PRIVATE_KEY_BYTES,
        reason="ssh_private_key",
    )
    ssh_public = _decode_ascii(
        _read_bounded_regular_file(
            os.path.join(key_dir, _SSH_PUBLIC),
            max_bytes=_MAX_SSH_PUBLIC_KEY_BYTES,
            reason="ssh_public_key",
        ),
        "ssh_public_key",
    )
    ssh_public = _validate_ssh_pair(ssh_private, ssh_public)
    _require_key_directory_layout(key_dir)
    return WorkerPublicMaterial(
        ssh_public_key=ssh_public,
        admission_anchor_hex=anchor_hex,
        admission_anchor_fingerprint=compute_verification_anchor_fingerprint(anchor_hex),
    )


def ensure_worker_keys(key_dir: str) -> WorkerPublicMaterial:
    """Generate + persist the worker's SSH + admission keypairs under ``key_dir`` if missing, and
    return the PUBLIC material. Idempotent: existing keys are reused (never regenerated), so the
    worker identity + authorized Proxmox key stay stable across restarts. The directory is created
    0700 (worker-owned); private keys are 0600. NO private key is ever returned."""
    from secp_api.worker_admission_contract import generate_ed25519_keypair

    if not (isinstance(key_dir, str) and key_dir.strip() and os.path.isabs(key_dir)):
        raise BundleManagerError("key_dir_unset")
    _require_private_directory(key_dir, "key_dir", create=True)
    _require_key_directory_layout(key_dir)

    paths = {name: os.path.join(key_dir, name) for name in _KEY_FILE_NAMES}

    # 1. Admission keypair (Ed25519 hex) — reuse if present so the registered anchor stays stable.
    admission_present = tuple(
        _entry_stat(path, "admission_key_pair") is not None
        for path in (paths[_ADMISSION_PRIVATE], paths[_ADMISSION_ANCHOR])
    )
    if admission_present[0] != admission_present[1]:
        raise BundleManagerError("admission_key_pair_incomplete")
    if all(admission_present):
        read_worker_admission_identity(paths[_ADMISSION_PRIVATE], paths[_ADMISSION_ANCHOR])

    # 2. SSH keypair (OpenSSH Ed25519) — reuse if present.
    ssh_present = tuple(
        _entry_stat(path, "ssh_key_pair") is not None
        for path in (paths[_SSH_PRIVATE], paths[_SSH_PUBLIC])
    )
    if ssh_present[0] != ssh_present[1]:
        raise BundleManagerError("ssh_key_pair_incomplete")
    if all(ssh_present):
        existing_ssh_private = _read_bounded_regular_file(
            paths[_SSH_PRIVATE],
            max_bytes=_MAX_SSH_PRIVATE_KEY_BYTES,
            reason="ssh_private_key",
        )
        existing_ssh_public = _decode_ascii(
            _read_bounded_regular_file(
                paths[_SSH_PUBLIC],
                max_bytes=_MAX_SSH_PUBLIC_KEY_BYTES,
                reason="ssh_public_key",
            ),
            "ssh_public_key",
        )
        _validate_ssh_pair(existing_ssh_private, existing_ssh_public)

    present_count = sum(admission_present) + sum(ssh_present)
    if present_count not in (0, len(_KEY_FILE_NAMES)):
        raise BundleManagerError("worker_key_set_incomplete")
    if present_count == 0:
        admission_private, admission_anchor = generate_ed25519_keypair()
        ssh_private, ssh_public = _generate_ssh_keypair()
        _validate_admission_pair(admission_private, admission_anchor)
        _validate_ssh_pair(ssh_private, ssh_public)
        _write_new_files(
            key_dir,
            (
                (_ADMISSION_PRIVATE, admission_private.encode("ascii")),
                (_ADMISSION_ANCHOR, admission_anchor.encode("ascii")),
                (_SSH_PRIVATE, ssh_private),
                (_SSH_PUBLIC, ssh_public.encode("ascii")),
            ),
            reason="worker_key_set",
        )
    return inspect_worker_keys(key_dir)


def _generate_ssh_keypair() -> tuple[bytes, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public_line = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return private_pem, public_line + " secp-worker"


def worker_ssh_private_key_path(key_dir: str) -> str:
    return os.path.join(key_dir, _SSH_PRIVATE)


# --- bundle assembly ---------------------------------------------------------


def _require(descriptor: dict, key: str) -> object:
    if key not in descriptor or descriptor[key] in (None, ""):
        raise BundleManagerError(f"descriptor_missing_{key}")
    return descriptor[key]


def _known_hosts_line(ssh_host: str, ssh_port: int, host_public_key: str) -> str:
    parts = host_public_key.strip().split()
    if len(parts) < 2 or parts[0] not in _SSH_KEYTYPES:
        raise BundleManagerError("host_public_key_malformed")
    keytype, blob = parts[0], parts[1]
    if not re.match(r"^[A-Za-z0-9+/]{32,}={0,3}$", blob):
        raise BundleManagerError("host_public_key_malformed")
    name = ssh_host.lower() if ssh_port == 22 else f"[{ssh_host.lower()}]:{ssh_port}"
    return f"{name} {keytype} {blob}\n"


def _host_key_fingerprint(host_public_key: str) -> str:
    import base64
    import binascii
    import hashlib

    parts = host_public_key.strip().split()
    if len(parts) < 2:
        raise BundleManagerError("host_public_key_malformed")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BundleManagerError("host_public_key_malformed") from exc
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def write_bundle(descriptor: dict, *, bundle_dir: str, ssh_private_key_path: str) -> None:
    """Write the four-file mounted discovery bundle ATOMICALLY into ``bundle_dir`` from the
    secret-free ``descriptor``. Fails closed on any invalid/inconsistent field, a reserved account,
    or a host-key fingerprint that does not match the host PUBLIC key. Sets 0700 on the dir + 0600
    on every file. The bundle is assembled in a temp dir and swapped in, so a partial bundle is
    never observable."""
    ssh_host = str(_require(descriptor, "ssh_host"))
    account = str(_require(descriptor, "account"))
    fingerprint = str(_require(descriptor, "host_key_fingerprint"))
    host_public_key = str(_require(descriptor, "host_public_key"))
    endpoint_binding_hash = str(_require(descriptor, "endpoint_binding_hash"))
    try:
        ssh_port = int(str(_require(descriptor, "ssh_port")))
    except (TypeError, ValueError) as exc:
        raise BundleManagerError("ssh_port_invalid") from exc

    if not _SAFE_HOST.match(ssh_host):
        raise BundleManagerError("ssh_host_invalid")
    if not _SAFE_ACCOUNT.match(account):
        raise BundleManagerError("account_invalid")
    if account.lower() in _RESERVED_ACCOUNTS:
        raise BundleManagerError("account_privileged")
    if not (1 <= ssh_port <= 65535):
        raise BundleManagerError("ssh_port_invalid")
    if not _FINGERPRINT.match(fingerprint):
        raise BundleManagerError("host_key_fingerprint_invalid")
    if not _ENDPOINT_BINDING_RE.match(endpoint_binding_hash):
        raise BundleManagerError("endpoint_binding_hash_invalid")
    # Defense in depth: the pinned fingerprint MUST match the host public key put in known_hosts.
    if _host_key_fingerprint(host_public_key) != fingerprint:
        raise BundleManagerError("host_key_fingerprint_mismatch")
    if not (
        isinstance(bundle_dir, str)
        and bundle_dir.strip()
        and os.path.isabs(bundle_dir)
        and isinstance(ssh_private_key_path, str)
        and os.path.isabs(ssh_private_key_path)
        and os.path.basename(ssh_private_key_path) == _SSH_PRIVATE
    ):
        raise BundleManagerError("bundle_path_invalid")

    manifest = {
        "ssh_host": ssh_host,
        "ssh_port": ssh_port,
        "account": account,
        "host_key_fingerprint": fingerprint,
    }
    binding = {field: descriptor[field] for field in _BINDING_FIELDS if field in descriptor}
    missing = [f for f in _BINDING_FIELDS if f not in binding]
    if missing:
        raise BundleManagerError(f"descriptor_missing_{missing[0]}")
    try:
        binding["authorization_version"] = int(binding["authorization_version"])
    except (TypeError, ValueError):
        raise BundleManagerError("authorization_version_invalid") from None
    binding = {k: (str(v) if k != "authorization_version" else v) for k, v in binding.items()}
    known_hosts = _known_hosts_line(ssh_host, ssh_port, host_public_key)
    id_key_bytes = _read_bounded_regular_file(
        ssh_private_key_path,
        max_bytes=_MAX_SSH_PRIVATE_KEY_BYTES,
        reason="ssh_private_key",
    )

    payloads = {
        _MANIFEST_NAME: json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
        _BINDING_NAME: json.dumps(binding, sort_keys=True, separators=(",", ":")).encode(),
        _KNOWN_HOSTS_NAME: known_hosts.encode(),
        _KEY_NAME: id_key_bytes,
    }

    parent = os.path.dirname(os.path.abspath(bundle_dir)) or "."
    _require_private_directory(parent, "bundle_parent", create=True)
    backup = bundle_dir + ".old"
    if _entry_stat(backup, "bundle_backup") is not None:
        raise BundleManagerError("bundle_backup_present")
    existing: dict[str, bytes] | None = None
    if _entry_stat(bundle_dir, "bundle") is not None:
        existing, _ = _read_owned_bundle(bundle_dir, expected_private_key=id_key_bytes)
        if existing == payloads:
            return

    staging = tempfile.mkdtemp(dir=parent, prefix=".secp-bundle-")
    staging_st = _require_private_directory(staging, "bundle_staging")
    try:
        for name, data in payloads.items():
            _atomic_write(os.path.join(staging, name), data)
        _fsync_directory(staging, "bundle_staging")
        _replace_dir(staging, bundle_dir, expected_private_key=id_key_bytes)
        staging = ""  # consumed
    finally:
        if staging:
            _remove_staging_directory(staging, staging_st)


def _atomic_write(path: str, data: bytes) -> None:
    """Create one new 0600 staged file, fsync it, and never overwrite a pre-existing entry."""
    if _entry_stat(path, "bundle_staged_file") is not None:
        raise BundleManagerError("bundle_staged_file_already_present")
    directory = os.path.dirname(path)
    try:
        tmp, tmp_st = _stage_private_file(directory, data)
    except BundleManagerError:
        raise
    except Exception:
        raise BundleManagerError("bundle_staged_file_write_failed") from None
    try:
        if _entry_stat(path, "bundle_staged_file") is not None:
            raise BundleManagerError("bundle_staged_file_appeared")
        _replace_path(tmp, path)
        tmp = ""
    except BundleManagerError:
        raise
    except Exception:
        raise BundleManagerError("bundle_staged_file_install_failed") from None
    finally:
        if tmp and not _unlink_if_inode(tmp, tmp_st):
            raise BundleManagerError("bundle_staged_file_recovery_required") from None


def _read_bundle_files(bundle_dir: str) -> tuple[dict[str, bytes], os.stat_result]:
    directory_st = _require_private_directory(bundle_dir, "bundle_existing")
    try:
        names = set(os.listdir(bundle_dir))
    except OSError:
        raise BundleManagerError("bundle_existing_list_failed") from None
    if names != set(_BUNDLE_FILE_LIMITS):
        raise BundleManagerError("bundle_existing_foreign")
    files: dict[str, bytes] = {}
    for name, limit in _BUNDLE_FILE_LIMITS.items():
        reason = {
            _MANIFEST_NAME: "bundle_manifest",
            _KEY_NAME: "bundle_key",
            _KNOWN_HOSTS_NAME: "bundle_known_hosts",
            _BINDING_NAME: "bundle_binding",
        }[name]
        files[name] = _read_bounded_regular_file(
            os.path.join(bundle_dir, name), max_bytes=limit, reason=reason
        )
    current = _entry_stat(bundle_dir, "bundle_existing")
    if current is None or not _same_inode(directory_st, current):
        raise BundleManagerError("bundle_existing_changed")
    return files, directory_st


def _read_owned_bundle(
    bundle_dir: str, *, expected_private_key: bytes
) -> tuple[dict[str, bytes], os.stat_result]:
    files, directory_st = _read_bundle_files(bundle_dir)
    if files[_KEY_NAME] != expected_private_key:
        # The private-key bytes are the ownership proof. Never overwrite/delete a same-shaped
        # directory that belongs to some prior/foreign worker key.
        raise BundleManagerError("bundle_existing_foreign")
    return files, directory_st


def _remove_flat_private_directory(
    path: str,
    expected: os.stat_result,
    *,
    allowed_names: frozenset[str],
    reason: str,
) -> None:
    """Remove a pinned, flat private directory without recursive path traversal.

    Every child is an allowlisted 0600 regular single-link file and is removed through the same
    quarantine/inode check used by key compensation. Unexpected, replaced, or newly added children
    make cleanup fail closed and leave the quarantined directory for recovery.
    """

    dir_fd: int | None = None
    try:
        if _IS_POSIX:
            dir_fd, actual = _open_validated_directory(path, reason)
            list_target: str | int = dir_fd
        else:
            actual = _require_private_directory(path, reason)
            list_target = path
        if not _same_inode(actual, expected):
            raise BundleManagerError(f"{reason}_changed")
        try:
            names = set(os.listdir(list_target))
        except OSError:
            raise BundleManagerError(f"{reason}_list_failed") from None
        if not names.issubset(allowed_names):
            raise BundleManagerError(f"{reason}_foreign_entry")
        for name in names:
            try:
                child = (
                    os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                    if dir_fd is not None
                    else os.lstat(os.path.join(path, name))
                )
            except OSError:
                raise BundleManagerError(f"{reason}_child_changed") from None
            if (
                not stat.S_ISREG(child.st_mode)
                or child.st_nlink != 1
                or child.st_dev != actual.st_dev
                or (_IS_POSIX and stat.S_IMODE(child.st_mode) != 0o600)
                or (_IS_POSIX and _GETUID is not None and child.st_uid != _GETUID())
            ):
                raise BundleManagerError(f"{reason}_child_unsafe")
            if not _unlink_if_inode(os.path.join(path, name), child):
                raise BundleManagerError(f"{reason}_child_changed")
        try:
            if os.listdir(list_target):
                raise BundleManagerError(f"{reason}_not_empty")
        except OSError:
            raise BundleManagerError(f"{reason}_list_failed") from None
        current = _entry_stat(path, reason)
        if current is None or not _same_inode(current, expected):
            raise BundleManagerError(f"{reason}_changed")
        os.rmdir(path)
    except BundleManagerError:
        raise
    except OSError:
        raise BundleManagerError(f"{reason}_remove_failed") from None
    finally:
        if dir_fd is not None:
            os.close(dir_fd)


def _remove_staging_directory(path: str, expected: os.stat_result) -> None:
    quarantined = _quarantine_if_inode(path, expected)
    if quarantined == "":
        return
    if quarantined is None:
        raise BundleManagerError("bundle_staging_cleanup_refused")
    _remove_flat_private_directory(
        quarantined,
        expected,
        allowed_names=frozenset(_BUNDLE_FILE_LIMITS),
        reason="bundle_staging_cleanup",
    )


def _remove_owned_bundle_directory(
    path: str, expected: os.stat_result, *, expected_private_key: bytes
) -> None:
    quarantined = _quarantine_if_inode(path, expected)
    if quarantined is None or quarantined == "":
        raise BundleManagerError("bundle_backup_changed")
    try:
        _files, current = _read_owned_bundle(quarantined, expected_private_key=expected_private_key)
        if not _same_inode(current, expected):
            raise BundleManagerError("bundle_backup_changed")
        _remove_flat_private_directory(
            quarantined,
            expected,
            allowed_names=frozenset(_BUNDLE_FILE_LIMITS),
            reason="bundle_backup_cleanup",
        )
    except (OSError, BundleManagerError):
        try:
            if (
                _entry_stat(quarantined, "bundle_backup_restore") is not None
                and _entry_stat(path, "bundle_backup_restore") is None
            ):
                _rename_noreplace(quarantined, path)
        except OSError:
            pass
        raise BundleManagerError("bundle_backup_cleanup_failed") from None


def _replace_dir(src: str, dst: str, *, expected_private_key: bytes) -> None:
    """Swap an owned bundle transactionally; restore the prior directory if installation fails."""
    parent = os.path.dirname(os.path.abspath(dst)) or "."
    _require_private_directory(parent, "bundle_parent")
    _staged_files, src_st = _read_owned_bundle(src, expected_private_key=expected_private_key)
    old = dst + ".old"
    if _entry_stat(old, "bundle_backup") is not None:
        raise BundleManagerError("bundle_backup_present")

    dst_entry = _entry_stat(dst, "bundle_existing")
    if dst_entry is None:
        installed = False
        try:
            _replace_path(src, dst)
            installed = True
            current = _entry_stat(dst, "bundle_installed")
            if current is None or not _same_inode(current, src_st):
                if current is not None and _entry_stat(src, "bundle_install_restore") is None:
                    _replace_path(dst, src)
                    installed = False
                raise BundleManagerError("bundle_install_source_changed")
            _fsync_directory(parent, "bundle_parent")
            return
        except Exception:
            if installed:
                try:
                    current = _entry_stat(dst, "bundle_install_rollback")
                    if current is None or not _same_inode(current, src_st):
                        raise BundleManagerError("bundle_install_rollback_changed")
                    _replace_path(dst, src)
                    _fsync_directory(parent, "bundle_parent")
                except Exception:
                    raise BundleManagerError("bundle_swap_recovery_required") from None
            raise BundleManagerError("bundle_swap_failed") from None

    _files, dst_st = _read_owned_bundle(dst, expected_private_key=expected_private_key)
    backed_up = False
    try:
        _replace_path(dst, old)
        backed_up = True
        moved_backup = _entry_stat(old, "bundle_backup")
        if moved_backup is None or not _same_inode(moved_backup, dst_st):
            if moved_backup is not None and _entry_stat(dst, "bundle_backup_restore") is None:
                _replace_path(old, dst)
                backed_up = False
            raise BundleManagerError("bundle_existing_changed")
        _fsync_directory(parent, "bundle_parent")
    except Exception:
        if backed_up:
            try:
                if _entry_stat(dst, "bundle_backup_rollback") is not None:
                    raise BundleManagerError("bundle_backup_rollback_destination_present")
                _replace_path(old, dst)
                _fsync_directory(parent, "bundle_parent")
            except Exception:
                raise BundleManagerError("bundle_swap_recovery_required") from None
        raise BundleManagerError("bundle_backup_failed") from None
    installed = False
    try:
        _replace_path(src, dst)
        installed = True
        moved_source = _entry_stat(dst, "bundle_installed")
        if moved_source is None or not _same_inode(moved_source, src_st):
            if moved_source is not None and _entry_stat(src, "bundle_source_restore") is None:
                _replace_path(dst, src)
                installed = False
            raise BundleManagerError("bundle_staging_changed")
        _fsync_directory(parent, "bundle_parent")
    except Exception:
        try:
            current = _entry_stat(dst, "bundle_restore")
            if installed:
                if current is None or not _same_inode(current, src_st):
                    raise BundleManagerError("bundle_restore_destination_changed")
                _replace_path(dst, src)
            elif current is not None:
                raise BundleManagerError("bundle_restore_destination_present")
            _replace_path(old, dst)
            _fsync_directory(parent, "bundle_parent")
        except Exception:
            raise BundleManagerError("bundle_swap_recovery_required") from None
        raise BundleManagerError("bundle_swap_failed") from None

    installed_st = _entry_stat(dst, "bundle_installed")
    if installed_st is None or not _same_inode(installed_st, src_st):
        raise BundleManagerError("bundle_swap_recovery_required")
    try:
        _remove_owned_bundle_directory(old, dst_st, expected_private_key=expected_private_key)
        _fsync_directory(parent, "bundle_parent")
    except BundleManagerError:
        raise BundleManagerError("bundle_swap_recovery_required") from None


def bundle_is_present(bundle_dir: str) -> bool:
    """True only if the bundle dir exists and all four bundle files are present (a coarse readiness
    signal; the mounted-bundle source runs the authoritative strict validation before any ssh)."""
    try:
        _read_bundle_files(bundle_dir)
    except (BundleManagerError, OSError):
        return False
    return True
