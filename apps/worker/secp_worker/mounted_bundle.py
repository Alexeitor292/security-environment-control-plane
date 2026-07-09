"""Real worker-only mounted bootstrap-bundle source (SECP-B6 §1).

Reads a deployment-local, worker-only mounted bundle from a FIXED mount directory and yields an
:class:`SshBootstrapBundle`. This is the ONLY place SSH connection material enters the process, and
it
is worker-only: there is NO API/UI/database/environment-variable source for the SSH host, account,
port, private key, known_hosts, or expected fingerprint. The mount is validated strictly (ownership,
permissions, regular-file type, no symlinks, no traversal, bounded size, well-formed manifest)
BEFORE
use, and every rejection fails closed with a CLOSED reason code that never echoes a raw bundle
value.
When the mount is absent or invalid the source refuses, so the shipped default remains sealed.

The bundle carries only file PATHS to the private key + known_hosts (never their contents) plus the
host/port/account/fingerprint metadata; none of it can reach
API/UI/DB/plan/evidence/audit/event/log/
exception/repr/response (the bundle has a redacted repr and is not serializable, and this module
raises only closed reason codes). ``dispose`` is a no-op — nothing sensitive is held in memory
beyond
the disposed bundle; disposal is driven on every path by the probe executor's ``finally``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from typing import NoReturn

from secp_worker.ssh_channel import (
    BootstrapBundleUnavailable,
    SshBootstrapBundle,
    SshChannelError,
)


@dataclass(frozen=True)
class BundleBindingAnchor:
    """The non-secret authorization anchor a mounted bundle declares (SECP-B6 F-BIND).

    All fields are safe control-plane IDs — never a host, account, port, key, fingerprint, endpoint,
    or secret. The engine compares this anchor to the CLAIMED job's authoritative enrollment and
    re-verifies the live-read authorization BEFORE any host contact, so a bundle mounted for one
    organization/target cannot be used to process a job for another.
    """

    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    enrollment_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    # SECP-B6 MB-2: the opaque ``sha256:`` SSH endpoint-binding digest the operator's bundle-prep
    # tool computed. The engine re-derives it from the validated manifest + the authoritative target
    # host and requires equality with this value AND the approved authorization's stored digest.
    endpoint_binding_hash: str


@dataclass(frozen=True)
class SshEndpointMetadata:
    """The NON-secret SSH endpoint metadata a bundle's manifest declares (SECP-B6 item-4).

    Sufficient to compute + bind the endpoint digest (MB-2) WITHOUT any private key material — read
    in the pre-admission metadata phase. Never carries the id_key/known_hosts bytes or their paths.
    """

    ssh_host: str
    ssh_port: int
    account: str
    host_key_fingerprint: str


@dataclass
class PreparedDiscoveryBundle:
    """A single strictly-validated discovery bundle snapshot (SECP-B6 MB-1/MB-2/item-4 Phase C).

    Produced in TWO phases from ONE descriptor-pinned acquisition so the authorization gates AND the
    probe executor consume the SAME validated snapshot — a post-validation mount swap cannot change
    what ssh reads. Phase 1 (:meth:`MountedWorkerBootstrapBundleSource.prepare_metadata`) fills the
    non-secret ``anchor`` + ``endpoint``; the PRIVATE ``ssh_bundle`` (id_key + known_hosts) loads
    ONLY after control-plane admission by :meth:`finalize_key_material`, so it is ``None`` until
    then. Non-serializable; the SSH bundle has a redacted repr; ``dispose`` removes the private
    copy AND closes the pinned descriptor.
    """

    anchor: BundleBindingAnchor
    endpoint: SshEndpointMetadata
    _source: MountedWorkerBootstrapBundleSource
    ssh_bundle: SshBootstrapBundle | None = None

    @property
    def key_material_loaded(self) -> bool:
        """True only once the private id_key/known_hosts have been read (post-admission)."""
        return self.ssh_bundle is not None

    def dispose(self) -> None:
        self._source._finalize_private_dir()

    def __repr__(self) -> str:
        return "PreparedDiscoveryBundle(<redacted>)"

    def __reduce__(self):  # the prepared bundle must never leave the process
        raise TypeError("PreparedDiscoveryBundle is not serializable")


# Fixed bundle layout inside the mount directory. Names are constants (no traversal is possible).
_MANIFEST_NAME = "manifest.json"
_KEY_NAME = "id_key"
_KNOWN_HOSTS_NAME = "known_hosts"
# SECP-B6 F-BIND: the non-secret authorization anchor that binds this bundle to the EXACT
# organization / execution target / onboarding / enrollment / live-read authorization it is
# authorized for. Kept in a separate file so the SSH manifest carries no authorization identity and
# the anchor carries no SSH/credential material.
_BINDING_NAME = "binding.json"

# Bounded sizes — a real bundle is tiny; an oversized file fails closed.
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_KEY_BYTES = 64 * 1024
_MAX_KNOWN_HOSTS_BYTES = 256 * 1024
_MAX_BINDING_BYTES = 64 * 1024

# Safe manifest values (host/account are safe tokens; port a bounded int; fingerprint the SSH SHA256
# form). No shell/path/whitespace characters are permitted.
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
_SAFE_ACCOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_MANIFEST_KEYS = frozenset({"ssh_host", "ssh_port", "account", "host_key_fingerprint"})
_BINDING_KEYS = frozenset(
    {
        "organization_id",
        "execution_target_id",
        "onboarding_id",
        "enrollment_id",
        "authorization_id",
        "authorization_version",
        "endpoint_binding_hash",
    }
)
_ENDPOINT_BINDING_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# SECP-B6 F-BLAST: privileged / reserved SSH accounts are refused. The server-side key MUST be a
# minimally-privileged, read-only-scoped service account (see docs); client-side command
# restrictions are NOT a substitute for server-side least privilege.
_RESERVED_ACCOUNTS = frozenset({"root", "admin", "administrator", "toor", "sysadmin", "superuser"})

_IS_POSIX = os.name == "posix"
# POSIX-only open/statvfs flags + calls, resolved via getattr so this module imports and type-checks
# on non-POSIX (where the strict descriptor path is refused before any of these is used).
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_ST_RDONLY = getattr(os, "ST_RDONLY", 1)
_statvfs = getattr(os, "statvfs", None)
_getuid = getattr(os, "getuid", None)


class MountedBundleRejected(BootstrapBundleUnavailable):
    """The mounted bundle failed a strict validation check. A subclass of
    :class:`BootstrapBundleUnavailable` (so the executor's fail-closed handling catches it) carrying
    a
    CLOSED reason code — never a raw host/account/port/path/key/fingerprint value."""

    def __init__(self, reason_code: str = "mounted_bundle_invalid") -> None:
        SshChannelError.__init__(self, reason_code)  # closed reason; skip the fixed parent message


def _reject(reason_code: str) -> NoReturn:
    raise MountedBundleRejected(reason_code)


def _lstat(path: str) -> os.stat_result:
    try:
        return os.lstat(path)  # lstat: does NOT follow a final symlink
    except OSError:
        _reject("bundle_path_missing")
        raise  # unreachable


def _check_owner_and_perms(
    st: os.stat_result, *, world_perm_mask: int, missing_reason: str
) -> None:
    if _IS_POSIX:
        if _getuid is not None and st.st_uid != _getuid():
            _reject(missing_reason + "_not_owned")
        if st.st_mode & world_perm_mask:
            _reject(missing_reason + "_bad_permissions")


def _require_regular_file(
    mount: str, path: str, *, max_bytes: int, world_perm_mask: int, reason: str
) -> None:
    st = _lstat(path)
    # Reject a symlink FIRST with a specific reason: ``_within`` follows the final symlink via
    # ``realpath`` and would otherwise mask a symlinked bundle file as a generic path escape.
    if stat.S_ISLNK(st.st_mode):
        _reject(reason + "_symlink")
    # Containment (defense-in-depth): the file must be the fixed-name entry directly inside the real
    # mount — never a traversal or an entry resolving elsewhere.
    if not _within(mount, path):
        _reject(reason + "_path_escape")
    if not stat.S_ISREG(st.st_mode):
        _reject(reason + "_not_regular_file")
    if st.st_size <= 0 or st.st_size > max_bytes:
        _reject(reason + "_size_invalid")
    _check_owner_and_perms(st, world_perm_mask=world_perm_mask, missing_reason=reason)


def _within(mount: str, path: str) -> bool:
    base = os.path.realpath(mount)
    return os.path.realpath(path) == os.path.join(base, os.path.basename(path))


def _validate_manifest_fields(manifest: dict) -> tuple[str, int, str, str]:
    """Validate the SSH manifest fields (shared by the path-based and descriptor paths)."""
    host = manifest["ssh_host"]
    account = manifest["account"]
    port = manifest["ssh_port"]
    fingerprint = manifest["host_key_fingerprint"]
    if not (isinstance(host, str) and _SAFE_HOST.match(host)):
        _reject("manifest_host_invalid")
    if not (isinstance(account, str) and _SAFE_ACCOUNT.match(account)):
        _reject("manifest_account_invalid")
    # SECP-B6 F-BLAST: a privileged/reserved account is refused; require a scoped read-only key.
    if account.lower() in _RESERVED_ACCOUNTS:
        _reject("manifest_account_privileged")
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        _reject("manifest_port_invalid")
    if not (isinstance(fingerprint, str) and _FINGERPRINT.match(fingerprint)):
        _reject("manifest_fingerprint_invalid")
    return host, port, account, fingerprint


def _write_private(path: str, data: bytes) -> None:
    """Write ``data`` to a fresh 0600 file (O_EXCL) the worker owns — the ssh-consumed copy."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


class MountedWorkerBootstrapBundleSource:
    """The real worker-only bundle source. Constructed with the FIXED deployment-local mount path;
    validates + reads the bundle on each ``acquire``, failing closed on any problem.

    ``strict`` selects the hardened live-profile path (SECP-B6 F-FS): on POSIX it validates
    file by DESCRIPTOR (``openat``/``fstat``: type, owner, perms, size, ``st_nlink == 1``, same
    device, ``O_NOFOLLOW``), requires a read-only filesystem, and copies the validated ``id_key`` +
    ``known_hosts`` bytes into a fresh worker-private temp dir so the known-hosts verifier and ssh
    consume the exact validated content — immune to a post-validation mount swap. On a non-POSIX
    host the strict path fails closed. ``strict=False`` (default; used in tests / non-live paths)
    keeps the path-based validation.

    ``require_read_only_mount`` (SECP-B8) defaults to True (production strict live profile: the
    bundle is an externally-provisioned read-only mount). It is set False ONLY for the
    WORKER-MANAGED bundle path, where the worker itself owns + wrote the bundle into a writable
    directory (0700 dir / 0600 files, worker-owned). Every OTHER strict protection is retained —
    descriptor pinning (``O_NOFOLLOW`` + fd snapshot), owner==uid, no group/other perms, single
    hardlink, same-device, bounded size, and the worker-private validated copy for ssh — so a
    post-validation swap is still defeated by the pinned descriptor; only the filesystem-RO check
    (which a self-writing worker cannot satisfy) is relaxed."""

    def __init__(
        self, mount_path: str, *, strict: bool = False, require_read_only_mount: bool = True
    ) -> None:
        self._mount_path = mount_path
        self._strict = strict
        self._require_read_only_mount = require_read_only_mount
        self._private_dir: str | None = None
        self._prepared: PreparedDiscoveryBundle | None = None
        # Strict two-phase state: the mount directory fd stays pinned between the metadata phase and
        # the post-admission key-material phase so BOTH read the same descriptor snapshot.
        self._dir_fd: int | None = None
        self._mount_dev: int | None = None

    def prepare_metadata(self) -> PreparedDiscoveryBundle:
        """Phase 1 (SECP-B6 item-4): pin + validate ONLY the NON-secret manifest + binding metadata,
        enough to compute the endpoint-binding digest and the authorization anchor. The private
        ``id_key`` / ``known_hosts`` are NOT read here — call :meth:`finalize_key_material` AFTER
        control-plane admission succeeds. In strict mode the mount dir fd stays pinned so the later
        key read comes from the SAME descriptor snapshot (immune to a post-validation swap)."""
        if self._strict:
            if not _IS_POSIX:
                _reject("mount_non_posix_unsupported")
            endpoint, anchor = self._prepare_metadata_descriptor()
        else:
            endpoint, anchor = self._prepare_metadata_pathbased()
        prepared = PreparedDiscoveryBundle(anchor=anchor, endpoint=endpoint, _source=self)
        self._prepared = prepared
        return prepared

    def finalize_key_material(self) -> None:
        """Phase 2 (SECP-B6 item-4): AFTER admission, read/copy the private ``id_key`` +
        ``known_hosts`` from the SAME pinned descriptor snapshot and complete the SSH bundle.
        Idempotent. Must follow :meth:`prepare_metadata`; key bytes are untouched before this."""
        prepared = self._prepared
        if prepared is None:
            _reject("bundle_not_prepared")
        assert prepared is not None
        if prepared.ssh_bundle is not None:
            return
        if self._strict:
            prepared.ssh_bundle = self._finalize_descriptor(prepared.endpoint)
        else:
            prepared.ssh_bundle = self._finalize_pathbased(prepared.endpoint)

    def acquire(self) -> SshBootstrapBundle:
        # Return the already-validated snapshot so the executor never re-reads the mount by name.
        if self._prepared is not None:
            if self._prepared.ssh_bundle is None:
                # The probe executor must never run before post-admission key material is loaded.
                _reject("bundle_key_material_not_loaded")
            return self._prepared.ssh_bundle
        if self._strict:
            if not _IS_POSIX:
                _reject("mount_non_posix_unsupported")
            return self._acquire_descriptor()
        return self._acquire_pathbased()

    def _acquire_pathbased(self) -> SshBootstrapBundle:
        mount = self._mount_path
        if not (isinstance(mount, str) and mount):
            _reject("mount_path_unset")
        mount_st = _lstat(mount)
        if stat.S_ISLNK(mount_st.st_mode):
            _reject("mount_symlink")
        if not stat.S_ISDIR(mount_st.st_mode):
            _reject("mount_not_directory")
        # The mount must not be writable by group/other (0o022) — defense against tampering.
        _check_owner_and_perms(mount_st, world_perm_mask=0o022, missing_reason="mount")

        manifest_path = os.path.join(mount, _MANIFEST_NAME)
        key_path = os.path.join(mount, _KEY_NAME)
        known_hosts_path = os.path.join(mount, _KNOWN_HOSTS_NAME)

        # Each bundle file: rejected as a symlink first (specific reason), then contained within the
        # real mount, then required to be a bounded, owner-only regular file.
        # Manifest: regular file, not group/other-writable, bounded, well-formed, exact safe keys.
        _require_regular_file(
            mount,
            manifest_path,
            max_bytes=_MAX_MANIFEST_BYTES,
            world_perm_mask=0o022,
            reason="manifest",
        )
        # Private key: regular file, NO group/other access at all (0o077), bounded.
        _require_regular_file(
            mount, key_path, max_bytes=_MAX_KEY_BYTES, world_perm_mask=0o077, reason="key"
        )
        # known_hosts: regular file, not group/other-writable, bounded.
        _require_regular_file(
            mount,
            known_hosts_path,
            max_bytes=_MAX_KNOWN_HOSTS_BYTES,
            world_perm_mask=0o022,
            reason="known_hosts",
        )

        manifest = self._read_manifest(manifest_path)
        host, port, account, fingerprint = _validate_manifest_fields(manifest)
        return SshBootstrapBundle(
            ssh_host=host,
            ssh_port=port,
            account=account,
            private_key_path=key_path,
            known_hosts_path=known_hosts_path,
            host_key_fingerprint=fingerprint,
        )

    def _acquire_descriptor(self) -> SshBootstrapBundle:
        """POSIX descriptor-based strict acquire (SECP-B6 F-FS). Never follows a symlink, pins the
        mount by directory fd, rejects hardlinks / cross-device / non-regular / mis-owned / world-
        writable / oversized files, requires a read-only filesystem, and hands ssh a worker-private
        copy of the validated bytes."""
        mount = self._mount_path
        if not (isinstance(mount, str) and mount):
            _reject("mount_path_unset")
        try:
            dir_fd = os.open(mount, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
        except OSError:
            _reject("mount_open_failed")
        try:
            dst = os.fstat(dir_fd)
            if not stat.S_ISDIR(dst.st_mode):
                _reject("mount_not_directory")
            if _getuid is not None and dst.st_uid != _getuid():
                _reject("mount_not_owned")
            if dst.st_mode & 0o022:
                _reject("mount_bad_permissions")
            if (
                self._require_read_only_mount
                and _statvfs is not None
                and not (_statvfs(dir_fd).f_flag & _ST_RDONLY)
            ):
                _reject("mount_not_read_only")
            mount_dev = dst.st_dev

            manifest_bytes = self._read_regular_at(
                dir_fd, _MANIFEST_NAME, _MAX_MANIFEST_BYTES, 0o022, mount_dev, "manifest"
            )
            manifest = self._parse_bytes(manifest_bytes, _MANIFEST_KEYS, "manifest")
            host, port, account, fingerprint = _validate_manifest_fields(manifest)
            key_bytes = self._read_regular_at(
                dir_fd, _KEY_NAME, _MAX_KEY_BYTES, 0o077, mount_dev, "key"
            )
            known_hosts_bytes = self._read_regular_at(
                dir_fd, _KNOWN_HOSTS_NAME, _MAX_KNOWN_HOSTS_BYTES, 0o022, mount_dev, "known_hosts"
            )
        finally:
            os.close(dir_fd)

        # Copy the validated bytes into a fresh worker-private (0700) dir; the known-hosts verifier
        # and ssh consume THESE inodes, so a swap of the mount after validation cannot take effect.
        private_dir = tempfile.mkdtemp(prefix="secp-b6-bundle-")
        os.chmod(private_dir, 0o700)
        self._private_dir = private_dir
        key_path = os.path.join(private_dir, _KEY_NAME)
        known_hosts_path = os.path.join(private_dir, _KNOWN_HOSTS_NAME)
        _write_private(key_path, key_bytes)
        _write_private(known_hosts_path, known_hosts_bytes)
        return SshBootstrapBundle(
            ssh_host=host,
            ssh_port=port,
            account=account,
            private_key_path=key_path,
            known_hosts_path=known_hosts_path,
            host_key_fingerprint=fingerprint,
        )

    def _prepare_metadata_descriptor(self) -> tuple[SshEndpointMetadata, BundleBindingAnchor]:
        """Phase-1 strict path: pin the mount dir fd, validate + read ONLY the non-secret manifest +
        binding (never id_key/known_hosts), and keep the fd open for the later key phase."""
        mount = self._mount_path
        if not (isinstance(mount, str) and mount):
            _reject("mount_path_unset")
        try:
            dir_fd = os.open(mount, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
        except OSError:
            _reject("mount_open_failed")
        keep_open = False
        try:
            dst = os.fstat(dir_fd)
            if not stat.S_ISDIR(dst.st_mode):
                _reject("mount_not_directory")
            if _getuid is not None and dst.st_uid != _getuid():
                _reject("mount_not_owned")
            if dst.st_mode & 0o022:
                _reject("mount_bad_permissions")
            if (
                self._require_read_only_mount
                and _statvfs is not None
                and not (_statvfs(dir_fd).f_flag & _ST_RDONLY)
            ):
                _reject("mount_not_read_only")
            mount_dev = dst.st_dev
            manifest_bytes = self._read_regular_at(
                dir_fd, _MANIFEST_NAME, _MAX_MANIFEST_BYTES, 0o022, mount_dev, "manifest"
            )
            manifest = self._parse_bytes(manifest_bytes, _MANIFEST_KEYS, "manifest")
            host, port, account, fingerprint = _validate_manifest_fields(manifest)
            binding_bytes = self._read_regular_at(
                dir_fd, _BINDING_NAME, _MAX_BINDING_BYTES, 0o022, mount_dev, "binding"
            )
            anchor = self._build_anchor(self._parse_bytes(binding_bytes, _BINDING_KEYS, "binding"))
            self._dir_fd = dir_fd
            self._mount_dev = mount_dev
            keep_open = True
            return SshEndpointMetadata(host, port, account, fingerprint), anchor
        finally:
            if not keep_open:
                os.close(dir_fd)

    def _finalize_descriptor(self, endpoint: SshEndpointMetadata) -> SshBootstrapBundle:
        """Phase-2 strict path: read/copy id_key + known_hosts from the PINNED descriptor snapshot
        into a fresh worker-private (0700) dir, then close the fd. Same hardlink/inode/cross-device/
        owner/perm protections as the single-shot acquire; immune to a post-metadata mount swap."""
        dir_fd = self._dir_fd
        mount_dev = self._mount_dev
        if dir_fd is None or mount_dev is None:
            _reject("bundle_descriptor_closed")
        assert dir_fd is not None and mount_dev is not None
        try:
            key_bytes = self._read_regular_at(
                dir_fd, _KEY_NAME, _MAX_KEY_BYTES, 0o077, mount_dev, "key"
            )
            known_hosts_bytes = self._read_regular_at(
                dir_fd, _KNOWN_HOSTS_NAME, _MAX_KNOWN_HOSTS_BYTES, 0o022, mount_dev, "known_hosts"
            )
        finally:
            os.close(dir_fd)
            self._dir_fd = None
            self._mount_dev = None
        private_dir = tempfile.mkdtemp(prefix="secp-b6-bundle-")
        os.chmod(private_dir, 0o700)
        self._private_dir = private_dir
        key_path = os.path.join(private_dir, _KEY_NAME)
        known_hosts_path = os.path.join(private_dir, _KNOWN_HOSTS_NAME)
        _write_private(key_path, key_bytes)
        _write_private(known_hosts_path, known_hosts_bytes)
        return SshBootstrapBundle(
            ssh_host=endpoint.ssh_host,
            ssh_port=endpoint.ssh_port,
            account=endpoint.account,
            private_key_path=key_path,
            known_hosts_path=known_hosts_path,
            host_key_fingerprint=endpoint.host_key_fingerprint,
        )

    def _prepare_metadata_pathbased(self) -> tuple[SshEndpointMetadata, BundleBindingAnchor]:
        """Phase-1 non-strict path (tests / non-live): validate the mount + manifest + binding by
        path. Reads NO private key material — only the non-secret manifest + binding.json."""
        mount = self._mount_path
        if not (isinstance(mount, str) and mount):
            _reject("mount_path_unset")
        mount_st = _lstat(mount)
        if stat.S_ISLNK(mount_st.st_mode):
            _reject("mount_symlink")
        if not stat.S_ISDIR(mount_st.st_mode):
            _reject("mount_not_directory")
        _check_owner_and_perms(mount_st, world_perm_mask=0o022, missing_reason="mount")
        manifest_path = os.path.join(mount, _MANIFEST_NAME)
        _require_regular_file(
            mount,
            manifest_path,
            max_bytes=_MAX_MANIFEST_BYTES,
            world_perm_mask=0o022,
            reason="manifest",
        )
        manifest = self._read_manifest(manifest_path)
        host, port, account, fingerprint = _validate_manifest_fields(manifest)
        anchor = self._load_anchor_uncached()
        return SshEndpointMetadata(host, port, account, fingerprint), anchor

    def _finalize_pathbased(self, endpoint: SshEndpointMetadata) -> SshBootstrapBundle:
        """Phase-2 non-strict path: validate the id_key + known_hosts files and build the SSH bundle
        pointing at the mount paths (ssh reads the bytes). Reached only AFTER admission."""
        mount = self._mount_path
        key_path = os.path.join(mount, _KEY_NAME)
        known_hosts_path = os.path.join(mount, _KNOWN_HOSTS_NAME)
        _require_regular_file(
            mount, key_path, max_bytes=_MAX_KEY_BYTES, world_perm_mask=0o077, reason="key"
        )
        _require_regular_file(
            mount,
            known_hosts_path,
            max_bytes=_MAX_KNOWN_HOSTS_BYTES,
            world_perm_mask=0o022,
            reason="known_hosts",
        )
        return SshBootstrapBundle(
            ssh_host=endpoint.ssh_host,
            ssh_port=endpoint.ssh_port,
            account=endpoint.account,
            private_key_path=key_path,
            known_hosts_path=known_hosts_path,
            host_key_fingerprint=endpoint.host_key_fingerprint,
        )

    def _read_regular_at(
        self, dir_fd: int, name: str, max_bytes: int, world_mask: int, mount_dev: int, reason: str
    ) -> bytes:
        try:
            fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)
        except OSError:
            # ELOOP (a symlink, O_NOFOLLOW), ENOENT (missing), etc. all fail closed.
            _reject(reason + "_open_failed")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                _reject(reason + "_not_regular_file")
            if st.st_nlink != 1:
                _reject(reason + "_hardlinked")
            if st.st_dev != mount_dev:
                _reject(reason + "_cross_device")
            if _getuid is not None and st.st_uid != _getuid():
                _reject(reason + "_not_owned")
            if st.st_mode & world_mask:
                _reject(reason + "_bad_permissions")
            if st.st_size <= 0 or st.st_size > max_bytes:
                _reject(reason + "_size_invalid")
            data = os.read(fd, max_bytes + 1)
            if len(data) > max_bytes or len(data) == 0:
                _reject(reason + "_size_invalid")
            return data
        finally:
            os.close(fd)

    def _parse_bytes(self, raw: bytes, keys: frozenset[str], reason: str) -> dict:
        try:
            data = json.loads(raw.decode("utf-8", "strict"))
        except (ValueError, UnicodeDecodeError):
            _reject(reason + "_malformed")
        if not isinstance(data, dict) or set(data.keys()) != keys:
            _reject(reason + "_shape_invalid")
        return data

    def load_anchor(self) -> BundleBindingAnchor:
        """Return the binding anchor — from the prepared snapshot if present, else a fresh read."""
        if self._prepared is not None:
            return self._prepared.anchor
        return self._load_anchor_uncached()

    def _load_anchor_uncached(self) -> BundleBindingAnchor:
        """Read + validate the non-secret authorization anchor (``binding.json``) from the mount.

        Contacts no host and reads no SSH material — a local file read of control-plane IDs only.
        The engine compares this against the claimed job's enrollment and re-verifies the live-read
        authorization BEFORE any SSH invocation. Fails closed with a closed reason on any problem.
        """
        mount = self._mount_path
        if not (isinstance(mount, str) and mount):
            _reject("mount_path_unset")
        mount_st = _lstat(mount)
        if stat.S_ISLNK(mount_st.st_mode):
            _reject("mount_symlink")
        if not stat.S_ISDIR(mount_st.st_mode):
            _reject("mount_not_directory")
        _check_owner_and_perms(mount_st, world_perm_mask=0o022, missing_reason="mount")

        binding_path = os.path.join(mount, _BINDING_NAME)
        _require_regular_file(
            mount,
            binding_path,
            max_bytes=_MAX_BINDING_BYTES,
            world_perm_mask=0o022,
            reason="binding",
        )
        data = self._read_json(binding_path, _MAX_BINDING_BYTES, "binding")
        if not isinstance(data, dict) or set(data.keys()) != _BINDING_KEYS:
            _reject("binding_shape_invalid")
        assert isinstance(data, dict)
        return self._build_anchor(data)

    def _build_anchor(self, data: dict) -> BundleBindingAnchor:
        """Validate a binding dict (already confirmed to have exactly ``_BINDING_KEYS``) into the
        non-secret :class:`BundleBindingAnchor`. Shared by the path-based + descriptor phases."""
        version = data["authorization_version"]
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            _reject("binding_version_invalid")
        ebh = data["endpoint_binding_hash"]
        if not (isinstance(ebh, str) and _ENDPOINT_BINDING_RE.match(ebh)):
            _reject("binding_endpoint_hash_invalid")
        try:
            return BundleBindingAnchor(
                organization_id=uuid.UUID(str(data["organization_id"])),
                execution_target_id=uuid.UUID(str(data["execution_target_id"])),
                onboarding_id=uuid.UUID(str(data["onboarding_id"])),
                enrollment_id=uuid.UUID(str(data["enrollment_id"])),
                authorization_id=uuid.UUID(str(data["authorization_id"])),
                authorization_version=version,
                endpoint_binding_hash=ebh,
            )
        except (ValueError, AttributeError, TypeError):
            _reject("binding_id_invalid")
            raise  # unreachable

    def _read_manifest(self, path: str) -> dict:
        data = self._read_json(path, _MAX_MANIFEST_BYTES, "manifest")
        if not isinstance(data, dict) or set(data.keys()) != _MANIFEST_KEYS:
            _reject("manifest_shape_invalid")
        return data

    def _read_json(self, path: str, max_bytes: int, reason: str) -> object:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(max_bytes + 1)
        except OSError:
            _reject(reason + "_unreadable")
            raise  # unreachable
        if len(raw) > max_bytes:
            _reject(reason + "_size_invalid")
        try:
            return json.loads(raw.decode("utf-8", "strict"))
        except (ValueError, UnicodeDecodeError):
            _reject(reason + "_malformed")
            raise  # unreachable

    def dispose(self) -> None:
        # When a prepared snapshot is active the ENGINE owns its lifecycle (via
        # PreparedDiscoveryBundle.dispose); a per-probe-session dispose is a NO-OP — otherwise the
        # first probe session would delete the worker-private copy the next session still needs.
        if self._prepared is not None:
            return
        self._finalize_private_dir()

    def _finalize_private_dir(self) -> None:
        # Remove the worker-private copy of the validated key/known_hosts (strict) AND close the
        # pinned mount descriptor if the run refused before the key-material phase. The mount itself
        # persists and is read-only; nothing else sensitive is held in memory. Called on every path.
        self._prepared = None
        dir_fd = self._dir_fd
        self._dir_fd = None
        self._mount_dev = None
        if dir_fd is not None:
            try:
                os.close(dir_fd)
            except OSError:
                pass
        private_dir = self._private_dir
        self._private_dir = None
        if private_dir is not None:
            shutil.rmtree(private_dir, ignore_errors=True)
