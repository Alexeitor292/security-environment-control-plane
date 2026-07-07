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
import stat

from secp_worker.ssh_channel import (
    BootstrapBundleUnavailable,
    SshBootstrapBundle,
    SshChannelError,
)

# Fixed bundle layout inside the mount directory. Names are constants (no traversal is possible).
_MANIFEST_NAME = "manifest.json"
_KEY_NAME = "id_key"
_KNOWN_HOSTS_NAME = "known_hosts"

# Bounded sizes — a real bundle is tiny; an oversized file fails closed.
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_KEY_BYTES = 64 * 1024
_MAX_KNOWN_HOSTS_BYTES = 256 * 1024

# Safe manifest values (host/account are safe tokens; port a bounded int; fingerprint the SSH SHA256
# form). No shell/path/whitespace characters are permitted.
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
_SAFE_ACCOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_MANIFEST_KEYS = frozenset({"ssh_host", "ssh_port", "account", "host_key_fingerprint"})

_IS_POSIX = os.name == "posix"


class MountedBundleRejected(BootstrapBundleUnavailable):
    """The mounted bundle failed a strict validation check. A subclass of
    :class:`BootstrapBundleUnavailable` (so the executor's fail-closed handling catches it) carrying
    a
    CLOSED reason code — never a raw host/account/port/path/key/fingerprint value."""

    def __init__(self, reason_code: str = "mounted_bundle_invalid") -> None:
        SshChannelError.__init__(self, reason_code)  # closed reason; skip the fixed parent message


def _reject(reason_code: str) -> None:
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
        if st.st_uid != os.getuid():  # type: ignore[attr-defined]
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


class MountedWorkerBootstrapBundleSource:
    """The real worker-only bundle source. Constructed with the FIXED deployment-local mount path;
    validates + reads the bundle on each ``acquire``, failing closed on any problem."""

    def __init__(self, mount_path: str) -> None:
        self._mount_path = mount_path

    def acquire(self) -> SshBootstrapBundle:
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
        host = manifest["ssh_host"]
        account = manifest["account"]
        port = manifest["ssh_port"]
        fingerprint = manifest["host_key_fingerprint"]
        if not (isinstance(host, str) and _SAFE_HOST.match(host)):
            _reject("manifest_host_invalid")
        if not (isinstance(account, str) and _SAFE_ACCOUNT.match(account)):
            _reject("manifest_account_invalid")
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            _reject("manifest_port_invalid")
        if not (isinstance(fingerprint, str) and _FINGERPRINT.match(fingerprint)):
            _reject("manifest_fingerprint_invalid")

        return SshBootstrapBundle(
            ssh_host=host,
            ssh_port=port,
            account=account,
            private_key_path=key_path,
            known_hosts_path=known_hosts_path,
            host_key_fingerprint=fingerprint,
        )

    def _read_manifest(self, path: str) -> dict:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(_MAX_MANIFEST_BYTES + 1)
        except OSError:
            _reject("manifest_unreadable")
            raise  # unreachable
        if len(raw) > _MAX_MANIFEST_BYTES:
            _reject("manifest_size_invalid")
        try:
            data = json.loads(raw.decode("utf-8", "strict"))
        except (ValueError, UnicodeDecodeError):
            _reject("manifest_malformed")
            raise  # unreachable
        if not isinstance(data, dict) or set(data.keys()) != _MANIFEST_KEYS:
            _reject("manifest_shape_invalid")
        return data

    def dispose(self) -> None:
        # Nothing sensitive is held in memory (the bundle carries only paths + already-disposed
        # metadata); the mount persists and is read by ssh directly. No-op by design.
        return None
