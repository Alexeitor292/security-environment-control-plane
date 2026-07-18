"""Executable OBJECT pinning for the host adapters (SECP-PR5D, blocker #3), POSIX.

An absolute path is not sufficient — a path can be replaced between check and exec. Following the
PR5B executable-object-pinning precedent, every host-invoked executable is opened ``O_NOFOLLOW``,
fstat-verified to be a regular, single-hardlink, trusted-ownership/mode object, stream-hashed, and
compared to the independently reviewed digest; the EXACT opened object is then executed via
``/proc/self/fd/<fd>`` (the descriptor kept open through spawn), never by re-resolving the
pathname —
so a replacement race is rejected. No PATH lookup; a merely-absolute profile-supplied executable
never runs on its path alone.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass

from secp_operator_deployment import DeploymentPackageError

_WRITE_MASK = 0o022  # no group/other write on a trusted executable
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024


class ExecutablePinError(DeploymentPackageError):
    """A pinned executable failed object verification (bounded reason code; never a path/digest)."""


@dataclass(frozen=True)
class ExecutablePin:
    """The independently reviewed identity of one host-invoked executable."""

    path: str
    digest: str  # sha256:<64-hex>


def open_pinned_executable(pin: ExecutablePin, *, require_root: bool = True) -> int:
    """Open + verify the pinned executable object; return the OPEN fd (caller MUST close it after
    spawn). Verifies: absolute path, O_NOFOLLOW open, regular file, exactly one hardlink,
    non-group/other-writable, (by default) root-owned, bounded size, and an EXACT streamed SHA-256
    match to the reviewed digest. ``require_root`` is relaxed only by tests that exercise the
    non-ownership checks on a user-owned sandbox binary."""
    if os.name != "posix":
        raise ExecutablePinError("executable_pinning_non_posix")
    if not (isinstance(pin.path, str) and pin.path.startswith("/")):
        raise ExecutablePinError("executable_not_absolute")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(pin.path, os.O_RDONLY | no_follow)
    except OSError:
        raise ExecutablePinError("executable_open_failed") from None
    ok = False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ExecutablePinError("executable_not_regular")
        if st.st_nlink != 1:
            raise ExecutablePinError("executable_hardlinked")
        if require_root and st.st_uid != 0:
            raise ExecutablePinError("executable_untrusted_owner")
        if stat.S_IMODE(st.st_mode) & _WRITE_MASK:
            raise ExecutablePinError("executable_untrusted_mode")
        if st.st_size <= 0 or st.st_size > _MAX_EXECUTABLE_BYTES:
            raise ExecutablePinError("executable_size_invalid")
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            h.update(chunk)
        if "sha256:" + h.hexdigest() != pin.digest:
            raise ExecutablePinError("executable_digest_mismatch")
        ok = True
        return fd
    finally:
        if not ok:
            os.close(fd)


def pinned_exec_path(fd: int) -> str:
    """The path used to execute the EXACT verified object (never the original pathname)."""
    return f"/proc/self/fd/{fd}"
