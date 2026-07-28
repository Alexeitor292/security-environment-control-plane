"""Plane-neutral hardened fixed-handoff reader (SECP-PR5H-B2, 2b-3b C2).

The controller-install API-plane one-shots (identity activation, signer-role provisioning) receive a
root-written handoff bind-mounted read-only at a FIXED code-owned path. This reader independently
authenticates that filesystem object before any byte is trusted — it never relies on the caller's
path being safe, and it closes the lstat-then-open TOCTOU gap:

* POSIX production host (off POSIX it fails closed — production is POSIX);
* the fixed expected path only (no caller-selected production path);
* trusted ancestors (each non-group/other-writable, sticky-world-writable like ``/run`` permitted);
* ``O_NOFOLLOW`` open (a final-component symlink is refused by the kernel), then fstat the OPENED
  DESCRIPTOR — never an lstat-then-open;
* the descriptor must be a regular, single-link (``nlink == 1``), uid-0 file whose group is EXACTLY
  the expected API service group, mode EXACTLY ``0640``;
* a bounded read, and a before/after descriptor identity sample (device, inode, type, uid, gid,
  mode, nlink, size, mtime) so a swap or mutation during the read is refused as drift.

Every failure is a bounded :class:`HardenedHandoffError` reason code — never a path, byte, or raw
exception. Tests inject a verified-reader seam rather than weakening this production reader.
"""

from __future__ import annotations

import os
import stat
from typing import NoReturn

from secp_commissioning.errors import CommissioningError

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_EXPECTED_MODE = 0o640


class HardenedHandoffError(CommissioningError):
    """A bounded, closed handoff-read refusal — only a reason code, never a path or byte."""


def _reject(reason_code: str) -> NoReturn:
    raise HardenedHandoffError(reason_code)


def _require_posix() -> None:
    if os.name != "posix":
        _reject("handoff_reader_unsupported_platform")


def _assert_trusted_ancestors(path: str) -> None:
    cur = os.path.dirname(os.path.abspath(path)) or os.sep
    while True:
        try:
            st = os.lstat(cur)
        except OSError:
            _reject("handoff_ancestor_unsafe")
        # untrusted if a symlink, or group/other-writable WITHOUT the sticky bit (a sticky
        # world-writable dir like /run is safe: only the owner can rename/delete entries).
        if stat.S_ISLNK(st.st_mode) or ((st.st_mode & 0o022) and not (st.st_mode & stat.S_ISVTX)):
            _reject("handoff_ancestor_unsafe")
        nxt = os.path.dirname(cur)
        if nxt == cur:
            return
        cur = nxt


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        st.st_dev,
        st.st_ino,
        stat.S_IFMT(st.st_mode),
        st.st_uid,
        st.st_gid,
        stat.S_IMODE(st.st_mode),
        st.st_nlink,
        st.st_size,
    )


def read_hardened_fixed_handoff(
    path: str, *, expected_gid: int, max_bytes: int, expected_uid: int = 0
) -> bytes:
    """Authenticate the fixed handoff object and return its exact bytes, or raise a bounded
    :class:`HardenedHandoffError`. POSIX-only; the caller passes the FIXED path + the exact expected
    API service group + a bounded size. ``expected_uid`` defaults to 0 (the production root writer);
    the hermetic reader tests pass the test process's own uid to exercise the
    mode/nlink/symlink/drift checks on a file a non-root CI can actually create — production always
    uses the root default."""
    _require_posix()
    if not os.path.isabs(path):
        _reject("handoff_path_not_absolute")
    _assert_trusted_ancestors(path)
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError:
        _reject("handoff_unreadable")  # missing, a symlink (ELOOP under O_NOFOLLOW), or denied
    try:
        st1 = os.fstat(fd)
        if (
            not stat.S_ISREG(st1.st_mode)
            or stat.S_ISLNK(st1.st_mode)
            or st1.st_uid != int(expected_uid)
            or st1.st_gid != int(expected_gid)
            or st1.st_nlink != 1
            or stat.S_IMODE(st1.st_mode) != _EXPECTED_MODE
        ):
            _reject("handoff_object_unsafe")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            block = os.read(fd, 1 << 16)
            if not block:
                break
            chunks.append(block)
            total += len(block)
        st2 = os.fstat(fd)
    finally:
        os.close(fd)
    if total > max_bytes:
        _reject("handoff_too_large")
    if _identity(st1) != _identity(st2) or st1.st_mtime_ns != st2.st_mtime_ns:
        _reject("handoff_changed_during_read")  # swapped/mutated mid-read
    return b"".join(chunks)


__all__ = ["HardenedHandoffError", "read_hardened_fixed_handoff"]
