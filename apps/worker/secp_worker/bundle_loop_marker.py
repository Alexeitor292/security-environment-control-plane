"""Process-instance-bound marker for the worker-owned discovery bundle loop.

The production activation probe runs in a short-lived ``docker exec`` process, so an in-memory
thread flag cannot prove that the ordinary worker's bundle-preparation thread started.  This module
publishes one fixed, non-secret tmpfs marker containing the worker PID and its Linux process start
tick.  A probe accepts the marker only when it names the same live PID as the ordinary readiness
marker and ``/proc`` still reports the exact start tick.  PID reuse therefore cannot turn a stale
marker into current activation evidence.

The marker contains no key, endpoint, credential, or environment value.  Importing this module is
side-effect free.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile

BUNDLE_PREP_LOOP_MARKER_PATH = "/tmp/secp-discovery-bundle-prep.ready"  # noqa: S108

_MAX_MARKER_BYTES = 96
_MARKER_PATTERN = re.compile(rb"v1 ([1-9][0-9]{0,9}) ([1-9][0-9]{0,31})\n")
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class BundleLoopMarkerError(RuntimeError):
    """Closed marker failure that never includes filesystem or process data."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _effective_uid() -> int | None:
    getter = getattr(os, "geteuid", None)
    return getter() if getter is not None else None


def _process_start_tick(pid: int) -> int:
    """Return Linux ``/proc/<pid>/stat`` field 22 using one bounded, no-follow read."""

    if type(pid) is not int or not 1 <= pid <= 2**31 - 1:
        raise BundleLoopMarkerError("bundle_loop_process_invalid")
    try:
        fd = os.open(f"/proc/{pid}/stat", os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError:
        raise BundleLoopMarkerError("bundle_loop_process_unavailable") from None
    try:
        raw = os.read(fd, 4097)
    except OSError:
        raise BundleLoopMarkerError("bundle_loop_process_unavailable") from None
    finally:
        os.close(fd)
    if not raw or len(raw) > 4096:
        raise BundleLoopMarkerError("bundle_loop_process_invalid")
    # The parenthesized comm field may itself contain spaces or ``)``.  Splitting after the final
    # close parenthesis leaves field 3 (state) at index 0 and field 22 (starttime) at index 19.
    close = raw.rfind(b")")
    fields = raw[close + 1 :].split() if close >= 0 else []
    if len(fields) <= 19:
        raise BundleLoopMarkerError("bundle_loop_process_invalid")
    try:
        tick = int(fields[19])
    except ValueError:
        raise BundleLoopMarkerError("bundle_loop_process_invalid") from None
    if tick <= 0:
        raise BundleLoopMarkerError("bundle_loop_process_invalid")
    return tick


def _read_marker(path: str) -> tuple[int, int, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError:
        raise BundleLoopMarkerError("bundle_loop_marker_unavailable") from None
    try:
        metadata = os.fstat(fd)
        effective_uid = _effective_uid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (effective_uid is not None and metadata.st_uid != effective_uid)
            or metadata.st_mode & 0o7777 != 0o600
            or not 1 <= metadata.st_size <= _MAX_MARKER_BYTES
        ):
            raise BundleLoopMarkerError("bundle_loop_marker_metadata_invalid")
        raw = os.read(fd, _MAX_MARKER_BYTES + 1)
    except OSError:
        raise BundleLoopMarkerError("bundle_loop_marker_unavailable") from None
    finally:
        os.close(fd)
    if len(raw) != metadata.st_size:
        raise BundleLoopMarkerError("bundle_loop_marker_read_invalid")
    match = _MARKER_PATTERN.fullmatch(raw)
    if match is None:
        raise BundleLoopMarkerError("bundle_loop_marker_format_invalid")
    return int(match.group(1)), int(match.group(2)), metadata


def mark_started() -> None:
    """Atomically publish a 0600 marker for this exact worker process instance."""

    path = BUNDLE_PREP_LOOP_MARKER_PATH
    pid = os.getpid()
    tick = _process_start_tick(pid)
    payload = f"v1 {pid} {tick}\n".encode("ascii")
    directory = os.path.dirname(path)
    if directory != "/tmp" or os.path.basename(path) != "secp-discovery-bundle-prep.ready":
        raise BundleLoopMarkerError("bundle_loop_marker_path_invalid")

    fd = -1
    temporary = ""
    try:
        fd, temporary = tempfile.mkstemp(prefix=".secp-bundle-loop-", dir=directory)
        fchmod = getattr(os, "fchmod", None)
        if fchmod is None:
            raise BundleLoopMarkerError("bundle_loop_marker_write_failed")
        fchmod(fd, 0o600)
        written = os.write(fd, payload)
        if written != len(payload):
            raise BundleLoopMarkerError("bundle_loop_marker_write_failed")
        os.fsync(fd)
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o7777 != 0o600
            or metadata.st_size != len(payload)
        ):
            raise BundleLoopMarkerError("bundle_loop_marker_metadata_invalid")
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        temporary = ""
        marker_pid, marker_tick, _metadata = _read_marker(path)
        if marker_pid != pid or marker_tick != tick:
            raise BundleLoopMarkerError("bundle_loop_marker_install_invalid")
    except BundleLoopMarkerError:
        raise
    except OSError:
        raise BundleLoopMarkerError("bundle_loop_marker_write_failed") from None
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def is_current(*, expected_worker_pid: int) -> bool:
    """Return true only for this exact live worker process instance and readiness PID."""

    try:
        marker_pid, marker_tick, _metadata = _read_marker(BUNDLE_PREP_LOOP_MARKER_PATH)
        return bool(
            marker_pid == expected_worker_pid
            and marker_tick == _process_start_tick(expected_worker_pid)
        )
    except BundleLoopMarkerError:
        return False


def clear_started() -> None:
    """Remove only a valid marker owned by the current worker UID."""

    path = BUNDLE_PREP_LOOP_MARKER_PATH
    try:
        _pid, _tick, expected = _read_marker(path)
    except BundleLoopMarkerError:
        return
    try:
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            return
        os.unlink(path)
    except (FileNotFoundError, OSError):
        return


__all__ = [
    "BUNDLE_PREP_LOOP_MARKER_PATH",
    "BundleLoopMarkerError",
    "mark_started",
    "is_current",
    "clear_started",
]
