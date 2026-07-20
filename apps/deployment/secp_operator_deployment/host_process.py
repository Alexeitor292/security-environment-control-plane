"""Hardened, bounded, streaming local command seam for the real-host adapters (SECP-PR5D, blocker
#2).

This is the ONLY module permitted to spawn a subprocess. It executes a PINNED executable OBJECT
(:mod:`pinned_exec`, blocker #3) via ``/proc/self/fd/<fd>`` — never a re-resolved pathname — under
strict constraints: ``shell=False``; an exact explicit environment with no inheritance of the
ambient
process environment; ``stdin=DEVNULL``; a fresh session/process group; validated positive-bounded
``timeout_seconds`` + ``max_output_bytes``; stdout read INCREMENTALLY (never fully captured then
checked) and bounded to ``max + a small detection buffer``; stderr discarded; and on timeout OR
output overflow the ENTIRE process group is terminated (SIGTERM → bounded grace → SIGKILL → bounded
reap), failing closed (``command_reap_failed``) if termination/reap cannot be proven. Every
failure is
redacted to a bounded reason code — never an argv, path, output, exception, or upstream message.

POSIX only; a non-POSIX host refuses. Tests inject a fake runner for the cross-platform adapter
logic
and exercise the real streaming/kill/pinning behaviour under POSIX real-process tests.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess  # noqa: S404 - the single reviewed subprocess seam; hardened below
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment.pinned_exec import (
    ExecutablePin,
    open_pinned_executable,
    pinned_exec_path,
)

# Exact, explicit child environment — never inherited from the ambient process environment.
_FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_MAX_TIMEOUT_SECONDS = 3600
_MAX_OUTPUT_CAP = 16 * 1024 * 1024
_DETECTION_BUFFER = 4096
_GRACE_SECONDS = 2.0
_KILL_DEADLINE_SECONDS = 5.0
_REAP_SECONDS = 3.0
_PROBE_INTERVAL_SECONDS = 0.02


@dataclass(frozen=True, repr=False)
class CommandResult:
    """The closed, bounded result of one local inspection command."""

    exit_code: int
    stdout: str

    def __repr__(self) -> str:
        stdout_bytes = len(self.stdout.encode("utf-8"))
        return f"CommandResult(exit_code={self.exit_code}, stdout_bytes={stdout_bytes})"


class CommandRunner(Protocol):
    def run(
        self,
        pin: ExecutablePin,
        argv_tail: Sequence[str],
        *,
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> CommandResult: ...


def _group_alive(pgid: int) -> bool:
    """Probe whether ANY process remains in the group via ``killpg(pgid, 0)``. ESRCH → gone; EPERM →
    a process exists (conservatively alive); success → alive. This inspects the WHOLE group, so a
    surviving grandchild that ignored SIGTERM is detected even after the group leader exits."""
    try:
        os.killpg(pgid, 0)  # type: ignore[attr-defined]  # POSIX-only; signal 0 = existence probe
        return True
    except ProcessLookupError:  # ESRCH — no process in the group
        return False
    except PermissionError:  # EPERM — a process exists but is not ours; treat as alive
        return True
    except OSError:
        return True


def _wait_group_gone(pgid: int, deadline: float) -> bool:
    while time.monotonic() < deadline:
        if not _group_alive(pgid):
            return True
        time.sleep(_PROBE_INTERVAL_SECONDS)
    return not _group_alive(pgid)


def _reap(proc: subprocess.Popen, timeout: float) -> bool:
    """Reap the direct child within ``timeout``. True if reaped; False if it is still running."""
    try:
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False


def _terminate_group(proc: subprocess.Popen, pgid: int | None) -> None:
    """Terminate the ENTIRE process group and PROVE it disappeared — never inferring group death
    from the leader's exit. SIGTERM the group → reap OUR direct child within a bounded grace so its
    zombie stops MASKING the group's liveness → if any member still survives (e.g. a
    SIGTERM-ignoring grandchild), SIGKILL the whole group → ensure the direct child is reaped (never
    a zombie) → PROVE the group is empty by polling ``killpg(pgid, 0)`` for ESRCH within a bounded
    deadline. Refuses with a bounded recovery-required reason (``command_reap_failed`` /
    ``command_group_not_terminated``) if the child cannot be reaped or the group cannot be proven
    gone. Every raise uses ``from None`` so that, even when this runs inside an active ``except``
    handler (the streaming-OSError or reap-timeout paths), the bounded reason NEVER carries a
    chained raw OS exception as ``__context__``. Never surfaces a pid/path/argv/output/exception."""
    if pgid is None:
        # No group to prove (spawn state unknown) — reap the direct child and fail closed.
        if not _reap(proc, _REAP_SECONDS):
            raise DeploymentPackageError("command_reap_failed") from None
        raise DeploymentPackageError("command_group_unknown") from None

    try:
        os.killpg(pgid, signal.SIGTERM)  # type: ignore[attr-defined]  # POSIX-only
    except OSError:
        pass
    # Reap the direct child FIRST: a well-behaved leader exits on SIGTERM within the grace, and
    # removing its zombie means the probe below reflects only surviving DESCENDANTS (an unreaped
    # leader zombie would itself answer killpg(pgid, 0) as alive and mask them).
    leader_reaped = _reap(proc, _GRACE_SECONDS)
    if _group_alive(pgid):
        # A SIGTERM-ignoring member survives — escalate to the whole group; nothing survives a KILL.
        try:
            os.killpg(pgid, signal.SIGKILL)  # type: ignore[attr-defined]  # POSIX-only
        except OSError:
            pass
    # Guarantee the direct child is reaped (the SIGKILL above forces a SIGTERM-ignoring leader out).
    if not leader_reaped and not _reap(proc, _REAP_SECONDS):
        raise DeploymentPackageError("command_reap_failed") from None
    # With the direct child reaped, PROVE the whole group disappeared: poll killpg(pgid, 0) for
    # ESRCH (init reaps SIGKILLed orphaned descendants promptly) within a bounded deadline, else
    # refuse.
    if not _wait_group_gone(pgid, time.monotonic() + _KILL_DEADLINE_SECONDS):
        raise DeploymentPackageError("command_group_not_terminated") from None


class RealCommandRunner:
    """Production hardened, bounded, streaming runner that execs a pinned executable object."""

    def __init__(self, *, require_root: bool = True) -> None:
        self._require_root = require_root

    def run(
        self,
        pin: ExecutablePin,
        argv_tail: Sequence[str],
        *,
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> CommandResult:
        if os.name != "posix":
            raise DeploymentPackageError("command_backend_non_posix")
        if not (isinstance(timeout_seconds, int) and 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS):
            raise DeploymentPackageError("command_timeout_invalid")
        if not (isinstance(max_output_bytes, int) and 0 < max_output_bytes <= _MAX_OUTPUT_CAP):
            raise DeploymentPackageError("command_output_bound_invalid")
        tail = list(argv_tail)
        if any(not isinstance(a, str) for a in tail):
            raise DeploymentPackageError("command_argv_invalid")

        fd = open_pinned_executable(pin, require_root=self._require_root)
        exec_path = pinned_exec_path(fd)
        hard_cap = max_output_bytes + _DETECTION_BUFFER
        try:
            try:
                proc = subprocess.Popen(  # noqa: S603 - pinned object, fixed env, no shell, no stdin
                    [pin.path, *tail],
                    executable=exec_path,
                    env=dict(_FIXED_ENV),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=(fd,),  # the verified object stays reachable via /proc/self/fd/<fd>
                    start_new_session=True,  # fresh session + process group for group-kill
                )
            except OSError:
                raise DeploymentPackageError("command_spawn_failed") from None

            # Capture the process-GROUP id immediately after spawn (start_new_session → the child
            # is a session/group leader, so pgid == child pid). Group termination is proven against
            # THIS id.
            try:
                pgid: int | None = os.getpgid(proc.pid)  # type: ignore[attr-defined]  # POSIX-only
            except OSError:
                pgid = None

            buf = bytearray()
            timed_out = False
            overflow = False
            deadline = time.monotonic() + timeout_seconds
            stdout = proc.stdout
            assert stdout is not None
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    ready, _, _ = select.select([stdout], [], [], remaining)
                    if not ready:
                        timed_out = True
                        break
                    # Read at most enough to cross hard_cap by one byte — memory is bounded BY
                    # DESIGN to hard_cap (max + a small detection buffer), never a full pipe chunk.
                    want = min(1 << 16, hard_cap - len(buf) + 1)
                    chunk = os.read(stdout.fileno(), want)
                    if not chunk:
                        break  # EOF
                    buf += chunk
                    if len(buf) > hard_cap:
                        overflow = True
                        break
            except OSError:
                # A mid-stream pipe/read failure (e.g. EIO/EBADF) must NEVER leave the child or its
                # group orphaned, and must NEVER surface a raw errno/exception: terminate + prove
                # the group gone (or a recovery-required refusal), then fail closed with a bounded
                # reason.
                _terminate_group(proc, pgid)
                raise DeploymentPackageError("command_stream_failed") from None
            finally:
                try:
                    stdout.close()
                except OSError:
                    pass

            if timed_out or overflow:
                _terminate_group(proc, pgid)  # proves the whole group disappeared (or refuses)
                raise DeploymentPackageError(
                    "command_timeout" if timed_out else "command_output_too_large"
                )

            try:
                code = proc.wait(timeout=_REAP_SECONDS)
            except subprocess.TimeoutExpired:
                _terminate_group(proc, pgid)
                raise DeploymentPackageError("command_reap_failed") from None
            if len(buf) > max_output_bytes:
                raise DeploymentPackageError("command_output_too_large")
            return CommandResult(exit_code=int(code), stdout=bytes(buf).decode("utf-8", "replace"))
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
