"""Real POSIX process behaviour for the bounded streaming runner (SECP-PR5D, blocker #2 + #3).

Proves, against real child processes, that output is bounded by DESIGN (never fully captured then
checked), that an over-producing child is terminated on overflow, that a timeout kills the process
group, that no orphan remains, and that the runner executes the EXACT pinned object. Uses copies of
system coreutils (nlink=1, 0755, user-owned) pinned with ``require_root=False``. Skips on non-POSIX.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="real-process runner is POSIX-only")


def _pin_system_binary(tmp_path, logical_name, *candidates):
    src = None
    for c in candidates:
        real = shutil.which(c) or c
        if os.path.exists(real):
            src = os.path.realpath(real)
            break
    if src is None:
        pytest.skip(f"none of {candidates} available")
    dest = str(tmp_path / logical_name)
    shutil.copy(src, dest)
    os.chmod(dest, 0o755)
    from secp_operator_deployment.pinned_exec import ExecutablePin

    data = open(dest, "rb").read()
    return ExecutablePin(dest, "sha256:" + hashlib.sha256(data).hexdigest())


def _runner():
    from secp_operator_deployment.host_process import RealCommandRunner

    return RealCommandRunner(require_root=False)


def test_pinned_object_executes_and_returns_bounded_output(tmp_path):
    pin = _pin_system_binary(tmp_path, "echo", "echo", "/bin/echo", "/usr/bin/echo")
    result = _runner().run(pin, ("ok",), timeout_seconds=10, max_output_bytes=1024)
    assert result.exit_code == 0 and "ok" in result.stdout


def test_over_producing_child_is_killed_on_overflow(tmp_path):
    from secp_operator_deployment import DeploymentPackageError

    pin = _pin_system_binary(tmp_path, "yes", "yes", "/usr/bin/yes", "/bin/yes")
    with pytest.raises(DeploymentPackageError) as exc:
        # `yes` produces unbounded output; the runner must detect overflow, kill the group, and
        # reap.
        _runner().run(pin, (), timeout_seconds=10, max_output_bytes=1024)
    assert exc.value.reason_code == "command_output_too_large"


def test_timeout_kills_the_process_group(tmp_path):
    from secp_operator_deployment import DeploymentPackageError

    pin = _pin_system_binary(tmp_path, "sleep", "sleep", "/bin/sleep", "/usr/bin/sleep")
    with pytest.raises(DeploymentPackageError) as exc:
        _runner().run(pin, ("30",), timeout_seconds=1, max_output_bytes=1024)
    assert exc.value.reason_code == "command_timeout"


def test_invalid_bounds_refuse(tmp_path):
    from secp_operator_deployment import DeploymentPackageError

    pin = _pin_system_binary(tmp_path, "echo", "echo", "/bin/echo", "/usr/bin/echo")
    r = _runner()
    with pytest.raises(DeploymentPackageError) as e1:
        r.run(pin, ("x",), timeout_seconds=0, max_output_bytes=1024)
    assert e1.value.reason_code == "command_timeout_invalid"
    with pytest.raises(DeploymentPackageError) as e2:
        r.run(pin, ("x",), timeout_seconds=10, max_output_bytes=0)
    assert e2.value.reason_code == "command_output_bound_invalid"


def test_digest_mismatch_prevents_execution(tmp_path):
    from secp_operator_deployment import DeploymentPackageError
    from secp_operator_deployment.pinned_exec import ExecutablePin

    pin = _pin_system_binary(tmp_path, "echo", "echo", "/bin/echo", "/usr/bin/echo")
    tampered = ExecutablePin(pin.path, "sha256:" + "0" * 64)
    with pytest.raises(DeploymentPackageError) as exc:
        _runner().run(tampered, ("ok",), timeout_seconds=10, max_output_bytes=1024)
    assert exc.value.reason_code == "executable_digest_mismatch"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _poll_gone(predicate, timeout: float = 8.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not predicate():
            return True
        time.sleep(0.05)
    return not predicate()


# The leader is the process-group leader (start_new_session → pgid == leader pid). It forks a
# grandchild subshell IN THE SAME GROUP that TRAPS (ignores) SIGTERM and loops forever, so a group
# SIGTERM alone can NEVER clear the group — only the escalated SIGKILL can. The leader records its
# own pid (== pgid) and the grandchild pid, then blocks. `$$` is the leader's pid; `$!` is the
# grandchild.
_LEADER_WITH_STUBBORN_GRANDCHILD = (
    "{ trap '' TERM; while :; do sleep 1; done; } &\n"
    "gc=$!\n"
    'echo "$$ $gc" > "$1"\n'
    "while :; do sleep 1; done\n"
)


def test_timeout_proves_full_group_disappearance_no_orphan(tmp_path):
    # Blocker #1: a group leader whose SIGTERM-ignoring grandchild survives the graceful signal
    # must still be fully terminated. After the bounded SIGTERM→grace→SIGKILL→reap sequence, BOTH
    # the leader and the grandchild are gone, killpg(pgid, 0) returns ESRCH, and no orphan remains.
    from secp_operator_deployment import DeploymentPackageError

    sh = _pin_system_binary(tmp_path, "sh", "sh", "/bin/sh", "/usr/bin/sh")
    if shutil.which("sleep") is None and not os.path.exists("/bin/sleep"):
        pytest.skip("sleep not available")
    record = tmp_path / "grouprec.txt"

    with pytest.raises(DeploymentPackageError) as exc:
        _runner().run(
            sh,
            ("-c", _LEADER_WITH_STUBBORN_GRANDCHILD, "secp-leader", str(record)),
            timeout_seconds=2,
            max_output_bytes=1024,
        )
    # The runner must PROVE group disappearance before returning — never a group-not-terminated /
    # reap-failed refusal (which would mean an orphan could remain).
    assert exc.value.reason_code == "command_timeout"

    pgid_str, gc_str = record.read_text(encoding="utf-8").split()
    pgid, grandchild = int(pgid_str), int(gc_str)

    # The whole group disappeared: killpg(pgid, 0) == ESRCH (not merely the leader's own exit).
    assert _poll_gone(lambda: _group_alive(pgid)), (
        "process group did not disappear (killpg != ESRCH)"
    )
    # Both the leader (== pgid) and the SIGTERM-ignoring grandchild are gone — no orphan survives.
    assert _poll_gone(lambda: _pid_alive(pgid)), "leader survived"
    assert _poll_gone(lambda: _pid_alive(grandchild)), "SIGTERM-ignoring grandchild orphaned"
