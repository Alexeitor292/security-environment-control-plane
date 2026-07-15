"""B1B-PR5B — the plan-only executor as the FINAL enforcement boundary (ADR-022 §2/§4).

The hardened :class:`PlanOnlyProcessExecutor` does not trust the orchestration: at construction it
independently re-checks a MANDATORY capability (type / classification / expiry / contract / exact
implementation digest / exact lease-attempt-fingerprint identity) and the exact execution context
(absolute safe workspace/executable/mirror, plan file a direct workspace child, the exact closed
child-env key set + contract version). At ``run`` it re-validates the argv, re-verifies the attested
executable/mirror/CLI identity immediately before spawn (TOCTOU), and enforces genuinely bounded,
strictly-decoded, process-group-isolated I/O. These prove each of those checks independently for
BOTH construction paths now that the plan-only seal is ``False``: the production issuer
(``issue_plan_only_executor``; controlled-live capability) and the token-gated test-only path
(inert fixture; test-only capability). ``run`` is exercised against tiny inert POSIX fixtures.
"""

from __future__ import annotations

import contextlib
import os
import stat
import sys
import uuid
from datetime import timedelta

import pytest
from secp_api.plan_activation_contract import PLAN_SECRET_ENV_CONTRACT_VERSION
from secp_worker.plan_gen.process_boundary import (
    PlanOnlyExecutionContext,
    PlanOnlyProcessError,
    PlanOnlyProcessExecutor,
    build_init_command,
    build_show_command,
    issue_plan_only_executor,
)
from tests._plan_only_fixtures import (
    NOW,
    build_controlled_live_capability,
    build_test_only_capability,
    exact_child_env,
    make_context,
    real_attested,
    stub_attested,
)

_FP = "sha256:" + "c" * 64


def _cap(**over):
    return build_test_only_capability(
        lease_id=uuid.uuid4(),
        attempt_id=uuid.uuid4(),
        attempt_number=1,
        operation_fingerprint=_FP,
        **over,
    )


def _construct(context) -> None:
    """Construct the executor via the token-gated test path (verification happens in __init__)."""
    PlanOnlyProcessExecutor.for_inert_fixture_test(context=context)


@contextlib.contextmanager
def _refused(reason_code: str):
    """Assert the block raises ``PlanOnlyProcessError`` with the EXACT bounded reason code.

    ``PlanOnlyProcessError`` carries a human message plus a machine ``reason_code``; the reason code
    is the contract the orchestration maps on, so tests pin it exactly.
    """
    with pytest.raises(PlanOnlyProcessError) as excinfo:
        yield
    assert excinfo.value.reason_code == reason_code, excinfo.value.reason_code


# =================================================================================================
# Item 1: the capability is MANDATORY and independently re-checked (cross-platform — construction
# verifies without spawning anything).
# =================================================================================================


def test_executor_refuses_a_non_capability_object():
    ctx = PlanOnlyExecutionContext(
        executable_handle=stub_attested().executable,
        provider_mirror_handle=stub_attested().provider_mirror,
        cli_config_handle=stub_attested().cli_config,
        module_bundle_handle=stub_attested().module_bundle,
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
        env=exact_child_env(),
        env_contract_version="",
        capability=object(),  # NOT a PlanOnlyCapability
        timeout=60,
        max_output_bytes=1024,
        expected_lease_id=uuid.uuid4(),
        expected_attempt_id=uuid.uuid4(),
        expected_attempt_number=1,
        expected_operation_fingerprint=_FP,
        now=NOW,
    )
    with _refused("capability_invalid"):
        _construct(ctx)


def test_executor_refuses_a_cross_lease_capability():
    """A capability minted for ANOTHER lease is refused even though it is otherwise valid."""
    cap = _cap()
    ctx = make_context(
        attested=stub_attested(),
        capability=cap,
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
        expected_lease_id=uuid.uuid4(),  # a DIFFERENT lease than the capability binds
    )
    with _refused("capability_binding_drift"):
        _construct(ctx)


def test_executor_refuses_a_cross_attempt_capability():
    cap = _cap()
    for over in ({"expected_attempt_id": uuid.uuid4()}, {"expected_attempt_number": 2}):
        ctx = make_context(
            attested=stub_attested(),
            capability=cap,
            workspace="/w/x",
            plan_file="/w/x/p.tfplan",
            **over,
        )
        with _refused("capability_binding_drift"):
            _construct(ctx)


def test_executor_refuses_a_cross_operation_fingerprint_capability():
    cap = _cap()
    ctx = make_context(
        attested=stub_attested(),
        capability=cap,
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
        expected_operation_fingerprint="sha256:" + "9" * 64,
    )
    with _refused("capability_binding_drift"):
        _construct(ctx)


def test_test_path_refuses_a_controlled_live_capability():
    """Classifications cannot cross: the inert test path requires a ``test_only`` capability."""
    cap = build_controlled_live_capability(
        lease_id=uuid.uuid4(), attempt_id=uuid.uuid4(), attempt_number=1, operation_fingerprint=_FP
    )
    ctx = make_context(
        attested=stub_attested(), capability=cap, workspace="/w/x", plan_file="/w/x/p.tfplan"
    )
    with _refused("capability_binding_drift"):
        _construct(ctx)


def test_executor_refuses_an_expired_capability_at_run_time_now():
    """A capability valid at ISSUE is refused if the execution ``now`` is past its expiry."""
    cap = _cap(now=NOW)  # expires_at = NOW + 10 minutes
    ctx = make_context(
        attested=stub_attested(),
        capability=cap,
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
        now=NOW + timedelta(hours=1),  # well past the capability expiry
    )
    with _refused("capability_invalid"):
        _construct(ctx)


# =================================================================================================
# Item 2: the exact execution context is independently re-checked.
# =================================================================================================


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"workspace": "relative/ws"}, "workspace_unsafe"),  # not absolute
        ({"plan_file": "/other/p.tfplan"}, "workspace_unsafe"),  # not a workspace child
        ({"env": {"PATH": "/usr/bin"}}, "secret_env_contract_violation"),  # wrong key set
        ({"env_contract_version": "wrong/v0"}, "secret_env_contract_violation"),
    ],
)
def test_executor_refuses_a_bad_context(over, reason):
    ctx = make_context(
        attested=stub_attested(),
        capability=_cap(),
        workspace=over.get("workspace", "/w/x"),
        plan_file=over.get("plan_file", "/w/x/p.tfplan"),
        env=over.get("env"),
        env_contract_version=over.get("env_contract_version", PLAN_SECRET_ENV_CONTRACT_VERSION),
    )
    with _refused(reason):
        _construct(ctx)


def test_executor_refuses_an_env_missing_a_required_key():
    """The child env must be EXACTLY the closed key set — a subset (dropped lock key) is refused."""
    env = exact_child_env()
    env.pop("TF_HTTP_LOCK_ADDRESS")  # locking silently disabled → refused
    cap = _cap()
    ctx = make_context(
        attested=stub_attested(),
        capability=cap,
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
        env=env,
    )
    with _refused("secret_env_contract_violation"):
        _construct(ctx)


# =================================================================================================
# Item 4: after unsealing, the PRODUCTION issuer (issue_plan_only_executor) enforces the same final
# boundary — it accepts ONLY an exact controlled-live context and refuses every drift. (These
# construct/verify without spawning; no subprocess, provider, or secret contact.)
# =================================================================================================


def _cl_cap(**over):
    return build_controlled_live_capability(
        lease_id=uuid.uuid4(),
        attempt_id=uuid.uuid4(),
        attempt_number=1,
        operation_fingerprint=_FP,
        **over,
    )


@contextlib.contextmanager
def _prod_refused(reason_code: str):
    with pytest.raises(PlanOnlyProcessError) as excinfo:
        yield
    assert excinfo.value.reason_code == reason_code, excinfo.value.reason_code


def test_production_issuer_constructs_only_the_exact_controlled_live_context():
    """The production issuer builds a real executor for a valid controlled-live context."""
    ctx = make_context(
        attested=stub_attested(), capability=_cl_cap(), workspace="/w/x", plan_file="/w/x/p.tfplan"
    )
    assert isinstance(issue_plan_only_executor(context=ctx), PlanOnlyProcessExecutor)


def test_production_issuer_refuses_a_non_context():
    with _prod_refused("capability_invalid"):
        issue_plan_only_executor(context=object())


def test_production_issuer_refuses_a_forged_capability_object():
    ctx = PlanOnlyExecutionContext(
        executable_handle=stub_attested().executable,
        provider_mirror_handle=stub_attested().provider_mirror,
        cli_config_handle=stub_attested().cli_config,
        module_bundle_handle=stub_attested().module_bundle,
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
        env=exact_child_env(),
        env_contract_version=PLAN_SECRET_ENV_CONTRACT_VERSION,
        capability=object(),  # a forged, capability-SHAPED object
        timeout=60,
        max_output_bytes=1024,
        expected_lease_id=uuid.uuid4(),
        expected_attempt_id=uuid.uuid4(),
        expected_attempt_number=1,
        expected_operation_fingerprint=_FP,
        now=NOW,
    )
    with _prod_refused("capability_invalid"):
        issue_plan_only_executor(context=ctx)


def test_production_issuer_refuses_a_test_only_classification():
    ctx = make_context(
        attested=stub_attested(), capability=_cap(), workspace="/w/x", plan_file="/w/x/p.tfplan"
    )
    with _prod_refused("capability_binding_drift"):
        issue_plan_only_executor(context=ctx)


def test_production_issuer_refuses_the_old_v1_process_digest():
    """A controlled-live capability minted against the OLD v1 process id/digest cannot even be built
    (issuance expects v2), so the production issuer can never receive one."""
    import hashlib

    from secp_worker.plan_gen.capability import PlanOnlyCapabilityRefused

    v1_id = "secp-002b-1b-pr5b/plan-only-executor/v1"
    v1_digest = "sha256:" + hashlib.sha256(v1_id.encode()).hexdigest()
    with pytest.raises(PlanOnlyCapabilityRefused, match="process implementation digest"):
        _cl_cap(process_implementation_id=v1_id, process_implementation_digest=v1_digest)


@pytest.mark.parametrize(
    ("ctx_over", "reason"),
    [
        ({"expected_lease_id": uuid.uuid4()}, "capability_binding_drift"),
        ({"expected_attempt_id": uuid.uuid4()}, "capability_binding_drift"),
        ({"expected_attempt_number": 2}, "capability_binding_drift"),
        ({"expected_operation_fingerprint": "sha256:" + "9" * 60}, "capability_binding_drift"),
        ({"workspace": "relative/ws"}, "workspace_unsafe"),
        ({"env": {"PATH": "/usr/bin"}}, "secret_env_contract_violation"),
        ({"env_contract_version": "wrong/v0"}, "secret_env_contract_violation"),
    ],
)
def test_production_issuer_refuses_binding_and_context_drift(ctx_over, reason):
    fields = dict(
        attested=stub_attested(),
        capability=_cl_cap(),
        workspace=ctx_over.pop("workspace", "/w/x"),
        plan_file="/w/x/p.tfplan",
    )
    if "env" in ctx_over:
        fields["env"] = ctx_over.pop("env")
    if "env_contract_version" in ctx_over:
        fields["env_contract_version"] = ctx_over.pop("env_contract_version")
    ctx = make_context(**fields, **ctx_over)
    with _prod_refused(reason):
        issue_plan_only_executor(context=ctx)


def test_production_issuer_refuses_an_expired_capability():
    cap = _cl_cap(now=NOW)  # expires_at = NOW + 10 minutes
    from datetime import timedelta

    ctx = make_context(
        attested=stub_attested(),
        capability=cap,
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
        now=NOW + timedelta(hours=1),
    )
    with _prod_refused("capability_invalid"):
        issue_plan_only_executor(context=ctx)


# =================================================================================================
# Item 3 + 7: bounded I/O, strict decoding, TOCTOU re-check, spawn failure (REAL subprocess; POSIX).
# =================================================================================================

pytestmark_posix = pytest.mark.skipif(
    sys.platform == "win32", reason="the real hardened subprocess needs POSIX exec + signals"
)

_SCRIPT_HEADER = "#!{python}\nimport sys, os, signal, time\nargv = sys.argv[1:]\nsub = argv[1]\n"


def _write_exe(directory: str, name: str, body: str, *, mode: int = 0o755) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_SCRIPT_HEADER.format(python=sys.executable) + body)
    os.chmod(path, mode)
    return path.replace("\\", "/")


def _posix_context(tmp_path, exe, *, timeout=30, max_output_bytes=4 * 1024 * 1024):
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    attested = real_attested(root, exe=exe)
    workspace = f"{root}/ws"
    os.makedirs(workspace, exist_ok=True)
    plan_file = f"{workspace}/plan.tfplan"
    cap = build_test_only_capability(
        lease_id=uuid.uuid4(), attempt_id=uuid.uuid4(), attempt_number=1, operation_fingerprint=_FP
    )
    ctx = make_context(
        attested=attested,
        capability=cap,
        workspace=workspace,
        plan_file=plan_file,
        timeout=timeout,
        max_output_bytes=max_output_bytes,
    )
    return (
        attested,
        workspace,
        plan_file,
        PlanOnlyProcessExecutor.for_inert_fixture_test(context=ctx),
    )


@pytestmark_posix
def test_run_enforces_the_output_byte_limit_while_reading(tmp_path):
    exe = _write_exe(
        str(tmp_path),
        "runner_infinite",
        'if sub == "show":\n'
        "    while True:\n"
        "        sys.stdout.buffer.write(b'a' * 4096)\n"
        "        sys.stdout.buffer.flush()\n"
        "sys.exit(0)\n",
    )
    _, ws, plan, executor = _posix_context(tmp_path, exe, max_output_bytes=8192)
    with _refused("process_output_too_large"):
        executor.run(build_show_command(executable=exe, workspace=ws, plan_file=plan))


@pytestmark_posix
def test_run_refuses_invalid_utf8_show_output(tmp_path):
    exe = _write_exe(
        str(tmp_path),
        "runner_badutf8",
        'if sub == "show":\n'
        "    sys.stdout.buffer.write(b'\\xff\\xfe\\x00not-utf8')\n"
        "    sys.stdout.buffer.flush()\n"
        "sys.exit(0)\n",
    )
    _, ws, plan, executor = _posix_context(tmp_path, exe)
    with _refused("show_json_invalid"):
        executor.run(build_show_command(executable=exe, workspace=ws, plan_file=plan))


@pytestmark_posix
def test_run_times_out_and_terminates_the_process_group(tmp_path):
    exe = _write_exe(
        str(tmp_path),
        "runner_slow",
        'if sub == "init":\n    time.sleep(30)\nsys.exit(0)\n',
    )
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe, timeout=1)
    with _refused("process_timed_out"):
        executor.run(build_init_command(executable=exe, workspace=ws, plugin_dir=f"{root}/mirror"))


@pytestmark_posix
def test_run_escalates_to_kill_when_the_child_ignores_sigterm(tmp_path):
    """A child that ignores SIGTERM is still KILLed within the bounded reap window (proven dead)."""
    exe = _write_exe(
        str(tmp_path),
        "runner_ignore_term",
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        'if sub == "init":\n    time.sleep(60)\nsys.exit(0)\n',
    )
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe, timeout=1)
    with _refused("process_timed_out"):
        executor.run(build_init_command(executable=exe, workspace=ws, plugin_dir=f"{root}/mirror"))


@pytestmark_posix
def test_run_maps_a_spawn_failure_to_a_bounded_reason(tmp_path):
    """A non-executable pinned binary yields a bounded ``process_spawn_failed`` (no traceback)."""
    # A regular, NON-executable file passes the lstat identity re-check but cannot be exec'd.
    exe = _write_exe(str(tmp_path), "not_exec", "sys.exit(0)\n", mode=0o644)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    with _refused("process_spawn_failed"):
        executor.run(build_init_command(executable=exe, workspace=ws, plugin_dir=f"{root}/mirror"))


# --- Failure-1 regression suite: the executable is bound to the freshly attested OBJECT, not the
#     pathname. Every same-path replacement is detected by the reviewed content digest (so inode
#     reuse cannot escape it), and on Linux the child executes the exact opened object via
#     /proc/self/fd. None of these depend on the filesystem assigning a different inode.

_OK_BODY = 'if sub == "init":\n    sys.exit(0)\nif sub == "show":\n    print("{}")\nsys.exit(0)\n'


def _init_cmd(exe, ws, root):
    return build_init_command(executable=exe, workspace=ws, plugin_dir=f"{root}/mirror")


@pytestmark_posix
def test_run_refuses_unlink_and_recreate_at_the_same_pathname(tmp_path):
    """Case 1: unlink + recreate DIFFERENT content at the same path — refused via the content digest
    even if the kernel immediately reuses the removed inode (the reported CI defect)."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    os.remove(exe)
    replaced = _write_exe(str(tmp_path), "runner_ok", _OK_BODY + "# swapped\n")
    assert replaced == exe  # SAME pathname
    with _refused("attested_path_changed"):
        executor.run(_init_cmd(exe, ws, root))


@pytestmark_posix
def test_run_refuses_os_replace_substitution(tmp_path):
    """Case 2: an atomic ``os.replace`` swap of the executable is refused."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    other = _write_exe(str(tmp_path), "runner_other", _OK_BODY + "# other\n")
    os.replace(other, exe)  # atomic rename over the attested path
    with _refused("attested_path_changed"):
        executor.run(_init_cmd(exe, ws, root))


@pytestmark_posix
def test_run_refuses_same_length_altered_content(tmp_path):
    """Case 3: an IN-PLACE, same-length, same-inode content edit is refused (digest, not size)."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    before = os.lstat(exe)
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    with open(exe, "r+b") as fh:  # overwrite one byte in place — length + inode unchanged
        data = bytearray(fh.read())
        data[-2] ^= 0x01
        fh.seek(0)
        fh.write(data)
    after = os.lstat(exe)
    assert after.st_ino == before.st_ino and after.st_size == before.st_size
    with _refused("attested_path_changed"):
        executor.run(_init_cmd(exe, ws, root))


@pytestmark_posix
def test_run_refuses_symlink_substitution(tmp_path):
    """Case 4: replacing the executable with a symlink (even to identical content) is refused."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    target = _write_exe(str(tmp_path), "runner_target", _OK_BODY)
    os.remove(exe)
    os.symlink(target, exe)  # O_NOFOLLOW must refuse this
    with _refused("attested_path_changed"):
        executor.run(_init_cmd(exe, ws, root))


@pytestmark_posix
def test_run_refuses_a_missing_executable(tmp_path):
    """Case 5: an executable removed after attestation is refused."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    os.remove(exe)
    with _refused("attested_path_changed"):
        executor.run(_init_cmd(exe, ws, root))


@pytestmark_posix
def test_run_refuses_a_wrong_object_type(tmp_path):
    """Case 6: the executable path becoming a DIRECTORY is refused."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    os.remove(exe)
    os.mkdir(exe)
    with _refused("attested_path_changed"):
        executor.run(_init_cmd(exe, ws, root))


@pytestmark_posix
def test_run_executes_the_unchanged_attested_object(tmp_path):
    """Case 7 + 8: an UNCHANGED attested executable runs — through the pinned opened object.

    On Linux the executor opens the executable no-follow, verifies the reviewed content digest, and
    execs ``/proc/self/fd/<fd>`` (the exact object), never re-resolving the pathname.
    """
    from secp_worker.plan_gen.process_boundary import _open_pinned_executable

    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    attested, ws, _plan, executor = _posix_context(tmp_path, exe)
    result = executor.run(_init_cmd(exe, ws, root))
    assert result.returncode == 0

    # White-box: the pinning helper hands the child the EXACT opened descriptor via /proc/self/fd.
    fd, exec_target, pass_fds = _open_pinned_executable(attested.executable)
    try:
        assert exec_target == f"/proc/self/fd/{fd}"
        assert pass_fds == (fd,)
        assert fd >= 0
    finally:
        os.close(fd)


@pytestmark_posix
def test_run_inherits_only_the_pinned_executable_descriptor(tmp_path):
    """Case 9: the child inherits ONLY stdio + the single pinned executable fd (explicit+minimal).

    The fixture reports its open descriptors >=3 via ``fstat`` (which opens nothing new), so a leak
    of any unrelated parent descriptor (pipes, workspace, etc.) would appear. ``close_fds=True`` +
    ``pass_fds=(fd,)`` must leave exactly one.
    """
    exe = _write_exe(
        str(tmp_path),
        "runner_fds",
        'if sub == "show":\n'
        "    open_fds = []\n"
        "    for i in range(3, 256):\n"
        "        try:\n"
        "            os.fstat(i)\n"
        "            open_fds.append(i)\n"
        "        except OSError:\n"
        "            pass\n"
        "    import json\n"
        "    print(json.dumps(open_fds))\n"
        "sys.exit(0)\n",
    )
    _, ws, plan, executor = _posix_context(tmp_path, exe)
    import json

    result = executor.run(build_show_command(executable=exe, workspace=ws, plan_file=plan))
    inherited = json.loads(result.stdout)
    assert len(inherited) == 1, inherited  # exactly the pinned executable fd; nothing else leaks


@pytestmark_posix
def test_the_reason_code_is_exactly_attested_path_changed(tmp_path):
    """Case 10: a drifted executable's bounded reason code is EXACTLY ``attested_path_changed``."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    _, ws, _plan, executor = _posix_context(tmp_path, exe)
    os.remove(exe)
    _write_exe(str(tmp_path), "runner_ok", _OK_BODY + "# swapped\n")
    with pytest.raises(PlanOnlyProcessError) as excinfo:
        executor.run(_init_cmd(exe, ws, root))
    assert excinfo.value.reason_code == "attested_path_changed"


@pytestmark_posix
@pytest.mark.skipif(
    os.name == "posix" and os.geteuid() == 0,
    reason="root bypasses file-permission checks, so os.open cannot be made to fail",
)
def test_a_cli_config_open_failure_maps_to_a_bounded_reason(tmp_path):
    """An ADJACENT attested file (the CLI config) whose fresh re-check open FAILS after a clean
    lstat (an unreadable file) maps to the bounded ``attested_path_changed`` — never a raw
    ``OSError`` that would carry the worker path and skip the attempt's terminal transition."""
    exe = _write_exe(str(tmp_path), "runner_ok", _OK_BODY)
    root = str(tmp_path).replace("\\", "/").rstrip("/")
    attested, ws, _plan, executor = _posix_context(tmp_path, exe)
    cli = attested.cli_config.path  # readable + digested at attestation
    os.chmod(cli, 0o000)  # inode/type unchanged (lstat passes) but the fresh open now EACCESs
    try:
        with _refused("attested_path_changed"):
            executor.run(_init_cmd(exe, ws, root))
    finally:
        os.chmod(cli, 0o600)  # restore so the tmp_path teardown can remove it


@pytestmark_posix
def test_a_show_result_carries_no_stderr_surface(tmp_path):
    """The bounded result exposes stdout only; stderr is counted but never retained (item 3)."""
    exe = _write_exe(
        str(tmp_path),
        "runner_stderr",
        'if sub == "show":\n'
        '    sys.stderr.write("PROVIDER-DIAGNOSTIC-SECRET\\n")\n'
        '    print("{}")\n'
        "sys.exit(0)\n",
    )
    _, ws, plan, executor = _posix_context(tmp_path, exe)
    result = executor.run(build_show_command(executable=exe, workspace=ws, plan_file=plan))
    assert result.stdout.strip() == "{}"
    assert not hasattr(result, "stderr")
    assert not hasattr(result, "stderr_tail")
    # POSIX file-mode sanity: the executor never widened the fixture's mode.
    assert stat.S_IMODE(os.stat(exe).st_mode) == 0o755
