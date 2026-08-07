"""The OpenTofu executor is closed by authority and derivation, not by a flag (ADR-030 §3).

`_B1A_SUBPROCESS_SEALED` and `armed=` made real execution *unconstructible*. They are gone, and the
question these tests answer is the one that replaces them: with the executor production-capable,
what stops it running something other than a reviewed command, on behalf of no one?

Two independent things, and each is attacked here rather than confirmed:

* it cannot be CONSTRUCTED without the exact durable operation authority — including against a
  forged object carrying every attribute a real one carries;
* it cannot RUN a command the reviewed grammar could not have produced, because it rebuilds the
  command rather than inspecting the one it was given.

A test that only checks "the reviewed command is accepted" proves an allowlist is permissive. The
ones that matter are the ones that try to get something else through.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from secp_api.provisioning_execution_authority import AuthorizedExecution
from secp_worker.provisioning.command_grammar import (
    PERMITTED_LABELS,
    PROVIDER_MIRROR_ROOT,
    CommandGrammarError,
    OpenTofuStep,
    build_argv,
    plan_file_for,
    step_for_label,
)
from secp_worker.provisioning.process_executor import (
    MAX_TIMEOUT_S,
    ProcessExecutionError,
    ProcessSpec,
    SubprocessProcessExecutor,
)

WORKER_PROV = Path(__file__).resolve().parents[2] / "worker" / "secp_worker" / "provisioning"

EXECUTABLE = "/opt/secp/bin/tofu"
MIRROR = "proxmox-1.2.3"
ROOT = "/var/lib/secp/workspaces"
WORKDIR = f"{ROOT}/op-1"


# === the grammar ==================================================================================


def test_the_permitted_labels_are_derived_from_the_steps_not_listed():
    """A hand-maintained list is a second artifact that drifts. This asserts there is only one."""
    assert PERMITTED_LABELS == frozenset(s.value for s in OpenTofuStep)
    source = inspect.getsource(
        __import__("secp_worker.provisioning.command_grammar", fromlist=["x"])
    )
    tree = ast.parse(source)
    (assignment,) = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AnnAssign)
        and isinstance(n.target, ast.Name)
        and n.target.id == "PERMITTED_LABELS"
    ]
    # Derived from a comprehension over the enum, not a literal set of strings.
    assert isinstance(assignment.value, ast.Call)
    assert not isinstance(assignment.value.args[0], ast.Set | ast.List | ast.Tuple)


def test_apply_and_destroy_are_the_same_command():
    """Stated in the grammar and asserted here: a destroy APPLIES an already-generated destroy plan.

    If these ever diverge, a destroy would be regenerating something at execution time -- which is
    exactly what applying the exact reviewed change set exists to prevent.
    """
    kw = {"executable": EXECUTABLE, "workdir": WORKDIR, "mirror_identity": MIRROR}
    assert build_argv(OpenTofuStep.apply, **kw) == build_argv(OpenTofuStep.destroy, **kw)
    assert "-destroy" not in build_argv(OpenTofuStep.destroy, **kw)


def test_the_destroy_plan_is_the_plan_plus_exactly_one_flag():
    kw = {"executable": EXECUTABLE, "workdir": WORKDIR, "mirror_identity": MIRROR}
    plan = build_argv(OpenTofuStep.plan, **kw)
    destroy_plan = build_argv(OpenTofuStep.destroy_plan, **kw)
    assert destroy_plan == [*plan, "-destroy"]


def test_the_plan_path_is_derived_from_the_workspace_and_never_supplied():
    kw = {"executable": EXECUTABLE, "workdir": WORKDIR, "mirror_identity": MIRROR}
    expected = plan_file_for(WORKDIR)
    assert expected.startswith(WORKDIR + "/")
    assert f"-out={expected}" in build_argv(OpenTofuStep.plan, **kw)
    assert build_argv(OpenTofuStep.show, **kw)[-1] == expected
    assert build_argv(OpenTofuStep.apply, **kw)[-1] == expected
    # No builder takes a plan path: there is nowhere for a caller to put one.
    assert "plan_file" not in inspect.signature(build_argv).parameters


def test_every_step_is_non_interactive_and_uncoloured():
    """A command that can prompt hangs a worker; colour codes corrupt the JSON the change-set hash
    is taken over. ``show`` is exempt from ``-input`` because it reads a file."""
    for step in OpenTofuStep:
        argv = build_argv(step, executable=EXECUTABLE, workdir=WORKDIR, mirror_identity=MIRROR)
        assert argv[0] == EXECUTABLE
        assert argv[1] == f"-chdir={WORKDIR}"
        if step is not OpenTofuStep.show:
            assert "-input=false" in argv
            assert "-no-color" in argv


def test_init_is_offline_in_every_independent_way():
    argv = build_argv(
        OpenTofuStep.init, executable=EXECUTABLE, workdir=WORKDIR, mirror_identity=MIRROR
    )
    for offline in ("-get=false", "-upgrade=false", "-lockfile=readonly"):
        assert offline in argv
    assert f"-plugin-dir={PROVIDER_MIRROR_ROOT}/{MIRROR}" in argv


def test_no_step_can_produce_a_shell_invocation():
    """Not "we do not pass shell=True" -- there is no argv the grammar emits that a shell could
    interpret, so the property does not depend on the call site."""
    for step in OpenTofuStep:
        argv = build_argv(step, executable=EXECUTABLE, workdir=WORKDIR, mirror_identity=MIRROR)
        assert argv[0] == EXECUTABLE
        for token in argv:
            for meta in (";", "|", "&", "$(", "`", ">", "<", "\n"):
                assert meta not in token, (step, token, meta)
        assert "-c" not in argv


def test_an_unknown_label_has_no_default():
    for unknown in ("", "version", "apply ", "APPLY", "plan;apply", "import"):
        with pytest.raises(CommandGrammarError):
            step_for_label(unknown)


# === the executor is closed by authority ========================================================


def _authority(**kw) -> AuthorizedExecution:
    """A real ``AuthorizedExecution``. Built directly rather than derived, because what is under
    test here is the EXECUTOR's behaviour given an authority -- the derivation that produces one has
    its own suite in ``test_provisioning_execution_authority.py``."""
    import uuid as _uuid

    from secp_api.enums import ProvisioningOperationKind

    defaults = dict(
        operation_id=_uuid.uuid4(),
        organization_identity=str(_uuid.uuid4()),
        target_identity=str(_uuid.uuid4()),
        manifest_id=_uuid.uuid4(),
        kind=ProvisioningOperationKind.apply,
        authorization_domain=ProvisioningOperationKind.apply,
        change_set_hash="sha256:" + "a" * 64,
        approval_id=_uuid.uuid4(),
        worker_installation_id="wk-1",
        toolchain_profile_id=_uuid.uuid4(),
        rendered_workspace_hash="sha256:" + "b" * 64,
        opentofu_executable=EXECUTABLE,
        provider_mirror_identity=MIRROR,
    )
    defaults.update(kw)
    return AuthorizedExecution(**defaults)


def _executor(**kw) -> SubprocessProcessExecutor:
    kw.setdefault("authority", _authority())
    kw.setdefault("workspace_root", ROOT)
    return SubprocessProcessExecutor(**kw)


def _spec(step: OpenTofuStep, **kw) -> ProcessSpec:
    argv = kw.pop(
        "argv", build_argv(step, executable=EXECUTABLE, workdir=WORKDIR, mirror_identity=MIRROR)
    )
    kw.setdefault("cwd", WORKDIR)
    kw.setdefault("timeout_s", 600.0)
    kw.setdefault("label", step.value)
    return ProcessSpec(argv=argv, **kw)


class _ForgedAuthority:
    """Every attribute a real authority exposes, and none of its provenance."""

    operation_id = "00000000-0000-0000-0000-000000000000"
    organization_identity = "forged"
    target_identity = "forged"
    manifest_id = "00000000-0000-0000-0000-000000000000"
    kind = "apply"
    authorization_domain = "apply"
    change_set_hash = "sha256:" + "0" * 64
    approval_id = "00000000-0000-0000-0000-000000000000"
    worker_installation_id = "wk-forged"
    toolchain_profile_id = "00000000-0000-0000-0000-000000000000"
    rendered_workspace_hash = "sha256:" + "0" * 64
    opentofu_executable = EXECUTABLE
    provider_mirror_identity = MIRROR
    authority_version = "secp.provisioning-execution-authority/v1"


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(None, id="none"),
        pytest.param(object(), id="bare-object"),
        pytest.param({"opentofu_executable": EXECUTABLE}, id="dict"),
        pytest.param("authorized", id="string"),
        pytest.param(_ForgedAuthority(), id="forgery-with-every-attribute"),
    ],
)
def test_the_executor_cannot_be_built_without_the_real_authority(bad):
    """The forgery is the case that matters. An executor validating by duck-typing would accept an
    object carrying the right attribute names; only an identity check on the authority type refuses
    it, and only that makes "authorized" mean "the derivation said so"."""
    with pytest.raises(ProcessExecutionError, match="AuthorizedExecution"):
        SubprocessProcessExecutor(authority=bad, workspace_root=ROOT)


def test_the_authority_is_the_whole_construction_surface():
    """ADR-030 section 2, asserted over the constructor: nothing here widens what may execute."""
    import inspect

    params = set(inspect.signature(SubprocessProcessExecutor.__init__).parameters)
    assert params == {"self", "authority", "workspace_root", "max_output_bytes"}
    for banned in ("armed", "enabled", "real", "unsealed", "sealed", "force", "settings", "grant"):
        assert banned not in params, banned


def test_the_authoritys_binary_is_used_not_the_workers_own():
    """The executable comes from the authority, so a worker cannot choose which binary performs an
    authorized apply."""
    pinned = "/opt/secp/bin/tofu-pinned"
    ex = SubprocessProcessExecutor(
        authority=_authority(opentofu_executable=pinned), workspace_root=ROOT
    )
    authorized = ex.authorize(
        _spec(
            OpenTofuStep.show,
            argv=build_argv(
                OpenTofuStep.show,
                executable=pinned,
                workdir=WORKDIR,
                mirror_identity=MIRROR,
            ),
        )
    )
    assert authorized.argv[0] == pinned


def test_an_authority_naming_an_unapproved_binary_is_refused():
    for bad in ("", "/usr/bin/tofu", "../tofu", "tofu; rm -rf /"):
        with pytest.raises(ProcessExecutionError, match="executable|mirror"):
            SubprocessProcessExecutor(
                authority=_authority(opentofu_executable=bad), workspace_root=ROOT
            )


def test_an_authority_naming_no_provider_mirror_is_refused():
    for bad in ("", "   "):
        with pytest.raises(ProcessExecutionError, match="mirror"):
            SubprocessProcessExecutor(
                authority=_authority(provider_mirror_identity=bad), workspace_root=ROOT
            )


# === the executor is closed by re-derivation ====================================================


def test_the_reviewed_command_for_every_step_is_accepted():
    """The permissive direction, asserted once so the refusals below mean something."""
    ex = _executor()
    for step in OpenTofuStep:
        authorized = ex.authorize(_spec(step))
        assert authorized.label == step.value
        assert authorized.argv == build_argv(
            step, executable=EXECUTABLE, workdir=WORKDIR, mirror_identity=MIRROR
        )


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda a: [*a, "-var=pw=hunter2"], id="appended-var"),
        pytest.param(lambda a: [*a, "-auto-approve"], id="appended-auto-approve"),
        pytest.param(lambda a: [a[0], *a[2:]], id="dropped-chdir"),
        pytest.param(lambda a: ["/bin/sh", "-c", " ".join(a)], id="wrapped-in-a-shell"),
        pytest.param(lambda a: ["tofu", *a[1:]], id="different-executable"),
        pytest.param(lambda a: [*a[:2], "destroy", *a[3:]], id="different-verb"),
        pytest.param(lambda a: [x.replace("-lock=true", "-lock=false") for x in a], id="unlocked"),
        pytest.param(lambda a: [x.replace("=false", "=true") for x in a], id="input-enabled"),
        pytest.param(lambda a: a[:-1], id="truncated"),
        pytest.param(lambda a: [], id="empty"),
    ],
)
def test_a_command_the_grammar_could_not_produce_is_refused(mutate):
    """Each is a real way an argv could arrive wrong -- an injected variable, a shell wrapper, a
    swapped verb, a disabled lock. None can be right, because the executor does not inspect the argv
    it was given; it rebuilds the one that was allowed and compares."""
    ex = _executor()
    good = build_argv(
        OpenTofuStep.apply, executable=EXECUTABLE, workdir=WORKDIR, mirror_identity=MIRROR
    )
    with pytest.raises(ProcessExecutionError, match="reviewed form"):
        ex.authorize(_spec(OpenTofuStep.apply, argv=mutate(good)))


def test_a_spec_cannot_choose_its_own_mirror():
    ex = _executor()
    argv = build_argv(
        OpenTofuStep.init,
        executable=EXECUTABLE,
        workdir=WORKDIR,
        mirror_identity="attacker-mirror",
    )
    with pytest.raises(ProcessExecutionError, match="reviewed form"):
        ex.authorize(_spec(OpenTofuStep.init, argv=argv))


@pytest.mark.parametrize(
    "cwd",
    [
        "/etc",
        "/var/lib/secp",
        "/var/lib/secp/workspaces/../../../etc",
        "relative/path",
        "",
        "/var/lib/secp/workspacesevil",
    ],
)
def test_the_working_directory_must_be_a_workspace_this_worker_owns(cwd):
    """``-chdir`` is where the configuration comes from, so a settable cwd is a settable apply.
    ``workspacesevil`` is included because a prefix test without the separator accepts it."""
    ex = _executor()
    argv = build_argv(OpenTofuStep.show, executable=EXECUTABLE, workdir=cwd, mirror_identity=MIRROR)
    with pytest.raises(ProcessExecutionError):
        ex.authorize(_spec(OpenTofuStep.show, argv=argv, cwd=cwd))


def test_an_unknown_label_is_refused_by_the_executor_too():
    ex = _executor()
    good = build_argv(
        OpenTofuStep.apply, executable=EXECUTABLE, workdir=WORKDIR, mirror_identity=MIRROR
    )
    with pytest.raises(CommandGrammarError):
        ex.authorize(ProcessSpec(argv=good, cwd=WORKDIR, timeout_s=60.0, label="probe"))


@pytest.mark.parametrize("timeout", [0.0, -1.0, MAX_TIMEOUT_S + 1, float("inf")])
def test_the_timeout_is_capped_independently_of_the_spec(timeout):
    ex = _executor()
    with pytest.raises(ProcessExecutionError, match="timeout"):
        ex.authorize(_spec(OpenTofuStep.show, timeout_s=timeout))


def test_the_environment_is_rebuilt_rather_than_accepted():
    """The engine already filters the environment; this filters it again.

    Not redundant: authorization is the last point before a real process, and a spec that reached
    here with an extra key would otherwise pass it straight through. What matters is that the key is
    absent from the OUTPUT, since the returned spec is what runs.
    """
    ex = _executor()
    authorized = ex.authorize(
        _spec(
            OpenTofuStep.show,
            env={
                "TF_VAR_token": "s3cret",
                "LD_PRELOAD": "/tmp/evil.so",
                "PROXMOX_PASSWORD": "hunter2",
                "PATH": "/usr/bin",
            },
        )
    )
    assert "LD_PRELOAD" not in authorized.env
    assert "PROXMOX_PASSWORD" not in authorized.env
    assert authorized.env["TF_VAR_token"] == "s3cret"
    assert authorized.env["TF_IN_AUTOMATION"] == "1"
    assert authorized.redacted_env()["TF_VAR_token"] == "***REDACTED***"


def test_the_executor_module_never_reaches_a_shell():
    """Code, not prose. The class docstring lists a shell payload among the things that are
    structurally impossible here, and a raw substring scan reads that sentence as the violation it
    describes -- a trap this repository has hit before."""
    tree = ast.parse((WORKER_PROV / "process_executor.py").read_text(encoding="utf-8"))
    docstrings = {
        node.body[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell":
                    assert isinstance(kw.value, ast.Constant) and kw.value.value is False
            called = ast.unparse(node.func)
            assert called not in ("os.system", "os.popen", "subprocess.Popen"), called
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node not in docstrings
        ):
            for shell in ("/bin/sh", "/bin/bash", "powershell", "cmd.exe"):
                assert shell not in node.value, node.value


# === there is no second builder =================================================================


def test_the_engine_builds_every_command_through_the_grammar():
    """The property a future executor-side re-derivation will rest on.

    Keyed on argv construction rather than on a name: any list literal in the engine containing an
    OpenTofu verb would be a command built somewhere other than the grammar, and a re-derivation
    that only covered the grammar's output would silently not cover it.
    """
    verbs = {"init", "plan", "show", "apply", "destroy", "validate", "import", "state"}
    tree = ast.parse((WORKER_PROV / "opentofu.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.List):
            continue
        literals = [e.value for e in node.elts if isinstance(e, ast.Constant)]
        assert not (set(literals) & verbs), literals
    imports = {
        alias.name
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("command_grammar")
        for alias in n.names
    }
    assert "build_argv" in imports


def test_the_grammar_itself_reaches_no_shell_and_no_process():
    """The builder returns argv and does nothing else -- it must not import subprocess, os or a
    network client, so a command being *built* can never be a command being *run*."""
    tree = ast.parse((WORKER_PROV / "command_grammar.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("os", "subprocess", "socket", "httpx", "requests", "shutil"):
        assert banned not in imported, banned
