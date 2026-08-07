"""One derivation builds every OpenTofu command (ADR-030 §3).

ADR-030 requires the executable command set to be "a **derived grammar** rather than a
hand-maintained list, so a reviewed operation and an executable command are the same fact". This is
that grammar's proof. It is deliberately the half of §3 that touches no seal: the executor-side
closure that consumes this grammar is blocked, because retiring `_B1A_SUBPROCESS_SEALED` requires
editing ``SealState``/``read_seals`` and the field set of the Ed25519-attested ``BootstrapEvidence``
document — a boundary ADR-030 declared out of scope for itself. See the ADR's implementation status.

What this does establish, and what makes the later closure possible at all, is that there is exactly
ONE place an OpenTofu argv is built. An executor that re-derives a command can only be as strong as
the guarantee that nothing else builds one.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from secp_worker.provisioning.command_grammar import (
    PERMITTED_LABELS,
    PROVIDER_MIRROR_ROOT,
    CommandGrammarError,
    OpenTofuStep,
    build_argv,
    plan_file_for,
    step_for_label,
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
