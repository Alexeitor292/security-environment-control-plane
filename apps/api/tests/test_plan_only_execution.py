"""B1B-PR5B — the plan-only EXECUTION mechanism (plan-only seal now False; both B1-A seals True).

These exercise the whole worker-only plan-only sequence — capability-bound argv derivation, the
hardened subprocess executor (which is the FINAL enforcement boundary and independently re-checks a
mandatory capability + exact context), the safe ephemeral workspace, the manifest-exact create-only
change policy, and the :class:`PlanOnlyOpenTofuRunner` that materializes the workspace BEFORE any
secret contact and wires ``init``/``plan``/``show`` into a redacted canonical change set. With
``_PLAN_ONLY_PROCESS_SEALED`` now False the production issuer constructs a real executor for a valid
controlled-live context; the inert fixture path keeps using the token-gated test-only construction.

The full sequence is proven cross-platform with a FAKE in-process executor, and the REAL hardened
subprocess is proven against a tiny inert local fixture on POSIX (Linux CI). The inert fixture opens
no network, mutates nothing outside the ephemeral workspace, emits bounded fixture ``show`` JSON,
and is never accepted as controlled-live provider evidence.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import stat
import sys
import uuid

import pytest
from secp_api.plan_activation_contract import PLAN_SECRET_ENV_CONTRACT_VERSION
from secp_worker.plan_gen.change_policy import (
    ExpectedPlanContext,
    PlanChangePolicyError,
    PlanChangePolicyEvaluator,
    expected_plan_context,
)
from secp_worker.plan_gen.controlled_live import (
    CONTROLLED_LIVE_ADAPTER_KIND,
    render_controlled_live_workspace,
)
from secp_worker.plan_gen.ephemeral_workspace import EphemeralWorkspaceError, plan_only_workspace
from secp_worker.plan_gen.plan_runner import PlanOnlyOpenTofuRunner, PlanOnlyRunError
from secp_worker.plan_gen.process_boundary import (
    PlanOnlyProcessError,
    PlanOnlyProcessExecutor,
    PlanOnlyProcessResult,
    build_init_command,
    build_plan_command,
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

_EXE = "/opt/tofu/tofu"
_CONTAINER_TYPE = "proxmox_virtual_environment_container"
_FP = "sha256:" + "c" * 64
_TEMPLATE = "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"


def _manifest() -> dict:
    node = {
        "ref": "c1",
        "guest_kind": "container",
        "vmid": 9001,
        "node": "pve-node-1",
        "storage": "local-lvm",
        "bridge": "vmbr9",
        "vcpu": 2,
        "memory_mb": 1024,
        "disk_gb": 8,
        "image": _TEMPLATE,
    }
    return {"topology": [{"team_ref": "t1", "nodes": [node]}]}


def _controlled_live_files() -> dict[str, str]:
    return render_controlled_live_workspace(
        _manifest(), provider_version="0.80.0", state_backend_kind="http"
    )


def _show_json(actions=("create",), rtype: str = _CONTAINER_TYPE) -> dict:
    """Fixture ``show -json`` for the container, with fake secret-looking values that MUST drop."""
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": f"{rtype}.t1_c1",
                "mode": "managed",
                "type": rtype,
                "name": "t1_c1",
                "provider_name": "registry.terraform.io/bpg/proxmox",
                "change": {
                    "actions": list(actions),
                    "before": None,
                    "after": {"vm_id": 9001, "api_token": "FAKE-DROP-ME"},
                    "after_sensitive": {"api_token": True},
                },
            }
        ],
    }


class _FakeExecutor:
    """A fake in-process executor: records the argv sequence, returns scripted results.

    It writes the transient binary plan file on the ``plan`` step (from the ``-out=`` token) so the
    runner's post-plan :func:`validate_transient_plan_file` re-check has a real file to inspect.
    """

    def __init__(self, *, show_stdout: str, init_rc: int = 0, plan_rc: int = 0, show_rc: int = 0):
        self.calls: list[str] = []
        self._show_stdout = show_stdout
        self._rc = {"init": init_rc, "plan": plan_rc, "show": show_rc}

    def run(self, command) -> PlanOnlyProcessResult:  # noqa: ANN001
        self.calls.append(command.kind)
        if command.kind == "plan":
            out = [a[len("-out=") :] for a in command.argv if a.startswith("-out=")]
            if out:
                with open(out[0], "w", encoding="utf-8") as fh:
                    fh.write("FAKE-BINARY-PLAN")
        return PlanOnlyProcessResult(
            kind=command.kind,
            returncode=self._rc[command.kind],
            stdout=self._show_stdout if command.kind == "show" else "",
        )


def _fake_factory(fake: _FakeExecutor):
    def factory(*, context):  # noqa: ANN001, ARG001 - the fake ignores the (validated) context
        return fake

    return factory


def _generate(runner, tmp_path, *, manifest=None, provenance=None, real=False):
    """Drive ``runner.generate_plan`` with the new-shaped inputs.

    ``real=False`` (the cross-platform default) supplies the lightweight :func:`stub_attested`
    handles used with a FAKE in-process executor. ``real=True`` writes a real inert executable UNDER
    ``tmp_path`` and attests it with :func:`real_attested`, for the REAL hardened subprocess. The
    mode is passed EXPLICITLY by the caller — never inferred from the runner's private factory field
    (bound-method identity of a classmethod is not stable, which previously mis-selected the stub).
    """
    manifest = manifest or _manifest()
    lease_id, attempt_id = uuid.uuid4(), uuid.uuid4()
    cap = build_test_only_capability(
        lease_id=lease_id, attempt_id=attempt_id, attempt_number=1, operation_fingerprint=_FP
    )
    trusted_root = str(tmp_path).replace("\\", "/")
    if real:
        exe = _write_inert_fixture(str(tmp_path))
        # The real subprocess must execute a genuine on-disk executable UNDER the trusted root — a
        # regression guard against silently falling back to the synthetic stub path.
        assert exe.startswith(trusted_root + "/"), exe
        attested = real_attested(trusted_root, exe=exe)
    else:
        attested = stub_attested()
    return runner.generate_plan(
        files=render_controlled_live_workspace(
            manifest, provider_version="0.80.0", state_backend_kind="http"
        ),
        trusted_root=trusted_root,
        resolve_child_env=exact_child_env,
        attested=attested,
        capability=cap,
        expected_lease_id=lease_id,
        expected_attempt_id=attempt_id,
        expected_attempt_number=1,
        operation_fingerprint=_FP,
        env_contract_version=PLAN_SECRET_ENV_CONTRACT_VERSION,
        expected_plan_context=expected_plan_context(manifest),
        provenance=provenance if provenance is not None else {"operation_fingerprint": _FP},
        timeout=60,
        max_output_bytes=4 * 1024 * 1024,
        now=NOW,
    )


# --- the seal + construction paths ---------------------------------------------------------------


def test_the_plan_only_seal_is_now_false():
    """The reviewed PR5B activation flipped the dedicated plan-only code seal to False."""
    from secp_worker.plan_gen import process_boundary as pb

    assert pb._PLAN_ONLY_PROCESS_SEALED is False


def test_production_issuer_constructs_with_a_controlled_live_context():
    """With the seal now False, the production issuer builds a real executor for a valid
    controlled-live context — construction only; no subprocess, provider, or secret contact."""
    lease_id, attempt_id = uuid.uuid4(), uuid.uuid4()
    ctx = make_context(
        attested=stub_attested(),
        capability=build_controlled_live_capability(
            lease_id=lease_id,
            attempt_id=attempt_id,
            attempt_number=1,
            operation_fingerprint=_FP,
        ),
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
    )
    executor = issue_plan_only_executor(context=ctx)
    assert isinstance(executor, PlanOnlyProcessExecutor)


def test_production_issuer_refuses_a_test_only_capability():
    """Classifications cannot cross: the production issuer requires a controlled-live capability."""
    ctx = make_context(
        attested=stub_attested(),
        capability=build_test_only_capability(
            lease_id=uuid.uuid4(),
            attempt_id=uuid.uuid4(),
            attempt_number=1,
            operation_fingerprint=_FP,
        ),
        workspace="/w/x",
        plan_file="/w/x/p.tfplan",
    )
    with pytest.raises(PlanOnlyProcessError) as excinfo:
        issue_plan_only_executor(context=ctx)
    assert excinfo.value.reason_code == "capability_binding_drift"


def test_direct_construction_is_refused_even_with_the_seal_false():
    """A direct, token-less construction is refused: the only production path is the issuer."""
    with pytest.raises(PlanOnlyProcessError, match="cannot be constructed directly"):
        PlanOnlyProcessExecutor()
    with pytest.raises(PlanOnlyProcessError, match="cannot be constructed directly"):
        PlanOnlyProcessExecutor(context=object())


def test_the_test_only_path_requires_a_context_and_a_test_only_capability():
    # A non-PlanOnlyExecutionContext is refused even on the test-only path.
    with pytest.raises(PlanOnlyProcessError, match="PlanOnlyExecutionContext"):
        PlanOnlyProcessExecutor.for_inert_fixture_test(context=object())


# --- capability-bound argv derivation ------------------------------------------------------------


def test_argv_builders_derive_the_three_reviewed_shapes():
    ws, plan, plugins = "/w/x", "/w/x/plan.tfplan", "/w/x/_offline_plugins"
    init = build_init_command(executable=_EXE, workspace=ws, plugin_dir=plugins)
    plan_cmd = build_plan_command(executable=_EXE, workspace=ws, plan_file=plan)
    show = build_show_command(executable=_EXE, workspace=ws, plan_file=plan)
    assert init.kind == "init" and "-lockfile=readonly" in init.argv
    assert (
        plan_cmd.kind == "plan"
        and f"-out={plan}" in plan_cmd.argv
        and "-destroy" not in plan_cmd.argv
    )
    assert show.argv == (_EXE, f"-chdir={ws}", "show", "-json", plan)


# --- the manifest-exact create-only change policy ------------------------------------------------

_EXPECTED = ExpectedPlanContext(
    expected_address=f"{_CONTAINER_TYPE}.a",
    expected_type=_CONTAINER_TYPE,
    expected_provider="registry.terraform.io/bpg/proxmox",
)


def _canonical(
    actions=("create",),
    rtype: str = _CONTAINER_TYPE,
    replace: bool = False,
    provider: str = "registry.terraform.io/bpg/proxmox",
) -> dict:
    return {
        "resources": [
            {
                "address": f"{rtype}.a",
                "mode": "managed",
                "type": rtype,
                "name": "a",
                "provider": provider,
                "actions": list(actions),
                "replace": replace,
            }
        ],
        "summary": {"count": 1, "by_action": {",".join(actions): 1}},
    }


def test_change_policy_accepts_a_single_create():
    decision = PlanChangePolicyEvaluator(expected=_EXPECTED).evaluate(_canonical())
    assert decision.created == 1
    assert decision.resource_types == (_CONTAINER_TYPE,)


@pytest.mark.parametrize(
    "change_set",
    [
        _canonical(actions=("delete",)),
        _canonical(actions=("update",)),
        _canonical(actions=("delete", "create")),  # replace via action list
        _canonical(replace=True),
        _canonical(actions=("read",)),
        _canonical(actions=("no-op",)),
        _canonical(rtype="proxmox_virtual_environment_vm"),  # unsupported type / wrong address
        _canonical(rtype="proxmox_virtual_environment_network"),
        _canonical(provider="registry.terraform.io/hashicorp/proxmox"),  # wrong provider identity
        {"resources": []},  # empty
        {"resources": "nope"},
        {},
    ],
)
def test_change_policy_refuses_anything_but_the_exact_single_create(change_set):
    with pytest.raises(PlanChangePolicyError, match="change_policy_refused"):
        PlanChangePolicyEvaluator(expected=_EXPECTED).evaluate(change_set)


def test_change_policy_refuses_two_resources():
    two = _canonical()
    two["resources"].append(dict(two["resources"][0], address=f"{_CONTAINER_TYPE}.b", name="b"))
    two["summary"] = {"count": 2, "by_action": {"create": 2}}
    with pytest.raises(PlanChangePolicyError, match="change_policy_refused"):
        PlanChangePolicyEvaluator(expected=_EXPECTED).evaluate(two)


# --- the full plan-only sequence via a fake executor (cross-platform) ----------------------------


def test_generate_plan_runs_init_plan_show_and_returns_a_redacted_change_set(tmp_path):
    fake = _FakeExecutor(show_stdout=json.dumps(_show_json()))
    runner = PlanOnlyOpenTofuRunner(executor_factory=_fake_factory(fake))
    result = _generate(runner, tmp_path)
    # Exactly init → plan → show, in order.
    assert fake.calls == ["init", "plan", "show"]
    assert result.created == 1
    assert result.resource_types == (_CONTAINER_TYPE,)
    assert result.change_set_hash.startswith("sha256:")
    # The change set is redacted: no before/after/secret survives canonicalization.
    blob = json.dumps(result.change_set)
    assert "FAKE-DROP-ME" not in blob
    assert "after" not in {k for r in result.change_set["resources"] for k in r}


def test_generate_plan_folds_provenance_into_the_hashed_change_set(tmp_path):
    """Item 10: the safe provenance is folded INTO the change set that is then hashed."""
    fake = _FakeExecutor(show_stdout=json.dumps(_show_json()))
    runner = PlanOnlyOpenTofuRunner(executor_factory=_fake_factory(fake))
    prov = {"operation_fingerprint": _FP, "toolchain_profile_hash": "sha256:" + "3" * 64}
    result = _generate(runner, tmp_path, provenance=prov)
    assert result.change_set["provenance"] == prov
    # A different provenance yields a different change_set_hash (the hash covers provenance).
    other = _generate(
        PlanOnlyOpenTofuRunner(
            executor_factory=_fake_factory(_FakeExecutor(show_stdout=json.dumps(_show_json())))
        ),
        tmp_path,
        provenance={"operation_fingerprint": _FP, "toolchain_profile_hash": "sha256:" + "9" * 64},
    )
    assert other.change_set_hash != result.change_set_hash


def test_generate_plan_always_removes_the_workspace(tmp_path):
    fake = _FakeExecutor(show_stdout=json.dumps(_show_json()))
    runner = PlanOnlyOpenTofuRunner(executor_factory=_fake_factory(fake))
    _generate(runner, tmp_path)
    # No residue: the trusted root has no leftover secp-plan-* workspace.
    assert not [p for p in os.listdir(tmp_path) if p.startswith("secp-plan-")]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"init_rc": 1}, "init_failed"),
        ({"plan_rc": 2}, "plan_failed"),
        ({"show_rc": 3}, "show_failed"),
    ],
)
def test_generate_plan_fails_closed_on_a_nonzero_step(tmp_path, kwargs, reason):
    fake = _FakeExecutor(show_stdout=json.dumps(_show_json()), **kwargs)
    runner = PlanOnlyOpenTofuRunner(executor_factory=_fake_factory(fake))
    with pytest.raises(PlanOnlyRunError, match=reason):
        _generate(runner, tmp_path)


def test_generate_plan_refuses_a_non_create_plan(tmp_path):
    fake = _FakeExecutor(show_stdout=json.dumps(_show_json(actions=("delete",))))
    runner = PlanOnlyOpenTofuRunner(executor_factory=_fake_factory(fake))
    with pytest.raises(PlanOnlyRunError, match="change_policy_refused"):
        _generate(runner, tmp_path)


def test_generate_plan_refuses_malformed_show_json(tmp_path):
    fake = _FakeExecutor(show_stdout="not json {")
    runner = PlanOnlyOpenTofuRunner(executor_factory=_fake_factory(fake))
    with pytest.raises(PlanOnlyRunError, match="plan_json_malformed"):
        _generate(runner, tmp_path)


def test_the_runner_has_no_apply_or_destroy_method():
    for forbidden in (
        "apply",
        "destroy",
        "apply_prepared",
        "destroy_prepared",
        "refresh",
        "import_",
    ):
        assert not hasattr(PlanOnlyOpenTofuRunner, forbidden)


# --- the safe ephemeral workspace ----------------------------------------------------------------


def test_workspace_refuses_an_untrusted_or_relative_root():
    with pytest.raises(EphemeralWorkspaceError, match="workspace_root_untrusted"):
        with plan_only_workspace({"main.tf": "x"}, trusted_root="relative/root"):
            pass


def test_workspace_refuses_an_unsafe_filename(tmp_path):
    with pytest.raises(EphemeralWorkspaceError, match="workspace_unsafe"):
        with plan_only_workspace({"../evil.tf": "x"}, trusted_root=str(tmp_path)):
            pass
    with pytest.raises(EphemeralWorkspaceError, match="workspace_unsafe"):
        with plan_only_workspace({"main.txt": "x"}, trusted_root=str(tmp_path)):
            pass


def test_workspace_writes_files_and_cleans_up(tmp_path):
    captured = {}
    with plan_only_workspace(_controlled_live_files(), trusted_root=str(tmp_path)) as ws:
        captured["dir"] = ws.workspace_dir
        assert os.path.isfile(os.path.join(ws.workspace_dir, "main.tf"))
        assert ws.plan_file.endswith("plan.tfplan")
        # The workspace no longer exposes a plugin-dir seam (item 12): init binds the attested
        # mirror explicitly, so the workspace never hosts a plugin directory it did not create.
        assert not hasattr(ws, "plugin_dir")
    # After exit the whole workspace is gone.
    assert not os.path.exists(captured["dir"])


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file-mode semantics")
def test_workspace_uses_restrictive_modes(tmp_path):
    with plan_only_workspace({"main.tf": "x"}, trusted_root=str(tmp_path)) as ws:
        dir_mode = stat.S_IMODE(os.stat(ws.workspace_dir).st_mode)
        file_mode = stat.S_IMODE(os.stat(os.path.join(ws.workspace_dir, "main.tf")).st_mode)
        assert dir_mode == 0o700
        assert file_mode == 0o600


# --- the fake adapter can never be the controlled-live adapter (defense in depth) ----------------


def test_the_controlled_live_adapter_kind_is_not_the_fake_one():
    assert CONTROLLED_LIVE_ADAPTER_KIND == "controlled_live_proxmox"
    assert CONTROLLED_LIVE_ADAPTER_KIND != "proxmox"


# =================================================================================================
# The REAL hardened subprocess against a tiny INERT local fixture (POSIX / Linux CI only).
# =================================================================================================

_INERT_FIXTURE = """#!{python}
import json
import sys

SHOW = json.loads({show!r})

argv = sys.argv[1:]
if len(argv) < 2 or not argv[0].startswith("-chdir="):
    sys.exit(2)
sub = argv[1]
if sub == "init":
    sys.exit(0)
if sub == "plan":
    out = [a[len("-out="):] for a in argv if a.startswith("-out=")]
    if not out:
        sys.exit(2)
    with open(out[0], "w", encoding="utf-8") as fh:
        fh.write("INERT-FIXTURE-BINARY-PLAN")
    sys.exit(0)
if sub == "show":
    print(json.dumps(SHOW))
    sys.exit(0)
sys.exit(2)
"""


def _write_inert_fixture(directory: str) -> str:
    path = os.path.join(directory, "inert_tofu")
    script = _INERT_FIXTURE.format(python=sys.executable, show=json.dumps(_show_json()))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(script)
    os.chmod(path, 0o755)
    return path.replace("\\", "/")


@pytest.mark.skipif(sys.platform == "win32", reason="inert executable fixture needs POSIX exec")
def test_real_subprocess_executor_runs_the_inert_fixture(tmp_path):
    """The REAL hardened subprocess drives init/plan/show against an inert local fixture."""
    trusted_root = str(tmp_path).replace("\\", "/")
    exe = _write_inert_fixture(str(tmp_path))
    attested = real_attested(trusted_root, exe=exe)
    lease_id, attempt_id = uuid.uuid4(), uuid.uuid4()
    cap = build_test_only_capability(
        lease_id=lease_id, attempt_id=attempt_id, attempt_number=1, operation_fingerprint=_FP
    )
    with plan_only_workspace(_controlled_live_files(), trusted_root=trusted_root) as ws:
        ctx = make_context(
            attested=attested, capability=cap, workspace=ws.workspace_dir, plan_file=ws.plan_file
        )
        executor = PlanOnlyProcessExecutor.for_inert_fixture_test(context=ctx)
        init = executor.run(
            build_init_command(
                executable=exe, workspace=ws.workspace_dir, plugin_dir=attested.provider_mirror.path
            )
        )
        plan = executor.run(
            build_plan_command(executable=exe, workspace=ws.workspace_dir, plan_file=ws.plan_file)
        )
        show = executor.run(
            build_show_command(executable=exe, workspace=ws.workspace_dir, plan_file=ws.plan_file)
        )
        assert init.returncode == 0 and plan.returncode == 0 and show.returncode == 0
        parsed = json.loads(show.stdout)
        assert parsed["resource_changes"][0]["type"] == _CONTAINER_TYPE


@pytest.mark.skipif(sys.platform == "win32", reason="inert executable fixture needs POSIX exec")
def test_real_runner_generate_plan_end_to_end_against_the_inert_fixture(tmp_path):
    """The full runner drives the REAL subprocess against the inert fixture and STOPS at a hash.

    ``real=True`` writes a genuine inert executable under ``tmp_path`` and attests it (never the
    synthetic ``stub_attested`` path) so the object-pinning execution mechanism is exercised end to
    end.
    """
    runner = PlanOnlyOpenTofuRunner(executor_factory=PlanOnlyProcessExecutor.for_inert_fixture_test)
    result = _generate(runner, tmp_path, real=True)
    assert result.created == 1
    assert result.resource_types == (_CONTAINER_TYPE,)
    assert "FAKE-DROP-ME" not in json.dumps(result.change_set)
    # The workspace (and the transient binary plan) are gone.
    assert not [p for p in os.listdir(tmp_path) if p.startswith("secp-plan-")]


def test_the_inert_fixture_is_never_controlled_live_evidence(tmp_path):
    """The inert fixture proves the mechanism; it is never accepted as real provider evidence."""
    exe = _write_inert_fixture(str(tmp_path)) if sys.platform != "win32" else "/opt/tofu/tofu"
    # The fixture path is a local temp path, not the reviewed controlled-live provider identity.
    from secp_worker.plan_gen.render_scan import CONTROLLED_LIVE_PROVIDER_SOURCE

    assert CONTROLLED_LIVE_PROVIDER_SOURCE == "bpg/proxmox"
    assert "inert_tofu" not in CONTROLLED_LIVE_PROVIDER_SOURCE
    assert exe  # touch the fixture path so the intent is explicit


# =================================================================================================
# Architecture scanner: the seal-bypassing test-only construction path is never reached by shipped
# code, and the executor grants no apply/destroy ability.
# =================================================================================================

_ROOT = pathlib.Path(__file__).resolve().parents[3]
_SHIPPED_PKGS = (
    _ROOT / "apps" / "worker" / "secp_worker",
    _ROOT / "apps" / "api" / "secp_api",
)
# The token-gated seal bypass — the ONLY names that construct the executor while sealed.
_TEST_ONLY_NAMES = ("for_inert_fixture_test", "_PLAN_ONLY_TEST_CONSTRUCTION_TOKEN")


def _shipped_files() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for pkg in _SHIPPED_PKGS:
        out += [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]
    return sorted(out)


def test_no_shipped_module_reaches_the_seal_bypassing_test_only_path():
    """Only test modules may USE the seal-bypassing construction path (ADR-022 §2).

    AST-based: an attribute access (``x.for_inert_fixture_test``) or a bare name reference is a real
    use and is refused; a docstring mention (a string constant) is prose and is allowed.
    """
    for path in _shipped_files():
        # process_boundary.py DEFINES the test-only classmethod + token; it is allowed to name them.
        if path.name == "process_boundary.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, ast.Name):
                used.add(node.id)
        leaked = used & set(_TEST_ONLY_NAMES)
        assert not leaked, f"{path.name} uses the seal-bypassing path {leaked}"


def test_the_executor_exposes_no_apply_or_destroy_surface():
    """The executor + runner name no apply/destroy/plan-destroy method (ADR-022 §4)."""
    src = (_ROOT / "apps" / "worker" / "secp_worker" / "plan_gen" / "plan_runner.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(src)
    method_names = {
        n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    for forbidden in ("apply", "destroy", "apply_prepared", "destroy_prepared", "refresh"):
        assert forbidden not in method_names, f"plan_runner defines a {forbidden} method"


def test_the_plan_only_seal_is_false_and_both_b1a_seals_remain_true():
    """The dedicated plan-only seal is now False; the two INDEPENDENT generic B1-A subprocess seals
    stay True, so the generic executor stays sealed and apply/destroy remain impossible."""
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert pb._PLAN_ONLY_PROCESS_SEALED is False
    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True


def test_no_pr6_apply_from_plan_workflow_or_dispatch_exists():
    """PR6 has not begun: no worker workflow consumes the plan-only approved change set to dispatch
    an apply, and no ``plan_gen`` module enqueues/starts a workflow. Approving the reviewed change
    set is a durable, human-only record; apply stays impossible (both B1-A seals True)."""
    temporal_app = (_ROOT / "apps" / "worker" / "secp_worker" / "temporal_app.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "PlanApplyWorkflow",
        "ApplyFromPlanWorkflow",
        "PlanOnlyApplyWorkflow",
        "RealApplyWorkflow",
        "plan_apply_activity",
        "apply_from_plan",
        "PR6",
    ):
        assert forbidden not in temporal_app, forbidden
    # No plan_gen module starts/enqueues a workflow (e.g. to dispatch an apply from a plan result).
    pkg = _ROOT / "apps" / "worker" / "secp_worker" / "plan_gen"
    for path in pkg.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for forbidden in (
            "start_workflow",
            "execute_workflow",
            "start_child_workflow",
            "signal_workflow",
            "signal_external_workflow",
        ):
            assert forbidden not in text, f"{path.name} dispatches a workflow ({forbidden})"
