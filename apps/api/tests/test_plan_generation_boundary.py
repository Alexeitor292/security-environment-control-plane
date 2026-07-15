"""B1B-PR5A — plan-generation boundary + plan-only seal lock (ADR-022 §2/§4/§9/§11).

Proves, by AST/text scan and by runtime assertion, that real plan generation STOPS at the sealed
plan-only boundary and that every pre-existing execution seal is untouched:

* the plan-only process seal is a code constant set ``True``; ``PlanOnlyProcessExecutor`` cannot be
  constructed (even with a capability) and cannot run;
* the plan-only command grammar admits only offline ``init`` / non-destroy ``plan`` / ``show -json``
  and refuses apply / destroy / ``plan -destroy`` / every other subcommand and token;
* the ``PlanOnlyCapability`` cannot be built without the module-private token and is not
  serializable (never pickled, placed in a Temporal argument, or leaked through repr/str/format);
* NO ``secp_worker.plan_gen`` module imports subprocess / socket / HTTP / a provider SDK, and the
  orchestration constructs no generic subprocess executor;
* the API package imports NO ``secp_worker`` module and names none of the worker-only plan-gen
  symbols; the workflow/activity are registered ONLY in the worker;
* both B1-A subprocess seals remain exactly and effectively ``True``.
"""

from __future__ import annotations

import ast
import pathlib
import pickle
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
PLAN_GEN_PKG = ROOT / "apps" / "worker" / "secp_worker" / "plan_gen"
API_PKG = ROOT / "apps" / "api" / "secp_api"

NOW = datetime(2026, 7, 14, tzinfo=UTC)

# Worker-only plan-gen symbols the API must never import or name.
FORBIDDEN_PLAN_GEN_NAMES = frozenset(
    {
        "PlanOnlyProcessExecutor",
        "PlanOnlyProcessError",
        "PlanOnlyCommand",
        "validate_plan_only_command",
        "PlanOnlyCapability",
        "PlanOnlyActivation",
        "issue_plan_only_capability",
        "PlanOnlyCapabilityRefused",
        "run_plan_generation",
        "build_provider_plan_env",
        "build_state_plan_env",
        "combined_plan_env",
    }
)

FORBIDDEN_IMPORT_ROOTS = frozenset(
    {"subprocess", "socket", "httpx", "requests", "aiohttp", "paramiko", "asyncssh", "proxmoxer"}
)

# B1B-PR5B: ``process_boundary.py`` is the ONE plan-gen module that legitimately runs a subprocess —
# the narrow, grammar-constrained, seal-gated plan-only executor. It is the only module allowed to
# import ``subprocess`` (and NOTHING else from the forbidden set); every other plan-gen module still
# forbids the entire set, including ``subprocess``. No plan-gen module may open a socket or a
# provider/HTTP/SSH transport.
_SUBPROCESS_ALLOWED_IN = frozenset({"process_boundary.py"})


def _plan_gen_files() -> list[pathlib.Path]:
    return sorted(p for p in PLAN_GEN_PKG.rglob("*.py") if "__pycache__" not in p.parts)


# --- the plan-only process seal ------------------------------------------------------------------


def test_plan_only_seal_is_a_code_constant_set_false():
    """The dedicated plan-only seal is a single CODE constant, now set to False (reviewed PR5B
    activation) — never configuration, never an environment flag."""
    from secp_worker.plan_gen import process_boundary as pb

    assert pb._PLAN_ONLY_PROCESS_SEALED is False
    text = pathlib.Path(pb.__file__).read_text(encoding="utf-8")
    assigns = re.findall(r"(?m)^_PLAN_ONLY_PROCESS_SEALED\s*=.*$", text)
    assert len(assigns) == 1
    assert assigns[0].split("=", 1)[1].strip() == "False"


def test_plan_only_executor_cannot_be_constructed_directly():
    """Even with the seal False, a direct/token-less construction is refused (only the production
    issuer or the token-gated test path may construct it)."""
    from secp_worker.plan_gen.process_boundary import PlanOnlyProcessError, PlanOnlyProcessExecutor

    with pytest.raises(PlanOnlyProcessError, match="cannot be constructed directly"):
        PlanOnlyProcessExecutor()
    # Supplying a bare object as context does not create a construction path either.
    with pytest.raises(PlanOnlyProcessError, match="cannot be constructed directly"):
        PlanOnlyProcessExecutor(context=object())


def test_both_b1a_subprocess_seals_remain_true():
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True


# --- the plan-only command grammar ---------------------------------------------------------------

_EXE = "/opt/tofu/tofu"
_WS = "/work/ephemeral-abc"
_PLAN = "/work/ephemeral-abc/plan.bin"


def _init_argv() -> list[str]:
    return [
        _EXE,
        f"-chdir={_WS}",
        "init",
        "-input=false",
        "-no-color",
        "-get=false",
        "-upgrade=false",
        "-lockfile=readonly",
        "-plugin-dir=/opt/tofu/plugins",
    ]


def _plan_argv() -> list[str]:
    return [
        _EXE,
        f"-chdir={_WS}",
        "plan",
        "-input=false",
        "-no-color",
        "-lock=true",
        f"-out={_PLAN}",
    ]


def test_grammar_admits_the_three_reviewed_shapes():
    from secp_worker.plan_gen.process_boundary import validate_plan_only_command

    for argv, kind in (
        (_init_argv(), "init"),
        (_plan_argv(), "plan"),
        ([_EXE, f"-chdir={_WS}", "show", "-json", _PLAN], "show"),
    ):
        cmd = validate_plan_only_command(argv, executable=_EXE, workspace=_WS, plan_file=_PLAN)
        assert cmd.kind == kind


@pytest.mark.parametrize(
    "argv",
    [
        [_EXE, f"-chdir={_WS}", "apply", "-auto-approve"],
        [_EXE, f"-chdir={_WS}", "destroy", "-auto-approve"],
        [_EXE, f"-chdir={_WS}", "plan", "-input=false", "-no-color", "-lock=true", "-destroy"],
        [_EXE, f"-chdir={_WS}", "state", "list"],
        [_EXE, f"-chdir={_WS}", "import", "res", "id"],
        [_EXE, f"-chdir={_WS}", "workspace", "select", "prod"],
        [_EXE, f"-chdir={_WS}", "force-unlock", "lock-id"],
        [_EXE, "-chdir=/etc", "plan", "-input=false", "-no-color", "-lock=true", f"-out={_PLAN}"],
        [_EXE, f"-chdir={_WS}", "plan", "-input=false", "-no-color", "-lock=true", "-out=/etc/x"],
        [_EXE, f"-chdir={_WS}", "show", "-json", "/etc/passwd"],
        [_EXE, f"-chdir={_WS}", "plan", "-input=false", "-no-color", "-lock=true", "-out=$(x)"],
    ],
)
def test_grammar_refuses_apply_destroy_and_every_other_shape(argv):
    from secp_worker.plan_gen.process_boundary import (
        PlanOnlyProcessError,
        validate_plan_only_command,
    )

    with pytest.raises(PlanOnlyProcessError):
        validate_plan_only_command(argv, executable=_EXE, workspace=_WS, plan_file=_PLAN)


# --- the worker-only, non-serializable capability ------------------------------------------------


def _activation(**overrides):
    from secp_api.plan_activation_contract import PLAN_ONLY_CAPABILITY_CONTRACT_VERSION
    from secp_worker.plan_gen.capability import CONTROLLED_LIVE_CLASSIFICATION, PlanOnlyActivation
    from secp_worker.plan_gen.controlled_live import (
        CONTROLLED_LIVE_PROVIDER_SOURCE,
        CONTROLLED_LIVE_RENDERER_VERSION,
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.process_boundary import (
        PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        plan_only_executor_implementation_digest,
    )

    h = lambda c: "sha256:" + c * 64  # noqa: E731 - compact test hash helper
    base = dict(
        organization_id=uuid.uuid4(),
        plan_generation_authorization_id=uuid.uuid4(),
        authorization_version=1,
        authorization_expiry=NOW + timedelta(hours=2),
        operation_fingerprint=h("c"),
        plan_only_capability_contract_version=PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
        classification=CONTROLLED_LIVE_CLASSIFICATION,
        expires_at=NOW + timedelta(hours=1),
        environment_version_id=uuid.uuid4(),
        environment_version_content_hash=h("d"),
        deployment_plan_id=uuid.uuid4(),
        deployment_plan_content_hash=h("e"),
        provisioning_manifest_id=uuid.uuid4(),
        provisioning_manifest_content_hash=h("b"),
        execution_target_id=uuid.uuid4(),
        target_config_hash=h("f"),
        target_onboarding_id=uuid.uuid4(),
        onboarding_boundary_hash=h("1"),
        eligibility_preflight_id=uuid.uuid4(),
        eligibility_evidence_hash=h("2"),
        toolchain_profile_id=uuid.uuid4(),
        toolchain_profile_hash=h("3"),
        toolchain_attestation_id=uuid.uuid4(),
        toolchain_attestation_hash=h("4"),
        fresh_attestation_evidence_hash=h("5"),
        provider_source=CONTROLLED_LIVE_PROVIDER_SOURCE,
        provider_version="0.80.0",
        provider_lockfile_hash=h("6"),
        provider_mirror_identity=h("7"),
        module_bundle_hash=h("8"),
        renderer_version=CONTROLLED_LIVE_RENDERER_VERSION,
        activation_dossier_id=uuid.uuid4(),
        activation_dossier_hash=h("a"),
        activation_dossier_revision=1,
        activation_dossier_expiry=NOW + timedelta(hours=3),
        provider_credential_binding_id=uuid.uuid4(),
        provider_credential_binding_version=1,
        state_credential_binding_id=uuid.uuid4(),
        state_credential_binding_version=1,
        remote_state_readiness_id=uuid.uuid4(),
        remote_state_evidence_hash=h("9"),
        plan_secret_readiness_id=uuid.uuid4(),
        plan_secret_evidence_hash=h("0"),
        worker_identity_registration_id=uuid.uuid4(),
        worker_identity_version=1,
        execution_lease_id=uuid.uuid4(),
        attempt_id=uuid.uuid4(),
        attempt_number=1,
        process_implementation_id=PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        process_implementation_digest=plan_only_executor_implementation_digest(),
        renderer_module_id=CONTROLLED_LIVE_RENDERER_VERSION,
        renderer_module_digest=controlled_live_renderer_implementation_digest(),
    )
    base.update(overrides)
    return PlanOnlyActivation(**base)


def _issue(activation, *, now=NOW):
    from secp_worker.plan_gen.capability import issue_plan_only_capability
    from secp_worker.plan_gen.controlled_live import (
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.process_boundary import plan_only_executor_implementation_digest

    return issue_plan_only_capability(
        activation,
        now=now,
        expected_process_digest=plan_only_executor_implementation_digest(),
        expected_renderer_digest=controlled_live_renderer_implementation_digest(),
    )


def test_capability_cannot_be_constructed_without_the_module_token():
    from secp_worker.plan_gen.capability import PlanOnlyCapability

    with pytest.raises(TypeError):
        PlanOnlyCapability(object(), _activation())


def test_issued_capability_is_non_serializable_and_redacted():
    cap = _issue(_activation())
    with pytest.raises(TypeError):
        pickle.dumps(cap)
    with pytest.raises(TypeError):
        cap.__getstate__()
    for rendered in (repr(cap), str(cap), f"{cap}"):
        assert "redacted" in rendered
        assert cap.activation.activation_dossier_hash not in rendered
        assert cap.activation.operation_fingerprint not in rendered


def test_capability_is_refused_when_expired_or_contract_drifted():
    from secp_worker.plan_gen.capability import PlanOnlyCapabilityRefused

    with pytest.raises(PlanOnlyCapabilityRefused, match="expired"):
        _issue(_activation(expires_at=NOW - timedelta(seconds=1)))
    with pytest.raises(PlanOnlyCapabilityRefused, match="contract"):
        _issue(_activation(plan_only_capability_contract_version="wrong/v0"))


def test_capability_is_refused_on_implementation_digest_drift():
    """A self-declared contract version is not enough: the process/renderer digest must be exact."""
    from secp_worker.plan_gen.capability import PlanOnlyCapabilityRefused

    with pytest.raises(PlanOnlyCapabilityRefused, match="process implementation digest"):
        _issue(_activation(process_implementation_digest="sha256:" + "0" * 64))
    with pytest.raises(PlanOnlyCapabilityRefused, match="renderer implementation digest"):
        _issue(_activation(renderer_module_digest="sha256:" + "0" * 64))
    with pytest.raises(PlanOnlyCapabilityRefused, match="classification"):
        _issue(_activation(classification="bogus"))


def test_capability_issuance_refuses_the_old_v1_implementation_identity():
    """The seal flip advanced the executor identity v1 -> v2. A capability minted against the OLD
    sealed v1 process implementation id/digest cannot be issued for the unsealed v2 executor."""
    import hashlib

    from secp_worker.plan_gen.capability import PlanOnlyCapabilityRefused

    v1_id = "secp-002b-1b-pr5b/plan-only-executor/v1"
    v1_digest = "sha256:" + hashlib.sha256(v1_id.encode()).hexdigest()
    # An activation carrying the exact old v1 digest is refused at issuance (expected digest is v2).
    v1_act = _activation(process_implementation_id=v1_id, process_implementation_digest=v1_digest)
    with pytest.raises(PlanOnlyCapabilityRefused, match="process implementation digest"):
        _issue(v1_act)


# --- the plan_gen package imports nothing capable of I/O -----------------------------------------


@pytest.mark.parametrize("path", _plan_gen_files(), ids=lambda p: p.name)
def test_no_plan_gen_module_imports_subprocess_or_transport(path):
    subprocess_ok = path.name in _SUBPROCESS_ALLOWED_IN
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        for module in modules:
            root = module.split(".")[0]
            if root == "subprocess" and subprocess_ok:
                # The plan-only executor is the sole allowed subprocess site (seal-gated grammar).
                continue
            assert root not in FORBIDDEN_IMPORT_ROOTS, f"{path.name}: {module}"


def test_the_orchestration_constructs_no_generic_subprocess_executor():
    """The plan-gen orchestration reaches the plan-only seal and STOPS; it never constructs the
    generic ``SubprocessProcessExecutor`` and names no such symbol in code."""
    src = (PLAN_GEN_PKG / "orchestration.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    called = {
        (n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", ""))
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
    }
    assert "SubprocessProcessExecutor" not in called
    assert "build_process_executor" not in called
    assert "run_real_provisioning" not in called


# --- the API boundary ----------------------------------------------------------------------------


def test_the_api_imports_no_worker_module_and_names_no_plan_gen_symbol():
    for path in sorted(API_PKG.rglob("*.py")):
        # dispatch.py is the pre-existing narrowly allowlisted crossing (inline dev dispatcher →
        # secp_worker.orchestration only). It never imports plan_gen.
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                assert "plan_gen" not in module, f"{path.name}: {module}"
                if path.name != "dispatch.py":
                    assert not module.startswith("secp_worker"), f"{path.name}: {module}"
        # No worker-only plan-gen symbol is NAMED in API code either.
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        leaked = names & FORBIDDEN_PLAN_GEN_NAMES
        assert not leaked, f"{path.name}: {leaked}"


def test_the_real_plan_generation_workflow_is_registered_only_in_the_worker():
    worker_main = (ROOT / "apps" / "worker" / "secp_worker" / "main.py").read_text(encoding="utf-8")
    assert "RealPlanGenerationWorkflow" in worker_main
    assert "real_plan_generation_activity" in worker_main
    # The API may reference the workflow NAME string to enqueue (dispatch.py), but never imports the
    # workflow class or the activity FUNCTION — those run only in the worker.
    for path in sorted(API_PKG.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "real_plan_generation_activity" not in text, path.name


# --- the durable PR5A models carry no secret-bearing column --------------------------------------


def test_no_plan_activation_model_has_a_secret_bearing_column():
    from secp_api.plan_activation_models import (
        RealLabActivationDossier,
        RealLabActivationDossierEvidence,
        RealPlanGenerationAttempt,
        RealPlanGenerationAuthorization,
    )

    forbidden_fragments = (
        "secret",
        "token",
        "password",
        "credential_reference",
        "secret_ref",
        "endpoint",
        "url",
        "bucket",
        "container",
        "object_key",
        "state_key",
        "state_path",
        "namespace_name",
        "access_key",
        "response",
        "body",
        "stack",
        "argv",
        "command",
    )
    # Opaque FK / hash references to the plan-SECRET-readiness RECORD (which itself carries no
    # secret) — an id or a digest, never a secret value or reference.
    allowed = {"plan_secret_readiness_id", "plan_secret_evidence_hash"}
    for model in (
        RealLabActivationDossier,
        RealLabActivationDossierEvidence,
        RealPlanGenerationAuthorization,
        RealPlanGenerationAttempt,
    ):
        for column in model.__table__.columns:  # type: ignore[attr-defined]
            if column.name in allowed:
                continue
            for fragment in forbidden_fragments:
                assert fragment not in column.name, f"{model.__tablename__}.{column.name}"  # type: ignore[attr-defined]
