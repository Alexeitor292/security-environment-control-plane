"""B1B-PR5B — the worker-bootstrap composition-provider injection seam + operator factory.

The durable Temporal plan/readiness activities obtain their compositions EXCLUSIVELY from an
injected
provider. The shipped worker injects the SEALED provider (refuses before I/O); a separately reviewed
operator worker injects controlled-live providers via ``build_operator_activity_set``. These prove
the injection is explicit, sealed-by-default, non-config-activatable, IDs-only across Temporal, and
that no readiness operation triggers plan generation and no plan operation triggers apply — with the
plan-only seal ``False`` and both B1-A seals ``True``. No network, real filesystem layout, real
OpenTofu, Proxmox, OpenBao, or state backend is used.
"""

from __future__ import annotations

import ast
import contextlib
import pathlib
import uuid

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[3]
_TEMPORAL_APP = _ROOT / "apps" / "worker" / "secp_worker" / "temporal_app.py"


# --- helpers: build the exact controlled-live / sealed / test-only compositions -------------------


def _controlled_live_plan_composition():
    from tests.test_plan_execution_components import _activated_composition

    return _activated_composition(classification="controlled_live")


def _test_only_plan_composition():
    from tests.test_plan_execution_components import _activated_composition

    return _activated_composition(classification="test_only")


def _controlled_live_readiness_composition():
    from secp_worker.readiness.composition import ReadinessComposition, ReadinessGate

    return ReadinessComposition(gate=ReadinessGate(enabled=True))


def _controlled_live_eligibility_composition():
    from secp_worker.onboarding.eligibility_preflight import (
        EligibilityPreflightComposition,
        EligibilityPreflightGate,
    )

    return EligibilityPreflightComposition(gate=EligibilityPreflightGate(enabled=True))


@contextlib.contextmanager
def _fake_session_scope():
    """A no-DB session scope: the injection tests never touch a real database."""
    yield object()


class _SpyProvider:
    """A provider whose ``get`` returns a fixed composition and records that it was called."""

    classification = "controlled_live"

    def __init__(self, composition) -> None:
        self.composition = composition
        self.get_calls = 0

    def get(self):
        self.get_calls += 1
        return self.composition


# --- 1. providers: sealed default, controlled-live, test-only, masquerade refusals ----------------


def test_sealed_plan_provider_always_returns_the_disabled_composition():
    from secp_worker.plan_gen.composition_provider import (
        SEALED_DEFAULT_PROVIDER,
        SealedPlanExecutionCompositionProvider,
    )

    provider = SealedPlanExecutionCompositionProvider()
    assert provider.classification == SEALED_DEFAULT_PROVIDER
    comp = provider.get()
    assert comp.gate.enabled is False
    assert comp.classification == ""  # the shipped default carries no classification


def test_controlled_live_plan_provider_accepts_only_a_controlled_live_composition():
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        sealed_plan_execution_composition,
    )
    from secp_worker.plan_gen.composition_provider import (
        CONTROLLED_LIVE_PROVIDER,
        ControlledLivePlanExecutionCompositionProvider,
    )

    provider = ControlledLivePlanExecutionCompositionProvider(_controlled_live_plan_composition())
    assert provider.classification == CONTROLLED_LIVE_PROVIDER
    assert provider.get().classification == "controlled_live"

    # A SEALED default cannot masquerade as controlled-live (verify raises composition_sealed).
    with pytest.raises(PlanExecutionCompositionError, match="composition_sealed"):
        ControlledLivePlanExecutionCompositionProvider(sealed_plan_execution_composition())
    # A TEST-ONLY composition is refused by the controlled-live provider.
    with pytest.raises(PlanExecutionCompositionError, match="not_controlled_live"):
        ControlledLivePlanExecutionCompositionProvider(_test_only_plan_composition())
    # A non-composition object is refused.
    with pytest.raises(PlanExecutionCompositionError, match="provider_composition_invalid"):
        ControlledLivePlanExecutionCompositionProvider(object())


def test_test_only_plan_provider_cannot_carry_a_controlled_live_composition():
    from secp_worker.plan_gen.composition import PlanExecutionCompositionError
    from secp_worker.plan_gen.composition_provider import (
        TEST_ONLY_PROVIDER,
        TestOnlyPlanExecutionCompositionProvider,
    )

    provider = TestOnlyPlanExecutionCompositionProvider(_test_only_plan_composition())
    assert provider.classification == TEST_ONLY_PROVIDER
    assert provider.get().classification == "test_only"
    # A controlled-live composition cannot be laundered through the test-only provider.
    with pytest.raises(PlanExecutionCompositionError, match="not_test_only"):
        TestOnlyPlanExecutionCompositionProvider(_controlled_live_plan_composition())


def test_readiness_and_eligibility_controlled_live_providers_refuse_sealed_defaults():
    from secp_worker.onboarding.eligibility_preflight import sealed_eligibility_composition
    from secp_worker.onboarding.eligibility_provider import (
        ControlledLiveEligibilityCompositionProvider,
        EligibilityCompositionProviderError,
    )
    from secp_worker.readiness.composition import (
        ReadinessComposition,
        ReadinessGate,
        sealed_readiness_composition,
    )
    from secp_worker.readiness.composition_provider import (
        ControlledLiveReadinessCompositionProvider,
        ReadinessCompositionProviderError,
    )

    # Controlled-live accepts an enabled composition; refuses the sealed default + a test_only one.
    ControlledLiveReadinessCompositionProvider(_controlled_live_readiness_composition())
    with pytest.raises(ReadinessCompositionProviderError, match="is_sealed_default"):
        ControlledLiveReadinessCompositionProvider(sealed_readiness_composition())
    with pytest.raises(ReadinessCompositionProviderError, match="is_test_only"):
        ControlledLiveReadinessCompositionProvider(
            ReadinessComposition(gate=ReadinessGate(enabled=True), test_only_capability=True)
        )

    ControlledLiveEligibilityCompositionProvider(_controlled_live_eligibility_composition())
    with pytest.raises(EligibilityCompositionProviderError, match="is_sealed_default"):
        ControlledLiveEligibilityCompositionProvider(sealed_eligibility_composition())


def test_providers_are_non_serializable():
    import pickle

    from secp_worker.plan_gen.composition_provider import (
        ControlledLivePlanExecutionCompositionProvider,
        SealedPlanExecutionCompositionProvider,
    )

    for provider in (
        SealedPlanExecutionCompositionProvider(),
        ControlledLivePlanExecutionCompositionProvider(_controlled_live_plan_composition()),
    ):
        with pytest.raises(TypeError):
            pickle.dumps(provider)


# --- 2. operator factory: typed deps, refuse missing/sealed, no I/O -------------------------------


def test_operator_factory_builds_the_activity_set_from_controlled_live_compositions():
    from secp_worker.operator_bootstrap import OperatorActivitySet, build_operator_activity_set
    from secp_worker.temporal_app import (
        RealPlanGenerationActivity,
        RemoteStateReadinessActivity,
    )

    activity_set = build_operator_activity_set(
        plan_execution_composition=_controlled_live_plan_composition(),
        readiness_composition=_controlled_live_readiness_composition(),
        eligibility_composition=_controlled_live_eligibility_composition(),
    )
    assert isinstance(activity_set, OperatorActivitySet)
    assert isinstance(activity_set.real_plan_generation, RealPlanGenerationActivity)
    assert isinstance(activity_set.remote_state_readiness, RemoteStateReadinessActivity)
    # Five registerable bound methods (never combining authorities): the three readiness activities
    # share the readiness composition but each uses only its own per-operation seam.
    assert len(activity_set.registerable_activities()) == 5


def test_operator_factory_refuses_missing_or_sealed_compositions():
    from secp_worker.operator_bootstrap import OperatorBootstrapError, build_operator_activity_set
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        sealed_plan_execution_composition,
    )

    with pytest.raises(OperatorBootstrapError, match="missing_plan_execution_composition"):
        build_operator_activity_set(
            plan_execution_composition=None,
            readiness_composition=_controlled_live_readiness_composition(),
            eligibility_composition=_controlled_live_eligibility_composition(),
        )
    # A shipped SEALED plan composition is refused (it can never be laundered through the factory).
    with pytest.raises(PlanExecutionCompositionError, match="composition_sealed"):
        build_operator_activity_set(
            plan_execution_composition=sealed_plan_execution_composition(),
            readiness_composition=_controlled_live_readiness_composition(),
            eligibility_composition=_controlled_live_eligibility_composition(),
        )


# --- 3. injection reaches run_plan_generation; cancellation precedes composition contact ----------


def test_controlled_live_provider_reaches_run_plan_generation_with_the_exact_composition(
    monkeypatch,
):
    from secp_worker.plan_gen.composition_provider import (
        ControlledLivePlanExecutionCompositionProvider,
    )
    from secp_worker.temporal_app import run_real_plan_generation_activity_body

    comp = _controlled_live_plan_composition()
    provider = ControlledLivePlanExecutionCompositionProvider(comp)
    seen: dict = {}

    class _Result:
        outcome = "refused"

    def _spy(session, *, manifest_id, composition, now):  # noqa: ANN001
        seen["composition"] = composition
        seen["manifest_id"] = manifest_id
        return _Result()

    monkeypatch.setattr("secp_api.db.session_scope", _fake_session_scope)
    monkeypatch.setattr("secp_worker.plan_gen.orchestration.run_plan_generation", _spy)

    out = run_real_plan_generation_activity_body(
        {"manifest_id": str(uuid.uuid4())}, composition_provider=provider
    )
    assert out == "refused"
    # The EXACT injected composition reached run_plan_generation — not
    # build_plan_execution_composition.
    assert seen["composition"] is comp


def test_cancellation_is_checked_before_the_composition_is_obtained(monkeypatch):
    from secp_worker.temporal_app import run_real_plan_generation_activity_body

    class _NoGetProvider:
        classification = "controlled_live"

        def get(self):
            raise AssertionError("provider.get() must not be called after cancellation")

    monkeypatch.setattr("secp_api.db.session_scope", _fake_session_scope)
    monkeypatch.setattr("secp_worker.temporal_app._cancelled", lambda: True)

    out = run_real_plan_generation_activity_body(
        {"manifest_id": str(uuid.uuid4())}, composition_provider=_NoGetProvider()
    )
    assert out == "refused"  # cancelled → refused BEFORE the provider (or any I/O) is touched


def test_readiness_activities_use_their_independently_injected_compositions(monkeypatch):
    from secp_worker import temporal_app

    class _FakeManifest:
        organization_id = uuid.uuid4()
        toolchain_profile_id = uuid.uuid4()

    class _FakeSession:
        def get(self, model, _id):  # noqa: ANN001
            name = getattr(model, "__name__", "")
            return _FakeManifest() if name == "ProvisioningManifest" else None

    @contextlib.contextmanager
    def _scope():
        yield _FakeSession()

    class _Result:
        outcome = "unverifiable"

    state_seen: dict = {}
    secret_seen: dict = {}

    def _state_spy(session, *, manifest_id, composition, now):  # noqa: ANN001
        state_seen["composition"] = composition
        return _Result()

    def _secret_spy(session, *, manifest_id, composition, now):  # noqa: ANN001
        secret_seen["composition"] = composition
        return _Result()

    monkeypatch.setattr("secp_api.db.session_scope", _scope)
    monkeypatch.setattr(
        "secp_worker.readiness.state_readiness.run_remote_state_readiness", _state_spy
    )
    monkeypatch.setattr(
        "secp_worker.readiness.plan_secret_readiness.run_plan_secret_readiness", _secret_spy
    )

    state_comp = _controlled_live_readiness_composition()
    secret_comp = _controlled_live_readiness_composition()
    temporal_app.run_remote_state_readiness_activity_body(
        {"manifest_id": str(uuid.uuid4())}, readiness_provider=_SpyProvider(state_comp)
    )
    temporal_app.run_plan_secret_readiness_activity_body(
        {"manifest_id": str(uuid.uuid4())}, readiness_provider=_SpyProvider(secret_comp)
    )
    # Each readiness activity used ITS OWN injected composition (separate authorities, never
    # shared).
    assert state_seen["composition"] is state_comp
    assert secret_seen["composition"] is secret_comp
    assert state_seen["composition"] is not secret_seen["composition"]


# --- 4. IDs-only Temporal args, no config activation, no module-global mutable provider -----------


def test_no_environment_or_config_value_alone_activates_the_live_provider(monkeypatch):
    from secp_worker.plan_gen.composition import build_plan_execution_composition
    from secp_worker.plan_gen.composition_provider import SealedPlanExecutionCompositionProvider

    # No settings/env produces anything but the disabled composition; the sealed provider is fixed.
    monkeypatch.setenv("SECP_ENABLE_PLAN_ONLY", "true")
    monkeypatch.setenv("SECP_PLAN_EXECUTION_COMPOSITION", "controlled_live")
    for settings in (None, {"enabled": True}, object()):
        assert build_plan_execution_composition(settings).gate.enabled is False
    assert SealedPlanExecutionCompositionProvider().get().gate.enabled is False


def test_the_shipped_module_level_activities_all_use_sealed_providers():
    """The shipped worker's default activity instances carry ONLY sealed providers — there is no
    module-global mutable/controlled-live provider that could be set to activate live execution."""
    from secp_worker import temporal_app
    from secp_worker.onboarding.eligibility_provider import SealedEligibilityCompositionProvider
    from secp_worker.plan_gen.composition_provider import SealedPlanExecutionCompositionProvider
    from secp_worker.readiness.composition_provider import SealedReadinessCompositionProvider

    assert isinstance(
        temporal_app._SEALED_REAL_PLAN_GENERATION_ACTIVITY._composition_provider,
        SealedPlanExecutionCompositionProvider,
    )
    assert isinstance(
        temporal_app._SEALED_ELIGIBILITY_ACTIVITY._eligibility_provider,
        SealedEligibilityCompositionProvider,
    )
    for attr in (
        "_SEALED_TOOLCHAIN_ACTIVITY",
        "_SEALED_REMOTE_STATE_ACTIVITY",
        "_SEALED_PLAN_SECRET_ACTIVITY",
    ):
        assert isinstance(
            getattr(temporal_app, attr)._readiness_provider, SealedReadinessCompositionProvider
        )
    # No module attribute is a CONTROLLED-LIVE provider instance.
    from secp_worker.plan_gen.composition_provider import (
        ControlledLivePlanExecutionCompositionProvider,
    )

    for value in vars(temporal_app).values():
        assert not isinstance(value, ControlledLivePlanExecutionCompositionProvider)


def test_missing_provider_refuses_at_activity_construction():
    from secp_worker.temporal_app import RealPlanGenerationActivity, ToolchainAttestationActivity

    with pytest.raises(ValueError, match="composition_provider is required"):
        RealPlanGenerationActivity(None)
    with pytest.raises(ValueError, match="readiness_provider is required"):
        ToolchainAttestationActivity(None)


def test_workflow_arguments_and_activity_dispatch_remain_ids_only():
    """The workflows dispatch by the stable activity NAME with the IDs-only dict arg — no
    composition,
    provider, path, endpoint, credential, or capability is ever placed in a Temporal argument."""
    from secp_worker import temporal_app

    assert temporal_app.REAL_PLAN_GENERATION_ACTIVITY_NAME == "real_plan_generation_activity"
    src = _TEMPORAL_APP.read_text(encoding="utf-8")
    tree = ast.parse(src)
    # Every workflow.execute_activity(...) first arg is a NAME constant/string (never a
    # composition).
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute_activity"
        ):
            first = node.args[0]
            assert isinstance(first, ast.Name | ast.Constant), ast.dump(first)
    # No composition/provider symbol is passed into a workflow argument.
    for forbidden in ("composition", "provider", "PlanExecutionComposition"):
        # Only NAME-constant dispatch appears in the workflow run bodies.
        assert f"execute_activity({forbidden}" not in src


def test_the_api_imports_no_provider_composition_or_operator_bootstrap():
    api_pkg = _ROOT / "apps" / "api" / "secp_api"
    forbidden = {
        "composition_provider",
        "operator_bootstrap",
        "PlanExecutionCompositionProvider",
        "build_operator_activity_set",
        "OperatorActivitySet",
        "build_plan_execution_composition",
        "sealed_plan_execution_composition",
    }
    for path in api_pkg.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.add(node.module)
                names.update(a.name for a in node.names)
        assert not (names & forbidden), f"{path.name} imports {names & forbidden}"


# --- 5. no automatic chaining; no plan→apply; all three seals
# --------------------------------------


def test_no_readiness_activity_triggers_plan_generation():
    """Readiness bodies never call run_plan_generation; completing readiness triggers no plan."""
    src = _TEMPORAL_APP.read_text(encoding="utf-8")
    tree = ast.parse(src)
    readiness_bodies = {
        "run_toolchain_attestation_activity_body",
        "_run_readiness_activity_body",
        "run_remote_state_readiness_activity_body",
        "run_plan_secret_readiness_activity_body",
        "run_eligibility_preflight_activity_body",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in readiness_bodies:
            called = {
                (c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", ""))
                for c in ast.walk(node)
                if isinstance(c, ast.Call)
            }
            assert "run_plan_generation" not in called, node.name


def test_no_plan_operation_triggers_apply_and_no_apply_workflow_exists():
    src = _TEMPORAL_APP.read_text(encoding="utf-8")
    for forbidden in (
        "ApplyWorkflow",
        "apply_activity",
        "run_apply",
        "PlanApplyWorkflow",
        "destroy_from_plan",
    ):
        assert forbidden not in src, forbidden


def test_all_three_seals_are_unchanged_by_the_bootstrap():
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert pb._PLAN_ONLY_PROCESS_SEALED is False
    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True
