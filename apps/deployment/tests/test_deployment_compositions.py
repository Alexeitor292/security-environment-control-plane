"""Typed controlled-live compositions: identity binding, fail-closed, provenance (SECP-PR5D,
#4/#9)."""

from __future__ import annotations

import dataclasses

import pytest
from _deploy_support import (
    StubControlledLiveRuntime,
    plan_execution_seams,
    valid_expected,
    valid_profile,
    valid_profile_raw,
)
from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment.compositions import (
    ControlledLiveCompositions,
    build_controlled_live_compositions,
)
from secp_operator_deployment.runtime_seams import SealedControlledLiveRuntime


def _agg():
    return build_controlled_live_compositions(
        profile=valid_profile(), runtime=StubControlledLiveRuntime(), expected=valid_expected()
    )


def test_aggregate_is_typed_and_immutable():
    from secp_worker.onboarding.eligibility_preflight import EligibilityPreflightComposition
    from secp_worker.plan_gen.composition import PlanExecutionComposition
    from secp_worker.readiness.composition import ReadinessComposition

    agg = _agg()
    assert isinstance(agg, ControlledLiveCompositions)
    assert type(agg.plan_execution) is PlanExecutionComposition
    assert type(agg.readiness) is ReadinessComposition
    assert type(agg.eligibility) is EligibilityPreflightComposition
    assert not isinstance(agg.plan_execution, dict)
    with pytest.raises(dataclasses.FrozenInstanceError):
        agg.plan_execution = None  # type: ignore[misc]


def test_plan_execution_is_controlled_live_bound():
    from secp_worker.plan_gen.composition import CONTROLLED_LIVE_CLASSIFICATION
    from secp_worker.plan_gen.process_boundary import issue_plan_only_executor

    agg = _agg()
    assert agg.plan_execution.gate.enabled is True
    assert agg.plan_execution.classification == CONTROLLED_LIVE_CLASSIFICATION
    assert agg.plan_execution.executor_factory is issue_plan_only_executor


def test_aggregate_is_accepted_by_the_reviewed_operator_consumer():
    from secp_worker.operator_bootstrap import build_operator_activity_set

    agg = _agg()
    activity_set = build_operator_activity_set(
        plan_execution_composition=agg.plan_execution,
        readiness_composition=agg.readiness,
        eligibility_composition=agg.eligibility,
    )
    assert len(activity_set.registerable_activities()) == 5


def test_provenance_bound_to_real_manifest_digest():
    from secp_operator_deployment import PACKAGE_IMPLEMENTATION_ID, package_implementation_digest

    prov = _agg().provenance
    assert prov.package_implementation_id == PACKAGE_IMPLEMENTATION_ID
    assert prov.package_implementation_digest == package_implementation_digest()


# --- blocker #4: the profile is never the sole authority ---


def test_missing_expected_identities_fails_closed():
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions(
            profile=valid_profile(), runtime=StubControlledLiveRuntime(), expected=None
        )
    assert exc.value.reason_code == "expected_identities_not_provisioned"


def test_profile_disagreeing_with_expected_refused():
    bad = valid_profile(operator_image_digest="sha256:" + "9" * 64)
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions(
            profile=bad, runtime=StubControlledLiveRuntime(), expected=valid_expected()
        )
    assert exc.value.reason_code == "operator_image_mismatch"


def test_expected_that_lies_about_package_identity_refused():
    bad_expected = valid_expected(package_implementation_digest="sha256:" + "0" * 64)
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions(
            profile=valid_profile(), runtime=StubControlledLiveRuntime(), expected=bad_expected
        )
    assert exc.value.reason_code == "expected_manifest_digest_invalid"


def test_shipped_default_runtime_fails_closed():
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions(
            profile=valid_profile(),
            runtime=SealedControlledLiveRuntime(),
            expected=valid_expected(),
        )
    assert exc.value.reason_code == "controlled_live_runtime_not_provisioned"


def test_raw_dict_profile_refused():
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions(
            profile=valid_profile_raw(),  # type: ignore[arg-type]
            runtime=StubControlledLiveRuntime(),
            expected=valid_expected(),
        )
    assert exc.value.reason_code == "profile_type_invalid"


def test_fake_non_concrete_resolver_cannot_satisfy_controlled_live():
    runtime = StubControlledLiveRuntime(seams=plan_execution_seams(provider_resolver=object()))
    with pytest.raises(Exception) as exc:
        build_controlled_live_compositions(
            profile=valid_profile(), runtime=runtime, expected=valid_expected()
        )
    assert "not_concrete" in getattr(exc.value, "reason_code", "") or "resolver" in getattr(
        exc.value, "reason_code", ""
    )


def test_incomplete_runtime_seams_refused():
    runtime = StubControlledLiveRuntime(
        seams=plan_execution_seams(deployment_activation_dossier_hash="")
    )
    with pytest.raises(Exception) as exc:
        build_controlled_live_compositions(
            profile=valid_profile(), runtime=runtime, expected=valid_expected()
        )
    assert getattr(exc.value, "reason_code", "") == "composition_dossier_binding_missing"


# --- blocker #5: readiness + eligibility + plan providers are bound to their EXACT authoritative
# TYPE OBJECT (never a forgeable module.qualname string); a foreign provider refuses ---


def test_real_readiness_and_eligibility_providers_pass_exact_type_identity():
    from secp_operator_deployment.identities import assert_reviewed_provider
    from secp_worker.onboarding.eligibility_preflight import (
        EligibilityPreflightComposition,
        EligibilityPreflightGate,
    )
    from secp_worker.onboarding.eligibility_provider import (
        ControlledLiveEligibilityCompositionProvider,
    )
    from secp_worker.readiness.composition import ReadinessComposition, ReadinessGate
    from secp_worker.readiness.composition_provider import (
        ControlledLiveReadinessCompositionProvider,
    )

    readiness = ControlledLiveReadinessCompositionProvider(
        ReadinessComposition(gate=ReadinessGate(enabled=True))
    )
    eligibility = ControlledLiveEligibilityCompositionProvider(
        EligibilityPreflightComposition(gate=EligibilityPreflightGate(enabled=True))
    )
    # the EXACT authoritative type object passes (the plan provider's real-path pass is covered by
    # a successful `_agg()`, which calls assert_reviewed_provider on the constructed plan
    # provider).
    assert_reviewed_provider(readiness, ControlledLiveReadinessCompositionProvider, reason="r")
    assert_reviewed_provider(eligibility, ControlledLiveEligibilityCompositionProvider, reason="e")


def test_forged_provider_spoofing_module_qualname_and_classification_refused():
    # A forged class that spoofs BOTH __module__ and __qualname__ to the reviewed identity AND
    # copies classification="controlled_live" would DEFEAT a module.qualname string compare — but
    # the exact type-object check refuses it for ALL THREE providers.
    from secp_operator_deployment.identities import (
        ELIGIBILITY_PROVIDER_IDENTITY,
        PLAN_PROVIDER_IDENTITY,
        READINESS_PROVIDER_IDENTITY,
        IdentityError,
        assert_reviewed_provider,
    )
    from secp_worker.onboarding.eligibility_provider import (
        ControlledLiveEligibilityCompositionProvider,
    )
    from secp_worker.plan_gen.composition_provider import (
        ControlledLivePlanExecutionCompositionProvider,
    )
    from secp_worker.readiness.composition_provider import (
        ControlledLiveReadinessCompositionProvider,
    )

    cases = [
        (ControlledLivePlanExecutionCompositionProvider, PLAN_PROVIDER_IDENTITY),
        (ControlledLiveReadinessCompositionProvider, READINESS_PROVIDER_IDENTITY),
        (ControlledLiveEligibilityCompositionProvider, ELIGIBILITY_PROVIDER_IDENTITY),
    ]
    for real_type, identity in cases:
        module, _, qualname = identity.rpartition(".")

        class _Forged:
            classification = "controlled_live"  # copies the classification string

        _Forged.__module__ = module  # spoofs module...
        _Forged.__qualname__ = qualname  # ...and qualname → a naive string identity check is fooled

        forged = _Forged()
        # prove the spoof is convincing at the string level (would defeat a module.qualname
        # compare):
        assert f"{type(forged).__module__}.{type(forged).__qualname__}" == identity
        # ...but the EXACT authoritative type-object check refuses it:
        with pytest.raises(IdentityError):
            assert_reviewed_provider(forged, real_type, reason="forged")


def test_expected_that_lies_about_readiness_provider_refused():
    bad = valid_expected(readiness_provider_identity="evil.module.Foo")
    with pytest.raises(DeploymentPackageError) as exc:
        build_controlled_live_compositions(
            profile=valid_profile(), runtime=StubControlledLiveRuntime(), expected=bad
        )
    assert exc.value.reason_code == "expected_readiness_provider_invalid"


def test_build_does_not_resolve_a_task_queue():
    agg = _agg()
    assert not hasattr(agg, "task_queue")
    assert not hasattr(agg.plan_execution, "task_queue")
