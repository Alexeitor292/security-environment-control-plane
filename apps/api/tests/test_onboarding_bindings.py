"""SECP-002B-1B-0 — enforceable onboarding bindings on plan/manifest/gate, evidence
integrity, simulated-vs-live eligibility, and boundary/scope intersection. Fakes only."""

from __future__ import annotations

import copy

import pytest
from secp_api.config import Settings
from secp_api.enums import CollectorKind, ProvisioningOperationKind, VerificationLevel
from secp_api.errors import ProvisioningRefusedError, ValidationFailedError
from secp_api.models import TargetOnboarding, TargetPreflight
from secp_api.onboarding import (
    OnboardingBoundarySpec,
    boundary_scope_intersection,
)
from secp_api.services import manifests
from secp_api.services import onboarding as onb
from secp_worker.provisioning import FakeProcessExecutor, build_fixture_show_json
from secp_worker.provisioning.execution import (
    assert_evidence_sufficient_for_execution,
    run_real_provisioning,
)
from tests.conftest import VALID_ONBOARDING_BOUNDARY, VALID_PROVISIONING_SCOPE  # type: ignore

REAL_ON = Settings(
    app_env="test",
    provisioning_application_mode="isolated_lab",
    enable_real_provisioning=True,
    workflow_dispatch_mode="temporal",
)


def _dry(session, manifest):
    return run_real_provisioning(
        session,
        manifest.id,
        ProvisioningOperationKind.dry_run,
        executor=FakeProcessExecutor(show_json=build_fixture_show_json(manifest.content)),
        settings=REAL_ON,
        dispatch_mode="temporal",
    )


# --- plan + manifest carry exact bindings ------------------------------------


def test_plan_and_manifest_carry_exact_onboarding_bindings(lab_env):
    env = lab_env()
    ob = env.onboarding
    assert env.plan.target_onboarding_id == ob.id
    assert env.plan.onboarding_boundary_hash == ob.approved_boundary_hash
    assert env.plan.approved_preflight_id == ob.approved_preflight_id
    assert env.plan.approved_preflight_evidence_hash == ob.approved_preflight_evidence_hash
    assert env.plan.onboarding_verification_level == ob.approved_verification_level

    m = env.manifest
    assert m.target_onboarding_id == ob.id
    assert m.approved_preflight_evidence_hash == ob.approved_preflight_evidence_hash
    block = m.content["onboarding"]
    assert block["target_onboarding_id"] == str(ob.id)
    assert block["approved_preflight_evidence_hash"] == ob.approved_preflight_evidence_hash
    assert block["verification_level"] == ob.approved_verification_level


def test_target_bound_plan_requires_active_onboarding(session, principal):
    """A target-bound plan cannot be generated without an active onboarding."""
    from secp_api.services import catalog, exercises, planning, targets

    target = targets.register_target(
        session,
        principal,
        display_name="No onboarding",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__NOOB",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
    )
    tmpl = catalog.create_template(session, principal, name="NoOb", slug="noob")
    from tests.conftest import VALID_DEFINITION

    ver = catalog.create_version(
        session, principal, template_id=tmpl.id, definition=VALID_DEFINITION
    )
    ex = exercises.create_exercise(
        session,
        principal,
        template_id=tmpl.id,
        version_id=ver.id,
        name="x",
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, ex.id)
    with pytest.raises(ValidationFailedError, match="no active onboarding"):
        planning.generate_plan(session, principal, ex.id)


# --- binding drift refuses manifest generation + real provisioning -----------


def test_retired_onboarding_refuses_manifest_generation(session, principal, lab_env):
    env = lab_env()
    onb.retire_onboarding(session, principal, env.onboarding.id)
    session.commit()
    with pytest.raises(ValidationFailedError, match="onboarding"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_verification_level_drift_refuses_manifest_generation(session, principal, lab_env):
    env = lab_env()
    # Direct-SQL tamper: change the onboarding approved verification level after plan gen.
    session.execute(
        TargetOnboarding.__table__.update()
        .where(TargetOnboarding.__table__.c.id == env.onboarding.id)
        .values(approved_verification_level="live_verified")
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ValidationFailedError, match="verification level"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_tampered_evidence_refuses_manifest_and_real_provisioning(session, principal, lab_env):
    env = lab_env()
    # Tamper the approved preflight evidence provenance (hash will no longer recompute).
    session.execute(
        TargetPreflight.__table__.update()
        .where(TargetPreflight.__table__.c.id == env.onboarding.approved_preflight_id)
        .values(target_config_hash="sha256:tampered")
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ValidationFailedError, match="altered"):
        manifests.generate_manifest(session, principal, env.plan.id)


def test_binding_drift_refuses_real_provisioning(session, principal, lab_env):
    env = lab_env()
    _dry(session, env.manifest)  # sanity: allowed with the intact binding
    session.commit()
    onb.retire_onboarding(session, principal, env.onboarding.id)
    session.commit()
    with pytest.raises(ProvisioningRefusedError, match="onboarding"):
        _dry(session, env.manifest)


# --- simulated vs live eligibility -------------------------------------------


def test_simulated_evidence_cannot_satisfy_live(lab_env):
    env = lab_env()
    assert env.onboarding.approved_verification_level == VerificationLevel.simulated.value
    # Simulated is fine for the fake/contract path (require_live=False)...
    assert_evidence_sufficient_for_execution(env.onboarding, require_live=False)
    # ...but can never satisfy LIVE real provisioning.
    with pytest.raises(ProvisioningRefusedError, match="live_verified"):
        assert_evidence_sufficient_for_execution(env.onboarding, require_live=True)


def test_live_verified_evidence_satisfies_live(session, principal):
    """A live_verified onboarding (fake worker fixture) satisfies the live requirement."""
    from secp_api.enums import IsolationModel, OnboardingMode
    from secp_api.onboarding import boundary_from_scope, simulate_boundary_checks
    from secp_api.services import targets

    t = targets.register_target(
        session,
        principal,
        display_name="Live",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__LIVE",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
    )
    session.commit()
    ob = onb.create_onboarding(
        session,
        principal,
        target_id=t.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        declared_boundary=boundary_from_scope(t.scope_policy),
    )
    checks = simulate_boundary_checks(ob.declared_boundary, IsolationModel.logical)
    onb.record_preflight_result(
        session,
        ob.id,
        checks=checks,
        verification_level=VerificationLevel.live_verified.value,
        collector_kind=CollectorKind.provider_worker.value,
        collector_identity="fake-provider-worker",
    )
    onb.submit_for_review(session, principal, ob.id)
    onb.approve_onboarding(session, principal, ob.id, "live reviewed")
    onb.activate_onboarding(session, principal, ob.id)
    assert ob.approved_verification_level == VerificationLevel.live_verified.value
    assert_evidence_sufficient_for_execution(ob, require_live=True)  # no raise


# --- boundary / scope intersection -------------------------------------------


def test_intersection_equals_boundary_when_within_scope():
    spec = OnboardingBoundarySpec.model_validate(VALID_ONBOARDING_BOUNDARY)
    inter = boundary_scope_intersection(spec, {"provisioning": VALID_PROVISIONING_SCOPE})
    assert inter["nodes"] == sorted(VALID_ONBOARDING_BOUNDARY["nodes"])
    assert inter["storage"] == VALID_ONBOARDING_BOUNDARY["storage"]
    assert inter["network_segments"] == VALID_ONBOARDING_BOUNDARY["network_segments"]
    assert inter["cidrs"] == VALID_ONBOARDING_BOUNDARY["cidrs"]
    assert inter["vmid_range"] == VALID_ONBOARDING_BOUNDARY["vmid_range"]


def test_automation_preserved_with_bindings(lab_env):
    env = lab_env()
    assert env.plan.summary["deployment_contract"]["manual_pre_creation_required"] is False
    assert env.manifest.content["deployment"]["scenario_resources_created_by_secp"] is True
