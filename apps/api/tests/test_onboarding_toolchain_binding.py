"""SECP-002B-1B-0 correction pass — toolchain provenance is bound through preflight approval
and execution (ADR-014 §4): the approved preflight's toolchain profile id/hash must equal the
current active profile == plan == manifest == pinned execution profile. Drift is refused at
onboarding approval, manifest generation, and the worker gate. Fakes only."""

from __future__ import annotations

import copy

import pytest
from secp_api.config import Settings
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    ProvisioningOperationKind,
)
from secp_api.errors import DomainError, ProvisioningRefusedError, ValidationFailedError
from secp_api.onboarding import boundary_from_scope
from secp_api.services import onboarding as onb
from secp_api.services import toolchain as toolchain_svc
from secp_worker.provisioning import FakeProcessExecutor, build_fixture_show_json
from secp_worker.provisioning.execution import run_real_provisioning
from tests.conftest import (  # type: ignore
    VALID_PROVISIONING_SCOPE,
    VALID_TOOLCHAIN_PROFILE,
)

REAL_ON = Settings(
    app_env="test",
    provisioning_application_mode="isolated_lab",
    enable_real_provisioning=True,
    workflow_dispatch_mode="temporal",
)


def _target_with_toolchain(session, principal, slug):
    from secp_api.services import targets

    target = targets.register_target(
        session,
        principal,
        display_name=f"TC-{slug}",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref=f"env:SECP_PROVIDER_SECRET__{slug.upper()}",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
        address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    )
    tp = toolchain_svc.register_toolchain_profile(
        session,
        principal,
        target_id=target.id,
        name=f"{slug}-v1",
        profile=copy.deepcopy(VALID_TOOLCHAIN_PROFILE),
    )
    session.commit()
    return target, tp


def _profile_variant(label: str, byte: str) -> dict:
    profile = copy.deepcopy(VALID_TOOLCHAIN_PROFILE)
    profile["module_bundle_id"] = f"secp-fake-lab-bundle-{label}"
    profile["module_bundle_hash"] = "sha256:" + byte * 32
    return profile


def _target_with_two_active_toolchains(session, principal, slug):
    from secp_api.services import targets

    target = targets.register_target(
        session,
        principal,
        display_name=f"TC2-{slug}",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref=f"env:SECP_PROVIDER_SECRET__{slug.upper()}",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
        address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    )
    older = toolchain_svc.register_toolchain_profile(
        session,
        principal,
        target_id=target.id,
        name=f"{slug}-v1",
        profile=_profile_variant(f"{slug}-old", "aa"),
    )
    current = toolchain_svc.register_toolchain_profile(
        session,
        principal,
        target_id=target.id,
        name=f"{slug}-v2",
        profile=_profile_variant(f"{slug}-current", "bb"),
    )
    session.commit()
    assert older.version < current.version
    assert older.status == current.status
    return target, older, current


def _approved_plan_with_reservations(session, principal, target, slug):
    from secp_api.models import TargetPreflight
    from secp_api.services import catalog, exercises, planning, reservations
    from tests.conftest import VALID_DEFINITION, onboard_and_activate

    onboarding = onboard_and_activate(session, principal, target)
    preflight = session.get(TargetPreflight, onboarding.approved_preflight_id)
    tmpl = catalog.create_template(session, principal, name=f"TCP-{slug}", slug=f"tcp-{slug}")
    ver = catalog.create_version(
        session, principal, template_id=tmpl.id, definition=VALID_DEFINITION
    )
    ex = exercises.create_exercise(
        session,
        principal,
        template_id=tmpl.id,
        version_id=ver.id,
        name=f"tcp-{slug}",
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, ex.id)
    plan = planning.generate_plan(session, principal, ex.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "ok")
    for team in ("team1", "team2"):
        reservations.reserve_network(
            session, principal, target_id=target.id, team_ref=team, exercise_id=ex.id
        )
    session.commit()
    return onboarding, preflight, plan


def test_toolchain_drift_refuses_onboarding_approval(session, principal):
    target, _tp = _target_with_toolchain(session, principal, "appr")
    ob = onb.create_onboarding(
        session,
        principal,
        target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        declared_boundary=boundary_from_scope(target.scope_policy),
    )
    onb.record_simulated_preflight(session, principal, ob.id)  # provenance -> v1
    # A new profile version becomes the active profile after the preflight was recorded.
    toolchain_svc.register_toolchain_profile(
        session,
        principal,
        target_id=target.id,
        name="appr-v2",
        profile=copy.deepcopy(VALID_TOOLCHAIN_PROFILE),
    )
    onb.submit_for_review(session, principal, ob.id)
    with pytest.raises(DomainError, match="toolchain"):
        onb.approve_onboarding(session, principal, ob.id, "should refuse")


def test_toolchain_drift_refuses_manifest_generation(session, principal):
    from secp_api.services import catalog, exercises, planning, reservations
    from tests.conftest import VALID_DEFINITION, onboard_and_activate

    target, _tp = _target_with_toolchain(session, principal, "mani")
    onboard_and_activate(session, principal, target)
    tmpl = catalog.create_template(session, principal, name="TCM", slug="tcm")
    ver = catalog.create_version(
        session, principal, template_id=tmpl.id, definition=VALID_DEFINITION
    )
    ex = exercises.create_exercise(
        session,
        principal,
        template_id=tmpl.id,
        version_id=ver.id,
        name="tcm",
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, ex.id)
    plan = planning.generate_plan(session, principal, ex.id)  # pins v1
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "ok")
    for team in ("team1", "team2"):
        reservations.reserve_network(
            session, principal, target_id=target.id, team_ref=team, exercise_id=ex.id
        )
    session.commit()
    # Replace the active profile after plan approval but before manifest generation.
    toolchain_svc.register_toolchain_profile(
        session,
        principal,
        target_id=target.id,
        name="mani-v2",
        profile=copy.deepcopy(VALID_TOOLCHAIN_PROFILE),
    )
    session.commit()
    from secp_api.services import manifests

    with pytest.raises(ValidationFailedError, match="toolchain"):
        manifests.generate_manifest(session, principal, plan.id)


def test_manifest_generation_refuses_plan_pinned_to_older_active_toolchain(session, principal):
    """Regression: preflight == current active is not enough; plan must also pin exactly
    that same toolchain profile id/hash before a manifest can be created."""
    from secp_api.models import DeploymentPlan, ProvisioningManifest
    from secp_api.services import manifests

    target, older, current = _target_with_two_active_toolchains(session, principal, "pin")
    _onboarding, preflight, plan = _approved_plan_with_reservations(
        session, principal, target, "pin"
    )
    assert preflight.toolchain_profile_id == current.id
    assert preflight.toolchain_profile_hash == current.content_hash
    assert plan.toolchain_profile_id == current.id
    assert plan.toolchain_profile_hash == current.content_hash

    # Direct-SQL corruption: the plan still points at a valid, active profile, but it is the
    # older one, not the approved preflight/current-active profile.
    session.execute(
        DeploymentPlan.__table__.update()
        .where(DeploymentPlan.__table__.c.id == plan.id)
        .values(toolchain_profile_id=older.id, toolchain_profile_hash=older.content_hash)
    )
    session.commit()
    session.expire_all()

    with pytest.raises(ValidationFailedError, match="toolchain provenance"):
        manifests.generate_manifest(session, principal, plan.id)
    assert (
        session.query(ProvisioningManifest)
        .filter(ProvisioningManifest.deployment_plan_id == plan.id)
        .count()
        == 0
    )


def test_toolchain_disabled_after_manifest_refuses_real_provisioning(session, principal, lab_env):
    env = lab_env()
    toolchain_svc.disable_toolchain_profile(session, principal, env.toolchain.id)
    session.commit()
    with pytest.raises(ProvisioningRefusedError, match="toolchain"):
        run_real_provisioning(
            session,
            env.manifest.id,
            ProvisioningOperationKind.dry_run,
            executor=FakeProcessExecutor(show_json=build_fixture_show_json(env.manifest.content)),
            settings=REAL_ON,
            dispatch_mode="temporal",
        )


def test_worker_gate_refuses_plan_pinned_to_older_active_toolchain(session, principal):
    """Worker-side equivalent: if a valid manifest exists and the plan is later corrupted to
    an older still-active profile, the gate refuses before rendering/process work."""
    from secp_api.models import DeploymentPlan
    from secp_api.services import manifests

    target, older, current = _target_with_two_active_toolchains(session, principal, "gate")
    _onboarding, preflight, plan = _approved_plan_with_reservations(
        session, principal, target, "gate"
    )
    assert preflight.toolchain_profile_id == current.id
    manifest = manifests.generate_manifest(session, principal, plan.id)
    session.commit()

    session.execute(
        DeploymentPlan.__table__.update()
        .where(DeploymentPlan.__table__.c.id == plan.id)
        .values(toolchain_profile_id=older.id, toolchain_profile_hash=older.content_hash)
    )
    session.commit()
    session.expire_all()

    with pytest.raises(ProvisioningRefusedError, match="toolchain profile"):
        run_real_provisioning(
            session,
            manifest.id,
            ProvisioningOperationKind.dry_run,
            executor=FakeProcessExecutor(show_json=build_fixture_show_json(manifest.content)),
            settings=REAL_ON,
            dispatch_mode="temporal",
        )


def test_preflight_evidence_toolchain_tamper_refuses_real_provisioning(session, principal, lab_env):
    """Direct-SQL tamper of the approved preflight's toolchain provenance breaks the evidence
    hash and is refused at the worker gate (the toolchain provenance is hash-bound)."""
    from secp_api.models import TargetPreflight

    env = lab_env()
    session.execute(
        TargetPreflight.__table__.update()
        .where(TargetPreflight.__table__.c.id == env.onboarding.approved_preflight_id)
        .values(toolchain_profile_hash="sha256:" + "ff" * 32)
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ProvisioningRefusedError, match="altered"):
        run_real_provisioning(
            session,
            env.manifest.id,
            ProvisioningOperationKind.dry_run,
            executor=FakeProcessExecutor(show_json=build_fixture_show_json(env.manifest.content)),
            settings=REAL_ON,
            dispatch_mode="temporal",
        )
