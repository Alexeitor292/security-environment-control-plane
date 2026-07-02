"""SECP-002B-1B-0 target onboarding — modes, isolation, completeness, boundary⊆scope,
drift, immutability, approval-gated lifecycle, and fail-closed single-active. Fakes only."""

from __future__ import annotations

import copy

import pytest
from secp_api.enums import (
    CollectorKind,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    VerificationLevel,
)
from secp_api.errors import DomainError, ImmutableResourceError, ValidationFailedError
from secp_api.models import AuditEvent, ExecutionTarget, TargetOnboarding
from secp_api.onboarding import simulate_boundary_checks
from secp_api.services import onboarding as onb
from tests.conftest import VALID_ONBOARDING_BOUNDARY, VALID_PROVISIONING_SCOPE  # type: ignore


def _register_target(session, principal, *, slug="lab"):
    from secp_api.services import targets

    t = targets.register_target(
        session,
        principal,
        display_name="Onboarding Target (placeholder)",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref=f"env:SECP_PROVIDER_SECRET__{slug.upper()}",
        scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
    )
    session.commit()
    return t


def _create(session, principal, target, *, mode, isolation, boundary=None):
    return onb.create_onboarding(
        session,
        principal,
        target_id=target.id,
        onboarding_mode=mode,
        isolation_model=isolation,
        declared_boundary=copy.deepcopy(boundary or VALID_ONBOARDING_BOUNDARY),
    )


def _drive_to_approved(session, principal, ob):
    onb.record_simulated_preflight(session, principal, ob.id)
    onb.submit_for_review(session, principal, ob.id)
    onb.approve_onboarding(session, principal, ob.id, "reviewed")


# --- both modes and both isolation models are valid --------------------------


@pytest.mark.parametrize("mode", [OnboardingMode.clean_server, OnboardingMode.existing_environment])
def test_both_onboarding_modes_are_valid(session, principal, mode):
    target = _register_target(session, principal, slug=f"m_{mode.value}")
    ob = _create(session, principal, target, mode=mode, isolation=IsolationModel.logical)
    assert ob.onboarding_mode == mode and ob.status == OnboardingStatus.draft


@pytest.mark.parametrize("isolation", [IsolationModel.physical, IsolationModel.logical])
def test_both_isolation_models_are_valid(session, principal, isolation):
    target = _register_target(session, principal, slug=f"i_{isolation.value}")
    ob = _create(
        session, principal, target, mode=OnboardingMode.existing_environment, isolation=isolation
    )
    assert ob.isolation_model == isolation


# --- completeness + external connectivity + boundary ⊆ scope -----------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.pop("nodes"),
        lambda b: b.__setitem__("nodes", []),
        lambda b: b.__setitem__("storage", ["*"]),
        lambda b: b.pop("cidrs"),
        lambda b: b.__setitem__("cidrs", ["0.0.0.0/0"]),
        lambda b: b.pop("quotas"),
        lambda b: b.pop("vmid_range"),
    ],
)
def test_incomplete_boundary_cannot_be_created(session, principal, mutate):
    target = _register_target(session, principal, slug="incomplete")
    bad = copy.deepcopy(VALID_ONBOARDING_BOUNDARY)
    mutate(bad)
    with pytest.raises(ValidationFailedError):
        _create(
            session,
            principal,
            target,
            mode=OnboardingMode.existing_environment,
            isolation=IsolationModel.logical,
            boundary=bad,
        )


def test_external_connectivity_allow_is_refused(session, principal):
    target = _register_target(session, principal, slug="extconn")
    bad = copy.deepcopy(VALID_ONBOARDING_BOUNDARY)
    bad["external_connectivity"] = {"policy": "allow"}
    with pytest.raises(ValidationFailedError):
        _create(
            session,
            principal,
            target,
            mode=OnboardingMode.existing_environment,
            isolation=IsolationModel.logical,
            boundary=bad,
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.__setitem__("nodes", ["pve-node-1", "pve-node-2", "pve-node-99"]),
        lambda b: b.__setitem__("storage", ["local-lvm", "extra-store"]),
        lambda b: b.__setitem__("network_segments", ["vmbr0", "vmbr9"]),
        lambda b: b.__setitem__("cidrs", ["10.99.0.0/16"]),
        lambda b: b.__setitem__("vmid_range", {"start": 8000, "end": 9100}),
        lambda b: b["quotas"].__setitem__("max_vms", 99999),
    ],
)
def test_boundary_broader_than_target_scope_is_refused(session, principal, mutate):
    target = _register_target(session, principal, slug="broader")
    bad = copy.deepcopy(VALID_ONBOARDING_BOUNDARY)
    mutate(bad)
    with pytest.raises(ValidationFailedError, match="broader than the target"):
        _create(
            session,
            principal,
            target,
            mode=OnboardingMode.existing_environment,
            isolation=IsolationModel.logical,
            boundary=bad,
        )


# --- logical isolation requires no-route evidence ----------------------------


def test_logical_isolation_requires_no_route_evidence(session, principal):
    target = _register_target(session, principal, slug="noroute")
    ob = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    checks = simulate_boundary_checks(
        ob.declared_boundary, IsolationModel.logical, omit={"no_route_to_protected"}
    )
    pf = onb.record_preflight_result(
        session,
        ob.id,
        checks=checks,
        verification_level=VerificationLevel.simulated.value,
        collector_kind=CollectorKind.fake_declared_boundary.value,
        collector_identity="control-plane-simulator",
    )
    assert pf.passed is False
    with pytest.raises(DomainError, match="passing preflight"):
        onb.submit_for_review(session, principal, ob.id)


# --- approval-gated lifecycle ------------------------------------------------


def test_full_lifecycle_reaches_active(session, principal):
    target = _register_target(session, principal, slug="lifecycle")
    ob = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    _drive_to_approved(session, principal, ob)
    assert ob.status == OnboardingStatus.approved
    assert ob.approved_preflight_id is not None and ob.approved_preflight_evidence_hash
    onb.activate_onboarding(session, principal, ob.id)
    assert ob.status == OnboardingStatus.active and ob.activated_at is not None


def test_activation_requires_approval(session, principal):
    target = _register_target(session, principal, slug="needapproval")
    ob = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    onb.record_simulated_preflight(session, principal, ob.id)
    onb.submit_for_review(session, principal, ob.id)  # ready_for_review, NOT approved
    with pytest.raises(DomainError, match="only 'approved' can be activated"):
        onb.activate_onboarding(session, principal, ob.id)


def test_creating_onboarding_never_activates_a_target(session, principal):
    target = _register_target(session, principal, slug="noautoactivate")
    ob = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.clean_server,
        isolation=IsolationModel.physical,
    )
    assert ob.status == OnboardingStatus.draft
    assert onb.active_onboarding_for_target(session, target.id) is None


# --- fail-closed single active ------------------------------------------------


def test_second_activation_is_refused_while_one_active(session, principal):
    target = _register_target(session, principal, slug="singleactive")
    ob1 = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    _drive_to_approved(session, principal, ob1)
    onb.activate_onboarding(session, principal, ob1.id)
    session.commit()
    ob2 = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    _drive_to_approved(session, principal, ob2)
    with pytest.raises(DomainError, match="already active"):
        onb.activate_onboarding(session, principal, ob2.id)


def test_db_rejects_a_second_active_onboarding(session, principal):
    """Direct-SQL corruption: the partial unique index rejects a 2nd active row."""
    from sqlalchemy.exc import IntegrityError

    target = _register_target(session, principal, slug="dbindex")
    ob1 = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    _drive_to_approved(session, principal, ob1)
    onb.activate_onboarding(session, principal, ob1.id)
    session.commit()
    rogue = TargetOnboarding(
        organization_id=target.organization_id,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary=copy.deepcopy(VALID_ONBOARDING_BOUNDARY),
        boundary_hash="sha256:rogue",
    )
    session.add(rogue)
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_active_selection_fails_closed_on_multiple(session, principal):
    """Defense-in-depth: with the DB index dropped, the service still fails closed."""
    from sqlalchemy import text as sqltext

    target = _register_target(session, principal, slug="ambig")
    ob1 = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    _drive_to_approved(session, principal, ob1)
    onb.activate_onboarding(session, principal, ob1.id)
    session.commit()
    # Drop the enforcing index, then force a second active row.
    session.execute(sqltext("DROP INDEX uq_target_onboarding_active"))
    ob2 = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    session.execute(
        TargetOnboarding.__table__.update()
        .where(TargetOnboarding.__table__.c.id == ob2.id)
        .values(status="active")
    )
    session.commit()
    session.expire_all()
    with pytest.raises(DomainError, match="ambiguous active onboarding"):
        onb.active_onboarding_for_target(session, target.id)


# --- immutability + auditability + drift -------------------------------------


def test_onboarding_approval_is_immutable_and_audited(session, principal):
    target = _register_target(session, principal, slug="immutable")
    ob = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    _drive_to_approved(session, principal, ob)
    session.commit()
    ob.declared_boundary = {**ob.declared_boundary, "nodes": ["pve-node-9"]}
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    actions = {e.action for e in session.query(AuditEvent).all()}
    assert "onboarding.approved" in actions and "onboarding.created" in actions


def test_scope_drift_after_approval_invalidates_activation(session, principal):
    target = _register_target(session, principal, slug="drift")
    ob = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    _drive_to_approved(session, principal, ob)
    session.commit()
    drifted = copy.deepcopy(target.scope_policy)
    drifted["provisioning"]["max_vms"] = 999
    session.execute(
        ExecutionTarget.__table__.update()
        .where(ExecutionTarget.__table__.c.id == target.id)
        .values(scope_policy=drifted)
    )
    session.commit()
    session.expire_all()
    with pytest.raises(DomainError, match="invalidated"):
        onb.activate_onboarding(session, principal, ob.id)
