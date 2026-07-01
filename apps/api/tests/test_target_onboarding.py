"""SECP-002B-1B-0 target onboarding — modes, isolation models, completeness, drift,
immutability, and the approval-gated lifecycle. All fakes; no real target is touched."""

from __future__ import annotations

import copy

import pytest
from secp_api.enums import IsolationModel, OnboardingMode, OnboardingStatus
from secp_api.errors import DomainError, ImmutableResourceError, ValidationFailedError
from secp_api.models import AuditEvent, ExecutionTarget
from secp_api.services import onboarding as onb
from secp_worker.onboarding import FakePreflightCollector
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


def _drive_to_approved(session, principal, ob, *, isolation):
    checks = FakePreflightCollector().collect(
        declared_boundary=ob.declared_boundary, isolation_model=isolation.value
    )
    onb.record_preflight(session, principal, ob.id, checks=checks)
    onb.submit_for_review(session, principal, ob.id)
    onb.approve_onboarding(session, principal, ob.id, "reviewed")


# --- both modes and both isolation models are valid --------------------------


@pytest.mark.parametrize("mode", [OnboardingMode.clean_server, OnboardingMode.existing_environment])
def test_both_onboarding_modes_are_valid(session, principal, mode):
    target = _register_target(session, principal, slug=f"m_{mode.value}")
    ob = _create(session, principal, target, mode=mode, isolation=IsolationModel.logical)
    assert ob.onboarding_mode == mode
    assert ob.status == OnboardingStatus.draft


@pytest.mark.parametrize("isolation", [IsolationModel.physical, IsolationModel.logical])
def test_both_isolation_models_are_valid(session, principal, isolation):
    target = _register_target(session, principal, slug=f"i_{isolation.value}")
    ob = _create(
        session, principal, target, mode=OnboardingMode.existing_environment, isolation=isolation
    )
    assert ob.isolation_model == isolation


# --- completeness + external connectivity ------------------------------------


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
    # Preflight WITHOUT the no_route_to_protected check → not passing for logical.
    checks = FakePreflightCollector(omit={"no_route_to_protected"}).collect(
        declared_boundary=ob.declared_boundary, isolation_model="logical"
    )
    pf = onb.record_preflight(session, principal, ob.id, checks=checks)
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
    _drive_to_approved(session, principal, ob, isolation=IsolationModel.logical)
    assert ob.status == OnboardingStatus.approved
    onb.activate_onboarding(session, principal, ob.id)
    assert ob.status == OnboardingStatus.active
    assert ob.activated_at is not None


def test_activation_requires_approval(session, principal):
    target = _register_target(session, principal, slug="needapproval")
    ob = _create(
        session,
        principal,
        target,
        mode=OnboardingMode.existing_environment,
        isolation=IsolationModel.logical,
    )
    checks = FakePreflightCollector().collect(
        declared_boundary=ob.declared_boundary, isolation_model="logical"
    )
    onb.record_preflight(session, principal, ob.id, checks=checks)
    onb.submit_for_review(session, principal, ob.id)  # ready_for_review, NOT approved
    with pytest.raises(DomainError, match="only 'approved' can be activated"):
        onb.activate_onboarding(session, principal, ob.id)


def test_creating_onboarding_never_activates_a_target(session, principal):
    """No config submission alone activates — a fresh onboarding is draft."""
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
    _drive_to_approved(session, principal, ob, isolation=IsolationModel.logical)
    session.commit()
    # Declared boundary + identity are immutable.
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
    _drive_to_approved(session, principal, ob, isolation=IsolationModel.logical)
    session.commit()
    # Broaden the target scope policy AFTER approval → approval invalidated.
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
