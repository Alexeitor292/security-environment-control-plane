"""SECP-002B-1B-9 — declarative staging-lab service lifecycle tests (fake-only, no infrastructure).

Covers the end-to-end lifecycle, approval binding to the exact immutable plan hash, rejection on
plan drift, separation from LiveReadAuthorization, immutability of identity/plan, idempotent
simulation + retry safety, fake teardown, org scoping, secret-free audit, and refusal of an
unapproved substrate.
"""

from __future__ import annotations

import json

import pytest
from secp_api.enums import (
    IsolationModel,
    LiveReadAuthorizationStatus,
    OnboardingMode,
    OnboardingStatus,
    StagingLabStatus,
    TargetStatus,
)
from secp_api.errors import AuthorizationError, DomainError, ImmutableResourceError
from secp_api.models import AuditEvent, ExecutionTarget, StagingLab, TargetOnboarding
from secp_api.services import staging_labs

BOOTSTRAP_PROFILE = "approved-offline-profile-a"


def _target(session, principal, *, status=TargetStatus.active) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="staging substrate",
        plugin_name="proxmox",
        config={},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="env:SECP_PROVIDER_SECRET__FAKE",
        status=status,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    return target


def _active_onboarding(session, principal, target) -> TargetOnboarding:
    ob = TargetOnboarding(
        organization_id=principal.organization_id,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.logical,
        status=OnboardingStatus.active,
        declared_boundary={},
        boundary_hash="sha256:" + "cd" * 32,
        created_by=principal.user_id,
    )
    session.add(ob)
    session.flush()
    return ob


def _approved_substrate(session, principal):
    target = _target(session, principal)
    _active_onboarding(session, principal, target)
    return target


def _create(session, principal, target, **over):
    kwargs = dict(
        execution_target_id=target.id,
        display_name="Alpha Lab",
        ownership_label="secp-lab-alpha",
        bootstrap_artifact_profile_id=BOOTSTRAP_PROFILE,
    )
    kwargs.update(over)
    return staging_labs.create_staging_lab(session, principal, **kwargs)


def _plan_and_approve(session, principal, lab) -> StagingLab:
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    return staging_labs.approve_staging_lab(
        session, principal, lab.id, expected_plan_hash=lab.plan_hash, reason="reviewed"
    )


def test_full_lifecycle_to_simulated_ready_and_teardown(session, principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    assert lab.status == StagingLabStatus.draft

    staging_labs.generate_plan(session, principal, lab.id)
    assert lab.status == StagingLabStatus.planned
    assert lab.plan_hash and lab.desired_state is not None and lab.plan_version == 1

    staging_labs.submit_for_approval(session, principal, lab.id)
    assert lab.status == StagingLabStatus.awaiting_approval

    staging_labs.approve_staging_lab(
        session, principal, lab.id, expected_plan_hash=lab.plan_hash, reason="ok"
    )
    assert lab.status == StagingLabStatus.approved
    assert lab.approved_plan_hash == lab.plan_hash
    assert lab.approved_plan_version == lab.plan_version
    assert lab.approved_by == principal.user_id and lab.approved_at is not None

    staging_labs.request_simulation(session, principal, lab.id)
    assert lab.status == StagingLabStatus.simulated_ready
    observed = lab.simulated_observed_state
    assert observed["simulated"] is True and observed["creates_infrastructure"] is False
    assert len(observed["resources"]) == 6
    assert all(r["owner"] == "secp-lab-alpha" for r in observed["resources"])

    staging_labs.request_teardown(session, principal, lab.id)
    assert lab.status == StagingLabStatus.destroyed
    assert all(
        r["observed_phase"] == "simulated_destroyed"
        for r in lab.simulated_observed_state["resources"]
    )


def test_approval_requires_exact_plan_hash_and_rejects_drift(session, principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    # A reviewer approving a *different* hash (as if the plan changed after review) is refused.
    with pytest.raises(DomainError):
        staging_labs.approve_staging_lab(
            session, principal, lab.id, expected_plan_hash="sha256:" + "00" * 32
        )
    assert lab.status == StagingLabStatus.awaiting_approval


def test_simulation_is_idempotent_and_retry_safe(session, principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)

    staging_labs.request_simulation(session, principal, lab.id)
    first = lab.simulated_observed_state
    first_ids = sorted(r["resource_id"] for r in first["resources"])

    # Re-simulate: same owned resource set, no duplicates.
    staging_labs.request_simulation(session, principal, lab.id)
    second_ids = sorted(r["resource_id"] for r in lab.simulated_observed_state["resources"])
    assert first_ids == second_ids
    assert len(second_ids) == len(set(second_ids)) == 6


def test_approval_is_not_a_live_read_authorization(session, principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    session.commit()
    # Approving the lab created no LiveReadAuthorization row, and the audit says so.
    from secp_api.models import LiveReadAuthorization

    assert session.query(LiveReadAuthorization).count() == 0
    events = session.query(AuditEvent).filter(AuditEvent.resource_id == str(lab.id)).all()
    approved = next(e for e in events if e.action == "staging_lab.approved")
    assert approved.data["authorizes"] == "fake_simulation_only"
    assert approved.data["live_read_authorization"] is False
    # The staging-lab lifecycle is a distinct enum/record from the live-read authorization
    # lifecycle: staging approval is only permission to enter fake simulation, and a
    # LiveReadAuthorization remains separately required for any future real collection.
    assert lab.status.__class__ is not LiveReadAuthorizationStatus
    assert lab.status == StagingLabStatus.approved


def test_unapproved_substrate_is_refused_at_plan(session, principal):
    target = _target(session, principal)  # active target but NO active onboarding
    lab = _create(session, principal, target)
    with pytest.raises(DomainError) as exc:
        staging_labs.generate_plan(session, principal, lab.id)
    assert "unapproved_substrate" in str(exc.value)
    # The refusal is audited with a generic reason code, secret-free.
    session.flush()
    events = session.query(AuditEvent).filter(AuditEvent.resource_id == str(lab.id)).all()
    assert any(e.action == "staging_lab.refused" for e in events)


def test_identity_and_plan_are_immutable(session, principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    staging_labs.generate_plan(session, principal, lab.id)
    session.commit()

    lab.ownership_label = "secp-lab-tampered"
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()

    lab = session.get(StagingLab, lab.id)
    lab.plan_hash = "sha256:" + "ff" * 32
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()

    lab = session.get(StagingLab, lab.id)
    with pytest.raises(ImmutableResourceError):
        session.delete(lab)
        session.flush()


def test_cross_org_access_is_refused(session, principal, other_org_principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    with pytest.raises(AuthorizationError):
        staging_labs.get_staging_lab(session, other_org_principal, lab.id)


def test_audit_trail_is_secret_free(session, principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    staging_labs.request_simulation(session, principal, lab.id)
    session.commit()
    events = session.query(AuditEvent).filter(AuditEvent.resource_id == str(lab.id)).all()
    blob = json.dumps([e.data for e in events]).lower()
    for forbidden in ("secret", "token", "password", "credential", "://", "env:secp_", "@pam"):
        assert forbidden not in blob


def test_illegal_transition_is_refused(session, principal):
    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    # Cannot simulate a draft lab (must be approved first).
    with pytest.raises(DomainError):
        staging_labs.request_simulation(session, principal, lab.id)


def test_manage_permission_required(session, principal):
    from dataclasses import replace

    target = _approved_substrate(session, principal)
    powerless = replace(principal, permissions=frozenset())
    with pytest.raises(AuthorizationError):
        _create(session, powerless, target)


def test_staging_lab_approval_uses_its_own_permission(session, principal):
    from dataclasses import replace

    from secp_api.enums import Permission

    target = _approved_substrate(session, principal)
    lab = _create(session, principal, target)
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    # A principal holding only the LIVE-READ / onboarding approval permission cannot approve a
    # staging lab — staging approval requires the dedicated staging_lab:approve permission.
    onboarding_only = replace(principal, permissions=frozenset({Permission.onboarding_approve}))
    with pytest.raises(AuthorizationError):
        staging_labs.approve_staging_lab(
            session, onboarding_only, lab.id, expected_plan_hash=lab.plan_hash
        )
    staging_only = replace(principal, permissions=frozenset({Permission.staging_lab_approve}))
    staging_labs.approve_staging_lab(
        session, staging_only, lab.id, expected_plan_hash=lab.plan_hash
    )
    assert lab.status == StagingLabStatus.approved
