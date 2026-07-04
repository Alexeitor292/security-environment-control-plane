"""SECP-002B-1B-9 — declarative staging-lab service lifecycle tests (fake-only, no infrastructure).

Covers the end-to-end lifecycle with a DURABLE work item processed by the worker consumer,
approval CAS binding to the exact immutable plan hash, rejection on plan drift, separation from
LiveReadAuthorization, immutability of identity/plan, idempotent queueing, org scoping,
secret-free audit, substrate eligibility enforcement, and server-generated labels.
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
    StagingWorkStatus,
    TargetStatus,
)
from secp_api.errors import AuthorizationError, DomainError, ImmutableResourceError
from secp_api.models import (
    AuditEvent,
    ExecutionTarget,
    StagingLab,
    StagingLabWorkItem,
    TargetOnboarding,
)
from secp_api.services import staging_labs
from secp_worker.staging_lab.consumer import claim_and_process_one


def _target(session, principal, *, status=TargetStatus.active, plugin="proxmox") -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="staging substrate",
        plugin_name=plugin,
        config={},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=None,
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


def _eligible_substrate(session, principal):
    """An active proxmox target with an active onboarding AND granted staging eligibility."""
    target = _target(session, principal)
    _active_onboarding(session, principal, target)
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    return target


def _create(session, principal, target, **over):
    return staging_labs.create_staging_lab(
        session, principal, execution_target_id=target.id, **over
    )


def _plan_and_approve(session, principal, lab) -> StagingLab:
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    return staging_labs.approve_staging_lab(
        session, principal, lab.id, expected_plan_hash=lab.plan_hash
    )


def test_labels_are_server_generated(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target, logical_name="alpha")
    assert lab.ownership_label == f"secp-lab-{lab.id.hex[:12]}"
    assert lab.display_name == "staging-lab-alpha"


def test_full_lifecycle_queue_then_worker_completes(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    assert lab.status == StagingLabStatus.approved

    # API only QUEUES — the lab is not yet ready and there are no observations.
    staging_labs.queue_simulation(session, principal, lab.id)
    assert lab.status == StagingLabStatus.simulation_queued
    assert lab.simulated_observed_state is None
    item = session.query(StagingLabWorkItem).filter_by(staging_lab_id=lab.id).one()
    assert item.status == StagingWorkStatus.queued
    # Work identity is a server-generated fingerprint over the canonical immutable tuple.
    assert item.operation_fingerprint == staging_labs.operation_fingerprint(
        lab.id, item.operation_kind, lab.plan_hash, lab.plan_version
    )

    # The WORKER claims and processes the durable item, then records completion.
    processed = claim_and_process_one(session)
    assert processed == item.id
    session.refresh(lab)
    session.refresh(item)
    assert lab.status == StagingLabStatus.simulated_ready
    assert item.status == StagingWorkStatus.completed
    observed = lab.simulated_observed_state
    assert observed["simulated"] is True and observed["creates_infrastructure"] is False
    assert len(observed["resources"]) == 6
    assert all(r["owner"] == lab.ownership_label for r in observed["resources"])

    # Teardown: queue then worker completes.
    staging_labs.queue_teardown(session, principal, lab.id)
    assert lab.status == StagingLabStatus.teardown_queued
    claim_and_process_one(session)
    session.refresh(lab)
    assert lab.status == StagingLabStatus.destroyed
    assert all(
        r["observed_phase"] == "simulated_destroyed"
        for r in lab.simulated_observed_state["resources"]
    )


def test_no_observations_before_worker_completes(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    staging_labs.queue_simulation(session, principal, lab.id)
    assert lab.status == StagingLabStatus.simulation_queued
    assert lab.simulated_observed_state is None


def test_queue_is_idempotent_by_fingerprint(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    # No caller idempotency key exists; re-queueing the identical operation+plan resolves to the
    # original work item (server-generated fingerprint), creating no second item.
    staging_labs.queue_simulation(session, principal, lab.id)
    staging_labs.queue_simulation(session, principal, lab.id)
    items = session.query(StagingLabWorkItem).filter_by(staging_lab_id=lab.id).all()
    assert len(items) == 1


def test_conflicting_operation_fails_closed(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    staging_labs.queue_simulation(session, principal, lab.id)
    # A different operation (teardown) while a simulation is queued is refused by lifecycle —
    # never silently resolved to the simulation work item.
    with pytest.raises(DomainError):
        staging_labs.queue_teardown(session, principal, lab.id)


def test_approval_requires_exact_plan_hash_and_rejects_drift(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
    with pytest.raises(DomainError):
        staging_labs.approve_staging_lab(
            session, principal, lab.id, expected_plan_hash="sha256:" + "00" * 32
        )
    assert lab.status == StagingLabStatus.awaiting_approval


def test_approval_is_not_a_live_read_authorization(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    session.commit()
    from secp_api.models import LiveReadAuthorization

    assert session.query(LiveReadAuthorization).count() == 0
    events = session.query(AuditEvent).filter(AuditEvent.resource_id == str(lab.id)).all()
    approved = next(e for e in events if e.action == "staging_lab.approved")
    assert approved.data["authorizes"] == "fake_simulation_only"
    assert approved.data["live_read_authorization"] is False
    assert "reason" not in approved.data  # no free-text reason is persisted or audited
    assert lab.status.__class__ is not LiveReadAuthorizationStatus


def test_uneligible_substrate_is_refused_at_create(session, principal):
    target = _target(session, principal)
    _active_onboarding(session, principal, target)
    with pytest.raises(DomainError) as exc:
        _create(session, principal, target)
    assert "eligible staging substrate" in str(exc.value)


def test_identity_and_plan_are_immutable(session, principal):
    target = _eligible_substrate(session, principal)
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
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    with pytest.raises(AuthorizationError):
        staging_labs.get_staging_lab(session, other_org_principal, lab.id)


def test_audit_trail_is_secret_free(session, principal):
    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    _plan_and_approve(session, principal, lab)
    staging_labs.queue_simulation(session, principal, lab.id)
    claim_and_process_one(session)
    session.commit()
    events = session.query(AuditEvent).filter(AuditEvent.resource_id == str(lab.id)).all()
    blob = json.dumps([e.data for e in events]).lower()
    for forbidden in ("secret", "token", "password", "credential", "://", "env:secp_", "@pam"):
        assert forbidden not in blob


def test_manage_permission_required(session, principal):
    from dataclasses import replace

    target = _eligible_substrate(session, principal)
    powerless = replace(principal, permissions=frozenset())
    with pytest.raises(AuthorizationError):
        _create(session, powerless, target)


def test_staging_lab_approval_uses_its_own_permission(session, principal):
    from dataclasses import replace

    from secp_api.enums import Permission

    target = _eligible_substrate(session, principal)
    lab = _create(session, principal, target)
    staging_labs.generate_plan(session, principal, lab.id)
    staging_labs.submit_for_approval(session, principal, lab.id)
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
