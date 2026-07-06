"""SECP-B4 corrective — worker durable claim/lease path for deployment operations.

Proves the normal worker runtime is WIRED to the engine but fails closed with the shipped SEALED
composition: it claims a committed queued apply operation with a CAS/lease, invokes the engine, and
refuses at the bootstrap boundary — the deployment transitions to rollback_required with a closed
reason and NO resource is created or host contacted. Also proves exclusive CAS claiming and
lease-based restart reclaim of a stale in-flight operation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secp_api.enums import (
    DeploymentOperationKind,
    DeploymentOperationStatus,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    StagingDeploymentStatus,
    TargetStatus,
)
from secp_api.models import (
    ExecutionTarget,
    StagingDeployment,
    StagingDeploymentOperation,
    StagingDeploymentResource,
    TargetOnboarding,
)
from secp_api.services import staging_deployment as svc
from secp_worker.deployment import consumer


def _approved_and_submitted(session, principal) -> StagingDeployment:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:secp/proxmox/target-1",
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    dep = svc.create_deployment(session, principal, execution_target_id=target.id)
    svc.generate_plan(session, principal, dep.id)
    svc.submit_for_approval(session, principal, dep.id)
    svc.approve_deployment(session, principal, dep.id, expected_plan_hash=dep.plan_hash)
    svc.submit_deployment(session, principal, dep.id)  # enqueues the durable apply op
    session.commit()
    return dep


def test_worker_claims_apply_and_sealed_composition_fails_closed(session, principal):
    dep = _approved_and_submitted(session, principal)
    op_id = consumer.claim_and_process_one(session)  # default = SEALED composition
    assert op_id is not None
    op = session.get(StagingDeploymentOperation, op_id)
    assert op.operation_kind == DeploymentOperationKind.apply
    assert op.status == DeploymentOperationStatus.failed
    assert op.failure_code == "bootstrap_unavailable"  # refused before any host action
    session.refresh(dep)
    assert dep.status == StagingDeploymentStatus.rollback_required
    assert dep.failure_code == "bootstrap_unavailable"
    # No resource was created and nothing was contacted.
    assert session.query(StagingDeploymentResource).count() == 0


def test_no_more_work_returns_none(session, principal):
    _approved_and_submitted(session, principal)
    assert consumer.claim_and_process_one(session) is not None
    assert consumer.claim_and_process_one(session) is None  # queue drained


def test_claim_is_exclusive_compare_and_swap(session, principal):
    _approved_and_submitted(session, principal)
    now = datetime.now(UTC)
    first = consumer._claim_candidate(session, now)
    assert first is not None and first.status == DeploymentOperationStatus.claimed
    # A second claim finds nothing claimable (the only op is already claimed, not yet stale).
    assert consumer._claim_candidate(session, now) is None


def test_stale_inflight_operation_is_reclaimed_after_lease(session, principal):
    _approved_and_submitted(session, principal)
    op = session.query(StagingDeploymentOperation).one()
    # Simulate a crashed worker: op stuck 'running' with an expired lease.
    op.status = DeploymentOperationStatus.running
    op.claimed_at = datetime.now(UTC) - timedelta(seconds=consumer._LEASE_SECONDS + 60)
    session.flush()
    reclaimed = consumer._claim_candidate(session, datetime.now(UTC))
    assert reclaimed is not None and reclaimed.id == op.id
    assert reclaimed.status == DeploymentOperationStatus.claimed  # reclaimed for restart recovery
