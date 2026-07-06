"""App-owned worker-owned target-discovery lifecycle service (SECP-B5).

Control-plane only. The API owns the enrollment desired state, durable read-only discovery job
records,
and the explicit approval of a discovery-derived candidate plan — it NEVER runs a probe, contacts a
host, or imports worker/SSH/Proxmox/subprocess code. Only the worker discovery engine may claim a
committed job and perform the read-only probes. Approval binds ONE exact candidate-plan hash + every
drift anchor (enrollment version, evidence hash, capacity-snapshot hash, worker identity version,
expiry); any drift or expiry fails closed. Live deployment apply of the plan remains sealed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.discovery_contract import discovery_operation_fingerprint
from secp_api.enums import (
    AuditAction,
    DiscoveryDecisionCode,
    DiscoveryJobStatus,
    OnboardingStatus,
    Permission,
    TargetDiscoveryStatus,
    WorkerIdentityStatus,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import (
    DiscoveryCandidatePlan,
    DiscoveryCandidatePlanApproval,
    DiscoveryJob,
    ExecutionTarget,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
    WorkerIdentityRegistration,
)
from secp_api.services.staging_labs import assert_safe_logical_name

_PROFILES = frozenset({"small_lab", "medium_lab"})


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    """Normalize a possibly-naive stored datetime (SQLite drops tz) to timezone-aware UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _ownership_label(enrollment_id: uuid.UUID) -> str:
    return f"secp-discover-{enrollment_id.hex[:12]}"


def _display_name(enrollment_id: uuid.UUID, logical_name: str | None) -> str:
    return f"target-discovery-{logical_name or enrollment_id.hex[:8]}"


def _get(session: Session, actor: Principal, enrollment_id: uuid.UUID) -> TargetDiscoveryEnrollment:
    row = session.get(TargetDiscoveryEnrollment, enrollment_id)
    if row is None:
        raise NotFoundError(f"target discovery enrollment {enrollment_id} not found")
    actor.require_org(row.organization_id)
    return row


def _active_onboarding(session: Session, target_id: uuid.UUID) -> TargetOnboarding | None:
    return session.execute(
        select(TargetOnboarding).where(
            TargetOnboarding.execution_target_id == target_id,
            TargetOnboarding.status == OnboardingStatus.active,
        )
    ).scalar_one_or_none()


def _approved_identity_version(session: Session, org_id: uuid.UUID) -> int:
    row = session.execute(
        select(WorkerIdentityRegistration).where(
            WorkerIdentityRegistration.organization_id == org_id,
            WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
        )
    ).scalar_one_or_none()
    return int(row.identity_version) if row is not None else 0


def _cas(
    session: Session,
    row: TargetDiscoveryEnrollment,
    *,
    expected: TargetDiscoveryStatus,
    new: TargetDiscoveryStatus,
    extra: dict | None = None,
) -> bool:
    values: dict = {"status": new, "revision": row.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(TargetDiscoveryEnrollment)
        .where(
            TargetDiscoveryEnrollment.id == row.id,
            TargetDiscoveryEnrollment.status == expected,
            TargetDiscoveryEnrollment.revision == row.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _enqueue_job(
    session: Session, row: TargetDiscoveryEnrollment, actor: Principal
) -> DiscoveryJob:
    fingerprint = discovery_operation_fingerprint(row.id, row.enrollment_version)
    existing = session.execute(
        select(DiscoveryJob).where(DiscoveryJob.operation_fingerprint == fingerprint)
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    job = DiscoveryJob(
        enrollment_id=row.id,
        organization_id=row.organization_id,
        operation_fingerprint=fingerprint,
        enrollment_version=row.enrollment_version,
        status=DiscoveryJobStatus.queued,
        created_by=actor.user_id,
    )
    session.add(job)
    try:
        session.flush()
    except IntegrityError as exc:  # a job is already in flight for this enrollment
        session.rollback()
        raise DomainError("a discovery job is already in flight for this enrollment") from exc
    return job


def request_discovery(
    session: Session,
    actor: Principal,
    *,
    execution_target_id: uuid.UUID,
    resource_profile: str = "small_lab",
    logical_name: str | None = None,
) -> TargetDiscoveryEnrollment:
    """Create a target-discovery enrollment bound to an active onboarding and enqueue the durable
    read-only discovery job (server labels only; no host/endpoint/credential input)."""
    actor.require(Permission.target_discovery_manage)
    if resource_profile not in _PROFILES:
        raise DomainError("unknown resource profile")
    if logical_name:
        logical_name = assert_safe_logical_name(logical_name)
    target = session.get(ExecutionTarget, execution_target_id)
    if target is None:
        raise NotFoundError(f"execution target {execution_target_id} not found")
    actor.require_org(target.organization_id)
    onboarding = _active_onboarding(session, target.id)
    if onboarding is None:
        raise DomainError("execution target has no active onboarding")

    enrollment_id = uuid.uuid4()
    row = TargetDiscoveryEnrollment(
        id=enrollment_id,
        organization_id=target.organization_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        display_name=_display_name(enrollment_id, logical_name),
        ownership_label=_ownership_label(enrollment_id),
        resource_profile=resource_profile,
        status=TargetDiscoveryStatus.requested,
        decision_code=DiscoveryDecisionCode.pending,
        enrollment_version=1,
        created_by=actor.user_id,
    )
    session.add(row)
    session.flush()
    _enqueue_job(session, row, actor)
    audit.record(
        session,
        action=AuditAction.target_discovery_requested,
        resource_type="target_discovery_enrollment",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data={"ownership_label": row.ownership_label, "enrollment_version": row.enrollment_version},
    )
    return row


def rerun_discovery(
    session: Session, actor: Principal, enrollment_id: uuid.UUID
) -> TargetDiscoveryEnrollment:
    """Bump the enrollment version, clear any prior plan, and enqueue a fresh read-only discovery
    job. A prior approval is invalidated because it binds the old version + evidence."""
    actor.require(Permission.target_discovery_manage)
    row = _get(session, actor, enrollment_id)
    if row.status in (TargetDiscoveryStatus.discovering,):
        raise DomainError("discovery is already running for this enrollment")
    onboarding = _active_onboarding(session, row.execution_target_id)
    if onboarding is None or onboarding.id != row.onboarding_id:
        raise DomainError("active onboarding changed; re-enroll the target")
    row.enrollment_version = row.enrollment_version + 1
    row.status = TargetDiscoveryStatus.requested
    row.decision_code = DiscoveryDecisionCode.pending
    row.active_plan_hash = ""
    row.approved_plan_hash = ""
    row.approved_by = None
    row.approved_at = None
    row.failure_code = None
    row.revision = row.revision + 1
    session.flush()
    _enqueue_job(session, row, actor)
    audit.record(
        session,
        action=AuditAction.target_discovery_requested,
        resource_type="target_discovery_enrollment",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data={"enrollment_version": row.enrollment_version, "rerun": True},
    )
    return row


def approve_candidate_plan(
    session: Session,
    actor: Principal,
    enrollment_id: uuid.UUID,
    *,
    expected_plan_hash: str,
) -> TargetDiscoveryEnrollment:
    """Approve the EXACT candidate plan, binding every drift anchor. Fails closed on drift/expiry.
    Approval grants NO execution — live apply remains sealed pending controlled integration."""
    actor.require(Permission.target_discovery_approve)
    row = _get(session, actor, enrollment_id)
    if row.status != TargetDiscoveryStatus.plan_ready:
        raise DomainError(f"enrollment is '{row.status.value}'; only plan_ready is approvable")
    if not expected_plan_hash or expected_plan_hash != row.active_plan_hash:
        raise DomainError("expected plan hash does not match the current candidate plan")
    plan = session.execute(
        select(DiscoveryCandidatePlan).where(
            DiscoveryCandidatePlan.enrollment_id == row.id,
            DiscoveryCandidatePlan.plan_hash == row.active_plan_hash,
        )
    ).scalar_one_or_none()
    if plan is None:
        raise DomainError("candidate plan record not found")
    now = _utcnow()
    if _aware(plan.expires_at) <= now:
        raise DomainError("candidate plan has expired; re-run discovery")
    if plan.enrollment_version != row.enrollment_version:
        raise DomainError("candidate plan is stale (enrollment changed); re-run discovery")
    if _approved_identity_version(session, row.organization_id) != plan.worker_identity_version:
        raise DomainError("worker identity changed since discovery; re-run discovery")
    onboarding = _active_onboarding(session, row.execution_target_id)
    if onboarding is None or onboarding.id != row.onboarding_id:
        raise DomainError("active onboarding changed; re-enroll the target")

    approval = DiscoveryCandidatePlanApproval(
        enrollment_id=row.id,
        organization_id=row.organization_id,
        plan_hash=plan.plan_hash,
        plan_version=plan.plan_version,
        snapshot_id=plan.snapshot_id,
        ownership_tag=plan.ownership_tag,
        capacity_snapshot_hash=plan.capacity_snapshot_hash,
        evidence_hash=plan.evidence_hash,
        worker_identity_version=plan.worker_identity_version,
        enrollment_version=plan.enrollment_version,
        expires_at=plan.expires_at,
        approved_by=actor.user_id,
    )
    session.add(approval)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DomainError("candidate plan already approved") from exc
    # The candidate plan is immutable; approval state lives on the enrollment + the immutable
    # approval record, never by mutating the content-addressed plan.
    if not _cas(
        session,
        row,
        expected=TargetDiscoveryStatus.plan_ready,
        new=TargetDiscoveryStatus.approved,
        extra={
            "decision_code": DiscoveryDecisionCode.approved,
            "approved_plan_hash": plan.plan_hash,
            "approved_by": actor.user_id,
            "approved_at": now,
        },
    ):
        raise DomainError("enrollment changed concurrently; retry approval")
    audit.record(
        session,
        action=AuditAction.discovery_plan_approved,
        resource_type="target_discovery_enrollment",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data={"plan_hash": plan.plan_hash, "executable": False},
    )
    return row


def reject_candidate_plan(
    session: Session, actor: Principal, enrollment_id: uuid.UUID
) -> TargetDiscoveryEnrollment:
    actor.require(Permission.target_discovery_approve)
    row = _get(session, actor, enrollment_id)
    if row.status != TargetDiscoveryStatus.plan_ready:
        raise DomainError("only a plan_ready enrollment can be rejected")
    if not _cas(
        session,
        row,
        expected=TargetDiscoveryStatus.plan_ready,
        new=TargetDiscoveryStatus.failed,
        extra={"decision_code": DiscoveryDecisionCode.rejected_policy},
    ):
        raise DomainError("enrollment changed concurrently; retry reject")
    audit.record(
        session,
        action=AuditAction.discovery_plan_rejected,
        resource_type="target_discovery_enrollment",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        outcome="denied",
        data={"enrollment_version": row.enrollment_version},
    )
    return row


# --- read helpers --------------------------------------------------------------------------------


def get_enrollment(
    session: Session, actor: Principal, enrollment_id: uuid.UUID
) -> TargetDiscoveryEnrollment:
    return _get(session, actor, enrollment_id)


def list_enrollments(session: Session, actor: Principal) -> list[TargetDiscoveryEnrollment]:
    return list(
        session.execute(
            select(TargetDiscoveryEnrollment)
            .where(TargetDiscoveryEnrollment.organization_id == actor.organization_id)
            .order_by(TargetDiscoveryEnrollment.created_at.desc())
        )
        .scalars()
        .all()
    )


def get_active_candidate_plan(
    session: Session, actor: Principal, enrollment_id: uuid.UUID
) -> DiscoveryCandidatePlan:
    row = _get(session, actor, enrollment_id)
    plan = session.execute(
        select(DiscoveryCandidatePlan).where(
            DiscoveryCandidatePlan.enrollment_id == row.id,
            DiscoveryCandidatePlan.plan_hash == row.active_plan_hash,
        )
    ).scalar_one_or_none()
    if plan is None:
        raise NotFoundError("no candidate plan is available for this enrollment")
    return plan


def get_latest_snapshot(session: Session, actor: Principal, enrollment_id: uuid.UUID):
    """The most recent immutable discovery evidence snapshot (capability/eligibility outcome)."""
    from secp_api.models import DiscoverySnapshot

    row = _get(session, actor, enrollment_id)
    return session.execute(
        select(DiscoverySnapshot)
        .where(DiscoverySnapshot.enrollment_id == row.id)
        .order_by(DiscoverySnapshot.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
