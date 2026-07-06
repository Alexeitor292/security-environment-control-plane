"""App-owned staging-lab deployment lifecycle service (SECP-B4).

Control-plane only. The API owns the desired state, immutable content-addressed plan, explicit
approval, and durable job records — it NEVER executes them and NEVER imports worker/provider/SSH/
OpenBao/transport/subprocess/secret code. Only a worker (see the deployment engine) may claim a
committed operation and perform any real host action, and only after re-verifying every binding.

A deployment approval binds ONE exact plan hash + target enrollment + ownership tag + capacity
assessment + artifact manifest identity + worker identity version. Any later drift fails closed
before mutation. Every transition is a compare-and-swap and records a safe, secret-free audit event.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.deployment_contract import (
    build_plan_document,
    compute_artifact_manifest_id,
    compute_capacity_assessment_hash,
    deployment_operation_fingerprint,
    deployment_plan_hash,
)
from secp_api.enums import (
    AuditAction,
    DeploymentOperationKind,
    DeploymentOperationStatus,
    OnboardingStatus,
    Permission,
    StagingDeploymentDecisionCode,
    StagingDeploymentStatus,
    WorkerIdentityStatus,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import (
    ExecutionTarget,
    StagingDeployment,
    StagingDeploymentApproval,
    StagingDeploymentOperation,
    StagingDeploymentPlan,
    StagingDeploymentResource,
    StagingDeploymentVerification,
    TargetOnboarding,
    WorkerIdentityRegistration,
)
from secp_api.ownership_contract import compute_ownership_tag
from secp_api.services.staging_labs import assert_safe_logical_name

# App-owned bounded resource profiles (never a caller free value).
_PROFILES = frozenset({"small_lab", "medium_lab"})


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _ownership_label(deployment_id: uuid.UUID) -> str:
    """Server-generated, immutable ownership label derived only from the deployment identity."""
    return f"secp-deploy-{deployment_id.hex[:12]}"


def _display_name(deployment_id: uuid.UUID, logical_name: str | None) -> str:
    return f"staging-deploy-{logical_name or deployment_id.hex[:8]}"


def _safe_audit(dep: StagingDeployment, **extra: object) -> dict:
    payload: dict[str, object] = {
        "execution_target_id": str(dep.execution_target_id),
        "ownership_label": dep.ownership_label,
        "status": dep.status.value,
        "plan_version": dep.plan_version,
        "plan_hash": dep.plan_hash,
        "revision": dep.revision,
    }
    payload.update(extra)
    return payload


def _get(session: Session, actor: Principal, deployment_id: uuid.UUID) -> StagingDeployment:
    dep = session.get(StagingDeployment, deployment_id)
    if dep is None:
        raise NotFoundError(f"staging deployment {deployment_id} not found")
    actor.require_org(dep.organization_id)
    return dep


def _active_onboarding(session: Session, target_id: uuid.UUID) -> TargetOnboarding | None:
    return session.execute(
        select(TargetOnboarding).where(
            TargetOnboarding.execution_target_id == target_id,
            TargetOnboarding.status == OnboardingStatus.active,
        )
    ).scalar_one_or_none()


def _approved_worker_identity_version(session: Session, organization_id: uuid.UUID) -> int:
    row = session.execute(
        select(WorkerIdentityRegistration).where(
            WorkerIdentityRegistration.organization_id == organization_id,
            WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
        )
    ).scalar_one_or_none()
    return int(row.identity_version) if row is not None else 0


def _cas(
    session: Session,
    dep: StagingDeployment,
    *,
    expected: StagingDeploymentStatus,
    new: StagingDeploymentStatus,
    extra: dict | None = None,
) -> bool:
    values: dict = {"status": new, "revision": dep.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(StagingDeployment)
        .where(
            StagingDeployment.id == dep.id,
            StagingDeployment.status == expected,
            StagingDeployment.revision == dep.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(dep)
    return True


# --- create / plan / approve / submit ------------------------------------------------------------


def create_deployment(
    session: Session,
    actor: Principal,
    *,
    execution_target_id: uuid.UUID,
    resource_profile: str = "small_lab",
    logical_name: str | None = None,
) -> StagingDeployment:
    """Create a draft real staging-lab deployment bound to an active onboarding (server labels)."""
    actor.require(Permission.staging_lab_manage)
    if resource_profile not in _PROFILES:
        raise DomainError("unknown resource profile")
    if logical_name is not None and logical_name != "":
        # Re-enforce the strict allowlist server-side (defense in depth; never trust the boundary).
        logical_name = assert_safe_logical_name(logical_name)
    target = session.get(ExecutionTarget, execution_target_id)
    if target is None:
        raise NotFoundError(f"execution target {execution_target_id} not found")
    actor.require_org(target.organization_id)
    onboarding = _active_onboarding(session, target.id)
    if onboarding is None:
        raise DomainError("execution target has no active onboarding")

    deployment_id = uuid.uuid4()
    dep = StagingDeployment(
        id=deployment_id,
        organization_id=target.organization_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        display_name=_display_name(deployment_id, logical_name),
        ownership_label=_ownership_label(deployment_id),
        resource_profile=resource_profile,
        status=StagingDeploymentStatus.draft,
        decision_code=StagingDeploymentDecisionCode.pending,
        created_by=actor.user_id,
    )
    session.add(dep)
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_deployment_created,
        resource_type="staging_deployment",
        resource_id=dep.id,
        organization_id=dep.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(dep),
    )
    return dep


def generate_plan(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> StagingDeployment:
    """Compile the immutable, content-addressed deployment plan (draft -> planned)."""
    actor.require(Permission.staging_lab_manage)
    dep = _get(session, actor, deployment_id)
    if dep.status not in (StagingDeploymentStatus.draft, StagingDeploymentStatus.planned):
        raise DomainError(f"deployment is '{dep.status.value}'; only draft/planned can be planned")
    onboarding = _active_onboarding(session, dep.execution_target_id)
    if onboarding is None or onboarding.id != dep.onboarding_id:
        raise DomainError("active onboarding changed; deployment cannot be planned")

    capacity_hash = compute_capacity_assessment_hash(
        boundary_hash=onboarding.boundary_hash, resource_profile=dep.resource_profile
    )
    artifact_manifest_id = compute_artifact_manifest_id(dep.resource_profile)
    plan_document = build_plan_document(
        ownership_label=dep.ownership_label,
        resource_profile=dep.resource_profile,
        capacity_assessment_hash=capacity_hash,
        artifact_manifest_id=artifact_manifest_id,
    )
    plan_hash = deployment_plan_hash(plan_document)
    plan_version = dep.plan_version + 1

    plan = StagingDeploymentPlan(
        deployment_id=dep.id,
        organization_id=dep.organization_id,
        plan_version=plan_version,
        plan_hash=plan_hash,
        ownership_tag=compute_ownership_tag(dep.ownership_label),
        capacity_assessment_hash=capacity_hash,
        artifact_manifest_id=artifact_manifest_id,
        plan_document=plan_document,
        created_by=actor.user_id,
    )
    session.add(plan)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DomainError("plan already exists for this deployment") from exc

    if not _cas(
        session,
        dep,
        expected=dep.status,
        new=StagingDeploymentStatus.planned,
        extra={
            "plan_hash": plan_hash,
            "plan_version": plan_version,
            "decision_code": StagingDeploymentDecisionCode.pending,
            "approved_plan_hash": "",
            "approved_by": None,
            "approved_at": None,
        },
    ):
        raise DomainError("deployment changed concurrently; retry planning")
    audit.record(
        session,
        action=AuditAction.staging_deployment_planned,
        resource_type="staging_deployment",
        resource_id=dep.id,
        organization_id=dep.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(dep),
    )
    return dep


def submit_for_approval(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> StagingDeployment:
    """planned -> awaiting_approval."""
    actor.require(Permission.staging_lab_manage)
    dep = _get(session, actor, deployment_id)
    if dep.status != StagingDeploymentStatus.planned:
        raise DomainError(f"deployment is '{dep.status.value}'; only 'planned' can be submitted")
    if not _cas(
        session,
        dep,
        expected=StagingDeploymentStatus.planned,
        new=StagingDeploymentStatus.awaiting_approval,
    ):
        raise DomainError("deployment changed concurrently; retry submit")
    audit.record(
        session,
        action=AuditAction.staging_deployment_submitted,
        resource_type="staging_deployment",
        resource_id=dep.id,
        organization_id=dep.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(dep),
    )
    return dep


def approve_deployment(
    session: Session,
    actor: Principal,
    deployment_id: uuid.UUID,
    *,
    expected_plan_hash: str,
) -> StagingDeployment:
    """awaiting_approval -> approved, binding ONE exact plan hash + all drift anchors (SECP-B4)."""
    actor.require(Permission.staging_lab_approve)
    dep = _get(session, actor, deployment_id)
    if dep.status != StagingDeploymentStatus.awaiting_approval:
        raise DomainError(
            f"deployment is '{dep.status.value}'; only awaiting_approval is approvable"
        )
    if not expected_plan_hash or expected_plan_hash != dep.plan_hash:
        raise DomainError("expected plan hash does not match the current plan (stale approval)")
    plan = session.execute(
        select(StagingDeploymentPlan).where(
            StagingDeploymentPlan.deployment_id == dep.id,
            StagingDeploymentPlan.plan_hash == dep.plan_hash,
        )
    ).scalar_one_or_none()
    if plan is None:
        raise DomainError("plan record not found for approval")
    onboarding = _active_onboarding(session, dep.execution_target_id)
    if onboarding is None or onboarding.id != dep.onboarding_id:
        raise DomainError("active onboarding changed; deployment cannot be approved")

    now = _utcnow()
    approval = StagingDeploymentApproval(
        deployment_id=dep.id,
        organization_id=dep.organization_id,
        approved_plan_hash=dep.plan_hash,
        plan_version=dep.plan_version,
        onboarding_id=dep.onboarding_id,
        ownership_tag=plan.ownership_tag,
        capacity_assessment_hash=plan.capacity_assessment_hash,
        artifact_manifest_id=plan.artifact_manifest_id,
        worker_identity_version=_approved_worker_identity_version(session, dep.organization_id),
        approved_by=actor.user_id,
    )
    session.add(approval)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DomainError("deployment already approved") from exc

    if not _cas(
        session,
        dep,
        expected=StagingDeploymentStatus.awaiting_approval,
        new=StagingDeploymentStatus.approved,
        extra={
            "decision_code": StagingDeploymentDecisionCode.approved,
            "approved_plan_hash": dep.plan_hash,
            "approved_by": actor.user_id,
            "approved_at": now,
        },
    ):
        raise DomainError("deployment changed concurrently; retry approval")
    audit.record(
        session,
        action=AuditAction.staging_deployment_approved,
        resource_type="staging_deployment",
        resource_id=dep.id,
        organization_id=dep.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(dep, approved_plan_hash=dep.approved_plan_hash),
    )
    return dep


def reject_deployment(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> StagingDeployment:
    """awaiting_approval -> failed (rejected_policy)."""
    actor.require(Permission.staging_lab_approve)
    dep = _get(session, actor, deployment_id)
    if dep.status != StagingDeploymentStatus.awaiting_approval:
        raise DomainError("only an awaiting_approval deployment can be rejected")
    if not _cas(
        session,
        dep,
        expected=StagingDeploymentStatus.awaiting_approval,
        new=StagingDeploymentStatus.failed,
        extra={"decision_code": StagingDeploymentDecisionCode.rejected_policy},
    ):
        raise DomainError("deployment changed concurrently; retry reject")
    audit.record(
        session,
        action=AuditAction.staging_deployment_rejected,
        resource_type="staging_deployment",
        resource_id=dep.id,
        organization_id=dep.organization_id,
        actor=str(actor.user_id),
        outcome="denied",
        data=_safe_audit(dep),
    )
    return dep


def _enqueue_operation(
    session: Session,
    dep: StagingDeployment,
    actor: Principal,
    kind: DeploymentOperationKind,
) -> StagingDeploymentOperation:
    """Commit a durable, idempotent operation record (API enqueues only; the worker executes)."""
    fingerprint = deployment_operation_fingerprint(dep.id, kind.value, dep.approved_plan_hash)
    existing = session.execute(
        select(StagingDeploymentOperation).where(
            StagingDeploymentOperation.operation_fingerprint == fingerprint
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing  # idempotent: the same (deployment, kind, plan) resolves to the same row
    op = StagingDeploymentOperation(
        deployment_id=dep.id,
        organization_id=dep.organization_id,
        operation_kind=kind,
        operation_fingerprint=fingerprint,
        plan_hash=dep.approved_plan_hash,
        status=DeploymentOperationStatus.queued,
        created_by=actor.user_id,
    )
    session.add(op)
    session.flush()
    return op


def submit_deployment(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> StagingDeployment:
    """approved -> bootstrap_pending; enqueues the durable apply operation (never run here)."""
    actor.require(Permission.staging_lab_manage)
    dep = _get(session, actor, deployment_id)
    if dep.status != StagingDeploymentStatus.approved:
        raise DomainError(f"deployment is '{dep.status.value}'; only 'approved' can be deployed")
    _enqueue_operation(session, dep, actor, DeploymentOperationKind.apply)
    if not _cas(
        session,
        dep,
        expected=StagingDeploymentStatus.approved,
        new=StagingDeploymentStatus.bootstrap_pending,
    ):
        raise DomainError("deployment changed concurrently; retry submit")
    audit.record(
        session,
        action=AuditAction.staging_deployment_apply_started,
        resource_type="staging_deployment",
        resource_id=dep.id,
        organization_id=dep.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(dep),
    )
    return dep


def request_teardown(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> StagingDeployment:
    """ready/failed/rolled_back -> teardown_requested, enqueuing the durable teardown operation."""
    actor.require(Permission.staging_lab_manage)
    dep = _get(session, actor, deployment_id)
    if dep.status not in (
        StagingDeploymentStatus.ready,
        StagingDeploymentStatus.failed,
        StagingDeploymentStatus.rolled_back,
    ):
        raise DomainError(f"deployment is '{dep.status.value}'; cannot request teardown")
    _enqueue_operation(session, dep, actor, DeploymentOperationKind.teardown)
    if not _cas(session, dep, expected=dep.status, new=StagingDeploymentStatus.teardown_requested):
        raise DomainError("deployment changed concurrently; retry teardown request")
    audit.record(
        session,
        action=AuditAction.staging_deployment_teardown_requested,
        resource_type="staging_deployment",
        resource_id=dep.id,
        organization_id=dep.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(dep),
    )
    return dep


# --- read helpers --------------------------------------------------------------------------------


def get_deployment(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> StagingDeployment:
    return _get(session, actor, deployment_id)


def list_deployments(session: Session, actor: Principal) -> list[StagingDeployment]:
    return list(
        session.execute(
            select(StagingDeployment)
            .where(StagingDeployment.organization_id == actor.organization_id)
            .order_by(StagingDeployment.created_at.desc())
        )
        .scalars()
        .all()
    )


def get_active_plan(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> StagingDeploymentPlan:
    """The immutable content-addressed plan record pinned by the deployment's current plan hash."""
    dep = _get(session, actor, deployment_id)
    plan = session.execute(
        select(StagingDeploymentPlan).where(
            StagingDeploymentPlan.deployment_id == dep.id,
            StagingDeploymentPlan.plan_hash == dep.plan_hash,
        )
    ).scalar_one_or_none()
    if plan is None:
        raise NotFoundError("no plan has been compiled for this deployment")
    return plan


def list_resources(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> list[StagingDeploymentResource]:
    """The durable record of resources this deployment created (safe categories/refs/state only)."""
    dep = _get(session, actor, deployment_id)
    return list(
        session.execute(
            select(StagingDeploymentResource)
            .where(StagingDeploymentResource.deployment_id == dep.id)
            .order_by(StagingDeploymentResource.created_at.asc())
        )
        .scalars()
        .all()
    )


def list_verifications(
    session: Session, actor: Principal, deployment_id: uuid.UUID
) -> list[StagingDeploymentVerification]:
    """The durable record of post-apply verification checks (closed check codes + status only)."""
    dep = _get(session, actor, deployment_id)
    return list(
        session.execute(
            select(StagingDeploymentVerification)
            .where(StagingDeploymentVerification.deployment_id == dep.id)
            .order_by(StagingDeploymentVerification.created_at.asc())
        )
        .scalars()
        .all()
    )
