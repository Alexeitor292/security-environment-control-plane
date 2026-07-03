"""Declarative disposable staging-lab lifecycle services (SECP-002B-1B-9).

Control-plane only and fake-only. This module owns the desired state, immutable plan, approval,
labeled fake simulation, and teardown of a disposable read-only staging lab. It NEVER imports
worker/provider/transport/secret/subprocess code, never contacts infrastructure, and never
creates a real target or a :class:`LiveReadAuthorization`. Fake simulation is dispatched only
through the worker-dispatch seam (:func:`secp_api.dispatch.get_dispatcher`).

A staging-lab approval is permission to enter *fake simulation only*. It is separate from, and
never a substitute for, the SECP-002B-1B-6 live-read authorization required for any future real
read-only collection.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.dispatch import get_dispatcher
from secp_api.enums import (
    AuditAction,
    Permission,
    StagingLabProfile,
    StagingLabStatus,
    StagingNetworkIntent,
    StagingResourceClass,
    StagingRollbackPolicy,
    TargetStatus,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import ExecutionTarget, StagingLab
from secp_api.staging_lab import (
    StagingLabPlanError,
    StagingLabSpec,
    compile_staging_plan,
    staging_plan_hash,
)

# Allowed lifecycle transitions (fail-closed; any other transition is refused).
_ALLOWED_TRANSITIONS: set[tuple[StagingLabStatus, StagingLabStatus]] = {
    (StagingLabStatus.draft, StagingLabStatus.planned),
    (StagingLabStatus.planned, StagingLabStatus.awaiting_approval),
    (StagingLabStatus.awaiting_approval, StagingLabStatus.approved),
    (StagingLabStatus.awaiting_approval, StagingLabStatus.failed),
    (StagingLabStatus.approved, StagingLabStatus.simulating),
    (StagingLabStatus.simulating, StagingLabStatus.simulated_ready),
    (StagingLabStatus.simulating, StagingLabStatus.failed),
    (StagingLabStatus.simulated_ready, StagingLabStatus.simulating),
    (StagingLabStatus.simulated_ready, StagingLabStatus.tearing_down),
    (StagingLabStatus.approved, StagingLabStatus.tearing_down),
    (StagingLabStatus.failed, StagingLabStatus.tearing_down),
    (StagingLabStatus.tearing_down, StagingLabStatus.destroyed),
}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _transition(lab: StagingLab, to: StagingLabStatus) -> None:
    if (lab.status, to) not in _ALLOWED_TRANSITIONS:
        raise DomainError(f"illegal staging-lab transition {lab.status.value} -> {to.value}")
    lab.status = to


def _get_lab(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    lab = session.get(StagingLab, lab_id)
    if lab is None:
        raise NotFoundError(f"staging lab {lab_id} not found")
    actor.require_org(lab.organization_id)
    return lab


def _substrate_is_approved(session: Session, target: ExecutionTarget) -> bool:
    """A substrate is approved when it is active and has a single active onboarding.

    Reuses the existing onboarding approval architecture — no parallel approval concept.
    """
    from secp_api.services.onboarding import active_onboarding_for_target

    if target.status != TargetStatus.active:
        return False
    try:
        return active_onboarding_for_target(session, target.id) is not None
    except DomainError:
        # Ambiguous active onboarding — fail closed (not approved for staging).
        return False


def _safe_audit(lab: StagingLab, **extra: object) -> dict:
    payload: dict[str, object] = {
        "execution_target_id": str(lab.execution_target_id),
        "ownership_label": lab.ownership_label,
        "status": lab.status.value,
        "plan_version": lab.plan_version,
        "plan_hash": lab.plan_hash,
    }
    payload.update(extra)
    return payload


def create_staging_lab(
    session: Session,
    actor: Principal,
    *,
    execution_target_id: uuid.UUID,
    display_name: str,
    ownership_label: str,
    profile: StagingLabProfile = StagingLabProfile.nested_proxmox,
    network_intent: StagingNetworkIntent = StagingNetworkIntent.host_only_no_uplink,
    resource_class: StagingResourceClass = StagingResourceClass.small_lab,
    rollback_policy: StagingRollbackPolicy = StagingRollbackPolicy.revert_to_known_clean_checkpoint,
    bootstrap_artifact_profile_id: str,
) -> StagingLab:
    """Create a draft staging lab bound to an approved substrate target. No plan yet."""
    actor.require(Permission.staging_lab_manage)
    target = session.get(ExecutionTarget, execution_target_id)
    if target is None:
        raise NotFoundError(f"execution target {execution_target_id} not found")
    actor.require_org(target.organization_id)
    label = (ownership_label or "").strip()
    if not label:
        raise DomainError("ownership_label is required")
    if not (display_name or "").strip():
        raise DomainError("display_name is required")

    lab = StagingLab(
        organization_id=target.organization_id,
        execution_target_id=target.id,
        display_name=display_name.strip(),
        ownership_label=label,
        profile=profile,
        network_intent=network_intent,
        resource_class=resource_class,
        rollback_policy=rollback_policy,
        bootstrap_artifact_profile_id=(bootstrap_artifact_profile_id or "").strip(),
        status=StagingLabStatus.draft,
        plan_version=0,
        plan_hash="",
        idempotency_key=uuid.uuid4().hex,
        created_by=actor.user_id,
    )
    session.add(lab)
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_created,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    return lab


def generate_plan(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Compile the immutable logical plan for a draft lab (draft -> planned)."""
    actor.require(Permission.staging_lab_manage)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.draft:
        raise DomainError(f"staging lab is '{lab.status.value}'; only 'draft' can be planned")
    target = session.get(ExecutionTarget, lab.execution_target_id)
    if target is None:
        raise NotFoundError("execution target no longer exists")

    spec = StagingLabSpec(
        ownership_label=lab.ownership_label,
        profile=lab.profile,
        network_intent=lab.network_intent,
        resource_class=lab.resource_class,
        rollback_policy=lab.rollback_policy,
        bootstrap_artifact_profile_id=lab.bootstrap_artifact_profile_id,
        substrate_approved=_substrate_is_approved(session, target),
    )
    try:
        plan = compile_staging_plan(spec)
    except StagingLabPlanError as exc:
        audit.record(
            session,
            action=AuditAction.staging_lab_refused,
            resource_type="staging_lab",
            resource_id=lab.id,
            organization_id=lab.organization_id,
            actor=str(actor.user_id),
            outcome="denied",
            data=_safe_audit(lab, reason_code=exc.reason_code),
        )
        raise DomainError(f"staging-lab plan refused: {exc.reason_code}") from exc

    lab.desired_state = plan
    lab.plan_hash = staging_plan_hash(plan)
    lab.plan_version = 1
    _transition(lab, StagingLabStatus.planned)
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_planned,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    return lab


def submit_for_approval(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Move a planned lab into the approval queue (planned -> awaiting_approval)."""
    actor.require(Permission.staging_lab_manage)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.planned:
        raise DomainError(f"staging lab is '{lab.status.value}'; only 'planned' can be submitted")
    _transition(lab, StagingLabStatus.awaiting_approval)
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_submitted,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    return lab


def approve_staging_lab(
    session: Session,
    actor: Principal,
    lab_id: uuid.UUID,
    *,
    expected_plan_hash: str,
    reason: str = "",
) -> StagingLab:
    """Approve the exact reviewed plan (awaiting_approval -> approved).

    Binds lab id, the immutable plan hash/version, the substrate id, the lifecycle state, the
    approver, and the approval time. Refuses if the reviewer's ``expected_plan_hash`` does not
    match the lab's current plan hash (i.e. the plan changed after review) or if the stored plan
    fails an integrity recompute. This is NOT a live-read authorization.
    """
    actor.require(Permission.staging_lab_approve)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.awaiting_approval:
        raise DomainError(
            f"staging lab is '{lab.status.value}'; only 'awaiting_approval' can be approved"
        )
    if not lab.plan_hash or lab.desired_state is None:
        raise DomainError("staging lab has no generated plan to approve")
    if staging_plan_hash(lab.desired_state) != lab.plan_hash:
        raise DomainError("staging-lab plan integrity check failed (hash mismatch)")
    if (expected_plan_hash or "").strip() != lab.plan_hash:
        raise DomainError(
            "the plan changed since review; re-review the current plan hash before approving"
        )
    _transition(lab, StagingLabStatus.approved)
    lab.approved_by = actor.user_id
    lab.approved_at = _utcnow()
    lab.approved_plan_hash = lab.plan_hash
    lab.approved_plan_version = lab.plan_version
    lab.decision_reason = reason
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_approved,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(
            lab,
            approved_plan_hash=lab.approved_plan_hash,
            approved_plan_version=lab.approved_plan_version,
            reason=reason,
            authorizes="fake_simulation_only",
            live_read_authorization=False,
        ),
    )
    return lab


def reject_staging_lab(
    session: Session, actor: Principal, lab_id: uuid.UUID, reason: str = ""
) -> StagingLab:
    actor.require(Permission.staging_lab_approve)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.awaiting_approval:
        raise DomainError(
            f"staging lab is '{lab.status.value}'; only 'awaiting_approval' can be rejected"
        )
    _transition(lab, StagingLabStatus.failed)
    lab.decision_reason = reason
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_rejected,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab, reason=reason),
    )
    return lab


def request_simulation(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Run the labeled fake simulation (approved/simulated_ready -> simulating -> simulated_ready).

    Idempotent: re-running reconciles the same owned resource set (no duplicate resources). No
    infrastructure is created.
    """
    actor.require(Permission.staging_lab_manage)
    lab = _get_lab(session, actor, lab_id)
    if lab.status not in (StagingLabStatus.approved, StagingLabStatus.simulated_ready):
        raise DomainError(
            f"staging lab is '{lab.status.value}'; only 'approved' or 'simulated_ready' "
            "can be (re)simulated"
        )
    _transition(lab, StagingLabStatus.simulating)
    audit.record(
        session,
        action=AuditAction.staging_lab_simulation_started,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab, simulation_only=True),
    )
    session.flush()
    # Worker-owned execution seam only; the API never instantiates the executor. The seam's
    # recorder mutates this same identity-mapped ``lab`` in place, so we return it.
    get_dispatcher().dispatch_staging_lab_simulation(session, lab.id, created_by=actor.user_id)
    return lab


def request_teardown(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Request controlled fake teardown (-> tearing_down -> destroyed). No infrastructure exists."""
    actor.require(Permission.staging_lab_manage)
    lab = _get_lab(session, actor, lab_id)
    if lab.status not in (
        StagingLabStatus.simulated_ready,
        StagingLabStatus.approved,
        StagingLabStatus.failed,
    ):
        raise DomainError(
            f"staging lab is '{lab.status.value}'; it cannot be torn down from this state"
        )
    _transition(lab, StagingLabStatus.tearing_down)
    audit.record(
        session,
        action=AuditAction.staging_lab_teardown_started,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    session.flush()
    get_dispatcher().dispatch_staging_lab_teardown(session, lab.id, created_by=actor.user_id)
    return lab


# --- Worker-callable recorders (invoked via the dispatch seam) ----------------


def record_staging_lab_simulation_result(
    session: Session,
    lab_id: uuid.UUID,
    *,
    observed: dict,
    created_by: uuid.UUID | None = None,
) -> StagingLab:
    """Record fake simulation observations (simulating -> simulated_ready). Idempotent."""
    lab = session.get(StagingLab, lab_id)
    if lab is None:
        raise NotFoundError(f"staging lab {lab_id} not found")
    if lab.status != StagingLabStatus.simulating:
        raise DomainError(
            f"staging lab is '{lab.status.value}'; a simulation result requires 'simulating'"
        )
    lab.simulated_observed_state = observed
    _transition(lab, StagingLabStatus.simulated_ready)
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_simulated_ready,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor="worker" if created_by is None else str(created_by),
        data=_safe_audit(
            lab,
            simulation_only=True,
            observed_resource_count=len(observed.get("resources", [])),
        ),
    )
    return lab


def record_staging_lab_teardown_result(
    session: Session,
    lab_id: uuid.UUID,
    *,
    observed: dict,
    created_by: uuid.UUID | None = None,
) -> StagingLab:
    """Record fake teardown observations (tearing_down -> destroyed)."""
    lab = session.get(StagingLab, lab_id)
    if lab is None:
        raise NotFoundError(f"staging lab {lab_id} not found")
    if lab.status != StagingLabStatus.tearing_down:
        raise DomainError(
            f"staging lab is '{lab.status.value}'; a teardown result requires 'tearing_down'"
        )
    lab.simulated_observed_state = observed
    _transition(lab, StagingLabStatus.destroyed)
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_destroyed,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor="worker" if created_by is None else str(created_by),
        data=_safe_audit(lab),
    )
    return lab


# --- Reads --------------------------------------------------------------------


def get_staging_lab(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    return _get_lab(session, actor, lab_id)


def list_staging_labs(session: Session, actor: Principal) -> list[StagingLab]:
    return list(
        session.execute(
            select(StagingLab)
            .where(StagingLab.organization_id == actor.organization_id)
            .order_by(StagingLab.created_at.desc())
        )
        .scalars()
        .all()
    )
