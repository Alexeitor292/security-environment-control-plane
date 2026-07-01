"""Target onboarding services (SECP-002B-1B-0, ADR-014).

Control-plane only. Manages the provider-neutral onboarding lifecycle (draft → preflight →
review → approval → activation), records redacted preflight evidence, and enforces that a
target may only be cleared for real provisioning once onboarding is ``active`` with no
config/scope drift. This module NEVER imports worker, provider, runner, subprocess,
OpenTofu, secret-resolver, or infrastructure code — and never inspects a real target.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    Permission,
    TargetStatus,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import ExecutionTarget, TargetOnboarding, TargetPreflight
from secp_api.onboarding import (
    onboarding_boundary_hash,
    preflight_evidence_hash,
    required_checks_passed,
    transition,
    validate_onboarding_boundary,
    validate_preflight_evidence,
)
from secp_api.provisioning_scope import provisioning_scope_policy_hash


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _get_target(session: Session, actor: Principal, target_id: uuid.UUID) -> ExecutionTarget:
    target = session.get(ExecutionTarget, target_id)
    if target is None:
        raise NotFoundError(f"execution target {target_id} not found")
    actor.require_org(target.organization_id)
    return target


def create_onboarding(
    session: Session,
    actor: Principal,
    *,
    target_id: uuid.UUID,
    onboarding_mode: OnboardingMode,
    isolation_model: IsolationModel,
    declared_boundary: dict,
) -> TargetOnboarding:
    """Create an onboarding draft with a validated, immutable declared boundary."""
    actor.require(Permission.onboarding_manage)
    target = _get_target(session, actor, target_id)

    spec = validate_onboarding_boundary(
        declared_boundary, mode=onboarding_mode, isolation_model=isolation_model
    )
    canonical = spec.model_dump(mode="json")
    ob = TargetOnboarding(
        organization_id=target.organization_id,
        execution_target_id=target.id,
        onboarding_mode=onboarding_mode,
        isolation_model=isolation_model,
        status=OnboardingStatus.draft,
        declared_boundary=canonical,
        boundary_hash=onboarding_boundary_hash(canonical),
        created_by=actor.user_id,
    )
    session.add(ob)
    session.flush()
    audit.record(
        session,
        action=AuditAction.onboarding_created,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={
            "execution_target_id": str(target.id),
            "onboarding_mode": onboarding_mode.value,
            "isolation_model": isolation_model.value,
            "boundary_hash": ob.boundary_hash,
        },
    )
    return ob


def get_onboarding(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> TargetOnboarding:
    ob = session.get(TargetOnboarding, onboarding_id)
    if ob is None:
        raise NotFoundError(f"onboarding {onboarding_id} not found")
    actor.require_org(ob.organization_id)
    return ob


def list_onboardings(
    session: Session, actor: Principal, target_id: uuid.UUID
) -> list[TargetOnboarding]:
    target = _get_target(session, actor, target_id)
    return list(
        session.execute(
            select(TargetOnboarding)
            .where(TargetOnboarding.execution_target_id == target.id)
            .order_by(TargetOnboarding.created_at.desc())
        )
        .scalars()
        .all()
    )


def list_preflights(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> list[TargetPreflight]:
    ob = get_onboarding(session, actor, onboarding_id)
    return list(
        session.execute(
            select(TargetPreflight)
            .where(TargetPreflight.onboarding_id == ob.id)
            .order_by(TargetPreflight.created_at)
        )
        .scalars()
        .all()
    )


def record_preflight(
    session: Session,
    actor: Principal,
    onboarding_id: uuid.UUID,
    *,
    checks: list[dict],
    collector: str = "fake",
) -> TargetPreflight:
    """Record a redacted, structured preflight result (fake-only in B1-B-0)."""
    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    if ob.status not in (OnboardingStatus.draft, OnboardingStatus.preflight_pending):
        raise DomainError(
            f"onboarding is '{ob.status.value}'; preflight can only be recorded while "
            "draft or preflight_pending"
        )
    validated = validate_preflight_evidence(checks)
    ok, _missing = required_checks_passed(validated, isolation_model=ob.isolation_model)
    canonical_checks = [c.model_dump(mode="json") for c in validated]

    pf = TargetPreflight(
        organization_id=ob.organization_id,
        onboarding_id=ob.id,
        collector=collector,
        passed=ok,
        checks=canonical_checks,
        evidence_hash=preflight_evidence_hash(canonical_checks),
        created_by=actor.user_id,
    )
    session.add(pf)
    if ob.status == OnboardingStatus.draft:
        ob.status = transition(ob.status, OnboardingStatus.preflight_pending)
    session.flush()
    audit.record(
        session,
        action=AuditAction.onboarding_preflight_recorded,
        resource_type="target_preflight",
        resource_id=pf.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={"onboarding_id": str(ob.id), "passed": ok, "evidence_hash": pf.evidence_hash},
    )
    return pf


def _latest_preflight(session: Session, onboarding_id: uuid.UUID) -> TargetPreflight | None:
    return (
        session.execute(
            select(TargetPreflight)
            .where(TargetPreflight.onboarding_id == onboarding_id)
            .order_by(TargetPreflight.created_at.desc())
        )
        .scalars()
        .first()
    )


def submit_for_review(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> TargetOnboarding:
    """Request human review. Requires a complete boundary and a passing preflight."""
    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    if ob.status != OnboardingStatus.preflight_pending:
        raise DomainError(
            f"onboarding is '{ob.status.value}'; only 'preflight_pending' can be submitted"
        )
    # Re-validate the (immutable) boundary is complete.
    validate_onboarding_boundary(
        ob.declared_boundary, mode=ob.onboarding_mode, isolation_model=ob.isolation_model
    )
    pf = _latest_preflight(session, ob.id)
    if pf is None or not pf.passed:
        raise DomainError(
            "onboarding requires a passing preflight result before review; record a "
            "preflight whose required checks all pass"
        )
    ob.status = transition(ob.status, OnboardingStatus.ready_for_review)
    audit.record(
        session,
        action=AuditAction.onboarding_submitted,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
    )
    return ob


def approve_onboarding(
    session: Session, actor: Principal, onboarding_id: uuid.UUID, reason: str = ""
) -> TargetOnboarding:
    """Explicit human approval (Charter Invariant 5). Requires onboarding:approve.

    Pins the target config + provisioning scope-policy hashes so any later drift
    invalidates the approval at activation.
    """
    actor.require(Permission.onboarding_approve)
    ob = get_onboarding(session, actor, onboarding_id)
    if ob.status != OnboardingStatus.ready_for_review:
        raise DomainError(
            f"onboarding is '{ob.status.value}'; only 'ready_for_review' can be approved"
        )
    target = session.get(ExecutionTarget, ob.execution_target_id)
    if target is None:
        raise NotFoundError("execution target no longer exists")
    ob.status = transition(ob.status, OnboardingStatus.approved)
    ob.approved_target_config_hash = target.config_hash
    ob.approved_scope_policy_hash = provisioning_scope_policy_hash(target.scope_policy or {})
    ob.decided_by = actor.user_id
    ob.decided_at = _utcnow()
    ob.decision_reason = reason
    audit.record(
        session,
        action=AuditAction.onboarding_approved,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={
            "boundary_hash": ob.boundary_hash,
            "approved_target_config_hash": ob.approved_target_config_hash,
            "reason": reason,
        },
    )
    return ob


def reject_onboarding(
    session: Session, actor: Principal, onboarding_id: uuid.UUID, reason: str = ""
) -> TargetOnboarding:
    actor.require(Permission.onboarding_approve)
    ob = get_onboarding(session, actor, onboarding_id)
    if ob.status not in (
        OnboardingStatus.preflight_pending,
        OnboardingStatus.ready_for_review,
        OnboardingStatus.approved,
        OnboardingStatus.draft,
    ):
        raise DomainError(f"onboarding is '{ob.status.value}'; it cannot be rejected")
    ob.status = transition(ob.status, OnboardingStatus.rejected)
    ob.decided_by = actor.user_id
    ob.decided_at = _utcnow()
    ob.decision_reason = reason
    audit.record(
        session,
        action=AuditAction.onboarding_rejected,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={"reason": reason},
    )
    return ob


def onboarding_drift(ob: TargetOnboarding, target: ExecutionTarget) -> str | None:
    """Return a reason string if the target has drifted from the approval, else None."""
    if ob.approved_target_config_hash is None or ob.approved_scope_policy_hash is None:
        return "onboarding was never approved (no pinned hashes)"
    if target.config_hash != ob.approved_target_config_hash:
        return "target configuration hash has drifted since onboarding approval"
    current_scope = provisioning_scope_policy_hash(target.scope_policy or {})
    if current_scope != ob.approved_scope_policy_hash:
        return "target scope policy has drifted since onboarding approval"
    return None


def activate_onboarding(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> TargetOnboarding:
    """Activate an approved onboarding. Refuses if the target has drifted since approval."""
    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    if ob.status != OnboardingStatus.approved:
        raise DomainError(f"onboarding is '{ob.status.value}'; only 'approved' can be activated")
    target = session.get(ExecutionTarget, ob.execution_target_id)
    if target is None or target.status != TargetStatus.active:
        raise DomainError("execution target is missing or not active")
    drift = onboarding_drift(ob, target)
    if drift is not None:
        raise DomainError(
            f"onboarding approval is invalidated: {drift}. Re-run onboarding review and "
            "obtain fresh approval."
        )
    ob.status = transition(ob.status, OnboardingStatus.active)
    ob.activated_at = _utcnow()
    audit.record(
        session,
        action=AuditAction.onboarding_activated,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={"boundary_hash": ob.boundary_hash},
    )
    return ob


def retire_onboarding(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> TargetOnboarding:
    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    ob.status = transition(ob.status, OnboardingStatus.retired)
    audit.record(
        session,
        action=AuditAction.onboarding_retired,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
    )
    return ob


def active_onboarding_for_target(session: Session, target_id: uuid.UUID) -> TargetOnboarding | None:
    """The active onboarding for a target, or None. Used by the real-provisioning gate."""
    return (
        session.execute(
            select(TargetOnboarding)
            .where(
                TargetOnboarding.execution_target_id == target_id,
                TargetOnboarding.status == OnboardingStatus.active,
            )
            .order_by(TargetOnboarding.activated_at.desc())
        )
        .scalars()
        .first()
    )
