"""Target onboarding services (SECP-002B-1B-0, ADR-014).

Control-plane only. Manages the provider-neutral onboarding lifecycle, records redacted,
hash-bound preflight evidence, binds an approved evidence package to the onboarding, and
enforces at most one active onboarding per target with no config/scope/boundary drift. This
module NEVER imports worker, provider, runner, subprocess, OpenTofu, secret-resolver, or
infrastructure code — and never inspects a real target.

Preflight provenance: the control-plane simulated path (``record_simulated_preflight``,
API-reachable) produces ``simulated`` evidence derived from the declared boundary and takes
**no** caller-supplied checks or collector labels. ``record_preflight_result`` is the
general recorder used by the worker collector seam (simulated today; ``live_verified`` in
future B1-B) and is not exposed on the API router.
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
    CollectorKind,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    Permission,
    TargetStatus,
    VerificationLevel,
)
from secp_api.errors import DomainError, NotFoundError, ValidationFailedError
from secp_api.models import ExecutionTarget, TargetOnboarding, TargetPreflight
from secp_api.onboarding import (
    assert_live_evidence_unsealed_allowed,
    build_evidence_package,
    evidence_package_hash,
    onboarding_boundary_hash,
    required_checks_passed,
    simulate_boundary_checks,
    transition,
    validate_boundary_within_scope,
    validate_collector_and_level,
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
    """Create an onboarding draft with a validated, immutable declared boundary.

    The boundary must be complete AND equal to or strictly narrower than the target
    provisioning scope policy (ADR-014 §5) — a boundary broader than the target scope is
    refused.
    """
    actor.require(Permission.onboarding_manage)
    target = _get_target(session, actor, target_id)

    spec = validate_onboarding_boundary(
        declared_boundary, mode=onboarding_mode, isolation_model=isolation_model
    )
    validate_boundary_within_scope(spec, target.scope_policy or {})
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


# --- Preflight recording (request/result contract) ---------------------------


def _evidence_provenance(session: Session, ob: TargetOnboarding, target: ExecutionTarget) -> dict:
    from secp_api.services.toolchain import active_profile_for_target

    tp = active_profile_for_target(session, target.id)
    return {
        "target_config_hash": target.config_hash,
        "scope_policy_hash": provisioning_scope_policy_hash(target.scope_policy or {}),
        "boundary_hash": ob.boundary_hash,
        "toolchain_profile_id": tp.id if tp is not None else None,
        "toolchain_profile_hash": tp.content_hash if tp is not None else None,
    }


def preflight_toolchain_matches_active(
    session: Session, target: ExecutionTarget, pf: TargetPreflight
) -> str | None:
    """Return a mismatch reason if the preflight toolchain provenance disagrees with the
    current active toolchain profile, else None. No mismatch when no profile is involved.

    Shared by onboarding approval and manifest generation (ADR-014 §4).
    """
    from secp_api.services.toolchain import active_profile_for_target

    tp = active_profile_for_target(session, target.id)
    involved = tp is not None or pf.toolchain_profile_id is not None
    if not involved:
        return None
    if tp is None:
        return "the toolchain profile present at preflight is no longer active"
    if pf.toolchain_profile_id is None:
        return "a toolchain profile was added after the preflight was recorded"
    if str(pf.toolchain_profile_id) != str(tp.id):
        return "the active toolchain profile differs from the one recorded at preflight"
    if pf.toolchain_profile_hash != tp.content_hash:
        return "the active toolchain profile content has drifted since the preflight"
    return None


def _assert_preflight_toolchain_matches_active(
    session: Session, target: ExecutionTarget, pf: TargetPreflight
) -> None:
    reason = preflight_toolchain_matches_active(session, target, pf)
    if reason is not None:
        raise DomainError(
            f"preflight toolchain provenance is invalid: {reason}; re-run the preflight "
            "against the current active toolchain profile before approving"
        )


def _next_evidence_version(session: Session, onboarding_id: uuid.UUID) -> int:
    from sqlalchemy import func

    return (
        session.execute(
            select(func.coalesce(func.max(TargetPreflight.evidence_version), 0)).where(
                TargetPreflight.onboarding_id == onboarding_id
            )
        ).scalar_one()
        + 1
    )


def recompute_evidence_hash(pf: TargetPreflight) -> str:
    """Deterministically recompute a preflight's evidence hash from its stored fields."""
    package = build_evidence_package(
        onboarding_id=str(pf.onboarding_id),
        boundary_hash=pf.boundary_hash,
        target_config_hash=pf.target_config_hash,
        scope_policy_hash=pf.scope_policy_hash,
        toolchain_profile_id=str(pf.toolchain_profile_id) if pf.toolchain_profile_id else None,
        toolchain_profile_hash=pf.toolchain_profile_hash,
        verification_level=pf.verification_level,
        collector_kind=pf.collector_kind,
        collector_identity=pf.collector_identity,
        evidence_version=pf.evidence_version,
        checks=pf.checks,
    )
    return evidence_package_hash(package)


def _record_preflight(
    session: Session,
    ob: TargetOnboarding,
    *,
    checks: list[dict],
    verification_level: str,
    collector_kind: str,
    collector_identity: str,
    created_by: uuid.UUID | None,
) -> TargetPreflight:
    if ob.status not in (OnboardingStatus.draft, OnboardingStatus.preflight_pending):
        raise DomainError(
            f"onboarding is '{ob.status.value}'; preflight can only be recorded while "
            "draft or preflight_pending"
        )
    validate_collector_and_level(collector_kind, verification_level)
    # B1-B-0 seal: no code path may create live_verified / provider_worker evidence in this
    # release (unconditional code-level seal, not a config toggle). Only simulated fakes.
    assert_live_evidence_unsealed_allowed(collector_kind, verification_level)
    validated = validate_preflight_evidence(checks)
    ok, _missing = required_checks_passed(validated, isolation_model=ob.isolation_model)
    canonical_checks = [c.model_dump(mode="json") for c in validated]

    target = session.get(ExecutionTarget, ob.execution_target_id)
    if target is None:
        raise NotFoundError("execution target no longer exists")
    prov = _evidence_provenance(session, ob, target)
    version = _next_evidence_version(session, ob.id)

    pf = TargetPreflight(
        organization_id=ob.organization_id,
        onboarding_id=ob.id,
        collector=collector_kind,
        verification_level=verification_level,
        collector_kind=collector_kind,
        collector_identity=collector_identity,
        evidence_version=version,
        target_config_hash=prov["target_config_hash"],
        scope_policy_hash=prov["scope_policy_hash"],
        boundary_hash=prov["boundary_hash"],
        toolchain_profile_id=prov["toolchain_profile_id"],
        toolchain_profile_hash=prov["toolchain_profile_hash"],
        passed=ok,
        checks=canonical_checks,
        evidence_hash="",  # set after we have the full package below
        created_by=created_by,
    )
    pf.evidence_hash = evidence_package_hash(
        build_evidence_package(
            onboarding_id=str(ob.id),
            boundary_hash=pf.boundary_hash,
            target_config_hash=pf.target_config_hash,
            scope_policy_hash=pf.scope_policy_hash,
            toolchain_profile_id=str(pf.toolchain_profile_id) if pf.toolchain_profile_id else None,
            toolchain_profile_hash=pf.toolchain_profile_hash,
            verification_level=pf.verification_level,
            collector_kind=pf.collector_kind,
            collector_identity=pf.collector_identity,
            evidence_version=pf.evidence_version,
            checks=canonical_checks,
        )
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
        actor="worker" if created_by is None else str(created_by),
        data={
            "onboarding_id": str(ob.id),
            "passed": ok,
            "verification_level": verification_level,
            "collector_kind": collector_kind,
            "evidence_hash": pf.evidence_hash,
        },
    )
    return pf


def record_simulated_preflight(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> TargetPreflight:
    """API-reachable: record SIMULATED evidence derived from the declared boundary.

    Takes NO caller-supplied checks or collector labels. The result is always
    ``simulated`` / ``fake_declared_boundary`` and can never make a target eligible for
    live real provisioning.
    """
    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    audit.record(
        session,
        action=AuditAction.onboarding_preflight_requested,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={"kind": "simulated"},
    )
    checks = simulate_boundary_checks(ob.declared_boundary, ob.isolation_model)
    return _record_preflight(
        session,
        ob,
        checks=checks,
        verification_level=VerificationLevel.simulated.value,
        collector_kind=CollectorKind.fake_declared_boundary.value,
        collector_identity="control-plane-simulator",
        created_by=actor.user_id,
    )


def record_preflight_result(
    session: Session,
    onboarding_id: uuid.UUID,
    *,
    checks: list[dict],
    verification_level: str,
    collector_kind: str,
    collector_identity: str,
) -> TargetPreflight:
    """Worker-callable recorder for collector-produced evidence (not on the API router).

    Enforces the collector/level contract AND the B1-B-0 live-evidence seal: in this release
    it accepts only *simulated* fake evidence. Any attempt to record ``live_verified`` /
    ``provider_worker`` evidence is refused (:class:`LiveEvidenceSealedError`). The seam is
    kept for a future, separately-reviewed B1-B change that adds a real collector.
    """
    ob = session.get(TargetOnboarding, onboarding_id)
    if ob is None:
        raise NotFoundError(f"onboarding {onboarding_id} not found")
    return _record_preflight(
        session,
        ob,
        checks=checks,
        verification_level=verification_level,
        collector_kind=collector_kind,
        collector_identity=collector_identity,
        created_by=None,
    )


def _latest_passing_preflight(session: Session, onboarding_id: uuid.UUID) -> TargetPreflight | None:
    return (
        session.execute(
            select(TargetPreflight)
            .where(
                TargetPreflight.onboarding_id == onboarding_id,
                TargetPreflight.passed.is_(True),
            )
            .order_by(TargetPreflight.evidence_version.desc())
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
    validate_onboarding_boundary(
        ob.declared_boundary, mode=ob.onboarding_mode, isolation_model=ob.isolation_model
    )
    pf = _latest_passing_preflight(session, ob.id)
    if pf is None:
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
    """Explicit human approval. Pins the exact approved preflight evidence package.

    Verifies the approved evidence is complete, passed, integrity-consistent, and matches
    the current target config/scope/boundary. Later preflights cannot silently replace it.
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

    pf = _latest_passing_preflight(session, ob.id)
    if pf is None or not pf.passed:
        raise DomainError("no complete, passing preflight evidence to approve")
    if recompute_evidence_hash(pf) != pf.evidence_hash:
        raise DomainError("preflight evidence integrity check failed (hash mismatch)")
    current_config = target.config_hash
    current_scope = provisioning_scope_policy_hash(target.scope_policy or {})
    if pf.boundary_hash != ob.boundary_hash:
        raise DomainError("preflight evidence was collected for a different boundary")
    if pf.target_config_hash != current_config or pf.scope_policy_hash != current_scope:
        raise DomainError("preflight evidence does not match the current target config/scope")
    # Toolchain provenance binding (ADR-014 §4): when a toolchain profile is required or
    # present, the approved evidence must have been collected against the current active
    # profile (exact id + hash). Refuse if a profile was added, replaced, disabled, or
    # altered since the preflight was recorded.
    _assert_preflight_toolchain_matches_active(session, target, pf)

    ob.status = transition(ob.status, OnboardingStatus.approved)
    ob.approved_target_config_hash = current_config
    ob.approved_scope_policy_hash = current_scope
    ob.approved_preflight_id = pf.id
    ob.approved_preflight_evidence_hash = pf.evidence_hash
    ob.approved_boundary_hash = ob.boundary_hash
    ob.approved_verification_level = pf.verification_level
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
            "approved_preflight_id": str(pf.id),
            "approved_preflight_evidence_hash": pf.evidence_hash,
            "approved_verification_level": pf.verification_level,
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
    """Return a reason string if the target/evidence has drifted from the approval, else None."""
    if ob.approved_target_config_hash is None or ob.approved_scope_policy_hash is None:
        return "onboarding was never approved (no pinned hashes)"
    if target.config_hash != ob.approved_target_config_hash:
        return "target configuration hash has drifted since onboarding approval"
    if provisioning_scope_policy_hash(target.scope_policy or {}) != ob.approved_scope_policy_hash:
        return "target scope policy has drifted since onboarding approval"
    if ob.approved_boundary_hash != ob.boundary_hash:
        return "declared boundary has drifted since onboarding approval"
    return None


def _other_active_exists(session: Session, ob: TargetOnboarding) -> bool:
    rows = (
        session.execute(
            select(TargetOnboarding.id).where(
                TargetOnboarding.execution_target_id == ob.execution_target_id,
                TargetOnboarding.status == OnboardingStatus.active,
                TargetOnboarding.id != ob.id,
            )
        )
        .scalars()
        .all()
    )
    return len(rows) > 0


def activate_onboarding(
    session: Session, actor: Principal, onboarding_id: uuid.UUID
) -> TargetOnboarding:
    """Activate an approved onboarding. Refuses on drift, evidence tampering, or another
    already-active onboarding for the same target (at most one active per target)."""
    actor.require(Permission.onboarding_manage)
    ob = get_onboarding(session, actor, onboarding_id)
    if ob.status != OnboardingStatus.approved:
        raise DomainError(f"onboarding is '{ob.status.value}'; only 'approved' can be activated")
    target = session.get(ExecutionTarget, ob.execution_target_id)
    if target is None or target.status != TargetStatus.active:
        raise DomainError("execution target is missing or not active")
    if _other_active_exists(session, ob):
        raise DomainError(
            "another onboarding for this target is already active; retire it before "
            "activating a new one (at most one active onboarding per target)"
        )
    drift = onboarding_drift(ob, target)
    if drift is not None:
        raise DomainError(
            f"onboarding approval is invalidated: {drift}. Re-run onboarding review and "
            "obtain fresh approval."
        )
    # Verify the pinned approved preflight still exists and is integrity-consistent.
    pf = (
        session.get(TargetPreflight, ob.approved_preflight_id) if ob.approved_preflight_id else None
    )
    if pf is None:
        raise DomainError("approved preflight evidence is missing")
    if recompute_evidence_hash(pf) != ob.approved_preflight_evidence_hash:
        raise DomainError("approved preflight evidence hash mismatch (altered or stale)")

    ob.status = transition(ob.status, OnboardingStatus.active)
    ob.activated_at = _utcnow()
    audit.record(
        session,
        action=AuditAction.onboarding_activated,
        resource_type="target_onboarding",
        resource_id=ob.id,
        organization_id=ob.organization_id,
        actor=str(actor.user_id),
        data={
            "boundary_hash": ob.boundary_hash,
            "approved_verification_level": ob.approved_verification_level,
        },
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
    """The single active onboarding for a target, or None. FAIL-CLOSED on ambiguity:
    raises when more than one active record exists — never silently picks the newest."""
    rows = (
        session.execute(
            select(TargetOnboarding).where(
                TargetOnboarding.execution_target_id == target_id,
                TargetOnboarding.status == OnboardingStatus.active,
            )
        )
        .scalars()
        .all()
    )
    if len(rows) > 1:
        raise DomainError(
            f"ambiguous active onboarding: {len(rows)} active records for target "
            f"{target_id}; fail closed (expected exactly one)"
        )
    return rows[0] if rows else None


def require_single_active_onboarding(session: Session, target_id: uuid.UUID) -> TargetOnboarding:
    """Return the single active onboarding, raising on zero or multiple (fail-closed)."""
    ob = active_onboarding_for_target(session, target_id)
    if ob is None:
        raise ValidationFailedError(
            "target has no active onboarding; a target-bound plan requires exactly one "
            "approved & active onboarding (SECP-002B-1B-0)"
        )
    return ob
