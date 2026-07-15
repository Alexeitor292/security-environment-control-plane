"""Worker-owned real-plan-generation orchestration — STOPS at the sealed plan-only boundary (PR5A).

The complete ordering, proven end to end without executing anything (ADR-022 §5/§9):

    fresh authoritative load
    → PlanGenerationReadinessStatus (combined, pure)
    → the plan-only process SEAL refusal
    → a bounded, secret-free ``plan_generation_refused`` audit + attempt record
    → STOP

It constructs NO process executor before the seal, resolves NO credential, renders NO workspace,
creates NO binary plan, and mints NO capability in a shipped path. In PR5A it NEVER returns
``completed`` — no plan executes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    PlanGenerationAttemptStatus,
    ReadinessReason,
)
from secp_api.models import ProvisioningManifest
from secp_api.plan_activation_contract import (
    PLAN_GENERATION_READINESS_POLICY_VERSION,
    plan_generation_readiness_status,
)
from secp_api.plan_activation_models import RealPlanGenerationAttempt
from secp_api.readiness_contract import PLAN_SECRET_READINESS_TTL
from sqlalchemy import select
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class PlanGenerationResult:
    """The closed, secret-free outcome of one PR5A plan-generation attempt. Never ``completed``."""

    outcome: str  # always PlanGenerationAttemptStatus.refused.value in PR5A
    reason_code: str
    attempt_id: uuid.UUID | None = None


def run_plan_generation(
    session: Session,
    *,
    manifest_id: uuid.UUID,
    now: datetime | None = None,
) -> PlanGenerationResult:
    """Load authoritative records, evaluate combined readiness, and REFUSE at the sealed
    boundary."""
    now = now or datetime.now(UTC)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        return _refuse(session, None, ReadinessReason.gate_incomplete.value, now)

    # A bounded, secret-free "started" marker — the worker began the attempt. There is NEVER a
    # "completed": PR5A refuses at the seal, so the only terminal audit is "refused".
    audit.record(
        session,
        action=AuditAction.plan_generation_started,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=manifest.organization_id,
        actor="worker",
        data={
            "operation_kind": "real_plan_generation",
            "provisioning_manifest_id": str(manifest.id),
            "readiness_policy_version": PLAN_GENERATION_READINESS_POLICY_VERSION,
        },
    )

    # 1. COMBINED PLAN-READINESS — pure, read-only. It resolves no secret and builds no environment.
    status = plan_generation_readiness_status(session, manifest, now=now)
    if not status.ready:
        reason = status.reasons[0] if status.reasons else ReadinessReason.gate_incomplete.value
        return _refuse(session, manifest, reason, now)

    # 2. THE PLAN-ONLY PROCESS SEAL — the LAST gate. Even when readiness is current, PR5A refuses
    #    here BEFORE constructing any executor or minting any capability (ADR-022 §9). Attempting to
    #    construct the plan-only executor proves the seal holds.
    from secp_worker.plan_gen.process_boundary import (
        PlanOnlyProcessError,
        PlanOnlyProcessExecutor,
    )

    try:
        PlanOnlyProcessExecutor()  # SEALED — this raises in PR5A.
    except PlanOnlyProcessError:
        return _refuse(session, manifest, ReadinessReason.plan_generation_sealed.value, now)
    # pragma: no cover - unreachable while the plan-only seal is True
    raise RuntimeError(  # pragma: no cover
        "plan-only executor was constructed while sealed — this must never happen in PR5A"
    )


def _refuse(
    session: Session,
    manifest: ProvisioningManifest | None,
    reason_code: str,
    now: datetime,
) -> PlanGenerationResult:
    """Record a bounded, secret-free refused attempt + audit, then STOP."""
    attempt_id: uuid.UUID | None = None
    if manifest is not None:
        fingerprint, authorization = _attempt_fingerprint(session, manifest, now)
        # Idempotency: a refused attempt for this exact (manifest, operation fingerprint) is
        # recorded once. A pre-check reuses the prior row instead of hitting the partial-unique
        # index, so a retry never poisons the surrounding transaction or discards the `started`
        # audit. The DB index remains the final guard.
        existing = (
            session.execute(
                select(RealPlanGenerationAttempt).where(
                    RealPlanGenerationAttempt.provisioning_manifest_id == manifest.id,
                    RealPlanGenerationAttempt.operation_fingerprint == fingerprint,
                    RealPlanGenerationAttempt.status == PlanGenerationAttemptStatus.refused,
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            attempt_id = existing.id
        else:
            row = RealPlanGenerationAttempt(
                id=uuid.uuid4(),
                organization_id=manifest.organization_id,
                authorization_id=authorization.id if authorization is not None else None,
                authorization_version=(
                    authorization.authorization_version if authorization is not None else None
                ),
                execution_target_id=manifest.execution_target_id,
                deployment_plan_id=manifest.deployment_plan_id,
                provisioning_manifest_id=manifest.id,
                target_onboarding_id=manifest.target_onboarding_id,
                activation_dossier_id=None,
                operation_fingerprint=fingerprint,
                status=PlanGenerationAttemptStatus.refused,
                refusal_reason_code=reason_code[:80],
                collected_at=now,
                expires_at=now + PLAN_SECRET_READINESS_TTL,
            )
            session.add(row)
            session.flush()
            attempt_id = row.id
        audit.record(
            session,
            action=AuditAction.plan_generation_refused,
            resource_type="provisioning_manifest",
            resource_id=manifest.id,
            organization_id=manifest.organization_id,
            actor="worker",
            outcome="refused",
            data={
                "operation_kind": "real_plan_generation",
                "provisioning_manifest_id": str(manifest.id),
                "reason_code": reason_code[:80],
                "readiness_policy_version": PLAN_GENERATION_READINESS_POLICY_VERSION,
            },
        )
    return PlanGenerationResult(
        outcome=PlanGenerationAttemptStatus.refused.value,
        reason_code=reason_code,
        attempt_id=attempt_id,
    )


def _attempt_fingerprint(session: Session, manifest: ProvisioningManifest, now: datetime):
    """A stable operation fingerprint for the refused attempt (the authorization's, if any)."""
    from secp_api.services.plan_activation import active_plan_generation_authorization

    authorization = active_plan_generation_authorization(session, manifest.id)
    if authorization is not None:
        return authorization.operation_fingerprint, authorization
    # No authorization yet: derive a stable per-manifest-content fingerprint so repeated refusals
    # for the same unreadiness collapse to one row.
    import hashlib

    digest = hashlib.sha256(
        f"secp-002b-1b-pr5a/plan-generation-attempt/v1|{manifest.id}|{manifest.content_hash}".encode()
    ).hexdigest()
    return "sha256:" + digest, None
