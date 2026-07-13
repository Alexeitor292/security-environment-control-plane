"""Worker-only controlled live read-only eligibility evidence recorder (SECP-002B-1B, B1B-PR3).

The single path that persists ``verification_level=live_verified`` onboarding preflight evidence.
It lives in the WORKER package on purpose: the control-plane API physically cannot import it (the
architecture-boundary lock permits ``apps/api`` to import ``secp_worker`` only from ``dispatch.py``,
and the eligibility symbols are additionally name-forbidden there), so NO API router, service, or
dispatcher can create live evidence. Only the registered Temporal worker activity — after the full
gate chain and the gated read-only collection — reaches ``run_real_eligibility_preflight``, which is
this recorder's sole caller.

It REUSES the existing immutable ``TargetEvidenceRecord`` + ``TargetPreflight`` tables (no parallel
evidence table) and the existing canonical hashing. It never generates observed evidence, contacts
nothing, resolves no secret, and imports no transport/plugin/OpenTofu code.

Worker-origination is STRUCTURAL, not label-based:

* the recorder receives a TYPED ``EligibilityEvaluation`` produced by the pure evaluator (carrying
  the exact validated payload the policy evaluated) plus authoritative record-derived binding facts
  and the idempotency fingerprint — NEVER a caller-controlled arbitrary evidence dict;
* the ``(evidence_source, verification_level)`` allowlist is an ADDITIONAL check on top of that —
  a simulated/fake or relabelled payload can never be admitted;
* the passing/failing outcome is derived from the deterministic policy, never a caller assertion;
* persistence is exact-once per ``(onboarding_id, operation_fingerprint)`` and immutable.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from secp_api import audit
from secp_api.eligibility_policy import ELIGIBILITY_EVIDENCE_TTL, EligibilityEvaluation
from secp_api.enums import (
    AuditAction,
    CollectorKind,
    EligibilityOutcome,
    PreflightCheckStatus,
    VerificationLevel,
)
from secp_api.errors import ValidationFailedError
from secp_api.models import ExecutionTarget, TargetEvidenceRecord, TargetOnboarding, TargetPreflight
from secp_api.onboarding import build_evidence_package, evidence_package_hash
from secp_api.provisioning_scope import provisioning_scope_policy_hash
from secp_api.target_evidence import (
    LIVE_READONLY_EVIDENCE_SOURCE,
    summarize_findings,
    target_evidence_hash,
    validate_target_evidence_payload,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# The preflight vocabulary has no ``unverifiable``; an unverifiable dimension is a non-passing
# ``warning`` (it flags a fact that could not be verified for human review — never a silent pass).
_STATUS_TO_PREFLIGHT = {
    "pass": PreflightCheckStatus.passed.value,
    "fail": PreflightCheckStatus.failed.value,
    "unverifiable": PreflightCheckStatus.warning.value,
}


class LiveEligibilityRecordingRefused(ValidationFailedError):
    """Raised when a proposed live-eligibility recording is not the exact controlled live pair."""


def _existing_by_fingerprint(
    session: Session, onboarding_id: uuid.UUID, operation_fingerprint: str
) -> TargetPreflight | None:
    return session.execute(
        select(TargetPreflight).where(
            TargetPreflight.onboarding_id == onboarding_id,
            TargetPreflight.operation_fingerprint == operation_fingerprint,
        )
    ).scalar_one_or_none()


def _next_evidence_version(session: Session, onboarding_id: uuid.UUID) -> int:
    current = (
        session.execute(
            select(func.max(TargetPreflight.evidence_version)).where(
                TargetPreflight.onboarding_id == onboarding_id
            )
        ).scalar()
        or 0
    )
    return int(current) + 1


def record_live_eligibility_evidence(
    session: Session,
    *,
    onboarding: TargetOnboarding,
    target: ExecutionTarget,
    evaluation: EligibilityEvaluation,
    operation_fingerprint: str,
    collector_identity: str,
    live_read_authorization_id: uuid.UUID,
    live_read_authorization_version: int,
    worker_identity_registration_id: uuid.UUID | None,
    now: datetime,
    created_by: uuid.UUID | None = None,
) -> TargetPreflight:
    """Persist one immutable, redacted, expiry-bound live-eligibility evidence pair (exact-once).

    The evidence payload is taken ONLY from ``evaluation.evidence_payload`` (the exact payload the
    pure evaluator validated + scored) — never a separately-supplied dict. It refuses any payload
    that is not the exact ``(live_readonly_proxmox, live_verified)`` pair. The ``passed`` flag and
    every dimension check come from the deterministic policy — never a caller assertion. Idempotent
    per ``(onboarding_id, operation_fingerprint)``: an exact retry returns the durable record
    unchanged and records no duplicate success audit.
    """
    # 1. Fail closed unless the evaluator's payload is exactly the controlled live pair (additional
    #    check on top of the structural worker-origination — a relabelled/fake payload is refused).
    evidence_payload = evaluation.evidence_payload
    validated = validate_target_evidence_payload(evidence_payload)
    if (
        validated["evidence_source"] != LIVE_READONLY_EVIDENCE_SOURCE
        or validated["verification_level"] != VerificationLevel.live_verified.value
    ):
        raise LiveEligibilityRecordingRefused(
            "live eligibility recorder accepts only live_readonly_proxmox / live_verified evidence"
        )

    # 2. Idempotency: an exact retry returns the already-durable record (no duplicate, no re-audit).
    existing = _existing_by_fingerprint(session, onboarding.id, operation_fingerprint)
    if existing is not None:
        return existing

    # 3. Use the EXACT findings the policy already computed (carried on the typed result) — the
    #    comparison is never re-run here, so the persisted findings cannot diverge from the scored
    #    outcome. ``status`` is summarized from those findings.
    findings = [dict(f) for f in evaluation.findings]
    status = summarize_findings(findings)
    eligible = evaluation.outcome == EligibilityOutcome.eligible.value

    evidence_record = TargetEvidenceRecord(
        organization_id=onboarding.organization_id,
        onboarding_id=onboarding.id,
        execution_target_id=target.id,
        evidence_source=LIVE_READONLY_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
        status=status,
        evidence_payload=validated,
        findings=findings,
        collected_at=now,
        evidence_hash="",
        created_by=created_by,
    )
    evidence_record.evidence_hash = target_evidence_hash(
        organization_id=str(onboarding.organization_id),
        onboarding_id=str(onboarding.id),
        execution_target_id=str(target.id),
        evidence_source=evidence_record.evidence_source,
        verification_level=evidence_record.verification_level,
        status=status.value,
        collected_at=now,
        evidence_payload=validated,
        findings=findings,
    )
    session.add(evidence_record)
    session.flush()

    # 4. Build the preflight from the policy dimension checks (redacted closed codes only).
    canonical_checks = [
        {"check": c["check"], "status": _STATUS_TO_PREFLIGHT[c["status"]], "detail": c["detail"]}
        for c in evaluation.as_preflight_checks()
    ]
    version = _next_evidence_version(session, onboarding.id)
    scope_policy_hash = provisioning_scope_policy_hash(target.scope_policy or {})

    pf = TargetPreflight(
        organization_id=onboarding.organization_id,
        onboarding_id=onboarding.id,
        collector=CollectorKind.provider_worker.value,
        verification_level=VerificationLevel.live_verified.value,
        collector_kind=CollectorKind.provider_worker.value,
        collector_identity=collector_identity,
        evidence_version=version,
        target_config_hash=target.config_hash,
        scope_policy_hash=scope_policy_hash,
        boundary_hash=onboarding.boundary_hash,
        toolchain_profile_id=None,
        toolchain_profile_hash=None,
        passed=eligible,
        checks=canonical_checks,
        evidence_hash="",
        target_evidence_id=evidence_record.id,
        target_evidence_hash=evidence_record.evidence_hash,
        created_by=created_by,
        operation_fingerprint=operation_fingerprint,
        eligibility_outcome=evaluation.outcome,
        eligibility_policy_version=evaluation.policy_version,
        evidence_expires_at=now + ELIGIBILITY_EVIDENCE_TTL,
        live_read_authorization_id=live_read_authorization_id,
        live_read_authorization_version=live_read_authorization_version,
        worker_identity_registration_id=worker_identity_registration_id,
    )
    pf.evidence_hash = evidence_package_hash(
        build_evidence_package(
            onboarding_id=str(onboarding.id),
            boundary_hash=pf.boundary_hash,
            target_config_hash=pf.target_config_hash,
            scope_policy_hash=pf.scope_policy_hash,
            toolchain_profile_id=None,
            toolchain_profile_hash=None,
            verification_level=pf.verification_level,
            collector_kind=pf.collector_kind,
            collector_identity=pf.collector_identity,
            evidence_version=pf.evidence_version,
            checks=canonical_checks,
            target_evidence_id=str(evidence_record.id),
            target_evidence_hash=evidence_record.evidence_hash,
        )
    )
    session.add(pf)
    session.flush()

    audit.record(
        session,
        action=AuditAction.eligibility_preflight_completed,
        resource_type="target_preflight",
        resource_id=pf.id,
        organization_id=onboarding.organization_id,
        actor="worker" if created_by is None else str(created_by),
        outcome=evaluation.outcome,
        data={
            "onboarding_id": str(onboarding.id),
            "execution_target_id": str(target.id),
            "evidence_source": LIVE_READONLY_EVIDENCE_SOURCE,
            "verification_level": VerificationLevel.live_verified.value,
            "eligibility_outcome": evaluation.outcome,
            "eligibility_policy_version": evaluation.policy_version,
            "passed": pf.passed,
            "evidence_hash": pf.evidence_hash,
            "target_evidence_hash": pf.target_evidence_hash,
            "live_read_authorization_id": str(live_read_authorization_id),
            "live_read_authorization_version": live_read_authorization_version,
        },
    )
    return pf
