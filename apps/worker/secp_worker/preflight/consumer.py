"""Worker-owned durable read-only staging-preflight consumer (SECP-B2-0).

Claims exactly one committed queued preflight (``FOR UPDATE SKIP LOCKED`` on PostgreSQL; a
portable compare-and-swap fallback on SQLite), runs the worker orchestration (which fails closed
at ``credential_unavailable`` because the sealed resolver is injected), and records a closed
outcome + safe readiness facts. Only the worker writes outcomes. Never imported by the API.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    ReadonlyPreflightOutcome,
    ReadonlyPreflightStatus,
)
from secp_api.models import ReadonlyStagingPreflight
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secp_worker.preflight.activation_gate import ResolutionActivationGate
from secp_worker.preflight.identity import WorkerIdentityVerifier
from secp_worker.preflight.orchestration import (
    PreflightCollectionRunner,
    PreflightResult,
    run_readonly_preflight,
)
from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
from secp_worker.preflight.secret_resolution import WorkerSecretResolver

# Terminal outcomes that count as a completed (vs failed/refused) run for audit routing.
_REFUSAL_OUTCOMES = {
    ReadonlyPreflightOutcome.not_ready,
    ReadonlyPreflightOutcome.authorization_expired,
    ReadonlyPreflightOutcome.authorization_revoked,
    ReadonlyPreflightOutcome.authorization_invalid,
    ReadonlyPreflightOutcome.credential_unavailable,
    ReadonlyPreflightOutcome.tls_or_policy_refused,
}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _cas(
    session: Session,
    pf: ReadonlyStagingPreflight,
    *,
    expected_status: ReadonlyPreflightStatus,
    new_status: ReadonlyPreflightStatus,
    extra: dict | None = None,
) -> bool:
    values: dict = {"status": new_status, "revision": pf.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(ReadonlyStagingPreflight)
        .where(
            ReadonlyStagingPreflight.id == pf.id,
            ReadonlyStagingPreflight.status == expected_status,
            ReadonlyStagingPreflight.revision == pf.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(pf)
    return True


def _claim_candidate(session: Session) -> ReadonlyStagingPreflight | None:
    dialect = session.bind.dialect.name if session.bind is not None else ""
    if dialect == "postgresql":
        candidate = (
            session.execute(
                select(ReadonlyStagingPreflight)
                .where(ReadonlyStagingPreflight.status == ReadonlyPreflightStatus.queued)
                .order_by(ReadonlyStagingPreflight.created_at)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .first()
        )
        if candidate is None:
            return None
        candidate.status = ReadonlyPreflightStatus.claimed
        candidate.revision = candidate.revision + 1
        candidate.claimed_at = _utcnow()
        session.flush()
        return candidate

    candidate = (
        session.execute(
            select(ReadonlyStagingPreflight)
            .where(ReadonlyStagingPreflight.status == ReadonlyPreflightStatus.queued)
            .order_by(ReadonlyStagingPreflight.created_at)
            .limit(1)
        )
        .scalars()
        .first()
    )
    if candidate is None:
        return None
    if not _cas(
        session,
        candidate,
        expected_status=ReadonlyPreflightStatus.queued,
        new_status=ReadonlyPreflightStatus.claimed,
        extra={"claimed_at": _utcnow()},
    ):
        return None
    return candidate


def claim_and_process_one(
    session: Session,
    *,
    secret_resolver: WorkerSecretResolver | None = None,
    collection_runner: PreflightCollectionRunner | None = None,
    identity_verifier: WorkerIdentityVerifier | None = None,
    activation_gate: ResolutionActivationGate | None = None,
) -> uuid.UUID | None:
    """Claim and process one queued preflight. Returns its id, or None if none/lost.

    ``secret_resolver`` defaults to the SEALED resolver (fail-closed ``credential_unavailable``);
    ``collection_runner`` defaults to None (no real collection is wired in this PR);
    ``identity_verifier`` / ``activation_gate`` default to the SHIPPED SEALED foundation
    (deny-by-default identity, disabled activation gate), so shipped runtime fails closed before any
    durable lease is acquired. All of these are injectable for tests only.
    """
    resolver = secret_resolver or SealedSecretResolver()
    candidate = _claim_candidate(session)
    if candidate is None:
        return None
    audit.record(
        session,
        action=AuditAction.readonly_preflight_claimed,
        resource_type="readonly_staging_preflight",
        resource_id=candidate.id,
        organization_id=candidate.organization_id,
        actor="worker",
        data={"execution_target_id": str(candidate.execution_target_id)},
    )

    # Worker-only transition into the running phase (compare-and-swap).
    if not _cas(
        session,
        candidate,
        expected_status=ReadonlyPreflightStatus.claimed,
        new_status=ReadonlyPreflightStatus.running,
    ):
        return candidate.id  # lost the race; another worker owns it

    try:
        result: PreflightResult = run_readonly_preflight(
            session,
            candidate.id,
            secret_resolver=resolver,
            collection_runner=collection_runner,
            identity_verifier=identity_verifier,
            activation_gate=activation_gate,
        )
    except Exception:  # defensive: never surface internals; fail closed
        result = PreflightResult(ReadonlyPreflightOutcome.worker_internal_failure)

    is_ready = result.outcome == ReadonlyPreflightOutcome.ready
    is_internal = result.outcome == ReadonlyPreflightOutcome.worker_internal_failure
    terminal_status = (
        ReadonlyPreflightStatus.completed
        if is_ready or result.outcome in _REFUSAL_OUTCOMES
        else ReadonlyPreflightStatus.failed
    )
    # Write the outcome + safe facts ATOMICALLY with the terminal transition, guarded by CAS. A
    # stale worker whose lab revision drifted (another operation changed state) loses the CAS: it
    # writes NO facts/outcome and emits NO terminal audit — it must not overwrite a newer state.
    terminal_ok = _cas(
        session,
        candidate,
        expected_status=ReadonlyPreflightStatus.running,
        new_status=terminal_status,
        extra={
            "outcome_code": result.outcome,
            "readiness_facts": result.readiness_facts,
            "completed_at": _utcnow(),
        },
    )
    if not terminal_ok:
        return candidate.id  # fail closed: no readiness facts, no misleading terminal audit
    # Only the worker that WON the terminal CAS emits the terminal audit (transactionally
    # consistent with the committed terminal transition above).
    action = (
        AuditAction.readonly_preflight_failed
        if is_internal
        else AuditAction.readonly_preflight_completed
        if is_ready
        else AuditAction.readonly_preflight_refused
    )
    audit.record(
        session,
        action=action,
        resource_type="readonly_staging_preflight",
        resource_id=candidate.id,
        organization_id=candidate.organization_id,
        actor="worker",
        outcome="success" if is_ready else "denied",
        data={
            "execution_target_id": str(candidate.execution_target_id),
            "outcome_code": result.outcome.value,
        },
    )
    return candidate.id


def process_all_queued(session: Session, *, max_items: int = 100) -> int:
    processed = 0
    for _ in range(max_items):
        if claim_and_process_one(session) is None:
            break
        processed += 1
    return processed
