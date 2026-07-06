"""Worker-only durable claim/lease consumer for deployment operations (SECP-B4 corrective, §1/§8).

Claims a committed, queued :class:`StagingDeploymentOperation` with a compare-and-swap + a lease
(``claimed_at`` + a lease TTL for restart recovery), transitions it queued → claimed → running →
terminal, and invokes the deployment engine with the SHIPPED SEALED composition — so the normal
worker runtime is wired end to end but REFUSES before any network/SSH/host action (the sealed
bootstrap seam fails closed first). A real composition is supplied only out of band on the isolated
worker after a bootstrap bundle is mounted.

Restart recovery: a stale in-flight operation (claimed/running past its lease) is reclaimable, and
the
engine's per-resource idempotent create (absent-or-already-ours) + unique resource records ensure a
resumed run never duplicates a bridge/VM/token/credential. This module contacts nothing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    DeploymentFailureCode,
    DeploymentOperationKind,
    DeploymentOperationStatus,
    StagingDeploymentStatus,
)
from secp_api.models import StagingDeployment, StagingDeploymentOperation
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from secp_worker.deployment.engine import (
    DeploymentComposition,
    EngineOutcome,
    rollback_or_teardown,
    run_apply,
    sealed_composition,
)

# Lease TTL: a claimed/running operation older than this is reclaimable (restart recovery).
_LEASE_SECONDS = 300


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _cas(
    session: Session,
    op: StagingDeploymentOperation,
    *,
    expected_status: DeploymentOperationStatus,
    new_status: DeploymentOperationStatus,
    extra: dict | None = None,
) -> bool:
    values: dict = {"status": new_status, "revision": op.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(StagingDeploymentOperation)
        .where(
            StagingDeploymentOperation.id == op.id,
            StagingDeploymentOperation.status == expected_status,
            StagingDeploymentOperation.revision == op.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(op)
    return True


def _candidate_stmt(now: datetime):
    threshold = now - timedelta(seconds=_LEASE_SECONDS)
    return (
        select(StagingDeploymentOperation)
        .where(
            or_(
                StagingDeploymentOperation.status == DeploymentOperationStatus.queued,
                and_(
                    StagingDeploymentOperation.status.in_(
                        [DeploymentOperationStatus.claimed, DeploymentOperationStatus.running]
                    ),
                    StagingDeploymentOperation.claimed_at < threshold,
                ),
            )
        )
        .order_by(StagingDeploymentOperation.created_at)
        .limit(1)
    )


def _claim_candidate(session: Session, now: datetime) -> StagingDeploymentOperation | None:
    dialect = session.bind.dialect.name if session.bind is not None else ""
    stmt = _candidate_stmt(now)
    if dialect == "postgresql":
        candidate = session.execute(stmt.with_for_update(skip_locked=True)).scalars().first()
        if candidate is None:
            return None
        candidate.status = DeploymentOperationStatus.claimed
        candidate.revision = candidate.revision + 1
        candidate.claimed_at = now
        candidate.attempt_count = candidate.attempt_count + 1
        session.flush()
        return candidate

    candidate = session.execute(stmt).scalars().first()
    if candidate is None:
        return None
    prev = candidate.status
    if not _cas(
        session,
        candidate,
        expected_status=prev,
        new_status=DeploymentOperationStatus.claimed,
        extra={"claimed_at": now, "attempt_count": candidate.attempt_count + 1},
    ):
        return None
    return candidate


_TERMINAL_AUDIT = {
    StagingDeploymentStatus.ready: AuditAction.staging_deployment_ready,
    StagingDeploymentStatus.rolled_back: AuditAction.staging_deployment_rolled_back,
    StagingDeploymentStatus.destroyed: AuditAction.staging_deployment_destroyed,
    StagingDeploymentStatus.rollback_required: AuditAction.staging_deployment_failed,
    StagingDeploymentStatus.failed: AuditAction.staging_deployment_failed,
}


def _run_engine(
    session: Session,
    op: StagingDeploymentOperation,
    dep: StagingDeployment,
    composition: DeploymentComposition,
    now: datetime,
) -> EngineOutcome:
    kind = op.operation_kind
    if kind == DeploymentOperationKind.apply:
        return run_apply(
            session,
            dep,
            composition=composition,
            now=now,
            operation_fingerprint=op.operation_fingerprint,
        )
    if kind == DeploymentOperationKind.rollback:
        return rollback_or_teardown(
            session,
            dep,
            composition=composition,
            now=now,
            final_status=StagingDeploymentStatus.rolled_back,
        )
    if kind == DeploymentOperationKind.teardown:
        return rollback_or_teardown(
            session,
            dep,
            composition=composition,
            now=now,
            final_status=StagingDeploymentStatus.destroyed,
        )
    if kind == DeploymentOperationKind.verify:
        return EngineOutcome(True, "verified")
    return EngineOutcome(False, DeploymentFailureCode.internal_error.value)


def claim_and_process_one(
    session: Session,
    *,
    composition: DeploymentComposition | None = None,
    now: datetime | None = None,
) -> uuid.UUID | None:
    """Claim and process one deployment operation. Returns its id, or None if none/lost.

    ``composition`` defaults to the SHIPPED SEALED composition, so the normal runtime invokes the
    engine but fails closed at the bootstrap boundary and performs no real host action. It is
    injectable for tests only.
    """
    now = now or _utcnow()
    composition = composition or sealed_composition()
    op = _claim_candidate(session, now)
    if op is None:
        return None
    if not _cas(
        session,
        op,
        expected_status=DeploymentOperationStatus.claimed,
        new_status=DeploymentOperationStatus.running,
    ):
        return op.id  # lost the race; another worker owns it

    dep = session.get(StagingDeployment, op.deployment_id)
    if dep is None:
        _cas(
            session,
            op,
            expected_status=DeploymentOperationStatus.running,
            new_status=DeploymentOperationStatus.failed,
            extra={"failure_code": DeploymentFailureCode.internal_error.value, "completed_at": now},
        )
        return op.id

    try:
        outcome = _run_engine(session, op, dep, composition, now)
    except Exception:  # never leak a raw engine/host error onto the operation record
        outcome = EngineOutcome(False, DeploymentFailureCode.internal_error.value)

    terminal = (
        DeploymentOperationStatus.completed if outcome.ok else DeploymentOperationStatus.failed
    )
    _cas(
        session,
        op,
        expected_status=DeploymentOperationStatus.running,
        new_status=terminal,
        extra={
            "failure_code": None if outcome.ok else outcome.reason_code,
            "phase": outcome.reason_code,
            "completed_at": now,
        },
    )
    action = _TERMINAL_AUDIT.get(dep.status)
    if action is not None:
        audit.record(
            session,
            action=action,
            resource_type="staging_deployment",
            resource_id=dep.id,
            organization_id=dep.organization_id,
            actor="worker",
            outcome="success" if outcome.ok else "failure",
            data={
                "operation_kind": op.operation_kind.value,
                "status": dep.status.value,
                "failure_code": dep.failure_code,
            },
        )
    return op.id


def process_all_queued(
    session: Session,
    *,
    composition: DeploymentComposition | None = None,
    max_items: int = 100,
) -> list[uuid.UUID]:
    processed: list[uuid.UUID] = []
    for _ in range(max_items):
        op_id = claim_and_process_one(session, composition=composition)
        if op_id is None:
            break
        processed.append(op_id)
    return processed
