"""Worker-only durable claim/lease consumer for read-only discovery jobs (SECP-B5 §1).

Claims a committed, queued :class:`DiscoveryJob` with a compare-and-swap + a lease (``claimed_at`` +
a lease TTL for restart recovery), transitions it queued → claimed → running → terminal, and invokes
the READ-ONLY discovery engine with the SHIPPED SEALED composition — so the normal worker runtime is
wired end to end but performs ZERO host contact (the sealed probe source refuses). A real read-only
probe executor is supplied only out of band on the isolated worker after a bootstrap bundle is
mounted. This module imports no mutation-capable code and contacts nothing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    DiscoveryFailureCode,
    DiscoveryJobStatus,
)
from secp_api.models import DiscoveryJob, TargetDiscoveryEnrollment
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from secp_worker.target_discovery.engine import (
    DiscoveryComposition,
    DiscoveryOutcome,
    run_discovery,
    sealed_discovery_composition,
)

# Lease TTL: a claimed/running job older than this is reclaimable (restart recovery).
_LEASE_SECONDS = 300


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _cas(
    session: Session,
    job: DiscoveryJob,
    *,
    expected_status: DiscoveryJobStatus,
    new_status: DiscoveryJobStatus,
    extra: dict | None = None,
) -> bool:
    values: dict = {"status": new_status, "revision": job.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(DiscoveryJob)
        .where(
            DiscoveryJob.id == job.id,
            DiscoveryJob.status == expected_status,
            DiscoveryJob.revision == job.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(job)
    return True


def _candidate_stmt(now: datetime):
    threshold = now - timedelta(seconds=_LEASE_SECONDS)
    return (
        select(DiscoveryJob)
        .where(
            or_(
                DiscoveryJob.status == DiscoveryJobStatus.queued,
                and_(
                    DiscoveryJob.status.in_(
                        [DiscoveryJobStatus.claimed, DiscoveryJobStatus.running]
                    ),
                    DiscoveryJob.claimed_at < threshold,
                ),
            )
        )
        .order_by(DiscoveryJob.created_at)
        .limit(1)
    )


def _claim_candidate(session: Session, now: datetime) -> DiscoveryJob | None:
    dialect = session.bind.dialect.name if session.bind is not None else ""
    stmt = _candidate_stmt(now)
    if dialect == "postgresql":
        candidate = session.execute(stmt.with_for_update(skip_locked=True)).scalars().first()
        if candidate is None:
            return None
        candidate.status = DiscoveryJobStatus.claimed
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
        new_status=DiscoveryJobStatus.claimed,
        extra={"claimed_at": now, "attempt_count": candidate.attempt_count + 1},
    ):
        return None
    return candidate


def claim_and_process_one(
    session: Session,
    *,
    composition: DiscoveryComposition | None = None,
    now: datetime | None = None,
) -> uuid.UUID | None:
    """Claim and process one discovery job. Returns its id, or None if none/lost.

    ``composition`` defaults to the SHIPPED SEALED composition, so the normal runtime invokes the
    read-only engine but contacts nothing (the sealed probe source refuses). Injectable for
    tests."""
    now = now or _utcnow()
    composition = composition or sealed_discovery_composition()
    job = _claim_candidate(session, now)
    if job is None:
        return None
    if not _cas(
        session,
        job,
        expected_status=DiscoveryJobStatus.claimed,
        new_status=DiscoveryJobStatus.running,
    ):
        return job.id  # lost the race; another worker owns it

    try:
        outcome = run_discovery(session, job, composition=composition, now=now)
    except Exception:  # never leak a raw engine/host error onto the job record
        outcome = DiscoveryOutcome(False, DiscoveryFailureCode.internal_error.value)

    terminal = DiscoveryJobStatus.completed if outcome.ok else DiscoveryJobStatus.failed
    _cas(
        session,
        job,
        expected_status=DiscoveryJobStatus.running,
        new_status=terminal,
        extra={
            "failure_code": None if outcome.ok else outcome.reason_code,
            "phase": outcome.reason_code,
            "completed_at": now,
        },
    )
    enrollment = session.get(TargetDiscoveryEnrollment, job.enrollment_id)
    if enrollment is not None:
        audit.record(
            session,
            action=(
                AuditAction.target_discovery_completed
                if outcome.ok
                else AuditAction.target_discovery_failed
            ),
            resource_type="target_discovery_enrollment",
            resource_id=enrollment.id,
            organization_id=enrollment.organization_id,
            actor="worker",
            outcome="success" if outcome.ok else "failure",
            data={
                "status": enrollment.status.value,
                "reason_code": outcome.reason_code,
                "bundle_available": False,
            },
        )
    return job.id


def process_all_queued(
    session: Session,
    *,
    composition: DiscoveryComposition | None = None,
    max_items: int = 100,
) -> list[uuid.UUID]:
    processed: list[uuid.UUID] = []
    for _ in range(max_items):
        job_id = claim_and_process_one(session, composition=composition)
        if job_id is None:
            break
        processed.append(job_id)
    return processed
