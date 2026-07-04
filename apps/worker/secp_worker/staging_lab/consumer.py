"""Worker-owned durable staging-lab work-item consumer (SECP-002B-1B-9).

Fake-only. This is the ONLY code that executes staging-lab simulation/teardown, and it runs in
the worker — never in the API process. It claims exactly one committed queued work item with a
database compare-and-swap, reloads the authoritative lab/approval/plan/organization/ownership and
lifecycle state, refuses stale/mismatched/cross-org/drifted/unowned work, runs the fake executor,
and only then writes simulated observations + completion. It constructs no transport, opens no
socket, spawns no subprocess, resolves no secret, and imports no provider/network code.

Boundary
--------
* Imports ``secp_api`` models/enums/audit (worker -> API dependency is permitted).
* Imports ``secp_worker.staging_lab.executor`` (worker-internal, fake-only).
* NEVER imported by ``apps/api`` (no API route or dispatcher references this module).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    StagingLabStatus,
    StagingWorkOperation,
    StagingWorkStatus,
)
from secp_api.models import StagingLab, StagingLabWorkItem
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secp_worker.staging_lab.executor import (
    FakeStagingLabExecutor,
    StagingLabOwnershipError,
)

# Operation -> (queued lab status the worker consumes, running status, terminal status).
_PHASES = {
    StagingWorkOperation.simulate_provision: (
        StagingLabStatus.simulation_queued,
        StagingLabStatus.simulating,
        StagingLabStatus.simulated_ready,
    ),
    StagingWorkOperation.simulate_teardown: (
        StagingLabStatus.teardown_queued,
        StagingLabStatus.tearing_down,
        StagingLabStatus.destroyed,
    ),
}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _cas_work(
    session: Session,
    item: StagingLabWorkItem,
    *,
    expected_status: StagingWorkStatus,
    new_status: StagingWorkStatus,
    extra: dict | None = None,
) -> bool:
    values: dict = {"status": new_status, "revision": item.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(StagingLabWorkItem)
        .where(
            StagingLabWorkItem.id == item.id,
            StagingLabWorkItem.status == expected_status,
            StagingLabWorkItem.revision == item.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(item)
    return True


def _cas_lab(
    session: Session,
    lab: StagingLab,
    *,
    expected_status: StagingLabStatus,
    new_status: StagingLabStatus,
    extra: dict | None = None,
) -> bool:
    values: dict = {"status": new_status, "revision": lab.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(StagingLab)
        .where(
            StagingLab.id == lab.id,
            StagingLab.status == expected_status,
            StagingLab.revision == lab.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(lab)
    return True


def _refuse(session: Session, item: StagingLabWorkItem, reason: str) -> None:
    """Terminally refuse a claimed work item with a generic, secret-free reason."""
    _cas_work(
        session,
        item,
        expected_status=StagingWorkStatus.claimed,
        new_status=StagingWorkStatus.refused,
        extra={"failure_reason": reason[:200], "failed_at": _utcnow()},
    )
    audit.record(
        session,
        action=AuditAction.staging_work_refused,
        resource_type="staging_lab_work_item",
        resource_id=item.id,
        organization_id=item.organization_id,
        actor="worker",
        outcome="denied",
        data={
            "staging_lab_id": str(item.staging_lab_id),
            "operation_kind": item.operation_kind.value,
            "reason_code": reason,
        },
    )


def _select_queued(session: Session) -> StagingLabWorkItem | None:
    return (
        session.execute(
            select(StagingLabWorkItem)
            .where(StagingLabWorkItem.status == StagingWorkStatus.queued)
            .order_by(StagingLabWorkItem.created_at)
            .limit(1)
        )
        .scalars()
        .first()
    )


def claim_and_process_one(session: Session) -> uuid.UUID | None:
    """Claim (exclusively) and process one queued work item. Returns its id, or None if none/lost.

    Authoritative-record based: after an exclusive compare-and-swap claim, every fact is reloaded
    from the durable lab and work item and re-validated before any fake execution.
    """
    candidate = _select_queued(session)
    if candidate is None:
        return None

    # Exclusive claim via compare-and-swap; a losing worker sees rowcount 0 and backs off.
    if not _cas_work(
        session,
        candidate,
        expected_status=StagingWorkStatus.queued,
        new_status=StagingWorkStatus.claimed,
        extra={"claimed_at": _utcnow()},
    ):
        return None
    audit.record(
        session,
        action=AuditAction.staging_work_claimed,
        resource_type="staging_lab_work_item",
        resource_id=candidate.id,
        organization_id=candidate.organization_id,
        actor="worker",
        data={
            "staging_lab_id": str(candidate.staging_lab_id),
            "operation_kind": candidate.operation_kind.value,
        },
    )

    lab = session.get(StagingLab, candidate.staging_lab_id)
    if lab is None:
        _refuse(session, candidate, "lab_missing")
        return candidate.id
    # Authoritative re-validation (fail closed).
    if lab.organization_id != candidate.organization_id:
        _refuse(session, candidate, "cross_org")
        return candidate.id
    if candidate.plan_hash != lab.plan_hash or candidate.plan_version != lab.plan_version:
        _refuse(session, candidate, "plan_drift")
        return candidate.id
    if lab.approved_plan_hash != lab.plan_hash:
        _refuse(session, candidate, "approval_mismatch")
        return candidate.id
    if lab.desired_state is None or lab.desired_state.get("ownership_label") != lab.ownership_label:
        _refuse(session, candidate, "ownership_mismatch")
        return candidate.id

    queued_status, running_status, terminal_status = _PHASES[candidate.operation_kind]
    if lab.status != queued_status:
        _refuse(session, candidate, "stale_lifecycle")
        return candidate.id

    # Worker-only transition into the running phase (compare-and-swap on the lab).
    if not _cas_lab(session, lab, expected_status=queued_status, new_status=running_status):
        _refuse(session, candidate, "lifecycle_raced")
        return candidate.id

    executor = FakeStagingLabExecutor()
    try:
        if candidate.operation_kind == StagingWorkOperation.simulate_provision:
            observed = executor.simulate(
                plan=lab.desired_state or {}, prior_observed=lab.simulated_observed_state
            )
        else:
            observed = executor.teardown(
                plan=lab.desired_state or {}, prior_observed=lab.simulated_observed_state
            )
    except StagingLabOwnershipError as exc:
        # Blast-radius refusal: revert the lab out of the running phase and fail the work.
        _cas_lab(session, lab, expected_status=running_status, new_status=StagingLabStatus.failed)
        _cas_work(
            session,
            candidate,
            expected_status=StagingWorkStatus.claimed,
            new_status=StagingWorkStatus.failed,
            extra={"failure_reason": exc.reason_code[:200], "failed_at": _utcnow()},
        )
        audit.record(
            session,
            action=AuditAction.staging_work_failed,
            resource_type="staging_lab_work_item",
            resource_id=candidate.id,
            organization_id=candidate.organization_id,
            actor="worker",
            outcome="denied",
            data={"staging_lab_id": str(lab.id), "reason_code": exc.reason_code},
        )
        return candidate.id

    # Worker alone writes observations + completion, guarded by compare-and-swap. A stale worker
    # whose lab revision drifted cannot complete after another operation changed state.
    if not _cas_lab(
        session,
        lab,
        expected_status=running_status,
        new_status=terminal_status,
        extra={"simulated_observed_state": observed},
    ):
        _cas_work(
            session,
            candidate,
            expected_status=StagingWorkStatus.claimed,
            new_status=StagingWorkStatus.refused,
            extra={"failure_reason": "stale_completion", "failed_at": _utcnow()},
        )
        return candidate.id
    _cas_work(
        session,
        candidate,
        expected_status=StagingWorkStatus.claimed,
        new_status=StagingWorkStatus.completed,
        extra={"completed_at": _utcnow()},
    )
    terminal_action = (
        AuditAction.staging_lab_simulated_ready
        if candidate.operation_kind == StagingWorkOperation.simulate_provision
        else AuditAction.staging_lab_destroyed
    )
    audit.record(
        session,
        action=terminal_action,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor="worker",
        data={
            "staging_lab_id": str(lab.id),
            "status": lab.status.value,
            "plan_hash": lab.plan_hash,
            "simulation_only": True,
            "observed_resource_count": len(observed.get("resources", [])),
        },
    )
    audit.record(
        session,
        action=AuditAction.staging_work_completed,
        resource_type="staging_lab_work_item",
        resource_id=candidate.id,
        organization_id=candidate.organization_id,
        actor="worker",
        data={"staging_lab_id": str(lab.id), "operation_kind": candidate.operation_kind.value},
    )
    return candidate.id


def process_all_queued(session: Session, *, max_items: int = 100) -> int:
    """Drain up to ``max_items`` queued work items (worker-side helper for tests/loops)."""
    processed = 0
    for _ in range(max_items):
        if claim_and_process_one(session) is None:
            break
        processed += 1
    return processed
