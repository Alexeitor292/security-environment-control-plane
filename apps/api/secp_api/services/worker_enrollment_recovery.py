"""Restart/crash recovery for durable worker enrollment (SECP-PR5H-A, ADR-027, Commit 5).

Two recovery mechanisms, both entirely persistence-driven — no correctness depends on process
memory, caches, in-process locks, or retained request objects, so a freshly constructed service on a
database session recovers identically:

* **Lost-response recovery** (a transaction that committed but whose response was lost) is served by
  the durable step-receipt ledger built in Commit 4: an exact retry returns the already-committed
  resulting revision without adding a history row, re-consuming the nonce, or repeating effects, and
  a conflicting retry refuses. That path lives in :mod:`secp_api.services.worker_enrollment`; this
  module adds the **expiry sweep**.

* **Expiry sweep**: an explicit, idempotent, restart-safe pass that drives *due, active* enrollments
  to ``recovery_required`` through the pure contract under the *same* ``(revision, state_digest)``
  compare-and-swap as any other transition. The database never expires a row on its own (a trigger
  would mutate the row outside the digest chain and break every ``state_digest``); expiry is decided
  only here, from a caller-supplied ``now``.

Sweep guarantees:

* **Bounded, deterministic, tenancy-scoped**: a fixed code-owned batch size, a stable
  ``(expires_at_ts, enrollment_id)`` order, and a hard per-organization filter. No caller-controlled
  SQL/table/sort key and no unbounded scan.
* **Concurrent one-winner**: each candidate is locked ``FOR UPDATE SKIP LOCKED`` and transitioned in
  its OWN transaction; the CAS remains authoritative, so two racing sweepers commit exactly one
  transition and the loser observes the committed result rather than creating another revision.
* **Poison isolation**: every candidate is a separate transaction, so a corrupt/poisoned row rolls
  back only itself and is surfaced as a bounded corruption category — it never marks unrelated valid
  rows recovered, and it is preserved, never repaired.
* **Never sweeps** ``healthy`` (not active), ``refused`` / ``recovery_required`` (terminals), a
  revoked invitation, a corrupt row, a not-yet-due row, or another organization's records.

Only bounded aggregate counts and safe reason categories are reported. No transport, API route, UI,
CLI, host mutation, provider contact, workflow, OpenTofu or operator activation is added here.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass
from typing import Final

from sqlalchemy.orm import Session, sessionmaker

from secp_api import worker_enrollment_repository as repo
from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError
from secp_api.worker_enrollment_contract import require_recovery
from secp_api.worker_enrollment_repository import RepositoryRefusal
from secp_api.worker_enrollment_schema import EnrollmentSchemaError, assert_enrollment_schema_ready

#: The single bounded reason code the sweep stamps on a recovered row (bounded snake_case grammar).
SWEEP_REASON: Final = "expiry_recovery"

#: A fixed, code-owned maximum batch size — never caller-controlled, never an unbounded scan.
DEFAULT_SWEEP_BATCH: Final = 256

#: A fixed, code-owned cap on how many cursor windows one drain may walk, so draining stays bounded.
DEFAULT_MAX_PASSES: Final = 64


@dataclass(frozen=True)
class RecoverySweepResult:
    """Bounded aggregate outcome of one sweep pass. Carries only counts and safe categories — never
    an enrollment id, a reason string, a row detail, or anything caller-identifying."""

    examined: int  # candidate ids fetched in this bounded batch
    recovered: int  # rows driven to recovery_required and committed (this sweeper won the CAS)
    skipped: int  # not due / already non-active / locked / no-op
    conflicts: int  # CAS lost to a concurrent writer (the winner already committed)
    corrupt: int  # rehydration corruption — preserved, never repaired, never recovered
    failed: int = 0  # an UNEXPECTED error: rolled back, and deliberately NOT reported as corruption
    #: Keyset position after the last examined candidate, or None when this window was the last one.
    #: A draining caller passes it back as ``after`` so the next pass ALWAYS advances — otherwise
    #: candidates that can never be recovered (a corrupt row is preserved, not repaired) would sit
    #: at the head of the window forever and starve every valid due enrollment behind them.
    next_cursor: tuple[_dt.datetime, str] | None = None

    @property
    def total(self) -> int:
        """Every examined candidate lands in exactly one category, so this equals ``examined``."""
        return self.recovered + self.skipped + self.conflicts + self.corrupt + self.failed


def _assert_schema_ready(session: Session) -> None:
    try:
        assert_enrollment_schema_ready(session)
    except EnrollmentSchemaError:
        raise WorkerEnrollmentError(EC.schema_unavailable) from None


def recover_expired(
    session_factory: sessionmaker,
    *,
    organization_id: uuid.UUID,
    now: str,
    batch_size: int = DEFAULT_SWEEP_BATCH,
    after: tuple[_dt.datetime, str] | None = None,
) -> RecoverySweepResult:
    """Sweep one bounded batch of THIS org's due, active enrollments to ``recovery_required``.

    ``session_factory`` yields fresh sessions: the candidate batch is read in one session, then
    every candidate is recovered in its OWN transaction — so the sweep is fresh-process-safe (no
    shared state), poison-isolated (one bad row rolls back only itself), and concurrent-safe
    (per-row lock + CAS). The caller invokes this repeatedly to drain more than one batch; a single
    call never scans or transitions more than ``batch_size`` rows.
    """
    now_ts = repo.parse_canonical_utc(now)
    if now_ts is None:
        raise WorkerEnrollmentError(EC.time_invalid)
    limit = max(1, min(int(batch_size), DEFAULT_SWEEP_BATCH))

    with session_factory() as reader:
        _assert_schema_ready(reader)
        candidates = repo.select_due_active_candidates(
            reader, organization_id=organization_id, now_ts=now_ts, limit=limit, after=after
        )
    candidate_ids = [enrollment_id for enrollment_id, _ in candidates]
    # A full window may have more behind it; hand back the keyset position so the caller advances.
    next_cursor = (candidates[-1][1], candidates[-1][0]) if len(candidates) == limit else None

    recovered = skipped = conflicts = corrupt = failed = 0
    for enrollment_id in candidate_ids:
        outcome = _recover_one_isolated(
            session_factory, organization_id=organization_id, enrollment_id=enrollment_id, now=now
        )
        if outcome == "recovered":
            recovered += 1
        elif outcome == "conflict":
            conflicts += 1
        elif outcome == "corrupt":
            corrupt += 1
        elif outcome == "failed":
            failed += 1
        else:
            skipped += 1

    return RecoverySweepResult(
        examined=len(candidate_ids),
        recovered=recovered,
        skipped=skipped,
        conflicts=conflicts,
        corrupt=corrupt,
        failed=failed,
        next_cursor=next_cursor,
    )


def drain_expired(
    session_factory: sessionmaker,
    *,
    organization_id: uuid.UUID,
    now: str,
    batch_size: int = DEFAULT_SWEEP_BATCH,
    max_passes: int = DEFAULT_MAX_PASSES,
) -> RecoverySweepResult:
    """Drain the due queue by walking the keyset cursor, up to a code-owned ``max_passes`` bound.

    This is the forward-progress guarantee: candidates that can never be recovered (a preserved
    corrupt row) are stepped over instead of re-occupying the head of every pass. Still bounded — at
    most ``max_passes * batch_size`` candidates are examined in one drain — and the aggregate counts
    are summed across passes."""
    passes = max(1, min(int(max_passes), DEFAULT_MAX_PASSES))
    totals = {
        "examined": 0,
        "recovered": 0,
        "skipped": 0,
        "conflicts": 0,
        "corrupt": 0,
        "failed": 0,
    }
    cursor: tuple[_dt.datetime, str] | None = None
    for _ in range(passes):
        result = recover_expired(
            session_factory,
            organization_id=organization_id,
            now=now,
            batch_size=batch_size,
            after=cursor,
        )
        totals["examined"] += result.examined
        totals["recovered"] += result.recovered
        totals["skipped"] += result.skipped
        totals["conflicts"] += result.conflicts
        totals["corrupt"] += result.corrupt
        totals["failed"] += result.failed
        cursor = result.next_cursor
        if cursor is None:
            break
    return RecoverySweepResult(**totals, next_cursor=cursor)


def _recover_one_isolated(
    session_factory: sessionmaker,
    *,
    organization_id: uuid.UUID,
    enrollment_id: str,
    now: str,
) -> str:
    """Recover one candidate in its OWN transaction. Returns a bounded outcome category. Any refusal
    rolls back this row only; a genuinely unexpected error also rolls back and is surfaced as an
    internal-failure category (never a partial commit, never a raw exception)."""
    with session_factory() as session:
        try:
            outcome = _recover_one(
                session, organization_id=organization_id, enrollment_id=enrollment_id, now=now
            )
            if outcome == "recovered":
                session.commit()
            else:
                _safe_rollback(session)
            return outcome
        except RepositoryRefusal as exc:
            _safe_rollback(session)
            return _classify(exc.reason_code)
        except WorkerEnrollmentError as exc:
            _safe_rollback(session)
            return _classify(exc.code)
        except Exception:  # noqa: BLE001 - a poisoned row must not abort the sweep or leak
            _safe_rollback(session)
            # deliberately NOT reported as corruption: an unexpected error (a dropped connection, a
            # bug) is not evidence the row is corrupt, and mislabelling it would be untruthful.
            return "failed"


def _safe_rollback(session: Session) -> None:
    """Roll back without letting the rollback itself abort the sweep. After a
    connection-invalidating failure the rollback can raise too; the row simply stays uncommitted (no
    success is reported for it) and the remaining candidates are still processed in own sessions."""
    try:
        session.rollback()
    except Exception:  # noqa: BLE001 - the transaction is already lost; nothing was committed
        pass


def _classify(code: str) -> str:
    if code == "enrollment_revision_conflict":
        return "conflict"
    if code in ("enrollment_state_corrupt", "enrollment_history_inconsistent"):
        return "corrupt"
    return "skipped"


def _recover_one(
    session: Session,
    *,
    organization_id: uuid.UUID,
    enrollment_id: str,
    now: str,
) -> str:
    """Lock, fully validate, and (if genuinely due) transition ONE candidate to recovery_required
    under CAS. Does not commit — the isolated wrapper owns the transaction boundary."""
    # SKIP LOCKED: a row held by another sweeper is skipped, not blocked (CAS stays authoritative).
    loaded = repo.lock_and_load_sweep_candidate(
        session, enrollment_id=enrollment_id, organization_id=organization_id
    )
    if loaded is None:
        return "skipped"  # absent, already non-active (a concurrent sweeper won), or locked

    # a revoked invitation is a separate lifecycle — never swept by expiry
    if repo.invitation_is_revoked(session, enrollment_id=enrollment_id):
        return "skipped"

    # the head must agree with the append-only history before we transition it (corrupt -> caught)
    repo.verify_history_consistent(session, enrollment_id, loaded.state)

    # only recover a row ACTUALLY due at the caller-supplied now (the shadow-column filter is an
    # index optimization; the authoritative decision is on the canonical text, re-proven here)
    if not _is_due(loaded.state.expires_at, now):
        return "skipped"

    # pure, absorbing-terminal transition; the sweep supplies the single bounded reason
    new_state = require_recovery(loaded.state, SWEEP_REASON)
    if new_state is loaded.state:  # already terminal (should not happen under the active filter)
        return "skipped"

    # append history + CAS the head atomically; a stale/concurrent sweeper fails the CAS and refuses
    repo.commit_transition(session, prior=loaded, new_state=new_state, step=None, input_digest=None)
    return "recovered"


def _is_due(expires_at: str, now: str) -> bool:
    """True only when ``now >= expires_at`` under strict UTC parsing. A malformed persisted expiry
    is corruption; a malformed ``now`` is a time error — both refuse rather than sweeping."""
    expires_dt = repo.parse_canonical_utc(expires_at)
    if expires_dt is None:
        raise RepositoryRefusal("enrollment_state_corrupt")
    now_dt = repo.parse_canonical_utc(now)
    if now_dt is None:
        raise WorkerEnrollmentError(EC.time_invalid)
    return now_dt >= expires_dt


__all__ = [
    "DEFAULT_MAX_PASSES",
    "DEFAULT_SWEEP_BATCH",
    "SWEEP_REASON",
    "RecoverySweepResult",
    "drain_expired",
    "recover_expired",
]
