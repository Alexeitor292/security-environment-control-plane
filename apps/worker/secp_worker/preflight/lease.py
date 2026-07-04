"""Durable, worker-only resolution-lease service (SECP-B2-3).

Implements the B2-2 durable lease + retry contract with a portable compare-and-swap that works
identically on SQLite and PostgreSQL. It persists ONLY secret-free operation/lease state — never a
credential, credential/secret reference, endpoint, target configuration, certificate, backend
response, or hash of any of those. It resolves nothing and contacts nothing.

Global operation uniqueness boundary (the budget/single-use key), exactly per B2-2::

    (live_read_authorization_id, authorization_version, operation_fingerprint)

Worker identity is recorded for evidence only and is deliberately **not** part of that key, so two
workers can never each hold a valid pre-success lease for the same operation. The retry budget is
fixed at ``N=3``, durable per uniqueness key, shared across every lease instance and worker
identity; a fresh lease never resets or expands it; only a new ``authorization_version`` creates a
distinct key with a fresh budget; authorization expiry alone never grants new attempts.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from secp_api import audit
from secp_api.enums import AuditAction, ResolutionLeaseReason, ResolutionLeaseStatus
from secp_api.models import ResolutionLease
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# Fixed by the SECP-B2-2 contract. Not configurable.
RETRY_BUDGET: int = 3
# Short lease-instance TTL; always clamped to never exceed the authorization expiry.
DEFAULT_LEASE_TTL_SECONDS: int = 120

_SUCCESS_ACTIONS = frozenset(
    {
        AuditAction.resolution_lease_acquired,
        AuditAction.resolution_lease_attempt_started,
        AuditAction.resolution_lease_consumed,
    }
)


class LeaseRefused(Exception):
    """Fail-closed lease refusal carrying only a closed, secret-free reason code."""

    def __init__(self, reason: ResolutionLeaseReason) -> None:
        super().__init__(f"resolution lease refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True)
class OperationKey:
    """The global operation uniqueness key (no worker identity)."""

    live_read_authorization_id: uuid.UUID
    authorization_version: int
    operation_fingerprint: str


def _as_utc(value: datetime) -> datetime:
    """Treat a naive stored datetime as UTC (SQLite drops tzinfo; PostgreSQL preserves it)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _load(session: Session, key: OperationKey) -> ResolutionLease | None:
    return (
        session.query(ResolutionLease)
        .filter(
            ResolutionLease.live_read_authorization_id == key.live_read_authorization_id,
            ResolutionLease.authorization_version == key.authorization_version,
            ResolutionLease.operation_fingerprint == key.operation_fingerprint,
        )
        .one_or_none()
    )


def _cas(session: Session, row: ResolutionLease, *, expected_revision: int, values: dict) -> bool:
    """Conditional update guarded by (id, revision). Returns True iff exactly one row changed."""
    result = session.execute(
        update(ResolutionLease)
        .where(
            ResolutionLease.id == row.id,
            ResolutionLease.revision == expected_revision,
        )
        .values(revision=expected_revision + 1, **values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _audit(
    session: Session,
    row: ResolutionLease,
    action: AuditAction,
    *,
    reason: ResolutionLeaseReason | None = None,
) -> None:
    data: dict = {
        "live_read_authorization_id": str(row.live_read_authorization_id),
        "authorization_version": row.authorization_version,
        "operation_fingerprint": row.operation_fingerprint,
        "lease_id": str(row.lease_id),
        "status": row.status.value,
        "attempt_count": row.attempt_count,
        "revision": row.revision,
        "worker_identity_id": row.worker_identity_id,
    }
    if reason is not None:
        data["reason_code"] = reason.value
    audit.record(
        session,
        action=action,
        resource_type="resolution_lease",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor="worker",
        outcome="success" if action in _SUCCESS_ACTIONS else "denied",
        data=data,
    )


def _mark_exhausted(session: Session, row: ResolutionLease) -> None:
    """Durably transition an over-budget operation to ``exhausted`` (CAS-guarded, fail-closed).

    A losing transition changes no state and emits no audit; the caller still fails closed.
    """
    if _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "status": ResolutionLeaseStatus.exhausted,
            "reason_code": ResolutionLeaseReason.retry_bound_exceeded.value,
        },
    ):
        _audit(
            session,
            row,
            AuditAction.resolution_lease_refused,
            reason=ResolutionLeaseReason.retry_bound_exceeded,
        )


def acquire_lease(
    session: Session,
    *,
    organization_id: uuid.UUID,
    key: OperationKey,
    worker_identity_id: str,
    authorization_expiry: datetime,
    now: datetime,
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
) -> ResolutionLease:
    """Acquire the single valid pre-success lease for one operation key, or fail closed.

    Refuses (``LeaseRefused``) on: a consumed operation (``replay_refused``); an exhausted budget
    (``retry_bound_exceeded``); an already-held valid pre-success lease (``lease_held``); or an
    already-expired authorization (``authorization_expired``). Never resets the durable budget.
    """
    authorization_expiry = _as_utc(authorization_expiry)
    lease_expires_at = min(now + timedelta(seconds=lease_ttl_seconds), authorization_expiry)
    if lease_expires_at <= now:
        raise LeaseRefused(ResolutionLeaseReason.authorization_expired)

    existing = _load(session, key)
    if existing is None:
        row = ResolutionLease(
            organization_id=organization_id,
            live_read_authorization_id=key.live_read_authorization_id,
            authorization_version=key.authorization_version,
            operation_fingerprint=key.operation_fingerprint,
            lease_id=uuid.uuid4(),
            revision=0,
            status=ResolutionLeaseStatus.active,
            attempt_count=0,
            lease_expires_at=lease_expires_at,
            worker_identity_id=worker_identity_id,
            reason_code="",
        )
        try:
            # SAVEPOINT: add + flush INSIDE the nested transaction so a duplicate-insert conflict is
            # contained by the savepoint and the outer session stays usable for the recovery reload.
            with session.begin_nested():
                session.add(row)
                session.flush()
        except IntegrityError:
            # Lost the insert race for this uniqueness key: another worker created the row.
            existing = _load(session, key)
            if existing is None:
                raise LeaseRefused(ResolutionLeaseReason.lease_held) from None
            return _reacquire_existing(session, existing, worker_identity_id, lease_expires_at, now)
        _audit(session, row, AuditAction.resolution_lease_acquired)
        return row
    return _reacquire_existing(session, existing, worker_identity_id, lease_expires_at, now)


def _reacquire_existing(
    session: Session,
    row: ResolutionLease,
    worker_identity_id: str,
    lease_expires_at: datetime,
    now: datetime,
) -> ResolutionLease:
    if row.status == ResolutionLeaseStatus.consumed:
        raise LeaseRefused(ResolutionLeaseReason.replay_refused)
    if row.status == ResolutionLeaseStatus.exhausted or row.attempt_count >= RETRY_BUDGET:
        _mark_exhausted(session, row)
        raise LeaseRefused(ResolutionLeaseReason.retry_bound_exceeded)
    # status == active
    if _as_utc(row.lease_expires_at) > now:
        # A valid pre-success lease already exists (possibly another worker): at most one.
        raise LeaseRefused(ResolutionLeaseReason.lease_held)
    # The prior lease instance expired: re-issue a fresh lease, PRESERVING the durable budget.
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "lease_id": uuid.uuid4(),
            "lease_expires_at": lease_expires_at,
            "worker_identity_id": worker_identity_id,
            "status": ResolutionLeaseStatus.active,
        },
    ):
        raise LeaseRefused(ResolutionLeaseReason.lease_held)  # lost the re-acquire race
    _audit(session, row, AuditAction.resolution_lease_acquired)
    return row


def begin_attempt(session: Session, row: ResolutionLease, *, now: datetime) -> ResolutionLease:
    """Durable, atomic begin-attempt transition immediately before the future secret boundary.

    This is the ONLY transition that consumes the retry budget. Lease issuance alone never resets
    or consumes it. Enforces the fixed ``N=3`` cap and the lease/authorization window, CAS-guarded.
    The shipped sealed path never reaches this call (it fails closed at the identity/activation gate
    before lease acquisition).
    """
    if row.status == ResolutionLeaseStatus.consumed:
        raise LeaseRefused(ResolutionLeaseReason.replay_refused)
    if row.status != ResolutionLeaseStatus.active:
        raise LeaseRefused(ResolutionLeaseReason.retry_bound_exceeded)
    if _as_utc(row.lease_expires_at) <= now:
        raise LeaseRefused(ResolutionLeaseReason.authorization_expired)
    if row.attempt_count >= RETRY_BUDGET:
        _mark_exhausted(session, row)
        raise LeaseRefused(ResolutionLeaseReason.retry_bound_exceeded)
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={"attempt_count": row.attempt_count + 1},
    ):
        raise LeaseRefused(ResolutionLeaseReason.lease_held)  # a concurrent transition won
    _audit(session, row, AuditAction.resolution_lease_attempt_started)
    return row


def mark_consumed(session: Session, row: ResolutionLease, *, now: datetime) -> ResolutionLease:
    """Mark the operation globally single-use after a successful resolution (future path only).

    Only ``active -> consumed`` is legal. An already-consumed or exhausted lease fails closed with
    NO state change (status, revision, attempt_count, lease_id preserved) and NO new audit event.
    Never reached in this PR's shipped or sealed-test flow (the sealed resolver never succeeds).
    """
    if row.status != ResolutionLeaseStatus.active:
        # Invalid source state: refuse before any CAS/audit so nothing is written.
        raise LeaseRefused(
            ResolutionLeaseReason.replay_refused
            if row.status == ResolutionLeaseStatus.consumed
            else ResolutionLeaseReason.retry_bound_exceeded
        )
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={"status": ResolutionLeaseStatus.consumed, "consumed_at": now},
    ):
        raise LeaseRefused(ResolutionLeaseReason.lease_held)
    _audit(session, row, AuditAction.resolution_lease_consumed)
    return row
