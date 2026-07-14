"""Durable, worker-only plan-secret resolution lease (B1B-PR4 / ADR-021 §J).

It reuses the SECP-B2-3 durable lease + retry contract byte-for-byte in behaviour — a portable
compare-and-swap that works identically on SQLite and PostgreSQL — but on the dedicated
:class:`~secp_api.models.PlanSecretResolutionLease` table, because the B2-3 ``ResolutionLease`` is
keyed on ``live_read_authorization_id`` (a NOT-NULL foreign key to ``live_read_authorization``) and
its uniqueness constraint is built from it. Reusing that row for a provisioning-secret operation
would make its foreign-key semantics FALSE.

Global operation uniqueness boundary (the budget / single-use key)::

    (authorization_id, authorization_version, operation_fingerprint)

The ``operation_fingerprint`` itself already folds in EVERY other security-relevant fact — the
organization, target, onboarding, manifest, plan, eligibility evidence id + hash, the
state-readiness
record id + hash, the toolchain profile id + hash, the worker identity id + version, the activation
dossier hash, the secret purpose, the resolver contract version, the readiness policy version, and
the authorization expiry (see ``ReadinessBinding.operation_fingerprint``).

Worker identity is recorded for evidence only and is deliberately **not** part of the key, so two
worker identities can never each hold a valid pre-success lease — and never open an independent
duplicate retry budget — for the same operation. The retry budget is fixed at ``N=3``, durable per
uniqueness key, shared across every lease instance and worker identity; a fresh lease never resets
or
expands it; only a new ``authorization_version`` (which requires a NEW authorization row) creates a
distinct key with a fresh budget; and the authorization expiry is an IMMUTABLE binding fact, so it
can never silently grant new attempts.

It persists ONLY secret-free lease state — never a credential, secret reference, hash of a
reference,
endpoint, backend response, or target configuration. It resolves nothing and contacts nothing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from secp_api import audit
from secp_api.enums import AuditAction, ResolutionLeaseReason, ResolutionLeaseStatus
from secp_api.models import PlanSecretResolutionLease
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# Fixed by the contract. Not configurable.
RETRY_BUDGET: int = 3
# Short lease-instance TTL; always clamped so it can never exceed the authorization expiry.
DEFAULT_LEASE_TTL_SECONDS: int = 120

_SUCCESS_ACTIONS = frozenset(
    {
        AuditAction.resolution_lease_acquired,
        AuditAction.resolution_lease_attempt_started,
        AuditAction.resolution_lease_consumed,
    }
)


class PlanSecretLeaseRefused(Exception):
    """Fail-closed lease refusal carrying only a closed, secret-free reason code."""

    def __init__(self, reason: ResolutionLeaseReason) -> None:
        super().__init__(f"plan-secret resolution lease refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True)
class PlanSecretOperationKey:
    """The global operation uniqueness key (deliberately NO worker identity)."""

    authorization_id: uuid.UUID
    authorization_version: int
    operation_fingerprint: str


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _load(session: Session, key: PlanSecretOperationKey) -> PlanSecretResolutionLease | None:
    return (
        session.query(PlanSecretResolutionLease)
        .filter(
            PlanSecretResolutionLease.authorization_id == key.authorization_id,
            PlanSecretResolutionLease.authorization_version == key.authorization_version,
            PlanSecretResolutionLease.operation_fingerprint == key.operation_fingerprint,
        )
        .one_or_none()
    )


def _cas(
    session: Session,
    row: PlanSecretResolutionLease,
    *,
    expected_revision: int,
    values: dict,
) -> bool:
    """Conditional update guarded by (id, revision). True iff exactly one row changed."""
    result = session.execute(
        update(PlanSecretResolutionLease)
        .where(
            PlanSecretResolutionLease.id == row.id,
            PlanSecretResolutionLease.revision == expected_revision,
        )
        .values(revision=expected_revision + 1, **values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _audit(
    session: Session,
    row: PlanSecretResolutionLease,
    action: AuditAction,
    *,
    reason: ResolutionLeaseReason | None = None,
) -> None:
    data: dict = {
        "operation_kind": "plan_secret_readiness",
        "authorization_id": str(row.authorization_id),
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
        resource_type="plan_secret_resolution_lease",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor="worker",
        outcome="success" if action in _SUCCESS_ACTIONS else "denied",
        data=data,
    )


def _mark_exhausted(session: Session, row: PlanSecretResolutionLease) -> None:
    """Durably transition an over-budget operation to ``exhausted`` (CAS-guarded, fail closed)."""
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
    key: PlanSecretOperationKey,
    worker_identity_id: str,
    authorization_expiry: datetime,
    now: datetime,
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
) -> PlanSecretResolutionLease:
    """Acquire the single valid pre-success lease for one operation key, or fail closed.

    Refuses on: a consumed operation (``replay_refused``); an exhausted budget
    (``retry_bound_exceeded``); an already-held valid pre-success lease (``lease_held``); or an
    already-expired authorization (``authorization_expired``). It NEVER resets the durable budget.
    Acquiring a lease contacts NO secret manager — only ``begin_attempt`` opens that boundary.
    """
    authorization_expiry = _as_utc(authorization_expiry)
    lease_expires_at = min(now + timedelta(seconds=lease_ttl_seconds), authorization_expiry)
    if lease_expires_at <= now:
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.authorization_expired)

    existing = _load(session, key)
    if existing is None:
        row = PlanSecretResolutionLease(
            organization_id=organization_id,
            authorization_id=key.authorization_id,
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
            # contained and the outer session stays usable for the recovery reload.
            with session.begin_nested():
                session.add(row)
                session.flush()
        except IntegrityError:
            existing = _load(session, key)
            if existing is None:
                raise PlanSecretLeaseRefused(ResolutionLeaseReason.lease_held) from None
            return _reacquire_existing(session, existing, worker_identity_id, lease_expires_at, now)
        _audit(session, row, AuditAction.resolution_lease_acquired)
        return row
    return _reacquire_existing(session, existing, worker_identity_id, lease_expires_at, now)


def _reacquire_existing(
    session: Session,
    row: PlanSecretResolutionLease,
    worker_identity_id: str,
    lease_expires_at: datetime,
    now: datetime,
) -> PlanSecretResolutionLease:
    if row.status == ResolutionLeaseStatus.consumed:
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.replay_refused)
    if row.status == ResolutionLeaseStatus.exhausted or row.attempt_count >= RETRY_BUDGET:
        _mark_exhausted(session, row)
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.retry_bound_exceeded)
    if _as_utc(row.lease_expires_at) > now:
        # A valid pre-success lease already exists (possibly another worker): at most one.
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.lease_held)
    # The prior lease instance EXPIRED: re-issue a fresh lease, PRESERVING the durable budget.
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
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.lease_held)
    _audit(session, row, AuditAction.resolution_lease_acquired)
    return row


def begin_attempt(
    session: Session, row: PlanSecretResolutionLease, *, now: datetime
) -> PlanSecretResolutionLease:
    """The ONLY budget-consuming transition, immediately before the secret-backend boundary.

    No secret-manager contact may happen before this call. Lease issuance alone never consumes or
    resets the budget. Enforces the fixed ``N=3`` cap and the lease/authorization window,
    CAS-guarded.
    """
    if row.status == ResolutionLeaseStatus.consumed:
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.replay_refused)
    if row.status != ResolutionLeaseStatus.active:
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.retry_bound_exceeded)
    if _as_utc(row.lease_expires_at) <= now:
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.authorization_expired)
    if row.attempt_count >= RETRY_BUDGET:
        _mark_exhausted(session, row)
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.retry_bound_exceeded)
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={"attempt_count": row.attempt_count + 1},
    ):
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.lease_held)
    _audit(session, row, AuditAction.resolution_lease_attempt_started)
    return row


def mark_consumed(
    session: Session, row: PlanSecretResolutionLease, *, now: datetime
) -> PlanSecretResolutionLease:
    """Mark the operation globally single-use AFTER a successful readiness handling.

    Only ``active -> consumed`` is legal. A failure NEVER becomes a consumed success: the readiness
    seam calls this only on a successful handling path. An already-consumed or exhausted lease fails
    closed with NO state change and NO new audit event.
    """
    if row.status != ResolutionLeaseStatus.active:
        raise PlanSecretLeaseRefused(
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
        raise PlanSecretLeaseRefused(ResolutionLeaseReason.lease_held)
    _audit(session, row, AuditAction.resolution_lease_consumed)
    return row
