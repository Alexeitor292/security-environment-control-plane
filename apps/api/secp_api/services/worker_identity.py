"""App-owned durable worker-identity registration lifecycle (SECP-B2-4.3).

This is the SEPARATE, explicit, time-bounded, audited, revocable trust anchor that must exist — and
be independently re-verified by a worker — before a future isolated staging worker can be trusted.
It authenticates NO worker, performs NO mTLS, accesses NO certificate/key/CSR/CA, contacts NO
backend, and enables NO runtime path. Approval requires a DEDICATED permission and a complete,
closed evidence set; nothing here can make a worker trusted at runtime.

Closed lifecycle: draft -> approved -> revoked / expired. Only closed error codes are surfaced.
"""

from __future__ import annotations

import functools
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    Permission,
    WorkerIdentityErrorCode,
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
)
from secp_api.errors import AuthorizationError, DomainError, NotFoundError, WorkerIdentityError
from secp_api.models import WorkerIdentityEvidence, WorkerIdentityRegistration
from secp_api.worker_identity_contract import (
    WORKER_IDENTITY_CONTRACT_VERSION,
    WorkerIdentityMetadataError,
    compute_worker_identity_evidence_fingerprint,
    validate_deployment_binding,
    validate_evidence_metadata,
    validate_identity_label,
    validate_verification_anchor_fingerprint,
    worker_identity_evidence_is_complete,
)

_Code = WorkerIdentityErrorCode
_DEFAULT_TTL_SECONDS = 3600
_MAX_TTL_SECONDS = 24 * 3600

_T = TypeVar("_T")


def _closed_errors(fn: Callable[..., _T]) -> Callable[..., _T]:
    """Translate every leaking error into a closed :class:`WorkerIdentityError` code."""

    @functools.wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> _T:
        try:
            return fn(*args, **kwargs)
        except WorkerIdentityError:
            raise
        except AuthorizationError as exc:
            raise WorkerIdentityError(_Code.forbidden) from exc
        except NotFoundError as exc:
            raise WorkerIdentityError(_Code.not_found) from exc
        except WorkerIdentityMetadataError as exc:
            raise WorkerIdentityError(_Code.invalid_metadata) from exc
        except DomainError as exc:
            raise WorkerIdentityError(_Code.invalid_state) from exc

    return wrapper


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _get(
    session: Session, actor: Principal, registration_id: uuid.UUID
) -> WorkerIdentityRegistration:
    row = session.get(WorkerIdentityRegistration, registration_id)
    if row is None:
        raise WorkerIdentityError(_Code.not_found)
    actor.require_org(row.organization_id)
    return row


def _next_identity_version(
    session: Session, organization_id: uuid.UUID, identity_label: str
) -> int:
    current = session.execute(
        select(func.coalesce(func.max(WorkerIdentityRegistration.identity_version), 0)).where(
            WorkerIdentityRegistration.organization_id == organization_id,
            WorkerIdentityRegistration.identity_label == identity_label,
        )
    ).scalar_one()
    return int(current) + 1


def _anchor_savepoint_to_request_transaction(session: Session) -> None:
    """Keep the retry savepoint inside SQLite's real request transaction.

    Python 3.11's sqlite3 driver uses legacy transaction control: a preceding SELECT does not emit
    ``BEGIN``, so the first SAVEPOINT can otherwise become the database's top-level transaction.
    Releasing that savepoint would make a newly inserted registration survive a later request
    rollback. An empty DML statement starts the physical transaction without changing a row.
    PostgreSQL already starts its transaction for the locking reads and needs no workaround.
    """
    if session.get_bind().dialect.name == "sqlite":
        session.execute(
            update(WorkerIdentityRegistration)
            .where(WorkerIdentityRegistration.id.is_(None))
            .values(revision=WorkerIdentityRegistration.revision)
        )


@_closed_errors
def register_worker_identity(
    session: Session,
    actor: Principal,
    *,
    mechanism: WorkerIdentityMechanism,
    identity_label: str,
    deployment_binding: str,
    verification_anchor_fingerprint: str,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> WorkerIdentityRegistration:
    """Register a DRAFT worker-identity trust anchor bound to one org + opaque identity label.

    Requires ``worker_identity:manage``. Every value is grammar-validated to a safe opaque shape (no
    certificate/key/CSR/CA/endpoint/reference/secret). The organization + monotonic version are
    derived SERVER-SIDE. It is NEVER auto-created; a distinct explicit call is required, and makes
    no worker trusted at runtime.
    """
    actor.require(Permission.worker_identity_manage)
    validate_identity_label(identity_label)
    validate_deployment_binding(deployment_binding)
    validate_verification_anchor_fingerprint(verification_anchor_fingerprint)
    # Fail closed on a stale slot: an active (draft/approved) registration for this (org, label)
    # past its canonical UTC expiry is materialized as ``expired`` (audited once) BEFORE a
    # replacement draft can occupy the single active slot enforced by the partial unique index.
    _expire_active_if_due(session, actor, actor.organization_id, identity_label)
    _anchor_savepoint_to_request_transaction(session)
    ttl = max(1, min(int(ttl_seconds), _MAX_TTL_SECONDS))
    for _attempt in range(5):
        version = _next_identity_version(session, actor.organization_id, identity_label)
        row = WorkerIdentityRegistration(
            organization_id=actor.organization_id,
            mechanism=mechanism,
            identity_label=identity_label,
            deployment_binding=deployment_binding,
            verification_anchor_fingerprint=verification_anchor_fingerprint,
            identity_version=version,
            expiry=_utcnow() + timedelta(seconds=ttl),
            evidence_fingerprint="",
            status=WorkerIdentityStatus.draft,
            revision=0,
            created_by=actor.user_id,
        )
        try:
            # Keep the caller's outer transaction and row locks intact. A full session.rollback()
            # here would release the composite worker-node review lock and permit a stale review to
            # survive a version-insert race.
            with session.begin_nested():
                session.add(row)
                session.flush()
        except IntegrityError:
            continue
        audit.record(
            session,
            action=AuditAction.worker_identity_registered,
            resource_type="worker_identity_registration",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            data=_safe_audit(row),
        )
        return row
    raise WorkerIdentityError(_Code.lifecycle_conflict)


@_closed_errors
def record_evidence(
    session: Session,
    actor: Principal,
    registration_id: uuid.UUID,
    *,
    kind: WorkerIdentityEvidenceKind,
    status: WorkerIdentityEvidenceStatus,
    proof_id: str,
    issuer: str,
) -> WorkerIdentityEvidence:
    """Record/replace one closed, secret-free evidence item on a DRAFT registration.

    Requires ``worker_identity:manage``. ``proof_id``/``issuer`` are validated to a safe opaque
    shape (no certificate/key/endpoint/reference/secret). Never allowed on a non-draft record.
    """
    actor.require(Permission.worker_identity_manage)
    row = _get(session, actor, registration_id)
    if row.status != WorkerIdentityStatus.draft:
        raise WorkerIdentityError(_Code.invalid_state)
    validate_evidence_metadata(proof_id=proof_id, issuer=issuer)
    existing = session.execute(
        select(WorkerIdentityEvidence).where(
            WorkerIdentityEvidence.registration_id == row.id,
            WorkerIdentityEvidence.kind == kind,
        )
    ).scalar_one_or_none()
    verified_at = _utcnow() if status == WorkerIdentityEvidenceStatus.verified else None
    if existing is None:
        existing = WorkerIdentityEvidence(
            registration_id=row.id,
            kind=kind,
            status=status,
            proof_id=proof_id,
            issuer=issuer,
            verified_at=verified_at,
        )
        session.add(existing)
    else:
        existing.status = status
        existing.proof_id = proof_id
        existing.issuer = issuer
        existing.verified_at = verified_at
    session.flush()
    audit.record(
        session,
        action=AuditAction.worker_identity_evidence_recorded,
        resource_type="worker_identity_registration",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data={**_safe_audit(row), "evidence_kind": kind.value, "evidence_status": status.value},
    )
    return existing


@_closed_errors
def approve_worker_identity(
    session: Session, actor: Principal, registration_id: uuid.UUID
) -> WorkerIdentityRegistration:
    """Approve a DRAFT registration against a COMPLETE evidence set (SEPARATE permission).

    Requires the dedicated ``worker_identity:approve`` permission — it CANNOT be inferred from
    ``worker_identity:manage`` or any other approval. Approval binds the complete evidence
    fingerprint; a compare-and-swap on ``revision`` makes concurrent approve/revoke safe.
    """
    actor.require(Permission.worker_identity_approve)
    row = _get(session, actor, registration_id)
    if row.status != WorkerIdentityStatus.draft:
        raise WorkerIdentityError(_Code.invalid_state)
    if _is_expired(row):
        # Approve fails closed once expired; the transition is materialized + audited (once). Flag
        # the refusal as carrying a durable transition so the HTTP layer commits it (only when THIS
        # caller won the CAS) instead of rolling it back.
        won = _mark_expired(session, row, actor)
        err = WorkerIdentityError(_Code.invalid_state)
        err.durable_transition = won
        raise err
    evidence = _evidence_rows(session, row.id)
    if not worker_identity_evidence_is_complete(evidence):
        raise WorkerIdentityError(_Code.evidence_incomplete)
    fingerprint = compute_worker_identity_evidence_fingerprint(evidence)
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "status": WorkerIdentityStatus.approved,
            "evidence_fingerprint": fingerprint,
            "approved_by": actor.user_id,
            "approved_at": _utcnow(),
        },
    ):
        raise WorkerIdentityError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.worker_identity_approved,
        resource_type="worker_identity_registration",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(row),
    )
    return row


@_closed_errors
def revoke_worker_identity(
    session: Session,
    actor: Principal,
    registration_id: uuid.UUID,
    reason_code: str = "operator",
) -> WorkerIdentityRegistration:
    """Immediately revoke a draft/approved registration (approval facts preserved), audited."""
    actor.require(Permission.worker_identity_manage)
    row = _get(session, actor, registration_id)
    if row.status not in (WorkerIdentityStatus.draft, WorkerIdentityStatus.approved):
        raise WorkerIdentityError(_Code.invalid_state)
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "status": WorkerIdentityStatus.revoked,
            "revoked_by": actor.user_id,
            "revoked_at": _utcnow(),
            "revocation_reason_code": _safe_reason_code(reason_code),
        },
    ):
        raise WorkerIdentityError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.worker_identity_revoked,
        resource_type="worker_identity_registration",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        outcome="revoked",
        data={**_safe_audit(row), "reason_code": row.revocation_reason_code},
    )
    return row


@_closed_errors
def get_worker_identity(
    session: Session, actor: Principal, registration_id: uuid.UUID
) -> WorkerIdentityRegistration:
    return _get(session, actor, registration_id)


@_closed_errors
def list_worker_identities(session: Session, actor: Principal) -> list[WorkerIdentityRegistration]:
    return list(
        session.execute(
            select(WorkerIdentityRegistration)
            .where(WorkerIdentityRegistration.organization_id == actor.organization_id)
            .order_by(WorkerIdentityRegistration.created_at.desc())
        )
        .scalars()
        .all()
    )


def _evidence_rows(session: Session, registration_id: uuid.UUID) -> list[WorkerIdentityEvidence]:
    return list(
        session.execute(
            select(WorkerIdentityEvidence)
            .where(WorkerIdentityEvidence.registration_id == registration_id)
            .order_by(WorkerIdentityEvidence.kind)
        )
        .scalars()
        .all()
    )


def _cas(
    session: Session,
    row: WorkerIdentityRegistration,
    *,
    expected_revision: int,
    values: dict,
) -> bool:
    result = session.execute(
        update(WorkerIdentityRegistration)
        .where(
            WorkerIdentityRegistration.id == row.id,
            WorkerIdentityRegistration.revision == expected_revision,
        )
        .values(revision=expected_revision + 1, **values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _is_expired(row: WorkerIdentityRegistration) -> bool:
    expiry = row.expiry
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return expiry <= _utcnow()


def _mark_expired(
    session: Session,
    row: WorkerIdentityRegistration,
    actor: Principal | None = None,
) -> bool:
    """Materialize an expired draft/approved registration as ``expired`` (revision-safe CAS).

    Returns ``True`` iff *this* caller won the transition. Only ``status`` moves to ``expired``; the
    approval facts, evidence fingerprint, approver, revocation facts, and audit history are never
    revived, reused, overwritten, or mutated. Exactly one immutable, secret-free expiration audit
    event is recorded, and ONLY by the CAS winner.
    """
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={"status": WorkerIdentityStatus.expired},
    ):
        return False
    audit.record(
        session,
        action=AuditAction.worker_identity_expired,
        resource_type="worker_identity_registration",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id) if actor is not None else "system",
        outcome="expired",
        data=_safe_audit(row),
    )
    return True


def _expire_active_if_due(
    session: Session, actor: Principal, organization_id: uuid.UUID, identity_label: str
) -> None:
    """Materialize any active (draft/approved) registration for one (org, identity label) whose
    canonical UTC expiry is at/before now. The partial unique index ``uq_worker_identity_active``
    guarantees at most one active row, so at most one is transitioned; a still-valid active
    registration is left untouched (a genuine replacement conflict is surfaced downstream)."""
    row = session.execute(
        select(WorkerIdentityRegistration).where(
            WorkerIdentityRegistration.organization_id == organization_id,
            WorkerIdentityRegistration.identity_label == identity_label,
            WorkerIdentityRegistration.status.in_(
                (WorkerIdentityStatus.draft, WorkerIdentityStatus.approved)
            ),
        )
    ).scalar_one_or_none()
    if row is not None and _is_expired(row):
        _mark_expired(session, row, actor)


def _safe_reason_code(reason_code: str) -> str:
    code = str(reason_code or "operator").strip().lower()[:80]
    return code if code.replace("_", "").replace("-", "").isalnum() else "operator"


def _safe_audit(row: WorkerIdentityRegistration, **extra: object) -> dict:
    payload: dict[str, object] = {
        "mechanism": getattr(row.mechanism, "value", row.mechanism),
        "identity_label": row.identity_label,
        "deployment_binding": row.deployment_binding,
        "verification_anchor_fingerprint": row.verification_anchor_fingerprint,
        "worker_identity_contract_version": WORKER_IDENTITY_CONTRACT_VERSION,
        "identity_version": row.identity_version,
        "status": row.status.value,
        "revision": row.revision,
    }
    if row.evidence_fingerprint:
        payload["evidence_fingerprint"] = row.evidence_fingerprint
    payload.update(extra)
    return payload
