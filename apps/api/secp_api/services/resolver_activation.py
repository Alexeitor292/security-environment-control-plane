"""App-owned durable resolver-activation authorization lifecycle (SECP-B2-4.1).

This is the SEPARATE, explicit, time-bounded, audited, revocable authorization that must exist —
and be independently re-verified by the worker — before a future isolated-staging OpenBao
activation can be considered. It grants NO infrastructure execution, resolves NO secret, contacts
NO backend, and is NEVER auto-created from a ``LiveReadAuthorization`` approval or a staging-lab
approval. Approval requires a DEDICATED permission and a complete, closed evidence set; nothing here
can arm a resolver.

Closed lifecycle: draft → approved → revoked / expired. Only closed error codes are surfaced.
"""

from __future__ import annotations

import functools
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    LiveReadAuthorizationStatus,
    Permission,
    ReadonlyPreflightStatus,
    ResolverActivationErrorCode,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    ResolverActivationStatus,
)
from secp_api.errors import AuthorizationError, DomainError, NotFoundError, ResolverActivationError
from secp_api.models import (
    LiveReadAuthorization,
    ReadonlyStagingPreflight,
    ResolverActivationAuthorization,
    ResolverActivationEvidence,
)
from secp_api.resolver_activation_contract import (
    RESOLVER_ACTIVATION_PURPOSE,
    RESOLVER_ADAPTER_CONTRACT_VERSION,
    EvidenceMetadataError,
    compute_evidence_fingerprint,
    compute_operation_fingerprint,
    evidence_is_complete,
    validate_evidence_metadata,
)

_Code = ResolverActivationErrorCode
_DEFAULT_TTL_SECONDS = 3600
_MAX_TTL_SECONDS = 24 * 3600
# A work item is a valid activation-binding target only while it is live (not terminal).
_ELIGIBLE_PREFLIGHT_STATUSES = frozenset(
    {
        ReadonlyPreflightStatus.queued,
        ReadonlyPreflightStatus.claimed,
        ReadonlyPreflightStatus.running,
    }
)

_T = TypeVar("_T")


def _closed_errors(fn: Callable[..., _T]) -> Callable[..., _T]:
    """Translate every leaking error into a closed :class:`ResolverActivationError` code."""

    @functools.wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> _T:
        try:
            return fn(*args, **kwargs)
        except ResolverActivationError:
            raise
        except AuthorizationError as exc:
            raise ResolverActivationError(_Code.forbidden) from exc
        except NotFoundError as exc:
            raise ResolverActivationError(_Code.not_found) from exc
        except EvidenceMetadataError as exc:
            raise ResolverActivationError(_Code.evidence_invalid) from exc
        except DomainError as exc:
            raise ResolverActivationError(_Code.invalid_state) from exc

    return wrapper


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _get(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> ResolverActivationAuthorization:
    row = session.get(ResolverActivationAuthorization, authorization_id)
    if row is None:
        raise ResolverActivationError(_Code.not_found)
    actor.require_org(row.organization_id)
    return row


def _next_authorization_version(
    session: Session, target_id: uuid.UUID, onboarding_id: uuid.UUID
) -> int:
    current = session.execute(
        select(
            func.coalesce(func.max(ResolverActivationAuthorization.authorization_version), 0)
        ).where(
            ResolverActivationAuthorization.execution_target_id == target_id,
            ResolverActivationAuthorization.onboarding_id == onboarding_id,
        )
    ).scalar_one()
    return int(current) + 1


def _load_eligible_work_item(
    session: Session, actor: Principal, preflight_id: uuid.UUID
) -> tuple[ReadonlyStagingPreflight, LiveReadAuthorization]:
    pf = session.get(ReadonlyStagingPreflight, preflight_id)
    if pf is None:
        raise ResolverActivationError(_Code.not_found)
    actor.require_org(pf.organization_id)
    if pf.status not in _ELIGIBLE_PREFLIGHT_STATUSES:
        raise ResolverActivationError(_Code.substrate_ineligible)
    authorization = session.get(LiveReadAuthorization, pf.live_read_authorization_id)
    if authorization is None:
        raise ResolverActivationError(_Code.not_found)
    # The live-read authorization must itself be approved + current — but its approval NEVER creates
    # or approves THIS record; it is only a precondition for a *draft* to be bindable.
    if authorization.status != LiveReadAuthorizationStatus.approved:
        raise ResolverActivationError(_Code.substrate_ineligible)
    if authorization.authorization_version != pf.authorization_version:
        raise ResolverActivationError(_Code.substrate_ineligible)
    return pf, authorization


@_closed_errors
def create_activation_authorization(
    session: Session,
    actor: Principal,
    *,
    preflight_id: uuid.UUID,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> ResolverActivationAuthorization:
    """Create a DRAFT resolver-activation authorization bound to one exact work item.

    Requires ``resolver_activation:manage``. Every bound fact (org, target, onboarding, live-read
    authorization id + version, purpose, resolver contract version, work-item id, operation
    fingerprint) is derived SERVER-SIDE from the authoritative records — the admin supplies only the
    work-item id + a TTL. It is NEVER auto-created; a distinct explicit call is required.
    """
    actor.require(Permission.resolver_activation_manage)
    pf, authorization = _load_eligible_work_item(session, actor, preflight_id)
    # Fail closed on a stale slot: any active (draft/approved) authorization for this exact work
    # item whose canonical UTC expiry is at/before now must be materialized as ``expired`` (audited
    # once) BEFORE a replacement draft can occupy the single active-preflight slot. Without this, an
    # expired-but-still-``approved`` row keeps occupying the partial-unique slot and every
    # replacement draft would conflict and end as ``lifecycle_conflict``.
    _expire_active_if_due(session, actor, pf.id)
    ttl = max(1, min(int(ttl_seconds), _MAX_TTL_SECONDS))
    fingerprint = compute_operation_fingerprint(pf)
    for _attempt in range(5):
        version = _next_authorization_version(session, pf.execution_target_id, pf.onboarding_id)
        row = ResolverActivationAuthorization(
            organization_id=pf.organization_id,
            execution_target_id=pf.execution_target_id,
            onboarding_id=pf.onboarding_id,
            live_read_authorization_id=pf.live_read_authorization_id,
            live_read_authorization_version=pf.authorization_version,
            preflight_id=pf.id,
            operation_fingerprint=fingerprint,
            resolver_adapter_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            purpose=RESOLVER_ACTIVATION_PURPOSE,
            authorization_expiry=_utcnow() + timedelta(seconds=ttl),
            evidence_fingerprint="",
            status=ResolverActivationStatus.draft,
            authorization_version=version,
            revision=0,
            created_by=actor.user_id,
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            continue
        audit.record(
            session,
            action=AuditAction.resolver_activation_created,
            resource_type="resolver_activation_authorization",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            data=_safe_audit(row),
        )
        return row
    raise ResolverActivationError(_Code.lifecycle_conflict)


@_closed_errors
def record_evidence(
    session: Session,
    actor: Principal,
    authorization_id: uuid.UUID,
    *,
    kind: ResolverActivationEvidenceKind,
    status: ResolverActivationEvidenceStatus,
    proof_id: str,
    issuer: str,
) -> ResolverActivationEvidence:
    """Record/replace one closed, secret-free evidence item on a DRAFT authorization.

    Requires ``resolver_activation:manage``. ``proof_id``/``issuer`` are validated to a safe opaque
    shape (no endpoint/reference/secret/whitespace). Never allowed on a non-draft record.
    """
    actor.require(Permission.resolver_activation_manage)
    row = _get(session, actor, authorization_id)
    if row.status != ResolverActivationStatus.draft:
        raise ResolverActivationError(_Code.invalid_state)
    validate_evidence_metadata(proof_id=proof_id, issuer=issuer)
    existing = session.execute(
        select(ResolverActivationEvidence).where(
            ResolverActivationEvidence.authorization_id == row.id,
            ResolverActivationEvidence.kind == kind,
        )
    ).scalar_one_or_none()
    verified_at = _utcnow() if status == ResolverActivationEvidenceStatus.verified else None
    if existing is None:
        existing = ResolverActivationEvidence(
            authorization_id=row.id,
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
        action=AuditAction.resolver_activation_evidence_recorded,
        resource_type="resolver_activation_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data={**_safe_audit(row), "evidence_kind": kind.value, "evidence_status": status.value},
    )
    return existing


@_closed_errors
def approve_activation_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> ResolverActivationAuthorization:
    """Approve a DRAFT authorization against a COMPLETE evidence set (SEPARATE permission).

    Requires the dedicated ``resolver_activation:approve`` permission — it CANNOT be inferred from
    onboarding, staging-lab, live-read, or any other approval. Approval binds the complete evidence
    fingerprint; a compare-and-swap on ``revision`` makes concurrent approve/revoke safe.
    """
    actor.require(Permission.resolver_activation_approve)
    row = _get(session, actor, authorization_id)
    if row.status != ResolverActivationStatus.draft:
        raise ResolverActivationError(_Code.invalid_state)
    if _is_expired(row):
        # Approve fails closed once expired; the transition is materialized + audited (once).
        _mark_expired(session, row, actor)
        raise ResolverActivationError(_Code.invalid_state)
    evidence = _evidence_rows(session, row.id)
    if not evidence_is_complete(evidence):
        raise ResolverActivationError(_Code.evidence_incomplete)
    fingerprint = compute_evidence_fingerprint(evidence)
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "status": ResolverActivationStatus.approved,
            "evidence_fingerprint": fingerprint,
            "approved_by": actor.user_id,
            "approved_at": _utcnow(),
        },
    ):
        raise ResolverActivationError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.resolver_activation_approved,
        resource_type="resolver_activation_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(row),
    )
    return row


@_closed_errors
def revoke_activation_authorization(
    session: Session,
    actor: Principal,
    authorization_id: uuid.UUID,
    reason_code: str = "operator",
) -> ResolverActivationAuthorization:
    """Immediately revoke a draft/approved authorization (approval facts preserved), audited."""
    actor.require(Permission.resolver_activation_manage)
    row = _get(session, actor, authorization_id)
    if row.status not in (ResolverActivationStatus.draft, ResolverActivationStatus.approved):
        raise ResolverActivationError(_Code.invalid_state)
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "status": ResolverActivationStatus.revoked,
            "revoked_by": actor.user_id,
            "revoked_at": _utcnow(),
            "revocation_reason_code": _safe_reason_code(reason_code),
        },
    ):
        raise ResolverActivationError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.resolver_activation_revoked,
        resource_type="resolver_activation_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        outcome="revoked",
        data={**_safe_audit(row), "reason_code": row.revocation_reason_code},
    )
    return row


@_closed_errors
def get_activation_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> ResolverActivationAuthorization:
    return _get(session, actor, authorization_id)


@_closed_errors
def list_activation_authorizations(
    session: Session, actor: Principal, *, execution_target_id: uuid.UUID
) -> list[ResolverActivationAuthorization]:
    return list(
        session.execute(
            select(ResolverActivationAuthorization)
            .where(
                ResolverActivationAuthorization.organization_id == actor.organization_id,
                ResolverActivationAuthorization.execution_target_id == execution_target_id,
            )
            .order_by(ResolverActivationAuthorization.created_at.desc())
        )
        .scalars()
        .all()
    )


def _evidence_rows(
    session: Session, authorization_id: uuid.UUID
) -> list[ResolverActivationEvidence]:
    return list(
        session.execute(
            select(ResolverActivationEvidence)
            .where(ResolverActivationEvidence.authorization_id == authorization_id)
            .order_by(ResolverActivationEvidence.kind)
        )
        .scalars()
        .all()
    )


def _cas(
    session: Session,
    row: ResolverActivationAuthorization,
    *,
    expected_revision: int,
    values: dict,
) -> bool:
    from sqlalchemy import update

    result = session.execute(
        update(ResolverActivationAuthorization)
        .where(
            ResolverActivationAuthorization.id == row.id,
            ResolverActivationAuthorization.revision == expected_revision,
        )
        .values(revision=expected_revision + 1, **values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _is_expired(row: ResolverActivationAuthorization) -> bool:
    expiry = row.authorization_expiry
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return expiry <= _utcnow()


def _mark_expired(
    session: Session,
    row: ResolverActivationAuthorization,
    actor: Principal | None = None,
) -> bool:
    """Materialize an expired draft/approved authorization as ``expired`` (revision-safe CAS).

    Returns ``True`` iff *this* caller won the transition. Only ``status`` moves to ``expired``; the
    approval facts, evidence fingerprint, approver, revocation facts, and audit history are never
    revived, reused, overwritten, or mutated. Exactly one immutable, secret-free expiration audit
    event is recorded, and ONLY by the CAS winner, so a concurrent loser (whose CAS matches zero
    rows) can never emit a duplicate.
    """
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={"status": ResolverActivationStatus.expired},
    ):
        return False
    audit.record(
        session,
        action=AuditAction.resolver_activation_expired,
        resource_type="resolver_activation_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id) if actor is not None else "system",
        outcome="expired",
        data=_safe_audit(row),
    )
    return True


def _expire_active_if_due(session: Session, actor: Principal, preflight_id: uuid.UUID) -> None:
    """Atomically identify and materialize any active (draft/approved) authorization for one work
    item whose canonical UTC expiry is at/before now.

    The partial unique index ``uq_resolver_activation_active_operation`` guarantees at most one
    active authorization per work item, so at most one row is transitioned. A still-valid active
    authorization is left untouched (a genuine replacement conflict is still surfaced downstream).
    """
    row = session.execute(
        select(ResolverActivationAuthorization).where(
            ResolverActivationAuthorization.preflight_id == preflight_id,
            ResolverActivationAuthorization.status.in_(
                (ResolverActivationStatus.draft, ResolverActivationStatus.approved)
            ),
        )
    ).scalar_one_or_none()
    if row is not None and _is_expired(row):
        _mark_expired(session, row, actor)


def _safe_reason_code(reason_code: str) -> str:
    code = str(reason_code or "operator").strip().lower()[:80]
    return code if code.replace("_", "").replace("-", "").isalnum() else "operator"


def _safe_audit(row: ResolverActivationAuthorization, **extra: object) -> dict:
    payload: dict[str, object] = {
        "execution_target_id": str(row.execution_target_id),
        "onboarding_id": str(row.onboarding_id),
        "live_read_authorization_id": str(row.live_read_authorization_id),
        "live_read_authorization_version": row.live_read_authorization_version,
        "preflight_id": str(row.preflight_id),
        "operation_fingerprint": row.operation_fingerprint,
        "resolver_adapter_contract_version": row.resolver_adapter_contract_version,
        "purpose": row.purpose,
        "status": row.status.value,
        "authorization_version": row.authorization_version,
        "revision": row.revision,
    }
    if row.evidence_fingerprint:
        payload["evidence_fingerprint"] = row.evidence_fingerprint
    payload.update(extra)
    return payload
