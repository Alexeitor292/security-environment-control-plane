"""App-owned read-only staging-preflight services (SECP-B2-0).

Control-plane only. The API lets an authorized admin (a) create+approve a short-lived live-read
authorization bound to an eligible Proxmox staging substrate, and (b) enqueue a durable read-only
preflight intent. The API NEVER executes collection: it only commits queued intent. It imports no
worker/plugin/transport/collector/HTTP code, resolves no secret, and contacts nothing.

A preflight authorization is created here explicitly and is separate from staging-lab approval. A
staging-lab plan or approval never creates or substitutes a live-read authorization.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    LiveReadAuthorizationStatus,
    Permission,
    ReadonlyPreflightStatus,
    StagingSubstrateEligibilityStatus,
    TargetStatus,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LIVE_READ_PLUGIN_NAME,
    LIVE_VERIFIED_LEVEL,
    PROXMOX_READONLY_POLICY_VERSION,
    connection_identity_hash,
)
from secp_api.models import (
    ExecutionTarget,
    LiveReadAuthorization,
    ReadonlyStagingPreflight,
    StagingSubstrateEligibility,
    TargetOnboarding,
)
from secp_api.services import live_authorizations

# Short-lived by construction: an admin-requested preflight authorization is time-bounded.
_DEFAULT_TTL_SECONDS = 900
_MAX_TTL_SECONDS = 3600


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _active_eligibility(
    session: Session, target_id: uuid.UUID
) -> StagingSubstrateEligibility | None:
    return (
        session.execute(
            select(StagingSubstrateEligibility).where(
                StagingSubstrateEligibility.execution_target_id == target_id,
                StagingSubstrateEligibility.status == StagingSubstrateEligibilityStatus.active,
            )
        )
        .scalars()
        .first()
    )


def _eligible_substrate(
    session: Session, actor: Principal, target_id: uuid.UUID
) -> tuple[ExecutionTarget, TargetOnboarding]:
    """Return (target, single active onboarding) iff the target is an eligible Proxmox substrate.

    Independent enforcement (not UI-only): same org, active, Proxmox, active staging eligibility,
    and exactly one active onboarding.
    """
    from secp_api.services.onboarding import active_onboarding_for_target

    target = session.get(ExecutionTarget, target_id)
    if target is None:
        raise NotFoundError(f"execution target {target_id} not found")
    actor.require_org(target.organization_id)
    if target.status != TargetStatus.active:
        raise DomainError("execution target is not active")
    if target.plugin_name != LIVE_READ_PLUGIN_NAME:
        raise DomainError("only proxmox targets support a read-only staging preflight")
    if _active_eligibility(session, target.id) is None:
        raise DomainError("execution target is not an eligible staging substrate")
    onboarding = active_onboarding_for_target(session, target.id)
    if onboarding is None:
        raise DomainError("execution target has no active onboarding")
    return target, onboarding


# --- Live-read authorization (explicit, short-lived; separate from staging-lab approval) -------


def create_preflight_authorization(
    session: Session,
    actor: Principal,
    *,
    execution_target_id: uuid.UUID,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> LiveReadAuthorization:
    """Create a DRAFT short-lived live-read authorization for an eligible substrate.

    Connection and boundary hashes are derived SERVER-SIDE from the authoritative records (the
    admin supplies no hashes, endpoints, or secrets). Requires ``onboarding:approve`` — the same
    authority that governs the live-read authorization contract, deliberately separate from
    ``staging_preflight:manage`` and ``staging_lab:approve``.
    """
    actor.require(Permission.onboarding_approve)
    target, onboarding = _eligible_substrate(session, actor, execution_target_id)
    ttl = max(1, min(int(ttl_seconds), _MAX_TTL_SECONDS))
    return live_authorizations.create_live_read_authorization(
        session,
        actor,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash=connection_identity_hash(target.config or {}),
        boundary_hash=onboarding.boundary_hash,
        authorization_version=1,
        authorization_expiry=_utcnow() + timedelta(seconds=ttl),
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=LIVE_VERIFIED_LEVEL,
    )


def approve_preflight_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> LiveReadAuthorization:
    return live_authorizations.approve_live_read_authorization(session, actor, authorization_id)


def revoke_preflight_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID, reason_code: str = "operator"
) -> LiveReadAuthorization:
    return live_authorizations.revoke_live_read_authorization(
        session, actor, authorization_id, reason_code
    )


def list_preflight_authorizations(
    session: Session, actor: Principal, execution_target_id: uuid.UUID
) -> list[LiveReadAuthorization]:
    target, _ = _eligible_substrate(session, actor, execution_target_id)
    return list(
        session.execute(
            select(LiveReadAuthorization)
            .where(LiveReadAuthorization.execution_target_id == target.id)
            .order_by(LiveReadAuthorization.created_at.desc())
        )
        .scalars()
        .all()
    )


# --- Durable preflight intent (API enqueues; worker executes) ---------------------------------


def _operation_fingerprint(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    onboarding_id: uuid.UUID,
    authorization_id: uuid.UUID,
    authorization_version: int,
) -> str:
    canonical = (
        f"{organization_id}|{target_id}|{onboarding_id}|{authorization_id}|{authorization_version}"
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_audit(pf: ReadonlyStagingPreflight, **extra: object) -> dict:
    payload: dict[str, object] = {
        "execution_target_id": str(pf.execution_target_id),
        "onboarding_id": str(pf.onboarding_id),
        "live_read_authorization_id": str(pf.live_read_authorization_id),
        "authorization_version": pf.authorization_version,
        "status": pf.status.value,
        "revision": pf.revision,
    }
    if pf.outcome_code is not None:
        payload["outcome_code"] = pf.outcome_code.value
    payload.update(extra)
    return payload


def queue_preflight(
    session: Session,
    actor: Principal,
    *,
    live_read_authorization_id: uuid.UUID,
) -> ReadonlyStagingPreflight:
    """Enqueue a durable read-only preflight intent bound to an approved authorization.

    The API only commits ``queued`` intent — it never executes collection. Requires
    ``staging_preflight:manage``. The target/onboarding are derived from the authorization; the
    substrate eligibility is independently re-checked. Idempotent by a server-generated fingerprint
    over (org, target, onboarding, authorization, version): a retry resolves to the original.
    """
    actor.require(Permission.staging_preflight_manage)
    authorization = session.get(LiveReadAuthorization, live_read_authorization_id)
    if authorization is None:
        raise NotFoundError(f"live-read authorization {live_read_authorization_id} not found")
    actor.require_org(authorization.organization_id)
    # Independent substrate eligibility re-check (derives target + single active onboarding).
    target, onboarding = _eligible_substrate(session, actor, authorization.execution_target_id)
    if authorization.onboarding_id != onboarding.id:
        raise DomainError("authorization is not bound to the substrate's active onboarding")
    # Defense in depth (the worker re-verifies authoritatively before any secret/transport step).
    if authorization.status != LiveReadAuthorizationStatus.approved:
        raise DomainError("live-read authorization is not approved")

    fingerprint = _operation_fingerprint(
        authorization.organization_id,
        target.id,
        onboarding.id,
        authorization.id,
        authorization.authorization_version,
    )
    existing = (
        session.execute(
            select(ReadonlyStagingPreflight).where(
                ReadonlyStagingPreflight.operation_fingerprint == fingerprint
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return existing  # idempotent replay of the identical (target, onboarding, authorization)

    preflight = ReadonlyStagingPreflight(
        organization_id=authorization.organization_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        live_read_authorization_id=authorization.id,
        authorization_version=authorization.authorization_version,
        collector_contract_version=authorization.collector_contract_version,
        endpoint_allowlist_version=authorization.endpoint_allowlist_version,
        operation_fingerprint=fingerprint,
        status=ReadonlyPreflightStatus.queued,
        revision=0,
        created_by=actor.user_id,
    )
    session.add(preflight)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DomainError(
            "an active read-only preflight already exists for this authorization"
        ) from exc
    audit.record(
        session,
        action=AuditAction.readonly_preflight_queued,
        resource_type="readonly_staging_preflight",
        resource_id=preflight.id,
        organization_id=preflight.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(preflight),
    )
    return preflight


def get_preflight(
    session: Session, actor: Principal, preflight_id: uuid.UUID
) -> ReadonlyStagingPreflight:
    pf = session.get(ReadonlyStagingPreflight, preflight_id)
    if pf is None:
        raise NotFoundError(f"read-only preflight {preflight_id} not found")
    actor.require_org(pf.organization_id)
    return pf


def list_preflights(
    session: Session, actor: Principal, execution_target_id: uuid.UUID
) -> list[ReadonlyStagingPreflight]:
    target, _ = _eligible_substrate(session, actor, execution_target_id)
    return list(
        session.execute(
            select(ReadonlyStagingPreflight)
            .where(ReadonlyStagingPreflight.execution_target_id == target.id)
            .order_by(ReadonlyStagingPreflight.created_at.desc())
        )
        .scalars()
        .all()
    )
