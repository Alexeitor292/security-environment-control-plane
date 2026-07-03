"""Durable live-read authorization lifecycle services (SECP-002B-1B-6).

This module records a secret-free authorization contract and its audit trail. It does not
wire activation, dispatch workers, resolve secrets, construct transports, or collect evidence.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, LiveReadAuthorizationStatus, Permission
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import ExecutionTarget, LiveReadAuthorization, TargetOnboarding

_SAFE_REASON_RE = re.compile(r"^[a-z0-9_.-]{1,80}$")


def _safe_reason_code(reason_code: str) -> str:
    candidate = str(reason_code or "").strip().lower()
    if _SAFE_REASON_RE.fullmatch(candidate):
        return candidate
    return "unspecified"


def _audit_payload(authorization: LiveReadAuthorization, *, reason_code: str | None = None) -> dict:
    payload = {
        "execution_target_id": str(authorization.execution_target_id),
        "onboarding_id": str(authorization.onboarding_id),
        "status": authorization.status.value,
        "authorization_version": authorization.authorization_version,
        "connection_hash": authorization.connection_hash,
        "boundary_hash": authorization.boundary_hash,
        "collector_contract_version": authorization.collector_contract_version,
        "endpoint_allowlist_version": authorization.endpoint_allowlist_version,
        "evidence_source": authorization.evidence_source,
        "verification_level": authorization.verification_level,
    }
    if reason_code is not None:
        payload["reason_code"] = _safe_reason_code(reason_code)
    return payload


def _get_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> LiveReadAuthorization:
    authorization = session.get(LiveReadAuthorization, authorization_id)
    if authorization is None:
        raise NotFoundError(f"live-read authorization {authorization_id} not found")
    actor.require_org(authorization.organization_id)
    return authorization


def create_live_read_authorization(
    session: Session,
    actor: Principal,
    *,
    execution_target_id: uuid.UUID,
    onboarding_id: uuid.UUID,
    connection_hash: str,
    boundary_hash: str,
    authorization_version: int,
    authorization_expiry: datetime,
    collector_contract_version: str,
    endpoint_allowlist_version: str,
    evidence_source: str,
    verification_level: str,
) -> LiveReadAuthorization:
    """Create a draft authorization contract bound to existing authoritative records."""
    actor.require(Permission.onboarding_approve)
    target = session.get(ExecutionTarget, execution_target_id)
    onboarding = session.get(TargetOnboarding, onboarding_id)
    if target is None:
        raise NotFoundError(f"execution target {execution_target_id} not found")
    if onboarding is None:
        raise NotFoundError(f"target onboarding {onboarding_id} not found")
    actor.require_org(target.organization_id)
    actor.require_org(onboarding.organization_id)
    if target.organization_id != onboarding.organization_id:
        raise DomainError("target and onboarding organizations do not match")
    if onboarding.execution_target_id != target.id:
        raise DomainError("onboarding does not belong to the execution target")
    if authorization_version < 1:
        raise DomainError("authorization_version must be positive")

    authorization = LiveReadAuthorization(
        organization_id=target.organization_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash=connection_hash,
        boundary_hash=boundary_hash,
        authorization_version=authorization_version,
        authorization_expiry=authorization_expiry,
        collector_contract_version=collector_contract_version,
        endpoint_allowlist_version=endpoint_allowlist_version,
        evidence_source=evidence_source,
        verification_level=verification_level,
        status=LiveReadAuthorizationStatus.draft,
        created_by=actor.user_id,
        revocation_reason_code="",
    )
    session.add(authorization)
    session.flush()
    audit.record(
        session,
        action=AuditAction.live_read_authorization_created,
        resource_type="live_read_authorization",
        resource_id=authorization.id,
        organization_id=authorization.organization_id,
        actor=str(actor.user_id),
        data=_audit_payload(authorization),
    )
    return authorization


def approve_live_read_authorization(
    session: Session,
    actor: Principal,
    authorization_id: uuid.UUID,
) -> LiveReadAuthorization:
    """Approve a draft authorization contract without enabling collection."""
    actor.require(Permission.onboarding_approve)
    authorization = _get_authorization(session, actor, authorization_id)
    if authorization.status != LiveReadAuthorizationStatus.draft:
        raise DomainError(
            "live-read authorization is not draft; only draft authorizations can be approved"
        )
    authorization.status = LiveReadAuthorizationStatus.approved
    authorization.approved_by = actor.user_id
    authorization.approved_at = datetime.now(UTC)
    audit.record(
        session,
        action=AuditAction.live_read_authorization_approved,
        resource_type="live_read_authorization",
        resource_id=authorization.id,
        organization_id=authorization.organization_id,
        actor=str(actor.user_id),
        data=_audit_payload(authorization),
    )
    session.flush()
    return authorization


def revoke_live_read_authorization(
    session: Session,
    actor: Principal,
    authorization_id: uuid.UUID,
    reason_code: str,
) -> LiveReadAuthorization:
    """Revoke an approved authorization while preserving approval facts."""
    actor.require(Permission.onboarding_approve)
    authorization = _get_authorization(session, actor, authorization_id)
    if authorization.status != LiveReadAuthorizationStatus.approved:
        raise DomainError(
            "live-read authorization is not approved; only approved authorizations can be revoked"
        )
    authorization.status = LiveReadAuthorizationStatus.revoked
    authorization.revoked_by = actor.user_id
    authorization.revoked_at = datetime.now(UTC)
    authorization.revocation_reason_code = _safe_reason_code(reason_code)
    audit.record(
        session,
        action=AuditAction.live_read_authorization_revoked,
        resource_type="live_read_authorization",
        resource_id=authorization.id,
        organization_id=authorization.organization_id,
        actor=str(actor.user_id),
        outcome="revoked",
        data=_audit_payload(authorization, reason_code=authorization.revocation_reason_code),
    )
    session.flush()
    return authorization


def record_live_read_authorization_validation_refused(
    session: Session,
    *,
    organization_id: uuid.UUID,
    actor: str = "worker",
    authorization_id: uuid.UUID | None = None,
    execution_target_id: uuid.UUID | None = None,
    onboarding_id: uuid.UUID | None = None,
    authorization_version: int | None = None,
    reason_code: str,
) -> None:
    """Append a secret-free refusal audit event for the future verifier seam."""
    data: dict[str, object] = {
        "reason_code": _safe_reason_code(reason_code),
        "status": "refused",
    }
    if execution_target_id is not None:
        data["execution_target_id"] = str(execution_target_id)
    if onboarding_id is not None:
        data["onboarding_id"] = str(onboarding_id)
    if authorization_version is not None:
        data["authorization_version"] = authorization_version
    audit.record(
        session,
        action=AuditAction.live_read_authorization_validation_refused,
        resource_type="live_read_authorization",
        resource_id=authorization_id,
        organization_id=organization_id,
        actor=actor,
        outcome="denied",
        data=data,
    )
