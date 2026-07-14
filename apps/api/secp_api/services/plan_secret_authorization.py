"""App-owned plan-secret readiness authorization lifecycle (B1B-PR4 / ADR-021 §G).

The SEPARATE, explicit, time-bounded, audited, revocable human authorization that must exist — and
be independently re-verified by the worker — before a plan-secret readiness operation may run.

It grants NO infrastructure execution, resolves NO secret, contacts NO backend, constructs NO
resolver, and is NEVER auto-created from a topology approval, an environment publication, a
deployment-plan approval, an onboarding approval, a live-read authorization, eligibility success,
toolchain attestation, or state readiness. **Creating it does not run readiness. Approving it does
not run readiness.** Approval requires a DEDICATED permission (``readiness:approve``) and a
COMPLETE, closed human-review evidence set.

Purpose is server-forced to ``plan_read``. Apply and destroy purposes are unrepresentable and
additionally refused, so no caller can mint an apply/destroy secret authorization.

Closed lifecycle: draft → approved → revoked / expired. Only closed error codes are surfaced; a
rejected value, backend detail, reference, or exception body is never echoed.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
import uuid
from collections.abc import Callable, Iterable
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
    PlanSecretAuthorizationStatus,
    PlanSecretEvidenceKind,
    PlanSecretEvidenceStatus,
    PlanSecretPurpose,
    ReadinessCapabilityClass,
    ReadinessErrorCode,
    ReadinessOperationKind,
)
from secp_api.errors import (
    AuthorizationError,
    DomainError,
    NotFoundError,
    ReadinessError,
)
from secp_api.models import (
    PlanSecretReadinessAuthorization,
    PlanSecretReadinessEvidence,
    ProvisioningManifest,
)
from secp_api.readiness_binding import load_readiness_binding
from secp_api.readiness_contract import (
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    READINESS_POLICY_VERSION,
    ReadinessBinding,
    as_utc,
    assert_plan_only_purpose,
    canonical_utc,
    is_placeholder_dossier,
)
from secp_api.secret_refs import InvalidSecretRefError, parse_secret_ref

_Code = ReadinessErrorCode
_DEFAULT_TTL_SECONDS = 3600
_MAX_TTL_SECONDS = 24 * 3600

# Every kind must be present and ``verified`` before approval.
REQUIRED_PLAN_SECRET_EVIDENCE_KINDS: frozenset[PlanSecretEvidenceKind] = frozenset(
    PlanSecretEvidenceKind
)

# An opaque, non-sensitive proof identifier / issuer label: letters, digits, dot, underscore, hyphen
# only — no whitespace, slash, ``:``, ``@``, or scheme, so it cannot carry a vault path, URL,
# ``env:``/``vault:`` reference, ``user@host``, or a multi-token secret.
# ``fullmatch`` is used at every call site — NEVER ``match``: Python's ``$`` also matches
# immediately BEFORE a trailing newline, so ``re.match(r"^...$", "ok\n")`` succeeds and a newline
# would reach a bounded column.
_SAFE_METADATA_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")
_SAFE_REASON_RE = re.compile(r"[a-z0-9_]{1,80}")

_T = TypeVar("_T")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _closed_errors(fn: Callable[..., _T]) -> Callable[..., _T]:
    """Map internal exceptions to CLOSED readiness error codes. Never leaks a backend detail."""

    @functools.wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> _T:
        try:
            return fn(*args, **kwargs)
        except ReadinessError:
            raise
        except NotFoundError:
            raise ReadinessError(_Code.not_found) from None
        except AuthorizationError:
            raise ReadinessError(_Code.forbidden) from None
        except DomainError:
            raise ReadinessError(_Code.invalid_state) from None

    return wrapper


def _cas(
    session: Session,
    row: PlanSecretReadinessAuthorization,
    *,
    expected_revision: int,
    values: dict,
) -> bool:
    """Conditional update guarded by (id, revision). Returns True iff exactly one row changed."""
    result = session.execute(
        update(PlanSecretReadinessAuthorization)
        .where(
            PlanSecretReadinessAuthorization.id == row.id,
            PlanSecretReadinessAuthorization.revision == expected_revision,
        )
        .values(revision=expected_revision + 1, **values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _safe_audit(row: PlanSecretReadinessAuthorization) -> dict:
    """Bounded, secret-free audit payload: ids, hashes, versions, bounded categories only.

    It carries NO secret, secret reference, endpoint, backend URL, state key, namespace name, token,
    external response body, exception text, or rejected caller value.
    """
    return {
        "authorization_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "execution_target_id": str(row.execution_target_id),
        "operation_kind": ReadinessOperationKind.plan_secret_readiness.value,
        "secret_purpose": row.purpose,
        "credential_reference_scheme": row.credential_reference_scheme,
        # OPAQUE credential identity. The reference itself, and any hash of it, is NEVER audited.
        "credential_binding_id": str(row.credential_binding_id),
        "credential_binding_version": row.credential_binding_version,
        "toolchain_attestation_id": str(row.toolchain_attestation_id),
        "resolver_contract_version": row.resolver_contract_version,
        "readiness_policy_version": row.readiness_policy_version,
        "authorization_version": row.authorization_version,
        "operation_fingerprint": row.operation_fingerprint,
        "evidence_fingerprint": row.evidence_fingerprint,
        "status": getattr(row.status, "value", row.status),
        "authorization_expiry": as_utc(row.authorization_expiry).isoformat(),
    }


def _get(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> PlanSecretReadinessAuthorization:
    row = session.get(PlanSecretReadinessAuthorization, authorization_id)
    if row is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(row.organization_id)
    return row


def _evidence_rows(
    session: Session, authorization_id: uuid.UUID
) -> list[PlanSecretReadinessEvidence]:
    return list(
        session.execute(
            select(PlanSecretReadinessEvidence).where(
                PlanSecretReadinessEvidence.authorization_id == authorization_id
            )
        )
        .scalars()
        .all()
    )


def compute_plan_secret_evidence_fingerprint(
    items: Iterable[PlanSecretReadinessEvidence],
) -> str:
    """Canonical ``sha256:`` fingerprint over the COMPLETE evidence set (safe metadata only).

    It folds in only closed metadata (kind / status / opaque proof id / issuer / canonical UTC
    verified-at) — never a value that could be sensitive. Approval binds this fingerprint; the
    worker recomputes and compares it, so an evidence item added, removed, or altered after approval
    invalidates the authorization.
    """
    canonical = [
        {
            "kind": _value(e.kind),
            "status": _value(e.status),
            "proof_id": e.proof_id,
            "issuer": e.issuer,
            "verified_at": canonical_utc(e.verified_at),
        }
        for e in sorted(items, key=lambda e: _value(e.kind))
    ]
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def plan_secret_evidence_is_complete(items: Iterable[PlanSecretReadinessEvidence]) -> bool:
    """True iff every required review kind is present with status ``verified``."""
    verified = {
        _value(e.kind) for e in items if _value(e.status) == PlanSecretEvidenceStatus.verified.value
    }
    return {k.value for k in REQUIRED_PLAN_SECRET_EVIDENCE_KINDS} <= verified


def _value(enum_or_str: object) -> str:
    return str(getattr(enum_or_str, "value", enum_or_str))


def _next_authorization_version(session: Session, manifest_id: uuid.UUID) -> int:
    current = session.execute(
        select(func.max(PlanSecretReadinessAuthorization.authorization_version)).where(
            PlanSecretReadinessAuthorization.provisioning_manifest_id == manifest_id
        )
    ).scalar()
    return int(current or 0) + 1


def _credential_reference_scheme(secret_ref: str | None) -> str:
    """The bounded SCHEME of the target's opaque credential reference (never the reference).

    Only the scheme (e.g. ``vault``) is derived and stored — a human reviews it as part of the
    authorization. The reference itself, and any hash of it, is NEVER persisted, audited, logged,
    or returned.
    """
    if not secret_ref:
        raise ReadinessError(_Code.binding_invalid)
    try:
        scheme, _locator = parse_secret_ref(secret_ref)
    except InvalidSecretRefError:
        raise ReadinessError(_Code.binding_invalid) from None
    return scheme


def _expire_active_if_due(session: Session, actor: Principal, manifest_id: uuid.UUID) -> None:
    """Materialize a stale (expired-but-still-active) authorization so the slot frees up."""
    from secp_api.readiness_binding import active_plan_secret_authorization

    row = active_plan_secret_authorization(session, manifest_id)
    if row is None or as_utc(row.authorization_expiry) > _utcnow():
        return
    _mark_expired(session, actor, row)


def _mark_expired(
    session: Session, actor: Principal, row: PlanSecretReadinessAuthorization
) -> bool:
    """CAS-guarded expiry transition. Only the CAS winner emits the audit event."""
    won = _cas(
        session,
        row,
        expected_revision=row.revision,
        values={"status": PlanSecretAuthorizationStatus.expired},
    )
    if won:
        audit.record(
            session,
            action=AuditAction.plan_secret_authorization_expired,
            resource_type="plan_secret_readiness_authorization",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            outcome="expired",
            data=_safe_audit(row),
        )
    return won


@_closed_errors
def create_plan_secret_authorization(
    session: Session,
    actor: Principal,
    *,
    manifest_id: uuid.UUID,
    purpose: str = PlanSecretPurpose.plan_read.value,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> PlanSecretReadinessAuthorization:
    """Create a DRAFT plan-secret readiness authorization bound to one exact manifest.

    Requires ``readiness:manage``. EVERY bound fact — organization, target, onboarding, plan,
    manifest + content hash, toolchain profile + hash, the exact current eligibility evidence, the
    exact current remote-state readiness record + evidence hash, the exact current DURABLE
    toolchain-attestation record + evidence hash, the exact current OPAQUE credential-binding id +
    version, the REVIEWED (non-placeholder) activation-dossier hash, the worker identity + version,
    the resolver contract version, the readiness policy version, and the operation-identity
    fingerprint — is derived SERVER-SIDE from the authoritative records through
    :func:`~secp_api.readiness_binding.load_readiness_binding`. The caller supplies only the
    manifest id, the purpose (which must be ``plan_read``), and a bounded TTL.

    It creates NO readiness evidence, contacts NO secret manager, and constructs NO resolver.
    """
    actor.require(Permission.readiness_manage)
    assert_plan_only_purpose(purpose)

    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(manifest.organization_id)

    _expire_active_if_due(session, actor, manifest.id)

    now = _utcnow()

    # State readiness is a separate, explicit operator action and MUST already be current: a
    # plan-secret authorization can never be created against an unproven state backend. Its record
    # also carries the REVIEWED (non-placeholder) activation-dossier hash the state operation
    # actually ran under, which this authorization INHERITS — the fail-closed placeholder can never
    # be bound (B1B-PR4 §4), and test-only evidence can never authorize anything (§3).
    from secp_api.readiness_binding import current_state_readiness

    state_readiness = current_state_readiness(session, manifest, now=now)
    if state_readiness is None:
        raise ReadinessError(_Code.invalid_state)
    if is_placeholder_dossier(state_readiness.activation_dossier_hash):
        raise ReadinessError(_Code.binding_invalid)
    if state_readiness.capability_class != ReadinessCapabilityClass.controlled_live:
        raise ReadinessError(_Code.binding_invalid)

    # Derive the binding for the REMOTE-STATE operation kind: that yields every shared fact —
    # including the DURABLE toolchain-attestation record and the OPAQUE credential binding — without
    # needing an authorization to already exist.
    result = load_readiness_binding(
        session,
        manifest_id=manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=now,
        activation_dossier_hash=state_readiness.activation_dossier_hash,
    )
    if result.binding is None or result.attestation is None or result.credential_binding is None:
        raise ReadinessError(_Code.binding_invalid)

    target = result.target
    assert target is not None  # noqa: S101 - the binding guarantees it
    scheme = _credential_reference_scheme(target.secret_ref)

    # The operation identity this authorization approves (everything EXCEPT the authorization).
    identity_binding = _plan_secret_identity_binding(result.binding, state_readiness)
    fingerprint = identity_binding.operation_identity_fingerprint()

    ttl = max(1, min(int(ttl_seconds), _MAX_TTL_SECONDS))
    for _attempt in range(5):
        version = _next_authorization_version(session, manifest.id)
        row = PlanSecretReadinessAuthorization(
            organization_id=manifest.organization_id,
            execution_target_id=target.id,
            target_onboarding_id=result.onboarding.id,  # type: ignore[union-attr]
            deployment_plan_id=manifest.deployment_plan_id,
            provisioning_manifest_id=manifest.id,
            toolchain_profile_id=result.toolchain.id,  # type: ignore[union-attr]
            eligibility_preflight_id=result.eligibility_preflight_id,
            remote_state_readiness_id=state_readiness.id,
            toolchain_attestation_id=result.attestation.id,
            credential_binding_id=result.credential_binding.id,
            credential_binding_version=result.credential_binding.binding_version,
            worker_identity_registration_id=result.worker_identity.id,  # type: ignore[union-attr]
            worker_identity_version=result.worker_identity.identity_version,  # type: ignore[union-attr]
            provisioning_manifest_content_hash=manifest.content_hash,
            target_config_hash=target.config_hash,
            onboarding_boundary_hash=result.onboarding.boundary_hash,  # type: ignore[union-attr]
            eligibility_evidence_hash=result.binding.eligibility_evidence_hash,
            toolchain_profile_hash=result.binding.toolchain_profile_hash,
            toolchain_attestation_hash=result.attestation.evidence_hash,
            remote_state_evidence_hash=state_readiness.evidence_hash,
            # The REVIEWED dossier the state-readiness operation ran under — never the placeholder.
            activation_dossier_hash=state_readiness.activation_dossier_hash,
            purpose=PlanSecretPurpose.plan_read.value,
            credential_reference_scheme=scheme,
            resolver_contract_version=PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
            readiness_policy_version=READINESS_POLICY_VERSION,
            operation_fingerprint=fingerprint,
            authorization_expiry=now + timedelta(seconds=ttl),
            evidence_fingerprint="",
            status=PlanSecretAuthorizationStatus.draft,
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
            action=AuditAction.plan_secret_authorization_created,
            resource_type="plan_secret_readiness_authorization",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            data=_safe_audit(row),
        )
        return row
    raise ReadinessError(_Code.lifecycle_conflict)


def _plan_secret_identity_binding(
    shared: ReadinessBinding, state_readiness: object
) -> ReadinessBinding:
    """Re-key a remote-state binding into the plan-secret operation identity binding."""
    from dataclasses import replace

    from secp_api.readiness_binding import PLAN_SECRET_RESOLVER_CONTRACT_VERSION as _rv

    return replace(
        shared,
        operation_kind=ReadinessOperationKind.plan_secret_readiness.value,
        adapter_contract_version=_rv,
        state_readiness_record_id=str(state_readiness.id),  # type: ignore[attr-defined]
        state_readiness_evidence_hash=state_readiness.evidence_hash,  # type: ignore[attr-defined]
    )


@_closed_errors
def record_plan_secret_evidence(
    session: Session,
    actor: Principal,
    authorization_id: uuid.UUID,
    *,
    kind: PlanSecretEvidenceKind,
    status: PlanSecretEvidenceStatus,
    proof_id: str,
    issuer: str,
) -> PlanSecretReadinessEvidence:
    """Record/replace one closed, secret-free human-review evidence item on a DRAFT authorization.

    Requires ``readiness:manage``. ``proof_id``/``issuer`` are validated to a safe opaque shape (no
    endpoint, reference, path, scheme, secret, or whitespace). Never allowed on a non-draft record.
    """
    actor.require(Permission.readiness_manage)
    row = _get(session, actor, authorization_id)
    if row.status != PlanSecretAuthorizationStatus.draft:
        raise ReadinessError(_Code.invalid_state)
    for value in (proof_id, issuer):
        if not (isinstance(value, str) and _SAFE_METADATA_RE.fullmatch(value)):
            raise ReadinessError(_Code.evidence_invalid)

    existing = session.execute(
        select(PlanSecretReadinessEvidence).where(
            PlanSecretReadinessEvidence.authorization_id == row.id,
            PlanSecretReadinessEvidence.kind == kind,
        )
    ).scalar_one_or_none()
    verified_at: datetime | None = (
        _utcnow() if status == PlanSecretEvidenceStatus.verified else None
    )
    if existing is None:
        existing = PlanSecretReadinessEvidence(
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
        action=AuditAction.plan_secret_authorization_evidence,
        resource_type="plan_secret_readiness_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data={**_safe_audit(row), "evidence_kind": kind.value, "evidence_status": status.value},
    )
    return existing


@_closed_errors
def approve_plan_secret_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> PlanSecretReadinessAuthorization:
    """Approve a DRAFT authorization against a COMPLETE review-evidence set (SEPARATE permission).

    Requires the dedicated ``readiness:approve`` permission — it can never be inferred from
    ``readiness:manage``, onboarding approval, live-read approval, resolver-activation approval,
    plan approval, or any other decision. **Approving does not run readiness and resolves no
    secret.** Approval binds the complete evidence fingerprint under a CAS on ``revision``.
    """
    actor.require(Permission.readiness_approve)
    row = _get(session, actor, authorization_id)
    if row.status != PlanSecretAuthorizationStatus.draft:
        raise ReadinessError(_Code.invalid_state)
    assert_plan_only_purpose(row.purpose)
    if as_utc(row.authorization_expiry) <= _utcnow():
        won = _mark_expired(session, actor, row)
        err = ReadinessError(_Code.invalid_state)
        err.durable_transition = won
        raise err
    evidence = _evidence_rows(session, row.id)
    if not plan_secret_evidence_is_complete(evidence):
        raise ReadinessError(_Code.evidence_incomplete)
    fingerprint = compute_plan_secret_evidence_fingerprint(evidence)
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "status": PlanSecretAuthorizationStatus.approved,
            "evidence_fingerprint": fingerprint,
            "approved_by": actor.user_id,
            "approved_at": _utcnow(),
        },
    ):
        raise ReadinessError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.plan_secret_authorized,
        resource_type="plan_secret_readiness_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(row),
    )
    return row


@_closed_errors
def revoke_plan_secret_authorization(
    session: Session,
    actor: Principal,
    authorization_id: uuid.UUID,
    reason_code: str = "operator",
) -> PlanSecretReadinessAuthorization:
    """Immediately revoke a draft/approved authorization. Revocation invalidates all FUTURE use.

    The next readiness attempt (and the next derived current-readiness check) refuses. Historical
    immutable readiness evidence is never mutated or erased.
    """
    actor.require(Permission.readiness_manage)
    row = _get(session, actor, authorization_id)
    if row.status not in (
        PlanSecretAuthorizationStatus.draft,
        PlanSecretAuthorizationStatus.approved,
    ):
        raise ReadinessError(_Code.invalid_state)
    safe_reason = reason_code if _SAFE_REASON_RE.fullmatch(str(reason_code)) else "operator"
    if not _cas(
        session,
        row,
        expected_revision=row.revision,
        values={
            "status": PlanSecretAuthorizationStatus.revoked,
            "revoked_by": actor.user_id,
            "revoked_at": _utcnow(),
            "revocation_reason_code": safe_reason,
        },
    ):
        raise ReadinessError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.plan_secret_authorization_revoked,
        resource_type="plan_secret_readiness_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        outcome="revoked",
        data={**_safe_audit(row), "reason_code": row.revocation_reason_code},
    )
    return row


@_closed_errors
def get_plan_secret_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> PlanSecretReadinessAuthorization:
    actor.require(Permission.readiness_read)
    return _get(session, actor, authorization_id)
