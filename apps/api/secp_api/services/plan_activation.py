"""B1B-PR5A plan-activation lifecycle services (ADR-022).

Two SEPARATE, explicit, permission-gated, audited lifecycles that must exist — and be independently
re-verified by the worker — before a real plan may be generated:

* the reviewed **activation dossier** (draft → evidence → approved → revoked/expired/superseded);
and
* the dedicated **plan-generation authorization** (draft → approved → consumed/revoked/expired).

Neither grants any execution. Creating or approving either enqueues nothing, executes nothing,
contacts no target, constructs no adapter/executor, resolves no secret, and mints no activation
grant. Every persisted value is bounded and secret-free (ids, opaque hashes, bounded categories,
opaque proof metadata); the detailed dossier stays deployment-local and outside source control.
"""

from __future__ import annotations

import functools
import re
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
    ActivationDossierEvidenceKind,
    ActivationDossierEvidenceStatus,
    ActivationDossierStatus,
    AuditAction,
    Permission,
    PlanGenerationAuthorizationStatus,
    PlanGenerationPurpose,
    ReadinessErrorCode,
    ReadinessOperationKind,
)
from secp_api.errors import AuthorizationError, DomainError, NotFoundError, ReadinessError
from secp_api.models import PlanSecretReadinessRecord, ProvisioningManifest
from secp_api.plan_activation_contract import (
    PLAN_GENERATION_READINESS_POLICY_VERSION,
    PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
    activation_dossier_hash,
    dossier_evidence_fingerprint,
    dossier_evidence_is_complete,
    plan_generation_operation_fingerprint,
)
from secp_api.plan_activation_models import (
    REVOCATION_REASON_CODES,
    RealLabActivationDossier,
    RealLabActivationDossierEvidence,
    RealPlanGenerationAuthorization,
)
from secp_api.readiness_contract import as_utc, is_placeholder_dossier, state_namespace_identity

_Code = ReadinessErrorCode
_DEFAULT_TTL_SECONDS = 24 * 3600
_MAX_TTL_SECONDS = 30 * 24 * 3600

REQUIRED_DOSSIER_EVIDENCE_KINDS: frozenset[ActivationDossierEvidenceKind] = frozenset(
    ActivationDossierEvidenceKind
)

# Opaque proof id / issuer label: no whitespace, slash, ``:``, ``@``, or scheme (so it cannot carry
# a
# vault path, URL, or reference). ``fullmatch`` at every call site — never ``match``.
_SAFE_METADATA_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")

# CLOSED revocation reason codes (B1B-PR5A amendment §4). Only these bounded codes may ever be
# persisted as ``revocation_reason_code`` — never arbitrary free text. The application coerces an
# unrecognized code to the neutral default; a DATABASE CHECK constraint (on both tables) is the
# authoritative backstop for the raw/Core/replica path, so no free-text string can be stored.
_REVOCATION_REASON_CODES = frozenset(REVOCATION_REASON_CODES)


def _closed_revocation_reason(reason_code: object) -> str:
    """Return ``reason_code`` iff it is a recognized closed code, else the neutral default."""
    return str(reason_code) if reason_code in _REVOCATION_REASON_CODES else "operator"


_T = TypeVar("_T")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _closed_errors(fn: Callable[..., _T]) -> Callable[..., _T]:
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


def _value(v: object) -> str:
    return str(getattr(v, "value", v))


# =================================================================================================
# Activation dossier
# =================================================================================================


def _dossier_safe_audit(row: RealLabActivationDossier) -> dict:
    """Bounded, secret-free audit payload: ids, hashes, versions, bounded categories only."""
    return {
        "activation_dossier_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "execution_target_id": str(row.execution_target_id),
        "operation_kind": row.operation_kind,
        "dossier_revision": row.dossier_revision,
        "dossier_hash": row.dossier_hash,
        "provider_credential_binding_id": str(row.provider_credential_binding_id),
        "provider_credential_binding_version": row.provider_credential_binding_version,
        "state_credential_binding_id": str(row.state_credential_binding_id),
        "state_credential_binding_version": row.state_credential_binding_version,
        "toolchain_attestation_id": str(row.toolchain_attestation_id),
        "evidence_fingerprint": row.evidence_fingerprint,
        "status": _value(row.status),
        "authorization_expiry": as_utc(row.authorization_expiry).isoformat(),
    }


def _dossier_cas(session: Session, row: RealLabActivationDossier, *, values: dict) -> bool:
    result = session.execute(
        update(RealLabActivationDossier)
        .where(
            RealLabActivationDossier.id == row.id,
            RealLabActivationDossier.revision == row.revision,
        )
        .values(revision=row.revision + 1, **values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _get_dossier(
    session: Session, actor: Principal, dossier_id: uuid.UUID
) -> RealLabActivationDossier:
    row = session.get(RealLabActivationDossier, dossier_id)
    if row is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(row.organization_id)
    return row


def _active_dossier(session: Session, manifest_id: uuid.UUID) -> RealLabActivationDossier | None:
    return (
        session.execute(
            select(RealLabActivationDossier).where(
                RealLabActivationDossier.provisioning_manifest_id == manifest_id,
                RealLabActivationDossier.status.in_(
                    (ActivationDossierStatus.draft, ActivationDossierStatus.approved)
                ),
            )
        )
        .scalars()
        .one_or_none()
    )


def _next_dossier_revision(session: Session, manifest_id: uuid.UUID) -> int:
    current = session.execute(
        select(func.max(RealLabActivationDossier.dossier_revision)).where(
            RealLabActivationDossier.provisioning_manifest_id == manifest_id
        )
    ).scalar()
    return int(current or 0) + 1


@_closed_errors
def create_activation_dossier(
    session: Session,
    actor: Principal,
    *,
    manifest_id: uuid.UUID,
    recovery_owner_proof: str,
    emergency_stop_owner_proof: str,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> RealLabActivationDossier:
    """Create a DRAFT activation dossier bound to one manifest's upstream authoritative facts.

    Requires ``activation_dossier:manage``. It derives EVERY bound fact server-side — organization,
    target/config-hash, onboarding/boundary-hash, plan/env-version + hashes, manifest + hash,
    toolchain profile + hash, the durable toolchain attestation + hash + expiry, the worker
    identity,
    BOTH operation-specific opaque credential bindings, and the server-derived state namespace — and
    computes the opaque dossier hash. It does NOT require eligibility to be ``eligible`` (the
    dossier
    is a PREREQUISITE of eligibility, not bound by it). It creates no evidence and executes nothing.
    """
    actor.require(Permission.activation_dossier_manage)
    for value in (recovery_owner_proof, emergency_stop_owner_proof):
        if not (isinstance(value, str) and _SAFE_METADATA_RE.fullmatch(value)):
            raise ReadinessError(_Code.evidence_invalid)

    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(manifest.organization_id)

    _expire_active_dossier_if_due(session, actor, manifest.id)
    if _active_dossier(session, manifest.id) is not None:
        raise ReadinessError(_Code.lifecycle_conflict)

    facts = _resolve_dossier_facts(session, manifest, now=_utcnow())

    now = _utcnow()
    ttl = max(1, min(int(ttl_seconds), _MAX_TTL_SECONDS))
    for _attempt in range(5):
        revision = _next_dossier_revision(session, manifest.id)
        dossier_hash = activation_dossier_hash(
            dossier_revision=revision, evidence_fingerprint="", **facts["hash_fields"]
        )
        row = RealLabActivationDossier(
            organization_id=manifest.organization_id,
            operation_kind=ReadinessOperationKind.plan_secret_readiness.value,
            dossier_revision=revision,
            dossier_hash=dossier_hash,
            recovery_owner_proof=recovery_owner_proof,
            emergency_stop_owner_proof=emergency_stop_owner_proof,
            evidence_fingerprint="",
            authorization_expiry=now + timedelta(seconds=ttl),
            status=ActivationDossierStatus.draft,
            revision=0,
            created_by=actor.user_id,
            **facts["columns"],
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            continue
        audit.record(
            session,
            action=AuditAction.activation_dossier_created,
            resource_type="real_lab_activation_dossier",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            data=_dossier_safe_audit(row),
        )
        return row
    raise ReadinessError(_Code.lifecycle_conflict)


def _bind_live_preflight(session: Session, onboarding, target, *, now: datetime) -> dict:  # noqa: ANN001
    """Resolve + validate the EXACT current live eligibility preflight a dossier supplements (§3).

    The dossier does not itself decide eligibility, but it must supplement ONE exact live
    observation. That preflight must be controlled-live (Path B), ``live_verified``, hash-valid,
    target/org/onboarding-bound, current (not expired, not drifted), and must NOT contain a live
    failure — its outcome may be ``eligible`` or ``unverifiable``, and it may be ``unverifiable``
    ONLY for dimensions the versioned source policy permits to be supplemented. A different or newer
    preflight yields a different binding hash, so the old dossier no longer matches (invalidation).

    Returns the safe binding facts: the preflight id, the evidence hash, and the opaque
    ``live_preflight_binding_hash`` folded into the dossier hash. Raises ``ReadinessError`` on any
    disagreement. It persists nothing and exposes no endpoint/host/credential.
    """
    from secp_api.eligibility_policy import (
        ELIGIBILITY_SOURCE_POLICY_VERSION,
        dimension_allows_deployment_control,
    )
    from secp_api.enums import EligibilityOutcome, PreflightCheckStatus, VerificationLevel
    from secp_api.models import LiveReadAuthorization, WorkerIdentityRegistration
    from secp_api.plan_activation_contract import live_preflight_binding_hash
    from secp_api.services.eligibility import evaluate_live_eligibility
    from secp_api.target_evidence import LIVE_READONLY_EVIDENCE_SOURCE

    status = evaluate_live_eligibility(session, onboarding, now=now)
    if status is None or status.record is None:
        raise ReadinessError(_Code.binding_invalid)
    pf = status.preflight
    record = status.record

    # Controlled-live (Path B), live_verified, hash-valid, current + org/onboarding/target bound.
    if record.evidence_source != LIVE_READONLY_EVIDENCE_SOURCE:
        raise ReadinessError(_Code.binding_invalid)
    if pf.verification_level != VerificationLevel.live_verified.value:
        raise ReadinessError(_Code.binding_invalid)
    if not status.hash_matches or status.expired or status.drifted:
        raise ReadinessError(_Code.binding_invalid)
    if pf.onboarding_id != onboarding.id or pf.organization_id != onboarding.organization_id:
        raise ReadinessError(_Code.binding_invalid)
    if pf.target_config_hash != target.config_hash or pf.boundary_hash != onboarding.boundary_hash:
        raise ReadinessError(_Code.binding_invalid)

    # NOT a live failure: outcome may be eligible or unverifiable, never ineligible/expired/drifted.
    if pf.eligibility_outcome not in (
        EligibilityOutcome.eligible.value,
        EligibilityOutcome.unverifiable.value,
    ):
        raise ReadinessError(_Code.binding_invalid)
    # An unverifiable dimension may only be one the policy allows to be supplemented; a failed
    # dimension can never be present here (any failure would make the outcome ineligible).
    for check in pf.checks or []:
        c_status = check.get("status")
        if c_status == PreflightCheckStatus.failed.value:
            raise ReadinessError(_Code.binding_invalid)
        supplementable = dimension_allows_deployment_control(str(check.get("check")))
        if c_status == PreflightCheckStatus.warning.value and not supplementable:
            raise ReadinessError(_Code.binding_invalid)

    auth = (
        session.get(LiveReadAuthorization, pf.live_read_authorization_id)
        if pf.live_read_authorization_id
        else None
    )
    wid = (
        session.get(WorkerIdentityRegistration, pf.worker_identity_registration_id)
        if pf.worker_identity_registration_id
        else None
    )
    if auth is None or wid is None:
        raise ReadinessError(_Code.binding_invalid)

    binding_hash = live_preflight_binding_hash(
        preflight_id=str(pf.id),
        evidence_hash=pf.evidence_hash,
        target_evidence_hash=pf.target_evidence_hash or "",
        evidence_source=record.evidence_source,
        verification_level=pf.verification_level,
        eligibility_outcome=pf.eligibility_outcome or "",
        eligibility_policy_version=pf.eligibility_policy_version or "",
        source_policy_version=ELIGIBILITY_SOURCE_POLICY_VERSION,
        collector_contract_version=auth.collector_contract_version,
        endpoint_allowlist_version=auth.endpoint_allowlist_version,
        live_read_authorization_id=str(pf.live_read_authorization_id),
        live_read_authorization_version=pf.live_read_authorization_version or 0,
        live_read_authorization_expiry=as_utc(auth.authorization_expiry).isoformat(),
        worker_identity_registration_id=str(pf.worker_identity_registration_id),
        worker_identity_version=wid.identity_version,
        target_config_hash=pf.target_config_hash,
        onboarding_id=str(onboarding.id),
        onboarding_boundary_hash=pf.boundary_hash,
        collected_at=as_utc(record.collected_at).isoformat(),
        evidence_expires_at=(
            as_utc(pf.evidence_expires_at).isoformat() if pf.evidence_expires_at else ""
        ),
    )
    return {
        "eligibility_preflight_id": pf.id,
        "eligibility_evidence_hash": pf.evidence_hash,
        "live_preflight_binding_hash": binding_hash,
    }


def _resolve_dossier_facts(
    session: Session, manifest: ProvisioningManifest, *, now: datetime
) -> dict:
    """Resolve the immutable upstream binding facts for a dossier, without the eligibility gate."""
    from secp_scenario_schema import content_hash

    from secp_api.credential_binding import (
        RealPlanCredentialError,
        real_plan_credential_bindings,
    )
    from secp_api.enums import OnboardingStatus, TargetStatus, ToolchainProfileStatus
    from secp_api.models import (
        DeploymentPlan,
        ExecutionTarget,
        TargetOnboarding,
        ToolchainProfile,
    )
    from secp_api.readiness_binding import (
        _sole_approved_worker_identity,
        current_toolchain_attestation,
    )

    if content_hash(manifest.content) != manifest.content_hash:
        raise ReadinessError(_Code.binding_invalid)
    plan = session.get(DeploymentPlan, manifest.deployment_plan_id)
    target = session.get(ExecutionTarget, manifest.execution_target_id)
    onboarding = (
        session.get(TargetOnboarding, manifest.target_onboarding_id)
        if manifest.target_onboarding_id
        else None
    )
    toolchain = (
        session.get(ToolchainProfile, manifest.toolchain_profile_id)
        if manifest.toolchain_profile_id
        else None
    )
    if plan is None or plan.environment_version_id is None or not plan.version_content_hash:
        raise ReadinessError(_Code.binding_invalid)
    if target is None or target.status != TargetStatus.active:
        raise ReadinessError(_Code.binding_invalid)
    if target.config_hash != manifest.target_config_hash:
        raise ReadinessError(_Code.binding_invalid)
    if onboarding is None or onboarding.status != OnboardingStatus.active:
        raise ReadinessError(_Code.binding_invalid)
    if manifest.onboarding_boundary_hash != onboarding.boundary_hash:
        raise ReadinessError(_Code.binding_invalid)
    if toolchain is None or toolchain.status != ToolchainProfileStatus.active:
        raise ReadinessError(_Code.binding_invalid)
    if toolchain.content_hash != manifest.toolchain_profile_hash:
        raise ReadinessError(_Code.binding_invalid)

    worker = _sole_approved_worker_identity(session, manifest.organization_id, now)
    if worker is None:
        raise ReadinessError(_Code.binding_invalid)
    attestation = current_toolchain_attestation(session, toolchain, now=now)
    if attestation is None:
        raise ReadinessError(_Code.binding_invalid)

    # The single strict real-plan credential gate (amendment §1): both DEDICATED references present
    # and distinct, each mapped to its own active binding whose source is ``dedicated_operation``.
    # The generic ``secret_ref`` fallback can never satisfy this.
    try:
        provider_binding, state_binding = real_plan_credential_bindings(session, target)
    except RealPlanCredentialError as exc:
        raise ReadinessError(_Code.binding_invalid) from exc

    # The dossier supplements ONE exact live preflight (amendment §3): resolve + validate it and pin
    # its id/hash + fold its full provenance into the dossier hash.
    preflight_binding = _bind_live_preflight(session, onboarding, target, now=now)

    namespace = state_namespace_identity(
        organization_id=str(manifest.organization_id),
        execution_target_id=str(target.id),
        onboarding_id=str(onboarding.id),
        manifest_id=str(manifest.id),
        manifest_content_hash=manifest.content_hash,
        deployment_plan_id=str(plan.id),
    )
    columns = {
        "execution_target_id": target.id,
        "target_onboarding_id": onboarding.id,
        "deployment_plan_id": plan.id,
        "environment_version_id": plan.environment_version_id,
        "provisioning_manifest_id": manifest.id,
        "toolchain_profile_id": toolchain.id,
        "toolchain_attestation_id": attestation.id,
        "worker_identity_registration_id": worker.id,
        "worker_identity_version": worker.identity_version,
        "provider_credential_binding_id": provider_binding.id,
        "provider_credential_binding_version": provider_binding.binding_version,
        "state_credential_binding_id": state_binding.id,
        "state_credential_binding_version": state_binding.binding_version,
        "environment_version_content_hash": plan.version_content_hash,
        "deployment_plan_content_hash": plan.version_content_hash,
        "provisioning_manifest_content_hash": manifest.content_hash,
        "target_config_hash": target.config_hash,
        "onboarding_boundary_hash": onboarding.boundary_hash,
        "toolchain_profile_hash": toolchain.content_hash,
        "toolchain_attestation_hash": attestation.evidence_hash,
        "toolchain_attestation_expires_at": attestation.expires_at,
        "state_namespace_hash": namespace,
        "eligibility_preflight_id": preflight_binding["eligibility_preflight_id"],
        "eligibility_evidence_hash": preflight_binding["eligibility_evidence_hash"],
    }
    hash_fields = {
        "organization_id": str(manifest.organization_id),
        "execution_target_id": str(target.id),
        "target_config_hash": target.config_hash,
        "target_onboarding_id": str(onboarding.id),
        "onboarding_boundary_hash": onboarding.boundary_hash,
        "deployment_plan_id": str(plan.id),
        "deployment_plan_content_hash": plan.version_content_hash,
        "environment_version_id": str(plan.environment_version_id),
        "environment_version_content_hash": plan.version_content_hash,
        "provisioning_manifest_id": str(manifest.id),
        "provisioning_manifest_content_hash": manifest.content_hash,
        "toolchain_profile_id": str(toolchain.id),
        "toolchain_profile_hash": toolchain.content_hash,
        "toolchain_attestation_id": str(attestation.id),
        "toolchain_attestation_hash": attestation.evidence_hash,
        "worker_identity_registration_id": str(worker.id),
        "worker_identity_version": worker.identity_version,
        "provider_credential_binding_id": str(provider_binding.id),
        "provider_credential_binding_version": provider_binding.binding_version,
        "state_credential_binding_id": str(state_binding.id),
        "state_credential_binding_version": state_binding.binding_version,
        "state_namespace_hash": namespace,
        "live_preflight_binding_hash": preflight_binding["live_preflight_binding_hash"],
    }
    return {"columns": columns, "hash_fields": hash_fields}


@_closed_errors
def record_dossier_evidence(
    session: Session,
    actor: Principal,
    dossier_id: uuid.UUID,
    *,
    kind: ActivationDossierEvidenceKind,
    status: ActivationDossierEvidenceStatus,
    proof_id: str,
    issuer: str,
) -> RealLabActivationDossierEvidence:
    """Record/replace one closed, secret-free review evidence item on a DRAFT dossier."""
    actor.require(Permission.activation_dossier_manage)
    row = _get_dossier(session, actor, dossier_id)
    if row.status != ActivationDossierStatus.draft:
        raise ReadinessError(_Code.invalid_state)
    for value in (proof_id, issuer):
        if not (isinstance(value, str) and _SAFE_METADATA_RE.fullmatch(value)):
            raise ReadinessError(_Code.evidence_invalid)

    existing = session.execute(
        select(RealLabActivationDossierEvidence).where(
            RealLabActivationDossierEvidence.dossier_id == row.id,
            RealLabActivationDossierEvidence.kind == kind,
        )
    ).scalar_one_or_none()
    verified_at = _utcnow() if status == ActivationDossierEvidenceStatus.verified else None
    if existing is None:
        existing = RealLabActivationDossierEvidence(
            dossier_id=row.id,
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
        action=AuditAction.activation_dossier_evidence,
        resource_type="real_lab_activation_dossier",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data={
            **_dossier_safe_audit(row),
            "evidence_kind": kind.value,
            "evidence_status": status.value,
        },
    )
    return existing


def _dossier_evidence_rows(
    session: Session, dossier_id: uuid.UUID
) -> list[RealLabActivationDossierEvidence]:
    return list(
        session.execute(
            select(RealLabActivationDossierEvidence).where(
                RealLabActivationDossierEvidence.dossier_id == dossier_id
            )
        )
        .scalars()
        .all()
    )


def _dossier_binding_is_current(
    session: Session, row: RealLabActivationDossier, *, now: datetime
) -> bool:
    """True iff re-deriving the dossier's facts (incl. the live preflight) reproduces its hash.

    A different or newer live preflight, an altered evidence hash, a rotated credential, or any
    drifted upstream fact changes a hash input, so the recomputed dossier hash no longer equals the
    stored one — and the dossier is no longer valid for current use (amendment §3). It never mutates
    the historical dossier row.
    """
    manifest = session.get(ProvisioningManifest, row.provisioning_manifest_id)
    if manifest is None:
        return False
    try:
        facts = _resolve_dossier_facts(session, manifest, now=now)
    except ReadinessError:
        return False
    recomputed = activation_dossier_hash(
        dossier_revision=row.dossier_revision,
        evidence_fingerprint="",
        **facts["hash_fields"],
    )
    return recomputed == row.dossier_hash


@_closed_errors
def approve_activation_dossier(
    session: Session, actor: Principal, dossier_id: uuid.UUID
) -> RealLabActivationDossier:
    """Approve a DRAFT dossier against the COMPLETE review-evidence set (DEDICATED permission).

    Requires ``activation_dossier:approve`` — never inferable from topology, plan, onboarding,
    live-read, readiness, or change-set approval. **Approving runs no readiness and executes
    nothing.** Approval binds the complete evidence fingerprint under a CAS.
    """
    actor.require(Permission.activation_dossier_approve)
    row = _get_dossier(session, actor, dossier_id)
    if row.status != ActivationDossierStatus.draft:
        raise ReadinessError(_Code.invalid_state)
    if as_utc(row.authorization_expiry) <= _utcnow():
        _mark_dossier_expired(session, actor, row)
        raise ReadinessError(_Code.invalid_state)
    if is_placeholder_dossier(row.dossier_hash):  # pragma: no cover - impossible by construction
        raise ReadinessError(_Code.binding_invalid)
    # Amendment §3: a new/changed live preflight (or any drifted upstream fact) invalidates the
    # dossier for current use. Re-derive the facts and recompute the dossier hash; if it no longer
    # equals the stored hash, the exact observation the dossier reviewed is no longer current.
    if not _dossier_binding_is_current(session, row, now=_utcnow()):
        raise ReadinessError(_Code.binding_invalid)
    evidence = _dossier_evidence_rows(session, row.id)
    if not dossier_evidence_is_complete(evidence):
        raise ReadinessError(_Code.evidence_incomplete)
    fingerprint = dossier_evidence_fingerprint(evidence)
    if not _dossier_cas(
        session,
        row,
        values={
            "status": ActivationDossierStatus.approved,
            "evidence_fingerprint": fingerprint,
            "approved_by": actor.user_id,
            "approved_at": _utcnow(),
        },
    ):
        raise ReadinessError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.activation_dossier_approved,
        resource_type="real_lab_activation_dossier",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data=_dossier_safe_audit(row),
    )
    return row


@_closed_errors
def revoke_activation_dossier(
    session: Session, actor: Principal, dossier_id: uuid.UUID, reason_code: str = "operator"
) -> RealLabActivationDossier:
    """Immediately revoke a draft/approved dossier. All FUTURE use is invalidated."""
    actor.require(Permission.activation_dossier_manage)
    row = _get_dossier(session, actor, dossier_id)
    if row.status not in (ActivationDossierStatus.draft, ActivationDossierStatus.approved):
        raise ReadinessError(_Code.invalid_state)
    safe_reason = _closed_revocation_reason(reason_code)
    if not _dossier_cas(
        session,
        row,
        values={
            "status": ActivationDossierStatus.revoked,
            "revoked_by": actor.user_id,
            "revoked_at": _utcnow(),
            "revocation_reason_code": safe_reason,
        },
    ):
        raise ReadinessError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.activation_dossier_revoked,
        resource_type="real_lab_activation_dossier",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        outcome="revoked",
        data={**_dossier_safe_audit(row), "reason_code": safe_reason},
    )
    return row


def _mark_dossier_expired(
    session: Session, actor: Principal, row: RealLabActivationDossier
) -> None:
    if _dossier_cas(session, row, values={"status": ActivationDossierStatus.expired}):
        audit.record(
            session,
            action=AuditAction.activation_dossier_expired,
            resource_type="real_lab_activation_dossier",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            outcome="expired",
            data=_dossier_safe_audit(row),
        )


def _expire_active_dossier_if_due(
    session: Session, actor: Principal, manifest_id: uuid.UUID
) -> None:
    row = _active_dossier(session, manifest_id)
    if row is None or as_utc(row.authorization_expiry) > _utcnow():
        return
    _mark_dossier_expired(session, actor, row)


@_closed_errors
def get_activation_dossier(
    session: Session, actor: Principal, dossier_id: uuid.UUID
) -> RealLabActivationDossier:
    actor.require(Permission.activation_dossier_manage)
    return _get_dossier(session, actor, dossier_id)


# =================================================================================================
# Plan-generation authorization
# =================================================================================================


def _authz_safe_audit(row: RealPlanGenerationAuthorization) -> dict:
    return {
        "plan_generation_authorization_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "execution_target_id": str(row.execution_target_id),
        "activation_dossier_id": str(row.activation_dossier_id),
        "purpose": row.purpose,
        "plan_only_capability_contract_version": row.plan_only_capability_contract_version,
        "provider_credential_binding_id": str(row.provider_credential_binding_id),
        "provider_credential_binding_version": row.provider_credential_binding_version,
        "state_credential_binding_id": str(row.state_credential_binding_id),
        "state_credential_binding_version": row.state_credential_binding_version,
        "operation_fingerprint": row.operation_fingerprint,
        "status": _value(row.status),
        "authorization_expiry": as_utc(row.authorization_expiry).isoformat(),
    }


def _authz_cas(session: Session, row: RealPlanGenerationAuthorization, *, values: dict) -> bool:
    result = session.execute(
        update(RealPlanGenerationAuthorization)
        .where(
            RealPlanGenerationAuthorization.id == row.id,
            RealPlanGenerationAuthorization.revision == row.revision,
        )
        .values(revision=row.revision + 1, **values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(row)
    return True


def _get_authz(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> RealPlanGenerationAuthorization:
    row = session.get(RealPlanGenerationAuthorization, authorization_id)
    if row is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(row.organization_id)
    return row


def active_plan_generation_authorization(
    session: Session, manifest_id: uuid.UUID
) -> RealPlanGenerationAuthorization | None:
    return (
        session.execute(
            select(RealPlanGenerationAuthorization).where(
                RealPlanGenerationAuthorization.provisioning_manifest_id == manifest_id,
                RealPlanGenerationAuthorization.status.in_(
                    (
                        PlanGenerationAuthorizationStatus.draft,
                        PlanGenerationAuthorizationStatus.approved,
                    )
                ),
            )
        )
        .scalars()
        .one_or_none()
    )


def _next_authz_version(session: Session, manifest_id: uuid.UUID) -> int:
    current = session.execute(
        select(func.max(RealPlanGenerationAuthorization.authorization_version)).where(
            RealPlanGenerationAuthorization.provisioning_manifest_id == manifest_id
        )
    ).scalar()
    return int(current or 0) + 1


@_closed_errors
def create_plan_generation_authorization(
    session: Session,
    actor: Principal,
    *,
    manifest_id: uuid.UUID,
    ttl_seconds: int = 3600,
) -> RealPlanGenerationAuthorization:
    """Create a DRAFT plan-generation authorization bound to the current readiness world.

    Requires ``plan_generation:manage``. It binds the approved dossier, the current remote-state +
    plan-secret readiness records, both credential bindings, the attestation, the eligible
    preflight,
    the worker identity, and the exact plan-only capability contract version — all derived
    server-side. It creates NO plan and executes nothing.
    """
    actor.require(Permission.plan_generation_manage)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(manifest.organization_id)

    _expire_active_authz_if_due(session, actor, manifest.id)
    if active_plan_generation_authorization(session, manifest.id) is not None:
        raise ReadinessError(_Code.lifecycle_conflict)

    facts = _resolve_authz_facts(session, manifest, now=_utcnow())

    now = _utcnow()
    ttl = max(1, min(int(ttl_seconds), _MAX_TTL_SECONDS))
    for _attempt in range(5):
        version = _next_authz_version(session, manifest.id)
        row = RealPlanGenerationAuthorization(
            organization_id=manifest.organization_id,
            purpose=PlanGenerationPurpose.plan_generation.value,
            plan_only_capability_contract_version=PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
            readiness_policy_version=PLAN_GENERATION_READINESS_POLICY_VERSION,
            authorization_expiry=now + timedelta(seconds=ttl),
            evidence_fingerprint="",
            status=PlanGenerationAuthorizationStatus.draft,
            authorization_version=version,
            revision=0,
            created_by=actor.user_id,
            **facts,
        )
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            continue
        audit.record(
            session,
            action=AuditAction.plan_generation_authorization_created,
            resource_type="real_plan_generation_authorization",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            data=_authz_safe_audit(row),
        )
        return row
    raise ReadinessError(_Code.lifecycle_conflict)


def _resolve_authz_facts(
    session: Session, manifest: ProvisioningManifest, *, now: datetime
) -> dict:
    """Resolve the authoritative bindings a plan-generation authorization must pin."""
    from secp_api.credential_binding import (
        RealPlanCredentialError,
        real_plan_credential_bindings,
    )
    from secp_api.models import ExecutionTarget
    from secp_api.readiness_binding import load_readiness_binding

    dossier = _active_dossier(session, manifest.id)
    if dossier is None or dossier.status != ActivationDossierStatus.approved:
        raise ReadinessError(_Code.invalid_state)
    if as_utc(dossier.authorization_expiry) <= now:
        raise ReadinessError(_Code.invalid_state)

    # Re-assert the strict real-plan credential gate (amendment §1): the authorization may bind
    # ONLY dedicated, distinct, independently-bound provider + state credentials, never legacy ones.
    target = session.get(ExecutionTarget, manifest.execution_target_id)
    if target is None:
        raise ReadinessError(_Code.binding_invalid)
    try:
        strict_provider, strict_state = real_plan_credential_bindings(session, target)
    except RealPlanCredentialError as exc:
        raise ReadinessError(_Code.binding_invalid) from exc

    result = load_readiness_binding(
        session,
        manifest_id=manifest.id,
        operation_kind=ReadinessOperationKind.plan_secret_readiness,
        now=now,
        activation_dossier_hash=dossier.dossier_hash,
    )
    if (
        result.binding is None
        or result.state_readiness is None
        or result.credential_binding is None
    ):
        raise ReadinessError(_Code.binding_invalid)
    provider_binding = result.credential_binding
    state_readiness = result.state_readiness
    # The readiness path's current provider binding must be EXACTLY the strict dedicated one.
    if provider_binding.id != strict_provider.id:
        raise ReadinessError(_Code.binding_invalid)

    secret_record = (
        session.execute(
            select(PlanSecretReadinessRecord).where(
                PlanSecretReadinessRecord.provisioning_manifest_id == manifest.id,
                PlanSecretReadinessRecord.operation_fingerprint
                == result.binding.operation_fingerprint(),
            )
        )
        .scalars()
        .one_or_none()
    )
    if secret_record is None:
        raise ReadinessError(_Code.invalid_state)

    state_binding = strict_state

    fingerprint = plan_generation_operation_fingerprint(
        activation_dossier_hash=dossier.dossier_hash,
        provisioning_manifest_content_hash=manifest.content_hash,
        provider_credential_binding_id=str(provider_binding.id),
        provider_credential_binding_version=provider_binding.binding_version,
        state_credential_binding_id=str(state_binding.id),
        state_credential_binding_version=state_binding.binding_version,
        remote_state_evidence_hash=state_readiness.evidence_hash,
        plan_secret_evidence_hash=secret_record.evidence_hash,
        plan_only_capability_contract_version=PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
    )
    return {
        "execution_target_id": manifest.execution_target_id,
        "target_onboarding_id": dossier.target_onboarding_id,
        "deployment_plan_id": manifest.deployment_plan_id,
        "provisioning_manifest_id": manifest.id,
        "toolchain_profile_id": dossier.toolchain_profile_id,
        "activation_dossier_id": dossier.id,
        "eligibility_preflight_id": result.eligibility_preflight_id,
        "toolchain_attestation_id": dossier.toolchain_attestation_id,
        "remote_state_readiness_id": state_readiness.id,
        "plan_secret_readiness_id": secret_record.id,
        "provider_credential_binding_id": provider_binding.id,
        "provider_credential_binding_version": provider_binding.binding_version,
        "state_credential_binding_id": state_binding.id,
        "state_credential_binding_version": state_binding.binding_version,
        "worker_identity_registration_id": dossier.worker_identity_registration_id,
        "worker_identity_version": dossier.worker_identity_version,
        "provisioning_manifest_content_hash": manifest.content_hash,
        "target_config_hash": manifest.target_config_hash,
        "onboarding_boundary_hash": dossier.onboarding_boundary_hash,
        "eligibility_evidence_hash": result.binding.eligibility_evidence_hash,
        "toolchain_profile_hash": manifest.toolchain_profile_hash or dossier.toolchain_profile_hash,
        "toolchain_attestation_hash": dossier.toolchain_attestation_hash,
        "remote_state_evidence_hash": state_readiness.evidence_hash,
        "plan_secret_evidence_hash": secret_record.evidence_hash,
        "activation_dossier_hash": dossier.dossier_hash,
        "dossier_evidence_fingerprint": dossier.evidence_fingerprint,
        "operation_fingerprint": fingerprint,
    }


@_closed_errors
def approve_plan_generation_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> RealPlanGenerationAuthorization:
    """Approve a DRAFT plan-generation authorization (DEDICATED ``plan_generation:approve``).

    **Approving does not run readiness, generate a plan, or execute anything.** It binds a
    completion
    fingerprint under a CAS.
    """
    actor.require(Permission.plan_generation_approve)
    row = _get_authz(session, actor, authorization_id)
    if row.status != PlanGenerationAuthorizationStatus.draft:
        raise ReadinessError(_Code.invalid_state)
    if row.purpose != PlanGenerationPurpose.plan_generation.value:  # pragma: no cover
        raise ReadinessError(_Code.invalid_state)
    if as_utc(row.authorization_expiry) <= _utcnow():
        _mark_authz_expired(session, actor, row)
        raise ReadinessError(_Code.invalid_state)
    if not _authz_cas(
        session,
        row,
        values={
            "status": PlanGenerationAuthorizationStatus.approved,
            "evidence_fingerprint": row.operation_fingerprint,
            "approved_by": actor.user_id,
            "approved_at": _utcnow(),
        },
    ):
        raise ReadinessError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.plan_generation_authorized,
        resource_type="real_plan_generation_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        data=_authz_safe_audit(row),
    )
    return row


@_closed_errors
def revoke_plan_generation_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID, reason_code: str = "operator"
) -> RealPlanGenerationAuthorization:
    actor.require(Permission.plan_generation_manage)
    row = _get_authz(session, actor, authorization_id)
    if row.status not in (
        PlanGenerationAuthorizationStatus.draft,
        PlanGenerationAuthorizationStatus.approved,
    ):
        raise ReadinessError(_Code.invalid_state)
    safe_reason = _closed_revocation_reason(reason_code)
    if not _authz_cas(
        session,
        row,
        values={
            "status": PlanGenerationAuthorizationStatus.revoked,
            "revoked_by": actor.user_id,
            "revoked_at": _utcnow(),
            "revocation_reason_code": safe_reason,
        },
    ):
        raise ReadinessError(_Code.lifecycle_conflict)
    audit.record(
        session,
        action=AuditAction.plan_generation_authorization_revoked,
        resource_type="real_plan_generation_authorization",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor=str(actor.user_id),
        outcome="revoked",
        data={**_authz_safe_audit(row), "reason_code": safe_reason},
    )
    return row


def _mark_authz_expired(
    session: Session, actor: Principal, row: RealPlanGenerationAuthorization
) -> None:
    if _authz_cas(session, row, values={"status": PlanGenerationAuthorizationStatus.expired}):
        audit.record(
            session,
            action=AuditAction.plan_generation_authorization_expired,
            resource_type="real_plan_generation_authorization",
            resource_id=row.id,
            organization_id=row.organization_id,
            actor=str(actor.user_id),
            outcome="expired",
            data=_authz_safe_audit(row),
        )


def _expire_active_authz_if_due(session: Session, actor: Principal, manifest_id: uuid.UUID) -> None:
    row = active_plan_generation_authorization(session, manifest_id)
    if row is None or as_utc(row.authorization_expiry) > _utcnow():
        return
    _mark_authz_expired(session, actor, row)


@_closed_errors
def get_plan_generation_authorization(
    session: Session, actor: Principal, authorization_id: uuid.UUID
) -> RealPlanGenerationAuthorization:
    actor.require(Permission.plan_generation_manage)
    return _get_authz(session, actor, authorization_id)


# --- combined plan-readiness + enqueue-only plan-generation request ------------------------------


@_closed_errors
def get_plan_generation_readiness(
    session: Session, actor: Principal, manifest_id: uuid.UUID, *, now: datetime | None = None
) -> dict:
    """The bounded combined plan-generation readiness read model (org-scoped, permission-protected).

    It resolves nothing, builds no environment, renders nothing, constructs no runner/executor,
    mints
    no grant, and enqueues + executes nothing. A refused derived check is audited with a bounded
    reason code and mutates NO historical record.
    """
    from secp_api.plan_activation_contract import plan_generation_readiness_status

    actor.require(Permission.plan_generation_manage)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(manifest.organization_id)
    now = now or _utcnow()
    status = plan_generation_readiness_status(session, manifest, now=now)
    return status.as_dict()


@_closed_errors
def request_plan_generation(session: Session, actor: Principal, manifest_id: uuid.UUID) -> None:
    """Explicitly request the worker-owned real-plan-generation operation (ENQUEUE-ONLY).

    Requires ``plan_generation:manage``. It records a secret-free requested audit and hands to the
    dispatcher, which durably enqueues on the worker path and REFUSES inline execution. The API
    never constructs an executor, resolves a credential, renders a workspace, or runs a process. It
    is NEVER auto-triggered by readiness, dossier approval, or authorization approval.
    """
    from secp_api.dispatch import get_dispatcher

    actor.require(Permission.plan_generation_manage)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(manifest.organization_id)
    audit.record(
        session,
        action=AuditAction.plan_generation_requested,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=manifest.organization_id,
        actor=str(actor.user_id),
        data={
            "operation_kind": "real_plan_generation",
            "provisioning_manifest_id": str(manifest.id),
            "readiness_policy_version": PLAN_GENERATION_READINESS_POLICY_VERSION,
            "plan_only_capability_contract_version": PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
        },
    )
    get_dispatcher().dispatch_real_plan_generation(session, manifest.id)


# --- bounded read-model views --------------------------------------------------------------------


def dossier_view(row: RealLabActivationDossier) -> dict:
    return {
        "activation_dossier_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "execution_target_id": str(row.execution_target_id),
        "operation_kind": row.operation_kind,
        "dossier_revision": row.dossier_revision,
        "dossier_hash": row.dossier_hash,
        "status": _value(row.status),
        "evidence_fingerprint": row.evidence_fingerprint,
        "authorization_expiry": as_utc(row.authorization_expiry).isoformat(),
        "provider_credential_binding_id": str(row.provider_credential_binding_id),
        "provider_credential_binding_version": row.provider_credential_binding_version,
        "state_credential_binding_id": str(row.state_credential_binding_id),
        "state_credential_binding_version": row.state_credential_binding_version,
        "evidence": [
            {
                "kind": _value(e.kind),
                "status": _value(e.status),
                "proof_id": e.proof_id,
                "issuer": e.issuer,
            }
            for e in sorted(row.evidence, key=lambda e: _value(e.kind))
        ],
        "approved_at": as_utc(row.approved_at).isoformat() if row.approved_at else None,
        "revoked_at": as_utc(row.revoked_at).isoformat() if row.revoked_at else None,
        "revocation_reason_code": row.revocation_reason_code,
    }


def plan_generation_authorization_view(row: RealPlanGenerationAuthorization) -> dict:
    return {
        "plan_generation_authorization_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "activation_dossier_id": str(row.activation_dossier_id),
        "purpose": row.purpose,
        "plan_only_capability_contract_version": row.plan_only_capability_contract_version,
        "operation_fingerprint": row.operation_fingerprint,
        "status": _value(row.status),
        "authorization_version": row.authorization_version,
        "authorization_expiry": as_utc(row.authorization_expiry).isoformat(),
        "evidence_fingerprint": row.evidence_fingerprint,
        "approved_at": as_utc(row.approved_at).isoformat() if row.approved_at else None,
        "revoked_at": as_utc(row.revoked_at).isoformat() if row.revoked_at else None,
        "consumed_at": as_utc(row.consumed_at).isoformat() if row.consumed_at else None,
        "revocation_reason_code": row.revocation_reason_code,
    }


__all__ = [
    "REQUIRED_DOSSIER_EVIDENCE_KINDS",
    "active_plan_generation_authorization",
    "get_plan_generation_readiness",
    "request_plan_generation",
    "approve_activation_dossier",
    "approve_plan_generation_authorization",
    "create_activation_dossier",
    "create_plan_generation_authorization",
    "dossier_view",
    "get_activation_dossier",
    "get_plan_generation_authorization",
    "plan_generation_authorization_view",
    "record_dossier_evidence",
    "revoke_activation_dossier",
    "revoke_plan_generation_authorization",
]
