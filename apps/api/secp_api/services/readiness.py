"""API-side readiness surface (B1B-PR4 / ADR-021 §B, §M, §P) — ENQUEUE-ONLY + safe read models.

This module is IMPORT-SAFE for the control-plane API. It:

* never contacts a state backend or a secret manager;
* never constructs a resolver, a state-readiness adapter, a transport, or a process environment;
* never inspects a target connection value, receives secret material, or resolves a secret;
* never calls worker readiness orchestration directly (it imports NO worker module);
* never persists readiness evidence (the worker recorder is structurally unreachable from here).

It may do exactly two things: durably ENQUEUE a readiness operation (a ``WorkflowRun`` + outbox row
via the dispatcher, which REFUSES inline execution with no fallback), and expose bounded, redacted
read models.

**The two readiness operations are SEPARATE explicit operator actions.** Requesting state readiness
never requests secret readiness. Passing eligibility never requests either. Completing both never
creates a plan: readiness STOPS.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    Permission,
    PlanSecretAuthorizationStatus,
    PlanSecretReadinessOutcome,
    ReadinessCapabilityClass,
    ReadinessErrorCode,
    ReadinessOperationKind,
    ReadinessReason,
    RemoteStateReadinessOutcome,
)
from secp_api.errors import ReadinessError
from secp_api.models import (
    PlanSecretReadinessAuthorization,
    PlanSecretReadinessRecord,
    ProvisioningManifest,
    RemoteStateReadinessRecord,
    ToolchainAttestationRecord,
)
from secp_api.readiness_binding import (
    TOOLCHAIN_ATTESTATION_POLICY_VERSION,
    active_plan_secret_authorization,
    current_toolchain_attestation,
    load_readiness_binding,
    plan_secret_authorization_refusal,
)
from secp_api.readiness_contract import (
    PLAN_SECRET_ENV_CONTRACT_VERSION,
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    PLAN_SECRET_SELF_TEST_POLICY_VERSION,
    READINESS_POLICY_VERSION,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    as_utc,
    is_placeholder_dossier,
)

_Code = ReadinessErrorCode


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _manifest(session: Session, actor: Principal, manifest_id: uuid.UUID) -> ProvisioningManifest:
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ReadinessError(_Code.not_found)
    actor.require_org(manifest.organization_id)
    return manifest


# --- enqueue-only request seams (the API never contacts anything) ---------------------------------


def request_toolchain_attestation(
    session: Session, actor: Principal, manifest_id: uuid.UUID
) -> None:
    """Explicitly request the worker-owned PR2 toolchain attestation (B1B-PR4 §1).

    A SEPARATE operator action from BOTH readiness operations, and a hard PREREQUISITE of each: a
    matching toolchain-profile hash is NOT an attestation. The API never touches a filesystem, reads
    a worker-local path, executes a binary, loads a provider, or persists attestation evidence — the
    verification is worker-local and READ-ONLY, and only the worker may record it.
    """
    from secp_api.dispatch import get_dispatcher

    actor.require(Permission.readiness_manage)
    manifest = _manifest(session, actor, manifest_id)
    audit.record(
        session,
        action=AuditAction.toolchain_attestation_requested,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=manifest.organization_id,
        actor=str(actor.user_id),
        data={
            "provisioning_manifest_id": str(manifest.id),
            "toolchain_profile_id": str(manifest.toolchain_profile_id),
            "verifier_policy_version": TOOLCHAIN_ATTESTATION_POLICY_VERSION,
            "readiness_policy_version": READINESS_POLICY_VERSION,
        },
    )
    get_dispatcher().dispatch_toolchain_attestation(session, manifest.id)


def request_remote_state_readiness(
    session: Session, actor: Principal, manifest_id: uuid.UUID
) -> None:
    """Explicitly request the worker-owned remote-state readiness operation.

    Permission-protected and org-scoped. It records a secret-free requested audit and hands to the
    dispatcher, which durably enqueues on the worker path and REFUSES inline execution. The API
    never contacts a backend, builds an adapter, reads a state key, or persists evidence. This does
    NOT request secret readiness and does NOT create a plan.
    """
    from secp_api.dispatch import get_dispatcher

    actor.require(Permission.readiness_manage)
    manifest = _manifest(session, actor, manifest_id)
    audit.record(
        session,
        action=AuditAction.remote_state_readiness_requested,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=manifest.organization_id,
        actor=str(actor.user_id),
        data={
            "operation_kind": ReadinessOperationKind.remote_state_readiness.value,
            "provisioning_manifest_id": str(manifest.id),
            "readiness_policy_version": READINESS_POLICY_VERSION,
            "adapter_contract_version": REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
        },
    )
    get_dispatcher().dispatch_remote_state_readiness(session, manifest.id)


def request_plan_secret_readiness(
    session: Session, actor: Principal, manifest_id: uuid.UUID
) -> None:
    """Explicitly request the worker-owned plan-secret readiness operation.

    A SEPARATE operator action from state readiness: neither invokes the other, and a successful
    state readiness never triggers this. The API never constructs a resolver, contacts a secret
    manager, resolves a secret, receives secret material, or builds a process environment.
    """
    from secp_api.dispatch import get_dispatcher

    actor.require(Permission.readiness_manage)
    manifest = _manifest(session, actor, manifest_id)
    audit.record(
        session,
        action=AuditAction.plan_secret_readiness_requested,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=manifest.organization_id,
        actor=str(actor.user_id),
        data={
            "operation_kind": ReadinessOperationKind.plan_secret_readiness.value,
            "provisioning_manifest_id": str(manifest.id),
            "readiness_policy_version": READINESS_POLICY_VERSION,
            "resolver_contract_version": PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
            "self_test_policy_version": PLAN_SECRET_SELF_TEST_POLICY_VERSION,
        },
    )
    get_dispatcher().dispatch_plan_secret_readiness(session, manifest.id)


# --- safe, redacted read models ------------------------------------------------------------------


def get_toolchain_attestation(
    session: Session, actor: Principal, manifest_id: uuid.UUID, *, now: datetime | None = None
) -> dict | None:
    """A bounded projection of the latest toolchain-attestation record for the manifest's profile.

    It carries NO worker-local path, filename, executable content, provider content, CLI content, or
    expected/observed raw digest — only ids, bounded facet names, bounded reason codes, versions and
    content hashes (B1B-PR4 §1).
    """
    actor.require(Permission.readiness_read)
    manifest = _manifest(session, actor, manifest_id)
    now = now or _utcnow()
    row = (
        session.execute(
            select(ToolchainAttestationRecord)
            .where(ToolchainAttestationRecord.toolchain_profile_id == manifest.toolchain_profile_id)
            .order_by(ToolchainAttestationRecord.collected_at.desc())
        )
        .scalars()
        .first()
    )
    if row is None:
        return None
    return {
        "record_id": str(row.id),
        "execution_target_id": str(row.execution_target_id),
        "toolchain_profile_id": str(row.toolchain_profile_id),
        "toolchain_profile_hash": row.toolchain_profile_hash,
        "worker_identity_registration_id": str(row.worker_identity_registration_id),
        "worker_identity_version": row.worker_identity_version,
        "verifier_policy_version": row.verifier_policy_version,
        "outcome": getattr(row.outcome, "value", row.outcome),
        "verified_facets": list(row.verified_facets or []),
        "reason_codes": list(row.reason_codes or []),
        "evidence_hash": row.evidence_hash,
        "operation_fingerprint": row.operation_fingerprint,
        "collected_at": as_utc(row.collected_at).isoformat(),
        "expires_at": as_utc(row.expires_at).isoformat(),
        "expired": as_utc(row.expires_at) <= now,
    }


def latest_remote_state_readiness(
    session: Session, manifest_id: uuid.UUID
) -> RemoteStateReadinessRecord | None:
    return (
        session.execute(
            select(RemoteStateReadinessRecord)
            .where(RemoteStateReadinessRecord.provisioning_manifest_id == manifest_id)
            .order_by(RemoteStateReadinessRecord.collected_at.desc())
        )
        .scalars()
        .first()
    )


def latest_plan_secret_readiness(
    session: Session, manifest_id: uuid.UUID
) -> PlanSecretReadinessRecord | None:
    return (
        session.execute(
            select(PlanSecretReadinessRecord)
            .where(PlanSecretReadinessRecord.provisioning_manifest_id == manifest_id)
            .order_by(PlanSecretReadinessRecord.collected_at.desc())
        )
        .scalars()
        .first()
    )


def get_remote_state_readiness(
    session: Session, actor: Principal, manifest_id: uuid.UUID, *, now: datetime | None = None
) -> dict | None:
    """A bounded, redacted projection of the latest remote-state readiness record, or ``None``.

    Exposes ONLY: the operation kind, a bounded outcome, bounded facets + reason codes, safe record
    ids, safe hashes (the immutable toolchain-profile content hash + a server-derived namespace hash
    over non-sensitive UUIDs — never a backend URL, kind, bucket, object key, state path, or ANY
    digest taken directly over the backend reference), opaque UUID proof ids, policy/adapter
    versions, the collection time, the expiry, and the derived current validity.
    """
    actor.require(Permission.readiness_read)
    manifest = _manifest(session, actor, manifest_id)
    row = latest_remote_state_readiness(session, manifest.id)
    if row is None:
        return None
    now = now or _utcnow()
    expired = as_utc(row.expires_at) <= now
    # ``current`` is derived from the AUTHORITATIVE binding, not from the record alone: the record
    # is
    # current only when today's binding still resolves AND names this exact operation fingerprint. A
    # record whose target config, onboarding boundary, toolchain profile, eligibility evidence, or
    # worker identity has since drifted is NOT current, even though it is still ``ready`` +
    # unexpired.
    binding_result = load_readiness_binding(
        session,
        manifest_id=manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=now,
        activation_dossier_hash=row.activation_dossier_hash,
    )
    current = (
        binding_result.binding is not None
        and binding_result.binding.operation_fingerprint() == row.operation_fingerprint
        and row.outcome == RemoteStateReadinessOutcome.ready
        and not expired
        # A CONTROLLED-LIVE capability and a REAL (non-placeholder) reviewed dossier are mandatory.
        and row.capability_class == ReadinessCapabilityClass.controlled_live
        and not is_placeholder_dossier(row.activation_dossier_hash)
    )
    return {
        "operation_kind": ReadinessOperationKind.remote_state_readiness.value,
        "record_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "execution_target_id": str(row.execution_target_id),
        "target_onboarding_id": str(row.target_onboarding_id),
        "outcome": getattr(row.outcome, "value", row.outcome),
        "facets": list(row.facets or []),
        "reason_codes": list(row.reason_codes or []),
        "state_backend_class": row.state_backend_class,
        "state_namespace_hash": row.state_namespace_hash,
        "encryption_proof_id": _opt(row.encryption_proof_id),
        "lock_proof_id": _opt(row.lock_proof_id),
        "backup_proof_id": _opt(row.backup_proof_id),
        "restore_proof_id": _opt(row.restore_proof_id),
        "eligibility_evidence_hash": row.eligibility_evidence_hash,
        "toolchain_profile_hash": row.toolchain_profile_hash,
        "toolchain_attestation_id": str(row.toolchain_attestation_id),
        "toolchain_attestation_hash": row.toolchain_attestation_hash,
        "capability_class": getattr(row.capability_class, "value", row.capability_class),
        "adapter_registration_id": str(row.adapter_registration_id),
        "readiness_policy_version": row.readiness_policy_version,
        "adapter_contract_version": row.adapter_contract_version,
        "operation_fingerprint": row.operation_fingerprint,
        "evidence_hash": row.evidence_hash,
        "collected_at": as_utc(row.collected_at).isoformat(),
        "expires_at": as_utc(row.expires_at).isoformat(),
        "expired": expired,
        "current": current,
    }


def get_plan_secret_readiness(
    session: Session, actor: Principal, manifest_id: uuid.UUID, *, now: datetime | None = None
) -> dict | None:
    """A bounded, redacted projection of the latest plan-secret readiness record, or ``None``.

    It exposes NO secret, secret reference, secret-reference hash, backend locator, endpoint,
    namespace name, token, backend response, environment name/value, or exception detail.
    """
    actor.require(Permission.readiness_read)
    manifest = _manifest(session, actor, manifest_id)
    row = latest_plan_secret_readiness(session, manifest.id)
    if row is None:
        return None
    now = now or _utcnow()
    status = provisioning_readiness_status(session, manifest, now=now)
    return {
        "operation_kind": ReadinessOperationKind.plan_secret_readiness.value,
        "record_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "authorization_id": str(row.authorization_id),
        "authorization_version": row.authorization_version,
        "secret_purpose": row.secret_purpose,
        "outcome": getattr(row.outcome, "value", row.outcome),
        "facets": list(row.facets or []),
        "reason_codes": list(row.reason_codes or []),
        "resolver_contract_version": row.resolver_contract_version,
        "self_test_policy_version": row.self_test_policy_version,
        "env_contract_version": row.env_contract_version,
        "readiness_policy_version": row.readiness_policy_version,
        "self_test_proof_id": _opt(row.self_test_proof_id),
        "remote_state_readiness_id": str(row.remote_state_readiness_id),
        "eligibility_evidence_hash": row.eligibility_evidence_hash,
        "toolchain_profile_hash": row.toolchain_profile_hash,
        "toolchain_attestation_id": str(row.toolchain_attestation_id),
        "toolchain_attestation_hash": row.toolchain_attestation_hash,
        # OPAQUE credential identity — never the reference, never a hash of it.
        "credential_binding_id": str(row.credential_binding_id),
        "credential_binding_version": row.credential_binding_version,
        "capability_class": getattr(row.capability_class, "value", row.capability_class),
        "adapter_registration_id": str(row.adapter_registration_id),
        "operation_fingerprint": row.operation_fingerprint,
        "evidence_hash": row.evidence_hash,
        "collected_at": as_utc(row.collected_at).isoformat(),
        "expires_at": as_utc(row.expires_at).isoformat(),
        "expired": as_utc(row.expires_at) <= now,
        "current": status.plan_secret_readiness_id == row.id,
    }


def plan_secret_authorization_view(row: PlanSecretReadinessAuthorization) -> dict:
    """A bounded authorization lifecycle read model. Never exposes a reference or a secret."""
    return {
        "authorization_id": str(row.id),
        "provisioning_manifest_id": str(row.provisioning_manifest_id),
        "execution_target_id": str(row.execution_target_id),
        "target_onboarding_id": str(row.target_onboarding_id),
        "deployment_plan_id": str(row.deployment_plan_id),
        "secret_purpose": row.purpose,
        "credential_reference_scheme": row.credential_reference_scheme,
        "credential_binding_id": str(row.credential_binding_id),
        "credential_binding_version": row.credential_binding_version,
        "toolchain_attestation_id": str(row.toolchain_attestation_id),
        "resolver_contract_version": row.resolver_contract_version,
        "readiness_policy_version": row.readiness_policy_version,
        "status": getattr(row.status, "value", row.status),
        "authorization_version": row.authorization_version,
        "authorization_expiry": as_utc(row.authorization_expiry).isoformat(),
        "operation_fingerprint": row.operation_fingerprint,
        "evidence_fingerprint": row.evidence_fingerprint,
        "evidence": [
            {
                "kind": getattr(e.kind, "value", e.kind),
                "status": getattr(e.status, "value", e.status),
                "proof_id": e.proof_id,
                "issuer": e.issuer,
            }
            for e in sorted(row.evidence, key=lambda e: getattr(e.kind, "value", str(e.kind)))
        ],
        "approved_at": as_utc(row.approved_at).isoformat() if row.approved_at else None,
        "revoked_at": as_utc(row.revoked_at).isoformat() if row.revoked_at else None,
        "revocation_reason_code": row.revocation_reason_code,
    }


# --- combined current-readiness helper (§M) ------------------------------------------------------


@dataclass(frozen=True)
class ProvisioningReadinessStatus:
    """Whether PR5 may LATER consider readiness current. It is NOT plan approval.

    A ``ready`` status launches nothing, approves nothing, and unseals nothing: it is a bounded,
    derived, read-only assertion that every gate is currently satisfied. This helper constructs no
    runner, no executor, no activation grant, no workspace, and no resolver; it renders nothing,
    resolves nothing, contacts nothing, and executes nothing.
    """

    ready: bool
    reasons: tuple[str, ...]
    eligibility_preflight_id: uuid.UUID | None = None
    toolchain_attestation_id: uuid.UUID | None = None
    credential_binding_id: uuid.UUID | None = None
    credential_binding_version: int | None = None
    remote_state_readiness_id: uuid.UUID | None = None
    plan_secret_readiness_id: uuid.UUID | None = None
    plan_secret_authorization_id: uuid.UUID | None = None

    def as_dict(self) -> dict:
        return {
            "ready": self.ready,
            "reasons": list(self.reasons),
            "eligibility_preflight_id": _opt(self.eligibility_preflight_id),
            "toolchain_attestation_id": _opt(self.toolchain_attestation_id),
            "credential_binding_id": _opt(self.credential_binding_id),
            "credential_binding_version": self.credential_binding_version,
            "remote_state_readiness_id": _opt(self.remote_state_readiness_id),
            "plan_secret_readiness_id": _opt(self.plan_secret_readiness_id),
            "plan_secret_authorization_id": _opt(self.plan_secret_authorization_id),
            "readiness_policy_version": READINESS_POLICY_VERSION,
        }


def _opt(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


def provisioning_readiness_status(  # noqa: C901,PLR0912 - one explicit gate per requirement
    session: Session, manifest: ProvisioningManifest, *, now: datetime
) -> ProvisioningReadinessStatus:
    """Derive whether EVERY readiness gate is currently satisfied for one manifest (B1B-PR4 §7).

    ``ready`` requires ALL of these to be exact and current:

    1. eligible live PR3 evidence;
    2. a successful DURABLE PR2 toolchain attestation record (a matching profile hash is not one);
    3. a NON-PLACEHOLDER activation dossier;
    4. a CONTROLLED-LIVE state-adapter capability;
    5. a successful state-readiness record;
    6. an approved, current plan-secret authorization;
    7. the current OPAQUE credential-binding id + version;
    8. a CONTROLLED-LIVE plan-secret adapter capability;
    9. a successful plan-secret readiness record;
    10. a current worker identity;
    11. every evidence hash;
    12. every policy / contract version;
    13. every expiry.

    (1)–(2), (6)–(7), (10)–(13) are enforced inside :func:`load_readiness_binding`, which fails
    closed with the exact reason for whichever gate is unsatisfied; the rest are asserted here.

    **Passing combined readiness is NOT plan approval.** It does not enqueue B1B-PR5, construct a
    runner or an executor, create an activation grant, render, resolve a target credential, or
    execute a process. Nothing here dispatches anything.
    """
    reasons: list[str] = []

    # The plan-secret record carries the REVIEWED dossier hash the operation actually ran under; the
    # binding must be re-derived with it, or the fingerprint would not reproduce.
    latest = latest_plan_secret_readiness(session, manifest.id)
    dossier = latest.activation_dossier_hash if latest is not None else ""
    if is_placeholder_dossier(dossier):
        # (3) The fail-closed placeholder can never satisfy readiness.
        return ProvisioningReadinessStatus(
            ready=False, reasons=(ReadinessReason.activation_dossier_placeholder.value,)
        )

    result = load_readiness_binding(
        session,
        manifest_id=manifest.id,
        operation_kind=ReadinessOperationKind.plan_secret_readiness,
        now=now,
        activation_dossier_hash=dossier,
    )
    if result.binding is None:
        reasons.append((result.reason or ReadinessReason.gate_incomplete).value)
        return ProvisioningReadinessStatus(ready=False, reasons=tuple(reasons))

    binding = result.binding
    state_readiness = result.state_readiness
    authorization = result.authorization
    attestation = result.attestation
    credential_binding = result.credential_binding
    assert state_readiness is not None and authorization is not None  # noqa: S101
    assert attestation is not None and credential_binding is not None  # noqa: S101

    # (9) The plan-secret readiness record for THIS exact operation fingerprint must exist, be
    # ``ready`` and be unexpired. A record from a different (older) binding never counts.
    record = (
        session.execute(
            select(PlanSecretReadinessRecord).where(
                PlanSecretReadinessRecord.provisioning_manifest_id == manifest.id,
                PlanSecretReadinessRecord.operation_fingerprint == binding.operation_fingerprint(),
            )
        )
        .scalars()
        .one_or_none()
    )
    if record is None:
        reasons.append(ReadinessReason.gate_incomplete.value)
    else:
        if record.outcome != PlanSecretReadinessOutcome.ready:
            reasons.append(getattr(record.outcome, "value", str(record.outcome)))
        if as_utc(record.expires_at) <= now:
            reasons.append(PlanSecretReadinessOutcome.expired.value)
        # (12) every policy / contract version
        if record.resolver_contract_version != PLAN_SECRET_RESOLVER_CONTRACT_VERSION:
            reasons.append(ReadinessReason.resolver_contract_mismatch.value)
        if record.self_test_policy_version != PLAN_SECRET_SELF_TEST_POLICY_VERSION:
            reasons.append(ReadinessReason.readiness_policy_mismatch.value)
        if record.env_contract_version != PLAN_SECRET_ENV_CONTRACT_VERSION:
            # A bumped JIT environment-projection contract invalidates the recorded
            # ``jit_injection_contract`` facet: it was proven against a DIFFERENT allowlist.
            reasons.append(ReadinessReason.readiness_policy_mismatch.value)
        if record.readiness_policy_version != READINESS_POLICY_VERSION:
            reasons.append(ReadinessReason.readiness_policy_mismatch.value)
        # (5) it must be bound to THIS state-readiness record
        if record.remote_state_readiness_id != state_readiness.id:
            reasons.append(ReadinessReason.secret_state_readiness_drifted.value)
        # (11) every evidence hash
        if record.authorization_evidence_fingerprint != authorization.evidence_fingerprint:
            reasons.append(ReadinessReason.secret_evidence_fingerprint_mismatch.value)
        # (2) + (11) the DURABLE attestation
        if record.toolchain_attestation_id != attestation.id:
            reasons.append(ReadinessReason.toolchain_attestation_drifted.value)
        if record.toolchain_attestation_hash != attestation.evidence_hash:
            reasons.append(ReadinessReason.toolchain_attestation_drifted.value)
        # (7) the OPAQUE credential binding — a rotated secret_ref invalidates readiness
        if record.credential_binding_id != credential_binding.id:
            reasons.append(ReadinessReason.credential_binding_drift.value)
        if record.credential_binding_version != credential_binding.binding_version:
            reasons.append(ReadinessReason.credential_binding_drift.value)
        # (3) a NON-placeholder reviewed dossier
        if is_placeholder_dossier(record.activation_dossier_hash):
            reasons.append(ReadinessReason.activation_dossier_placeholder.value)
        # (8) a CONTROLLED-LIVE plan-secret adapter capability
        if record.capability_class != ReadinessCapabilityClass.controlled_live:
            reasons.append(ReadinessReason.adapter_capability_not_controlled_live.value)

    # (5) + (13) the state-readiness record itself is still ``ready`` + unexpired ...
    if state_readiness.outcome != RemoteStateReadinessOutcome.ready:
        reasons.append(ReadinessReason.secret_state_readiness_missing.value)
    if as_utc(state_readiness.expires_at) <= now:
        reasons.append(ReadinessReason.secret_state_readiness_expired.value)
    # (4) ... and was produced under a CONTROLLED-LIVE capability + a real reviewed dossier.
    if state_readiness.capability_class != ReadinessCapabilityClass.controlled_live:
        reasons.append(ReadinessReason.adapter_capability_not_controlled_live.value)
    if is_placeholder_dossier(state_readiness.activation_dossier_hash):
        reasons.append(ReadinessReason.activation_dossier_placeholder.value)

    return ProvisioningReadinessStatus(
        ready=not reasons,
        reasons=tuple(dict.fromkeys(reasons)),
        eligibility_preflight_id=result.eligibility_preflight_id,
        toolchain_attestation_id=attestation.id,
        credential_binding_id=credential_binding.id,
        credential_binding_version=credential_binding.binding_version,
        remote_state_readiness_id=state_readiness.id,
        plan_secret_readiness_id=record.id if record is not None else None,
        plan_secret_authorization_id=authorization.id,
    )


def get_provisioning_readiness(
    session: Session, actor: Principal, manifest_id: uuid.UUID, *, now: datetime | None = None
) -> dict:
    """The bounded combined current-readiness read model (org-scoped + permission-protected).

    A refused derived check is audited with a bounded reason code — and mutates NO historical
    record (a prior successful readiness row is never turned into a failure).
    """
    actor.require(Permission.readiness_read)
    manifest = _manifest(session, actor, manifest_id)
    now = now or _utcnow()
    status = provisioning_readiness_status(session, manifest, now=now)
    if not status.ready:
        audit.record(
            session,
            action=AuditAction.provisioning_readiness_refused,
            resource_type="provisioning_manifest",
            resource_id=manifest.id,
            organization_id=manifest.organization_id,
            actor=str(actor.user_id),
            outcome="refused",
            data={
                "provisioning_manifest_id": str(manifest.id),
                "reason_codes": list(status.reasons),
                "readiness_policy_version": READINESS_POLICY_VERSION,
            },
        )
    return status.as_dict()


def authorization_lifecycle_status(
    session: Session, manifest: ProvisioningManifest, *, now: datetime
) -> dict | None:
    """The bounded lifecycle status of the manifest's active plan-secret authorization, if any."""
    row = active_plan_secret_authorization(session, manifest.id)
    if row is None:
        return None
    view = plan_secret_authorization_view(row)
    view["expired"] = as_utc(row.authorization_expiry) <= now
    view["usable"] = row.status == PlanSecretAuthorizationStatus.approved and not view["expired"]
    return view


__all__ = [
    "ProvisioningReadinessStatus",
    "authorization_lifecycle_status",
    "current_toolchain_attestation",
    "get_plan_secret_readiness",
    "get_provisioning_readiness",
    "get_remote_state_readiness",
    "get_toolchain_attestation",
    "latest_plan_secret_readiness",
    "latest_remote_state_readiness",
    "plan_secret_authorization_refusal",
    "plan_secret_authorization_view",
    "provisioning_readiness_status",
    "request_plan_secret_readiness",
    "request_remote_state_readiness",
    "request_toolchain_attestation",
]
