"""Authoritative readiness-binding derivation (SECP-002B-1B, B1B-PR4 / ADR-021 §C).

Turns a stable ``provisioning_manifest_id`` into the strict, immutable
:class:`~secp_api.readiness_contract.ReadinessBinding` by loading ONLY authoritative control-plane
records. No field is ever accepted from a caller, a request body, a Temporal argument, or an
adapter: a Temporal workflow argument carries an id and nothing else, and this module re-derives the
complete binding from the database.

It performs no external contact. It builds no adapter, no resolver, no transport, no process, no
environment, and no activation grant. It imports no worker, plugin, HTTP, subprocess, or secret
code. It reads the toolchain profile's ``state_backend`` only to confirm the profile is
REMOTE-state-backed — the raw kind and reference never leave this function and are never returned,
persisted, audited, logged, or exposed. It deliberately computes **no digest of the backend
reference**: an unsalted hash of an enumerable locator is an offline confirmation oracle for it, so
the backend is anchored instead by the immutable ``toolchain_profile_hash`` (B1B-PR4 §5).

The binding REFUSES (fail closed, closed reason code, nothing persisted) whenever the current
B1B-PR3 eligibility result is not ``live_verified`` + ``eligible`` + current + unexpired + undrifted
+ hash-valid. There is no production shortcut that upgrades ``unverifiable`` into ``eligible``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime

from secp_scenario_schema import content_hash
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.enums import (
    CredentialBindingStatus,
    CredentialPurposeClass,
    EligibilityOutcome,
    OnboardingStatus,
    PlanSecretAuthorizationStatus,
    PlanStatus,
    ReadinessOperationKind,
    ReadinessReason,
    RemoteStateReadinessOutcome,
    TargetStatus,
    ToolchainAttestationOutcome,
    ToolchainProfileStatus,
    WorkerIdentityStatus,
)
from secp_api.models import (
    CredentialBinding,
    DeploymentPlan,
    ExecutionTarget,
    PlanSecretReadinessAuthorization,
    ProvisioningManifest,
    RemoteStateReadinessRecord,
    TargetOnboarding,
    ToolchainAttestationRecord,
    ToolchainProfile,
    WorkerIdentityRegistration,
)
from secp_api.readiness_contract import (
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    READINESS_ACTIVATION_DOSSIER_PLACEHOLDER,
    READINESS_POLICY_VERSION,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    PurposeNotPermitted,
    ReadinessBinding,
    as_utc,
    assert_plan_only_purpose,
    canonical_utc,
    state_namespace_identity,
)
from secp_api.services.eligibility import evaluate_live_eligibility
from secp_api.toolchain_profile import toolchain_profile_hash, validate_toolchain_profile

_R = ReadinessReason

# The real toolchain-attestation policy the binding pins. It MUST equal the worker's
# ``secp_worker.provisioning.toolchain_verify.ATTESTATION_POLICY_VERSION`` (a drift-guard test
# asserts the equality).
#
# Both readiness operations require a DURABLE ``ToolchainAttestationRecord`` produced by the worker
# actually running B1B-PR2's ``RealToolchainVerifier`` against an explicit deployment-local
# filesystem layout. A matching toolchain-profile hash is NOT an attestation: the profile is a
# DECLARATION, the record is the EVIDENCE that the declaration was verified on this worker.
TOOLCHAIN_ATTESTATION_POLICY_VERSION = "secp-002b-1b/toolchain-attest/v1"


@dataclass(frozen=True)
class ReadinessBindingResult:
    """Either an authoritative binding, or a closed refusal reason. Never both."""

    binding: ReadinessBinding | None = None
    reason: ReadinessReason | None = None
    # Authoritative rows the caller (worker) needs; loaded here so it never re-derives them.
    manifest: ProvisioningManifest | None = None
    plan: DeploymentPlan | None = None
    target: ExecutionTarget | None = None
    onboarding: TargetOnboarding | None = None
    toolchain: ToolchainProfile | None = None
    worker_identity: WorkerIdentityRegistration | None = None
    eligibility_preflight_id: uuid.UUID | None = None
    attestation: ToolchainAttestationRecord | None = None
    credential_binding: CredentialBinding | None = None
    state_readiness: RemoteStateReadinessRecord | None = None
    authorization: PlanSecretReadinessAuthorization | None = None

    @property
    def ok(self) -> bool:
        return self.binding is not None


def _refuse(reason: ReadinessReason) -> ReadinessBindingResult:
    return ReadinessBindingResult(reason=reason)


def _adapter_contract_version(kind: ReadinessOperationKind) -> str:
    return (
        REMOTE_STATE_ADAPTER_CONTRACT_VERSION
        if kind is ReadinessOperationKind.remote_state_readiness
        else PLAN_SECRET_RESOLVER_CONTRACT_VERSION
    )


def _sole_approved_worker_identity(
    session: Session, organization_id: uuid.UUID, now: datetime
) -> WorkerIdentityRegistration | None:
    """Exactly one approved, unexpired worker-identity registration for the org (0 or >1 → None)."""
    rows = [
        r
        for r in session.execute(
            select(WorkerIdentityRegistration).where(
                WorkerIdentityRegistration.organization_id == organization_id,
                WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
            )
        )
        .scalars()
        .all()
        if r.expiry is not None and as_utc(r.expiry) > now
    ]
    return rows[0] if len(rows) == 1 else None


def current_toolchain_attestation(
    session: Session, toolchain: ToolchainProfile, *, now: datetime
) -> ToolchainAttestationRecord | None:
    """The current ``attested``, unexpired, undrifted toolchain attestation for a profile.

    A matching profile id/hash is NOT an attestation: this record only exists because the worker ran
    the real ``RealToolchainVerifier`` against an explicit deployment-local on-disk layout and EVERY
    required facet verified.
    """
    rows = (
        session.execute(
            select(ToolchainAttestationRecord)
            .where(
                ToolchainAttestationRecord.toolchain_profile_id == toolchain.id,
                ToolchainAttestationRecord.outcome == ToolchainAttestationOutcome.attested,
            )
            .order_by(ToolchainAttestationRecord.collected_at.desc())
        )
        .scalars()
        .all()
    )
    for row in rows:
        if as_utc(row.expires_at) <= now:
            continue
        if row.verifier_policy_version != TOOLCHAIN_ATTESTATION_POLICY_VERSION:
            continue
        if row.toolchain_profile_hash != toolchain.content_hash:
            continue
        if row.organization_id != toolchain.organization_id:
            continue
        return row
    return None


def current_state_readiness(
    session: Session, manifest: ProvisioningManifest, *, now: datetime
) -> RemoteStateReadinessRecord | None:
    """The latest ``ready``, unexpired remote-state readiness record for this exact manifest.

    It checks EXACTLY these facts and no others: the outcome is ``ready``; the record is unexpired;
    the readiness policy and adapter contract versions are current; and the manifest content hash
    still agrees. The **full** binding agreement (target config, onboarding boundary, toolchain
    profile hash, toolchain attestation id + hash, eligibility evidence hash, namespace identity,
    credential binding, capability class, activation dossier, worker identity) is
    enforced by :func:`load_readiness_binding`, which compares this record against the freshly
    derived binding — a plan-secret readiness attempt therefore cannot proceed on a state-readiness
    record that agrees here but disagrees with today's authoritative world. The historical row is
    never mutated.
    """
    rows = (
        session.execute(
            select(RemoteStateReadinessRecord)
            .where(
                RemoteStateReadinessRecord.provisioning_manifest_id == manifest.id,
                RemoteStateReadinessRecord.outcome == RemoteStateReadinessOutcome.ready,
            )
            .order_by(RemoteStateReadinessRecord.collected_at.desc())
        )
        .scalars()
        .all()
    )
    for row in rows:
        if as_utc(row.expires_at) <= now:
            continue
        if row.readiness_policy_version != READINESS_POLICY_VERSION:
            continue
        if row.adapter_contract_version != REMOTE_STATE_ADAPTER_CONTRACT_VERSION:
            continue
        if row.provisioning_manifest_content_hash != manifest.content_hash:
            continue
        return row
    return None


def active_plan_secret_authorization(
    session: Session, manifest_id: uuid.UUID
) -> PlanSecretReadinessAuthorization | None:
    """The single active (draft or approved) plan-secret authorization for a manifest, if any."""
    return (
        session.execute(
            select(PlanSecretReadinessAuthorization).where(
                PlanSecretReadinessAuthorization.provisioning_manifest_id == manifest_id,
                PlanSecretReadinessAuthorization.status.in_(
                    (
                        PlanSecretAuthorizationStatus.draft,
                        PlanSecretAuthorizationStatus.approved,
                    )
                ),
            )
        )
        .scalars()
        .one_or_none()
    )


def load_readiness_binding(  # noqa: PLR0911,C901,PLR0912,PLR0915 - one refusal per gate
    session: Session,
    *,
    manifest_id: uuid.UUID,
    operation_kind: ReadinessOperationKind,
    now: datetime,
    activation_dossier_hash: str = READINESS_ACTIVATION_DOSSIER_PLACEHOLDER,
) -> ReadinessBindingResult:
    """Derive the complete authoritative readiness binding for one manifest, or fail closed.

    Ordered gates (each returns a closed, secret-free reason; nothing is contacted or persisted):

    1. manifest exists + its content hash re-verifies (no tampering);
    2. its deployment plan is approved and target-bound, with matching binding hashes;
    3. its execution target is active with no config drift;
    4. its target onboarding is active with no boundary drift;
    5. its toolchain profile is active, valid, hash-consistent, and REMOTE-state-backed;
    6. the CURRENT B1B-PR3 live eligibility evidence is ``live_verified`` + ``eligible`` + current
       + unexpired + undrifted + hash-valid (anything else — ``unverifiable``, ``ineligible``,
       ``expired``, ``drifted``, ``refused``, hash-invalid, or missing — REFUSES);
    7. exactly one approved, unexpired worker identity backs the organization;
    8. for plan-secret readiness only: a current remote-state readiness record exists, and an
       APPROVED, unexpired, plan-read-purpose authorization binds every fact above.
    """
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        return _refuse(_R.manifest_missing)

    if content_hash(manifest.content) != manifest.content_hash:
        return _refuse(_R.manifest_hash_invalid)

    plan = session.get(DeploymentPlan, manifest.deployment_plan_id)
    if plan is None or plan.organization_id != manifest.organization_id:
        return _refuse(_R.plan_binding_invalid)
    if plan.status not in (PlanStatus.approved, PlanStatus.applied):
        return _refuse(_R.plan_not_approved)
    if plan.execution_target_id is None or plan.execution_target_id != manifest.execution_target_id:
        return _refuse(_R.plan_binding_invalid)
    if plan.environment_version_id is None or not plan.version_content_hash:
        return _refuse(_R.plan_binding_invalid)

    target = session.get(ExecutionTarget, manifest.execution_target_id)
    if target is None or target.organization_id != manifest.organization_id:
        return _refuse(_R.plan_binding_invalid)
    if target.status != TargetStatus.active:
        return _refuse(_R.target_not_active)
    if target.config_hash != manifest.target_config_hash:
        return _refuse(_R.target_config_drift)

    onboarding_id = manifest.target_onboarding_id
    if onboarding_id is None:
        return _refuse(_R.onboarding_not_active)
    onboarding = session.get(TargetOnboarding, onboarding_id)
    if onboarding is None or onboarding.organization_id != manifest.organization_id:
        return _refuse(_R.onboarding_not_active)
    if onboarding.status != OnboardingStatus.active or onboarding.execution_target_id != target.id:
        return _refuse(_R.onboarding_not_active)
    if manifest.onboarding_boundary_hash != onboarding.boundary_hash:
        return _refuse(_R.onboarding_boundary_drift)

    toolchain_id = manifest.toolchain_profile_id
    if toolchain_id is None:
        return _refuse(_R.toolchain_profile_missing)
    toolchain = session.get(ToolchainProfile, toolchain_id)
    if (
        toolchain is None
        or toolchain.organization_id != manifest.organization_id
        or toolchain.execution_target_id != target.id
    ):
        return _refuse(_R.toolchain_profile_missing)
    if toolchain.status != ToolchainProfileStatus.active:
        return _refuse(_R.toolchain_profile_invalid)
    try:
        spec = validate_toolchain_profile(toolchain.content)
    except Exception:
        # Never echo a validation body: the profile content is deployment structure.
        return _refuse(_R.toolchain_profile_invalid)
    recomputed = toolchain_profile_hash(toolchain.content)
    if recomputed != toolchain.content_hash or recomputed != manifest.toolchain_profile_hash:
        return _refuse(_R.toolchain_profile_drift)

    # The remote-state backend is validated here (remote-only) but is NEVER digested into a durable
    # value: an unsalted hash of an enumerable locator is a confirmation oracle. The BACKEND BINDING
    # ANCHOR is the exact immutable ToolchainProfile content hash, which is already durable.
    _ = spec.state_backend  # validated above; the raw kind/reference never leave this function

    # 6. CURRENT live eligibility (B1B-PR3). Nothing upgrades a non-eligible outcome.
    eligibility = evaluate_live_eligibility(session, onboarding, now=now)
    if eligibility is None:
        return _refuse(_R.eligibility_missing)
    if not eligibility.hash_matches:
        return _refuse(_R.eligibility_hash_invalid)
    if eligibility.expired:
        return _refuse(_R.eligibility_expired)
    if eligibility.drifted:
        return _refuse(_R.eligibility_drifted)
    if eligibility.outcome != EligibilityOutcome.eligible.value or not eligibility.valid:
        return _refuse(_R.eligibility_not_eligible)

    worker_identity = _sole_approved_worker_identity(session, manifest.organization_id, now)
    if worker_identity is None:
        return _refuse(_R.worker_identity_untrusted)

    # 7. The DURABLE, worker-produced PR2 toolchain ATTESTATION (B1B-PR4 §1). A matching profile
    #    hash is a DECLARATION, never evidence: this record exists only because the worker ran the
    #    real ``RealToolchainVerifier`` against an explicit deployment-local on-disk layout.
    # The DURABLE, worker-produced toolchain ATTESTATION. A matching profile hash is not one.
    attestation = current_toolchain_attestation(session, toolchain, now=now)
    if attestation is None:
        return _refuse(_R.toolchain_attestation_missing)
    from secp_api.readiness_contract import readiness_evidence_hash

    recomputed_attestation = readiness_evidence_hash(
        {
            "kind": "toolchain_attestation",
            "toolchain_profile_id": str(toolchain.id),
            "toolchain_profile_hash": toolchain.content_hash,
            "verifier_policy_version": attestation.verifier_policy_version,
            "outcome": getattr(attestation.outcome, "value", str(attestation.outcome)),
            "verified_facets": list(attestation.verified_facets or []),
            "reason_codes": list(attestation.reason_codes or []),
            "worker_identity_registration_id": str(attestation.worker_identity_registration_id),
            "worker_identity_version": attestation.worker_identity_version,
            "operation_fingerprint": attestation.operation_fingerprint,
        }
    )
    if recomputed_attestation != attestation.evidence_hash:
        return _refuse(_R.toolchain_attestation_hash_invalid)
    # It must be bound to the CURRENT worker identity + version.
    if (
        attestation.worker_identity_registration_id != worker_identity.id
        or attestation.worker_identity_version != worker_identity.identity_version
    ):
        return _refuse(_R.toolchain_attestation_drifted)

    # The OPAQUE credential binding for the target's CURRENT provider_plan_read credential
    # selection.
    # (PR5A introduced a second purpose, state_backend_plan, so this MUST filter by purpose — an
    # unfiltered query would raise MultipleResultsFound once both bindings exist.) Rotating the
    # provider reference rotates this binding, which changes the fingerprint and invalidates every
    # prior authorization and readiness record — while storing no reference and no hash of one.
    credential_binding = (
        session.execute(
            select(CredentialBinding).where(
                CredentialBinding.execution_target_id == target.id,
                CredentialBinding.purpose_class == CredentialPurposeClass.provider_plan_read,
                CredentialBinding.status == CredentialBindingStatus.active,
            )
        )
        .scalars()
        .one_or_none()
    )
    if credential_binding is None:
        return _refuse(_R.credential_binding_missing)

    namespace = state_namespace_identity(
        organization_id=str(manifest.organization_id),
        execution_target_id=str(target.id),
        onboarding_id=str(onboarding.id),
        manifest_id=str(manifest.id),
        manifest_content_hash=manifest.content_hash,
        deployment_plan_id=str(plan.id),
    )

    shared = ReadinessBinding(
        organization_id=str(manifest.organization_id),
        environment_version_id=str(plan.environment_version_id),
        environment_version_content_hash=plan.version_content_hash or "",
        deployment_plan_id=str(plan.id),
        deployment_plan_content_hash=(
            plan.approved_content_hash or plan.version_content_hash or ""
        ),
        provisioning_manifest_id=str(manifest.id),
        provisioning_manifest_content_hash=manifest.content_hash,
        execution_target_id=str(target.id),
        target_config_hash=target.config_hash,
        target_onboarding_id=str(onboarding.id),
        onboarding_boundary_hash=onboarding.boundary_hash,
        effective_boundary_hash=manifest.effective_boundary_hash or "",
        eligibility_preflight_id=str(eligibility.preflight.id),
        eligibility_evidence_hash=eligibility.evidence_hash,
        eligibility_policy_version=eligibility.policy_version,
        eligibility_expires_at=canonical_utc(eligibility.expires_at),
        toolchain_profile_id=str(toolchain.id),
        toolchain_profile_hash=toolchain.content_hash,
        toolchain_attestation_policy_version=TOOLCHAIN_ATTESTATION_POLICY_VERSION,
        toolchain_attestation_id=str(attestation.id),
        toolchain_attestation_hash=attestation.evidence_hash,
        state_namespace_identity=namespace,
        credential_binding_id=str(credential_binding.id),
        credential_binding_version=credential_binding.binding_version,
        activation_dossier_hash=activation_dossier_hash,
        worker_identity_registration_id=str(worker_identity.id),
        worker_identity_version=worker_identity.identity_version,
        operation_kind=operation_kind.value,
        readiness_policy_version=READINESS_POLICY_VERSION,
        adapter_contract_version=_adapter_contract_version(operation_kind),
    )

    if operation_kind is ReadinessOperationKind.remote_state_readiness:
        return ReadinessBindingResult(
            binding=shared,
            manifest=manifest,
            plan=plan,
            target=target,
            onboarding=onboarding,
            toolchain=toolchain,
            worker_identity=worker_identity,
            eligibility_preflight_id=eligibility.preflight.id,
            attestation=attestation,
            credential_binding=credential_binding,
        )

    # --- plan-secret readiness: state readiness first, then the dedicated authorization ----------
    state_readiness = current_state_readiness(session, manifest, now=now)
    if state_readiness is None:
        return _refuse(_R.secret_state_readiness_missing)
    if state_readiness.state_namespace_hash != namespace:
        return _refuse(_R.secret_state_readiness_drifted)
    if state_readiness.eligibility_evidence_hash != eligibility.evidence_hash:
        return _refuse(_R.secret_state_readiness_drifted)
    if state_readiness.toolchain_profile_hash != toolchain.content_hash:
        return _refuse(_R.secret_state_readiness_drifted)
    if state_readiness.toolchain_attestation_id != attestation.id:
        return _refuse(_R.toolchain_attestation_drifted)
    if state_readiness.toolchain_attestation_hash != attestation.evidence_hash:
        return _refuse(_R.toolchain_attestation_drifted)
    # The state-readiness record was produced under a REVIEWED dossier; the placeholder can never
    # satisfy readiness.
    from secp_api.readiness_contract import is_placeholder_dossier

    if is_placeholder_dossier(state_readiness.activation_dossier_hash):
        return _refuse(_R.activation_dossier_placeholder)
    # A CONTROLLED-LIVE capability is mandatory: test-only evidence never advances readiness.
    from secp_api.enums import ReadinessCapabilityClass

    if state_readiness.capability_class != ReadinessCapabilityClass.controlled_live:
        return _refuse(_R.adapter_capability_not_controlled_live)

    state_bound = replace(
        shared,
        state_readiness_record_id=str(state_readiness.id),
        state_readiness_evidence_hash=state_readiness.evidence_hash,
    )
    # The operation identity — everything EXCEPT which authorization approves it. An authorization
    # binds exactly this at creation; a mismatch means it was minted for a different world.
    identity = state_bound.operation_identity_fingerprint()

    authorization = active_plan_secret_authorization(session, manifest.id)
    if authorization is None:
        return _refuse(_R.secret_authorization_missing)
    reason = plan_secret_authorization_refusal(
        authorization,
        manifest=manifest,
        target=target,
        onboarding=onboarding,
        toolchain=toolchain,
        eligibility_evidence_hash=eligibility.evidence_hash,
        eligibility_preflight_id=eligibility.preflight.id,
        state_readiness=state_readiness,
        worker_identity=worker_identity,
        attestation=attestation,
        credential_binding=credential_binding,
        operation_identity_fingerprint=identity,
        now=now,
    )
    if reason is not None:
        return _refuse(reason)

    binding = replace(
        state_bound,
        authorization_id=str(authorization.id),
        authorization_version=authorization.authorization_version,
        # The expiry is an IMMUTABLE binding fact of the authorization row, so folding it into the
        # fingerprint cannot silently mint a fresh retry budget: changing an expiry is impossible —
        # it requires a NEW authorization (a new id AND a new version), which is a new operation.
        authorization_expiry=canonical_utc(authorization.authorization_expiry),
    )
    return ReadinessBindingResult(
        binding=binding,
        state_readiness=state_readiness,
        authorization=authorization,
        manifest=manifest,
        plan=plan,
        target=target,
        onboarding=onboarding,
        toolchain=toolchain,
        worker_identity=worker_identity,
        eligibility_preflight_id=eligibility.preflight.id,
        attestation=attestation,
        credential_binding=credential_binding,
    )


def plan_secret_authorization_refusal(  # noqa: PLR0911 - one explicit refusal per bound fact
    authorization: PlanSecretReadinessAuthorization,
    *,
    manifest: ProvisioningManifest,
    target: ExecutionTarget,
    onboarding: TargetOnboarding,
    toolchain: ToolchainProfile,
    eligibility_evidence_hash: str,
    eligibility_preflight_id: uuid.UUID,
    state_readiness: RemoteStateReadinessRecord,
    worker_identity: WorkerIdentityRegistration,
    attestation: ToolchainAttestationRecord,
    credential_binding: CredentialBinding,
    operation_identity_fingerprint: str,
    now: datetime,
) -> ReadinessReason | None:
    """Return the closed refusal reason for an authorization against today's world, or ``None``.

    Every bound fact is re-checked against the CURRENT authoritative records: a draft, revoked,
    expired, wrong-purpose, wrong-organization/target/onboarding/manifest/plan, drifted-eligibility,
    drifted-state-readiness, drifted-toolchain, drifted-dossier, drifted-worker-identity, or
    wrong-resolver-contract authorization can never authorize a readiness attempt. Revocation takes
    effect immediately: the next check refuses.
    """
    if authorization.status == PlanSecretAuthorizationStatus.draft:
        return _R.secret_authorization_draft
    if authorization.status == PlanSecretAuthorizationStatus.revoked:
        return _R.secret_authorization_revoked
    if authorization.status != PlanSecretAuthorizationStatus.approved:
        return _R.secret_authorization_expired
    if as_utc(authorization.authorization_expiry) <= now:
        return _R.secret_authorization_expired
    try:
        assert_plan_only_purpose(authorization.purpose)
    except PurposeNotPermitted:
        return _R.secret_authorization_purpose_invalid
    if authorization.organization_id != manifest.organization_id:
        return _R.secret_authorization_binding_invalid
    if authorization.execution_target_id != target.id:
        return _R.secret_authorization_binding_invalid
    if authorization.target_onboarding_id != onboarding.id:
        return _R.secret_authorization_binding_invalid
    if authorization.provisioning_manifest_id != manifest.id:
        return _R.secret_authorization_binding_invalid
    if authorization.deployment_plan_id != manifest.deployment_plan_id:
        return _R.secret_authorization_binding_invalid
    if authorization.toolchain_profile_id != toolchain.id:
        return _R.secret_authorization_binding_invalid
    if authorization.eligibility_preflight_id != eligibility_preflight_id:
        return _R.secret_authorization_binding_invalid
    if authorization.remote_state_readiness_id != state_readiness.id:
        return _R.secret_authorization_binding_invalid
    if authorization.worker_identity_registration_id != worker_identity.id:
        return _R.worker_identity_untrusted
    if authorization.worker_identity_version != worker_identity.identity_version:
        return _R.worker_identity_untrusted
    if authorization.provisioning_manifest_content_hash != manifest.content_hash:
        return _R.secret_authorization_binding_invalid
    if authorization.target_config_hash != target.config_hash:
        return _R.target_config_drift
    if authorization.onboarding_boundary_hash != onboarding.boundary_hash:
        return _R.onboarding_boundary_drift
    if authorization.eligibility_evidence_hash != eligibility_evidence_hash:
        return _R.eligibility_drifted
    if authorization.toolchain_profile_hash != toolchain.content_hash:
        return _R.toolchain_profile_drift
    if authorization.toolchain_attestation_id != attestation.id:
        return _R.toolchain_attestation_drifted
    if authorization.toolchain_attestation_hash != attestation.evidence_hash:
        return _R.toolchain_attestation_drifted
    # A rotated credential (a changed ExecutionTarget.secret_ref) invalidates the authorization —
    # WITHOUT the schema ever storing the reference or a hash of it.
    if authorization.credential_binding_id != credential_binding.id:
        return _R.credential_binding_drift
    if authorization.credential_binding_version != credential_binding.binding_version:
        return _R.credential_binding_drift
    if authorization.remote_state_evidence_hash != state_readiness.evidence_hash:
        return _R.secret_state_readiness_drifted
    from secp_api.readiness_contract import is_placeholder_dossier

    if is_placeholder_dossier(authorization.activation_dossier_hash):
        return _R.activation_dossier_placeholder
    if authorization.activation_dossier_hash != state_readiness.activation_dossier_hash:
        return _R.activation_dossier_mismatch
    if authorization.resolver_contract_version != PLAN_SECRET_RESOLVER_CONTRACT_VERSION:
        return _R.resolver_contract_mismatch
    if authorization.readiness_policy_version != READINESS_POLICY_VERSION:
        return _R.readiness_policy_mismatch
    if authorization.operation_fingerprint != operation_identity_fingerprint:
        return _R.secret_authorization_binding_invalid
    if not authorization.evidence_fingerprint:
        return _R.secret_evidence_fingerprint_mismatch
    return None
