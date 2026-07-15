"""Pure, import-safe B1B-PR5A plan-activation contract (ADR-022).

This module derives the OPAQUE activation-dossier hash, the plan-generation operation fingerprint,
and the combined :class:`PlanGenerationReadinessStatus` — the single, pure, read-only assertion that
every real-plan prerequisite is currently satisfied. It:

* contacts nothing, resolves no secret, builds no environment, renders nothing;
* constructs no runner, no executor, and no activation grant;
* enqueues nothing and executes nothing.

A ``ready`` status is NOT plan approval and launches nothing (ADR-022 §5). It only asserts that PR5B
*could later* generate a plan under the full gate.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from secp_api.enums import (
    ActivationDossierEvidenceKind,
    ActivationDossierEvidenceStatus,
    ActivationDossierStatus,
    CredentialPurposeClass,
    PlanGenerationAuthorizationStatus,
    PlanGenerationPurpose,
    PlanSecretReadinessOutcome,
    ReadinessOperationKind,
    ReadinessReason,
    RemoteStateReadinessOutcome,
)

# --- the two SEPARATE plan-only child-environment allowlists (ADR-022 §10) -----------------------
# The provider plan-read credential projects to the exact provider var (as in PR4); the
# state-backend plan credential projects to the exact OpenTofu http-backend var. They are DISTINCT
# allowlists — a
# combined SecretMaterial is never built, and neither value ever crosses into the other's variable.
PLAN_PROVIDER_ENV_ALLOWLIST: tuple[str, ...] = ("TF_VAR_pm_api_token",)
PLAN_STATE_ENV_ALLOWLIST: tuple[str, ...] = ("TF_HTTP_PASSWORD",)
PLAN_SECRET_ENV_CONTRACT_VERSION = "secp-002b-1b-pr5a/plan-secret-env/v1"

# --- version + digest prefixes (bumping any invalidates every prior fingerprint) ------------------
PLAN_ONLY_CAPABILITY_CONTRACT_VERSION = "secp-002b-1b-pr5a/plan-only-capability/v1"
PLAN_GENERATION_READINESS_POLICY_VERSION = "secp-002b-1b-pr5a/plan-generation-readiness/v1"
_DOSSIER_HASH_PREFIX = "secp-002b-1b-pr5a/activation-dossier/v1"
_DOSSIER_EVIDENCE_PREFIX = "secp-002b-1b-pr5a/activation-dossier-evidence/v1"
_PLAN_GEN_FINGERPRINT_PREFIX = "secp-002b-1b-pr5a/plan-generation-operation/v1"

# Every dossier evidence kind must be present + verified before the dossier may be approved.
REQUIRED_DOSSIER_EVIDENCE_KINDS: frozenset[ActivationDossierEvidenceKind] = frozenset(
    ActivationDossierEvidenceKind
)

_R = ReadinessReason


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def dossier_evidence_fingerprint(items) -> str:  # noqa: ANN001 - iterable of evidence rows
    """Canonical ``sha256:`` fingerprint over the COMPLETE dossier evidence set (safe metadata
    only).

    It folds in only closed metadata (kind / status / opaque proof id / issuer). Never a value that
    could be sensitive. Approval binds this; a change to any evidence item invalidates the dossier.
    """
    from secp_api.readiness_contract import canonical_utc

    parts = []
    for e in sorted(items, key=lambda e: str(getattr(e.kind, "value", e.kind))):
        parts.append(
            "|".join(
                (
                    str(getattr(e.kind, "value", e.kind)),
                    str(getattr(e.status, "value", e.status)),
                    str(e.proof_id),
                    str(e.issuer),
                    canonical_utc(e.verified_at),
                )
            )
        )
    return _sha256("|".join((_DOSSIER_EVIDENCE_PREFIX, *parts)))


def activation_dossier_hash(
    *,
    organization_id: str,
    execution_target_id: str,
    target_config_hash: str,
    target_onboarding_id: str,
    onboarding_boundary_hash: str,
    deployment_plan_id: str,
    deployment_plan_content_hash: str,
    environment_version_id: str,
    environment_version_content_hash: str,
    provisioning_manifest_id: str,
    provisioning_manifest_content_hash: str,
    toolchain_profile_id: str,
    toolchain_profile_hash: str,
    toolchain_attestation_id: str,
    toolchain_attestation_hash: str,
    worker_identity_registration_id: str,
    worker_identity_version: int,
    provider_credential_binding_id: str,
    provider_credential_binding_version: int,
    state_credential_binding_id: str,
    state_credential_binding_version: int,
    state_namespace_hash: str,
    dossier_revision: int,
    evidence_fingerprint: str,
    live_preflight_binding_hash: str,
) -> str:
    """The OPAQUE, server-derived dossier hash readiness folds into its operation fingerprint.

    It is a digest over safe bindings + the exact live-preflight binding + the complete evidence
    fingerprint — never any real value. Its format differs from the fail-closed placeholder
    sentinel, so it can never equal it. A different or newer live preflight yields a different
    ``live_preflight_binding_hash`` and therefore a different dossier hash (amendment §3).
    """
    return _sha256(
        "|".join(
            (
                _DOSSIER_HASH_PREFIX,
                organization_id,
                execution_target_id,
                target_config_hash,
                target_onboarding_id,
                onboarding_boundary_hash,
                deployment_plan_id,
                deployment_plan_content_hash,
                environment_version_id,
                environment_version_content_hash,
                provisioning_manifest_id,
                provisioning_manifest_content_hash,
                toolchain_profile_id,
                toolchain_profile_hash,
                toolchain_attestation_id,
                toolchain_attestation_hash,
                worker_identity_registration_id,
                str(worker_identity_version),
                provider_credential_binding_id,
                str(provider_credential_binding_version),
                state_credential_binding_id,
                str(state_credential_binding_version),
                state_namespace_hash,
                str(dossier_revision),
                evidence_fingerprint,
                live_preflight_binding_hash,
            )
        )
    )


# The versioned provenance contract for the exact live preflight a dossier supplements (§3).
LIVE_PREFLIGHT_BINDING_VERSION = "secp-002b-1b-pr5a/dossier-preflight-binding/v1"


def live_preflight_binding_hash(
    *,
    preflight_id: str,
    evidence_hash: str,
    target_evidence_hash: str,
    evidence_source: str,
    verification_level: str,
    eligibility_outcome: str,
    eligibility_policy_version: str,
    source_policy_version: str,
    collector_contract_version: str,
    endpoint_allowlist_version: str,
    live_read_authorization_id: str,
    live_read_authorization_version: int,
    live_read_authorization_expiry: str,
    worker_identity_registration_id: str,
    worker_identity_version: int,
    target_config_hash: str,
    onboarding_id: str,
    onboarding_boundary_hash: str,
    collected_at: str,
    evidence_expires_at: str,
) -> str:
    """A digest binding the dossier to the EXACT live preflight it supplements (amendment §3).

    It pins the preflight id + both evidence hashes + source/verification level + outcome + every
    policy/contract/allowlist version + the live-read authorization identity/version/expiry + the
    worker identity + target/onboarding binding + collection/expiry timestamps. A changed or newer
    preflight, an altered evidence hash, drifted authorization/worker, or a policy-version bump all
    change this digest — so the dossier no longer matches the current preflight and is refused.
    """
    return _sha256(
        "|".join(
            (
                LIVE_PREFLIGHT_BINDING_VERSION,
                preflight_id,
                evidence_hash,
                target_evidence_hash,
                evidence_source,
                verification_level,
                eligibility_outcome,
                eligibility_policy_version,
                source_policy_version,
                collector_contract_version,
                endpoint_allowlist_version,
                live_read_authorization_id,
                str(live_read_authorization_version),
                live_read_authorization_expiry,
                worker_identity_registration_id,
                str(worker_identity_version),
                target_config_hash,
                onboarding_id,
                onboarding_boundary_hash,
                collected_at,
                evidence_expires_at,
            )
        )
    )


def plan_generation_operation_fingerprint(
    *,
    activation_dossier_hash: str,
    provisioning_manifest_content_hash: str,
    provider_credential_binding_id: str,
    provider_credential_binding_version: int,
    state_credential_binding_id: str,
    state_credential_binding_version: int,
    remote_state_evidence_hash: str,
    plan_secret_evidence_hash: str,
    plan_only_capability_contract_version: str,
) -> str:
    """The operation identity a plan-generation authorization binds (everything except itself)."""
    return _sha256(
        "|".join(
            (
                _PLAN_GEN_FINGERPRINT_PREFIX,
                PlanGenerationPurpose.plan_generation.value,
                activation_dossier_hash,
                provisioning_manifest_content_hash,
                provider_credential_binding_id,
                str(provider_credential_binding_version),
                state_credential_binding_id,
                str(state_credential_binding_version),
                remote_state_evidence_hash,
                plan_secret_evidence_hash,
                plan_only_capability_contract_version,
                PLAN_GENERATION_READINESS_POLICY_VERSION,
            )
        )
    )


def dossier_evidence_is_complete(items) -> bool:  # noqa: ANN001 - iterable of evidence rows
    """True iff every required review kind is present with status ``verified``."""
    verified = {
        str(getattr(e.kind, "value", e.kind))
        for e in items
        if str(getattr(e.status, "value", e.status))
        == ActivationDossierEvidenceStatus.verified.value
    }
    return {k.value for k in REQUIRED_DOSSIER_EVIDENCE_KINDS} <= verified


# =================================================================================================
# Combined plan-generation readiness (the pure, read-only helper — ADR-022 §3, task item 8)
# =================================================================================================


@dataclass(frozen=True)
class PlanGenerationReadinessStatus:
    """Whether PR5B may LATER generate a real plan. It is NOT plan approval and launches nothing.

    A ``ready`` status constructs no runner, no executor, and no activation grant; it renders
    nothing, resolves nothing, contacts nothing, enqueues nothing, and executes nothing.
    """

    ready: bool
    reasons: tuple[str, ...]
    activation_dossier_id: uuid.UUID | None = None
    plan_generation_authorization_id: uuid.UUID | None = None
    provider_credential_binding_id: uuid.UUID | None = None
    state_credential_binding_id: uuid.UUID | None = None
    remote_state_readiness_id: uuid.UUID | None = None
    plan_secret_readiness_id: uuid.UUID | None = None

    def as_dict(self) -> dict:
        def _opt(v):  # noqa: ANN001, ANN202
            return str(v) if v is not None else None

        return {
            "ready": self.ready,
            "reasons": list(self.reasons),
            "activation_dossier_id": _opt(self.activation_dossier_id),
            "plan_generation_authorization_id": _opt(self.plan_generation_authorization_id),
            "provider_credential_binding_id": _opt(self.provider_credential_binding_id),
            "state_credential_binding_id": _opt(self.state_credential_binding_id),
            "remote_state_readiness_id": _opt(self.remote_state_readiness_id),
            "plan_secret_readiness_id": _opt(self.plan_secret_readiness_id),
            "readiness_policy_version": PLAN_GENERATION_READINESS_POLICY_VERSION,
        }


def _active_binding(session: Session, target_id, purpose):  # noqa: ANN001, ANN202
    from secp_api.credential_binding import active_credential_binding

    return active_credential_binding(session, target_id, purpose)


def plan_generation_readiness_status(  # noqa: C901, PLR0911, PLR0912, PLR0915
    session: Session, manifest, *, now: datetime
) -> PlanGenerationReadinessStatus:
    """Derive whether EVERY real-plan gate is currently satisfied for one manifest (ADR-022 §3).

    ``ready`` requires ALL of, exact and current: eligible live PR3 evidence; a current toolchain
    attestation; current remote-state readiness; current provider-plan secret readiness; a current,
    separately-reviewed state-backend credential binding (its own dossier evidence + three-way
    agreement); a current worker identity; an APPROVED, non-placeholder, unexpired,
    complete-evidence
    activation dossier; an APPROVED, unexpired, unconsumed plan-generation authorization bound to
    the
    exact plan-only capability contract version; the provider AND state credential bindings agreeing
    across target == manifest == dossier; and every policy/contract version + expiry.

    Passing does NOT approve a plan, enqueue PR5B, construct a runner/executor, mint a grant,
    render,
    resolve a credential, or execute a process.
    """
    from sqlalchemy import select

    from secp_api.plan_activation_models import (
        RealLabActivationDossier,
        RealPlanGenerationAuthorization,
    )
    from secp_api.readiness_binding import load_readiness_binding
    from secp_api.readiness_contract import as_utc, is_placeholder_dossier

    reasons: list[str] = []

    # 1. The active APPROVED activation dossier (a non-placeholder, unexpired, complete dossier).
    dossier = (
        session.execute(
            select(RealLabActivationDossier).where(
                RealLabActivationDossier.provisioning_manifest_id == manifest.id,
                RealLabActivationDossier.status.in_(
                    (ActivationDossierStatus.draft, ActivationDossierStatus.approved)
                ),
            )
        )
        .scalars()
        .one_or_none()
    )
    if dossier is None:
        return PlanGenerationReadinessStatus(
            ready=False, reasons=(_R.activation_dossier_missing.value,)
        )
    if dossier.status != ActivationDossierStatus.approved:
        reasons.append(_R.activation_dossier_not_approved.value)
    if as_utc(dossier.authorization_expiry) <= now:
        reasons.append(_R.activation_dossier_expired.value)
    if is_placeholder_dossier(dossier.dossier_hash):
        reasons.append(_R.activation_dossier_binding_invalid.value)
    if not dossier_evidence_is_complete(dossier.evidence):
        reasons.append(_R.activation_dossier_evidence_incomplete.value)

    # 1b. The dossier's bound live preflight must still be the CURRENT one (amendment §3). A new or
    #     changed preflight (different id or evidence hash) invalidates the dossier for current use.
    from secp_api.models import TargetOnboarding
    from secp_api.services.eligibility import evaluate_live_eligibility

    onboarding = (
        session.get(TargetOnboarding, manifest.target_onboarding_id)
        if manifest.target_onboarding_id
        else None
    )
    live = (
        evaluate_live_eligibility(session, onboarding, now=now) if onboarding is not None else None
    )
    if (
        live is None
        or dossier.eligibility_preflight_id is None
        or live.preflight.id != dossier.eligibility_preflight_id
        or live.preflight.evidence_hash != dossier.eligibility_evidence_hash
    ):
        reasons.append(_R.activation_dossier_preflight_drift.value)

    # 2. The authoritative readiness binding, re-derived with the DOSSIER's real hash. This enforces
    #    eligible live evidence, the durable attestation, current state + plan-secret readiness, the
    #    provider credential binding, worker identity, and every upstream hash — failing closed with
    #    the exact reason.
    result = load_readiness_binding(
        session,
        manifest_id=manifest.id,
        operation_kind=ReadinessOperationKind.plan_secret_readiness,
        now=now,
        activation_dossier_hash=dossier.dossier_hash,
    )
    if result.binding is None:
        reasons.append((result.reason or _R.combined_plan_readiness_incomplete).value)
        return PlanGenerationReadinessStatus(
            ready=False,
            reasons=tuple(dict.fromkeys(reasons)),
            activation_dossier_id=dossier.id,
        )

    binding = result.binding
    state_readiness = result.state_readiness
    provider_binding = result.credential_binding
    assert state_readiness is not None and provider_binding is not None  # noqa: S101

    # 3. The plan-secret readiness record for THIS exact fingerprint must be current + ready.
    from secp_api.models import PlanSecretReadinessRecord

    secret_record = (
        session.execute(
            select(PlanSecretReadinessRecord).where(
                PlanSecretReadinessRecord.provisioning_manifest_id == manifest.id,
                PlanSecretReadinessRecord.operation_fingerprint == binding.operation_fingerprint(),
            )
        )
        .scalars()
        .one_or_none()
    )
    if secret_record is None or secret_record.outcome != PlanSecretReadinessOutcome.ready:
        reasons.append(_R.provider_secret_readiness_not_current.value)
    elif as_utc(secret_record.expires_at) <= now:
        reasons.append(_R.provider_secret_readiness_not_current.value)

    # 4. Remote-state readiness must itself be current + ready + unexpired.
    if state_readiness.outcome != RemoteStateReadinessOutcome.ready:
        reasons.append(_R.remote_state_readiness_not_current.value)
    if as_utc(state_readiness.expires_at) <= now:
        reasons.append(_R.remote_state_readiness_not_current.value)

    # 5. The SEPARATE state-backend credential binding — current + three-way agreement.
    state_binding = _active_binding(
        session, manifest.execution_target_id, CredentialPurposeClass.state_backend_plan
    )
    if state_binding is None:
        reasons.append(_R.state_credential_binding_missing.value)

    # 5b. The STRICT real-plan credential gate (amendment §1): both provider and state bindings must
    #     be dedicated_operation, sourced from distinct dedicated references — never the generic
    #     secret_ref fallback, never a shared reference, never a legacy-sourced binding.
    from secp_api.credential_binding import RealPlanCredentialError, real_plan_credential_bindings
    from secp_api.models import ExecutionTarget

    target = session.get(ExecutionTarget, manifest.execution_target_id)
    if target is None:
        reasons.append(_R.real_plan_credentials_not_dedicated.value)
    else:
        try:
            real_plan_credential_bindings(session, target)
        except RealPlanCredentialError:
            reasons.append(_R.real_plan_credentials_not_dedicated.value)

    # 6. THREE-WAY credential agreement: target == manifest == dossier (both purposes).
    _check_three_way(manifest, dossier, provider_binding, state_binding, reasons)

    # 7. The state-backend "secret readiness" is proven by: a reviewed state credential (its dossier
    #    evidence is in the complete set above), a current bound state credential, and a current
    #    remote-state readiness (the backend it points at). If any is missing, mark unproven.
    if state_binding is None or state_readiness.outcome != RemoteStateReadinessOutcome.ready:
        reasons.append(_R.state_secret_readiness_unproven.value)

    # 8. The APPROVED, unexpired, unconsumed plan-generation authorization bound to this operation.
    authorization = (
        session.execute(
            select(RealPlanGenerationAuthorization).where(
                RealPlanGenerationAuthorization.provisioning_manifest_id == manifest.id,
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
    if authorization is None:
        reasons.append(_R.plan_generation_authorization_missing.value)
    else:
        _check_authorization(
            authorization,
            dossier=dossier,
            state_readiness=state_readiness,
            secret_record=secret_record,
            provider_binding=provider_binding,
            state_binding=state_binding,
            now=now,
            reasons=reasons,
        )

    return PlanGenerationReadinessStatus(
        ready=not reasons,
        reasons=tuple(dict.fromkeys(reasons)),
        activation_dossier_id=dossier.id,
        plan_generation_authorization_id=authorization.id if authorization is not None else None,
        provider_credential_binding_id=provider_binding.id,
        state_credential_binding_id=state_binding.id if state_binding is not None else None,
        remote_state_readiness_id=state_readiness.id,
        plan_secret_readiness_id=secret_record.id if secret_record is not None else None,
    )


def _check_three_way(manifest, dossier, provider_binding, state_binding, reasons) -> None:  # noqa: ANN001
    """target == manifest == dossier, for BOTH the provider and state credential bindings."""
    # provider
    if (
        manifest.provider_credential_binding_id is None
        or manifest.provider_credential_binding_id != provider_binding.id
        or manifest.provider_credential_binding_version != provider_binding.binding_version
    ):
        reasons.append(_R.credential_binding_manifest_mismatch.value)
    if (
        dossier.provider_credential_binding_id != provider_binding.id
        or dossier.provider_credential_binding_version != provider_binding.binding_version
    ):
        reasons.append(_R.credential_binding_dossier_mismatch.value)
    # state
    if state_binding is not None:
        if (
            manifest.state_credential_binding_id is None
            or manifest.state_credential_binding_id != state_binding.id
            or manifest.state_credential_binding_version != state_binding.binding_version
        ):
            reasons.append(_R.credential_binding_manifest_mismatch.value)
        if (
            dossier.state_credential_binding_id != state_binding.id
            or dossier.state_credential_binding_version != state_binding.binding_version
        ):
            reasons.append(_R.credential_binding_dossier_mismatch.value)


def _check_authorization(  # noqa: C901, PLR0912
    authorization,
    *,
    dossier,
    state_readiness,
    secret_record,
    provider_binding,
    state_binding,
    now,
    reasons,  # noqa: ANN001, E501
) -> None:
    from secp_api.readiness_contract import as_utc

    if authorization.status != PlanGenerationAuthorizationStatus.approved:
        reasons.append(_R.plan_generation_authorization_not_approved.value)
    if authorization.status == PlanGenerationAuthorizationStatus.consumed:
        reasons.append(_R.plan_generation_authorization_consumed.value)
    if as_utc(authorization.authorization_expiry) <= now:
        reasons.append(_R.plan_generation_authorization_expired.value)
    if authorization.purpose != PlanGenerationPurpose.plan_generation.value:
        reasons.append(_R.plan_generation_authorization_drifted.value)
    if authorization.plan_only_capability_contract_version != PLAN_ONLY_CAPABILITY_CONTRACT_VERSION:
        reasons.append(_R.plan_only_capability_contract_mismatch.value)
    if authorization.activation_dossier_id != dossier.id:
        reasons.append(_R.plan_generation_authorization_drifted.value)
    if authorization.activation_dossier_hash != dossier.dossier_hash:
        reasons.append(_R.plan_generation_authorization_drifted.value)
    if authorization.remote_state_readiness_id != state_readiness.id:
        reasons.append(_R.plan_generation_authorization_drifted.value)
    if secret_record is not None and authorization.plan_secret_readiness_id != secret_record.id:
        reasons.append(_R.plan_generation_authorization_drifted.value)
    if (
        authorization.provider_credential_binding_id != provider_binding.id
        or authorization.provider_credential_binding_version != provider_binding.binding_version
    ):
        reasons.append(_R.provider_credential_binding_drift.value)
    if state_binding is not None and (
        authorization.state_credential_binding_id != state_binding.id
        or authorization.state_credential_binding_version != state_binding.binding_version
    ):
        reasons.append(_R.state_credential_binding_drift.value)
    if not authorization.evidence_fingerprint:
        reasons.append(_R.plan_generation_authorization_drifted.value)
