"""Plan-only execution lease + attempt lifecycle (B1B-PR5B, ADR-022 §8) — worker-only.

Assembles the complete authoritative execution binding from the database (never from a caller), then
provides the durable CAS lease + attempt-lifecycle operations:

* :func:`assemble_execution_binding` — re-derives every authoritative fact for one manifest, or
  returns a closed refusal reason (it reuses the combined readiness gate);
* :func:`acquire_execution_lease` — database-backed CAS acquisition of the single active lease per
  operation fingerprint, carrying the fixed shared attempt budget (an expired-lease recovery never
  resets it);
* :func:`begin_attempt` — records a ``running`` attempt and increments ``attempts_used`` BEFORE any
  secret-manager contact;
* :func:`consume_lease` / :func:`fail_attempt` / :func:`require_recovery` — the guarded terminal
  transitions. Uncertain process termination becomes ``recovery_required`` (no automatic retry, no
  force-unlock); a replay after a successful result returns the existing result with no execution.

Nothing here contacts a target, resolves a secret, renders a workspace, or constructs a process.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from secp_api.enums import (
    CredentialPurposeClass,
    PlanExecutionLeaseStatus,
    PlanGenerationAttemptStatus,
    ReadinessReason,
)
from secp_api.models import ProvisioningManifest
from secp_api.plan_activation_contract import plan_generation_readiness_status
from secp_api.plan_activation_models import (
    PLAN_EXECUTION_ATTEMPT_BUDGET,
    PlanGenerationExecutionLease,
    RealPlanGenerationAttempt,
    RealPlanGenerationResult,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

_R = ReadinessReason
_DEFAULT_LEASE_TTL = timedelta(minutes=10)


def _as_utc(value):  # noqa: ANN001, ANN202
    from secp_api.readiness_contract import as_utc

    return as_utc(value)


@dataclass(frozen=True)
class ExecutionBinding:
    """Every authoritative fact one plan-only execution binds (opaque ids + hashes only)."""

    organization_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    authorization_expiry: datetime
    provisioning_manifest_id: uuid.UUID
    provisioning_manifest_content_hash: str
    deployment_plan_id: uuid.UUID
    deployment_plan_content_hash: str
    environment_version_id: uuid.UUID
    environment_version_content_hash: str
    execution_target_id: uuid.UUID
    target_config_hash: str
    target_onboarding_id: uuid.UUID
    onboarding_boundary_hash: str
    activation_dossier_id: uuid.UUID
    activation_dossier_hash: str
    activation_dossier_revision: int
    activation_dossier_expiry: datetime
    eligibility_preflight_id: uuid.UUID
    eligibility_evidence_hash: str
    toolchain_profile_id: uuid.UUID
    toolchain_profile_hash: str
    toolchain_attestation_id: uuid.UUID
    toolchain_attestation_hash: str
    toolchain_attestation_policy_version: str
    worker_identity_registration_id: uuid.UUID
    worker_identity_version: int
    provider_credential_binding_id: uuid.UUID
    provider_credential_binding_version: int
    state_credential_binding_id: uuid.UUID
    state_credential_binding_version: int
    remote_state_readiness_id: uuid.UUID
    remote_state_evidence_hash: str
    plan_secret_readiness_id: uuid.UUID
    plan_secret_evidence_hash: str
    state_namespace_hash: str
    operation_fingerprint: str


def assemble_execution_binding(
    session: Session, manifest: ProvisioningManifest, *, now: datetime
) -> tuple[ExecutionBinding | None, str | None]:
    """Re-derive every authoritative execution fact for one manifest, or a closed refusal reason."""
    from secp_api.credential_binding import active_credential_binding
    from secp_api.models import (
        DeploymentPlan,
        PlanSecretReadinessRecord,
        RemoteStateReadinessRecord,
    )
    from secp_api.plan_activation_models import RealLabActivationDossier
    from secp_api.readiness_binding import load_readiness_binding
    from secp_api.readiness_contract import ReadinessOperationKind
    from secp_api.services.plan_activation import active_plan_generation_authorization

    status = plan_generation_readiness_status(session, manifest, now=now)
    if not status.ready:
        return None, (
            status.reasons[0] if status.reasons else _R.combined_plan_readiness_incomplete.value
        )

    dossier = session.get(RealLabActivationDossier, status.activation_dossier_id)
    authorization = active_plan_generation_authorization(session, manifest.id)
    if dossier is None or authorization is None:
        return None, _R.combined_plan_readiness_incomplete.value

    result = load_readiness_binding(
        session,
        manifest_id=manifest.id,
        operation_kind=ReadinessOperationKind.plan_secret_readiness,
        now=now,
        activation_dossier_hash=dossier.dossier_hash,
    )
    if result.binding is None:
        return None, (result.reason or _R.combined_plan_readiness_incomplete).value
    binding = result.binding
    plan = session.get(DeploymentPlan, manifest.deployment_plan_id)
    state_binding = active_credential_binding(
        session, manifest.execution_target_id, CredentialPurposeClass.state_backend_plan
    )
    provider_binding = result.credential_binding
    state_readiness = session.get(RemoteStateReadinessRecord, status.remote_state_readiness_id)
    secret_readiness = session.get(PlanSecretReadinessRecord, status.plan_secret_readiness_id)
    if None in (plan, state_binding, provider_binding, state_readiness, secret_readiness):
        return None, _R.combined_plan_readiness_incomplete.value
    assert plan is not None and state_binding is not None and provider_binding is not None  # noqa: S101
    assert state_readiness is not None and secret_readiness is not None  # noqa: S101

    execution = ExecutionBinding(
        organization_id=manifest.organization_id,
        authorization_id=authorization.id,
        authorization_version=authorization.authorization_version,
        authorization_expiry=authorization.authorization_expiry,
        provisioning_manifest_id=manifest.id,
        provisioning_manifest_content_hash=manifest.content_hash,
        deployment_plan_id=plan.id,
        deployment_plan_content_hash=binding.deployment_plan_content_hash,
        environment_version_id=uuid.UUID(binding.environment_version_id),
        environment_version_content_hash=binding.environment_version_content_hash,
        execution_target_id=manifest.execution_target_id,
        target_config_hash=binding.target_config_hash,
        target_onboarding_id=uuid.UUID(binding.target_onboarding_id),
        onboarding_boundary_hash=binding.onboarding_boundary_hash,
        activation_dossier_id=dossier.id,
        activation_dossier_hash=dossier.dossier_hash,
        activation_dossier_revision=dossier.dossier_revision,
        activation_dossier_expiry=dossier.authorization_expiry,
        eligibility_preflight_id=uuid.UUID(binding.eligibility_preflight_id),
        eligibility_evidence_hash=binding.eligibility_evidence_hash,
        toolchain_profile_id=uuid.UUID(binding.toolchain_profile_id),
        toolchain_profile_hash=binding.toolchain_profile_hash,
        toolchain_attestation_id=uuid.UUID(binding.toolchain_attestation_id),
        toolchain_attestation_hash=binding.toolchain_attestation_hash,
        toolchain_attestation_policy_version=binding.toolchain_attestation_policy_version,
        worker_identity_registration_id=uuid.UUID(binding.worker_identity_registration_id),
        worker_identity_version=binding.worker_identity_version,
        provider_credential_binding_id=provider_binding.id,
        provider_credential_binding_version=provider_binding.binding_version,
        state_credential_binding_id=state_binding.id,
        state_credential_binding_version=state_binding.binding_version,
        remote_state_readiness_id=state_readiness.id,
        remote_state_evidence_hash=state_readiness.evidence_hash,
        plan_secret_readiness_id=secret_readiness.id,
        plan_secret_evidence_hash=secret_readiness.evidence_hash,
        state_namespace_hash=binding.state_namespace_identity,
        operation_fingerprint=authorization.operation_fingerprint,
    )
    return execution, None


def existing_successful_result(
    session: Session, binding: ExecutionBinding
) -> RealPlanGenerationResult | None:
    """The prior successful result for this exact operation (replay returns it, no execution)."""
    return (
        session.execute(
            select(RealPlanGenerationResult).where(
                RealPlanGenerationResult.authorization_id == binding.authorization_id,
                RealPlanGenerationResult.authorization_version == binding.authorization_version,
                RealPlanGenerationResult.operation_fingerprint == binding.operation_fingerprint,
            )
        )
        .scalars()
        .one_or_none()
    )


def _next_lease_epoch(session: Session, binding: ExecutionBinding) -> int:
    from sqlalchemy import func

    current = session.execute(
        select(func.max(PlanGenerationExecutionLease.lease_epoch)).where(
            PlanGenerationExecutionLease.authorization_id == binding.authorization_id,
            PlanGenerationExecutionLease.authorization_version == binding.authorization_version,
            PlanGenerationExecutionLease.operation_fingerprint == binding.operation_fingerprint,
        )
    ).scalar()
    return int(current or 0) + 1


def active_lease(
    session: Session, binding: ExecutionBinding
) -> PlanGenerationExecutionLease | None:
    return (
        session.execute(
            select(PlanGenerationExecutionLease).where(
                PlanGenerationExecutionLease.operation_fingerprint == binding.operation_fingerprint,
                PlanGenerationExecutionLease.status == PlanExecutionLeaseStatus.active,
            )
        )
        .scalars()
        .one_or_none()
    )


def _has_recovery_required_lease(session: Session, binding: ExecutionBinding) -> bool:
    from sqlalchemy import func

    count = session.execute(
        select(func.count())
        .select_from(PlanGenerationExecutionLease)
        .where(
            PlanGenerationExecutionLease.operation_fingerprint == binding.operation_fingerprint,
            PlanGenerationExecutionLease.status == PlanExecutionLeaseStatus.recovery_required,
        )
    ).scalar()
    return int(count or 0) > 0


def acquire_execution_lease(
    session: Session,
    binding: ExecutionBinding,
    *,
    lease_owner: str,
    now: datetime,
    ttl: timedelta = _DEFAULT_LEASE_TTL,
) -> tuple[PlanGenerationExecutionLease | None, str | None]:
    """Database-backed CAS acquisition of the single active lease for this operation fingerprint.

    Returns ``(lease, None)`` on success. If a live active lease already holds the operation, the
    shared attempt budget is exhausted, or a prior lease is terminally ``recovery_required``,
    returns
    ``(None, reason)`` — never a second live lease. A stale active lease (past its
    ``lease_expires_at``) is recovered under a guarded transition that PRESERVES its attempt count;
    a
    fresh epoch is then acquired without resetting the shared budget. On the losing side of a CAS
    race
    only the acquisition SAVEPOINT is rolled back — never the surrounding worker audit /
    authoritative
    load / attempt work.
    """
    # A terminally recovery-required prior lease is non-retryable until a new authorization version
    # mints a distinct operation key.
    if _has_recovery_required_lease(session, binding):
        return None, "lease_recovery_required"

    existing = active_lease(session, binding)
    if existing is not None:
        if _as_utc(existing.lease_expires_at) > now:
            return None, "lease_contended"
        # STALE active lease: recover it (guarded active->expired), preserving its attempt count, so
        # the partial-active index is freed and the shared budget is unchanged.
        existing.status = PlanExecutionLeaseStatus.expired
        try:
            session.flush()
        except IntegrityError:  # another worker recovered it first
            session.rollback()
            return None, "lease_contended"

    # Budget: sum attempts_used across ALL prior leases for this operation key (shared, never
    # reset).
    from sqlalchemy import func

    prior_used = session.execute(
        select(func.coalesce(func.sum(PlanGenerationExecutionLease.attempts_used), 0)).where(
            PlanGenerationExecutionLease.authorization_id == binding.authorization_id,
            PlanGenerationExecutionLease.authorization_version == binding.authorization_version,
            PlanGenerationExecutionLease.operation_fingerprint == binding.operation_fingerprint,
        )
    ).scalar()
    if int(prior_used or 0) >= PLAN_EXECUTION_ATTEMPT_BUDGET:
        return None, "lease_budget_exhausted"

    lease = PlanGenerationExecutionLease(
        id=uuid.uuid4(),
        organization_id=binding.organization_id,
        authorization_id=binding.authorization_id,
        authorization_version=binding.authorization_version,
        authorization_expiry=binding.authorization_expiry,
        provisioning_manifest_id=binding.provisioning_manifest_id,
        provisioning_manifest_content_hash=binding.provisioning_manifest_content_hash,
        deployment_plan_id=binding.deployment_plan_id,
        environment_version_id=binding.environment_version_id,
        execution_target_id=binding.execution_target_id,
        target_config_hash=binding.target_config_hash,
        target_onboarding_id=binding.target_onboarding_id,
        onboarding_boundary_hash=binding.onboarding_boundary_hash,
        activation_dossier_id=binding.activation_dossier_id,
        activation_dossier_hash=binding.activation_dossier_hash,
        activation_dossier_revision=binding.activation_dossier_revision,
        eligibility_preflight_id=binding.eligibility_preflight_id,
        eligibility_evidence_hash=binding.eligibility_evidence_hash,
        toolchain_profile_id=binding.toolchain_profile_id,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        toolchain_attestation_id=binding.toolchain_attestation_id,
        toolchain_attestation_hash=binding.toolchain_attestation_hash,
        worker_identity_registration_id=binding.worker_identity_registration_id,
        worker_identity_version=binding.worker_identity_version,
        provider_credential_binding_id=binding.provider_credential_binding_id,
        provider_credential_binding_version=binding.provider_credential_binding_version,
        state_credential_binding_id=binding.state_credential_binding_id,
        state_credential_binding_version=binding.state_credential_binding_version,
        remote_state_readiness_id=binding.remote_state_readiness_id,
        remote_state_evidence_hash=binding.remote_state_evidence_hash,
        plan_secret_readiness_id=binding.plan_secret_readiness_id,
        plan_secret_evidence_hash=binding.plan_secret_evidence_hash,
        operation_fingerprint=binding.operation_fingerprint,
        lease_epoch=_next_lease_epoch(session, binding),
        lease_owner=lease_owner[:80],
        lease_expires_at=now + ttl,
        attempt_budget=PLAN_EXECUTION_ATTEMPT_BUDGET,
        attempts_used=0,
        status=PlanExecutionLeaseStatus.active,
        acquired_at=now,
    )
    # Acquire under a SAVEPOINT so a lost CAS race rolls back ONLY this insert — never the
    # surrounding
    # authoritative-load / audit / attempt work in the same transaction.
    try:
        with session.begin_nested():
            session.add(lease)
            session.flush()
    except IntegrityError:
        # Lost the CAS race against a concurrent worker (the active partial-unique index fired).
        return None, "lease_contended"
    return lease, None


def begin_attempt(
    session: Session,
    lease: PlanGenerationExecutionLease,
    binding: ExecutionBinding,
    *,
    now: datetime,
) -> RealPlanGenerationAttempt:
    """Record a ``running`` attempt and increment the shared budget BEFORE any secret contact."""
    lease.attempts_used += 1
    attempt = RealPlanGenerationAttempt(
        id=uuid.uuid4(),
        organization_id=binding.organization_id,
        authorization_id=binding.authorization_id,
        authorization_version=binding.authorization_version,
        execution_target_id=binding.execution_target_id,
        deployment_plan_id=binding.deployment_plan_id,
        provisioning_manifest_id=binding.provisioning_manifest_id,
        target_onboarding_id=binding.target_onboarding_id,
        activation_dossier_id=binding.activation_dossier_id,
        operation_fingerprint=binding.operation_fingerprint,
        status=PlanGenerationAttemptStatus.running,
        refusal_reason_code="",
        collected_at=now,
    )
    session.add(attempt)
    session.flush()
    return attempt


def fail_attempt(
    session: Session,
    lease: PlanGenerationExecutionLease,
    attempt: RealPlanGenerationAttempt,
    *,
    reason_code: str,
    now: datetime,
) -> None:
    """Mark a running attempt ``failed`` and expire the lease (budget is preserved, never reset)."""
    attempt.status = PlanGenerationAttemptStatus.failed
    attempt.refusal_reason_code = reason_code[:80]
    if lease.status == PlanExecutionLeaseStatus.active:
        lease.status = PlanExecutionLeaseStatus.expired
    session.flush()


def require_recovery(
    session: Session,
    lease: PlanGenerationExecutionLease,
    attempt: RealPlanGenerationAttempt,
    *,
    reason_code: str,
    now: datetime,
) -> None:
    """Uncertain termination / cleanup residue: ``recovery_required`` (terminal, no auto-retry)."""
    attempt.status = PlanGenerationAttemptStatus.recovery_required
    attempt.refusal_reason_code = reason_code[:80]
    if lease.status == PlanExecutionLeaseStatus.active:
        lease.recovery_reason_code = reason_code[:80]
        lease.status = PlanExecutionLeaseStatus.recovery_required
    session.flush()


def consume_lease(
    session: Session,
    lease: PlanGenerationExecutionLease,
    attempt: RealPlanGenerationAttempt,
    *,
    result_id: uuid.UUID | None,
    now: datetime,
) -> None:
    """Consume the lease AFTER a durable result (or a proven test-only run); complete attempt."""
    attempt.status = PlanGenerationAttemptStatus.completed
    if lease.status == PlanExecutionLeaseStatus.active:
        lease.result_id = result_id
        lease.consumed_at = now
        lease.status = PlanExecutionLeaseStatus.consumed
    session.flush()
