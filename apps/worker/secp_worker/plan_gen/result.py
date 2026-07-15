"""Durable plan-only result + pending exact-hash approval (B1B-PR5B, ADR-022 §6/§7) — worker-only.

On a successful controlled-live plan-only run, this persists the durable, immutable, redacted
canonical change set + its exact ``change_set_hash`` and wires a PENDING, human-only
:class:`ProvisioningChangeSetApproval` for a PROSPECTIVE apply — derived entirely server-side from
the immutable result. It is exactly-once (a replay returns the existing result without any process
execution) and NEVER auto-approves. Approving the change set enqueues no PR6, calls no
apply/destroy,
and issues no apply capability; both B1-A seals stay ``True``, so apply remains technically
impossible regardless.

A ``test_only`` capability (the inert-fixture path) can NEVER reach this: it is refused before any
durable controlled-live result or real pending approval is created.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from secp_api import audit
from secp_api.enums import AuditAction, PlanGenerationResultStatus, ProvisioningOperationKind
from secp_api.models import ProvisioningManifest, ToolchainProfile
from secp_api.plan_activation_models import RealPlanGenerationResult
from secp_api.services.approvals import record_change_set
from sqlalchemy.orm import Session

from secp_worker.plan_gen.capability import PlanOnlyCapability
from secp_worker.plan_gen.lease import (
    ExecutionBinding,
    consume_lease,
    existing_successful_result,
)
from secp_worker.plan_gen.plan_runner import PlanOnlyPlanResult


class PlanResultRefused(Exception):
    """A controlled-live durable result may not be produced (bounded reason code)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _verify_result_provenance(activation, binding, lease, attempt, plan_result) -> None:  # noqa: ANN001, PLR0913
    """Refuse unless capability, binding, lease, attempt and plan-result provenance all agree."""
    checks = (
        str(activation.execution_lease_id) == str(lease.id),
        str(activation.attempt_id) == str(attempt.id),
        int(activation.attempt_number) == int(lease.attempts_used),
        activation.operation_fingerprint == binding.operation_fingerprint,
        str(activation.plan_generation_authorization_id) == str(binding.authorization_id),
        int(activation.authorization_version) == int(binding.authorization_version),
        activation.provisioning_manifest_content_hash == binding.provisioning_manifest_content_hash,
        str(activation.provider_credential_binding_id)
        == str(binding.provider_credential_binding_id),
        int(activation.provider_credential_binding_version)
        == int(binding.provider_credential_binding_version),
        str(activation.state_credential_binding_id) == str(binding.state_credential_binding_id),
        int(activation.state_credential_binding_version)
        == int(binding.state_credential_binding_version),
        str(activation.activation_dossier_hash) == str(binding.activation_dossier_hash),
    )
    if not all(checks):
        raise PlanResultRefused("result_provenance_mismatch")
    # The plan-result's own folded provenance must bind the exact operation fingerprint + policy.
    prov = (
        plan_result.change_set.get("provenance")
        if isinstance(plan_result.change_set, dict)
        else None
    )
    if not isinstance(prov, dict):
        raise PlanResultRefused("result_provenance_mismatch")
    if prov.get("operation_fingerprint") != binding.operation_fingerprint:
        raise PlanResultRefused("result_provenance_mismatch")
    if prov.get("change_policy_version") != plan_result.change_policy_version:
        raise PlanResultRefused("result_provenance_mismatch")


def record_plan_generation_result(
    session: Session,
    *,
    binding: ExecutionBinding,
    capability: PlanOnlyCapability,
    plan_result: PlanOnlyPlanResult,
    lease,  # PlanGenerationExecutionLease  # noqa: ANN001
    attempt,  # RealPlanGenerationAttempt  # noqa: ANN001
    manifest: ProvisioningManifest,
    toolchain_profile: ToolchainProfile,
    now: datetime,
) -> RealPlanGenerationResult:
    """Persist the durable controlled-live result + a pending exact-hash approval (exactly-once).

    Refuses a ``test_only`` capability. On a replay (a prior successful result for the exact
    ``(authorization, version, operation fingerprint)``) it returns the existing result and creates
    no second process execution.
    """
    activation = capability.activation
    if not capability.is_controlled_live:
        # The inert-fixture / test-only path can never produce a controlled-live durable result.
        raise PlanResultRefused("test_only_cannot_produce_controlled_live_result")

    # Independently compare the capability / binding / lease / attempt / plan-result provenance
    # BEFORE
    # persistence (defence in depth — the result is not trusted to be internally consistent).
    _verify_result_provenance(activation, binding, lease, attempt, plan_result)

    # Exactly-once: a prior successful result short-circuits (replay returns it, no execution).
    existing = existing_successful_result(session, binding)
    if existing is not None:
        return existing

    # A PENDING, human-only approval for a PROSPECTIVE apply, keyed on the EXACT change-set hash.
    approval = record_change_set(
        session,
        manifest,
        toolchain_profile,
        authorizes_kind=ProvisioningOperationKind.apply,
        change_set_hash=plan_result.change_set_hash,
        rendered_workspace_hash=plan_result.workspace_hash,
        summary=dict(plan_result.change_set.get("summary", {})),
        created_by=None,
    )

    result = RealPlanGenerationResult(
        id=uuid.uuid4(),
        organization_id=binding.organization_id,
        attempt_id=attempt.id,
        execution_lease_id=lease.id,
        authorization_id=binding.authorization_id,
        authorization_version=binding.authorization_version,
        provisioning_manifest_id=binding.provisioning_manifest_id,
        provisioning_manifest_content_hash=binding.provisioning_manifest_content_hash,
        deployment_plan_id=binding.deployment_plan_id,
        deployment_plan_content_hash=binding.deployment_plan_content_hash,
        environment_version_id=binding.environment_version_id,
        environment_version_content_hash=binding.environment_version_content_hash,
        execution_target_id=binding.execution_target_id,
        target_config_hash=binding.target_config_hash,
        target_onboarding_id=binding.target_onboarding_id,
        onboarding_boundary_hash=binding.onboarding_boundary_hash,
        activation_dossier_id=binding.activation_dossier_id,
        activation_dossier_hash=binding.activation_dossier_hash,
        eligibility_preflight_id=binding.eligibility_preflight_id,
        eligibility_evidence_hash=binding.eligibility_evidence_hash,
        toolchain_profile_id=binding.toolchain_profile_id,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        toolchain_attestation_id=binding.toolchain_attestation_id,
        toolchain_attestation_hash=binding.toolchain_attestation_hash,
        fresh_attestation_evidence_hash=activation.fresh_attestation_evidence_hash,
        provider_source=activation.provider_source,
        provider_version=activation.provider_version,
        provider_lockfile_hash=activation.provider_lockfile_hash,
        provider_mirror_identity=activation.provider_mirror_identity,
        module_bundle_hash=activation.module_bundle_hash,
        renderer_version=activation.renderer_version,
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
        change_set=plan_result.change_set,
        change_set_hash=plan_result.change_set_hash,
        workspace_hash=plan_result.workspace_hash,
        change_summary={
            "created": plan_result.created,
            "resource_types": list(plan_result.resource_types),
        },
        change_policy_version=plan_result.change_policy_version,
        change_policy_outcome="create_only",
        plan_only_capability_contract_version=activation.plan_only_capability_contract_version,
        operation_fingerprint=binding.operation_fingerprint,
        change_set_approval_id=approval.id,
        status=PlanGenerationResultStatus.pending_approval,
        generated_at=now,
    )
    session.add(result)
    session.flush()

    # Consume the lease (bind the result) and complete the attempt — only AFTER the result +
    # pending approval are committed to this transaction.
    consume_lease(session, lease, attempt, result_id=result.id, now=now)

    audit.record(
        session,
        action=AuditAction.plan_execution_change_set_recorded,
        resource_type="real_plan_generation_result",
        resource_id=result.id,
        organization_id=binding.organization_id,
        actor="worker",
        data={
            "operation_fingerprint": binding.operation_fingerprint,
            "change_set_hash": plan_result.change_set_hash,
            "created": plan_result.created,
            "change_set_approval_id": str(approval.id),
        },
    )
    return result
