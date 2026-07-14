"""Worker-only immutable readiness-evidence persistence (B1B-PR4 / ADR-021 §F, §L).

Structurally worker-originated: this module lives in the worker package and the API **cannot import
it** (the architecture-boundary lock forbids API→worker imports outside the dispatch seam and
name-forbids these symbols). It takes a TYPED evaluation — never a caller-supplied evidence dict —
so a hand-crafted payload can never become durable readiness evidence.

It persists ONLY safe evidence: bounded facet names + statuses, bounded reason codes, an opaque
backend BINDING HASH, an opaque NAMESPACE hash, opaque external proof ids, the resolver / self-test
/
env / policy / adapter versions, safe hashes, timestamps, an expiry, and an evidence hash.

It NEVER persists: a state body, state JSON, state metadata containing resource identities, an
object key, a backend URL, a bucket / container name, an account id, an access key, a token, a
provider body, a lock payload, a secret, a secret reference, a hash of a secret reference, an
endpoint, a namespace name, a backend response body, an environment variable value, or exception
detail.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    PlanSecretReadinessOutcome,
    ReadinessCapabilityClass,
    ReadinessOperationKind,
    RemoteStateReadinessOutcome,
)
from secp_api.models import (
    PlanSecretReadinessRecord,
    RemoteStateReadinessRecord,
)
from secp_api.readiness_contract import (
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_FACETS,
    MAX_EVIDENCE_REASONS,
    PLAN_SECRET_ENV_CONTRACT_VERSION,
    PLAN_SECRET_READINESS_TTL,
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    PLAN_SECRET_SELF_TEST_POLICY_VERSION,
    READINESS_POLICY_VERSION,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    REMOTE_STATE_READINESS_TTL,
    ReadinessBinding,
    readiness_evidence_hash,
)
from sqlalchemy.orm import Session

from secp_worker.readiness.plan_secret_evaluation import PlanSecretEvaluation
from secp_worker.readiness.state_evaluation import RemoteStateEvaluation


class ReadinessRecordingRefused(Exception):
    """The typed evaluation is not safe to persist (over-size bound). Never echoes the payload."""


def _bounded(payload: dict) -> dict:
    """Fail closed if the safe evidence payload is over-sized (an adapter smuggling data)."""
    import json

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ReadinessRecordingRefused("readiness evidence payload exceeds the bounded size")
    return payload


def record_remote_state_readiness(
    session: Session,
    *,
    binding: ReadinessBinding,
    evaluation: RemoteStateEvaluation,
    capability,  # noqa: ANN001 - ReadinessAdapterCapability (worker-only, non-serializable)
    attestation_id: uuid.UUID,
    now: datetime,
) -> RemoteStateReadinessRecord:
    """Persist ONE immutable remote-state readiness record (exact-once per operation fingerprint).

    The ``capability`` is MANDATORY: evidence can only exist when a reviewed deployment-local
    activation authorized the exact adapter IMPLEMENTATION for this exact operation. Its class
    (``controlled_live`` / ``test_only``) and the reviewed dossier hash are recorded, so test-only
    evidence can never later be mistaken for controlled-live deployment evidence.
    """
    if capability is None:
        raise ReadinessRecordingRefused("readiness evidence requires a verified adapter capability")
    facets = evaluation.facet_payload()[:MAX_EVIDENCE_FACETS]
    reasons = list(evaluation.reason_codes)[:MAX_EVIDENCE_REASONS]
    fingerprint = binding.operation_fingerprint()

    payload = _bounded(
        {
            "operation_kind": ReadinessOperationKind.remote_state_readiness.value,
            "outcome": evaluation.outcome,
            "facets": facets,
            "reason_codes": reasons,
            "state_backend_class": evaluation.backend_class,
            "state_namespace_hash": binding.state_namespace_identity,
            "encryption_proof_id": str(evaluation.encryption_proof_id or ""),
            "lock_proof_id": str(evaluation.lock_proof_id or ""),
            "backup_proof_id": str(evaluation.backup_proof_id or ""),
            "restore_proof_id": str(evaluation.restore_proof_id or ""),
            "eligibility_evidence_hash": binding.eligibility_evidence_hash,
            "toolchain_profile_hash": binding.toolchain_profile_hash,
            "toolchain_attestation_hash": binding.toolchain_attestation_hash,
            "activation_dossier_hash": capability.activation_dossier_hash,
            "capability_class": capability.capability_class,
            "readiness_policy_version": READINESS_POLICY_VERSION,
            "adapter_contract_version": REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
            "operation_fingerprint": fingerprint,
        }
    )

    # Exact-once applies to the TERMINAL (``ready``) outcome only: a NON-ready attempt appends a
    # new immutable record so a retry is possible (a partial unique index enforces the one-``ready``
    # rule at the database level).
    existing = (
        session.query(RemoteStateReadinessRecord)
        .filter(
            RemoteStateReadinessRecord.provisioning_manifest_id
            == uuid.UUID(binding.provisioning_manifest_id),
            RemoteStateReadinessRecord.operation_fingerprint == fingerprint,
            RemoteStateReadinessRecord.outcome == RemoteStateReadinessOutcome.ready,
        )
        .one_or_none()
    )
    if existing is not None:
        return existing

    row = RemoteStateReadinessRecord(
        organization_id=uuid.UUID(binding.organization_id),
        execution_target_id=uuid.UUID(binding.execution_target_id),
        target_onboarding_id=uuid.UUID(binding.target_onboarding_id),
        deployment_plan_id=uuid.UUID(binding.deployment_plan_id),
        provisioning_manifest_id=uuid.UUID(binding.provisioning_manifest_id),
        toolchain_profile_id=uuid.UUID(binding.toolchain_profile_id),
        eligibility_preflight_id=uuid.UUID(binding.eligibility_preflight_id),
        toolchain_attestation_id=attestation_id,
        worker_identity_registration_id=uuid.UUID(binding.worker_identity_registration_id),
        worker_identity_version=binding.worker_identity_version,
        provisioning_manifest_content_hash=binding.provisioning_manifest_content_hash,
        target_config_hash=binding.target_config_hash,
        onboarding_boundary_hash=binding.onboarding_boundary_hash,
        eligibility_evidence_hash=binding.eligibility_evidence_hash,
        eligibility_policy_version=binding.eligibility_policy_version,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        toolchain_attestation_policy_version=binding.toolchain_attestation_policy_version,
        toolchain_attestation_hash=binding.toolchain_attestation_hash,
        activation_dossier_hash=capability.activation_dossier_hash,
        state_backend_class=evaluation.backend_class,
        state_namespace_hash=binding.state_namespace_identity,
        capability_class=ReadinessCapabilityClass(capability.capability_class),
        adapter_registration_id=capability.adapter_registration_id,
        encryption_proof_id=evaluation.encryption_proof_id,
        lock_proof_id=evaluation.lock_proof_id,
        backup_proof_id=evaluation.backup_proof_id,
        restore_proof_id=evaluation.restore_proof_id,
        operation_fingerprint=fingerprint,
        readiness_policy_version=READINESS_POLICY_VERSION,
        adapter_contract_version=REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
        outcome=RemoteStateReadinessOutcome(evaluation.outcome),
        facets=facets,
        reason_codes=reasons,
        collected_at=now,
        expires_at=now + REMOTE_STATE_READINESS_TTL,
        evidence_hash=readiness_evidence_hash(payload),
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        action=AuditAction.remote_state_readiness_completed,
        resource_type="remote_state_readiness_record",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor="worker",
        data={
            "operation_kind": ReadinessOperationKind.remote_state_readiness.value,
            "provisioning_manifest_id": binding.provisioning_manifest_id,
            "outcome": evaluation.outcome,
            "reason_codes": reasons,
            "state_backend_class": evaluation.backend_class,
            "state_namespace_hash": binding.state_namespace_identity,
            "capability_class": capability.capability_class,
            "adapter_registration_id": str(capability.adapter_registration_id),
            "toolchain_attestation_id": str(attestation_id),
            "operation_fingerprint": fingerprint,
            "evidence_hash": row.evidence_hash,
            "readiness_policy_version": READINESS_POLICY_VERSION,
            "adapter_contract_version": REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
            "expires_at": row.expires_at.isoformat(),
        },
    )
    return row


def record_plan_secret_readiness(
    session: Session,
    *,
    binding: ReadinessBinding,
    evaluation: PlanSecretEvaluation,
    authorization_evidence_fingerprint: str,
    lease_id: uuid.UUID | None,
    capability,  # noqa: ANN001 - ReadinessAdapterCapability (worker-only, non-serializable)
    attestation_id: uuid.UUID,
    credential_binding,  # noqa: ANN001 - CredentialBinding (an OPAQUE id + version, nothing else)
    now: datetime,
) -> PlanSecretReadinessRecord:
    """Persist ONE immutable plan-secret readiness record (exact-once per operation fingerprint).

    The ``capability`` is MANDATORY (see :func:`record_remote_state_readiness`).
    """
    if capability is None:
        raise ReadinessRecordingRefused("readiness evidence requires a verified adapter capability")
    facets = evaluation.facet_payload()[:MAX_EVIDENCE_FACETS]
    reasons = list(evaluation.reason_codes)[:MAX_EVIDENCE_REASONS]
    fingerprint = binding.operation_fingerprint()

    payload = _bounded(
        {
            "operation_kind": ReadinessOperationKind.plan_secret_readiness.value,
            "outcome": evaluation.outcome,
            "facets": facets,
            "reason_codes": reasons,
            "secret_purpose": evaluation.secret_purpose,
            "resolver_contract_version": PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
            "self_test_policy_version": PLAN_SECRET_SELF_TEST_POLICY_VERSION,
            "env_contract_version": PLAN_SECRET_ENV_CONTRACT_VERSION,
            "self_test_proof_id": str(evaluation.self_test_proof_id or ""),
            "eligibility_evidence_hash": binding.eligibility_evidence_hash,
            "toolchain_profile_hash": binding.toolchain_profile_hash,
            "toolchain_attestation_hash": binding.toolchain_attestation_hash,
            "credential_binding_id": binding.credential_binding_id,
            "credential_binding_version": binding.credential_binding_version,
            "activation_dossier_hash": capability.activation_dossier_hash,
            "capability_class": capability.capability_class,
            "remote_state_evidence_hash": binding.state_readiness_evidence_hash,
            "readiness_policy_version": READINESS_POLICY_VERSION,
            "operation_fingerprint": fingerprint,
        }
    )

    # Exact-once applies to the TERMINAL (``ready``) outcome only (see above).
    existing = (
        session.query(PlanSecretReadinessRecord)
        .filter(
            PlanSecretReadinessRecord.provisioning_manifest_id
            == uuid.UUID(binding.provisioning_manifest_id),
            PlanSecretReadinessRecord.operation_fingerprint == fingerprint,
            PlanSecretReadinessRecord.outcome == PlanSecretReadinessOutcome.ready,
        )
        .one_or_none()
    )
    if existing is not None:
        return existing

    row = PlanSecretReadinessRecord(
        organization_id=uuid.UUID(binding.organization_id),
        authorization_id=uuid.UUID(binding.authorization_id),
        authorization_version=binding.authorization_version,
        execution_target_id=uuid.UUID(binding.execution_target_id),
        target_onboarding_id=uuid.UUID(binding.target_onboarding_id),
        deployment_plan_id=uuid.UUID(binding.deployment_plan_id),
        provisioning_manifest_id=uuid.UUID(binding.provisioning_manifest_id),
        toolchain_profile_id=uuid.UUID(binding.toolchain_profile_id),
        eligibility_preflight_id=uuid.UUID(binding.eligibility_preflight_id),
        remote_state_readiness_id=uuid.UUID(binding.state_readiness_record_id),
        toolchain_attestation_id=attestation_id,
        credential_binding_id=credential_binding.id,
        credential_binding_version=credential_binding.binding_version,
        worker_identity_registration_id=uuid.UUID(binding.worker_identity_registration_id),
        worker_identity_version=binding.worker_identity_version,
        lease_id=lease_id,
        capability_class=ReadinessCapabilityClass(capability.capability_class),
        adapter_registration_id=capability.adapter_registration_id,
        provisioning_manifest_content_hash=binding.provisioning_manifest_content_hash,
        target_config_hash=binding.target_config_hash,
        onboarding_boundary_hash=binding.onboarding_boundary_hash,
        eligibility_evidence_hash=binding.eligibility_evidence_hash,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        toolchain_attestation_hash=binding.toolchain_attestation_hash,
        remote_state_evidence_hash=binding.state_readiness_evidence_hash,
        activation_dossier_hash=capability.activation_dossier_hash,
        authorization_evidence_fingerprint=authorization_evidence_fingerprint,
        secret_purpose=evaluation.secret_purpose,
        resolver_contract_version=PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
        self_test_policy_version=PLAN_SECRET_SELF_TEST_POLICY_VERSION,
        env_contract_version=PLAN_SECRET_ENV_CONTRACT_VERSION,
        readiness_policy_version=READINESS_POLICY_VERSION,
        self_test_proof_id=evaluation.self_test_proof_id,
        operation_fingerprint=fingerprint,
        outcome=PlanSecretReadinessOutcome(evaluation.outcome),
        facets=facets,
        reason_codes=reasons,
        collected_at=now,
        expires_at=now + PLAN_SECRET_READINESS_TTL,
        evidence_hash=readiness_evidence_hash(payload),
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        action=AuditAction.plan_secret_readiness_completed,
        resource_type="plan_secret_readiness_record",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor="worker",
        data={
            "operation_kind": ReadinessOperationKind.plan_secret_readiness.value,
            "provisioning_manifest_id": binding.provisioning_manifest_id,
            "authorization_id": binding.authorization_id,
            "authorization_version": binding.authorization_version,
            "secret_purpose": evaluation.secret_purpose,
            "outcome": evaluation.outcome,
            "reason_codes": reasons,
            "resolver_contract_version": PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
            "self_test_policy_version": PLAN_SECRET_SELF_TEST_POLICY_VERSION,
            "self_test_proof_id": str(evaluation.self_test_proof_id or ""),
            "capability_class": capability.capability_class,
            "adapter_registration_id": str(capability.adapter_registration_id),
            "credential_binding_id": binding.credential_binding_id,
            "credential_binding_version": binding.credential_binding_version,
            "toolchain_attestation_id": str(attestation_id),
            "lease_id": str(lease_id) if lease_id else "",
            "operation_fingerprint": fingerprint,
            "evidence_hash": row.evidence_hash,
            "readiness_policy_version": READINESS_POLICY_VERSION,
            "expires_at": row.expires_at.isoformat(),
        },
    )
    return row
