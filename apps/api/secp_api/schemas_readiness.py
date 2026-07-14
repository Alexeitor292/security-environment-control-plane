"""Bounded, redacted readiness API schemas (B1B-PR4 / ADR-021 §P).

Every response model is an explicit allowlist. There is NO field — and no code path — through which
a backend endpoint, backend URL, backend object key, bucket / container name, state key or path,
namespace name, secret, secret reference, secret-reference hash, token, worker-local path, raw proof
metadata, provider output, or exception body could reach a client. The remote-state backend is
visible only as a bounded ``state_backend_class`` plus opaque digests.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from secp_api.enums import (
    PlanSecretEvidenceKind,
    PlanSecretEvidenceStatus,
    PlanSecretPurpose,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReadinessRequestAccepted(_Strict):
    """The API durably ENQUEUED the operation. It executed nothing and contacted nothing."""

    operation_kind: str
    provisioning_manifest_id: str
    status: str = "queued"


class ReadinessFacetOut(_Strict):
    facet: str
    status: str


class RemoteStateReadinessOut(_Strict):
    operation_kind: str
    record_id: str
    provisioning_manifest_id: str
    execution_target_id: str
    target_onboarding_id: str
    outcome: str
    facets: list[ReadinessFacetOut] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    # Bounded class + OPAQUE identifiers only. Never a URL, kind, bucket, object key, or state path
    # — and NEVER a digest derived directly from the backend reference (that would be an offline
    # confirmation oracle over an enumerable locator; see ADR-021 §E).
    state_backend_class: str
    state_namespace_hash: str
    # Opaque UUIDs issued by the adapter — never a locator, label, or reason code.
    encryption_proof_id: str
    lock_proof_id: str
    backup_proof_id: str
    restore_proof_id: str
    eligibility_evidence_hash: str
    toolchain_profile_hash: str
    toolchain_attestation_id: str
    toolchain_attestation_hash: str
    capability_class: str
    adapter_registration_id: str
    readiness_policy_version: str
    adapter_contract_version: str
    operation_fingerprint: str
    evidence_hash: str
    collected_at: str
    expires_at: str
    expired: bool
    current: bool


class PlanSecretReadinessOut(_Strict):
    operation_kind: str
    record_id: str
    provisioning_manifest_id: str
    authorization_id: str
    authorization_version: int
    secret_purpose: str
    outcome: str
    facets: list[ReadinessFacetOut] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    resolver_contract_version: str
    self_test_policy_version: str
    env_contract_version: str
    readiness_policy_version: str
    self_test_proof_id: str
    remote_state_readiness_id: str
    eligibility_evidence_hash: str
    toolchain_profile_hash: str
    toolchain_attestation_id: str
    toolchain_attestation_hash: str
    # OPAQUE credential identity: a UUID + a monotonic version. NEVER the secret reference, a hash
    # of it, a locator, or a backend path (B1B-PR4 §2).
    credential_binding_id: str
    credential_binding_version: int
    capability_class: str
    adapter_registration_id: str
    operation_fingerprint: str
    evidence_hash: str
    collected_at: str
    expires_at: str
    expired: bool
    current: bool


class PlanSecretEvidenceOut(_Strict):
    kind: str
    status: str
    proof_id: str
    issuer: str


class PlanSecretAuthorizationOut(_Strict):
    authorization_id: str
    provisioning_manifest_id: str
    execution_target_id: str
    target_onboarding_id: str
    deployment_plan_id: str
    secret_purpose: str
    # The reviewed reference SCHEME only ("vault"/"env") — never the reference or a hash of it.
    credential_reference_scheme: str
    # The OPAQUE credential binding this authorization approves. Rotating the target's reference
    # rotates the binding version, which invalidates this authorization for all FUTURE use.
    credential_binding_id: str
    credential_binding_version: int
    toolchain_attestation_id: str
    resolver_contract_version: str
    readiness_policy_version: str
    status: str
    authorization_version: int
    authorization_expiry: str
    operation_fingerprint: str
    evidence_fingerprint: str
    evidence: list[PlanSecretEvidenceOut] = Field(default_factory=list)
    approved_at: str | None = None
    revoked_at: str | None = None
    revocation_reason_code: str = ""


class CreatePlanSecretAuthorizationIn(_Strict):
    """Create a DRAFT plan-secret authorization.

    ``purpose`` is a closed enum whose ONLY member is ``plan_read``: an ``apply`` or ``destroy``
    secret purpose is not merely rejected — it is unrepresentable, so pydantic refuses the request
    body before any service code runs.
    """

    purpose: PlanSecretPurpose = PlanSecretPurpose.plan_read
    ttl_seconds: int = Field(default=3600, ge=1, le=24 * 3600)


class RecordPlanSecretEvidenceIn(_Strict):
    kind: PlanSecretEvidenceKind
    status: PlanSecretEvidenceStatus
    proof_id: str = Field(min_length=1, max_length=120)
    issuer: str = Field(min_length=1, max_length=120)


class RevokePlanSecretAuthorizationIn(_Strict):
    reason_code: str = Field(default="operator", max_length=80)


class ToolchainAttestationOut(_Strict):
    """The durable PR2 worker-local toolchain attestation record (B1B-PR4 §1).

    It carries NO worker-local path, filename, executable content, provider content, CLI content, or
    expected/observed raw digest — only ids, bounded facet names, bounded reason codes, versions and
    content hashes.
    """

    record_id: str
    execution_target_id: str
    toolchain_profile_id: str
    toolchain_profile_hash: str
    worker_identity_registration_id: str
    worker_identity_version: int
    verifier_policy_version: str
    outcome: str
    verified_facets: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    evidence_hash: str
    operation_fingerprint: str
    collected_at: str
    expires_at: str
    expired: bool


class ProvisioningReadinessOut(_Strict):
    """The derived combined current-readiness view. It is NOT plan approval and launches nothing."""

    ready: bool
    reasons: list[str] = Field(default_factory=list)
    eligibility_preflight_id: str | None = None
    toolchain_attestation_id: str | None = None
    credential_binding_id: str | None = None
    credential_binding_version: int | None = None
    remote_state_readiness_id: str | None = None
    plan_secret_readiness_id: str | None = None
    plan_secret_authorization_id: str | None = None
    readiness_policy_version: str
