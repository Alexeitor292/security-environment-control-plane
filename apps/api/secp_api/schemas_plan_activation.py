"""Bounded, redacted B1B-PR5A plan-activation API schemas (ADR-022).

Every response is an explicit allowlist. There is NO field through which a real endpoint,
credential,
secret reference, state key, namespace name, node/storage/bridge name, CIDR, or raw proof text could
reach a client — only ids, opaque hashes, bounded categories, opaque proof metadata, and timestamps.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from secp_api.enums import (
    ActivationDossierEvidenceKind,
    ActivationDossierEvidenceStatus,
    PlanGenerationPurpose,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateActivationDossierIn(_Strict):
    """Create a DRAFT activation dossier. Owner proofs are opaque tokens, never a real identity."""

    recovery_owner_proof: str = Field(min_length=1, max_length=120)
    emergency_stop_owner_proof: str = Field(min_length=1, max_length=120)
    ttl_seconds: int = Field(default=24 * 3600, ge=1, le=30 * 24 * 3600)


class RecordDossierEvidenceIn(_Strict):
    kind: ActivationDossierEvidenceKind
    status: ActivationDossierEvidenceStatus
    proof_id: str = Field(min_length=1, max_length=120)
    issuer: str = Field(min_length=1, max_length=120)


class RevokeDossierIn(_Strict):
    reason_code: str = Field(default="operator", max_length=80)


class DossierEvidenceOut(_Strict):
    kind: str
    status: str
    proof_id: str
    issuer: str


class ActivationDossierOut(_Strict):
    activation_dossier_id: str
    provisioning_manifest_id: str
    execution_target_id: str
    operation_kind: str
    dossier_revision: int
    dossier_hash: str
    status: str
    evidence_fingerprint: str
    authorization_expiry: str
    provider_credential_binding_id: str
    provider_credential_binding_version: int
    state_credential_binding_id: str
    state_credential_binding_version: int
    evidence: list[DossierEvidenceOut] = Field(default_factory=list)
    approved_at: str | None = None
    revoked_at: str | None = None
    revocation_reason_code: str = ""


class CreatePlanGenerationAuthorizationIn(_Strict):
    """Create a DRAFT plan-generation authorization.

    ``purpose`` is a closed enum whose ONLY member is ``plan_generation``: apply/destroy purposes
    are
    unrepresentable, so pydantic refuses such a body before any service code runs.
    """

    purpose: PlanGenerationPurpose = PlanGenerationPurpose.plan_generation
    ttl_seconds: int = Field(default=3600, ge=1, le=30 * 24 * 3600)


class RevokePlanGenerationAuthorizationIn(_Strict):
    reason_code: str = Field(default="operator", max_length=80)


class PlanGenerationAuthorizationOut(_Strict):
    plan_generation_authorization_id: str
    provisioning_manifest_id: str
    activation_dossier_id: str
    purpose: str
    plan_only_capability_contract_version: str
    operation_fingerprint: str
    status: str
    authorization_version: int
    authorization_expiry: str
    evidence_fingerprint: str
    approved_at: str | None = None
    revoked_at: str | None = None
    consumed_at: str | None = None
    revocation_reason_code: str = ""


class PlanGenerationRequestAccepted(_Strict):
    """The API durably ENQUEUED the operation. It executed nothing and contacted nothing."""

    operation_kind: str
    provisioning_manifest_id: str
    status: str = "queued"


class PlanGenerationReadinessOut(_Strict):
    """The derived combined plan-readiness view. It is NOT plan approval and launches nothing."""

    ready: bool
    reasons: list[str] = Field(default_factory=list)
    activation_dossier_id: str | None = None
    plan_generation_authorization_id: str | None = None
    provider_credential_binding_id: str | None = None
    state_credential_binding_id: str | None = None
    remote_state_readiness_id: str | None = None
    plan_secret_readiness_id: str | None = None
    readiness_policy_version: str
