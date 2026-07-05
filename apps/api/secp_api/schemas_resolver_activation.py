"""API schemas for durable resolver-activation authorization (SECP-B2-4.1).

Secret-free by construction. The API accepts only UUIDs, a bounded TTL, closed evidence
kind/status enums, and safe opaque proof metadata; it returns only IDs, closed enums, safe hashes,
timestamps, and a closed evidence summary — NEVER an endpoint, host, port, vault path, reference,
token, credential, backend configuration, or secret. There is no secret/backend/credential field.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from secp_api.enums import ResolverActivationEvidenceKind, ResolverActivationEvidenceStatus


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CreateResolverActivation(BaseModel):
    # The exact work item to bind; every other fact is derived server-side.
    preflight_id: uuid.UUID
    ttl_seconds: int = Field(default=3600, ge=1, le=86400)


# A safe opaque proof identifier / issuer: bounded, no whitespace/scheme (the service also validates
# against a strict pattern). This is proof metadata, never a secret/endpoint/reference.
_SAFE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$"


class RecordResolverActivationEvidence(BaseModel):
    kind: ResolverActivationEvidenceKind
    status: ResolverActivationEvidenceStatus
    proof_id: str = Field(pattern=_SAFE)
    issuer: str = Field(pattern=_SAFE)


class ResolverActivationEvidenceOut(ORMModel):
    kind: ResolverActivationEvidenceKind
    status: ResolverActivationEvidenceStatus
    proof_id: str
    issuer: str
    verified_at: datetime | None


class ResolverActivationOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    live_read_authorization_id: uuid.UUID
    live_read_authorization_version: int
    preflight_id: uuid.UUID
    operation_fingerprint: str
    resolver_adapter_contract_version: str
    purpose: str
    authorization_expiry: datetime
    evidence_fingerprint: str
    status: str
    authorization_version: int
    revision: int
    approved_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
    evidence: list[ResolverActivationEvidenceOut] = []
