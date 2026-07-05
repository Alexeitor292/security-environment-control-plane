"""API schemas for durable worker-identity registration (SECP-B2-4.3).

Secret-free by construction. The API accepts only a closed mechanism enum, opaque grammar-validated
label/binding, a canonical ``sha256:<hex>`` verification-anchor FINGERPRINT (never the anchor
material), a bounded TTL, closed evidence kind/status enums, and safe opaque proof metadata; it
returns only IDs, closed enums, safe hashes, timestamps, and a closed evidence summary — NEVER a
certificate, key, CSR, CA, endpoint, host, port, token, reference, backend configuration, or secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from secp_api.enums import (
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# Opaque grammar (no whitespace/scheme/slash/colon/at) — cannot carry a host/endpoint/reference/PEM.
_SAFE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$"
# A canonical fingerprint of a PUBLIC verification anchor — never the anchor material.
_ANCHOR_FP = r"^sha256:[0-9a-f]{64}$"


class RegisterWorkerIdentity(BaseModel):
    mechanism: WorkerIdentityMechanism
    identity_label: str = Field(pattern=_SAFE)
    deployment_binding: str = Field(pattern=_SAFE)
    verification_anchor_fingerprint: str = Field(pattern=_ANCHOR_FP)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400)


class RecordWorkerIdentityEvidence(BaseModel):
    kind: WorkerIdentityEvidenceKind
    status: WorkerIdentityEvidenceStatus
    proof_id: str = Field(pattern=_SAFE)
    issuer: str = Field(pattern=_SAFE)


class WorkerIdentityEvidenceOut(ORMModel):
    kind: WorkerIdentityEvidenceKind
    status: WorkerIdentityEvidenceStatus
    proof_id: str
    issuer: str
    verified_at: datetime | None


class WorkerIdentityOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    mechanism: WorkerIdentityMechanism
    identity_label: str
    deployment_binding: str
    verification_anchor_fingerprint: str
    identity_version: int
    expiry: datetime
    evidence_fingerprint: str
    status: str
    revision: int
    approved_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
    evidence: list[WorkerIdentityEvidenceOut] = []
