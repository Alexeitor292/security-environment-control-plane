"""API schemas for the app-owned read-only staging preflight (SECP-B2-0).

Secret-free by construction. The API accepts only UUIDs and a bounded TTL, and returns only IDs,
closed enums/codes, safe hashes, timestamps, and safe readiness facts — never an endpoint, host,
IP, port, path, bridge/VNet/VLAN/VMID/storage id, certificate, token, credential, secret ref, or
target config value.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PreflightSubstrateOut(BaseModel):
    id: uuid.UUID
    alias: str


class CreatePreflightAuthorization(BaseModel):
    execution_target_id: uuid.UUID
    # Short-lived by construction; the service caps this to a safe maximum.
    ttl_seconds: int = Field(default=900, ge=1, le=3600)


class PreflightAuthorizationOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    authorization_version: int
    status: str
    authorization_expiry: datetime
    created_at: datetime
    approved_at: datetime | None
    revoked_at: datetime | None


class QueuePreflight(BaseModel):
    live_read_authorization_id: uuid.UUID


class ReadonlyPreflightOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    live_read_authorization_id: uuid.UUID
    authorization_version: int
    status: str
    revision: int
    outcome_code: str | None
    readiness_facts: dict | None
    created_at: datetime
    completed_at: datetime | None
