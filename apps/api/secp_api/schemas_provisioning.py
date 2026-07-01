"""API schemas for provisioning manifests and operations (SECP-002B-0).

Secret-free by construction (the underlying models exclude all secret material).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ManifestOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    deployment_plan_id: uuid.UUID
    execution_target_id: uuid.UUID
    target_config_hash: str
    content: dict
    content_hash: str
    validated_at: datetime | None
    created_at: datetime


class OperationOut(ORMModel):
    id: uuid.UUID
    manifest_id: uuid.UUID
    kind: str
    status: str
    idempotency_key: str
    runner: str
    operation_ref: str | None
    attempts: int
    result: dict
    error: str | None
    created_at: datetime
    finished_at: datetime | None
