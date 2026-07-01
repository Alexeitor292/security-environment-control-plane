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
    target_scope_policy_hash: str | None = None
    toolchain_profile_id: uuid.UUID | None = None
    toolchain_profile_hash: str | None = None
    content: dict
    content_hash: str
    validated_at: datetime | None
    created_at: datetime


class ToolchainProfileCreate(BaseModel):
    """Register an immutable toolchain profile for a target (SECP-002B-1A)."""

    name: str
    profile: dict


class ToolchainProfileOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    name: str
    version: int
    runner_kind: str
    activation_class: str
    renderer_version: str
    content: dict
    content_hash: str
    status: str
    created_at: datetime


class ChangeSetApprovalOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    manifest_id: uuid.UUID
    toolchain_profile_id: uuid.UUID
    authorizes_kind: str
    change_set_hash: str
    rendered_workspace_hash: str
    manifest_content_hash: str
    toolchain_profile_hash: str
    target_scope_policy_hash: str
    reservations_hash: str
    renderer_version: str
    module_bundle_hash: str
    summary: dict
    status: str
    decided_at: datetime | None
    decision_reason: str
    created_at: datetime


class ApprovalDecision(BaseModel):
    reason: str = ""


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
