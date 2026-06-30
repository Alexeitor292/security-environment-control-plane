"""Pydantic request/response schemas for the control-plane API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- requests -----------------------------------------------------------------


class TemplateCreate(BaseModel):
    name: str
    slug: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    display_name: str = ""
    description: str = ""


class VersionCreate(BaseModel):
    definition: dict


class ExerciseCreate(BaseModel):
    template_id: uuid.UUID
    version_id: uuid.UUID
    name: str


class DecisionBody(BaseModel):
    reason: str = ""


# --- responses ----------------------------------------------------------------


class TemplateOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    slug: str
    display_name: str
    description: str
    created_at: datetime


class VersionOut(ORMModel):
    id: uuid.UUID
    template_id: uuid.UUID
    version_number: int
    api_version: str
    content_hash: str
    spec: dict
    created_at: datetime


class ExerciseOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    template_id: uuid.UUID
    environment_version_id: uuid.UUID
    name: str
    lifecycle_state: str
    team_count: int
    created_at: datetime


class InstanceOut(ORMModel):
    id: uuid.UUID
    exercise_id: uuid.UUID
    team_index: int
    team_ref: str
    instance_ref: str
    lifecycle_state: str
    provider: str


class PlanOut(ORMModel):
    id: uuid.UUID
    exercise_id: uuid.UUID
    environment_version_id: uuid.UUID
    version_content_hash: str
    status: str
    summary: dict
    approved_content_hash: str | None
    decided_at: datetime | None
    created_at: datetime


class WorkflowRunOut(ORMModel):
    id: uuid.UUID
    exercise_id: uuid.UUID
    kind: str
    status: str
    dispatch_mode: str
    correlation_id: str
    target_instance_id: uuid.UUID | None
    detail: dict
    created_at: datetime
    finished_at: datetime | None


class AuditEventOut(ORMModel):
    id: uuid.UUID
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    data: dict
    created_at: datetime


class PluginOut(BaseModel):
    name: str
    version: str
    contract_version: str
    healthy: bool
    simulated: bool
    capabilities: list[str]


class PrincipalOut(BaseModel):
    user_id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    permissions: list[str]
    is_dev_fallback: bool


class ValidationOut(BaseModel):
    ok: bool
    errors: list[str] = []
    warnings: list[str] = []
