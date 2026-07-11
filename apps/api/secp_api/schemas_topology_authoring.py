"""Pydantic request/response schemas for durable topology authoring (SECP-B9).

Every response is secret-free and derived from server-owned records. Requests
carry the optimistic-concurrency anchors (base revision number + content hash)
the service requires; the topology document itself is validated by the pure
contract module, not here (so the closed codes stay authoritative)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secp_api.enums import (
    TopologyAuthoringStatus,
    TopologyRevisionStatus,
    TopologyValidationStatus,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ requests


class TopologyDraftCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    source_environment_version_id: uuid.UUID | None = None
    exercise_id: uuid.UUID | None = None
    # Optional explicit starting document; when omitted the server derives one
    # from the source version (if any) or starts empty.
    document: dict[str, Any] | None = None


class TopologyRevisionCreate(BaseModel):
    base_revision_number: int = Field(ge=1)
    base_content_hash: str = Field(min_length=8, max_length=80)
    document: dict[str, Any]
    change_note: str | None = Field(default=None, max_length=500)


class TopologyHashPin(BaseModel):
    """Shared body for validate/submit/approve/reject — pins the exact hash."""

    content_hash: str = Field(min_length=8, max_length=80)


class TopologyDecision(TopologyHashPin):
    reason: str | None = Field(default=None, max_length=500)


# ----------------------------------------------------------------- responses


class TopologyRevisionOut(ORMModel):
    id: uuid.UUID
    document_id: uuid.UUID
    revision_number: int
    parent_revision_id: uuid.UUID | None
    schema_version: str
    content_hash: str
    status: TopologyRevisionStatus
    change_note: str | None
    source_environment_version_id: uuid.UUID | None
    created_by: uuid.UUID | None
    created_at: datetime
    decided_by: uuid.UUID | None
    decided_at: datetime | None


class TopologyRevisionDetailOut(TopologyRevisionOut):
    # The canonical, secret-free topology document. Only exposed on the
    # single-revision read (not in list responses).
    document_content: dict[str, Any]


class TopologyValidationOut(ORMModel):
    id: uuid.UUID
    revision_id: uuid.UUID
    content_hash: str
    status: TopologyValidationStatus
    error_count: int
    warning_count: int
    findings: list[dict[str, Any]]
    result_hash: str
    validated_by: uuid.UUID | None
    validated_at: datetime


class TopologyDocumentOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    display_name: str
    status: TopologyAuthoringStatus
    source_environment_version_id: uuid.UUID | None
    exercise_id: uuid.UUID | None
    current_revision_id: uuid.UUID | None
    validated_revision_id: uuid.UUID | None
    submitted_revision_id: uuid.UUID | None
    approved_revision_id: uuid.UUID | None
    revision_count: int
    created_at: datetime
    updated_at: datetime


class TopologyDocumentDetailOut(TopologyDocumentOut):
    """Aggregate + its current revision + the current revision's validation
    posture, so the workspace can detect a stale local draft in one call."""

    current_revision: TopologyRevisionDetailOut | None
    current_validation_status: TopologyValidationStatus
