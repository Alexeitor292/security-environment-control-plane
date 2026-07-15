"""API schemas for the Provider Targets area (SECP-002A).

Sanitized: no secret material is ever serialized. ``secret_ref`` is an opaque
reference (not a secret) and is echoed back so an admin can see which reference a
target uses.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from secp_api.enums import CredentialPurposeClass


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AddressSpaceIn(BaseModel):
    cidr_block: str
    subnet_prefix: int


class TargetCreate(BaseModel):
    display_name: str
    plugin_name: str
    config: dict
    secret_ref: str | None = None
    # B1B-PR5A operation-specific opaque references (never a secret; never echoed by a read model).
    provider_plan_secret_ref: str | None = None
    state_backend_secret_ref: str | None = None
    scope_policy: dict = {}
    address_spaces: list[AddressSpaceIn] = []


class TargetCredentialRotate(BaseModel):
    """Replace a target's GENERIC opaque credential reference through the supported rotation path.

    ``secret_ref`` remains an opaque ``<scheme>:<locator>`` pointer — never a secret. Applying it
    rotates the target's ``provider_plan_read`` opaque credential binding (B1B-PR4 §2).
    """

    secret_ref: str | None = None


class TargetOperationCredentialRotate(BaseModel):
    """Replace one OPERATION-SPECIFIC opaque credential reference (B1B-PR5A, ADR-022).

    ``purpose_class`` is a closed enum whose only members are ``provider_plan_read`` and
    ``state_backend_plan`` — apply/destroy purposes are unrepresentable. The reference remains an
    opaque pointer; rotating it invalidates every prior dossier/readiness/authorization that folded
    the old binding version.
    """

    purpose_class: CredentialPurposeClass
    secret_ref: str | None = None


class AddressSpaceOut(ORMModel):
    cidr_block: str
    subnet_prefix: int


class TargetOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    display_name: str
    plugin_name: str
    config: dict
    config_hash: str
    secret_ref: str | None
    status: str
    scope_policy: dict
    created_at: datetime


class SnapshotOut(ORMModel):
    id: uuid.UUID
    execution_target_id: uuid.UUID
    plugin_name: str
    plugin_version: str
    target_config_hash: str
    status: str
    workflow_run_id: uuid.UUID | None
    requested_at: datetime
    completed_at: datetime | None
    summary: dict
    error: str | None


class ResourceOut(ORMModel):
    id: uuid.UUID
    resource_type: str
    provider_external_id: str
    display_name: str
    parent_ref: str | None
    status: str
    attributes: dict


class ReservationOut(ORMModel):
    id: uuid.UUID
    execution_target_id: uuid.UUID
    team_ref: str
    cidr: str
    status: str
