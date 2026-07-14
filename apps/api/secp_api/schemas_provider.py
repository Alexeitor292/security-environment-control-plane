"""API schemas for the Provider Targets area (SECP-002A).

Sanitized: no secret material is ever serialized. ``secret_ref`` is an opaque
reference (not a secret) and is echoed back so an admin can see which reference a
target uses.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


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
    scope_policy: dict = {}
    address_spaces: list[AddressSpaceIn] = []


class TargetCredentialRotate(BaseModel):
    """Replace a target's OPAQUE credential reference through the supported rotation path.

    ``secret_ref`` remains an opaque ``<scheme>:<locator>`` pointer — never a secret. Applying it
    rotates the target's opaque credential binding to the next version (B1B-PR4 §2).
    """

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
