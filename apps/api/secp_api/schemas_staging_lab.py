"""API schemas for the declarative disposable staging-lab workflow (SECP-002B-1B-9).

Secret-free and provider-neutral by construction. No endpoint, host, IP, bridge/VNet name,
VMID, storage id, certificate, credential, token, secret reference, or artifact path/URL/checksum
is accepted or returned — only safe logical intent, lifecycle state, plan hash, ownership
identity, and fake simulated observations.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from secp_api.enums import (
    StagingLabProfile,
    StagingNetworkIntent,
    StagingResourceClass,
    StagingRollbackPolicy,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class StagingLabCreate(BaseModel):
    execution_target_id: uuid.UUID
    display_name: str
    ownership_label: str
    profile: StagingLabProfile = StagingLabProfile.nested_proxmox
    network_intent: StagingNetworkIntent = StagingNetworkIntent.host_only_no_uplink
    resource_class: StagingResourceClass = StagingResourceClass.small_lab
    rollback_policy: StagingRollbackPolicy = StagingRollbackPolicy.revert_to_known_clean_checkpoint
    bootstrap_artifact_profile_id: str


class StagingLabApprove(BaseModel):
    expected_plan_hash: str
    reason: str = ""


class StagingLabDecision(BaseModel):
    reason: str = ""


class StagingLabOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    display_name: str
    ownership_label: str
    purpose: str
    profile: str
    network_intent: str
    resource_class: str
    rollback_policy: str
    bootstrap_artifact_profile_id: str
    status: str
    plan_version: int
    plan_hash: str
    desired_state: dict | None
    simulated_observed_state: dict | None
    approved_plan_hash: str
    approved_plan_version: int
    approved_at: datetime | None
    decision_reason: str
    created_at: datetime
