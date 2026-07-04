"""API schemas for the declarative disposable staging-lab workflow (SECP-002B-1B-9).

Secret-free and provider-neutral by construction. The API accepts only controlled enums, a
substrate UUID, and one optional strictly-validated logical name. It accepts NO endpoint, host,
IP, bridge/VNet name, VMID, storage id, certificate, credential, token, secret ref, or artifact
path/URL/checksum — and returns none either.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from secp_api.enums import (
    StagingBootstrapArtifactProfile,
    StagingResourceClass,
    StagingRollbackPolicy,
)
from secp_api.errors import ValidationFailedError
from secp_api.services.staging_labs import assert_safe_logical_name


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class StagingLabCreate(BaseModel):
    """All persisted labels are server-owned. Only a substrate UUID, controlled enums, and one
    optional strict-slug logical name are accepted."""

    execution_target_id: uuid.UUID
    resource_class: StagingResourceClass = StagingResourceClass.small_lab
    rollback_policy: StagingRollbackPolicy = StagingRollbackPolicy.revert_to_known_clean_checkpoint
    bootstrap_artifact_profile: StagingBootstrapArtifactProfile = (
        StagingBootstrapArtifactProfile.nested_proxmox_offline_base
    )
    logical_name: str | None = None

    @field_validator("logical_name")
    @classmethod
    def _validate_logical_name(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        # Strict allowlist. Surface as a pydantic ValidationError (422) at the API boundary by
        # raising ValueError; the same rule is re-enforced server-side in the service layer.
        try:
            return assert_safe_logical_name(value)
        except ValidationFailedError as exc:
            raise ValueError(str(exc)) from exc


class StagingLabApprove(BaseModel):
    # Only the exact reviewed plan hash is accepted — no free-text reason.
    expected_plan_hash: str


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
    bootstrap_artifact_profile: str
    status: str
    revision: int
    plan_version: int
    plan_hash: str
    desired_state: dict | None
    simulated_observed_state: dict | None
    approved_plan_hash: str
    approved_plan_version: int
    approved_at: datetime | None
    decision_code: str
    created_at: datetime


class StagingLabWorkItemOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    staging_lab_id: uuid.UUID
    operation_kind: str
    plan_hash: str
    plan_version: int
    status: str
    revision: int
    failure_code: str | None
    created_at: datetime


class EligibleSubstrateOut(BaseModel):
    id: uuid.UUID
    alias: str
