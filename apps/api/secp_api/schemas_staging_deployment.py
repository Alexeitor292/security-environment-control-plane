"""API schemas for the real staging-lab deployment lifecycle (SECP-B4 §2).

Secret-free and provider-neutral by construction. The API accepts ONLY a substrate UUID, a closed
resource-profile label, one optional strict-slug logical name, and (for approval) the exact reviewed
plan hash. It accepts NO SSH material, API token, host/endpoint, free-form command, shell text,
bridge/storage name, VMID, network range, path, or arbitrary provider option — and returns none.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from secp_api.errors import ValidationFailedError
from secp_api.services.staging_labs import assert_safe_logical_name


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class DeploymentCreate(BaseModel):
    """All persisted labels are server-owned. Only a substrate UUID, a closed resource profile, and
    an optional strict logical name are accepted — never a host/endpoint/credential/free option."""

    execution_target_id: uuid.UUID
    resource_profile: Literal["small_lab", "medium_lab"] = "small_lab"
    logical_name: str | None = None

    @field_validator("logical_name")
    @classmethod
    def _validate_logical_name(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        # Strict allowlist (shared with staging labs). Surface as a 422 via ValueError; the same
        # rule is re-enforced server-side in the service layer. The error never echoes the input.
        try:
            return assert_safe_logical_name(value)
        except ValidationFailedError as exc:
            raise ValueError(str(exc)) from exc


class DeploymentApprove(BaseModel):
    # Only the exact reviewed plan hash is accepted — no free-text reason, no override.
    expected_plan_hash: str


class DeploymentOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    display_name: str
    ownership_label: str
    resource_profile: str
    status: str
    decision_code: str
    revision: int
    plan_version: int
    plan_hash: str
    approved_plan_hash: str
    approved_at: datetime | None
    failure_code: str | None
    created_at: datetime


class PlannedResourceOut(BaseModel):
    """One planned resource CATEGORY + bounded count + generated ownership-bound reference. NEVER a
    secret, endpoint, host, or real bridge/VMID/storage name."""

    kind: str
    count: int
    resource_ref: str


class DeploymentPlanOut(ORMModel):
    plan_version: int
    plan_hash: str
    ownership_tag: str
    capacity_assessment_hash: str
    artifact_manifest_id: str
    resources: list[PlannedResourceOut]


class DeploymentResourceOut(ORMModel):
    resource_kind: str
    ownership_tag: str
    resource_ref: str
    inverse_op: str
    state: str


class DeploymentVerificationOut(ORMModel):
    check_code: str
    status: str


class BootstrapAvailabilityOut(BaseModel):
    """A SAFE boolean + closed refusal reason only — never the bootstrap bundle's location/contents.

    From the control plane's perspective the one-time SSH bootstrap authority is worker-local and
    deployment-mounted, so it is reported as unavailable here with a closed reason; the API cannot
    and must not read it.
    """

    available: bool = False
    reason_code: str = "deployment_local_bootstrap_not_mounted"
