"""API schemas for worker-owned read-only target discovery (SECP-B5 §4).

Secret-free and provider-neutral by construction. The API accepts ONLY a substrate UUID, a closed
resource profile, one optional strict logical name, and (for approval) the exact reviewed plan hash.
It accepts and returns NO SSH host/account/port/key path/known_hosts path/fingerprint, Proxmox
endpoint/token, raw command output, arbitrary node/storage/VMID entry field, free-form command, or
provider option. Discovered node/storage LABELS + bounded capacity numbers are returned only as
safe,
typed values.
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


class DiscoveryRequest(BaseModel):
    """Only a substrate UUID, a closed resource profile, and an optional strict logical name."""

    execution_target_id: uuid.UUID
    resource_profile: Literal["small_lab", "medium_lab"] = "small_lab"
    logical_name: str | None = None

    @field_validator("logical_name")
    @classmethod
    def _validate_logical_name(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        try:
            return assert_safe_logical_name(value)
        except ValidationFailedError as exc:
            raise ValueError(str(exc)) from exc


class DiscoveryApprove(BaseModel):
    # Only the exact reviewed candidate-plan hash — no free-text reason, no override.
    expected_plan_hash: str


class EnrollmentOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    display_name: str
    ownership_label: str
    resource_profile: str
    status: str
    decision_code: str
    enrollment_version: int
    revision: int
    active_plan_hash: str
    approved_plan_hash: str
    approved_at: datetime | None
    failure_code: str | None
    created_at: datetime


class CandidatePlanResourceOut(BaseModel):
    """A candidate resource CATEGORY + generated ownership-safe identifiers. Never a
    secret/endpoint."""

    kind: str
    resource_ref: str
    ownership_marker: str


class CandidatePlanOut(BaseModel):
    plan_version: int
    plan_hash: str
    ownership_tag: str
    resource_profile: str
    node: str
    storage: str
    capacity_snapshot_hash: str
    evidence_hash: str
    worker_identity_version: int
    enrollment_version: int
    expires_at: datetime
    executable: bool
    status: str
    resources: list[CandidatePlanResourceOut]


class DiscoveryEvidenceOut(BaseModel):
    """The safe capability/eligibility outcome from the latest immutable discovery snapshot.
    Bounded,
    typed, secret-free facts only — never raw output, endpoint, address, or credential."""

    eligibility: str
    reason_code: str | None
    version_major: int | None
    version_minor: int | None
    is_clustered: bool | None
    node: str | None
    node_count: int | None
    cpu_total: int | None
    mem_total_mb: int | None
    mem_free_mb: int | None
    nested_available: bool | None
    selected_storage: str | None
    storage_count: int
    candidate_vmids: list[int]
    evidence_hash: str
    bundle_available: bool
    created_at: datetime


class DiscoveryBootstrapAvailabilityOut(BaseModel):
    """A SAFE boolean + closed reason only — never the bootstrap bundle's location/contents. The
    worker-local read-only SSH authority is worker-mounted; the API cannot read it, so it is
    reported
    unavailable here with a closed reason."""

    available: bool = False
    reason_code: str = "worker_local_bootstrap_not_mounted"


class SealedApplyNoticeOut(BaseModel):
    """Reminds callers that live deployment apply remains sealed after read-only discovery."""

    live_apply_sealed: bool = True
    message: str = (
        "Read-only discovery complete. Live deployment remains sealed until controlled "
        "integration enablement."
    )
