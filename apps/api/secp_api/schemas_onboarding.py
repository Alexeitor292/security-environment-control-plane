"""API schemas for target onboarding + preflight (SECP-002B-1B-0, ADR-014).

Secret-free by construction. Provider-neutral. Preflight evidence is redacted and safe
for display.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, computed_field

from secp_api.enums import IsolationModel, IsolationProfile, NetworkApproach, OnboardingMode


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class OnboardingCreate(BaseModel):
    onboarding_mode: OnboardingMode
    isolation_model: IsolationModel
    declared_boundary: dict


class OnboardingOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_mode: str
    isolation_model: str
    status: str
    declared_boundary: dict
    boundary_hash: str
    approved_target_config_hash: str | None
    approved_scope_policy_hash: str | None
    approved_preflight_id: uuid.UUID | None
    approved_preflight_evidence_hash: str | None
    approved_boundary_hash: str | None
    approved_verification_level: str | None
    decided_at: datetime | None
    decision_reason: str
    activated_at: datetime | None
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def network_approach(self) -> str:
        """Durable network approach declared in the boundary (backward-compatible default)."""
        return str(
            (self.declared_boundary or {}).get(
                "network_approach", NetworkApproach.use_approved_existing_segment.value
            )
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def isolation_profile(self) -> str:
        """Declared isolation profile (backward-compatible default: fully_segregated)."""
        return str(
            (self.declared_boundary or {}).get(
                "isolation_profile", IsolationProfile.fully_segregated.value
            )
        )


class PreflightOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    onboarding_id: uuid.UUID
    collector: str
    verification_level: str
    collector_kind: str
    collector_identity: str
    evidence_version: int
    passed: bool
    checks: list
    evidence_hash: str
    created_at: datetime


class OnboardingDecision(BaseModel):
    reason: str = ""
