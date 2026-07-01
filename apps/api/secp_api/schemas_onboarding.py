"""API schemas for target onboarding + preflight (SECP-002B-1B-0, ADR-014).

Secret-free by construction. Provider-neutral. Preflight evidence is redacted and safe
for display.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from secp_api.enums import IsolationModel, OnboardingMode


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
    decided_at: datetime | None
    decision_reason: str
    activated_at: datetime | None
    created_at: datetime


class PreflightSubmit(BaseModel):
    checks: list[dict]
    collector: str = "fake"


class PreflightOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    onboarding_id: uuid.UUID
    collector: str
    passed: bool
    checks: list
    evidence_hash: str
    created_at: datetime


class OnboardingDecision(BaseModel):
    reason: str = ""
