"""Target onboarding routes (SECP-002B-1B-0, control plane only, ADR-014).

The API creates onboarding drafts, records fake-only preflight evidence, drives the
review/approval/activation lifecycle, and reads redacted status/evidence. It NEVER
imports worker, provider, runner, subprocess, OpenTofu, secret-resolver, or infrastructure
SDK code, and no endpoint activates a target merely because a user submitted a
configuration — human approval is required before ``active``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_onboarding import (
    OnboardingCreate,
    OnboardingDecision,
    OnboardingOut,
    PreflightOut,
)
from secp_api.services import onboarding

router = APIRouter(prefix="/api/v1", tags=["onboarding"])


@router.post("/targets/{target_id}/onboarding", response_model=OnboardingOut, status_code=201)
def create_onboarding(
    target_id: uuid.UUID,
    body: OnboardingCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OnboardingOut:
    ob = onboarding.create_onboarding(
        session,
        principal,
        target_id=target_id,
        onboarding_mode=body.onboarding_mode,
        isolation_model=body.isolation_model,
        declared_boundary=body.declared_boundary,
    )
    return OnboardingOut.model_validate(ob)


@router.get("/targets/{target_id}/onboarding", response_model=list[OnboardingOut])
def list_onboardings(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[OnboardingOut]:
    return [
        OnboardingOut.model_validate(o)
        for o in onboarding.list_onboardings(session, principal, target_id)
    ]


@router.get("/onboarding/{onboarding_id}", response_model=OnboardingOut)
def get_onboarding(
    onboarding_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OnboardingOut:
    return OnboardingOut.model_validate(
        onboarding.get_onboarding(session, principal, onboarding_id)
    )


@router.post("/onboarding/{onboarding_id}/preflight", response_model=PreflightOut, status_code=201)
def request_preflight(
    onboarding_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PreflightOut:
    """Request a SIMULATED preflight (derived from the declared boundary).

    Takes no caller-supplied checks or collector labels: the result is always
    ``simulated`` / ``fake_declared_boundary`` and can never make a target eligible for
    live real provisioning. Live_verified evidence is produced only by the trusted
    worker-only provider collector (future B1-B).
    """
    pf = onboarding.record_simulated_preflight(session, principal, onboarding_id)
    return PreflightOut.model_validate(pf)


@router.get("/onboarding/{onboarding_id}/preflight", response_model=list[PreflightOut])
def list_preflights(
    onboarding_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[PreflightOut]:
    return [
        PreflightOut.model_validate(p)
        for p in onboarding.list_preflights(session, principal, onboarding_id)
    ]


@router.post("/onboarding/{onboarding_id}/submit", response_model=OnboardingOut)
def submit_for_review(
    onboarding_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OnboardingOut:
    return OnboardingOut.model_validate(
        onboarding.submit_for_review(session, principal, onboarding_id)
    )


@router.post("/onboarding/{onboarding_id}/approve", response_model=OnboardingOut)
def approve_onboarding(
    onboarding_id: uuid.UUID,
    body: OnboardingDecision,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OnboardingOut:
    """Explicit human approval — required before a target can become active."""
    return OnboardingOut.model_validate(
        onboarding.approve_onboarding(session, principal, onboarding_id, body.reason)
    )


@router.post("/onboarding/{onboarding_id}/reject", response_model=OnboardingOut)
def reject_onboarding(
    onboarding_id: uuid.UUID,
    body: OnboardingDecision,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OnboardingOut:
    return OnboardingOut.model_validate(
        onboarding.reject_onboarding(session, principal, onboarding_id, body.reason)
    )


@router.post("/onboarding/{onboarding_id}/activate", response_model=OnboardingOut)
def activate_onboarding(
    onboarding_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OnboardingOut:
    """Activate an approved onboarding (refused on config/scope drift since approval)."""
    return OnboardingOut.model_validate(
        onboarding.activate_onboarding(session, principal, onboarding_id)
    )


@router.post("/onboarding/{onboarding_id}/retire", response_model=OnboardingOut)
def retire_onboarding(
    onboarding_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OnboardingOut:
    return OnboardingOut.model_validate(
        onboarding.retire_onboarding(session, principal, onboarding_id)
    )
