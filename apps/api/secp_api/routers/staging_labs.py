"""Declarative disposable staging-lab routes (SECP-002B-1B-9, control plane only, fake-only).

The API creates a staging-lab desired state, compiles an immutable plan, drives approval, runs a
clearly-labeled fake simulation (worker-dispatched), reports lifecycle state, and requests fake
teardown. It NEVER imports worker/provider/runner/transport/secret/subprocess code, contacts no
infrastructure, and creates no real target or live-read authorization. Every execution control is
simulation-only — no infrastructure is created by this router.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_staging_lab import (
    StagingLabApprove,
    StagingLabCreate,
    StagingLabDecision,
    StagingLabOut,
)
from secp_api.services import staging_labs

router = APIRouter(prefix="/api/v1", tags=["staging-labs"])

# Every execution control in this PR is simulation-only. Surfaced to clients for display.
SIMULATION_ONLY_NOTICE = "Simulation only — no infrastructure will be created."


@router.post("/staging-labs", response_model=StagingLabOut, status_code=201)
def create_staging_lab(
    body: StagingLabCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    lab = staging_labs.create_staging_lab(
        session,
        principal,
        execution_target_id=body.execution_target_id,
        display_name=body.display_name,
        ownership_label=body.ownership_label,
        profile=body.profile,
        network_intent=body.network_intent,
        resource_class=body.resource_class,
        rollback_policy=body.rollback_policy,
        bootstrap_artifact_profile_id=body.bootstrap_artifact_profile_id,
    )
    return StagingLabOut.model_validate(lab)


@router.get("/staging-labs", response_model=list[StagingLabOut])
def list_staging_labs(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[StagingLabOut]:
    return [
        StagingLabOut.model_validate(lab)
        for lab in staging_labs.list_staging_labs(session, principal)
    ]


@router.get("/staging-labs/{lab_id}", response_model=StagingLabOut)
def get_staging_lab(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    return StagingLabOut.model_validate(staging_labs.get_staging_lab(session, principal, lab_id))


@router.post("/staging-labs/{lab_id}/plan", response_model=StagingLabOut)
def generate_plan(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    """Compile the immutable logical plan (no infrastructure is created)."""
    return StagingLabOut.model_validate(staging_labs.generate_plan(session, principal, lab_id))


@router.post("/staging-labs/{lab_id}/submit", response_model=StagingLabOut)
def submit_for_approval(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    return StagingLabOut.model_validate(
        staging_labs.submit_for_approval(session, principal, lab_id)
    )


@router.post("/staging-labs/{lab_id}/approve", response_model=StagingLabOut)
def approve_staging_lab(
    lab_id: uuid.UUID,
    body: StagingLabApprove,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    """Approve the exact reviewed plan. Grants permission to enter FAKE simulation only —
    this is not a live-read authorization."""
    return StagingLabOut.model_validate(
        staging_labs.approve_staging_lab(
            session,
            principal,
            lab_id,
            expected_plan_hash=body.expected_plan_hash,
            reason=body.reason,
        )
    )


@router.post("/staging-labs/{lab_id}/reject", response_model=StagingLabOut)
def reject_staging_lab(
    lab_id: uuid.UUID,
    body: StagingLabDecision,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    return StagingLabOut.model_validate(
        staging_labs.reject_staging_lab(session, principal, lab_id, body.reason)
    )


@router.post("/staging-labs/{lab_id}/simulate", response_model=StagingLabOut)
def simulate_staging_lab(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    """Run the labeled fake simulation. Simulation only — no infrastructure will be created."""
    return StagingLabOut.model_validate(staging_labs.request_simulation(session, principal, lab_id))


@router.post("/staging-labs/{lab_id}/teardown", response_model=StagingLabOut)
def teardown_staging_lab(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    """Request controlled FAKE teardown. Simulation only — no infrastructure exists to destroy."""
    return StagingLabOut.model_validate(staging_labs.request_teardown(session, principal, lab_id))
