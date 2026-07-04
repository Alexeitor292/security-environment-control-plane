"""Declarative disposable staging-lab routes (SECP-002B-1B-9, control plane only, fake-only).

The API creates a staging-lab desired state, compiles an immutable plan, drives approval, and
**enqueues durable work items** for simulation/teardown — it never executes them. It NEVER imports
worker/provider/runner/transport/secret/subprocess code, contacts no infrastructure, and creates
no real target or live-read authorization. Every execution control queues work only; a worker
records completion. There is NO endpoint here to grant staging-substrate eligibility.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_staging_lab import (
    EligibleSubstrateOut,
    StagingLabApprove,
    StagingLabCreate,
    StagingLabOut,
    StagingLabWorkItemOut,
)
from secp_api.services import staging_labs

router = APIRouter(prefix="/api/v1", tags=["staging-labs"])

# Every execution control in this PR queues fake work only — no infrastructure is created.
SIMULATION_ONLY_NOTICE = "Simulation only — no infrastructure will be created."


@router.get("/staging-labs/eligible-substrates", response_model=list[EligibleSubstrateOut])
def list_eligible_substrates(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[EligibleSubstrateOut]:
    """Substrates the UI may offer: same-org, active, Proxmox, eligible, onboarded (aliases)."""
    return [
        EligibleSubstrateOut(id=row["id"], alias=row["alias"])
        for row in staging_labs.list_eligible_substrates(session, principal)
    ]


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
        resource_class=body.resource_class,
        rollback_policy=body.rollback_policy,
        bootstrap_artifact_profile=body.bootstrap_artifact_profile,
        logical_name=body.logical_name,
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


@router.get("/staging-labs/{lab_id}/work-items", response_model=list[StagingLabWorkItemOut])
def list_work_items(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[StagingLabWorkItemOut]:
    return [
        StagingLabWorkItemOut.model_validate(item)
        for item in staging_labs.list_work_items(session, principal, lab_id)
    ]


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
    """Approve the exact reviewed plan. Grants permission to ENQUEUE fake simulation only —
    this is not a live-read authorization. Records the closed decision code (no free text)."""
    return StagingLabOut.model_validate(
        staging_labs.approve_staging_lab(
            session, principal, lab_id, expected_plan_hash=body.expected_plan_hash
        )
    )


@router.post("/staging-labs/{lab_id}/reject", response_model=StagingLabOut)
def reject_staging_lab(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    """Reject a lab awaiting approval. Records the closed decision code (no free text)."""
    return StagingLabOut.model_validate(staging_labs.reject_staging_lab(session, principal, lab_id))


@router.post("/staging-labs/{lab_id}/simulate", response_model=StagingLabOut)
def queue_simulation(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    """QUEUE a fake simulation. Simulation only — no infrastructure will be created. The lab
    enters ``simulation_queued``; a worker records completion later. The work identity is a
    server-generated fingerprint (no caller idempotency key)."""
    return StagingLabOut.model_validate(staging_labs.queue_simulation(session, principal, lab_id))


@router.post("/staging-labs/{lab_id}/teardown", response_model=StagingLabOut)
def queue_teardown(
    lab_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> StagingLabOut:
    """QUEUE a fake teardown. Simulation only — no infrastructure exists to destroy. The lab
    enters ``teardown_queued``; a worker records completion later."""
    return StagingLabOut.model_validate(staging_labs.queue_teardown(session, principal, lab_id))
