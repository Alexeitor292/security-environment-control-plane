"""Real staging-lab deployment lifecycle routes (SECP-B4 §2, control plane only).

The API creates a deployment desired state, compiles an immutable content-addressed plan, drives ONE
explicit exact-plan approval, and **enqueues durable operations** (apply / teardown) — it NEVER
executes them and NEVER contacts infrastructure. Only a worker (the deployment engine) may claim a
committed operation and perform a real host action, and only after re-verifying every binding.

This router NEVER imports or constructs SSH, Proxmox, OpenBao, artifact-download, subprocess, or
provider clients, and accepts NO SSH material, API token, host/endpoint, free-form command, shell
text, bridge/storage name, VMID, network range, path, or arbitrary provider option. There is NO
"enable live mode" toggle. Bootstrap authority is surfaced only as a safe boolean + closed reason.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_staging_deployment import (
    BootstrapAvailabilityOut,
    DeploymentApprove,
    DeploymentCreate,
    DeploymentOut,
    DeploymentPlanOut,
    DeploymentResourceOut,
    DeploymentVerificationOut,
    PlannedResourceOut,
)
from secp_api.services import staging_deployment as svc

router = APIRouter(prefix="/api/v1", tags=["staging-deployments"])

# Every control here queues durable work only. No real host is contacted until this PR is merged, a
# worker-local bootstrap bundle is injected into the running worker, and an exact plan is approved.
CONTROL_PLANE_ONLY_NOTICE = "Control plane only — no infrastructure is contacted by the API."


@router.post("/staging-deployments", response_model=DeploymentOut, status_code=201)
def create_deployment(
    body: DeploymentCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    """Create a draft deployment bound to an active onboarding (all labels are server-owned)."""
    dep = svc.create_deployment(
        session,
        principal,
        execution_target_id=body.execution_target_id,
        resource_profile=body.resource_profile,
        logical_name=body.logical_name,
    )
    return DeploymentOut.model_validate(dep)


@router.get("/staging-deployments", response_model=list[DeploymentOut])
def list_deployments(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[DeploymentOut]:
    return [DeploymentOut.model_validate(d) for d in svc.list_deployments(session, principal)]


@router.get("/staging-deployments/{deployment_id}", response_model=DeploymentOut)
def get_deployment(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    return DeploymentOut.model_validate(svc.get_deployment(session, principal, deployment_id))


@router.get("/staging-deployments/{deployment_id}/plan", response_model=DeploymentPlanOut)
def get_plan(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentPlanOut:
    """The immutable content-addressed plan: safe resource CATEGORIES + counts + generated refs."""
    plan = svc.get_active_plan(session, principal, deployment_id)
    resources = [
        PlannedResourceOut(
            kind=str(entry["kind"]),
            count=int(entry["count"]),
            resource_ref=str(entry["resource_ref"]),
        )
        for entry in plan.plan_document.get("resources", [])
    ]
    return DeploymentPlanOut(
        plan_version=plan.plan_version,
        plan_hash=plan.plan_hash,
        ownership_tag=plan.ownership_tag,
        capacity_assessment_hash=plan.capacity_assessment_hash,
        artifact_manifest_id=plan.artifact_manifest_id,
        resources=resources,
    )


@router.get(
    "/staging-deployments/{deployment_id}/resources",
    response_model=list[DeploymentResourceOut],
)
def list_resources(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[DeploymentResourceOut]:
    """Resources the deployment created — safe category, ownership tag, generated ref, and state."""
    return [
        DeploymentResourceOut.model_validate(r)
        for r in svc.list_resources(session, principal, deployment_id)
    ]


@router.get(
    "/staging-deployments/{deployment_id}/verifications",
    response_model=list[DeploymentVerificationOut],
)
def list_verifications(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[DeploymentVerificationOut]:
    """Post-apply verification results — closed check code + status only."""
    return [
        DeploymentVerificationOut.model_validate(v)
        for v in svc.list_verifications(session, principal, deployment_id)
    ]


@router.get(
    "/staging-deployments/{deployment_id}/bootstrap-availability",
    response_model=BootstrapAvailabilityOut,
)
def get_bootstrap_availability(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BootstrapAvailabilityOut:
    """A SAFE boolean + closed reason only. The one-time SSH bootstrap authority is worker-local and
    deployment-mounted; the API cannot and must not read it, so it is always reported unavailable
    here with a closed reason (never its location or contents)."""
    svc.get_deployment(session, principal, deployment_id)  # authorize + 404 on unknown
    return BootstrapAvailabilityOut()


@router.post("/staging-deployments/{deployment_id}/plan", response_model=DeploymentOut)
def generate_plan(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    """Compile the immutable content-addressed plan (draft -> planned). No infrastructure hit."""
    return DeploymentOut.model_validate(svc.generate_plan(session, principal, deployment_id))


@router.post("/staging-deployments/{deployment_id}/submit", response_model=DeploymentOut)
def submit_for_approval(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    """planned -> awaiting_approval."""
    return DeploymentOut.model_validate(svc.submit_for_approval(session, principal, deployment_id))


@router.post("/staging-deployments/{deployment_id}/approve", response_model=DeploymentOut)
def approve_deployment(
    deployment_id: uuid.UUID,
    body: DeploymentApprove,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    """Approve the EXACT reviewed plan (awaiting_approval -> approved), binding every drift anchor.
    Approval alone contacts nothing; it only authorizes a later worker-executed apply."""
    return DeploymentOut.model_validate(
        svc.approve_deployment(
            session, principal, deployment_id, expected_plan_hash=body.expected_plan_hash
        )
    )


@router.post("/staging-deployments/{deployment_id}/reject", response_model=DeploymentOut)
def reject_deployment(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    """Reject a deployment awaiting approval. Records the closed decision code (no free text)."""
    return DeploymentOut.model_validate(svc.reject_deployment(session, principal, deployment_id))


@router.post("/staging-deployments/{deployment_id}/deploy", response_model=DeploymentOut)
def deploy(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    """approved -> bootstrap_pending; ENQUEUES the durable apply operation (never run by the API).

    The apply only proceeds if a worker-local bootstrap bundle has been injected into the running
    worker AND the exact approved plan still re-verifies; the API neither knows nor controls this.
    """
    return DeploymentOut.model_validate(svc.submit_deployment(session, principal, deployment_id))


@router.post("/staging-deployments/{deployment_id}/teardown", response_model=DeploymentOut)
def request_teardown(
    deployment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DeploymentOut:
    """ready/failed/rolled_back -> teardown_requested; enqueues the durable teardown operation."""
    return DeploymentOut.model_validate(svc.request_teardown(session, principal, deployment_id))
