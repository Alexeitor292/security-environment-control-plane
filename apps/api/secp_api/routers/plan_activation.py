"""B1B-PR5A plan-activation API (ADR-022) — enqueue-only + lifecycle admin + safe read models.

Every route is organization-scoped and permission-protected (enforced in the service layer). The API
runs the activation-dossier lifecycle and the plan-generation-authorization lifecycle, exposes the
combined plan-readiness read model, and durably ENQUEUES the real-plan-generation operation (the
dispatcher refuses inline execution with no fallback). It contacts nothing, resolves no credential,
constructs no executor, renders nothing, and generates no plan. **No lifecycle transition ever
auto-triggers a plan-generation request.**
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.enums import WorkflowKind
from secp_api.schemas_plan_activation import (
    ActivationDossierOut,
    CreateActivationDossierIn,
    CreatePlanGenerationAuthorizationIn,
    PlanGenerationAuthorizationOut,
    PlanGenerationReadinessOut,
    PlanGenerationRequestAccepted,
    RecordDossierEvidenceIn,
    RevokeDossierIn,
    RevokePlanGenerationAuthorizationIn,
)
from secp_api.services import plan_activation

router = APIRouter(prefix="/api/v1", tags=["plan-activation"])

_MANIFEST = "/provisioning-manifests/{manifest_id}"


# --- activation dossier lifecycle ----------------------------------------------------------------


@router.post(
    f"{_MANIFEST}/activation-dossiers",
    response_model=ActivationDossierOut,
    status_code=201,
)
def create_activation_dossier(
    manifest_id: uuid.UUID,
    body: CreateActivationDossierIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ActivationDossierOut:
    """Create a DRAFT activation dossier. Creating it executes nothing and contacts nothing."""
    row = plan_activation.create_activation_dossier(
        session,
        principal,
        manifest_id=manifest_id,
        recovery_owner_proof=body.recovery_owner_proof,
        emergency_stop_owner_proof=body.emergency_stop_owner_proof,
        ttl_seconds=body.ttl_seconds,
    )
    session.flush()
    return ActivationDossierOut.model_validate(plan_activation.dossier_view(row))


@router.post("/activation-dossiers/{dossier_id}/evidence", response_model=ActivationDossierOut)
def record_dossier_evidence(
    dossier_id: uuid.UUID,
    body: RecordDossierEvidenceIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ActivationDossierOut:
    plan_activation.record_dossier_evidence(
        session,
        principal,
        dossier_id,
        kind=body.kind,
        status=body.status,
        proof_id=body.proof_id,
        issuer=body.issuer,
    )
    row = plan_activation.get_activation_dossier(session, principal, dossier_id)
    return ActivationDossierOut.model_validate(plan_activation.dossier_view(row))


@router.post("/activation-dossiers/{dossier_id}/approve", response_model=ActivationDossierOut)
def approve_activation_dossier(
    dossier_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ActivationDossierOut:
    """Approve under the DEDICATED ``activation_dossier:approve`` permission. Approving runs
    nothing."""
    row = plan_activation.approve_activation_dossier(session, principal, dossier_id)
    return ActivationDossierOut.model_validate(plan_activation.dossier_view(row))


@router.post("/activation-dossiers/{dossier_id}/revoke", response_model=ActivationDossierOut)
def revoke_activation_dossier(
    dossier_id: uuid.UUID,
    body: RevokeDossierIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ActivationDossierOut:
    row = plan_activation.revoke_activation_dossier(
        session, principal, dossier_id, body.reason_code
    )
    return ActivationDossierOut.model_validate(plan_activation.dossier_view(row))


@router.get("/activation-dossiers/{dossier_id}", response_model=ActivationDossierOut)
def get_activation_dossier(
    dossier_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ActivationDossierOut:
    row = plan_activation.get_activation_dossier(session, principal, dossier_id)
    return ActivationDossierOut.model_validate(plan_activation.dossier_view(row))


# --- plan-generation authorization lifecycle -----------------------------------------------------


@router.post(
    f"{_MANIFEST}/plan-generation-authorizations",
    response_model=PlanGenerationAuthorizationOut,
    status_code=201,
)
def create_plan_generation_authorization(
    manifest_id: uuid.UUID,
    body: CreatePlanGenerationAuthorizationIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanGenerationAuthorizationOut:
    """Create a DRAFT plan-generation authorization. Creating it does NOT enqueue execution."""
    row = plan_activation.create_plan_generation_authorization(
        session, principal, manifest_id=manifest_id, ttl_seconds=body.ttl_seconds
    )
    session.flush()
    return PlanGenerationAuthorizationOut.model_validate(
        plan_activation.plan_generation_authorization_view(row)
    )


@router.post(
    "/plan-generation-authorizations/{authorization_id}/approve",
    response_model=PlanGenerationAuthorizationOut,
)
def approve_plan_generation_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanGenerationAuthorizationOut:
    """Approve under the DEDICATED ``plan_generation:approve`` permission. Approving executes
    nothing."""
    row = plan_activation.approve_plan_generation_authorization(
        session, principal, authorization_id
    )
    return PlanGenerationAuthorizationOut.model_validate(
        plan_activation.plan_generation_authorization_view(row)
    )


@router.post(
    "/plan-generation-authorizations/{authorization_id}/revoke",
    response_model=PlanGenerationAuthorizationOut,
)
def revoke_plan_generation_authorization(
    authorization_id: uuid.UUID,
    body: RevokePlanGenerationAuthorizationIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanGenerationAuthorizationOut:
    row = plan_activation.revoke_plan_generation_authorization(
        session, principal, authorization_id, body.reason_code
    )
    return PlanGenerationAuthorizationOut.model_validate(
        plan_activation.plan_generation_authorization_view(row)
    )


@router.get(
    "/plan-generation-authorizations/{authorization_id}",
    response_model=PlanGenerationAuthorizationOut,
)
def get_plan_generation_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanGenerationAuthorizationOut:
    row = plan_activation.get_plan_generation_authorization(session, principal, authorization_id)
    return PlanGenerationAuthorizationOut.model_validate(
        plan_activation.plan_generation_authorization_view(row)
    )


# --- combined plan readiness + enqueue-only plan-generation request ------------------------------


@router.get(f"{_MANIFEST}/plan-generation-readiness", response_model=PlanGenerationReadinessOut)
def get_plan_generation_readiness(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanGenerationReadinessOut:
    """The derived combined plan-readiness view. It is NOT plan approval and launches nothing."""
    return PlanGenerationReadinessOut.model_validate(
        plan_activation.get_plan_generation_readiness(session, principal, manifest_id)
    )


@router.post(
    f"{_MANIFEST}/plan-generation",
    response_model=PlanGenerationRequestAccepted,
    status_code=202,
)
def request_plan_generation(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanGenerationRequestAccepted:
    """Explicitly request the worker-owned real-plan-generation operation (enqueue-only).

    It durably enqueues a workflow run + outbox row; the inline dispatcher refuses with no fallback.
    The worker loads the authoritative records, evaluates combined plan-readiness, and REFUSES at
    the
    still-sealed plan-only process boundary. It is NEVER auto-triggered by readiness or approval.
    """
    plan_activation.request_plan_generation(session, principal, manifest_id)
    return PlanGenerationRequestAccepted(
        operation_kind=WorkflowKind.real_plan_generation.value,
        provisioning_manifest_id=str(manifest_id),
    )
