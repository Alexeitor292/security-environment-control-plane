"""Remote-state + plan-secret readiness API (B1B-PR4 / ADR-021 §P) — ENQUEUE-ONLY + read models.

Every route is organization-scoped and permission-protected. The API:

* durably ENQUEUES a readiness operation (the dispatcher refuses inline execution, no fallback);
* exposes bounded, redacted read models;
* runs the plan-secret authorization admin lifecycle (create draft → record review evidence →
  approve under a DEDICATED permission → revoke).

It NEVER contacts a state backend or a secret manager, constructs a resolver or a state adapter,
inspects a target connection value, builds a process environment, receives secret material, or calls
worker readiness orchestration. **Requesting state readiness does not request secret readiness;
neither creates a plan.** There is no backend-configuration form, no secret entry, no state-key
entry, and no activation toggle.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.enums import ReadinessOperationKind, WorkflowKind
from secp_api.errors import ReadinessError
from secp_api.schemas_readiness import (
    CreatePlanSecretAuthorizationIn,
    PlanSecretAuthorizationOut,
    PlanSecretReadinessOut,
    ProvisioningReadinessOut,
    ReadinessRequestAccepted,
    RecordPlanSecretEvidenceIn,
    RemoteStateReadinessOut,
    RevokePlanSecretAuthorizationIn,
    ToolchainAttestationOut,
)
from secp_api.services import plan_secret_authorization, readiness

router = APIRouter(prefix="/api/v1", tags=["provisioning-readiness"])

_MANIFEST = "/provisioning-manifests/{manifest_id}"


@router.post(
    f"{_MANIFEST}/toolchain-attestation",
    response_model=ReadinessRequestAccepted,
    status_code=202,
)
def request_toolchain_attestation(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ReadinessRequestAccepted:
    """Explicitly request the worker-owned PR2 toolchain attestation (enqueue-only).

    A hard PREREQUISITE of BOTH readiness operations: a matching toolchain-profile hash is not an
    attestation. The API reads no worker-local filesystem and executes no binary.
    """
    readiness.request_toolchain_attestation(session, principal, manifest_id)
    return ReadinessRequestAccepted(
        operation_kind=WorkflowKind.toolchain_attestation.value,
        provisioning_manifest_id=str(manifest_id),
    )


@router.get(
    f"{_MANIFEST}/toolchain-attestation",
    response_model=ToolchainAttestationOut | None,
)
def get_toolchain_attestation(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ToolchainAttestationOut | None:
    view = readiness.get_toolchain_attestation(session, principal, manifest_id)
    return None if view is None else ToolchainAttestationOut.model_validate(view)


@router.post(
    f"{_MANIFEST}/remote-state-readiness",
    response_model=ReadinessRequestAccepted,
    status_code=202,
)
def request_remote_state_readiness(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ReadinessRequestAccepted:
    """Explicitly request the worker-owned remote-state readiness operation (enqueue-only)."""
    readiness.request_remote_state_readiness(session, principal, manifest_id)
    return ReadinessRequestAccepted(
        operation_kind=ReadinessOperationKind.remote_state_readiness.value,
        provisioning_manifest_id=str(manifest_id),
    )


@router.get(
    f"{_MANIFEST}/remote-state-readiness",
    response_model=RemoteStateReadinessOut | None,
)
def get_remote_state_readiness(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> RemoteStateReadinessOut | None:
    view = readiness.get_remote_state_readiness(session, principal, manifest_id)
    return None if view is None else RemoteStateReadinessOut.model_validate(view)


@router.post(
    f"{_MANIFEST}/plan-secret-readiness",
    response_model=ReadinessRequestAccepted,
    status_code=202,
)
def request_plan_secret_readiness(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ReadinessRequestAccepted:
    """Explicitly request the worker-owned plan-secret readiness operation (enqueue-only).

    A SEPARATE operator action: it is never triggered by eligibility, toolchain attestation, or a
    successful state readiness, and it never advances to a plan.
    """
    readiness.request_plan_secret_readiness(session, principal, manifest_id)
    return ReadinessRequestAccepted(
        operation_kind=ReadinessOperationKind.plan_secret_readiness.value,
        provisioning_manifest_id=str(manifest_id),
    )


@router.get(
    f"{_MANIFEST}/plan-secret-readiness",
    response_model=PlanSecretReadinessOut | None,
)
def get_plan_secret_readiness(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanSecretReadinessOut | None:
    view = readiness.get_plan_secret_readiness(session, principal, manifest_id)
    return None if view is None else PlanSecretReadinessOut.model_validate(view)


@router.get(f"{_MANIFEST}/provisioning-readiness", response_model=ProvisioningReadinessOut)
def get_provisioning_readiness(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ProvisioningReadinessOut:
    """The derived combined current-readiness view. It is NOT plan approval and launches nothing."""
    return ProvisioningReadinessOut.model_validate(
        readiness.get_provisioning_readiness(session, principal, manifest_id)
    )


# --- plan-secret authorization admin lifecycle ---------------------------------------------------


@router.post(
    f"{_MANIFEST}/plan-secret-authorizations",
    response_model=PlanSecretAuthorizationOut,
    status_code=201,
)
def create_plan_secret_authorization(
    manifest_id: uuid.UUID,
    body: CreatePlanSecretAuthorizationIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanSecretAuthorizationOut:
    """Create a DRAFT plan-secret authorization. Creating it does NOT run readiness."""
    row = plan_secret_authorization.create_plan_secret_authorization(
        session,
        principal,
        manifest_id=manifest_id,
        purpose=body.purpose.value,
        ttl_seconds=body.ttl_seconds,
    )
    session.flush()
    return PlanSecretAuthorizationOut.model_validate(readiness.plan_secret_authorization_view(row))


@router.post(
    "/plan-secret-authorizations/{authorization_id}/evidence",
    response_model=PlanSecretAuthorizationOut,
)
def record_plan_secret_evidence(
    authorization_id: uuid.UUID,
    body: RecordPlanSecretEvidenceIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanSecretAuthorizationOut:
    plan_secret_authorization.record_plan_secret_evidence(
        session,
        principal,
        authorization_id,
        kind=body.kind,
        status=body.status,
        proof_id=body.proof_id,
        issuer=body.issuer,
    )
    row = plan_secret_authorization.get_plan_secret_authorization(
        session, principal, authorization_id
    )
    return PlanSecretAuthorizationOut.model_validate(readiness.plan_secret_authorization_view(row))


@router.post(
    "/plan-secret-authorizations/{authorization_id}/approve",
    response_model=PlanSecretAuthorizationOut,
)
def approve_plan_secret_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanSecretAuthorizationOut:
    """Approve under the DEDICATED ``readiness:approve`` permission. Approving runs NO readiness."""
    try:
        row = plan_secret_authorization.approve_plan_secret_authorization(
            session, principal, authorization_id
        )
    except ReadinessError as exc:
        # A fail-closed approve on an EXPIRED authorization also materializes the terminal
        # ``expired`` transition + its single expiry audit. Commit that durable transition here
        # (only when it actually won its CAS) so it survives the request; ``db_session`` would
        # otherwise roll it back. Then re-raise so the caller still gets the redacted 409.
        if exc.durable_transition:
            session.commit()
        raise
    return PlanSecretAuthorizationOut.model_validate(readiness.plan_secret_authorization_view(row))


@router.post(
    "/plan-secret-authorizations/{authorization_id}/revoke",
    response_model=PlanSecretAuthorizationOut,
)
def revoke_plan_secret_authorization(
    authorization_id: uuid.UUID,
    body: RevokePlanSecretAuthorizationIn,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanSecretAuthorizationOut:
    """Revoke immediately. All FUTURE use is invalidated; historical evidence is never mutated."""
    row = plan_secret_authorization.revoke_plan_secret_authorization(
        session, principal, authorization_id, body.reason_code
    )
    return PlanSecretAuthorizationOut.model_validate(readiness.plan_secret_authorization_view(row))


@router.get(
    "/plan-secret-authorizations/{authorization_id}",
    response_model=PlanSecretAuthorizationOut,
)
def get_plan_secret_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanSecretAuthorizationOut:
    row = plan_secret_authorization.get_plan_secret_authorization(
        session, principal, authorization_id
    )
    return PlanSecretAuthorizationOut.model_validate(readiness.plan_secret_authorization_view(row))
