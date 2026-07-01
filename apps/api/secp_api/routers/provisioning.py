"""Provisioning manifest + operation routes (SECP-002B-0, control plane only).

The API generates immutable manifests and reads manifests/operations. It NEVER
imports a runner, OpenTofu, or a provider client, and never resolves secrets. The
fake runner executes only in the worker behind the safety gate (ADR-012).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_provisioning import (
    ApprovalDecision,
    ChangeSetApprovalOut,
    ManifestOut,
    OperationOut,
    ToolchainProfileCreate,
    ToolchainProfileOut,
)
from secp_api.services import approvals, manifests, provisioning, toolchain

router = APIRouter(prefix="/api/v1", tags=["provisioning"])


@router.post("/plans/{plan_id}/manifest", response_model=ManifestOut, status_code=201)
def generate_manifest(
    plan_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ManifestOut:
    """Generate an immutable, secret-free provisioning manifest from an approved plan."""
    manifest = manifests.generate_manifest(session, principal, plan_id)
    return ManifestOut.model_validate(manifest)


@router.get("/manifests/{manifest_id}", response_model=ManifestOut)
def get_manifest(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ManifestOut:
    return ManifestOut.model_validate(manifests.get_manifest(session, principal, manifest_id))


@router.get("/manifests/{manifest_id}/operations", response_model=list[OperationOut])
def list_operations(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[OperationOut]:
    return [
        OperationOut.model_validate(o)
        for o in provisioning.list_operations(session, principal, manifest_id)
    ]


@router.get("/provisioning-operations/{operation_id}", response_model=OperationOut)
def get_operation(
    operation_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> OperationOut:
    return OperationOut.model_validate(provisioning.get_operation(session, principal, operation_id))


# --- Toolchain profiles (SECP-002B-1A, ADR-013) ------------------------------


@router.post(
    "/targets/{target_id}/toolchain-profiles",
    response_model=ToolchainProfileOut,
    status_code=201,
)
def register_toolchain_profile(
    target_id: uuid.UUID,
    body: ToolchainProfileCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ToolchainProfileOut:
    """Register an immutable, secret-free toolchain profile for an execution target."""
    tp = toolchain.register_toolchain_profile(
        session, principal, target_id=target_id, name=body.name, profile=body.profile
    )
    return ToolchainProfileOut.model_validate(tp)


@router.get("/targets/{target_id}/toolchain-profiles", response_model=list[ToolchainProfileOut])
def list_toolchain_profiles(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[ToolchainProfileOut]:
    return [
        ToolchainProfileOut.model_validate(tp)
        for tp in toolchain.list_toolchain_profiles(session, principal, target_id)
    ]


@router.get("/toolchain-profiles/{profile_id}", response_model=ToolchainProfileOut)
def get_toolchain_profile(
    profile_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ToolchainProfileOut:
    return ToolchainProfileOut.model_validate(
        toolchain.get_toolchain_profile(session, principal, profile_id)
    )


@router.post("/toolchain-profiles/{profile_id}/disable", response_model=ToolchainProfileOut)
def disable_toolchain_profile(
    profile_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ToolchainProfileOut:
    return ToolchainProfileOut.model_validate(
        toolchain.disable_toolchain_profile(session, principal, profile_id)
    )


# --- Change-set approvals (SECP-002B-1A, ADR-013) ----------------------------


@router.get("/manifests/{manifest_id}/change-sets", response_model=list[ChangeSetApprovalOut])
def list_change_sets(
    manifest_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[ChangeSetApprovalOut]:
    return [
        ChangeSetApprovalOut.model_validate(a)
        for a in approvals.list_change_set_approvals(session, principal, manifest_id)
    ]


@router.get("/change-sets/{approval_id}", response_model=ChangeSetApprovalOut)
def get_change_set(
    approval_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ChangeSetApprovalOut:
    return ChangeSetApprovalOut.model_validate(
        approvals.get_change_set_approval(session, principal, approval_id)
    )


@router.post("/change-sets/{approval_id}/approve", response_model=ChangeSetApprovalOut)
def approve_change_set(
    approval_id: uuid.UUID,
    body: ApprovalDecision,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ChangeSetApprovalOut:
    """Explicit human approval of an exact dry-run change set (no AI, no bypass)."""
    return ChangeSetApprovalOut.model_validate(
        approvals.approve_change_set(session, principal, approval_id, body.reason)
    )


@router.post("/change-sets/{approval_id}/reject", response_model=ChangeSetApprovalOut)
def reject_change_set(
    approval_id: uuid.UUID,
    body: ApprovalDecision,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ChangeSetApprovalOut:
    return ChangeSetApprovalOut.model_validate(
        approvals.reject_change_set(session, principal, approval_id, body.reason)
    )
