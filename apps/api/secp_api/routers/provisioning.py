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
from secp_api.schemas_provisioning import ManifestOut, OperationOut
from secp_api.services import manifests, provisioning

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
