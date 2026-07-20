"""SECP-B8 — worker discovery node public-key publication API surface.

Lets the UI auto-populate the bootstrap wizard's "Worker SSH public key" field from a worker's
self-published PUBLIC material (so the operator never runs ``ssh-keygen``). Every endpoint delegates
to ``services.worker_nodes`` (permission checks live there). A private key is never accepted — the
service validates that the SSH key is a PUBLIC key and rejects private-key material.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_worker_nodes import (
    WorkerNodeIdentityApprovalLinkRequest,
    WorkerNodeOut,
    WorkerNodeRegisterRequest,
)
from secp_api.services import worker_nodes as svc

# Nested under the read-only-bootstrap prefix so the single-segment
# ``GET /api/v1/target-discovery/{enrollment_id}`` route cannot shadow it.
router = APIRouter(
    prefix="/api/v1/target-discovery/read-only-bootstrap/worker-nodes", tags=["target-discovery"]
)


@router.get("", response_model=list[WorkerNodeOut])
def list_worker_nodes(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[WorkerNodeOut]:
    return [WorkerNodeOut.model_validate(r) for r in svc.list_worker_nodes(session, principal)]


@router.post("", response_model=WorkerNodeOut, status_code=201)
def register_worker_node(
    body: WorkerNodeRegisterRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerNodeOut:
    row = svc.register_worker_node(
        session,
        principal,
        node_label=body.node_label,
        ssh_public_key=body.ssh_public_key,
        admission_anchor_hex=body.admission_anchor_hex,
    )
    return WorkerNodeOut.model_validate(row)


@router.get("/{node_id}", response_model=WorkerNodeOut)
def get_worker_node(
    node_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerNodeOut:
    return WorkerNodeOut.model_validate(svc.get_worker_node(session, principal, node_id))


@router.post("/{node_id}/identity-approval-link", response_model=WorkerNodeOut)
def approve_and_link_worker_identity(
    node_id: uuid.UUID,
    body: WorkerNodeIdentityApprovalLinkRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerNodeOut:
    """Perform one explicit reviewed registration/evidence/approval/link transaction.

    This is a composition of the existing worker-identity lifecycle operations. It does not add a
    second lifecycle, infer evidence, or silently approve publication.
    """
    return WorkerNodeOut.model_validate(
        svc.approve_and_link_worker_node_identity(
            session,
            principal,
            node_id=node_id,
            expected_node_revision=body.expected_node_revision,
            expected_ssh_public_key_fingerprint=body.expected_ssh_public_key_fingerprint,
            expected_admission_anchor_fingerprint=body.expected_admission_anchor_fingerprint,
            deployment_binding=body.deployment_binding,
            proof_id=body.proof_id,
            issuer=body.issuer,
            deployment_binding_review_confirmed=body.deployment_binding_review_confirmed,
            verification_anchor_review_confirmed=body.verification_anchor_review_confirmed,
            rotation_revocation_review_confirmed=body.rotation_revocation_review_confirmed,
        )
    )
