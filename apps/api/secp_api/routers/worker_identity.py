"""Worker-identity registration admin lifecycle API (SECP-B2-4.3).

App-owned administrative lifecycle only: register a draft trust anchor, record closed evidence, view
the safe state/evidence summary, approve (separate permission), and revoke. There is NO certificate,
key, CSR, CA, endpoint, backend configuration, credential, or attestation-material entry, and NO
activation-toggle route. Approving a registration does NOT authenticate any worker — a worker
independently re-verifies it and the shipped runtime remains deny-by-default.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.errors import WorkerIdentityError
from secp_api.schemas_worker_identity import (
    RecordWorkerIdentityEvidence,
    RegisterWorkerIdentity,
    WorkerIdentityOut,
)
from secp_api.services import worker_identity

router = APIRouter(prefix="/api/v1/worker-identity", tags=["worker-identity"])


@router.post("/registrations", response_model=WorkerIdentityOut, status_code=201)
def register(
    body: RegisterWorkerIdentity,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerIdentityOut:
    return WorkerIdentityOut.model_validate(
        worker_identity.register_worker_identity(
            session,
            principal,
            mechanism=body.mechanism,
            identity_label=body.identity_label,
            deployment_binding=body.deployment_binding,
            verification_anchor_fingerprint=body.verification_anchor_fingerprint,
            ttl_seconds=body.ttl_seconds,
        )
    )


@router.get("/registrations", response_model=list[WorkerIdentityOut])
def list_registrations(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[WorkerIdentityOut]:
    return [
        WorkerIdentityOut.model_validate(r)
        for r in worker_identity.list_worker_identities(session, principal)
    ]


@router.get("/registrations/{registration_id}", response_model=WorkerIdentityOut)
def get_registration(
    registration_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerIdentityOut:
    return WorkerIdentityOut.model_validate(
        worker_identity.get_worker_identity(session, principal, registration_id)
    )


@router.post("/registrations/{registration_id}/evidence", response_model=WorkerIdentityOut)
def record_evidence(
    registration_id: uuid.UUID,
    body: RecordWorkerIdentityEvidence,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerIdentityOut:
    worker_identity.record_evidence(
        session,
        principal,
        registration_id,
        kind=body.kind,
        status=body.status,
        proof_id=body.proof_id,
        issuer=body.issuer,
    )
    return WorkerIdentityOut.model_validate(
        worker_identity.get_worker_identity(session, principal, registration_id)
    )


@router.post("/registrations/{registration_id}/approve", response_model=WorkerIdentityOut)
def approve(
    registration_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerIdentityOut:
    try:
        return WorkerIdentityOut.model_validate(
            worker_identity.approve_worker_identity(session, principal, registration_id)
        )
    except WorkerIdentityError as exc:
        # A fail-closed approve on an EXPIRED registration also materializes the terminal
        # ``expired`` transition + its single expiration audit. Commit that transition here (only
        # it won its CAS) so it survives the request; ``db_session`` would otherwise roll it back.
        # Then re-raise so the caller still gets the redacted 409.
        if getattr(exc, "durable_transition", False):
            session.commit()
        raise


@router.post("/registrations/{registration_id}/revoke", response_model=WorkerIdentityOut)
def revoke(
    registration_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkerIdentityOut:
    return WorkerIdentityOut.model_validate(
        worker_identity.revoke_worker_identity(session, principal, registration_id)
    )
