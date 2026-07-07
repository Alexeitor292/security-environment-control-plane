"""Internal worker discovery-admission route (SECP-B6 MB-1).

A narrowly scoped, NON-public, worker-only endpoint through which an isolated worker performs the
control-plane-verified admission handshake before live discovery. It is NOT mounted under the public
``/api/v1`` surface, carries no user auth, and is inert unless the deployment-local controlled-
integration profile is enabled. In a deployed topology it is reached ONLY over mutual TLS on an
internal network.

Identity is NEVER taken from a request body field or a proxy header: the ``complete`` step verifies
the worker's Ed25519 signature over the server-issued nonce against the registration's pinned public
anchor (``secp_api.services.worker_admission``), so a body-asserted or spoofed identity cannot pass.
Every refusal returns ONLY a closed reason code (no secret/host/key/endpoint value).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from secp_api.config import Settings
from secp_api.deps import db_session, settings_dep
from secp_api.services import worker_admission

router = APIRouter(prefix="/internal/worker-discovery-admission", tags=["internal-worker"])


class _BeginRequest(BaseModel):
    discovery_job_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    endpoint_binding_hash: str


class _CompleteRequest(BaseModel):
    admission_id: uuid.UUID
    public_anchor: str
    signature: str


def _require_internal_enabled(settings: Settings) -> None:
    # The endpoint does not exist unless the deployment-local live profile is enabled.
    if not getattr(settings, "discovery_controlled_integration_enabled", False):
        raise HTTPException(status_code=404, detail={"code": "not_found"})


@router.post("/begin")
def begin_admission(
    payload: _BeginRequest,
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
) -> dict:
    _require_internal_enabled(settings)
    try:
        admission = worker_admission.issue_discovery_admission_challenge(
            session,
            discovery_job_id=payload.discovery_job_id,
            authorization_id=payload.authorization_id,
            authorization_version=payload.authorization_version,
            endpoint_binding_hash=payload.endpoint_binding_hash,
        )
    except worker_admission.WorkerAdmissionRefused as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": "worker_admission_refused", "reason_code": exc.reason_code},
        ) from None
    # Only non-secret IDs + the nonce the worker must sign — never a key/endpoint/host.
    return {
        "admission_id": str(admission.id),
        "nonce": admission.nonce,
        "organization_id": str(admission.organization_id),
        "discovery_job_id": str(admission.discovery_job_id),
        "worker_registration_id": str(admission.worker_registration_id),
        "identity_version": admission.identity_version,
        "endpoint_binding_hash": admission.endpoint_binding_hash,
        "expires_at": admission.expires_at.isoformat(),
    }


@router.post("/complete")
def complete_admission(
    payload: _CompleteRequest,
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
) -> dict:
    _require_internal_enabled(settings)
    try:
        worker_admission.complete_discovery_admission(
            session,
            admission_id=payload.admission_id,
            presented_anchor=payload.public_anchor,
            signature=payload.signature,
        )
    except worker_admission.WorkerAdmissionRefused as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": "worker_admission_refused", "reason_code": exc.reason_code},
        ) from None
    return {"status": "admitted", "admission_id": str(payload.admission_id)}
