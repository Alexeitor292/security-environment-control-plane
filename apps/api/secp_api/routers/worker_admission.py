"""Internal worker discovery-admission route (SECP-B6 MB-1).

A narrowly scoped, NON-public, worker-only endpoint through which an isolated worker performs the
control-plane-verified admission handshake before live discovery — AND the exact-job binding
(``assert``) + one-time consume (``consume``) that gate a candidate plan. It is NOT mounted on the
public ``/api/v1`` surface, carries no user auth, and is inert unless the deployment-local
controlled-integration profile is enabled. In a deployed topology it is reached ONLY over
CA-validated TLS on an internal network — the control-plane boundary the worker crosses instead of
importing the admission service.

Identity is NEVER taken from a request body field or a proxy header: the ``complete`` step verifies
the worker's Ed25519 signature over the server-issued nonce against the registration's pinned public
anchor (``secp_api.services.worker_admission``), so a body-asserted or spoofed identity cannot pass.
The ``assert``/``consume`` steps re-derive the enrollment from the claimed job server-side and rerun
the authoritative worker-identity + live-read verifier, using the SERVER's clock (a client-supplied
time is never trusted). Every refusal returns ONLY a closed reason code (no secret/host/key/endpoint
value).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from secp_api.config import Settings
from secp_api.deps import db_session, settings_dep
from secp_api.models import DiscoveryJob, TargetDiscoveryEnrollment
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


class _BindingRequest(BaseModel):
    """Shared shape for ``assert`` + ``consume``: the worker asserts only NON-secret IDs; the server
    re-derives the enrollment from the job and reruns the authoritative verifier at the server."""

    admission_id: uuid.UUID
    discovery_job_id: uuid.UUID
    endpoint_binding_hash: str


def _require_internal_enabled(settings: Settings) -> None:
    # The endpoint does not exist unless the deployment-local live profile is enabled.
    if not getattr(settings, "discovery_controlled_integration_enabled", False):
        raise HTTPException(status_code=404, detail={"code": "not_found"})


def _refused(reason_code: str) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={"code": "worker_admission_refused", "reason_code": reason_code},
    )


def _resolve_enrollment(session: Session, discovery_job_id: uuid.UUID) -> TargetDiscoveryEnrollment:
    """Authoritatively resolve the enrollment from the claimed job (never from the request body)."""
    job = session.get(DiscoveryJob, discovery_job_id)
    if job is None:
        raise _refused("job_not_found")
    enrollment = session.get(TargetDiscoveryEnrollment, job.enrollment_id)
    if enrollment is None:
        raise _refused("enrollment_not_found")
    return enrollment


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
        raise _refused(exc.reason_code) from None
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
        raise _refused(exc.reason_code) from None
    return {"status": "admitted", "admission_id": str(payload.admission_id)}


@router.post("/assert")
def assert_admission(
    payload: _BindingRequest,
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
) -> dict:
    """Pre-probe: confirm the admission is admitted, bound to THIS exact job/endpoint, and its
    worker identity + live-read authorization still verify at the server clock. Does not consume."""
    _require_internal_enabled(settings)

    enrollment = _resolve_enrollment(session, payload.discovery_job_id)
    try:
        result = worker_admission.assert_discovery_admission_valid(
            session,
            admission_id=payload.admission_id,
            enrollment=enrollment,
            discovery_job_id=payload.discovery_job_id,
            endpoint_binding_hash=payload.endpoint_binding_hash,
            now=datetime.now(UTC),
        )
    except worker_admission.WorkerAdmissionRefused as exc:
        raise _refused(exc.reason_code) from None
    return {
        "status": "valid",
        "admission_id": str(payload.admission_id),
        "registration_id": str(result.registration_id),
        "identity_version": result.identity_version,
    }


@router.post("/consume")
def consume_admission(
    payload: _BindingRequest,
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
) -> dict:
    """Post-probe: re-assert validity at the server's clock, then atomically consume the one-time
    admission (a replay/second consume fails closed). Returns the authoritative registration id +
    version that the persisted candidate plan must bind."""
    _require_internal_enabled(settings)

    enrollment = _resolve_enrollment(session, payload.discovery_job_id)
    try:
        result = worker_admission.consume_discovery_admission(
            session,
            admission_id=payload.admission_id,
            enrollment=enrollment,
            discovery_job_id=payload.discovery_job_id,
            endpoint_binding_hash=payload.endpoint_binding_hash,
            now=datetime.now(UTC),
        )
    except worker_admission.WorkerAdmissionRefused as exc:
        raise _refused(exc.reason_code) from None
    return {
        "status": "consumed",
        "admission_id": str(payload.admission_id),
        "registration_id": str(result.registration_id),
        "identity_version": result.identity_version,
    }
