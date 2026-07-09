"""SECP-B7 — Proxmox read-only discovery bootstrap API surface.

The wizard endpoints that replace the manual SECP-B6 canary steps. Every endpoint delegates to
``services.bootstrap_discovery`` (permission checks live there) and returns only secret-free values.
The API generates the bootstrap script + endpoint digest + binding descriptor; it never accepts an
SSH private key or a raw command, and it never contacts Proxmox.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_bootstrap_discovery import (
    BindingDescriptorOut,
    BootstrapCompleteRequest,
    BootstrapScriptOut,
    BootstrapSessionCreate,
    BootstrapSessionOut,
    BundleDescriptorOut,
    DiscoveryReadinessOut,
    SubstrateEligibilityGrantOut,
)
from secp_api.services import bootstrap_discovery as svc
from secp_api.services import staging_labs as staging_labs_svc

router = APIRouter(prefix="/api/v1/target-discovery/read-only-bootstrap", tags=["target-discovery"])


@router.post("/sessions", response_model=BootstrapSessionOut, status_code=201)
def create_session(
    body: BootstrapSessionCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BootstrapSessionOut:
    row = svc.create_bootstrap_session(
        session,
        principal,
        execution_target_id=body.execution_target_id,
        worker_ssh_public_key=body.worker_ssh_public_key,
        ssh_port=body.ssh_port,
    )
    return BootstrapSessionOut.model_validate(row)


@router.get("/sessions", response_model=list[BootstrapSessionOut])
def list_sessions(
    execution_target_id: uuid.UUID | None = None,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[BootstrapSessionOut]:
    rows = svc.list_bootstrap_sessions(session, principal, execution_target_id=execution_target_id)
    return [BootstrapSessionOut.model_validate(r) for r in rows]


@router.get("/sessions/{session_id}", response_model=BootstrapSessionOut)
def get_session(
    session_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BootstrapSessionOut:
    return BootstrapSessionOut.model_validate(
        svc.get_bootstrap_session(session, principal, session_id)
    )


@router.get("/sessions/{session_id}/script", response_model=BootstrapScriptOut)
def get_script(
    session_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BootstrapScriptOut:
    row = svc.get_bootstrap_session(session, principal, session_id)
    script = svc.render_session_script(session, principal, session_id)
    return BootstrapScriptOut(
        session_id=row.id,
        account=row.account,
        pve_role=row.pve_role,
        worker_ssh_public_key_fingerprint=row.worker_ssh_public_key_fingerprint,
        script=script,
    )


@router.post("/sessions/{session_id}/complete", response_model=BootstrapSessionOut)
def complete_session(
    session_id: uuid.UUID,
    body: BootstrapCompleteRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BootstrapSessionOut:
    row = svc.complete_bootstrap_session(
        session,
        principal,
        session_id,
        host_key_fingerprint=body.host_key_fingerprint,
        proof_text=body.proof_text,
        host_public_key=body.host_public_key,
    )
    return BootstrapSessionOut.model_validate(row)


@router.post("/sessions/{session_id}/bind", response_model=BootstrapSessionOut)
def bind_session(
    session_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BootstrapSessionOut:
    row = svc.bind_bootstrap_session(session, principal, session_id)
    return BootstrapSessionOut.model_validate(row)


@router.get("/enrollments/{enrollment_id}/binding-descriptor", response_model=BindingDescriptorOut)
def get_binding_descriptor(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BindingDescriptorOut:
    return BindingDescriptorOut.model_validate(
        svc.get_binding_descriptor(session, principal, enrollment_id)
    )


@router.get("/enrollments/{enrollment_id}/bundle-descriptor", response_model=BundleDescriptorOut)
def get_bundle_descriptor(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> BundleDescriptorOut:
    """SECP-B8: the secret-free superset the worker assembles its mounted bundle from. Fails closed
    unless the session is fully bound AND the host public key was captured."""
    return BundleDescriptorOut.model_validate(
        svc.get_bundle_descriptor(session, principal, enrollment_id)
    )


@router.get("/enrollments/{enrollment_id}/readiness", response_model=DiscoveryReadinessOut)
def get_discovery_readiness(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DiscoveryReadinessOut:
    """SECP-B8: precise missing-prerequisite diagnostic so the UI/worker never fails opaquely."""
    return DiscoveryReadinessOut.model_validate(
        svc.discovery_readiness(session, principal, enrollment_id)
    )


@router.post(
    "/targets/{execution_target_id}/substrate-eligibility",
    response_model=SubstrateEligibilityGrantOut,
    status_code=201,
)
def grant_substrate_eligibility(
    execution_target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> SubstrateEligibilityGrantOut:
    """SECP-B8: guided target-admin action to grant staging-substrate eligibility (fixes the B7
    ``readonly_preflight_substrate_ineligible`` gap). Requires ``staging_substrate:manage`` — the
    service enforces it and NEVER silently auto-grants."""
    record = staging_labs_svc.grant_substrate_eligibility(
        session, principal, execution_target_id=execution_target_id
    )
    return SubstrateEligibilityGrantOut.model_validate(record)
