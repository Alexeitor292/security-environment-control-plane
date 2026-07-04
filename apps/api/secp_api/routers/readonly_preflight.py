"""App-owned read-only staging preflight routes (SECP-B2-0, control plane only).

The API lists eligible substrates (aliases only), lets an admin explicitly create/approve/revoke a
short-lived live-read authorization, and ENQUEUES durable preflight intent. It NEVER imports
worker/plugin/transport/collector/HTTP code and never executes collection — a worker consumes the
queued intent. Every response is secret-free.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_readonly_preflight import (
    CreatePreflightAuthorization,
    PreflightAuthorizationOut,
    PreflightSubstrateOut,
    QueuePreflight,
    ReadonlyPreflightOut,
)
from secp_api.services import readonly_preflight, staging_labs

router = APIRouter(prefix="/api/v1/readonly-preflight", tags=["readonly-preflight"])


@router.get("/substrates", response_model=list[PreflightSubstrateOut])
def list_substrates(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[PreflightSubstrateOut]:
    """Eligible Proxmox staging substrates (same-org, active, eligible, onboarded); aliases only."""  # noqa: E501
    return [
        PreflightSubstrateOut(id=row["id"], alias=row["alias"])
        for row in staging_labs.list_eligible_substrates(session, principal)
    ]


@router.post("/authorizations", response_model=PreflightAuthorizationOut, status_code=201)
def create_authorization(
    body: CreatePreflightAuthorization,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PreflightAuthorizationOut:
    """Create a DRAFT short-lived live-read authorization (hashes derived server-side)."""
    auth = readonly_preflight.create_preflight_authorization(
        session,
        principal,
        execution_target_id=body.execution_target_id,
        ttl_seconds=body.ttl_seconds,
    )
    return PreflightAuthorizationOut.model_validate(auth)


@router.get("/authorizations", response_model=list[PreflightAuthorizationOut])
def list_authorizations(
    execution_target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[PreflightAuthorizationOut]:
    return [
        PreflightAuthorizationOut.model_validate(a)
        for a in readonly_preflight.list_preflight_authorizations(
            session, principal, execution_target_id
        )
    ]


@router.post("/authorizations/{authorization_id}/approve", response_model=PreflightAuthorizationOut)
def approve_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PreflightAuthorizationOut:
    return PreflightAuthorizationOut.model_validate(
        readonly_preflight.approve_preflight_authorization(session, principal, authorization_id)
    )


@router.post("/authorizations/{authorization_id}/revoke", response_model=PreflightAuthorizationOut)
def revoke_authorization(
    authorization_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PreflightAuthorizationOut:
    return PreflightAuthorizationOut.model_validate(
        readonly_preflight.revoke_preflight_authorization(session, principal, authorization_id)
    )


@router.post("", response_model=ReadonlyPreflightOut, status_code=201)
def queue_preflight(
    body: QueuePreflight,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ReadonlyPreflightOut:
    """QUEUE durable read-only preflight intent. The API never executes collection; a worker does.

    Read-only readiness verification only — it creates/alters/starts/stops nothing."""
    pf = readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=body.live_read_authorization_id
    )
    return ReadonlyPreflightOut.model_validate(pf)


@router.get("", response_model=list[ReadonlyPreflightOut])
def list_preflights(
    execution_target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[ReadonlyPreflightOut]:
    return [
        ReadonlyPreflightOut.model_validate(p)
        for p in readonly_preflight.list_preflights(session, principal, execution_target_id)
    ]


@router.get("/{preflight_id}", response_model=ReadonlyPreflightOut)
def get_preflight(
    preflight_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ReadonlyPreflightOut:
    return ReadonlyPreflightOut.model_validate(
        readonly_preflight.get_preflight(session, principal, preflight_id)
    )
