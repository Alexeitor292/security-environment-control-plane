"""Provider Targets routes (SECP-002A): targets, read-only discovery, inventory.

The API never calls a provider plugin and never resolves a secret reference.
Discovery is queued to the worker (Temporal); in inline dev mode it is refused.
There is no secret-entry form: only an opaque ``secret_ref`` is accepted.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.dispatch import get_dispatcher
from secp_api.schemas_provider import (
    AddressSpaceOut,
    ReservationOut,
    ResourceOut,
    SnapshotOut,
    TargetCreate,
    TargetOut,
)
from secp_api.services import inventory, reservations, targets

router = APIRouter(prefix="/api/v1", tags=["providers"])

# Surfaced so the UI can clearly state provisioning is not enabled in SECP-002A.
PROVISIONING_ENABLED = False


@router.get("/targets", response_model=list[TargetOut])
def list_targets(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[TargetOut]:
    return [TargetOut.model_validate(t) for t in targets.list_targets(session, principal)]


@router.post("/targets", response_model=TargetOut, status_code=201)
def register_target(
    body: TargetCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    target = targets.register_target(
        session,
        principal,
        display_name=body.display_name,
        plugin_name=body.plugin_name,
        config=body.config,
        secret_ref=body.secret_ref,
        scope_policy=body.scope_policy,
        address_spaces=[a.model_dump() for a in body.address_spaces],
    )
    return TargetOut.model_validate(target)


@router.get("/targets/{target_id}", response_model=TargetOut)
def get_target(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    return TargetOut.model_validate(targets.get_target(session, principal, target_id))


@router.get("/targets/{target_id}/address-spaces", response_model=list[AddressSpaceOut])
def list_address_spaces(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[AddressSpaceOut]:
    return [
        AddressSpaceOut.model_validate(a)
        for a in targets.list_address_spaces(session, principal, target_id)
    ]


@router.post("/targets/{target_id}/disable", response_model=TargetOut)
def disable_target(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    return TargetOut.model_validate(targets.disable_target(session, principal, target_id))


@router.get("/targets/{target_id}/reservations", response_model=list[ReservationOut])
def list_reservations(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[ReservationOut]:
    return [
        ReservationOut.model_validate(r)
        for r in reservations.list_reservations(session, principal, target_id)
    ]


# --- discovery (read-only) ----------------------------------------------------


@router.post("/targets/{target_id}/discover", response_model=SnapshotOut, status_code=202)
def request_discovery(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> SnapshotOut:
    """Queue a READ-ONLY discovery. Refused in inline dev mode (requires Temporal)."""
    snap = inventory.request_discovery(session, principal, target_id, dispatcher=get_dispatcher())
    return SnapshotOut.model_validate(snap)


@router.get("/targets/{target_id}/snapshots", response_model=list[SnapshotOut])
def list_snapshots(
    target_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[SnapshotOut]:
    return [
        SnapshotOut.model_validate(s)
        for s in inventory.list_snapshots(session, principal, target_id)
    ]


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotOut)
def get_snapshot(
    snapshot_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> SnapshotOut:
    return SnapshotOut.model_validate(inventory.get_snapshot(session, principal, snapshot_id))


@router.get("/snapshots/{snapshot_id}/resources", response_model=list[ResourceOut])
def list_snapshot_resources(
    snapshot_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[ResourceOut]:
    return [
        ResourceOut.model_validate(r)
        for r in inventory.list_snapshot_resources(session, principal, snapshot_id)
    ]


@router.get("/providers/capabilities")
def provider_capabilities(_: Principal = Depends(current_principal)) -> dict:
    """Tells the UI that provisioning is NOT enabled in SECP-002A."""
    return {
        "milestone": "SECP-002A",
        "provisioning_enabled": PROVISIONING_ENABLED,
        "discovery": "read-only",
        "note": "Proxmox provisioning is deferred to SECP-002B. Discovery is read-only.",
    }
