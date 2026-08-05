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
from secp_api.deps import DB_SESSION, current_principal
from secp_api.dispatch import get_dispatcher
from secp_api.provider_capabilities import build_report
from secp_api.provider_capability_projection import capabilities_out
from secp_api.schemas_provider import (
    AddressSpaceOut,
    ReservationOut,
    ResourceOut,
    SnapshotOut,
    TargetCreate,
    TargetCredentialRotate,
    TargetOperationCredentialRotate,
    TargetOut,
)
from secp_api.schemas_provider_capabilities import ProviderCapabilitiesOut
from secp_api.services import inventory, reservations, targets

router = APIRouter(prefix="/api/v1", tags=["providers"])

# `PROVISIONING_ENABLED = False` used to live here and was served by
# `GET /providers/capabilities`. It is deliberately GONE from the response rather than corrected to
# `True`: the question it answered has three states, not two (see `secp_api.provider_capabilities`),
# and a module-level constant is exactly the shape that let it stay false for six merges after it
# stopped being true. A test asserts the key no longer appears in the response.
#
# It had ONE non-UI consumer, and that consumer is a different concern entirely:
# `secp_worker.activation_probe._default_seals` reads it as one of four "reviewed code constants"
# that together assert this deployment has real provisioning SEALED. That is a claim about the
# worker's execution boundary — the other three are the subprocess and plan-only seals — not about
# what the API surface can express, and it feeds the discovery-activation evidence chain.
#
# So the seal input survives, under a name that says which of the two questions it answers, with
# its VALUE UNCHANGED so no evidence-chain semantics move. Whether this seal is still accurate is a
# real question and it belongs to the discovery-activation owner, not to this slice: it is asserted
# by a reviewed constant that nothing re-derives, which is the same shape as the defect above.
REAL_PROVISIONING_SEALED = True


@router.get("/targets", response_model=list[TargetOut])
def list_targets(
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[TargetOut]:
    return [TargetOut.model_validate(t) for t in targets.list_targets(session, principal)]


@router.post("/targets", response_model=TargetOut, status_code=201)
def register_target(
    body: TargetCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    target = targets.register_target(
        session,
        principal,
        display_name=body.display_name,
        plugin_name=body.plugin_name,
        config=body.config,
        secret_ref=body.secret_ref,
        provider_plan_secret_ref=body.provider_plan_secret_ref,
        state_backend_secret_ref=body.state_backend_secret_ref,
        scope_policy=body.scope_policy,
        address_spaces=[a.model_dump() for a in body.address_spaces],
    )
    return TargetOut.model_validate(target)


@router.get("/targets/{target_id}", response_model=TargetOut)
def get_target(
    target_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    return TargetOut.model_validate(targets.get_target(session, principal, target_id))


@router.get("/targets/{target_id}/address-spaces", response_model=list[AddressSpaceOut])
def list_address_spaces(
    target_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[AddressSpaceOut]:
    return [
        AddressSpaceOut.model_validate(a)
        for a in targets.list_address_spaces(session, principal, target_id)
    ]


@router.post("/targets/{target_id}/rotate-credential", response_model=TargetOut)
def rotate_target_credential(
    target_id: uuid.UUID,
    body: TargetCredentialRotate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    """The SUPPORTED path for replacing a target's opaque credential reference (B1B-PR4 §2).

    Requires the dedicated ``credential_binding:manage`` permission and ROTATES the target's opaque
    credential binding, which invalidates every prior plan-secret authorization and readiness record
    without modifying any historical evidence. Credential replacement is never invisible.
    """
    return TargetOut.model_validate(
        targets.rotate_target_credential(session, principal, target_id, secret_ref=body.secret_ref)
    )


@router.post("/targets/{target_id}/rotate-operation-credential", response_model=TargetOut)
def rotate_target_operation_credential(
    target_id: uuid.UUID,
    body: TargetOperationCredentialRotate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    """Replace an OPERATION-SPECIFIC opaque credential reference (B1B-PR5A, ADR-022).

    Requires ``credential_binding:manage`` and rotates ONLY the matching opaque binding
    (``provider_plan_read`` or ``state_backend_plan``), invalidating every prior activation dossier,
    readiness record, and plan-generation authorization that folded the old binding version. Apply
    and destroy purposes are unrepresentable.
    """
    return TargetOut.model_validate(
        targets.rotate_target_operation_credential(
            session,
            principal,
            target_id,
            purpose_class=body.purpose_class,
            secret_ref=body.secret_ref,
        )
    )


@router.post("/targets/{target_id}/disable", response_model=TargetOut)
def disable_target(
    target_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TargetOut:
    return TargetOut.model_validate(targets.disable_target(session, principal, target_id))


@router.get("/targets/{target_id}/reservations", response_model=list[ReservationOut])
def list_reservations(
    target_id: uuid.UUID,
    session: Session = DB_SESSION,
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
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> SnapshotOut:
    """Queue a READ-ONLY discovery. Refused in inline dev mode (requires Temporal)."""
    snap = inventory.request_discovery(session, principal, target_id, dispatcher=get_dispatcher())
    return SnapshotOut.model_validate(snap)


@router.get("/targets/{target_id}/snapshots", response_model=list[SnapshotOut])
def list_snapshots(
    target_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[SnapshotOut]:
    return [
        SnapshotOut.model_validate(s)
        for s in inventory.list_snapshots(session, principal, target_id)
    ]


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotOut)
def get_snapshot(
    snapshot_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> SnapshotOut:
    return SnapshotOut.model_validate(inventory.get_snapshot(session, principal, snapshot_id))


@router.get("/snapshots/{snapshot_id}/resources", response_model=list[ResourceOut])
def list_snapshot_resources(
    snapshot_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[ResourceOut]:
    return [
        ResourceOut.model_validate(r)
        for r in inventory.list_snapshot_resources(session, principal, snapshot_id)
    ]


@router.get("/providers/capabilities", response_model=ProviderCapabilitiesOut)
def provider_capabilities(
    principal: Principal = Depends(current_principal),
) -> ProviderCapabilitiesOut:
    """What this build can actually do, derived from the live modules that implement it.

    This endpoint used to return a hardcoded ``provisioning_enabled: False`` with the note
    "Proxmox provisioning is deferred to SECP-002B", and a docstring saying its purpose was to tell
    the UI provisioning was not enabled. It had been false for six merges: #105-#110 shipped
    desired-state compilation, plan generation, apply authorization, observed verification, destroy
    authorization and the residue proof.

    A capability endpoint that reads a constant is a restatement — it cannot notice the capability
    changing, which is the one thing it exists to do. Every value here is now derived, and
    ``supported_unauthorized`` is distinguished from ``not_supported`` because the old single flag
    conflated them (along with "not for this target"), and they call for different actions.
    """
    return capabilities_out(build_report(principal))
