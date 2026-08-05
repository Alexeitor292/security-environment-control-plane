"""Range catalog and lifecycle routes.

deploy/reset/destroy return ``202`` immediately and run in the background — a deploy takes minutes
and an HTTP request must not hold it. The operation row created here is the handle the UI polls.

Every route resolves its session through ``DB_SESSION`` (the shared function-scoped commit
boundary) and returns an ordinary JSON body. Nothing streams: the session closes before the body
reaches the socket, so a ``StreamingResponse`` over ORM instances would truncate after the 200.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import DB_SESSION, current_principal
from secp_api.dispatch import get_dispatcher
from secp_api.range_enums import RangeOperationKind, RangeState
from secp_api.range_projection import (
    event_out,
    operation_out,
    range_out,
    resource_out,
    teardown_evidence_out,
    template_out,
)
from secp_api.schemas_range import (
    RangeCreate,
    RangeEventOut,
    RangeOperationAbandonIn,
    RangeOperationOut,
    RangeOut,
    RangeResourceOut,
    RangeTemplateOut,
    TeardownEvidenceOut,
)
from secp_api.services import ranges

router = APIRouter(prefix="/api/v1", tags=["ranges"])


@router.get("/range-templates", response_model=list[RangeTemplateOut])
def list_range_templates(
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeTemplateOut]:
    del principal  # authentication only; the shipped catalog is not tenant data
    return [template_out(row) for row in ranges.list_templates(session)]


@router.get("/range-templates/{slug}", response_model=RangeTemplateOut)
def get_range_template(
    slug: str,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeTemplateOut:
    del principal
    return template_out(ranges.get_template_row(session, slug))


@router.post("/ranges", response_model=RangeOut, status_code=201)
def create_range(
    body: RangeCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOut:
    instance = ranges.create_range(
        session, principal, template_slug=body.template_slug, name=body.name
    )
    return range_out(session, instance)


@router.get("/ranges", response_model=list[RangeOut])
def list_ranges(
    state: list[RangeState] | None = Query(default=None),
    include_destroyed: bool = Query(default=False),
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeOut]:
    rows = ranges.list_ranges(session, principal, states=state, include_destroyed=include_destroyed)
    return [range_out(session, row) for row in rows]


@router.get("/ranges/{range_id}", response_model=RangeOut)
def get_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOut:
    return range_out(session, ranges.get_range(session, principal, range_id))


def _start(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    kind: RangeOperationKind,
) -> RangeOperationOut:
    """Validate the transition, create the operation row, and DISPATCH it.

    The API stops here. Everything that touches a provider happens in the worker
    (:mod:`secp_worker.range.execution`), reached only through the dispatch seam — the API process
    never contacts a container runtime (Charter Invariants 6/7, ADR-005).

    Enqueue-only: the dispatcher writes a durable outbox row and nothing is submitted to Temporal
    until this request's transaction commits, so a rolled-back request cannot leave a range
    half-deployed.
    """
    _, operation = ranges.start_operation(session, principal, range_id, kind)
    get_dispatcher().dispatch_range_operation(session, operation.id)
    return operation_out(operation)


@router.post("/ranges/{range_id}/deploy", response_model=RangeOperationOut, status_code=202)
def deploy_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return _start(session, principal, range_id, RangeOperationKind.deploy)


@router.post("/ranges/{range_id}/reset", response_model=RangeOperationOut, status_code=202)
def reset_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return _start(session, principal, range_id, RangeOperationKind.reset)


@router.post("/ranges/{range_id}/destroy", response_model=RangeOperationOut, status_code=202)
def destroy_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return _start(session, principal, range_id, RangeOperationKind.destroy)


@router.post("/range-operations/{operation_id}/abandon", response_model=RangeOperationOut)
def abandon_range_operation(
    operation_id: uuid.UUID,
    body: RangeOperationAbandonIn | None = None,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    """Release a stranded operation and put its range into ``recovery_required``.

    This endpoint exists because there was previously NO way out. An operation dispatched to a
    worker that could not resolve it stayed ``pending`` forever, its range stayed ``resetting``
    forever, and ``destroy`` and ``reset`` both answered 409 because neither may start from an
    in-flight state. The only recovery was hand-written SQL against
    ``range_deployment_operation`` — on a running system, with the range's containers still up.

    Refuses (409) while the operation is still within its lease, unless the caller passes
    ``force``: abandoning an operation that IS executing puts a second writer on the range. The
    operation becomes ``unproven``, never ``failed``; nothing here observed it fail. Every resource
    the range has created stays enumerated and none is marked absent, so the destroy that follows
    still sweeps the complete set and still has to PROVE each one gone.
    """
    _, operation = ranges.abandon_operation(
        session, principal, operation_id, force=bool(body and body.force)
    )
    return operation_out(operation)


@router.get("/range-operations/{operation_id}", response_model=RangeOperationOut)
def get_range_operation(
    operation_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> RangeOperationOut:
    return operation_out(ranges.get_operation(session, principal, operation_id))


@router.get("/ranges/{range_id}/operations", response_model=list[RangeOperationOut])
def list_range_operations(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeOperationOut]:
    return [operation_out(row) for row in ranges.list_operations(session, principal, range_id)]


@router.get("/ranges/{range_id}/resources", response_model=list[RangeResourceOut])
def list_range_resources(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeResourceOut]:
    return [resource_out(row) for row in ranges.list_resources(session, principal, range_id)]


@router.get("/ranges/{range_id}/events", response_model=list[RangeEventOut])
def list_range_events(
    range_id: uuid.UUID,
    after_sequence: int = Query(default=0, ge=0),
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[RangeEventOut]:
    return [
        event_out(row)
        for row in ranges.list_events(session, principal, range_id, after_sequence=after_sequence)
    ]


@router.get("/ranges/{range_id}/teardown-evidence", response_model=list[TeardownEvidenceOut])
def list_range_teardown_evidence(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[TeardownEvidenceOut]:
    return [
        teardown_evidence_out(row)
        for row in ranges.list_teardown_evidence(session, principal, range_id)
    ]
