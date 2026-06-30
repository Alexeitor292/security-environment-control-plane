"""Topology and audit-log routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas import AuditEventOut
from secp_api.services import topology

router = APIRouter(prefix="/api/v1", tags=["observability"])


@router.get("/exercises/{exercise_id}/topology")
def exercise_topology(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    """Per-team topologies (one isolated React-Flow graph per team)."""
    return topology.exercise_topologies(session, principal, exercise_id)


@router.get("/instances/{instance_id}/topology")
def instance_topology(
    instance_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> dict:
    return topology.instance_topology(session, principal, instance_id)


@router.get("/audit", response_model=list[AuditEventOut])
def list_audit(
    exercise_id: uuid.UUID | None = None,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[AuditEventOut]:
    events = topology.list_audit_events(session, principal, exercise_id=exercise_id)
    return [AuditEventOut.model_validate(e) for e in events]
