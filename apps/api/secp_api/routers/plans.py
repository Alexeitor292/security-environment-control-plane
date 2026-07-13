"""Deployment-plan routes: generate, submit, approve, reject.

Every response is serialized through ``PlanOut.from_plan`` with the exact bound EnvironmentVersion
re-verified by ``planning.require_plan_version_binding`` — so the immutable one-version binding and
its typed publication provenance surface identically across the whole plan lifecycle, and any
corrupted binding fails closed (redacted ``plan_version_binding_invalid``) without leaking ids or
hashes. No plan endpoint queries topology-authoring records, and none deploys.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.errors import NotFoundError
from secp_api.models import DeploymentPlan
from secp_api.schemas import DecisionBody, PlanOut
from secp_api.services import planning

router = APIRouter(prefix="/api/v1", tags=["plans"])


def _serialize(session: Session, principal: Principal, plan: DeploymentPlan) -> PlanOut:
    version = planning.require_plan_version_binding(session, principal, plan)
    return PlanOut.from_plan(plan, version)


@router.post("/exercises/{exercise_id}/plan", response_model=PlanOut, status_code=201)
def generate_plan(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    plan = planning.generate_plan(session, principal, exercise_id)
    return _serialize(session, principal, plan)


@router.get("/exercises/{exercise_id}/plan", response_model=PlanOut)
def latest_plan(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    plan = planning.latest_plan(session, principal, exercise_id)
    if plan is None:
        raise NotFoundError("no plan exists for this exercise")
    return _serialize(session, principal, plan)


@router.post("/plans/{plan_id}/submit", response_model=PlanOut)
def submit_plan(
    plan_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    plan = planning.submit_plan(session, principal, plan_id)
    return _serialize(session, principal, plan)


@router.post("/plans/{plan_id}/approve", response_model=PlanOut)
def approve_plan(
    plan_id: uuid.UUID,
    body: DecisionBody | None = None,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    reason = body.reason if body else ""
    plan = planning.approve_plan(session, principal, plan_id, reason)
    return _serialize(session, principal, plan)


@router.post("/plans/{plan_id}/reject", response_model=PlanOut)
def reject_plan(
    plan_id: uuid.UUID,
    body: DecisionBody | None = None,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    reason = body.reason if body else ""
    plan = planning.reject_plan(session, principal, plan_id, reason)
    return _serialize(session, principal, plan)
