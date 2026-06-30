"""Deployment-plan routes: generate, submit, approve, reject."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.errors import NotFoundError
from secp_api.schemas import DecisionBody, PlanOut
from secp_api.services import planning

router = APIRouter(prefix="/api/v1", tags=["plans"])


@router.post("/exercises/{exercise_id}/plan", response_model=PlanOut, status_code=201)
def generate_plan(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    return PlanOut.model_validate(planning.generate_plan(session, principal, exercise_id))


@router.get("/exercises/{exercise_id}/plan", response_model=PlanOut)
def latest_plan(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    plan = planning.latest_plan(session, principal, exercise_id)
    if plan is None:
        raise NotFoundError("no plan exists for this exercise")
    return PlanOut.model_validate(plan)


@router.post("/plans/{plan_id}/submit", response_model=PlanOut)
def submit_plan(
    plan_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    return PlanOut.model_validate(planning.submit_plan(session, principal, plan_id))


@router.post("/plans/{plan_id}/approve", response_model=PlanOut)
def approve_plan(
    plan_id: uuid.UUID,
    body: DecisionBody | None = None,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    reason = body.reason if body else ""
    return PlanOut.model_validate(planning.approve_plan(session, principal, plan_id, reason))


@router.post("/plans/{plan_id}/reject", response_model=PlanOut)
def reject_plan(
    plan_id: uuid.UUID,
    body: DecisionBody | None = None,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> PlanOut:
    reason = body.reason if body else ""
    return PlanOut.model_validate(planning.reject_plan(session, principal, plan_id, reason))
