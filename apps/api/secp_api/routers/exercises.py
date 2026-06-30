"""Exercise lifecycle routes: create, validate, deploy, reset, destroy."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas import (
    ExerciseCreate,
    ExerciseOut,
    InstanceOut,
    WorkflowRunOut,
)
from secp_api.services import exercises

router = APIRouter(prefix="/api/v1/exercises", tags=["exercises"])


@router.get("", response_model=list[ExerciseOut])
def list_exercises(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[ExerciseOut]:
    return [ExerciseOut.model_validate(e) for e in exercises.list_exercises(session, principal)]


@router.post("", response_model=ExerciseOut, status_code=201)
def create_exercise(
    body: ExerciseCreate,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ExerciseOut:
    exercise = exercises.create_exercise(
        session,
        principal,
        template_id=body.template_id,
        version_id=body.version_id,
        name=body.name,
        execution_target_id=body.execution_target_id,
    )
    return ExerciseOut.model_validate(exercise)


@router.get("/{exercise_id}", response_model=ExerciseOut)
def get_exercise(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ExerciseOut:
    return ExerciseOut.model_validate(exercises.get_exercise(session, principal, exercise_id))


@router.get("/{exercise_id}/instances", response_model=list[InstanceOut])
def list_instances(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[InstanceOut]:
    return [
        InstanceOut.model_validate(i)
        for i in exercises.list_instances(session, principal, exercise_id)
    ]


@router.post("/{exercise_id}/validate", response_model=ExerciseOut)
def validate_exercise(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> ExerciseOut:
    return ExerciseOut.model_validate(exercises.validate_exercise(session, principal, exercise_id))


@router.post("/{exercise_id}/deploy", response_model=WorkflowRunOut)
def deploy_exercise(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkflowRunOut:
    """Approve-gated deploy. Refused unless an approved plan exists (ADR-004)."""
    run = exercises.start_exercise(session, principal, exercise_id)
    return WorkflowRunOut.model_validate(run)


@router.post("/{exercise_id}/instances/{instance_id}/reset", response_model=WorkflowRunOut)
def reset_instance(
    exercise_id: uuid.UUID,
    instance_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkflowRunOut:
    run = exercises.reset_instance(session, principal, exercise_id, instance_id)
    return WorkflowRunOut.model_validate(run)


@router.post("/{exercise_id}/destroy", response_model=WorkflowRunOut)
def destroy_exercise(
    exercise_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> WorkflowRunOut:
    run = exercises.destroy_exercise(session, principal, exercise_id)
    return WorkflowRunOut.model_validate(run)
