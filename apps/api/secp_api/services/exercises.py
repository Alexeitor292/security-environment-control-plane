"""Exercise services: create, validate, and lifecycle execution (deploy/reset/destroy).

Execution always goes through the :class:`WorkflowDispatcher` seam, never by
calling plugins directly from the API (Charter Invariants 6, 7; ADR-005).
"""

from __future__ import annotations

import uuid

from secp_scenario_schema import validate_definition
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.db import session_scope
from secp_api.dispatch import WorkflowDispatcher, get_dispatcher
from secp_api.enums import AuditAction, LifecycleState, Permission
from secp_api.errors import ApprovalRequiredError, NotFoundError
from secp_api.lifecycle import transition
from secp_api.models import EnvironmentInstance, Exercise, WorkflowRun
from secp_api.services.catalog import ensure_teams, get_version


def create_exercise(
    session: Session,
    actor: Principal,
    *,
    template_id: uuid.UUID,
    version_id: uuid.UUID,
    name: str,
) -> Exercise:
    actor.require(Permission.exercise_operate)
    version = get_version(session, actor, version_id)
    if version.template_id != template_id:
        raise NotFoundError("version does not belong to template")

    # team_count comes from the immutable definition (single source of truth).
    definition = validate_definition(version.spec)
    team_count = definition.spec.teams.count
    ensure_teams(session, actor.organization_id, team_count)

    exercise = Exercise(
        organization_id=actor.organization_id,
        template_id=template_id,
        environment_version_id=version_id,
        name=name,
        lifecycle_state=LifecycleState.draft,
        team_count=team_count,
        created_by=actor.user_id,
    )
    session.add(exercise)
    session.flush()
    audit.record(
        session,
        action=AuditAction.exercise_created,
        resource_type="exercise",
        resource_id=exercise.id,
        organization_id=actor.organization_id,
        actor=str(actor.user_id),
        data={"version_id": str(version_id), "team_count": team_count},
    )
    return exercise


def get_exercise(session: Session, actor: Principal, exercise_id: uuid.UUID) -> Exercise:
    exercise = session.get(Exercise, exercise_id)
    if exercise is None:
        raise NotFoundError(f"exercise {exercise_id} not found")
    actor.require_org(exercise.organization_id)
    return exercise


def validate_exercise(session: Session, actor: Principal, exercise_id: uuid.UUID) -> Exercise:
    actor.require(Permission.exercise_operate)
    exercise = get_exercise(session, actor, exercise_id)
    version = get_version(session, actor, exercise.environment_version_id)
    # Re-validate the immutable definition (the 'validate' lifecycle step).
    validate_definition(version.spec)
    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.validated)
    audit.record(
        session,
        action=AuditAction.exercise_validated,
        resource_type="exercise",
        resource_id=exercise.id,
        organization_id=actor.organization_id,
        actor=str(actor.user_id),
    )
    return exercise


def _audit_apply_refusal(
    actor: Principal, exercise_id: uuid.UUID, organization_id: uuid.UUID, reason: str
) -> None:
    """Persist a refusal audit in its own transaction (survives the rollback)."""
    with session_scope() as s:
        audit.record(
            s,
            action=AuditAction.apply_refused,
            resource_type="exercise",
            resource_id=exercise_id,
            organization_id=organization_id,
            actor=str(actor.user_id),
            outcome="denied",
            data={"reason": reason},
        )


def start_exercise(
    session: Session,
    actor: Principal,
    exercise_id: uuid.UUID,
    dispatcher: WorkflowDispatcher | None = None,
) -> WorkflowRun:
    """Approve-gated deploy. Refused (and audited) unless the plan is approved."""
    actor.require(Permission.exercise_apply)
    exercise = get_exercise(session, actor, exercise_id)
    dispatcher = dispatcher or get_dispatcher()
    try:
        return dispatcher.dispatch_deploy(session, exercise.id)
    except ApprovalRequiredError as exc:
        # The main transaction will roll back; record the refusal separately.
        _audit_apply_refusal(actor, exercise.id, exercise.organization_id, exc.message)
        raise


def reset_instance(
    session: Session,
    actor: Principal,
    exercise_id: uuid.UUID,
    instance_id: uuid.UUID,
    dispatcher: WorkflowDispatcher | None = None,
) -> WorkflowRun:
    actor.require(Permission.exercise_reset)
    exercise = get_exercise(session, actor, exercise_id)
    dispatcher = dispatcher or get_dispatcher()
    return dispatcher.dispatch_reset(session, exercise.id, instance_id)


def destroy_exercise(
    session: Session,
    actor: Principal,
    exercise_id: uuid.UUID,
    dispatcher: WorkflowDispatcher | None = None,
) -> WorkflowRun:
    actor.require(Permission.exercise_destroy)
    exercise = get_exercise(session, actor, exercise_id)
    dispatcher = dispatcher or get_dispatcher()
    return dispatcher.dispatch_destroy(session, exercise.id)


def list_instances(
    session: Session, actor: Principal, exercise_id: uuid.UUID
) -> list[EnvironmentInstance]:
    exercise = get_exercise(session, actor, exercise_id)
    return list(
        session.execute(
            select(EnvironmentInstance)
            .where(EnvironmentInstance.exercise_id == exercise.id)
            .order_by(EnvironmentInstance.team_index)
        )
        .scalars()
        .all()
    )


def list_exercises(session: Session, actor: Principal) -> list[Exercise]:
    return list(
        session.execute(
            select(Exercise)
            .where(Exercise.organization_id == actor.organization_id)
            .order_by(Exercise.created_at.desc())
        )
        .scalars()
        .all()
    )
