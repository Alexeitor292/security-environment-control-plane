"""Shared orchestration: deploy / reset / destroy.

This is the single implementation invoked by BOTH the inline dispatcher (dev/test)
and the Temporal worker (production-shaped). It enforces the approval gate, drives
the lifecycle state machine, runs the plugin's side-effecting capabilities through
the worker boundary, persists WorkflowRun records, and audits every transition
(ADR-004, ADR-005; Charter Invariants 4–7, 10, 14, 15).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    LifecycleState,
    PlanStatus,
    WorkflowKind,
    WorkflowStatus,
)
from secp_api.errors import ApprovalRequiredError, InvalidTransitionError, NotFoundError
from secp_api.lifecycle import INSTANCE_TRANSITIONS, transition
from secp_api.models import (
    DeploymentPlan,
    EnvironmentInstance,
    EnvironmentVersion,
    Exercise,
    Team,
    WorkflowRun,
)
from secp_api.registry import get_registry
from secp_api.safety import assert_inline_execution_allowed
from secp_plugin_api.v1 import PluginContext, TargetInstance
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_worker.resource_port import SqlAlchemyResourcePort


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _get_exercise(session: Session, exercise_id: uuid.UUID) -> Exercise:
    ex = session.get(Exercise, exercise_id)
    if ex is None:
        raise NotFoundError(f"exercise {exercise_id} not found")
    return ex


def _get_version(session: Session, version_id: uuid.UUID) -> EnvironmentVersion:
    v = session.get(EnvironmentVersion, version_id)
    if v is None:
        raise NotFoundError(f"environment version {version_id} not found")
    return v


def _approved_plan(session: Session, exercise: Exercise) -> DeploymentPlan:
    """Return the approved plan or refuse (the apply gate — ADR-004)."""
    plan = (
        session.execute(
            select(DeploymentPlan)
            .where(DeploymentPlan.exercise_id == exercise.id)
            .order_by(DeploymentPlan.created_at.desc())
        )
        .scalars()
        .first()
    )
    if plan is None:
        raise ApprovalRequiredError("no deployment plan exists for this exercise")
    if plan.status not in (PlanStatus.approved, PlanStatus.applied):
        raise ApprovalRequiredError(
            f"deployment plan is '{plan.status.value}', not approved; apply refused"
        )
    version = _get_version(session, exercise.environment_version_id)
    if plan.approved_content_hash != version.content_hash:
        raise ApprovalRequiredError(
            "approved plan hash does not match the environment version; apply refused"
        )
    return plan


def _select_plugin_name(definition_spec: dict) -> str:
    registry = get_registry()
    required = (definition_spec.get("spec") or {}).get("requiredPlugins") or []
    for name in required:
        if registry.has(name):
            return name
    return "simulator"


def _targets_for(session: Session, exercise: Exercise) -> list[TargetInstance]:
    instances = (
        session.execute(
            select(EnvironmentInstance)
            .where(EnvironmentInstance.exercise_id == exercise.id)
            .order_by(EnvironmentInstance.team_index)
        )
        .scalars()
        .all()
    )
    return [
        TargetInstance(
            instance_id=str(inst.id),
            instance_ref=inst.instance_ref,
            team_ref=inst.team_ref,
            team_index=inst.team_index,
        )
        for inst in instances
    ]


def _ensure_instances(session: Session, exercise: Exercise) -> None:
    """Create one EnvironmentInstance per team (Charter Invariant 5)."""
    existing = (
        session.execute(
            select(EnvironmentInstance).where(EnvironmentInstance.exercise_id == exercise.id)
        )
        .scalars()
        .all()
    )
    if existing:
        return
    teams = (
        session.execute(
            select(Team).where(Team.organization_id == exercise.organization_id).order_by(Team.slug)
        )
        .scalars()
        .all()
    )
    team_by_index = {i: t for i, t in enumerate(teams)}
    for idx in range(exercise.team_count):
        team = team_by_index.get(idx)
        team_ref = team.slug if team else f"team{idx + 1}"
        instance = EnvironmentInstance(
            organization_id=exercise.organization_id,
            exercise_id=exercise.id,
            team_id=team.id if team else None,
            team_index=idx,
            team_ref=team_ref,
            instance_ref=f"{exercise.name}-{team_ref}",
            lifecycle_state=LifecycleState.deploying,
        )
        session.add(instance)
        session.flush()
        audit.record(
            session,
            action=AuditAction.instance_created,
            resource_type="environment_instance",
            resource_id=instance.id,
            organization_id=exercise.organization_id,
            actor="system",
            data={"team_ref": team_ref, "team_index": idx},
        )


def _new_workflow(
    session: Session,
    exercise: Exercise,
    kind: WorkflowKind,
    dispatch_mode: str,
    target_instance_id: uuid.UUID | None = None,
) -> WorkflowRun:
    run = WorkflowRun(
        organization_id=exercise.organization_id,
        exercise_id=exercise.id,
        kind=kind,
        status=WorkflowStatus.running,
        dispatch_mode=dispatch_mode,
        correlation_id=uuid.uuid4().hex,
        target_instance_id=target_instance_id,
    )
    session.add(run)
    session.flush()
    return run


def _finish_workflow(
    session: Session, run: WorkflowRun, status: WorkflowStatus, detail: dict
) -> None:
    run.status = status
    run.detail = detail
    run.finished_at = _utcnow()
    session.flush()


# --- Workflows ----------------------------------------------------------------


def run_deploy(
    session: Session, exercise_id: uuid.UUID, dispatch_mode: str = "inline"
) -> WorkflowRun:
    exercise = _get_exercise(session, exercise_id)

    # The approval gate — both dispatchers pass through here (ADR-004).
    plan_row = _approved_plan(session, exercise)

    if exercise.lifecycle_state != LifecycleState.approved:
        raise InvalidTransitionError(
            f"deploy requires exercise in 'approved', found '{exercise.lifecycle_state.value}'"
        )

    # Resolve the plugin up front and enforce the inline-execution safety boundary
    # BEFORE any state mutation, so a refusal leaves the exercise untouched.
    version = _get_version(session, exercise.environment_version_id)
    plugin_name = _select_plugin_name(version.spec)
    plugin = get_registry().get(plugin_name)
    if dispatch_mode == "inline":
        assert_inline_execution_allowed(plugin)

    run = _new_workflow(session, exercise, WorkflowKind.deploy, dispatch_mode)
    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.deploying)
    audit.record(
        session,
        action=AuditAction.deploy_started,
        resource_type="exercise",
        resource_id=exercise.id,
        organization_id=exercise.organization_id,
        data={"workflow_run": run.correlation_id},
    )

    _ensure_instances(session, exercise)

    targets = _targets_for(session, exercise)
    plugin_plan = plugin.plan(version.spec, targets)

    port = SqlAlchemyResourcePort(session, provider=plugin_name)
    context = PluginContext(resources=port, correlation_id=run.correlation_id)
    apply_result = plugin.apply(plugin_plan, context)

    # Bring instances and exercise to running.
    instances = (
        session.execute(
            select(EnvironmentInstance).where(EnvironmentInstance.exercise_id == exercise.id)
        )
        .scalars()
        .all()
    )
    for inst in instances:
        inst.lifecycle_state = transition(
            inst.lifecycle_state, LifecycleState.running, INSTANCE_TRANSITIONS
        )
    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.running)
    plan_row.status = PlanStatus.applied

    _finish_workflow(
        session,
        run,
        WorkflowStatus.completed,
        {
            "plugin": plugin_name,
            "instances_applied": apply_result.instances_applied,
            "created": apply_result.created,
        },
    )
    audit.record(
        session,
        action=AuditAction.deploy_completed,
        resource_type="exercise",
        resource_id=exercise.id,
        organization_id=exercise.organization_id,
        data={"created": apply_result.created, "plugin": plugin_name},
    )
    return run


def run_reset(
    session: Session,
    exercise_id: uuid.UUID,
    instance_id: uuid.UUID,
    dispatch_mode: str = "inline",
) -> WorkflowRun:
    exercise = _get_exercise(session, exercise_id)
    instance = session.get(EnvironmentInstance, instance_id)
    if instance is None or instance.exercise_id != exercise.id:
        raise NotFoundError(f"instance {instance_id} not found for exercise")

    # Enforce the inline-execution boundary before any mutation.
    version = _get_version(session, exercise.environment_version_id)
    plugin_name = _select_plugin_name(version.spec)
    plugin = get_registry().get(plugin_name)
    if dispatch_mode == "inline":
        assert_inline_execution_allowed(plugin)

    run = _new_workflow(
        session, exercise, WorkflowKind.reset, dispatch_mode, target_instance_id=instance.id
    )
    instance.lifecycle_state = transition(
        instance.lifecycle_state, LifecycleState.resetting, INSTANCE_TRANSITIONS
    )
    audit.record(
        session,
        action=AuditAction.reset_started,
        resource_type="environment_instance",
        resource_id=instance.id,
        organization_id=exercise.organization_id,
        data={"workflow_run": run.correlation_id},
    )

    targets = _targets_for(session, exercise)
    plugin_plan = plugin.plan(version.spec, targets)

    port = SqlAlchemyResourcePort(session, provider=plugin_name)
    context = PluginContext(resources=port, correlation_id=run.correlation_id)
    reset_result = plugin.reset(plugin_plan, str(instance.id), context)

    instance.lifecycle_state = transition(
        instance.lifecycle_state, LifecycleState.running, INSTANCE_TRANSITIONS
    )
    _finish_workflow(
        session,
        run,
        WorkflowStatus.completed,
        {"idempotent_noop": reset_result.idempotent_noop, "plugin": plugin_name},
    )
    audit.record(
        session,
        action=AuditAction.reset_completed,
        resource_type="environment_instance",
        resource_id=instance.id,
        organization_id=exercise.organization_id,
        data={"idempotent_noop": reset_result.idempotent_noop},
    )
    return run


def run_destroy(
    session: Session, exercise_id: uuid.UUID, dispatch_mode: str = "inline"
) -> WorkflowRun:
    exercise = _get_exercise(session, exercise_id)

    # Enforce the inline-execution boundary before any mutation (applies even to
    # the idempotent no-op path below).
    version = _get_version(session, exercise.environment_version_id)
    plugin_name = _select_plugin_name(version.spec)
    plugin = get_registry().get(plugin_name)
    if dispatch_mode == "inline":
        assert_inline_execution_allowed(plugin)

    # Idempotent: destroying an already-destroyed exercise is a safe no-op.
    if exercise.lifecycle_state == LifecycleState.destroyed:
        run = _new_workflow(session, exercise, WorkflowKind.destroy, dispatch_mode)
        _finish_workflow(session, run, WorkflowStatus.completed, {"idempotent_noop": True})
        audit.record(
            session,
            action=AuditAction.destroy_completed,
            resource_type="exercise",
            resource_id=exercise.id,
            organization_id=exercise.organization_id,
            data={"idempotent_noop": True},
        )
        return run

    run = _new_workflow(session, exercise, WorkflowKind.destroy, dispatch_mode)
    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.destroying)
    audit.record(
        session,
        action=AuditAction.destroy_started,
        resource_type="exercise",
        resource_id=exercise.id,
        organization_id=exercise.organization_id,
        data={"workflow_run": run.correlation_id},
    )

    instances = (
        session.execute(
            select(EnvironmentInstance).where(EnvironmentInstance.exercise_id == exercise.id)
        )
        .scalars()
        .all()
    )
    port = SqlAlchemyResourcePort(session, provider=plugin_name)
    context = PluginContext(resources=port, correlation_id=run.correlation_id)

    destroy_result = plugin.destroy([str(i.id) for i in instances], context)

    for inst in instances:
        if inst.lifecycle_state != LifecycleState.destroyed:
            # running/failed -> destroying -> destroyed
            if inst.lifecycle_state == LifecycleState.running:
                inst.lifecycle_state = transition(
                    inst.lifecycle_state, LifecycleState.destroying, INSTANCE_TRANSITIONS
                )
            inst.lifecycle_state = LifecycleState.destroyed
    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.destroyed)

    _finish_workflow(
        session,
        run,
        WorkflowStatus.completed,
        {
            "instances_destroyed": destroy_result.instances_destroyed,
            "idempotent_noop": destroy_result.idempotent_noop,
        },
    )
    audit.record(
        session,
        action=AuditAction.destroy_completed,
        resource_type="exercise",
        resource_id=exercise.id,
        organization_id=exercise.organization_id,
        data={"instances": len(instances)},
    )
    return run
