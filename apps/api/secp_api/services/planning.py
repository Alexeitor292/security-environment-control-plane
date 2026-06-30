"""Deployment-plan services: generate, submit, approve, reject (the approval gate).

A plan is generated deterministically from one immutable environment version and
pins that version's content hash. Apply is refused unless the plan is approved and
the hash still matches (ADR-004).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_plugin_api.v1 import TargetInstance
from secp_scenario_schema import validate_definition
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, LifecycleState, Permission, PlanStatus
from secp_api.errors import DomainError, NotFoundError
from secp_api.lifecycle import transition
from secp_api.models import DeploymentPlan
from secp_api.registry import get_registry
from secp_api.services.catalog import get_version
from secp_api.services.exercises import get_exercise


def _preview_targets(definition) -> list[TargetInstance]:
    """Synthetic targets for a pre-deploy plan preview (no instances exist yet).

    Determinism of the plugin's ``plan`` guarantees the previewed topology matches
    what ``apply`` will realise once concrete instances are created.
    """
    count = definition.spec.teams.count
    return [
        TargetInstance(
            instance_id=f"preview-{i}",
            instance_ref=f"preview-{i}",
            team_ref=f"team{i + 1}",
            team_index=i,
        )
        for i in range(count)
    ]


def generate_plan(session: Session, actor: Principal, exercise_id: uuid.UUID) -> DeploymentPlan:
    actor.require(Permission.plan_generate)
    exercise = get_exercise(session, actor, exercise_id)
    version = get_version(session, actor, exercise.environment_version_id)

    definition = validate_definition(version.spec)
    plugin_name = next(
        (p for p in definition.spec.requiredPlugins if get_registry().has(p)),
        "simulator",
    )
    plugin = get_registry().get(plugin_name)
    plugin_plan = plugin.plan(version.spec, _preview_targets(definition))

    summary = {
        "plugin": plugin_name,
        "teams": definition.spec.teams.count,
        "isolation": definition.spec.teams.isolationPolicy.value,
        "total_networks": plugin_plan.total_networks,
        "total_nodes": plugin_plan.total_nodes,
        "per_team": [
            {
                "team_ref": ip.team_ref,
                "networks": [{"name": n.name, "cidr": n.cidr} for n in ip.desired.networks],
                "nodes": [
                    {"name": n.name, "role": n.role, "kind": n.kind.value, "ip": n.ip_address}
                    for n in ip.desired.nodes
                ],
            }
            for ip in plugin_plan.instances
        ],
    }

    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.planned)
    plan = DeploymentPlan(
        organization_id=exercise.organization_id,
        exercise_id=exercise.id,
        environment_version_id=version.id,
        version_content_hash=version.content_hash,
        status=PlanStatus.generated,
        plan=plugin_plan.model_dump(mode="json"),
        summary=summary,
        generated_by=actor.user_id,
    )
    session.add(plan)
    session.flush()
    audit.record(
        session,
        action=AuditAction.plan_generated,
        resource_type="deployment_plan",
        resource_id=plan.id,
        organization_id=exercise.organization_id,
        actor=str(actor.user_id),
        data={"content_hash": version.content_hash, "plugin": plugin_name},
    )
    return plan


def get_plan(session: Session, actor: Principal, plan_id: uuid.UUID) -> DeploymentPlan:
    plan = session.get(DeploymentPlan, plan_id)
    if plan is None:
        raise NotFoundError(f"deployment plan {plan_id} not found")
    actor.require_org(plan.organization_id)
    return plan


def latest_plan(
    session: Session, actor: Principal, exercise_id: uuid.UUID
) -> DeploymentPlan | None:
    exercise = get_exercise(session, actor, exercise_id)
    return (
        session.execute(
            select(DeploymentPlan)
            .where(DeploymentPlan.exercise_id == exercise.id)
            .order_by(DeploymentPlan.created_at.desc())
        )
        .scalars()
        .first()
    )


def submit_plan(session: Session, actor: Principal, plan_id: uuid.UUID) -> DeploymentPlan:
    actor.require(Permission.plan_generate)
    plan = get_plan(session, actor, plan_id)
    if plan.status != PlanStatus.generated:
        raise DomainError(f"plan is '{plan.status.value}', cannot submit")
    exercise = get_exercise(session, actor, plan.exercise_id)
    exercise.lifecycle_state = transition(
        exercise.lifecycle_state, LifecycleState.awaiting_approval
    )
    plan.status = PlanStatus.awaiting_approval
    audit.record(
        session,
        action=AuditAction.plan_submitted,
        resource_type="deployment_plan",
        resource_id=plan.id,
        organization_id=plan.organization_id,
        actor=str(actor.user_id),
    )
    return plan


def approve_plan(
    session: Session, actor: Principal, plan_id: uuid.UUID, reason: str = ""
) -> DeploymentPlan:
    """Explicitly approve a plan (Charter Invariant 5). Requires plan:approve."""
    actor.require(Permission.plan_approve)
    plan = get_plan(session, actor, plan_id)
    if plan.status != PlanStatus.awaiting_approval:
        raise DomainError(
            f"plan is '{plan.status.value}', only 'awaiting_approval' can be approved"
        )
    exercise = get_exercise(session, actor, plan.exercise_id)
    version = get_version(session, actor, exercise.environment_version_id)

    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.approved)
    plan.status = PlanStatus.approved
    plan.decided_by = actor.user_id
    plan.decided_at = datetime.now(UTC)
    plan.approved_content_hash = version.content_hash
    plan.decision_reason = reason
    audit.record(
        session,
        action=AuditAction.plan_approved,
        resource_type="deployment_plan",
        resource_id=plan.id,
        organization_id=plan.organization_id,
        actor=str(actor.user_id),
        data={"approved_content_hash": version.content_hash, "reason": reason},
    )
    return plan


def reject_plan(
    session: Session, actor: Principal, plan_id: uuid.UUID, reason: str = ""
) -> DeploymentPlan:
    actor.require(Permission.plan_approve)
    plan = get_plan(session, actor, plan_id)
    if plan.status != PlanStatus.awaiting_approval:
        raise DomainError(
            f"plan is '{plan.status.value}', only 'awaiting_approval' can be rejected"
        )
    exercise = get_exercise(session, actor, plan.exercise_id)
    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.validated)
    plan.status = PlanStatus.rejected
    plan.decided_by = actor.user_id
    plan.decided_at = datetime.now(UTC)
    plan.decision_reason = reason
    audit.record(
        session,
        action=AuditAction.plan_rejected,
        resource_type="deployment_plan",
        resource_id=plan.id,
        organization_id=plan.organization_id,
        actor=str(actor.user_id),
        data={"reason": reason},
    )
    return plan
