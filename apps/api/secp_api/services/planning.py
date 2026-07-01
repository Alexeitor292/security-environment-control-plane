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
from secp_api.enums import AuditAction, LifecycleState, Permission, PlanStatus, TargetStatus
from secp_api.errors import DomainError, NotFoundError
from secp_api.lifecycle import transition
from secp_api.models import DeploymentPlan
from secp_api.provisioning_scope import provisioning_scope_policy_hash
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

    # --- execution-target pinning (ADR-006) ----------------------------------
    # When the exercise is bound to a target, validate it and capture its
    # immutable config hash so approval covers the exact destination.
    target = None
    if exercise.execution_target_id is not None:
        from secp_api.services.targets import get_target

        target = get_target(session, actor, exercise.execution_target_id)
        if target.status != TargetStatus.active:
            raise DomainError(
                f"execution target '{target.display_name}' is not active "
                f"(status='{target.status.value}'); only active targets may be used "
                "for new deployment plans"
            )
    # -------------------------------------------------------------------------

    definition = validate_definition(version.spec)
    # --- provider selection (ADR-006) ----------------------------------------
    # requiredPlugins is a *capability declaration*, not an executor list.
    # For SECP-002A the topology preview is always produced by the Simulator.
    # A target-bound plan records the intended execution provider in the summary
    # but does NOT invoke it; provisioning is deferred to SECP-002B.
    if target is not None:
        execution_provider = target.plugin_name  # e.g. "proxmox"
        topology_preview_provider = "simulator"  # only preview available in 002A
    else:
        execution_provider = "simulator"
        topology_preview_provider = "simulator"
    # -------------------------------------------------------------------------
    plugin = get_registry().get(topology_preview_provider)
    plugin_plan = plugin.plan(version.spec, _preview_targets(definition))

    summary: dict = {
        "execution_provider": execution_provider,
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
    # Include pinned target info in the human-readable summary so approval
    # clearly covers the exact destination (ADR-006).
    if target is not None:
        summary["topology_preview_provider"] = topology_preview_provider
        summary["execution_target"] = {
            "id": str(target.id),
            "plugin_name": target.plugin_name,
            "display_name": target.display_name,
            "config_hash": target.config_hash,
        }
        # Automated, declarative deployment contract (SECP-002B-1B-0, ADR-014). Standard
        # provider-backed deployment is automated: SECP allocates IDs/addresses and creates
        # the scenario resources — the user does NOT manually pre-create VMs, containers,
        # networks, addresses, or storage. Every action remains subject to plan approval,
        # the target scope policy, immutable manifests, and worker-only execution.
        summary["deployment_contract"] = {
            "mode": "automated",
            "provisioning_model": "declarative",
            "target_boundary_source": "target.scope_policy.provisioning + onboarding boundary",
            "secp_automated_actions": [
                "allocate_vm_ids",
                "allocate_addresses",
                "create_networks",
                "create_vms",
                "create_containers",
                "create_disks",
                "create_attachments",
            ],
            "scenario_resources_created_by_secp": True,
            "manual_pre_creation_required": False,
            "user_provided_preexisting_assets": [],  # excluded from standard mode
            "subject_to_approval": True,
            "subject_to_scope_policy": True,
        }
        # Hash scope_policy["provisioning"] so plan approval covers the exact
        # provisioning policy, not just the target config hash (SECP-002B-0).
        scope_hash = provisioning_scope_policy_hash(target.scope_policy)
        summary["scope_policy_hash"] = scope_hash
        # Pin the active toolchain profile (if any) so plan approval also covers the
        # exact worker-side IaC runtime for the real OpenTofu path (SECP-002B-1A).
        # No profile => fake-runner/Simulator paths only; the real-lab gate fails closed.
        from secp_api.services.toolchain import active_profile_for_target

        toolchain = active_profile_for_target(session, target.id)
        if toolchain is not None:
            toolchain_profile_id = toolchain.id
            toolchain_profile_hash = toolchain.content_hash
            summary["toolchain_profile"] = {
                "id": str(toolchain.id),
                "content_hash": toolchain.content_hash,
                "runner_kind": toolchain.runner_kind,
                "activation_class": toolchain.activation_class,
                "version": toolchain.version,
            }
        else:
            toolchain_profile_id = None
            toolchain_profile_hash = None
        # Enforceable onboarding binding (SECP-002B-1B-0, ADR-014). A target-bound plan
        # may be generated only when exactly ONE active onboarding exists for the target;
        # the plan binds that onboarding + its approved preflight evidence.
        from secp_api.services.onboarding import require_single_active_onboarding

        onboarding = require_single_active_onboarding(session, target.id)
        onboarding_id = onboarding.id
        onboarding_boundary_hash = onboarding.approved_boundary_hash
        approved_preflight_id = onboarding.approved_preflight_id
        approved_preflight_evidence_hash = onboarding.approved_preflight_evidence_hash
        onboarding_verification_level = onboarding.approved_verification_level
        summary["onboarding"] = {
            "id": str(onboarding.id),
            "isolation_model": onboarding.isolation_model.value,
            "onboarding_mode": onboarding.onboarding_mode.value,
            "boundary_hash": onboarding_boundary_hash,
            "verification_level": onboarding_verification_level,
        }
    else:
        scope_hash = None
        toolchain_profile_id = None
        toolchain_profile_hash = None
        onboarding_id = None
        onboarding_boundary_hash = None
        approved_preflight_id = None
        approved_preflight_evidence_hash = None
        onboarding_verification_level = None

    exercise.lifecycle_state = transition(exercise.lifecycle_state, LifecycleState.planned)
    plan = DeploymentPlan(
        organization_id=exercise.organization_id,
        exercise_id=exercise.id,
        environment_version_id=version.id,
        version_content_hash=version.content_hash,
        execution_target_id=target.id if target is not None else None,
        target_config_hash=target.config_hash if target is not None else None,
        target_scope_policy_hash=scope_hash,
        toolchain_profile_id=toolchain_profile_id,
        toolchain_profile_hash=toolchain_profile_hash,
        target_onboarding_id=onboarding_id,
        onboarding_boundary_hash=onboarding_boundary_hash,
        approved_preflight_id=approved_preflight_id,
        approved_preflight_evidence_hash=approved_preflight_evidence_hash,
        onboarding_verification_level=onboarding_verification_level,
        status=PlanStatus.generated,
        plan=plugin_plan.model_dump(mode="json"),
        summary=summary,
        generated_by=actor.user_id,
    )
    session.add(plan)
    session.flush()
    audit_data: dict = {
        "content_hash": version.content_hash,
        "execution_provider": execution_provider,
    }
    if target is not None:
        audit_data["execution_target_id"] = str(target.id)
        audit_data["target_config_hash"] = target.config_hash
        audit_data["target_scope_policy_hash"] = scope_hash
    audit.record(
        session,
        action=AuditAction.plan_generated,
        resource_type="deployment_plan",
        resource_id=plan.id,
        organization_id=exercise.organization_id,
        actor=str(actor.user_id),
        data=audit_data,
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


def assert_deployment_eligible(session: Session, exercise_id: uuid.UUID) -> None:
    """SECP-002A deployment preflight — shared by all dispatch paths.

    Must be called before any WorkflowRun creation, outbox queuing, Temporal
    workflow request, state mutation, secret resolution, or provider invocation.
    Refuses when the latest approved (or applied) plan is pinned to a real
    execution target.

    The normal approval-gate and hash checks remain in the existing downstream
    guards (_approved_plan in orchestration.py); this function adds the SECP-002A
    provisioning-boundary enforcement as far upstream as possible.
    """
    from secp_api.safety import InlineExecutionForbidden

    plan = (
        session.execute(
            select(DeploymentPlan)
            .where(DeploymentPlan.exercise_id == exercise_id)
            .order_by(DeploymentPlan.created_at.desc())
        )
        .scalars()
        .first()
    )
    # No plan or not yet approved: the normal approval gate handles this.
    if plan is None or plan.status not in (PlanStatus.approved, PlanStatus.applied):
        return
    if plan.execution_target_id is not None:
        raise InlineExecutionForbidden(
            f"deployment to a non-simulator execution target "
            f"(target={plan.execution_target_id}, "
            f"target_config_hash={plan.target_config_hash}) is not implemented "
            "in SECP-002A. No WorkflowRun, outbox row, Temporal workflow, "
            "secret resolution, or state mutation was started. "
            "Provisioning is deferred to SECP-002B."
        )
