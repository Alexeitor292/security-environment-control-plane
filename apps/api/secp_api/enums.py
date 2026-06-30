"""Shared enumerations: lifecycle states, plan/workflow status, audit actions."""

from __future__ import annotations

from enum import Enum


class LifecycleState(str, Enum):
    """The authoritative environment/exercise lifecycle (Charter §6, design §7/§9)."""

    draft = "draft"
    validated = "validated"
    planned = "planned"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    deploying = "deploying"
    running = "running"
    resetting = "resetting"
    destroying = "destroying"
    destroyed = "destroyed"
    failed = "failed"


class PlanStatus(str, Enum):
    generated = "generated"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    rejected = "rejected"
    applied = "applied"


class TargetStatus(str, Enum):
    """Lifecycle status of an ExecutionTarget (ADR-006)."""

    active = "active"
    disabled = "disabled"
    discovery_failed = "discovery_failed"


class ReservationStatus(str, Enum):
    """Status of a network address-space reservation (ADR-009)."""

    reserved = "reserved"
    released = "released"


class SnapshotStatus(str, Enum):
    """Status of a provider inventory snapshot (ADR-008)."""

    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class WorkflowKind(str, Enum):
    deploy = "deploy"
    reset = "reset"
    destroy = "destroy"
    discover = "discover"  # provider inventory discovery (read-only)


class WorkflowStatus(str, Enum):
    queued = "queued"  # created by the API, awaiting worker execution (ADR-010)
    running = "running"
    completed = "completed"
    failed = "failed"


class Permission(str, Enum):
    """Coarse RBAC permissions gating sensitive control-plane actions."""

    template_author = "template:author"
    version_create = "version:create"
    exercise_operate = "exercise:operate"
    plan_generate = "plan:generate"
    plan_approve = "plan:approve"
    exercise_apply = "exercise:apply"
    exercise_reset = "exercise:reset"
    exercise_destroy = "exercise:destroy"
    audit_read = "audit:read"
    # SECP-002A — provider targets and read-only discovery.
    target_manage = "target:manage"
    inventory_discover = "inventory:discover"
    inventory_read = "inventory:read"


class AuditAction(str, Enum):
    organization_created = "organization.created"
    user_created = "user.created"
    team_created = "team.created"
    template_created = "template.created"
    version_created = "version.created"
    version_mutation_rejected = "version.mutation_rejected"
    exercise_created = "exercise.created"
    exercise_validated = "exercise.validated"
    plan_generated = "plan.generated"
    plan_submitted = "plan.submitted"
    plan_approved = "plan.approved"
    plan_rejected = "plan.rejected"
    apply_refused = "apply.refused"
    execution_refused = "execution.refused"
    deploy_started = "deploy.started"
    deploy_completed = "deploy.completed"
    instance_created = "instance.created"
    reset_started = "reset.started"
    reset_completed = "reset.completed"
    destroy_started = "destroy.started"
    destroy_completed = "destroy.completed"
    lifecycle_transition = "lifecycle.transition"
    authorization_denied = "authorization.denied"
    # SECP-002A — execution targets, discovery, reservations, secret resolution.
    target_created = "target.created"
    target_disabled = "target.disabled"
    discovery_requested = "discovery.requested"
    discovery_started = "discovery.started"
    discovery_completed = "discovery.completed"
    discovery_failed = "discovery.failed"
    secret_resolution_failed = "secret.resolution_failed"
    provider_operation_refused = "provider.operation_refused"
    reservation_created = "reservation.created"
    reservation_released = "reservation.released"
    # SECP-002A plan target-pinning.
    plan_target_bound = "plan.target_bound"
    target_deploy_refused = "deploy.target_refused"
