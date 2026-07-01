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


class ProvisioningOperationKind(str, Enum):
    """The kind of provisioning operation (SECP-002B-0, ADR-012)."""

    dry_run = "dry_run"
    apply = "apply"
    destroy = "destroy"


class ProvisioningStatus(str, Enum):
    """Durable provisioning-operation lifecycle (SECP-002B-0, ADR-011/012)."""

    manifest_generated = "manifest_generated"
    pending_approval = "pending_approval"
    queued = "queued"
    dry_run_completed = "dry_run_completed"
    applying = "applying"
    applied = "applied"
    failed = "failed"
    destroy_queued = "destroy_queued"
    destroyed = "destroyed"


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
    # SECP-002B-0 — provisioning safety harness (manifests + fake runner).
    provisioning_manage = "provisioning:manage"
    provisioning_read = "provisioning:read"


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
    # SECP-002B-0 — provisioning manifests and fake-runner operations.
    manifest_generated = "manifest.generated"
    manifest_validated = "manifest.validated"
    manifest_generation_refused = "manifest.generation_refused"
    provisioning_operation_created = "provisioning.operation_created"
    provisioning_dry_run_completed = "provisioning.dry_run_completed"
    provisioning_apply_started = "provisioning.apply_started"
    provisioning_applied = "provisioning.applied"
    provisioning_failed = "provisioning.failed"
    provisioning_destroy_queued = "provisioning.destroy_queued"
    provisioning_destroyed = "provisioning.destroyed"
    provisioning_refused = "provisioning.refused"
