"""Worker-side provisioning execution (SECP-002B-0, ADR-011/012).

Runs the FakeOpenTofuRunner ONLY when the explicit gate is enabled AND every
provisioning precondition holds. This is the only place the runner is reached. The
API never imports this module or the runner.
"""

from __future__ import annotations

import uuid

from secp_api import audit
from secp_api.config import Settings, get_settings
from secp_api.enums import (
    AuditAction,
    PlanStatus,
    ProvisioningOperationKind,
    ProvisioningStatus,
    ReservationStatus,
    TargetStatus,
)
from secp_api.errors import ProvisioningRefusedError
from secp_api.models import (
    DeploymentPlan,
    EnvironmentVersion,
    ExecutionTarget,
    NetworkReservation,
    ProvisioningManifest,
    ProvisioningOperation,
)
from secp_api.provisioning_scope import validate_provisioning_scope
from secp_api.services import provisioning as prov_service
from secp_api.services.manifests import manifest_idempotency_key
from secp_scenario_schema import content_hash, validate_definition
from sqlalchemy import select

from secp_worker.provisioning.runner import ProvisioningRunner, RunnerError


def _refuse(session, operation: ProvisioningOperation, reason: str) -> None:
    """Audit + mark the operation failed, then raise ProvisioningRefusedError."""
    audit.record(
        session,
        action=AuditAction.provisioning_refused,
        resource_type="provisioning_operation",
        resource_id=operation.id,
        organization_id=operation.organization_id,
        actor="worker",
        outcome="denied",
        data={"reason": reason},
    )
    # Best effort: reflect the refusal on the operation (manifest_generated -> failed).
    try:
        prov_service.mark_failed(session, operation, error=f"refused: {reason}")
    except Exception:  # transition may be illegal from a terminal state
        pass
    raise ProvisioningRefusedError(reason)


def _assert_gate_and_preconditions(
    session, operation: ProvisioningOperation, manifest: ProvisioningManifest, settings: Settings
) -> None:
    # 1. Explicit dev/test gate (never in production — enforced by Settings too).
    if settings.is_production or not settings.enable_fake_provisioning:
        _refuse(
            session,
            operation,
            "fake provisioning runner is disabled; set SECP_ENABLE_FAKE_PROVISIONING=true "
            "(dev/test only) — target-bound provisioning is refused by default",
        )

    # 2. Manifest integrity (content hash matches recorded hash).
    if content_hash(manifest.content) != manifest.content_hash:
        _refuse(session, operation, "manifest content hash mismatch (integrity)")

    # 3. Approved, target-bound plan.
    plan = session.get(DeploymentPlan, manifest.deployment_plan_id)
    if plan is None or plan.status not in (PlanStatus.approved, PlanStatus.applied):
        _refuse(session, operation, "manifest plan is not approved")
    if plan.execution_target_id is None:
        _refuse(session, operation, "manifest plan is not target-bound")

    # 4. Active target, no hash drift.
    target = session.get(ExecutionTarget, manifest.execution_target_id)
    if target is None or target.status != TargetStatus.active:
        _refuse(session, operation, "execution target is missing or not active")
    if target.config_hash != manifest.target_config_hash:
        _refuse(session, operation, "target config hash drifted from the manifest")

    # 5. Strict provisioning scope policy still valid.
    validate_provisioning_scope(target.scope_policy)

    # 6. Finalized reservations still present for every team.
    version = session.get(EnvironmentVersion, plan.environment_version_id)
    teams = validate_definition(version.spec).spec.teams.count
    reserved = (
        session.execute(
            select(NetworkReservation).where(
                NetworkReservation.execution_target_id == target.id,
                NetworkReservation.exercise_id == plan.exercise_id,
                NetworkReservation.status == ReservationStatus.reserved,
            )
        )
        .scalars()
        .all()
    )
    if len({r.team_ref for r in reserved}) < teams:
        _refuse(session, operation, "finalized CIDR reservations are missing or released")


def run_provisioning(
    session,
    operation_id: uuid.UUID,
    kind: ProvisioningOperationKind,
    runner: ProvisioningRunner,
    *,
    settings: Settings | None = None,
) -> ProvisioningOperation:
    """Execute a fake provisioning operation of ``kind`` (worker-only)."""
    settings = settings or get_settings()
    operation = session.get(ProvisioningOperation, operation_id)
    if operation is None:
        raise ProvisioningRefusedError(f"operation {operation_id} not found")
    manifest = session.get(ProvisioningManifest, operation.manifest_id)
    if manifest is None:
        _refuse(session, operation, "manifest not found")

    _assert_gate_and_preconditions(session, operation, manifest, settings)

    op_ref = manifest_idempotency_key(manifest.content_hash, kind)
    operation.kind = kind
    operation.operation_ref = op_ref
    operation.attempts = (operation.attempts or 0) + 1

    try:
        validation = runner.validate(manifest.content)
        if not validation.ok:
            return prov_service.mark_failed(
                session, operation, error="manifest failed runner validation (redacted)"
            )

        if kind == ProvisioningOperationKind.dry_run:
            return _run_dry_run(session, operation, manifest, runner, op_ref)
        if kind == ProvisioningOperationKind.apply:
            return _run_apply(session, operation, manifest, runner, op_ref)
        if kind == ProvisioningOperationKind.destroy:
            return _run_destroy(session, operation, manifest, runner, op_ref)
        return prov_service.mark_failed(session, operation, error="unknown operation kind")
    except RunnerError:
        # Redacted: never surface the underlying detail.
        return prov_service.mark_failed(session, operation, error="runner error (redacted)")
    except ProvisioningRefusedError:
        raise
    except Exception:
        return prov_service.mark_failed(session, operation, error="provisioning error (redacted)")


def _run_dry_run(session, operation, manifest, runner, op_ref):
    if operation.status in (
        ProvisioningStatus.manifest_generated,
        ProvisioningStatus.pending_approval,
    ):
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.queued,
            action=AuditAction.provisioning_operation_created,
            data={"kind": "dry_run"},
        )
    change_set = runner.dry_run(manifest.content, operation_id=op_ref)
    operation.result = change_set.model_dump()
    if operation.status != ProvisioningStatus.dry_run_completed:
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.dry_run_completed,
            action=AuditAction.provisioning_dry_run_completed,
            data={"summary": change_set.summary},
        )
    else:
        session.flush()  # deterministic re-run keeps state
    return operation


def _run_apply(session, operation, manifest, runner, op_ref):
    if operation.status == ProvisioningStatus.applied:
        # Idempotent: already applied.
        result = runner.apply(manifest.content, operation_id=op_ref)
        operation.result = result.model_dump()
        session.flush()
        return operation
    if operation.status in (
        ProvisioningStatus.manifest_generated,
        ProvisioningStatus.pending_approval,
    ):
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.queued,
            action=AuditAction.provisioning_operation_created,
            data={"kind": "apply"},
        )
    prov_service.advance(
        session,
        operation,
        ProvisioningStatus.applying,
        action=AuditAction.provisioning_apply_started,
        data={},
    )
    result = runner.apply(manifest.content, operation_id=op_ref)
    operation.result = result.model_dump()
    prov_service.advance(
        session,
        operation,
        ProvisioningStatus.applied,
        action=AuditAction.provisioning_applied,
        data={"summary": result.summary, "idempotent_noop": result.idempotent_noop},
        finished=True,
    )
    return operation


def _run_destroy(session, operation, manifest, runner, op_ref):
    if operation.status == ProvisioningStatus.destroyed:
        return operation  # idempotent noop
    prov_service.advance(
        session,
        operation,
        ProvisioningStatus.destroy_queued,
        action=AuditAction.provisioning_destroy_queued,
        data={},
    )
    result = runner.destroy(manifest.content, operation_id=op_ref)
    operation.result = result.model_dump()
    prov_service.advance(
        session,
        operation,
        ProvisioningStatus.destroyed,
        action=AuditAction.provisioning_destroyed,
        data={"destroyed": len(result.destroyed), "idempotent_noop": result.idempotent_noop},
        finished=True,
    )
    return operation
