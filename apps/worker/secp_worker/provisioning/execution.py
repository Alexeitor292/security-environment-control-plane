"""Worker-side provisioning execution (SECP-002B-0, ADR-011/012).

Runs the FakeOpenTofuRunner ONLY when the explicit gate is enabled AND every
provisioning precondition holds. This is the only place the runner is reached. The
API never imports this module or the runner.

Per-kind operations
-------------------
Each call to ``run_provisioning`` for a (manifest_id, kind) pair creates or
retrieves an independent ProvisioningOperation record whose idempotency key is
``sha256(manifest_content_hash + ":" + kind.value)``.  The kind, idempotency key,
and historical result of any completed operation are never mutated.

Durable state
-------------
The ProvisioningOperation record IS the authoritative state.  FakeOpenTofuRunner's
in-memory ``_state`` dict is a local cache only; a fresh runner instance will
never produce incorrect idempotency answers because ``run_provisioning`` reads
operation.status from the database before calling the runner.
"""

from __future__ import annotations

import uuid
from typing import NoReturn

from secp_api import audit
from secp_api.config import Settings, get_settings
from secp_api.enums import (
    AuditAction,
    PlanStatus,
    ProvisioningApplicationMode,
    ProvisioningOperationKind,
    ProvisioningStatus,
    ReservationStatus,
    TargetStatus,
    ToolchainProfileStatus,
)
from secp_api.errors import ProvisioningRefusedError
from secp_api.models import (
    DeploymentPlan,
    EnvironmentVersion,
    ExecutionTarget,
    NetworkReservation,
    ProvisioningManifest,
    ProvisioningOperation,
    ToolchainProfile,
)
from secp_api.provisioning_lifecycle import is_permitted
from secp_api.provisioning_scope import provisioning_scope_policy_hash, validate_provisioning_scope
from secp_api.services import approvals as approvals_service
from secp_api.services import provisioning as prov_service
from secp_api.services.manifests import manifest_idempotency_key
from secp_scenario_schema import content_hash, validate_definition
from sqlalchemy import select

from secp_worker.provisioning.runner import ProvisioningRunner, RunnerError

_LOCAL_STATE_TOKENS = {"local", "local-state", "localfs", "file", "disk", ""}


def _refuse(
    session,
    operation: ProvisioningOperation,
    reason: str,
    *,
    action: AuditAction = AuditAction.provisioning_refused,
) -> NoReturn:
    """Audit + mark the operation failed, then raise ProvisioningRefusedError."""
    audit.record(
        session,
        action=action,
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


def _assert_manifest_integrity(
    session, operation: ProvisioningOperation, manifest: ProvisioningManifest
) -> None:
    if content_hash(manifest.content) != manifest.content_hash:
        _refuse(session, operation, "manifest content hash mismatch (integrity)")


def _assert_plan_and_target(
    session, operation: ProvisioningOperation, manifest: ProvisioningManifest
) -> tuple[DeploymentPlan, ExecutionTarget]:
    plan = session.get(DeploymentPlan, manifest.deployment_plan_id)
    if plan is None or plan.status not in (PlanStatus.approved, PlanStatus.applied):
        _refuse(session, operation, "manifest plan is not approved")
    if plan.execution_target_id is None:
        _refuse(session, operation, "manifest plan is not target-bound")
    target = session.get(ExecutionTarget, manifest.execution_target_id)
    if target is None or target.status != TargetStatus.active:
        _refuse(session, operation, "execution target is missing or not active")
    if target.config_hash != manifest.target_config_hash:
        _refuse(session, operation, "target config hash drifted from the manifest")
    return plan, target


def _assert_scope_binding(
    session,
    operation: ProvisioningOperation,
    manifest: ProvisioningManifest,
    plan: DeploymentPlan,
    target: ExecutionTarget,
) -> None:
    # Strict provisioning scope policy still valid.
    validate_provisioning_scope(target.scope_policy)
    # Scope-policy hash must agree across current target, approved plan, and manifest.
    current_scope_hash = provisioning_scope_policy_hash(target.scope_policy or {})
    if plan.target_scope_policy_hash is None:
        _refuse(
            session,
            operation,
            "approved plan has no scope-policy hash (pre-migration plan); "
            "regenerate the plan and obtain fresh approval",
        )
    if current_scope_hash != plan.target_scope_policy_hash:
        _refuse(
            session,
            operation,
            "target scope_policy has drifted since plan approval; "
            "regenerate the plan and obtain fresh approval before provisioning",
        )
    if manifest.target_scope_policy_hash is None:
        _refuse(
            session,
            operation,
            "manifest has no scope-policy hash binding; generate a new manifest",
        )
    if current_scope_hash != manifest.target_scope_policy_hash:
        _refuse(
            session,
            operation,
            "target scope_policy has drifted from the manifest binding; "
            "generate a new manifest and obtain fresh approval before proceeding",
        )
    # Belt-and-suspenders: exact content comparison against manifest snapshot.
    current_provisioning_policy = (target.scope_policy or {}).get("provisioning", {})
    manifest_policy_snapshot = manifest.content.get("scope_policy", {})
    if current_provisioning_policy != manifest_policy_snapshot:
        _refuse(
            session,
            operation,
            "target scope_policy has drifted from the manifest snapshot; "
            "generate a new manifest and obtain fresh approval before proceeding",
        )
    # External connectivity must remain deny (never permissive).
    if manifest_policy_snapshot.get("external_connectivity", {}).get("policy") != "deny":
        _refuse(
            session,
            operation,
            "external connectivity policy is not 'deny'; permissive external "
            "connectivity is refused",
        )


def _assert_reservation_binding(
    session,
    operation: ProvisioningOperation,
    manifest: ProvisioningManifest,
    plan: DeploymentPlan,
    target: ExecutionTarget,
) -> None:
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
    db_by_team: dict[str, NetworkReservation] = {r.team_ref: r for r in reserved}
    if len(db_by_team) < teams:
        _refuse(session, operation, "finalized CIDR reservations are missing or released")
    manifest_reservations = {
        r["team_ref"]: r["cidr"] for r in manifest.content.get("reservations", [])
    }
    for team_ref, expected_cidr in manifest_reservations.items():
        db_res = db_by_team.get(team_ref)
        if db_res is None:
            _refuse(
                session,
                operation,
                f"reservation for {team_ref} is missing or released; "
                "the manifest snapshot is stale — generate a new manifest",
            )
        if db_res.cidr != expected_cidr:
            _refuse(
                session,
                operation,
                f"reservation for {team_ref} has CIDR {db_res.cidr!r} but manifest "
                f"snapshot expected {expected_cidr!r}; "
                "generate a new manifest to reflect the updated reservation",
            )
        if db_res.organization_id != manifest.organization_id:
            _refuse(
                session,
                operation,
                f"reservation for {team_ref} belongs to a different organization",
            )
        if db_res.exercise_id != plan.exercise_id:
            _refuse(
                session,
                operation,
                f"reservation for {team_ref} is assigned to a different exercise",
            )


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
    _assert_manifest_integrity(session, operation, manifest)
    plan, target = _assert_plan_and_target(session, operation, manifest)
    _assert_scope_binding(session, operation, manifest, plan, target)
    _assert_reservation_binding(session, operation, manifest, plan, target)


def run_provisioning(
    session,
    manifest_id: uuid.UUID,
    kind: ProvisioningOperationKind,
    runner: ProvisioningRunner,
    *,
    settings: Settings | None = None,
) -> ProvisioningOperation:
    """Execute a fake provisioning operation of ``kind`` for the given manifest.

    Each (manifest_id, kind) pair maps to an independent, durable
    ProvisioningOperation record.  The operation is created on first call and
    returned idempotently on subsequent calls.  No raw IntegrityError escapes.
    """
    settings = settings or get_settings()
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ProvisioningRefusedError(f"manifest {manifest_id} not found")

    # Get or create the per-kind durable operation record.
    operation = prov_service.get_or_create_operation(session, manifest, kind)

    _assert_gate_and_preconditions(session, operation, manifest, settings)

    op_ref = manifest_idempotency_key(manifest.content_hash, kind)
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
        # DB-authoritative idempotent noop: the operation is already complete.
        # Do NOT call the runner — its in-memory state may be empty (fresh instance).
        # The prior resources are stored in operation.result; tag as idempotent.
        operation.result = {**operation.result, "idempotent_noop": True}
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
    # Advance through queued if starting from manifest_generated or pending_approval.
    if operation.status in (
        ProvisioningStatus.manifest_generated,
        ProvisioningStatus.pending_approval,
    ):
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.queued,
            action=AuditAction.provisioning_operation_created,
            data={"kind": "destroy"},
        )
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


# =============================================================================
# Real, isolated-lab OpenTofu path (SECP-002B-1A, ADR-013)
# =============================================================================
#
# Disabled by default. Reached ONLY when the full activation gate holds. Uses the
# worker-only OpenTofuRunner behind an injected ProcessExecutor (always the
# FakeProcessExecutor in B1-A — no real binary/provider/endpoint). There is NO fallback
# to the FakeOpenTofuRunner on this path.


def _refuse_real(session, operation: ProvisioningOperation, reason: str) -> NoReturn:
    _refuse(session, operation, reason, action=AuditAction.real_provisioning_refused)


def _assert_real_gate(
    session,
    operation: ProvisioningOperation,
    manifest: ProvisioningManifest,
    settings: Settings,
    dispatch_mode: str,
) -> tuple[DeploymentPlan, ExecutionTarget, ToolchainProfile]:
    # 1. Explicit isolated-lab application mode.
    if settings.provisioning_application_mode != ProvisioningApplicationMode.isolated_lab.value:
        _refuse_real(
            session,
            operation,
            "isolated-lab application mode is not enabled "
            "(set SECP_PROVISIONING_APPLICATION_MODE=isolated_lab)",
        )
    # 2. Explicit real-provisioning setting (never in production in B1-A).
    if settings.is_production or not settings.enable_real_provisioning:
        _refuse_real(
            session,
            operation,
            "real provisioning is disabled; set SECP_ENABLE_REAL_PROVISIONING=true "
            "(reviewed disposable lab only) — real provisioning is refused by default",
        )
    # 3. Temporal/durable worker path only; inline execution is refused.
    if dispatch_mode != "temporal":
        _refuse_real(
            session,
            operation,
            "real provisioning requires the durable Temporal path; inline execution is refused",
        )
    # 4-8. Shared preconditions (integrity, approved target-bound plan, active target +
    #      config hash, scope-policy validity + hash agreement + deny external
    #      connectivity, finalized reservation binding).
    _assert_manifest_integrity(session, operation, manifest)
    plan, target = _assert_plan_and_target(session, operation, manifest)
    _assert_scope_binding(session, operation, manifest, plan, target)
    _assert_reservation_binding(session, operation, manifest, plan, target)
    # 9. Toolchain profile + isolated-lab classification + hash agreement + remote state.
    profile = _assert_toolchain_and_activation(session, operation, manifest, plan, target)
    return plan, target, profile


def _assert_toolchain_and_activation(
    session,
    operation: ProvisioningOperation,
    manifest: ProvisioningManifest,
    plan: DeploymentPlan,
    target: ExecutionTarget,
) -> ToolchainProfile:
    from secp_api.errors import ValidationFailedError
    from secp_api.toolchain_profile import toolchain_profile_hash, validate_toolchain_profile

    # Must be pinned on both the plan and the manifest, and the ids must agree.
    if plan.toolchain_profile_id is None or manifest.toolchain_profile_id is None:
        _refuse_real(
            session,
            operation,
            "no toolchain profile is pinned; the real OpenTofu path requires a pinned "
            "isolated_lab toolchain profile",
        )
    if plan.toolchain_profile_id != manifest.toolchain_profile_id:
        _refuse_real(
            session,
            operation,
            "toolchain profile id disagreement between plan and manifest",
        )
    profile = session.get(ToolchainProfile, manifest.toolchain_profile_id)
    if profile is None or profile.status != ToolchainProfileStatus.active:
        _refuse_real(session, operation, "pinned toolchain profile is missing or not active")
    # Exact id agreement: profile.id == plan == manifest.
    if not (profile.id == plan.toolchain_profile_id == manifest.toolchain_profile_id):
        _refuse_real(session, operation, "toolchain profile id mismatch")
    # The profile must belong to this exact target and organization.
    if profile.execution_target_id != target.id:
        _refuse_real(
            session, operation, "toolchain profile is bound to a different execution target"
        )
    if profile.organization_id != manifest.organization_id:
        _refuse_real(session, operation, "toolchain profile belongs to a different organization")
    # Validate the stored content (shape/safety) and confirm activation class.
    try:
        spec = validate_toolchain_profile(profile.content)
    except ValidationFailedError:
        _refuse_real(session, operation, "toolchain profile failed validation (redacted)")
    if spec.activation_class != "isolated_lab":
        _refuse_real(
            session,
            operation,
            "toolchain profile activation_class is not 'isolated_lab'; the target is not "
            "classified as an isolated disposable lab",
        )
    # Recompute the canonical hash of profile.content: detects content tampering that did
    # not update content_hash, and confirms profile == plan == manifest hash agreement.
    recomputed = toolchain_profile_hash(profile.content)
    if recomputed != profile.content_hash:
        _refuse_real(
            session,
            operation,
            "toolchain profile content hash does not match its recorded hash "
            "(content tampering); regenerate the profile",
        )
    if not (recomputed == plan.toolchain_profile_hash == manifest.toolchain_profile_hash):
        _refuse_real(
            session,
            operation,
            "toolchain profile has drifted (profile/plan/manifest hash disagreement); "
            "regenerate the plan and manifest and obtain fresh approval",
        )
    # Remote state backend must be present and non-local.
    backend = profile.content.get("state_backend") or {}
    if str(backend.get("kind", "")).strip().lower() in _LOCAL_STATE_TOKENS:
        _refuse_real(
            session,
            operation,
            "a validated remote state backend is required; local-only state is refused",
        )
    return profile


def _resolve_lab_secret_env(
    session,
    operation: ProvisioningOperation,
    target: ExecutionTarget,
    kind: ProvisioningOperationKind,
    secret_resolver,
) -> dict[str, str]:
    """Worker-only, just-in-time secret resolution for mutating operations.

    Dry runs use placeholder input variables (no secret needed). Apply/destroy require
    a resolver and a configured secret reference; the resolved token is used to build
    ``TF_VAR_*`` env and is never persisted, hashed, or logged un-redacted.
    """
    if kind not in (ProvisioningOperationKind.apply, ProvisioningOperationKind.destroy):
        return {}
    from secp_worker.provisioning.activation import build_lab_secret_env

    if secret_resolver is None:
        _refuse_real(
            session,
            operation,
            "no secret resolver available for worker-only just-in-time resolution",
        )
    if not target.secret_ref:
        _refuse_real(session, operation, "target has no secret reference configured")
    try:
        credential = secret_resolver.resolve(target.secret_ref)
        token = credential.reveal_secret()
    except ProvisioningRefusedError:
        raise
    except Exception:
        _refuse_real(session, operation, "secret resolution failed (redacted)")
    return build_lab_secret_env(target.config, token)


def run_real_provisioning(
    session,
    manifest_id: uuid.UUID,
    kind: ProvisioningOperationKind,
    *,
    executor=None,
    settings: Settings | None = None,
    dispatch_mode: str = "temporal",
    secret_resolver=None,
    workspace_root: str | None = None,
    verifier=None,
) -> ProvisioningOperation:
    """Execute a REAL isolated-lab OpenTofu operation behind the full activation gate.

    The process ``executor`` is worker-only (always a FakeProcessExecutor in B1-A). When
    not injected it is produced by ``build_process_executor`` using a grant minted ONLY
    after the full gate succeeds — and a hard B1-A seal keeps it a FakeProcessExecutor.
    There is NO FakeOpenTofuRunner fallback on this path.
    """
    from secp_worker.provisioning.activation import (
        build_process_executor,
        grant_real_lab_activation,
    )
    from secp_worker.provisioning.opentofu import OpenTofuRunner
    from secp_worker.provisioning.toolchain_verify import FakeToolchainVerifier

    settings = settings or get_settings()
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ProvisioningRefusedError(f"manifest {manifest_id} not found")

    operation = prov_service.get_or_create_operation(session, manifest, kind)
    plan, target, profile = _assert_real_gate(session, operation, manifest, settings, dispatch_mode)

    # The full gate has passed: mint the worker-only activation grant. Configuration alone
    # can never construct a real subprocess executor; in B1-A a hard seal keeps it fake.
    grant = grant_real_lab_activation(manifest_id=manifest_id, gate_passed=True)

    op_ref = manifest_idempotency_key(manifest.content_hash, kind)
    operation.operation_ref = op_ref
    operation.attempts = (operation.attempts or 0) + 1
    operation.runner = "opentofu"

    secret_env = _resolve_lab_secret_env(session, operation, target, kind, secret_resolver)
    process_executor = (
        executor if executor is not None else build_process_executor(settings, grant=grant)
    )
    runner = OpenTofuRunner(
        process_executor,
        profile=profile.content,
        verifier=verifier or FakeToolchainVerifier(),
        secret_env=secret_env,
        workspace_root=workspace_root,
    )

    try:
        if kind == ProvisioningOperationKind.dry_run:
            return _real_dry_run(
                session, operation, manifest, profile, runner, op_ref, destroy=False
            )
        if kind == ProvisioningOperationKind.destroy_dry_run:
            return _real_dry_run(
                session, operation, manifest, profile, runner, op_ref, destroy=True
            )
        if kind == ProvisioningOperationKind.apply:
            return _real_apply(session, operation, manifest, profile, runner, op_ref)
        if kind == ProvisioningOperationKind.destroy:
            return _real_destroy(session, operation, manifest, profile, runner, op_ref)
        return prov_service.mark_failed(session, operation, error="unknown operation kind")
    except RunnerError:
        return prov_service.mark_failed(session, operation, error="runner error (redacted)")
    except ProvisioningRefusedError:
        raise
    except Exception:
        return prov_service.mark_failed(session, operation, error="provisioning error (redacted)")


def _record_workspace_rendered(session, operation, prepared) -> None:
    audit.record(
        session,
        action=AuditAction.workspace_rendered,
        resource_type="provisioning_operation",
        resource_id=operation.id,
        organization_id=operation.organization_id,
        actor="worker",
        data={
            "workspace_hash": prepared.workspace_hash,
            "change_set_hash": prepared.change_set_hash,
            "kind": prepared.kind,
        },
    )


def _advance_to_queued(session, operation: ProvisioningOperation, kind_label: str) -> None:
    """Advance an early or previously-failed operation to queued (retry-safe)."""
    if operation.status in (
        ProvisioningStatus.manifest_generated,
        ProvisioningStatus.pending_approval,
        ProvisioningStatus.failed,
    ) and is_permitted(operation.status, ProvisioningStatus.queued):
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.queued,
            action=AuditAction.provisioning_operation_created,
            data={"kind": kind_label},
        )


def _real_dry_run(session, operation, manifest, profile, runner, op_ref, *, destroy):
    # Exact-artifact prepare; the ephemeral workspace + plan are always cleaned up.
    prepared = runner.prepare(manifest.content, operation_id=op_ref, destroy=destroy)
    try:
        if destroy:
            authorizes = ProvisioningOperationKind.destroy
            completed_state = ProvisioningStatus.destroy_dry_run_completed
        else:
            authorizes = ProvisioningOperationKind.apply
            completed_state = ProvisioningStatus.dry_run_completed

        # Advance to queued only from an early state (re-run while awaiting stays put).
        if operation.status in (
            ProvisioningStatus.manifest_generated,
            ProvisioningStatus.pending_approval,
        ):
            prov_service.advance(
                session,
                operation,
                ProvisioningStatus.queued,
                action=AuditAction.provisioning_operation_created,
                data={"kind": "destroy_dry_run" if destroy else "dry_run"},
            )

        _record_workspace_rendered(session, operation, prepared)
        # Durable, redacted result: canonical change set only — no secrets, no raw plan
        # JSON, no workspace filesystem path.
        operation.result = {
            "kind": prepared.kind,
            "summary": prepared.change_set.get("summary", {}),
            "change_set_hash": prepared.change_set_hash,
            "workspace_hash": prepared.workspace_hash,
            "resources": prepared.change_set.get("resources", []),
        }
        # Record the pending human-approval binding for this exact change set. A changed
        # regenerated dry run produces a new hash -> a new pending approval, preserving
        # the original approval/audit history.
        approvals_service.record_change_set(
            session,
            manifest,
            profile,
            authorizes_kind=authorizes,
            change_set_hash=prepared.change_set_hash,
            rendered_workspace_hash=prepared.workspace_hash,
            summary=prepared.change_set.get("summary", {}),
            created_by=operation.created_by,
        )
        # Advance queued -> completed -> awaiting when legal; a re-run while already
        # awaiting takes no (illegal) transition.
        if operation.status == ProvisioningStatus.queued:
            prov_service.advance(
                session,
                operation,
                completed_state,
                action=AuditAction.provisioning_dry_run_completed,
                data={
                    "summary": prepared.change_set.get("summary", {}),
                    "change_set_hash": prepared.change_set_hash,
                },
            )
        if operation.status == completed_state:
            prov_service.advance(
                session,
                operation,
                ProvisioningStatus.awaiting_change_set_approval,
                action=AuditAction.change_set_recorded,
                data={
                    "authorizes_kind": authorizes.value,
                    "change_set_hash": prepared.change_set_hash,
                },
            )
        session.flush()
        return operation
    finally:
        runner.cleanup(prepared)


def _assert_approval_bindings(session, operation, manifest, profile, approval) -> None:
    """Any drift between the approval bindings and current state fails closed (#6)."""
    if approval.manifest_content_hash != manifest.content_hash:
        _refuse_real(session, operation, "manifest changed since approval; re-approve")
    if approval.toolchain_profile_hash != profile.content_hash:
        _refuse_real(session, operation, "toolchain profile changed since approval; re-approve")
    if approval.target_scope_policy_hash != (manifest.target_scope_policy_hash or ""):
        _refuse_real(session, operation, "scope policy changed since approval; re-approve")
    if approval.reservations_hash != approvals_service.reservations_hash(manifest):
        _refuse_real(session, operation, "reservations changed since approval; re-approve")


def _require_approved_change_set(session, operation, manifest, authorizes_kind, regen_hash):
    matching = approvals_service.find_approved_change_set(
        session, manifest.id, authorizes_kind, regen_hash
    )
    if matching is not None:
        return matching
    # Distinguish "no approval" (#9/#11) from "regenerated dry run differs" (#10).
    from secp_api.enums import ChangeSetApprovalStatus
    from secp_api.models import ProvisioningChangeSetApproval

    any_approved = (
        session.execute(
            select(ProvisioningChangeSetApproval).where(
                ProvisioningChangeSetApproval.manifest_id == manifest.id,
                ProvisioningChangeSetApproval.authorizes_kind == authorizes_kind,
                ProvisioningChangeSetApproval.status == ChangeSetApprovalStatus.approved,
            )
        )
        .scalars()
        .first()
    )
    if any_approved is None:
        _refuse_real(
            session,
            operation,
            f"{authorizes_kind.value} requires an explicit human-approved dry-run change "
            "set; none is approved",
        )
    _refuse_real(
        session,
        operation,
        "the regenerated dry run differs from the approved change set; re-approve the "
        "new change set before proceeding",
    )


def _real_apply(session, operation, manifest, profile, runner, op_ref):
    # Idempotent: an already-applied operation returns immediately, invoking NO renderer,
    # executor, runner, secret resolution, or approval consumption.
    if operation.status == ProvisioningStatus.applied:
        operation.result = {**(operation.result or {}), "idempotent_noop": True}
        session.flush()
        return operation

    # Prepare exactly one plan; the SAME prepared plan file is applied (no re-plan).
    prepared = runner.prepare(manifest.content, operation_id=op_ref, destroy=False)
    try:
        approval = _require_approved_change_set(
            session, operation, manifest, ProvisioningOperationKind.apply, prepared.change_set_hash
        )
        _assert_approval_bindings(session, operation, manifest, profile, approval)

        _advance_to_queued(session, operation, "apply")
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.applying,
            action=AuditAction.provisioning_apply_started,
            data={"change_set_hash": prepared.change_set_hash},
        )
        result = runner.apply_prepared(prepared, operation_id=op_ref)
        operation.result = {
            "summary": result.summary,
            "resources": result.resources,
            "change_set_hash": prepared.change_set_hash,
        }
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.applied,
            action=AuditAction.provisioning_applied,
            data={"summary": result.summary},
            finished=True,
        )
        approvals_service.mark_consumed(session, approval)
        return operation
    finally:
        runner.cleanup(prepared)


def _real_destroy(session, operation, manifest, profile, runner, op_ref):
    # Idempotent: an already-destroyed operation returns immediately, invoking nothing.
    if operation.status == ProvisioningStatus.destroyed:
        return operation

    prepared = runner.prepare(manifest.content, operation_id=op_ref, destroy=True)
    try:
        approval = _require_approved_change_set(
            session,
            operation,
            manifest,
            ProvisioningOperationKind.destroy,
            prepared.change_set_hash,
        )
        _assert_approval_bindings(session, operation, manifest, profile, approval)

        _advance_to_queued(session, operation, "destroy")
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.destroy_queued,
            action=AuditAction.provisioning_destroy_queued,
            data={"change_set_hash": prepared.change_set_hash},
        )
        result = runner.destroy_prepared(prepared, operation_id=op_ref)
        operation.result = {
            "destroyed": len(result.destroyed),
            "resources": result.destroyed,
            "change_set_hash": prepared.change_set_hash,
        }
        prov_service.advance(
            session,
            operation,
            ProvisioningStatus.destroyed,
            action=AuditAction.provisioning_destroyed,
            data={"destroyed": len(result.destroyed)},
            finished=True,
        )
        approvals_service.mark_consumed(session, approval)
        return operation
    finally:
        runner.cleanup(prepared)
