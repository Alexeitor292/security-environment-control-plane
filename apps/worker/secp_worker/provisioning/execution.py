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
    AuditOutcome,
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
        outcome=AuditOutcome.denied,
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
    # The content snapshot is the effective provisioning-policy view. The exact effective
    # snapshot is verified after onboarding/effective-boundary recomputation below.
    manifest_policy_snapshot = manifest.content.get("scope_policy", {})
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
    # 2. RETIRED by ADR-030 §2. This checked ``settings.enable_real_provisioning``, a settings field
    #    whose value widened what may execute — the exact shape §2 forbids. It is not replaced by
    #    another setting or another boolean: whether this operation may execute is answered by
    #    ``authorize_provisioning_execution`` against durable rows, and a deployment-wide flag
    #    cannot express "this operation, this worker, this approved change set, now".
    #
    #    The production check went with it for the same reason. "Not in production" is a property
    #    of the process, and a process-wide property is precisely what must not be able to permit
    #    or forbid a specific authorized operation.
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
    # 10. Target onboarding: exact agreement onboarding → plan → manifest → approved
    #     preflight evidence, with no config/scope/boundary drift (SECP-002B-1B-0, ADR-014).
    _assert_target_onboarded(session, operation, manifest, plan, target)
    return plan, target, profile


def _assert_target_onboarded(
    session,
    operation: ProvisioningOperation,
    manifest: ProvisioningManifest,
    plan: DeploymentPlan,
    target: ExecutionTarget,
):
    from secp_api.errors import DomainError
    from secp_api.models import TargetPreflight
    from secp_api.services.onboarding import (
        active_onboarding_for_target,
        onboarding_drift,
        recompute_evidence_hash,
    )

    try:
        ob = active_onboarding_for_target(session, target.id)
    except DomainError:
        _refuse_real(session, operation, "ambiguous active onboarding for target; fail closed")
    if ob is None:
        _refuse_real(
            session,
            operation,
            "target has no approved & active onboarding record; real provisioning requires "
            "an approved target onboarding (SECP-002B-1B, ADR-014)",
        )
    drift = onboarding_drift(ob, target)
    if drift is not None:
        _refuse_real(
            session,
            operation,
            f"onboarding approval is invalidated: {drift}; re-onboard and obtain fresh approval",
        )
    # Exact agreement across onboarding record, plan, manifest columns, AND the immutable
    # manifest content block. The approved preflight IDENTITY (id) must agree everywhere, not
    # just the evidence hash (ADR-014 §3 correction pass).
    ob_pf_id = str(ob.approved_preflight_id)
    content_ob = manifest.content.get("onboarding", {}) or {}
    checks = (
        (plan.target_onboarding_id == ob.id, "plan onboarding id mismatch"),
        (manifest.target_onboarding_id == ob.id, "manifest onboarding id mismatch"),
        (content_ob.get("target_onboarding_id") == str(ob.id), "content onboarding id mismatch"),
        (str(plan.approved_preflight_id) == ob_pf_id, "plan approved preflight id mismatch"),
        (
            str(manifest.approved_preflight_id) == ob_pf_id,
            "manifest approved preflight id mismatch",
        ),
        (
            content_ob.get("approved_preflight_id") == ob_pf_id,
            "content approved preflight id mismatch",
        ),
        (
            plan.onboarding_boundary_hash == ob.approved_boundary_hash,
            "plan onboarding boundary hash mismatch",
        ),
        (
            manifest.onboarding_boundary_hash == ob.approved_boundary_hash,
            "manifest onboarding boundary hash mismatch",
        ),
        (
            content_ob.get("onboarding_boundary_hash") == ob.approved_boundary_hash,
            "content onboarding boundary hash mismatch",
        ),
        (
            plan.approved_preflight_evidence_hash == ob.approved_preflight_evidence_hash,
            "plan approved preflight evidence hash mismatch",
        ),
        (
            manifest.approved_preflight_evidence_hash == ob.approved_preflight_evidence_hash,
            "manifest approved preflight evidence hash mismatch",
        ),
        (
            content_ob.get("approved_preflight_evidence_hash")
            == ob.approved_preflight_evidence_hash,
            "content approved preflight evidence hash mismatch",
        ),
        (
            plan.onboarding_verification_level == ob.approved_verification_level,
            "plan onboarding verification level mismatch",
        ),
        (
            manifest.onboarding_verification_level == ob.approved_verification_level,
            "manifest onboarding verification level mismatch",
        ),
        (
            content_ob.get("verification_level") == ob.approved_verification_level,
            "content onboarding verification level mismatch",
        ),
    )
    for ok, reason in checks:
        if not ok:
            _refuse_real(session, operation, f"onboarding binding drift: {reason}")
    # Recompute the approved preflight evidence hash (altered/stale evidence refused).
    pf = (
        session.get(TargetPreflight, ob.approved_preflight_id) if ob.approved_preflight_id else None
    )
    if pf is None or recompute_evidence_hash(pf) != ob.approved_preflight_evidence_hash:
        _refuse_real(session, operation, "approved preflight evidence is missing or altered")
    # Toolchain provenance binding (ADR-014 §4): the approved preflight's toolchain provenance
    # must equal the plan's pinned profile (already proven == manifest == current active by
    # _assert_toolchain_and_activation), so pf == plan == manifest == active.
    if plan.toolchain_profile_id is not None:
        if str(pf.toolchain_profile_id) != str(plan.toolchain_profile_id) or (
            pf.toolchain_profile_hash != plan.toolchain_profile_hash
        ):
            _refuse_real(
                session,
                operation,
                "approved preflight toolchain provenance disagrees with the pinned profile",
            )
    # Effective execution boundary (ADR-014 §2): recompute from the active onboarding +
    # current target scope, require non-empty and exact agreement with plan, manifest, and
    # manifest content, then enforce every declared action against it BEFORE rendering,
    # secret resolution, executor construction, or process calls.
    _assert_effective_boundary(session, operation, manifest, plan, target, ob)
    return ob


def _assert_effective_boundary(
    session,
    operation: ProvisioningOperation,
    manifest: ProvisioningManifest,
    plan: DeploymentPlan,
    target: ExecutionTarget,
    ob,
) -> None:
    from secp_api.effective_boundary import effective_policy_view
    from secp_api.onboarding import (
        OnboardingBoundarySpec,
        effective_boundary_hash,
        effective_boundary_is_empty,
    )
    from secp_api.onboarding import effective_boundary as compute_effective_boundary

    from secp_worker.provisioning.boundary import enforce_manifest_within_boundary

    spec = OnboardingBoundarySpec.model_validate(ob.declared_boundary)
    eff = compute_effective_boundary(spec, target.scope_policy or {})
    if effective_boundary_is_empty(eff):
        _refuse_real(
            session, operation, "effective execution boundary is empty; re-onboard the target"
        )
    eff_hash = effective_boundary_hash(eff)
    content_ob = manifest.content.get("onboarding", {}) or {}
    content_eff = content_ob.get("effective_boundary")
    content_eff_hash = content_ob.get("effective_boundary_hash")
    boundary_checks = (
        (plan.effective_boundary == eff, "plan effective boundary mismatch"),
        (plan.effective_boundary_hash == eff_hash, "plan effective boundary hash mismatch"),
        (manifest.effective_boundary == eff, "manifest effective boundary mismatch"),
        (manifest.effective_boundary_hash == eff_hash, "manifest effective boundary hash mismatch"),
        (content_eff == eff, "manifest content effective boundary mismatch"),
        (content_eff_hash == eff_hash, "manifest content effective boundary hash mismatch"),
    )
    for ok, reason in boundary_checks:
        if not ok:
            _refuse_real(session, operation, f"effective boundary drift: {reason}")
    target_policy = validate_provisioning_scope(target.scope_policy)
    expected_policy_snapshot = effective_policy_view(target_policy, eff).model_dump(mode="json")
    if manifest.content.get("scope_policy", {}) != expected_policy_snapshot:
        _refuse_real(
            session,
            operation,
            "effective provisioning policy snapshot has drifted from the effective boundary",
        )
    violations = enforce_manifest_within_boundary(manifest.content, eff)
    if violations:
        _refuse_real(
            session,
            operation,
            f"manifest action outside the effective execution boundary: {violations[0]}",
        )


def assert_evidence_sufficient_for_execution(onboarding, *, require_live: bool) -> None:
    """Structural enforcement (ADR-014 §2): live provisioning requires ``live_verified``
    evidence. Simulated evidence supports onboarding UX/review but never unlocks live
    real provisioning. Raises ``ProvisioningRefusedError`` when insufficient."""
    from secp_api.enums import VerificationLevel

    if (
        require_live
        and onboarding.approved_verification_level != VerificationLevel.live_verified.value
    ):
        raise ProvisioningRefusedError(
            "live real provisioning requires live_verified onboarding evidence; simulated "
            "evidence cannot satisfy live eligibility (SECP-002B-1B, ADR-014)"
        )


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


def _default_provider_execution_resolver():
    """The SHIPPED provider-execution resolver: purpose-bound, sealed until a backend is composed.

    Mirrors `proxmox_discovery_runtime`'s discovery factory rather than inventing a second shape.
    `client=None` is the shipped state and fails CLOSED — a deployment with no trusted secret
    backend refuses before target contact instead of falling back to anything.

    The purpose is fixed HERE, at construction, not taken from a caller. A resolver whose purpose an
    argument could choose would let a discovery operation request an apply credential by naming one.
    """
    from secp_worker.preflight.proxmox_secret_resolver import ProxmoxOperationSecretResolver
    from secp_worker.preflight.secret_resolution import ResolutionPurpose

    return ProxmoxOperationSecretResolver(
        purpose=ResolutionPurpose.proxmox_provider_execution, client=None
    )


def _resolve_lab_secret_env(  # noqa: PLR0913 - one parameter per authority/identity input
    session,
    operation: ProvisioningOperation,
    target: ExecutionTarget,
    kind: ProvisioningOperationKind,
    secret_resolver,
    authority=None,
) -> dict[str, str]:
    """Worker-only, just-in-time resolution of the MUTATION credential. Purpose-bound throughout.

    AUTHORITY FIRST, THEN THE CREDENTIAL
    -------------------------------------
    ``authority`` is the ``AuthorizedExecution`` already derived from durable rows. It is required
    here and the ordering is the point: possession of a credential is not permission to use it, so
    the credential is resolved only for an operation that has ALREADY been authorized, and the
    request is bound to that exact operation. Resolving first and authorizing after would mean a
    live secret existed in the process for an execution that was never permitted.

    NO FALLBACK, IN ANY DIRECTION
    ------------------------------
    The reference comes from ``ExecutionTarget.provider_execution_secret_ref`` alone. The generic
    ``secret_ref`` — which the legacy discovery and live-readonly paths resolve — cannot satisfy it,
    and neither can the plan-read or state-backend references. A missing dedicated reference
    REFUSES; it does not degrade to whichever reference happens to be present, which is exactly how
    a read-only credential would become the apply credential.

    What replaced what: this used to resolve ``target.secret_ref`` through a duck-typed
    ``resolve(str)`` protocol with no purpose at all. Any object with a ``.resolve`` method
    satisfied it.
    """
    if kind not in (ProvisioningOperationKind.apply, ProvisioningOperationKind.destroy):
        # A dry run plans with placeholder input variables and needs no credential at all.
        return {}

    from secp_api.credential_binding import (
        RealPlanCredentialError,
        require_provider_execution_credential_reference,
    )

    from secp_worker.plan_gen.secret_env import build_provider_plan_env
    from secp_worker.preflight.secret_resolution import (
        ResolutionContractViolation,
        SecretResolutionUnavailable,
        TrustedCredentialReference,
        build_provider_execution_resolution_request,
    )

    if authority is None:
        # No durable authority means no real execution is about to happen — the development and
        # simulator path runs NOTHING. So no credential is resolved at all, which is stronger than
        # resolving a fake one: there is no live material in the process for an execution that was
        # never authorized. The old path resolved `target.secret_ref` here regardless.
        return {}
    try:
        reference = require_provider_execution_credential_reference(target)
    except RealPlanCredentialError:
        _refuse_real(
            session,
            operation,
            "target has no dedicated provider-execution credential reference; the generic and "
            "read-only references can never satisfy a mutation",
        )

    request, expectation = build_provider_execution_resolution_request(
        organization_id=operation.organization_id,
        execution_target_id=target.id,
        worker_installation_id=authority.worker_installation_id,
        operation_identity=str(authority.operation_id),
        operation_generation=int(operation.attempts or 1),
        credential_reference=TrustedCredentialReference(reference),
    )
    resolver = (
        secret_resolver if secret_resolver is not None else (_default_provider_execution_resolver())
    )
    try:
        from datetime import UTC, datetime

        material = resolver.resolve(request, expectation=expectation, now=datetime.now(UTC))
    except (ResolutionContractViolation, SecretResolutionUnavailable) as exc:
        # Bounded reason codes only — never the reference, the backend response or the raw error.
        _refuse_real(session, operation, f"provider-execution credential unavailable: {exc}")
    except ProvisioningRefusedError:
        raise
    except Exception:
        _refuse_real(
            session, operation, "provider-execution credential resolution failed (redacted)"
        )

    # The canonical projection: SecretMaterial only, allowlisted variable name, control-character
    # and size checks. Reused rather than re-hand-writing `TF_VAR_pm_api_token`, which is how the
    # old path bypassed every one of those checks.
    env = build_provider_plan_env(material)
    endpoint = str((target.config or {}).get("base_url", ""))
    if endpoint:
        env["TF_VAR_pm_endpoint"] = endpoint  # non-secret
    return env


def _render_once(session, operation: ProvisioningOperation, manifest, profile):
    """Render the workspace the authority will name and the executor will apply. No process runs.

    Rendering is pure — it builds strings from the manifest and the profile — so it is safe to do
    before any authorization exists. What it produces is the ``content_hash`` that ties the approved
    change set, the authority and the applied plan to one artifact.
    """
    from secp_worker.provisioning.rendering import RenderingError, WorkspaceRenderer

    try:
        return WorkspaceRenderer().render(manifest.content, profile.content)
    except RenderingError:
        _refuse_real(session, operation, "workspace rendering refused (redacted)")


def _authorized_executor(
    session,
    operation: ProvisioningOperation,
    *,
    worker_installation_id: str,
    toolchain_layout,
    rendered_workspace_hash: str,
):
    """Derive the durable execution authority and build the real executor, or refuse.

    The two failure modes are kept distinct all the way to the operator-visible refusal. A
    measurement failure says nobody could read this worker's toolchain; an authority refusal says
    it was read and is not the authorized one. Collapsing them would send an operator to re-pin a
    profile when the real problem is an unreadable mirror.
    """
    from secp_api.provisioning_execution_authority import ExecutionAuthorityRefused

    from secp_worker.provisioning.activation import authorized_executor_for_operation
    from secp_worker.provisioning.toolchain_verify import ToolchainMeasurementError

    try:
        return authorized_executor_for_operation(
            session,
            operation_id=operation.id,
            organization_id=operation.organization_id,
            worker_installation_id=worker_installation_id,
            toolchain_layout=toolchain_layout,
            rendered_workspace_hash=rendered_workspace_hash,
        )
    except ToolchainMeasurementError as exc:
        _refuse_real(
            session,
            operation,
            f"this worker's toolchain could not be measured ({exc.reason}); real execution "
            "requires a readable, attested toolchain on this worker",
        )
    except ExecutionAuthorityRefused as exc:
        _refuse_real(
            session,
            operation,
            f"the control plane did not authorize this execution ({exc.reason})",
        )


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
    worker_installation_id: str | None = None,
    toolchain_layout=None,
) -> ProvisioningOperation:
    """Execute a REAL isolated-lab OpenTofu operation behind the full activation gate.

    TWO PATHS, PRODUCED DIFFERENTLY ON PURPOSE
    -------------------------------------------
    * **Development / simulator.** No ``worker_installation_id`` and no ``toolchain_layout``:
      ``build_process_executor`` returns a ``FakeProcessExecutor`` that runs nothing. This path
      needs no live worker, no enrolment and no on-disk toolchain, and that is fine because it
      cannot reach a process.
    * **Production.** Both supplied: the workspace is rendered ONCE, this worker's real toolchain is
      measured, ``authorize_provisioning_execution`` is asked whether THIS operation may execute
      against durable rows, and the real ``SubprocessProcessExecutor`` is constructed from the
      answer.

    The two are separate branches taking separate inputs rather than one branch with a mode,
    specifically so that "the simulator runs without a selected worker" can never come to imply
    "real execution runs without a selected worker". An operation whose
    ``worker_installation_id`` is NULL refuses on the production path — inside the authority, at
    ``execution_worker_selection_not_durable``, with no code here able to skip it.

    The authority is derived HERE, at the moment of execution, from durable state. It is not passed
    in as a claim, not serialized into Temporal, and not cached as still-valid: a caller can supply
    only identifiers and what its own filesystem measures.
    """
    from secp_worker.provisioning.activation import build_process_executor
    from secp_worker.provisioning.opentofu import OpenTofuRunner
    from secp_worker.provisioning.toolchain_verify import FakeToolchainVerifier

    settings = settings or get_settings()
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise ProvisioningRefusedError(f"manifest {manifest_id} not found")

    operation = prov_service.get_or_create_operation(session, manifest, kind)

    # Terminal idempotent replay FIRST — before ANY privileged setup. A retry of an
    # already-applied apply (or already-destroyed destroy) returns the durable operation
    # unchanged: no gate evaluation, no attempt-count mutation, no secret resolution, no
    # executor/runner construction, no toolchain verification, no rendering, no process
    # calls, and no approval lookup/consumption. The completed historical result is left
    # intact (the no-op is derivable at the API/view level from the terminal status).
    if kind == ProvisioningOperationKind.apply and operation.status == ProvisioningStatus.applied:
        return operation
    if (
        kind == ProvisioningOperationKind.destroy
        and operation.status == ProvisioningStatus.destroyed
    ):
        return operation

    plan, target, profile = _assert_real_gate(session, operation, manifest, settings, dispatch_mode)

    op_ref = manifest_idempotency_key(manifest.content_hash, kind)
    operation.operation_ref = op_ref
    operation.attempts = (operation.attempts or 0) + 1
    operation.runner = "opentofu"

    # The workspace is rendered ONCE, here, and the same object is both authorized and applied.
    # Deriving the authority from a re-render would authorize a hash computed from a different
    # render; rendering is deterministic so the two would normally agree, and "normally agree" is
    # exactly the gap — the authorized artifact and the executed artifact must be one object.
    rendered_workspace = None
    if executor is not None:
        process_executor = executor
    elif worker_installation_id is not None and toolchain_layout is not None:
        rendered_workspace = _render_once(session, operation, manifest, profile)
        process_executor = _authorized_executor(
            session,
            operation,
            worker_installation_id=worker_installation_id,
            toolchain_layout=toolchain_layout,
            rendered_workspace_hash=rendered_workspace.content_hash,
        )
    else:
        # Development / simulator: runs nothing, needs no worker, cannot reach a process.
        process_executor = build_process_executor(settings)

    # A real (non-fake) executor requires live_verified onboarding evidence. This used to sit behind
    # a `b1a_fake_only` refusal that made every real executor unreachable, so the branch was marked
    # `pragma: no cover - unreachable`. The refusal is gone with the seal it belonged to, and the
    # evidence requirement it was standing in front of is now the operative check (ADR-014 §2).
    # A simulated-evidence target therefore cannot reach real execution.
    if not getattr(process_executor, "b1a_fake_only", False):
        from secp_api.services.onboarding import active_onboarding_for_target

        assert_evidence_sufficient_for_execution(
            active_onboarding_for_target(session, target.id), require_live=True
        )

    # Taken FROM the executor, not threaded alongside it: this guarantees the credential is bound
    # to the same authority that produced the thing about to run. A separately-passed authority
    # could, after a refactor, describe a different operation than the executor was built for.
    secret_env = _resolve_lab_secret_env(
        session,
        operation,
        target,
        kind,
        secret_resolver,
        getattr(process_executor, "authority", None),
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
                session,
                operation,
                manifest,
                profile,
                runner,
                op_ref,
                destroy=False,
                workspace=rendered_workspace,
            )
        if kind == ProvisioningOperationKind.destroy_dry_run:
            return _real_dry_run(
                session,
                operation,
                manifest,
                profile,
                runner,
                op_ref,
                destroy=True,
                workspace=rendered_workspace,
            )
        if kind == ProvisioningOperationKind.apply:
            return _real_apply(
                session, operation, manifest, profile, runner, op_ref, workspace=rendered_workspace
            )
        if kind == ProvisioningOperationKind.destroy:
            return _real_destroy(
                session, operation, manifest, profile, runner, op_ref, workspace=rendered_workspace
            )
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


def _real_dry_run(
    session, operation, manifest, profile, runner, op_ref, *, destroy, workspace=None
):
    # Exact-artifact prepare; the ephemeral workspace + plan are always cleaned up.
    prepared = runner.prepare(
        manifest.content, operation_id=op_ref, destroy=destroy, workspace=workspace
    )
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


def _real_apply(session, operation, manifest, profile, runner, op_ref, *, workspace=None):
    # Terminal idempotency is handled up-front in run_real_provisioning (before any
    # privileged setup); here the operation is guaranteed non-terminal.
    # Prepare exactly one plan; the SAME prepared plan file is applied (no re-plan).
    prepared = runner.prepare(
        manifest.content, operation_id=op_ref, destroy=False, workspace=workspace
    )
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


def _real_destroy(session, operation, manifest, profile, runner, op_ref, *, workspace=None):
    # Terminal idempotency is handled up-front in run_real_provisioning; here the
    # operation is guaranteed non-terminal.
    prepared = runner.prepare(
        manifest.content, operation_id=op_ref, destroy=True, workspace=workspace
    )
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
