"""Worker-owned real-plan-generation orchestration (B1B-PR5B, ADR-022 §5/§6/§8/§9).

The complete ordering (the dedicated plan-only code seal is now ``False``, but the SHIPPED default
composition is disabled, so the ordinary shipped path still STOPS at the composition gate):

    fresh authoritative load
    → combined PlanGenerationReadinessStatus (pure)
    → replay short-circuit (a prior successful result returns without any execution)
    → PLAN-EXECUTION COMPOSITION verification
        · the SHIPPED default composition is DISABLED → refuse ``composition_refusal`` here,
          BEFORE any
          filesystem access, secret-manager contact, rendering, executor construction, or process —
          this is the only shipped production behavior; it STOPS.
    → [reached only with a separately reviewed, activated composition]
        execution-lease CAS acquire → begin_attempt (running; budget++ BEFORE any secret contact)
        → fresh execution-time toolchain re-attestation
        → JIT provider + state secret resolution (two SEPARATE credentials)
        → typed runtime inputs + the EXACT explicit child environment
        → secret-free controlled-live render
        → plan-only capability preparation (bound to the exact implementation digests)
        → execute init/plan/show via the composition's executor factory
            · a controlled-live composition uses the production issuer, which — now the code seal is
              ``False`` — constructs a real executor for its exact controlled-live context;
            · a test-only composition uses its injected (test-only) factory to prove the mechanism
              against the inert fixture — it never produces a controlled-live durable result.
        → durable result + pending exact-hash approval (controlled-live only; exactly-once)
        → cleanup (the workspace + transient plan are always removed)
    → bounded, secret-free audit → STOP

Every refusal records a bounded, secret-free attempt + audit. No argv, cwd, path, endpoint, secret,
reference, environment value, or process output ever enters the database, audit, or a return value.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api import audit
from secp_api.enums import (
    AuditAction,
    PlanExecutionReason,
    PlanGenerationAttemptStatus,
    ReadinessReason,
)
from secp_api.models import ProvisioningManifest
from secp_api.plan_activation_contract import (
    PLAN_GENERATION_READINESS_POLICY_VERSION,
    PLAN_SECRET_ENV_CONTRACT_VERSION,
    plan_generation_readiness_status,
)
from secp_api.plan_activation_models import RealPlanGenerationAttempt
from secp_api.readiness_contract import PLAN_SECRET_READINESS_TTL
from sqlalchemy import select
from sqlalchemy.orm import Session

_R = ReadinessReason
_PE = PlanExecutionReason


@dataclass(frozen=True)
class PlanGenerationResult:
    """The closed, secret-free outcome of one plan-generation attempt."""

    outcome: str  # PlanGenerationAttemptStatus value
    reason_code: str
    attempt_id: uuid.UUID | None = None
    result_id: uuid.UUID | None = None


def run_plan_generation(
    session: Session,
    *,
    manifest_id: uuid.UUID,
    now: datetime | None = None,
    composition=None,  # noqa: ANN001 - PlanExecutionComposition (defaults to the sealed shipped one)
    lease_owner: str = "worker",
) -> PlanGenerationResult:
    """Run the full plan-only ordering; refuse at the sealed composition gate in production."""
    now = now or datetime.now(UTC)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        return _refuse(session, None, _R.gate_incomplete.value, now)

    audit.record(
        session,
        action=AuditAction.plan_generation_started,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=manifest.organization_id,
        actor="worker",
        data={
            "operation_kind": "real_plan_generation",
            "provisioning_manifest_id": str(manifest.id),
            "readiness_policy_version": PLAN_GENERATION_READINESS_POLICY_VERSION,
        },
    )

    # 1. COMBINED PLAN-READINESS — pure, read-only. Resolves no secret, builds no environment.
    status = plan_generation_readiness_status(session, manifest, now=now)
    if not status.ready:
        reason = status.reasons[0] if status.reasons else _R.gate_incomplete.value
        return _refuse(session, manifest, reason, now)

    # 2. REPLAY — a prior successful result for this exact operation returns WITHOUT execution.
    from secp_worker.plan_gen.lease import assemble_execution_binding, existing_successful_result

    binding, bind_reason = assemble_execution_binding(session, manifest, now=now)
    if binding is None:
        fallback = _R.combined_plan_readiness_incomplete.value
        return _refuse(session, manifest, bind_reason or fallback, now)
    replay = existing_successful_result(session, binding)
    if replay is not None:
        return PlanGenerationResult(
            outcome=PlanGenerationAttemptStatus.completed.value,
            reason_code="replay",
            result_id=replay.id,
        )

    # 3. THE PLAN-EXECUTION COMPOSITION. The shipped default is SEALED → refuse here, before any
    #    filesystem access, secret contact, rendering, executor construction, or process. This is
    #    the ONLY shipped production behavior; it STOPS.
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        build_plan_execution_composition,
        verify_plan_execution_composition,
    )

    comp = composition if composition is not None else build_plan_execution_composition()
    try:
        verify_plan_execution_composition(comp)
    except PlanExecutionCompositionError:
        # composition_sealed (or any incomplete binding) → a clean, expected refusal.
        return _refuse(session, manifest, _PE.plan_only_sealed.value, now, audit_composition=True)

    # 4. THE ACTIVATED PATH — reached only with a reviewed/activated composition (tests inject one).
    return _execute_activated(session, manifest, binding, comp, lease_owner=lease_owner, now=now)


def _execute_activated(  # noqa: C901, PLR0911, PLR0912, PLR0915 - the full ordered pipeline
    session: Session,
    manifest: ProvisioningManifest,
    binding,  # ExecutionBinding  # noqa: ANN001
    comp,  # PlanExecutionComposition  # noqa: ANN001
    *,
    lease_owner: str,
    now: datetime,
) -> PlanGenerationResult:
    from secp_api.models import ToolchainProfile

    from secp_worker.plan_gen.capability import PlanOnlyCapabilityRefused
    from secp_worker.plan_gen.change_policy import expected_plan_context
    from secp_worker.plan_gen.composition import (
        CONTROLLED_LIVE_CLASSIFICATION,
        TEST_ONLY_CLASSIFICATION,
    )
    from secp_worker.plan_gen.controlled_live import (
        ControlledLiveRenderError,
        render_controlled_live_workspace,
    )
    from secp_worker.plan_gen.destination_binding import DestinationBindingError
    from secp_worker.plan_gen.lease import acquire_execution_lease, begin_attempt, consume_lease
    from secp_worker.plan_gen.plan_runner import PlanOnlyOpenTofuRunner, PlanOnlyRunError
    from secp_worker.plan_gen.reattest import FreshAttestationError, fresh_execution_attestation
    from secp_worker.plan_gen.result import PlanResultRefused, record_plan_generation_result

    # 4a-pre. AUTHORITATIVE DESTINATION BINDING (ADR-022 §5/§6). Bind the provider endpoint to the
    #     approved ExecutionTarget and the OpenTofu HTTP state address to the immutable
    #     ToolchainProfile.state_backend.reference, proven EXACTLY equal to the composition-supplied
    #     values, BEFORE any lease acquire, secret resolution, workspace creation, or process. A
    #     mismatch (or a stale target config / drifted profile) refuses here — before any external
    # contact — so readiness (backend A) can never diverge from what OpenTofu would plan (backend
    #     B), and the provider endpoint can never differ from the approved Proxmox target.
    try:
        provider_input, state_input = _bind_destinations(session, binding, comp)
    except DestinationBindingError as exc:
        return _refuse(session, manifest, exc.reason_code, now)

    # 4a. CAS lease acquire (pre-attempt: a failure here inserts a bounded REFUSED attempt row).
    lease, lease_reason = acquire_execution_lease(
        session, binding, lease_owner=lease_owner, now=now
    )
    if lease is None:
        return _refuse(session, manifest, lease_reason or _PE.lease_unavailable.value, now)
    _audit(session, AuditAction.plan_execution_lease_acquired, binding, {"lease_id": str(lease.id)})

    # 4b. begin_attempt — records the SINGLE running attempt row + increments the shared budget
    #     BEFORE any secret contact. After this point every terminal outcome UPDATES this exact row.
    attempt = begin_attempt(session, lease, binding, now=now)

    # 4c. fresh execution-time re-attestation (filesystem only) → typed AttestedToolchain.
    toolchain = session.get(ToolchainProfile, binding.toolchain_profile_id)
    if toolchain is None:
        return _terminate_running(
            session, binding, lease, attempt, _PE.reattestation_failed.value, now
        )
    try:
        attested = fresh_execution_attestation(
            comp,
            profile_content=toolchain.content,
            durable_profile_hash=binding.toolchain_profile_hash,
            durable_policy_version=binding.toolchain_attestation_policy_version,
            durable_attestation_id=str(binding.toolchain_attestation_id),
        )
    except FreshAttestationError as exc:
        return _terminate_running(session, binding, lease, attempt, exc.reason_code, now)
    _audit(session, AuditAction.plan_execution_reattested, binding, {"attempt_id": str(attempt.id)})

    # 4d. secret-free controlled-live render (in-memory) + the exact expected-plan policy context.
    try:
        files = render_controlled_live_workspace(
            manifest.content, provider_version=comp.provider_version, state_backend_kind="http"
        )
        expected_ctx = expected_plan_context(manifest.content)
    except ControlledLiveRenderError as exc:
        return _terminate_running(session, binding, lease, attempt, exc.reason_code, now)
    _audit(session, AuditAction.plan_execution_workspace_rendered, binding, {})

    # 4e. prepare the plan-only capability (bound to the exact reviewed implementation digests).
    classification = (
        TEST_ONLY_CLASSIFICATION if comp.is_test_only else CONTROLLED_LIVE_CLASSIFICATION
    )
    try:
        capability = _issue_capability(
            comp, binding, toolchain, lease, attempt, attested.evidence_hash, classification, now
        )
    except PlanOnlyCapabilityRefused:
        return _terminate_running(
            session, binding, lease, attempt, _PE.capability_invalid.value, now
        )

    provenance = _full_provenance(binding, capability, lease, attempt)

    # 4f. execute: materialize workspace → resolve the TWO credentials (only AFTER materialize) →
    #     exact child env → init/plan/show → canonicalize → manifest-exact change policy. The
    #     provider + state runtime inputs are the AUTHORITATIVE, already-bound ones (§5/§6).
    def _resolve_env():  # noqa: ANN202 - the injected post-materialize resolve callback
        return _build_child_env(
            session,
            comp,
            binding,
            lease,
            attested,
            now,
            provider_input=provider_input,
            state_input=state_input,
        )

    runner = PlanOnlyOpenTofuRunner(executor_factory=comp.executor_factory)
    try:
        plan_result = runner.generate_plan(
            files=files,
            trusted_root=comp.trusted_workspace_root,
            resolve_child_env=_resolve_env,
            attested=attested,
            capability=capability,
            expected_lease_id=lease.id,
            expected_attempt_id=attempt.id,
            expected_attempt_number=lease.attempts_used,
            operation_fingerprint=binding.operation_fingerprint,
            env_contract_version=PLAN_SECRET_ENV_CONTRACT_VERSION,
            expected_plan_context=expected_ctx,
            provenance=provenance,
            timeout=comp.process_timeout_seconds,
            max_output_bytes=comp.max_output_bytes,
            now=now,
        )
    except PlanOnlyRunError as exc:
        if exc.reason_code == "recovery_required":
            return _terminate_running(
                session, binding, lease, attempt, _PE.recovery_required.value, now, recovery=True
            )
        return _terminate_running(session, binding, lease, attempt, exc.reason_code, now)
    _audit(
        session, AuditAction.plan_execution_plan_created, binding, {"attempt_id": str(attempt.id)}
    )

    # 4g. durable result. A controlled-live capability persists the result + pending approval +
    #     consumes the lease (exactly-once). A test-only run proves the mechanism only.
    if capability.is_controlled_live:
        try:
            result = record_plan_generation_result(
                session,
                binding=binding,
                capability=capability,
                plan_result=plan_result,
                lease=lease,
                attempt=attempt,
                manifest=manifest,
                toolchain_profile=toolchain,
                now=now,
            )
        except PlanResultRefused as exc:
            return _terminate_running(session, binding, lease, attempt, exc.reason_code, now)
        _audit(
            session, AuditAction.plan_execution_completed, binding, {"result_id": str(result.id)}
        )
        _audit(session, AuditAction.plan_execution_lease_released, binding, {"consumed": True})
        return PlanGenerationResult(
            outcome=PlanGenerationAttemptStatus.completed.value,
            reason_code="completed",
            attempt_id=attempt.id,
            result_id=result.id,
        )

    consume_lease(session, lease, attempt, result_id=None, now=now)
    _audit(session, AuditAction.plan_execution_completed, binding, {"classification": "test_only"})
    return PlanGenerationResult(
        outcome=PlanGenerationAttemptStatus.completed.value,
        reason_code="test_only_mechanism_proven",
        attempt_id=attempt.id,
    )


def _terminate_running(  # noqa: ANN001, PLR0913
    session, binding, lease, attempt, reason_code: str, now, *, recovery: bool = False
) -> PlanGenerationResult:
    """The SINGLE terminal transition for a running attempt — no second refused row is ever
    inserted.

    A generic execution-time failure becomes ``failed``; an uncertain-termination / cleanup-residue
    outcome becomes ``recovery_required`` (terminal, no auto-retry). The returned ``attempt_id`` is
    the
    actual running attempt's id.
    """
    from secp_worker.plan_gen.lease import fail_attempt, require_recovery

    if recovery:
        require_recovery(session, lease, attempt, reason_code=reason_code, now=now)
        action = AuditAction.plan_execution_recovery_required
        status = PlanGenerationAttemptStatus.recovery_required
    else:
        fail_attempt(session, lease, attempt, reason_code=reason_code, now=now)
        action = AuditAction.plan_execution_failed
        status = PlanGenerationAttemptStatus.failed
    _audit(
        session, action, binding, {"attempt_id": str(attempt.id), "reason_code": reason_code[:80]}
    )
    return PlanGenerationResult(
        outcome=status.value, reason_code=reason_code, attempt_id=attempt.id
    )


def _operational_paths(comp, attested):  # noqa: ANN001, ANN202
    """Worker-derived, nonsecret operation-local paths; the CLI config is the ATTESTED path."""
    import posixpath

    from secp_worker.plan_gen.runtime_inputs import OperationalPaths

    root = comp.trusted_workspace_root.replace("\\", "/").rstrip("/")
    return OperationalPaths(
        home=posixpath.join(root, "op_home"),
        tmpdir=posixpath.join(root, "op_tmp"),
        tf_data_dir=posixpath.join(root, "op_tfdata"),
        cli_config_file=attested.cli_config.path,
    )


def _bind_destinations(session, binding, comp):  # noqa: ANN001, ANN202
    """Bind the provider endpoint + HTTP state address to the AUTHORITATIVE records (else fail).

    Provider: require ``plugin_name == "proxmox"``, re-validate the immutable target config against
    its hash, derive the canonical endpoint from ``config["base_url"]``, and require exact equality
    with the composition endpoint. State: derive the authoritative binding from the immutable
    ``ToolchainProfile.state_backend.reference`` (its hash re-verified), and require the composition
    state address/lock/unlock to canonically equal it. Returns the AUTHORITATIVE
    ``(ProviderRuntimeInput, StateRuntimeInput)`` — never the composition copies. Raises
    :class:`~secp_worker.plan_gen.destination_binding.DestinationBindingError` (closed reason) with
    no endpoint/host/path echoed; performs no external contact.
    """
    from secp_api.models import ExecutionTarget, ToolchainProfile
    from secp_api.toolchain_profile import toolchain_profile_hash, validate_toolchain_profile

    from secp_worker.plan_gen.destination_binding import (
        DestinationBindingError,
        assert_provider_endpoint_bound,
        assert_readiness_backend_equals,
        assert_state_runtime_bound,
        derive_state_backend_binding,
    )

    target = session.get(ExecutionTarget, binding.execution_target_id)
    if target is None:
        raise DestinationBindingError("execution_target_missing")
    if target.config_hash != binding.target_config_hash:
        raise DestinationBindingError("target_config_hash_stale")
    provider_input = assert_provider_endpoint_bound(
        target=target, composition_endpoint=comp.provider_runtime_input_source.endpoint
    )

    toolchain = session.get(ToolchainProfile, binding.toolchain_profile_id)
    if toolchain is None:
        raise DestinationBindingError("toolchain_profile_missing")
    if toolchain_profile_hash(toolchain.content) != binding.toolchain_profile_hash:
        raise DestinationBindingError("toolchain_profile_hash_stale")
    spec = validate_toolchain_profile(toolchain.content)
    state_backend_binding = derive_state_backend_binding(
        reference=spec.state_backend.reference,
        backend_kind=spec.state_backend.kind,
        toolchain_profile_id=binding.toolchain_profile_id,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        state_namespace_identity=binding.state_namespace_hash,
    )
    state_input = assert_state_runtime_bound(
        binding=state_backend_binding, composition_state_source=comp.state_runtime_input_source
    )
    # Change 4: the readiness evidence's backend anchor is the SAME immutable profile hash →
    # readiness
    # was collected for exactly this backend (the profile hash was just re-verified above).
    assert_readiness_backend_equals(
        binding=state_backend_binding,
        readiness_toolchain_profile_hash=binding.toolchain_profile_hash,
    )
    return provider_input, state_input


def _build_child_env(  # noqa: ANN001, ANN202, PLR0913
    session, comp, binding, lease, attested, now, *, provider_input, state_input
):
    """Resolve the two SEPARATE credentials + build the EXACT child env (post-materialization).

    ``provider_input`` / ``state_input`` are the AUTHORITATIVE, already-bound runtime inputs (proven
    equal to the approved target / immutable ToolchainProfile before any lease/secret/process) — the
    composition copies are never used to build the child environment.
    """
    from secp_worker.plan_gen.plan_runner import PlanOnlyRunError
    from secp_worker.plan_gen.runtime_inputs import RuntimeInputError, build_child_environment

    try:
        provider_material, state_material = _resolve_two_credentials(
            session, comp, binding, lease, now
        )
        return build_child_environment(
            provider_material=provider_material,
            state_material=state_material,
            provider_input=provider_input,
            state_input=state_input,
            operational=_operational_paths(comp, attested),
        )
    except RuntimeInputError as exc:
        raise PlanOnlyRunError(exc.reason_code) from exc
    except Exception as exc:  # noqa: BLE001 - any resolver refusal maps to a bounded reason (no leak)
        raise PlanOnlyRunError(_PE.secret_resolution_failed.value) from exc


def _verify_binding_agreement(session, binding, purpose_binding_id, purpose_binding_version):  # noqa: ANN001, ANN202
    """target == manifest == dossier == execution binding (id + version) for one credential
    purpose."""
    from secp_api.models import ProvisioningManifest as _PM
    from secp_api.plan_activation_models import RealLabActivationDossier

    is_provider = purpose_binding_id == binding.provider_credential_binding_id
    manifest = session.get(_PM, binding.provisioning_manifest_id)
    dossier = session.get(RealLabActivationDossier, binding.activation_dossier_id)
    if manifest is None or dossier is None:
        raise _AgreementError
    if is_provider:
        m_id, m_ver = (
            manifest.provider_credential_binding_id,
            manifest.provider_credential_binding_version,
        )
        d_id, d_ver = (
            dossier.provider_credential_binding_id,
            dossier.provider_credential_binding_version,
        )
    else:
        m_id, m_ver = (
            manifest.state_credential_binding_id,
            manifest.state_credential_binding_version,
        )
        d_id, d_ver = dossier.state_credential_binding_id, dossier.state_credential_binding_version
    if not (m_id == d_id == purpose_binding_id):
        raise _AgreementError
    if not (m_ver == d_ver == purpose_binding_version):
        raise _AgreementError


class _AgreementError(Exception):
    """Credential binding disagreement across target/manifest/dossier/execution (bounded)."""


def _resolve_two_credentials(session, comp, binding, lease, now):  # noqa: ANN001, ANN202
    """Resolve the provider then the state credential — actual dedicated references, SEPARATE
    contracts (independent candidate + expectation objects), verified resolver activations."""
    from secp_api.models import ExecutionTarget
    from secp_api.readiness_contract import canonical_utc

    from secp_worker.plan_gen.plan_secret_resolution import (
        PLAN_EXECUTION_RESOLVER_CONTRACT_VERSION,
        PlanCredentialReference,
        PlanExecutionResolutionContract,
        PlanExecutionResolutionPurpose,
        build_trusted_plan_resolution_request,
        derive_reference_scheme,
        issue_plan_resolver_capability,
    )

    target = session.get(ExecutionTarget, binding.execution_target_id)
    if target is None:
        raise _AgreementError
    expiry = canonical_utc(binding.authorization_expiry)

    def _make_contract(purpose, binding_id, binding_version, actual_ref, scheme):  # noqa: ANN001, ANN202
        # NOTE: constructed fresh each call, so candidate and expectation are INDEPENDENT objects.
        return PlanExecutionResolutionContract(
            purpose=purpose,
            organization_id=binding.organization_id,
            execution_target_id=binding.execution_target_id,
            provisioning_manifest_id=binding.provisioning_manifest_id,
            provisioning_manifest_content_hash=binding.provisioning_manifest_content_hash,
            activation_dossier_id=binding.activation_dossier_id,
            activation_dossier_hash=binding.activation_dossier_hash,
            credential_binding_id=binding_id,
            credential_binding_version=binding_version,
            binding_source="dedicated_operation",
            worker_identity_registration_id=binding.worker_identity_registration_id,
            worker_identity_version=binding.worker_identity_version,
            resolver_contract_version=PLAN_EXECUTION_RESOLVER_CONTRACT_VERSION,
            operation_fingerprint=binding.operation_fingerprint,
            authorization_expiry=expiry,
            execution_lease_id=lease.id,
            attempt_number=lease.attempts_used,
            credential_reference=PlanCredentialReference(actual_ref, scheme=scheme),
        )

    def _resolve(purpose, resolver, activation, binding_id, binding_version, actual_ref):  # noqa: ANN001, ANN202, PLR0913
        # The ACTUAL dedicated reference (never the generic secret_ref); target==manifest==dossier.
        _verify_binding_agreement(session, binding, binding_id, binding_version)
        scheme = derive_reference_scheme(actual_ref)
        candidate = _make_contract(purpose, binding_id, binding_version, actual_ref, scheme)
        expectation = _make_contract(purpose, binding_id, binding_version, actual_ref, scheme)
        capability = issue_plan_resolver_capability(
            contract=expectation,
            activation=activation,
            worker_identity_registration_id=binding.worker_identity_registration_id,
            worker_identity_version=binding.worker_identity_version,
        )
        request = build_trusted_plan_resolution_request(candidate)
        return resolver.resolve(request, expectation=expectation, capability=capability, now=now)

    provider_material = _resolve(
        PlanExecutionResolutionPurpose.provider_plan_read,
        comp.provider_resolver,
        comp.provider_resolver_activation,
        binding.provider_credential_binding_id,
        binding.provider_credential_binding_version,
        target.provider_plan_secret_ref or "",
    )
    state_material = _resolve(
        PlanExecutionResolutionPurpose.state_backend_plan,
        comp.state_resolver,
        comp.state_resolver_activation,
        binding.state_credential_binding_id,
        binding.state_credential_binding_version,
        target.state_backend_secret_ref or "",
    )
    return provider_material, state_material


def _full_provenance(binding, capability, lease, attempt) -> dict:  # noqa: ANN001
    """The complete safe canonical provenance folded into the change set before hashing (§10)."""
    from secp_worker.plan_gen.change_policy import PLAN_CHANGE_POLICY_VERSION

    a = capability.activation
    return {
        "provenance_version": "secp-002b-1b-pr5b/result-provenance/v1",
        "organization_id": str(binding.organization_id),
        "provisioning_manifest_id": str(binding.provisioning_manifest_id),
        "provisioning_manifest_content_hash": binding.provisioning_manifest_content_hash,
        "environment_version_id": str(binding.environment_version_id),
        "environment_version_content_hash": binding.environment_version_content_hash,
        "deployment_plan_id": str(binding.deployment_plan_id),
        "deployment_plan_content_hash": binding.deployment_plan_content_hash,
        "execution_target_id": str(binding.execution_target_id),
        "target_config_hash": binding.target_config_hash,
        "target_onboarding_id": str(binding.target_onboarding_id),
        "onboarding_boundary_hash": binding.onboarding_boundary_hash,
        "activation_dossier_id": str(binding.activation_dossier_id),
        "activation_dossier_hash": binding.activation_dossier_hash,
        "activation_dossier_revision": binding.activation_dossier_revision,
        "plan_generation_authorization_id": str(binding.authorization_id),
        "authorization_version": binding.authorization_version,
        "eligibility_preflight_id": str(binding.eligibility_preflight_id),
        "eligibility_evidence_hash": binding.eligibility_evidence_hash,
        "toolchain_profile_id": str(binding.toolchain_profile_id),
        "toolchain_profile_hash": binding.toolchain_profile_hash,
        "toolchain_attestation_id": str(binding.toolchain_attestation_id),
        "toolchain_attestation_hash": binding.toolchain_attestation_hash,
        "fresh_attestation_evidence_hash": a.fresh_attestation_evidence_hash,
        "provider_source": a.provider_source,
        "provider_version": a.provider_version,
        "provider_lockfile_hash": a.provider_lockfile_hash,
        "provider_mirror_identity": a.provider_mirror_identity,
        "module_bundle_hash": a.module_bundle_hash,
        "renderer_version": a.renderer_version,
        "renderer_module_id": a.renderer_module_id,
        "process_implementation_id": a.process_implementation_id,
        "provider_credential_binding_id": str(binding.provider_credential_binding_id),
        "provider_credential_binding_version": binding.provider_credential_binding_version,
        "state_credential_binding_id": str(binding.state_credential_binding_id),
        "state_credential_binding_version": binding.state_credential_binding_version,
        "remote_state_readiness_id": str(binding.remote_state_readiness_id),
        "remote_state_evidence_hash": binding.remote_state_evidence_hash,
        "plan_secret_readiness_id": str(binding.plan_secret_readiness_id),
        "plan_secret_evidence_hash": binding.plan_secret_evidence_hash,
        "state_namespace_hash": binding.state_namespace_hash,
        "worker_identity_registration_id": str(binding.worker_identity_registration_id),
        "worker_identity_version": binding.worker_identity_version,
        "execution_lease_id": str(lease.id),
        "attempt_id": str(attempt.id),
        "attempt_number": lease.attempts_used,
        "plan_only_capability_contract_version": a.plan_only_capability_contract_version,
        "readiness_policy_version": PLAN_GENERATION_READINESS_POLICY_VERSION,
        "change_policy_version": PLAN_CHANGE_POLICY_VERSION,
        "operation_fingerprint": binding.operation_fingerprint,
    }


def _issue_capability(  # noqa: ANN001, ANN202, PLR0913
    comp, binding, toolchain, lease, attempt, fresh_hash, classification, now
):
    from datetime import timedelta

    from secp_api.plan_activation_contract import PLAN_ONLY_CAPABILITY_CONTRACT_VERSION
    from secp_api.toolchain_profile import validate_toolchain_profile

    from secp_worker.plan_gen.capability import PlanOnlyActivation, issue_plan_only_capability
    from secp_worker.plan_gen.controlled_live import (
        CONTROLLED_LIVE_RENDERER_VERSION,
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.process_boundary import (
        PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        plan_only_executor_implementation_digest,
    )

    spec = validate_toolchain_profile(toolchain.content)
    activation = PlanOnlyActivation(
        organization_id=binding.organization_id,
        plan_generation_authorization_id=binding.authorization_id,
        authorization_version=binding.authorization_version,
        authorization_expiry=binding.authorization_expiry,
        operation_fingerprint=binding.operation_fingerprint,
        plan_only_capability_contract_version=PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
        classification=classification,
        expires_at=now + timedelta(minutes=10),
        environment_version_id=binding.environment_version_id,
        environment_version_content_hash=binding.environment_version_content_hash,
        deployment_plan_id=binding.deployment_plan_id,
        deployment_plan_content_hash=binding.deployment_plan_content_hash,
        provisioning_manifest_id=binding.provisioning_manifest_id,
        provisioning_manifest_content_hash=binding.provisioning_manifest_content_hash,
        execution_target_id=binding.execution_target_id,
        target_config_hash=binding.target_config_hash,
        target_onboarding_id=binding.target_onboarding_id,
        onboarding_boundary_hash=binding.onboarding_boundary_hash,
        eligibility_preflight_id=binding.eligibility_preflight_id,
        eligibility_evidence_hash=binding.eligibility_evidence_hash,
        toolchain_profile_id=binding.toolchain_profile_id,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        toolchain_attestation_id=binding.toolchain_attestation_id,
        toolchain_attestation_hash=binding.toolchain_attestation_hash,
        fresh_attestation_evidence_hash=fresh_hash,
        provider_source=comp.provider_source,
        provider_version=comp.provider_version,
        provider_lockfile_hash=spec.provider_lockfile_hash,
        provider_mirror_identity=spec.provider_mirror.identity,
        module_bundle_hash=spec.module_bundle_hash,
        renderer_version=CONTROLLED_LIVE_RENDERER_VERSION,
        activation_dossier_id=binding.activation_dossier_id,
        activation_dossier_hash=binding.activation_dossier_hash,
        activation_dossier_revision=binding.activation_dossier_revision,
        activation_dossier_expiry=binding.activation_dossier_expiry,
        provider_credential_binding_id=binding.provider_credential_binding_id,
        provider_credential_binding_version=binding.provider_credential_binding_version,
        state_credential_binding_id=binding.state_credential_binding_id,
        state_credential_binding_version=binding.state_credential_binding_version,
        remote_state_readiness_id=binding.remote_state_readiness_id,
        remote_state_evidence_hash=binding.remote_state_evidence_hash,
        plan_secret_readiness_id=binding.plan_secret_readiness_id,
        plan_secret_evidence_hash=binding.plan_secret_evidence_hash,
        worker_identity_registration_id=binding.worker_identity_registration_id,
        worker_identity_version=binding.worker_identity_version,
        execution_lease_id=lease.id,
        attempt_id=attempt.id,
        attempt_number=lease.attempts_used,
        process_implementation_id=PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        process_implementation_digest=plan_only_executor_implementation_digest(),
        renderer_module_id=CONTROLLED_LIVE_RENDERER_VERSION,
        renderer_module_digest=controlled_live_renderer_implementation_digest(),
    )
    return issue_plan_only_capability(
        activation,
        now=now,
        expected_process_digest=plan_only_executor_implementation_digest(),
        expected_renderer_digest=controlled_live_renderer_implementation_digest(),
    )


def _refuse(
    session: Session,
    manifest: ProvisioningManifest | None,
    reason_code: str,
    now: datetime,
    *,
    audit_composition: bool = False,
) -> PlanGenerationResult:
    """Record a bounded, secret-free refused attempt + audit, then STOP."""
    attempt_id: uuid.UUID | None = None
    if manifest is not None:
        fingerprint, authorization = _attempt_fingerprint(session, manifest, now)
        existing = (
            session.execute(
                select(RealPlanGenerationAttempt).where(
                    RealPlanGenerationAttempt.provisioning_manifest_id == manifest.id,
                    RealPlanGenerationAttempt.operation_fingerprint == fingerprint,
                    RealPlanGenerationAttempt.status == PlanGenerationAttemptStatus.refused,
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            attempt_id = existing.id
        else:
            row = RealPlanGenerationAttempt(
                id=uuid.uuid4(),
                organization_id=manifest.organization_id,
                authorization_id=authorization.id if authorization is not None else None,
                authorization_version=(
                    authorization.authorization_version if authorization is not None else None
                ),
                execution_target_id=manifest.execution_target_id,
                deployment_plan_id=manifest.deployment_plan_id,
                provisioning_manifest_id=manifest.id,
                target_onboarding_id=manifest.target_onboarding_id,
                activation_dossier_id=None,
                operation_fingerprint=fingerprint,
                status=PlanGenerationAttemptStatus.refused,
                refusal_reason_code=reason_code[:80],
                collected_at=now,
                expires_at=now + PLAN_SECRET_READINESS_TTL,
            )
            session.add(row)
            session.flush()
            attempt_id = row.id
        audit.record(
            session,
            action=AuditAction.plan_generation_refused,
            resource_type="provisioning_manifest",
            resource_id=manifest.id,
            organization_id=manifest.organization_id,
            actor="worker",
            outcome="refused",
            data={
                "operation_kind": "real_plan_generation",
                "provisioning_manifest_id": str(manifest.id),
                "reason_code": reason_code[:80],
                "readiness_policy_version": PLAN_GENERATION_READINESS_POLICY_VERSION,
            },
        )
    return PlanGenerationResult(
        outcome=PlanGenerationAttemptStatus.refused.value,
        reason_code=reason_code,
        attempt_id=attempt_id,
    )


def _audit(session: Session, action, binding, data: dict) -> None:  # noqa: ANN001
    """A bounded, secret-free plan-execution audit event (ids/hashes/reasons/counts only)."""
    payload = {"operation_fingerprint": binding.operation_fingerprint}
    payload.update(data)
    audit.record(
        session,
        action=action,
        resource_type="plan_generation_execution_lease",
        resource_id=binding.provisioning_manifest_id,
        organization_id=binding.organization_id,
        actor="worker",
        data=payload,
    )


def _attempt_fingerprint(session: Session, manifest: ProvisioningManifest, now: datetime):
    """A stable operation fingerprint for the refused attempt (the authorization's, if any)."""
    from secp_api.services.plan_activation import active_plan_generation_authorization

    authorization = active_plan_generation_authorization(session, manifest.id)
    if authorization is not None:
        return authorization.operation_fingerprint, authorization
    import hashlib

    digest = hashlib.sha256(
        f"secp-002b-1b-pr5a/plan-generation-attempt/v1|{manifest.id}|{manifest.content_hash}".encode()
    ).hexdigest()
    return "sha256:" + digest, None
