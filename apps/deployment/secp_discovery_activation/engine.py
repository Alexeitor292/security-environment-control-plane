"""Machine-readable, fail-closed production B8 activation operations.

``plan`` and ``render`` are pure.  ``inspect``/``verify``/``status``/``evidence`` observe only.
``install`` and ``rollback`` require an explicit two-part write gate and execute through one closed
adapter.  Once a mutation is attempted, a missing/malformed receipt is recovery-required; every
failure after worker recreation restores the prior Compose/container state while preserving any
newly generated durable worker keys.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_commissioning.canonical import sha256_digest

from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    DiscoveryActivationError,
)
from secp_discovery_activation.adapters import (
    ActivationAdapter,
    CompensationResult,
    ContainerRuntimeObservation,
    FixedInputBinding,
    HostObservation,
    MutationReceipt,
)
from secp_discovery_activation.evidence import (
    CLASSIFICATION_ADOPTED,
    CLASSIFICATION_CREATED,
    ROLE_ADMISSION_CA,
    ROLE_ADMISSION_PROXY_GATE,
    ROLE_ADMISSION_SERVER_CERTIFICATE,
    ROLE_ADMISSION_SERVER_KEY,
    ROLE_CONTROLLER_OVERRIDE,
    ROLE_PROFILE,
    ROLE_PROXY_CONTRACT,
    ROLE_WORKER_OVERRIDE,
    ROLE_WORKER_RUNTIME_OVERLAY,
    ROLE_WORKER_STATE,
    ActivationEvidence,
    AdmissionTLSEvidence,
    ContainerRuntimeEvidence,
    EvidenceAttestation,
    EvidenceAuthenticator,
    EvidenceTrustRoot,
    FixedInputEvidence,
    ManagedObjectRecord,
    PersistentStateEvidence,
    WorkerPublicEvidence,
    attestation_bytes,
    evidence_bytes,
    issue_attestation,
    parse_attestation_bytes,
    parse_evidence_bytes,
    path_binding_digest,
    verify_evidence,
)
from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE, PRODUCTION_LAYOUT
from secp_discovery_activation.profile import DeploymentProfile
from secp_discovery_activation.render import ActivationRender, render_activation
from secp_discovery_activation.state import PreparedStateReceipt, WorkerStateBackend
from secp_discovery_activation.status import RECOVERY_REQUIRED, derive_status
from secp_discovery_activation.tls import ValidatedTLSMaterial

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_OBJECT_ROLES = frozenset(
    {
        ROLE_PROFILE,
        ROLE_WORKER_OVERRIDE,
        ROLE_WORKER_RUNTIME_OVERLAY,
        ROLE_CONTROLLER_OVERRIDE,
        ROLE_PROXY_CONTRACT,
        ROLE_ADMISSION_CA,
        ROLE_ADMISSION_PROXY_GATE,
        ROLE_ADMISSION_SERVER_CERTIFICATE,
        ROLE_ADMISSION_SERVER_KEY,
        ROLE_WORKER_STATE,
    }
)


class ActivationEngineError(DiscoveryActivationError):
    """The activation engine refused with a bounded reason code."""


@dataclass(frozen=True)
class WriteGate:
    write: bool = False
    confirm: bool = False

    def refusal_reason(self) -> str | None:
        if not self.write:
            return "write_authority_required"
        if not self.confirm:
            return "explicit_confirmation_required"
        return None


@dataclass(frozen=True)
class ActivationPlan:
    contract_version: str
    implementation_id: str
    activation_enabled: bool
    worker_image_digest: str
    render_manifest_digest: str
    artifact_digests: tuple[tuple[str, str], ...]
    operations: tuple[str, ...]
    verification_gates: tuple[str, ...]
    rollback_operations: tuple[str, ...]
    external_contacts_during_plan: bool = False
    host_mutations_during_plan: bool = False

    def canonical(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "implementation_id": self.implementation_id,
            "activation_enabled": self.activation_enabled,
            "worker_image_digest": self.worker_image_digest,
            "render_manifest_digest": self.render_manifest_digest,
            "artifact_digests": dict(self.artifact_digests),
            "operations": list(self.operations),
            "verification_gates": list(self.verification_gates),
            "rollback_operations": list(self.rollback_operations),
            "external_contacts_during_plan": self.external_contacts_during_plan,
            "host_mutations_during_plan": self.host_mutations_during_plan,
            "plan_digest": self.digest(),
        }

    def digest(self) -> str:
        payload = {
            "contract_version": self.contract_version,
            "implementation_id": self.implementation_id,
            "activation_enabled": self.activation_enabled,
            "worker_image_digest": self.worker_image_digest,
            "render_manifest_digest": self.render_manifest_digest,
            "artifact_digests": list(self.artifact_digests),
            "operations": list(self.operations),
            "verification_gates": list(self.verification_gates),
            "rollback_operations": list(self.rollback_operations),
            "external_contacts_during_plan": self.external_contacts_during_plan,
            "host_mutations_during_plan": self.host_mutations_during_plan,
        }
        return sha256_digest(payload)


@dataclass(frozen=True)
class OperationResult:
    operation: str
    outcome: str
    reason_code: str | None
    recovery_required: bool
    details: dict[str, object]

    def canonical(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "recovery_required": self.recovery_required,
            "details": self.details,
        }


@dataclass(frozen=True)
class EngineDependencies:
    adapter: ActivationAdapter
    state: WorkerStateBackend
    evidence_authenticator: EvidenceAuthenticator
    evidence_trust_root: EvidenceTrustRoot
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


def _result(
    operation: str,
    outcome: str,
    *,
    reason: str | None = None,
    recovery: bool = False,
    details: dict[str, object] | None = None,
) -> OperationResult:
    return OperationResult(operation, outcome, reason, recovery, details or {})


def build_plan(
    profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
) -> tuple[ActivationPlan, ActivationRender]:
    """Pure deterministic plan; it reads no host state and opens no connection."""

    if type(profile) is not DeploymentProfile:
        raise ActivationEngineError("profile_type_invalid")
    if type(tls_material) is not ValidatedTLSMaterial:
        raise ActivationEngineError("tls_material_type_invalid")
    rendered = render_activation(profile, tls_material.metadata)
    plan = ActivationPlan(
        contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        activation_enabled=profile.activation_enabled,
        worker_image_digest=profile.ordinary_worker_image_digest,
        render_manifest_digest=rendered.manifest.sha256,
        artifact_digests=tuple((entry.name, entry.sha256) for entry in rendered.manifest.artifacts),
        operations=(
            "validate-fixed-worker-state",
            "capture-coherent-worker-generation",
            "persist-content-bound-rollback-journal",
            "install-controller-tls-and-admission-proxy",
            "verify-pinned-internal-tls",
            "install-worker-ca-and-compose-override",
            "recreate-ordinary-worker-only",
            "verify-worker-and-public-node",
            "commit-detached-signed-evidence-last",
        ),
        verification_gates=(
            "exact-worker-image",
            "healthy-new-generation",
            "ordinary-queue-only",
            "worker-only-state-mount",
            "strict-pinned-tls",
            "bundle-prep-loop-started",
            "safe-persistent-keys",
            "public-only-worker-node",
            "operator-absent",
            "safety-seals-exact",
        ),
        rollback_operations=(
            "restore-prior-worker-config-content-and-metadata",
            "restore-prior-ordinary-worker-generation",
            "restore-prior-controller-config-content-and-metadata",
            "retain-generated-worker-keys",
            "remove-only-authenticated-transaction-created-empty-objects",
        ),
    )
    return plan, rendered


def plan_operation(
    profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
) -> OperationResult:
    try:
        plan, _rendered = build_plan(profile, tls_material)
        return _result("plan", "planned", details=plan.canonical())
    except DiscoveryActivationError as exc:
        return _result("plan", "refused", reason=exc.reason_code)


def render_operation(
    profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
) -> OperationResult:
    """Return reviewable nonsecret artifacts; TLS/key bytes are never rendered to output."""

    try:
        _plan, rendered = build_plan(profile, tls_material)
        return _result(
            "render",
            "rendered",
            details={
                "manifest": rendered.manifest.canonical(),
                "manifest_digest": rendered.manifest.sha256,
                "artifacts": [
                    {
                        "name": artifact.name,
                        "path": artifact.path,
                        "mode": artifact.mode,
                        "uid": artifact.uid,
                        "gid": artifact.gid,
                        "sha256": artifact.sha256,
                        "content": artifact.text(),
                    }
                    for artifact in rendered.artifacts
                ],
            },
        )
    except DiscoveryActivationError as exc:
        return _result("render", "refused", reason=exc.reason_code)


def inspect_operation(profile: DeploymentProfile, deps: EngineDependencies) -> OperationResult:
    try:
        observation = deps.adapter.observe(profile)
        if type(observation) is not HostObservation:
            raise ActivationEngineError("host_observation_type_invalid")
        return _result("inspect", "inspected", details=_safe_observation(observation))
    except DiscoveryActivationError as exc:
        return _result("inspect", "refused", reason=exc.reason_code)
    except Exception:
        return _result("inspect", "refused", reason="host_observation_failed")


def _safe_observation(observation: HostObservation) -> dict[str, object]:
    generation = observation.worker_generation
    public = observation.worker_public
    base = observation.base_compose_binding
    runtime = observation.worker_runtime
    runtime_generation = runtime.generation if runtime is not None else None
    return {
        "inspected": observation.inspected,
        "coherent": observation.coherent,
        "worker_present": observation.worker_present,
        "worker_generation": (
            {
                "container_id": generation.container_id,
                "restart_count": generation.restart_count,
                "started_at": generation.started_at,
                "generation_digest": generation.digest(),
            }
            if generation
            else None
        ),
        "worker_image_digest": observation.worker_image_digest,
        "base_compose_binding": (
            {
                "content_digest": base.content_digest,
                "owner_uid": base.owner_uid,
                "owner_gid": base.owner_gid,
                "mode": base.mode,
            }
            if base is not None
            else None
        ),
        "worker_runtime": (
            {
                "present": runtime.present,
                "generation_digest": (
                    runtime_generation.digest() if runtime_generation is not None else None
                ),
                "image_digest": runtime.image_digest,
                "configuration_digest": runtime.configuration_digest,
                "mounts_digest": runtime.mounts_digest,
                "networks_digest": runtime.networks_digest,
                "compose_project": runtime.compose_project,
                "compose_service": runtime.compose_service,
                "expected_image": runtime.expected_image,
                "hardening_verified": runtime.hardening_verified,
                "mounts_verified": runtime.mounts_verified,
                "endpoint_binding_verified": runtime.endpoint_binding_verified,
            }
            if runtime is not None
            else None
        ),
        "worker_running": observation.worker_running,
        "worker_healthy": observation.worker_healthy,
        "ordinary_queue_exact": observation.ordinary_queues == (ORDINARY_TASK_QUEUE,),
        "b8_flags_enabled": (
            observation.controlled_integration_enabled and observation.worker_managed_bundle_enabled
        ),
        "state_mount_isolated": (
            observation.state_mount_read_write_only_worker
            and observation.discovery_mount_absent_from_other_containers
        ),
        "tls_ready": observation.tls_ready,
        "operator_absent": observation.operator_absent(),
        "safety_seals_valid": observation.safety_seals_valid(),
        "keys_generated": observation.keys_generated,
        "key_metadata_safe": observation.key_metadata_safe,
        "worker_public_node": (
            {
                "id": public.node_id,
                "revision": public.revision,
                "ssh_public_fingerprint": public.ssh_public_fingerprint,
                "admission_anchor_fingerprint": public.admission_anchor_fingerprint,
                "public_material_only": public.public_material_only,
            }
            if public
            else None
        ),
        "database_private_material_absent": observation.database_private_material_absent,
        "recovery_required": observation.recovery_required,
    }


def _preflight_reason(profile: DeploymentProfile, observation: HostObservation) -> str | None:
    if not observation.inspected or not observation.coherent:
        return "preflight_observation_incoherent"
    if not observation.worker_present or observation.worker_generation is None:
        return "ordinary_worker_absent"
    if not (observation.worker_running and observation.worker_healthy):
        return "ordinary_worker_unhealthy"
    if observation.worker_image_digest != profile.ordinary_worker_image_digest:
        return "ordinary_worker_image_mismatch"
    if observation.ordinary_queues != (ORDINARY_TASK_QUEUE,):
        return "ordinary_worker_queue_drift"
    if not observation.operator_absent():
        return "operator_present"
    if not observation.safety_seals_valid():
        return "safety_seal_posture_invalid"
    if observation.recovery_required:
        return "prior_recovery_required"
    if (
        observation.state_mount_read_write_only_worker
        and not observation.discovery_mount_absent_from_other_containers
    ):
        return "worker_state_cross_container_exposure"
    try:
        _fixed_input_evidence(observation.base_compose_binding)
    except ActivationEngineError as exc:
        return exc.reason_code
    runtime = observation.worker_runtime
    if (
        type(runtime) is not ContainerRuntimeObservation
        or not runtime.present
        or runtime.generation != observation.worker_generation
        or runtime.image_digest != profile.ordinary_worker_image_digest
        or runtime.expected_image is not True
        or runtime.hardening_verified is not True
    ):
        return "ordinary_worker_runtime_unverified"
    return None


def _fixed_input_evidence(value: FixedInputBinding | None) -> FixedInputEvidence:
    if type(value) is not FixedInputBinding:
        raise ActivationEngineError("worker_base_compose_unbound")
    try:
        return FixedInputEvidence(
            content_digest=value.content_digest,
            owner_uid=value.owner_uid,
            owner_gid=value.owner_gid,
            mode=value.mode,
        )
    except Exception:
        raise ActivationEngineError("worker_base_compose_unbound") from None


def _worker_runtime_evidence(
    profile: DeploymentProfile, observation: HostObservation
) -> ContainerRuntimeEvidence:
    runtime = observation.worker_runtime
    if (
        type(runtime) is not ContainerRuntimeObservation
        or not runtime.verified()
        or runtime.generation is None
        or runtime.generation != observation.worker_generation
        or runtime.image_digest != profile.ordinary_worker_image_digest
        or runtime.configuration_digest is None
        or runtime.mounts_digest is None
        or runtime.networks_digest is None
        or runtime.compose_project is None
        or runtime.compose_service is None
        or not runtime.endpoint_binding_verified
    ):
        raise ActivationEngineError("ordinary_worker_runtime_unverified")
    try:
        return ContainerRuntimeEvidence(
            runtime_role="ordinary_worker",
            generation=runtime.generation,
            image_digest=runtime.image_digest,
            configuration_digest=runtime.configuration_digest,
            mounts_digest=runtime.mounts_digest,
            networks_digest=runtime.networks_digest,
            compose_project=runtime.compose_project,
            compose_service=runtime.compose_service,
            expected_image=runtime.expected_image,
            hardening_verified=runtime.hardening_verified,
            mounts_verified=runtime.mounts_verified,
            endpoint_binding_verified=runtime.endpoint_binding_verified,
        )
    except Exception:
        raise ActivationEngineError("ordinary_worker_runtime_unverified") from None


def _expected_artifact_digests(
    profile: DeploymentProfile,
    rendered: ActivationRender,
    tls_material: ValidatedTLSMaterial,
) -> dict[str, str]:
    if profile.worker_runtime_overlay_digest is None:
        raise ActivationEngineError("worker_runtime_overlay_digest_missing")
    by_name = {artifact.name: artifact.sha256 for artifact in rendered.artifacts}
    return {
        ROLE_PROFILE: rendered.manifest.profile_sha256,
        ROLE_WORKER_OVERRIDE: by_name["worker_compose_override"],
        ROLE_WORKER_RUNTIME_OVERLAY: profile.worker_runtime_overlay_digest,
        ROLE_CONTROLLER_OVERRIDE: by_name["controller_compose_override"],
        ROLE_PROXY_CONTRACT: by_name["admission_proxy_contract"],
        ROLE_ADMISSION_CA: _sha256(tls_material.ca_certificate_pem()),
        ROLE_ADMISSION_SERVER_CERTIFICATE: _sha256(tls_material.server_certificate_pem()),
    }


def _postcondition_reason(
    profile: DeploymentProfile,
    before: HostObservation,
    after: HostObservation,
    expected_digests: dict[str, str],
) -> str | None:
    if not after.inspected or not after.coherent:
        return "post_observation_incoherent"
    if before.worker_generation is None or after.worker_generation is None:
        return "worker_generation_missing"
    if after.worker_generation == before.worker_generation:
        return "worker_generation_unchanged"
    if after.worker_image_digest != profile.ordinary_worker_image_digest:
        return "worker_image_changed"
    if not (after.worker_running and after.worker_healthy):
        return "worker_health_failed"
    if after.ordinary_queues != (ORDINARY_TASK_QUEUE,):
        return "ordinary_queue_drift"
    if not (after.controlled_integration_enabled and after.worker_managed_bundle_enabled):
        return "b8_flags_not_enabled"
    if not after.fixed_worker_paths:
        return "worker_paths_invalid"
    if not (
        after.state_mount_read_write_only_worker
        and after.ca_mount_read_only_worker
        and after.discovery_mount_absent_from_other_containers
    ):
        return "worker_mount_isolation_failed"
    if not after.bundle_prep_loop_started:
        return "bundle_prep_loop_not_started"
    if not after.tls_ready:
        return "internal_tls_failed"
    if not after.operator_absent():
        return "operator_appeared"
    if not after.safety_seals_valid():
        return "safety_seal_posture_invalid"
    if not (after.keys_generated and after.key_metadata_safe):
        return "worker_key_metadata_invalid"
    public = after.worker_public
    if public is None or not public.public_material_only or public.revision < 1:
        return "public_worker_node_missing_or_unsafe"
    if not after.database_private_material_absent:
        return "database_private_material_unproven"
    if dict(after.configuration_artifact_digests) != expected_digests:
        return "configuration_artifact_drift"
    if before.base_compose_binding != after.base_compose_binding:
        return "worker_base_compose_drift"
    try:
        _worker_runtime_evidence(profile, after)
    except ActivationEngineError as exc:
        return exc.reason_code
    return None


def install_operation(
    profile: DeploymentProfile,
    tls_material: ValidatedTLSMaterial,
    gate: WriteGate,
    deps: EngineDependencies,
    *,
    installation_identity: str,
) -> OperationResult:
    """Run the reviewed transaction and commit authenticated evidence only after all gates pass."""

    refusal = gate.refusal_reason()
    if refusal is not None:
        return _result("install", "refused", reason=refusal)
    if not profile.activation_enabled:
        return _result("install", "refused", reason="activation_disabled")
    if not _SAFE_ID.fullmatch(installation_identity):
        return _result("install", "refused", reason="installation_identity_invalid")

    state_receipt: PreparedStateReceipt | None = None
    adapter_staged = False
    try:
        _plan, rendered = build_plan(profile, tls_material)
        # Requirement ordering: reject unsafe persistent state before the first Docker/Compose
        # observation.  ``inspect`` never repairs or changes an existing object.
        deps.state.inspect(uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid)
        before = deps.adapter.observe(profile)
        if type(before) is not HostObservation:
            raise ActivationEngineError("host_observation_type_invalid")
        preflight = _preflight_reason(profile, before)
        if preflight is not None:
            raise ActivationEngineError(preflight)

        state_receipt = deps.state.prepare(
            uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
        )
        staged = deps.adapter.stage_rollback(
            profile,
            rendered,
            before,
            state_receipt=state_receipt.canonical(),
        )
        adapter_staged = True
        if (
            type(staged) is not MutationReceipt
            or not staged.journal_present
            or staged.effects_started
        ):
            raise ActivationEngineError("rollback_journal_invalid")

        deps.adapter.install_controller(profile, rendered, tls_material)
        if not deps.adapter.verify_internal_tls(profile, tls_material):
            raise ActivationEngineError("internal_tls_verification_failed")
        deps.adapter.install_worker(profile, rendered, tls_material)
        # The rollback journal exists and both proposed TLS/state/config artifacts have now been
        # verified.  Only here may the ordinary worker be recreated.
        deps.adapter.recreate_worker(profile)
        assert before.worker_generation is not None
        after = deps.adapter.await_worker_publication(
            profile, previous_generation=before.worker_generation
        )
        expected_digests = _expected_artifact_digests(profile, rendered, tls_material)
        post_reason = _postcondition_reason(profile, before, after, expected_digests)
        if post_reason is not None:
            raise ActivationEngineError(post_reason)

        state_metadata = deps.state.inspect(
            uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
        )
        if not (state_metadata.prepared and state_metadata.keys_generated):
            raise ActivationEngineError("persistent_worker_keys_unproven")
        receipt = _require_live_receipt(deps, require_effects=True)
        evidence = _build_evidence(
            profile,
            rendered,
            tls_material,
            state_metadata=state_metadata,
            state_receipt=state_receipt,
            observation=after,
            receipt=receipt,
            timestamp=_timestamp(deps.clock()),
            installation_identity=installation_identity,
        )
        attestation = issue_attestation(evidence, deps.evidence_authenticator)
        deps.adapter.commit_evidence(evidence_bytes(evidence), attestation_bytes(attestation))

        # Detached attestation is the commit point: re-read canonical bytes, authenticate first,
        # then reobserve the same worker generation/node/artifacts before returning success.
        installed_evidence, _installed_attestation = _load_verified_evidence(deps)
        if installed_evidence.canonical() != evidence.canonical():
            raise ActivationEngineError("committed_evidence_mismatch")
        final = deps.adapter.observe(profile)
        final_reason = _postcondition_reason(profile, before, final, expected_digests)
        if final_reason is not None or final.worker_generation != after.worker_generation:
            raise ActivationEngineError(final_reason or "worker_generation_changed_after_commit")
        committed_receipt = _require_live_receipt(deps, require_effects=True)
        if not committed_receipt.evidence_committed:
            raise ActivationEngineError("evidence_commit_receipt_missing")
        return _result(
            "install",
            "installed",
            details={
                "state": "public-node-published",
                "evidence_digest": evidence.digest(),
                "worker_generation_digest": final.worker_generation.digest()
                if final.worker_generation
                else None,
                "worker_discovery_node_id": (
                    evidence.worker_public_material.worker_discovery_node_id
                ),
                "worker_discovery_node_revision": (
                    evidence.worker_public_material.worker_discovery_node_revision
                ),
                "ordinary_task_queue": evidence.ordinary_task_queue,
                "worker_state_classification": state_receipt.classification,
            },
        )
    except DiscoveryActivationError as exc:
        return _handle_install_failure(
            profile,
            deps,
            state_receipt=state_receipt,
            adapter_staged=adapter_staged,
            reason=exc.reason_code,
        )
    except Exception:
        return _handle_install_failure(
            profile,
            deps,
            state_receipt=state_receipt,
            adapter_staged=adapter_staged,
            reason="activation_transaction_error",
        )


def _handle_install_failure(
    profile: DeploymentProfile,
    deps: EngineDependencies,
    *,
    state_receipt: PreparedStateReceipt | None,
    adapter_staged: bool,
    reason: str,
) -> OperationResult:
    if not adapter_staged:
        if state_receipt is not None:
            state_ok = deps.state.compensate(
                state_receipt,
                uid=profile.ordinary_runtime_uid,
                gid=profile.ordinary_runtime_gid,
            )
            if not state_ok:
                return _result(
                    "install", "recovery-required", reason="recovery_required", recovery=True
                )
        return _result("install", "refused", reason=reason)
    try:
        receipt = deps.adapter.receipt()
    except Exception:
        return _result("install", "recovery-required", reason="recovery_required", recovery=True)
    if type(receipt) is not MutationReceipt or not receipt.journal_present:
        return _result("install", "recovery-required", reason="recovery_required", recovery=True)
    try:
        compensation = deps.adapter.compensate(receipt)
    except Exception:
        return _result("install", "recovery-required", reason="recovery_required", recovery=True)
    if not _compensation_proven(compensation):
        return _result("install", "recovery-required", reason="recovery_required", recovery=True)
    # Before recreation no worker could have generated state, so remove only the exact still-empty
    # directories created by this transaction.  After recreation durable keys are retained.
    if state_receipt is not None and not receipt.worker_recreated:
        if not deps.state.compensate(
            state_receipt,
            uid=profile.ordinary_runtime_uid,
            gid=profile.ordinary_runtime_gid,
        ):
            return _result(
                "install", "recovery-required", reason="recovery_required", recovery=True
            )
    return _result(
        "install",
        "rolled-back",
        reason=reason,
        details={
            "previous_worker_restored": compensation.previous_worker_restored,
            "previous_artifacts_restored": compensation.previous_artifacts_restored,
            "durable_worker_state_retained": compensation.residual_worker_state,
        },
    )


def _compensation_proven(compensation: object) -> bool:
    return bool(
        type(compensation) is CompensationResult
        and compensation.proven
        and compensation.previous_worker_restored
        and compensation.previous_artifacts_restored
    )


def _require_live_receipt(deps: EngineDependencies, *, require_effects: bool) -> MutationReceipt:
    try:
        receipt = deps.adapter.receipt()
    except Exception:
        raise ActivationEngineError("transaction_receipt_unavailable") from None
    if (
        type(receipt) is not MutationReceipt
        or not receipt.journal_present
        or (require_effects and not receipt.effects_started)
    ):
        raise ActivationEngineError("transaction_receipt_invalid")
    return receipt


def _build_evidence(
    profile: DeploymentProfile,
    rendered: ActivationRender,
    tls_material: ValidatedTLSMaterial,
    *,
    state_metadata,
    state_receipt: PreparedStateReceipt,
    observation: HostObservation,
    receipt: MutationReceipt,
    timestamp: str,
    installation_identity: str,
) -> ActivationEvidence:
    generation = observation.worker_generation
    public = observation.worker_public
    if generation is None or public is None:
        raise ActivationEngineError("evidence_observation_incomplete")
    classifications = dict(receipt.object_classifications)
    if set(classifications) != _OBJECT_ROLES or any(
        value not in (CLASSIFICATION_CREATED, CLASSIFICATION_ADOPTED)
        for value in classifications.values()
    ):
        raise ActivationEngineError("receipt_object_classification_invalid")
    if classifications[ROLE_WORKER_STATE] != state_receipt.classification:
        raise ActivationEngineError("receipt_state_classification_mismatch")
    digests = _expected_artifact_digests(profile, rendered, tls_material)
    artifacts = {artifact.name: artifact for artifact in rendered.artifacts}
    layout = PRODUCTION_LAYOUT
    object_specs = (
        (ROLE_PROFILE, layout.profile_path, digests[ROLE_PROFILE], 0, 0, 0o640),
        (
            ROLE_WORKER_OVERRIDE,
            layout.worker_compose_override_path,
            digests[ROLE_WORKER_OVERRIDE],
            0,
            0,
            0o640,
        ),
        (
            ROLE_WORKER_RUNTIME_OVERLAY,
            layout.worker_runtime_overlay_path,
            digests[ROLE_WORKER_RUNTIME_OVERLAY],
            0,
            0,
            0o644,
        ),
        (
            ROLE_CONTROLLER_OVERRIDE,
            layout.controller_compose_override_path,
            digests[ROLE_CONTROLLER_OVERRIDE],
            0,
            0,
            0o640,
        ),
        (
            ROLE_PROXY_CONTRACT,
            layout.proxy_contract_path,
            digests[ROLE_PROXY_CONTRACT],
            artifacts["admission_proxy_contract"].uid,
            artifacts["admission_proxy_contract"].gid,
            artifacts["admission_proxy_contract"].mode,
        ),
        (ROLE_ADMISSION_CA, layout.ca_certificate_path, digests[ROLE_ADMISSION_CA], 0, 0, 0o644),
        (
            ROLE_ADMISSION_SERVER_CERTIFICATE,
            layout.server_certificate_path,
            digests[ROLE_ADMISSION_SERVER_CERTIFICATE],
            0,
            0,
            0o644,
        ),
        (
            ROLE_ADMISSION_SERVER_KEY,
            layout.server_private_key_path,
            None,
            0,
            profile.admission_proxy_runtime_gid,
            0o640,
        ),
        (
            ROLE_ADMISSION_PROXY_GATE,
            layout.admission_proxy_gate_path,
            None,
            0,
            profile.admission_proxy_runtime_gid,
            0o640,
        ),
        (
            ROLE_WORKER_STATE,
            layout.worker_state_host_path,
            None,
            profile.ordinary_runtime_uid,
            profile.ordinary_runtime_gid,
            0o700,
        ),
    )
    records = tuple(
        ManagedObjectRecord(
            role=role,
            path_binding=path_binding_digest(role, path),
            content_digest=content_digest,
            owner_uid=uid,
            owner_gid=gid,
            mode=mode,
            classification=classifications[role],
        )
        for role, path, content_digest, uid, gid, mode in object_specs
    )
    tls = tls_material.metadata
    return ActivationEvidence(
        contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        activation_status="public-node-published",
        worker_image_digest=profile.ordinary_worker_image_digest,
        worker_generation=generation,
        worker_base_compose=_fixed_input_evidence(observation.base_compose_binding),
        worker_runtime=_worker_runtime_evidence(profile, observation),
        ordinary_task_queue=ORDINARY_TASK_QUEUE,
        configuration_artifact_digests=digests,
        managed_objects=records,
        persistent_state=PersistentStateEvidence(
            path_binding=path_binding_digest(ROLE_WORKER_STATE, layout.worker_state_host_path),
            owner_uid=profile.ordinary_runtime_uid,
            owner_gid=profile.ordinary_runtime_gid,
            mode=0o700,
            key_directory_present=state_metadata.key_directory_present,
            bundle_directory_present=state_metadata.bundle_directory_present,
            key_file_count=state_metadata.key_file_count,
            bundle_file_count=state_metadata.bundle_file_count,
            keys_generated=state_metadata.keys_generated,
            bundle_populated=state_metadata.bundle_populated,
            classification=state_receipt.classification,
        ),
        admission_tls=AdmissionTLSEvidence(
            ca_certificate_fingerprint=tls.ca_certificate_fingerprint,
            server_certificate_fingerprint=tls.server_certificate_fingerprint,
            server_public_key_fingerprint=tls.server_public_key_fingerprint,
            server_dns_identity=tls.server_dns_identity,
            server_dns_sans=tls.server_dns_sans,
        ),
        worker_public_material=WorkerPublicEvidence(
            ssh_public_fingerprint=public.ssh_public_fingerprint,
            admission_anchor_fingerprint=public.admission_anchor_fingerprint,
            worker_discovery_node_id=public.node_id,
            worker_discovery_node_revision=public.revision,
        ),
        installation_timestamp=timestamp,
        controller_installation_identity=installation_identity,
        worker_installation_identity=installation_identity,
        operator_service_present=observation.operator_service_present,
        operator_queue_polled=observation.operator_queue_polled,
        generic_activation_subprocess_sealed=observation.generic_activation_subprocess_sealed,
        generic_executor_subprocess_sealed=observation.generic_executor_subprocess_sealed,
        plan_only_process_sealed=observation.plan_only_process_sealed,
        real_provisioning_enabled=observation.real_provisioning_enabled,
        forbidden_infrastructure_contacts_performed=False,
        workflows_submitted=False,
        run_plan_generation_called=False,
        opentofu_executed=False,
        proxmox_contacted=False,
    )


def _load_verified_evidence(
    deps: EngineDependencies,
) -> tuple[ActivationEvidence, EvidenceAttestation]:
    raw = deps.adapter.load_evidence()
    if raw is None or not isinstance(raw, tuple) or len(raw) != 2:
        raise ActivationEngineError("activation_evidence_missing")
    evidence = parse_evidence_bytes(raw[0])
    attestation = parse_attestation_bytes(raw[1])
    verify_evidence(evidence, attestation, deps.evidence_trust_root)
    return evidence, attestation


def evidence_operation(deps: EngineDependencies) -> OperationResult:
    try:
        evidence, attestation = _load_verified_evidence(deps)
        return _result(
            "evidence",
            "verified",
            details={
                "evidence": evidence.canonical(),
                "evidence_digest": evidence.digest(),
                "attestation": {
                    "algorithm": attestation.algorithm,
                    "key_id": attestation.key_id,
                    "verified": True,
                },
            },
        )
    except DiscoveryActivationError as exc:
        return _result("evidence", "refused", reason=exc.reason_code)
    except Exception:
        return _result("evidence", "refused", reason="evidence_verification_failed")


def verify_operation(profile: DeploymentProfile, deps: EngineDependencies) -> OperationResult:
    try:
        evidence, _attestation = _load_verified_evidence(deps)
        observation = deps.adapter.observe(profile)
        if type(observation) is not HostObservation:
            raise ActivationEngineError("host_observation_type_invalid")
        # Evidence supplies the independently authenticated expected generation/artifact identities.
        if observation.worker_generation != evidence.worker_generation:
            raise ActivationEngineError("worker_generation_evidence_drift")
        expected = dict(evidence.configuration_artifact_digests)
        synthetic_before = HostObservation(
            worker_generation=_different_generation(evidence),
            base_compose_binding=observation.base_compose_binding,
        )
        reason = _postcondition_reason(profile, synthetic_before, observation, expected)
        if reason is not None:
            raise ActivationEngineError(reason)
        if (
            _fixed_input_evidence(observation.base_compose_binding) != evidence.worker_base_compose
            or _worker_runtime_evidence(profile, observation) != evidence.worker_runtime
        ):
            raise ActivationEngineError("worker_runtime_evidence_drift")
        return _result(
            "verify",
            "verified",
            details={
                "evidence_digest": evidence.digest(),
                "worker_generation_digest": evidence.worker_generation.digest(),
                "worker_discovery_node_id": (
                    evidence.worker_public_material.worker_discovery_node_id
                ),
                "worker_discovery_node_revision": (
                    evidence.worker_public_material.worker_discovery_node_revision
                ),
            },
        )
    except DiscoveryActivationError as exc:
        return _result("verify", "refused", reason=exc.reason_code)
    except Exception:
        return _result("verify", "refused", reason="verification_failed")


def _different_generation(evidence: ActivationEvidence):  # noqa: ANN202
    from secp_discovery_activation.evidence import WorkerGeneration

    generation = evidence.worker_generation
    replacement = "0" * 64 if generation.container_id != "0" * 64 else "1" * 64
    return WorkerGeneration(
        container_id=replacement,
        restart_count=generation.restart_count,
        started_at=generation.started_at,
    )


def status_operation(profile: DeploymentProfile, deps: EngineDependencies) -> OperationResult:
    try:
        observation = deps.adapter.observe(profile)
        if type(observation) is not HostObservation:
            raise ActivationEngineError("host_observation_type_invalid")
        if observation.recovery_required:
            report = derive_status(
                observation.status_observation(activation_enabled=profile.activation_enabled)
            )
            return _result(
                "status",
                report.state,
                recovery=True,
                reason=report.findings[0],
                details=report.canonical(),
            )
        raw = deps.adapter.load_evidence()
        if raw is not None:
            # Authenticate before status trusts evidence classification or ownership.
            _load_verified_evidence(deps)
        elif observation.artifacts_prepared and observation.worker_config_installed:
            return _result(
                "status",
                RECOVERY_REQUIRED,
                reason="installed_evidence_missing",
                recovery=True,
            )
        report = derive_status(
            observation.status_observation(activation_enabled=profile.activation_enabled)
        )
        return _result(
            "status",
            report.state,
            recovery=report.state == RECOVERY_REQUIRED,
            reason=report.findings[0] if report.findings else None,
            details=report.canonical(),
        )
    except DiscoveryActivationError as exc:
        return _result("status", RECOVERY_REQUIRED, reason=exc.reason_code, recovery=True)
    except Exception:
        return _result(
            "status", RECOVERY_REQUIRED, reason="status_observation_failed", recovery=True
        )


def rollback_operation(
    profile: DeploymentProfile, gate: WriteGate, deps: EngineDependencies
) -> OperationResult:
    refusal = gate.refusal_reason()
    if refusal is not None:
        return _result("rollback", "refused", reason=refusal)
    try:
        evidence, _attestation = _load_verified_evidence(deps)
        receipt = _require_live_receipt(deps, require_effects=True)
        result = deps.adapter.rollback_committed(evidence, receipt)
        if not _compensation_proven(result):
            return _result(
                "rollback", "recovery-required", reason="recovery_required", recovery=True
            )
        return _result(
            "rollback",
            "rolled-back",
            details={
                "previous_worker_restored": result.previous_worker_restored,
                "previous_artifacts_restored": result.previous_artifacts_restored,
                "durable_worker_state_retained": result.residual_worker_state,
            },
        )
    except DiscoveryActivationError as exc:
        recovery = exc.reason_code in {
            "transaction_receipt_unavailable",
            "transaction_receipt_invalid",
        }
        return _result(
            "rollback",
            "recovery-required" if recovery else "refused",
            reason="recovery_required" if recovery else exc.reason_code,
            recovery=recovery,
        )
    except Exception:
        return _result("rollback", "recovery-required", reason="recovery_required", recovery=True)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ActivationEngineError("clock_not_timezone_aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


__all__ = [
    "ActivationEngineError",
    "WriteGate",
    "ActivationPlan",
    "OperationResult",
    "EngineDependencies",
    "build_plan",
    "inspect_operation",
    "plan_operation",
    "render_operation",
    "install_operation",
    "verify_operation",
    "status_operation",
    "rollback_operation",
    "evidence_operation",
]
