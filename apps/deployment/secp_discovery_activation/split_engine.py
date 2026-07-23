"""Two-host transactional state machine for production B8 discovery activation.

Controller and worker mutations never share an adapter.  The controller first commits a local,
TLS-ready transaction and emits an authenticated offer.  The worker authenticates that fixed-inbox
offer, performs its own local transaction, and emits an authenticated result.  A later controller
invocation commits and independently verifies aggregate evidence while the API rollback fence is
still engaged, then releases and freshly observes that fence as the resumable finalization step.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal

from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    DiscoveryActivationError,
)
from secp_discovery_activation.adapters import ContainerRuntimeObservation, FixedInputBinding
from secp_discovery_activation.engine import ActivationPlan, OperationResult, WriteGate
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
    EvidenceAuthenticator,
    EvidenceTrustRoot,
    FixedInputEvidence,
    ManagedObjectRecord,
    PersistentStateEvidence,
    WorkerPublicEvidence,
    evidence_bytes,
    issue_attestation,
    parse_evidence_bytes,
    path_binding_digest,
    verify_evidence,
)
from secp_discovery_activation.evidence import (
    attestation_bytes as evidence_attestation_bytes,
)
from secp_discovery_activation.evidence import (
    parse_attestation_bytes as parse_evidence_attestation,
)
from secp_discovery_activation.handoff import (
    ControllerOffer,
    HandoffSigner,
    WorkerResult,
    handoff_bytes,
    issue_handoff_attestation,
    parse_controller_offer,
    parse_handoff_attestation,
    parse_worker_result,
    verify_handoff,
)
from secp_discovery_activation.handoff import (
    attestation_bytes as handoff_attestation_bytes,
)
from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE, PRODUCTION_LAYOUT
from secp_discovery_activation.migration_heads import (
    ACCEPTED_CONTROLLER_MIGRATION_HEADS,
    ISSUED_CONTROLLER_MIGRATION_HEAD,
)
from secp_discovery_activation.profile import DeploymentProfile
from secp_discovery_activation.render import (
    ActivationRender,
    RenderedArtifact,
    render_activation,
    render_worker_compose_override,
)
from secp_discovery_activation.split_adapters import (
    ApiRollbackFenceObservation,
    ApiRollbackFenceState,
    ControllerActivationAdapter,
    ControllerCompensation,
    ControllerObservation,
    ControllerReceipt,
    WorkerActivationAdapter,
    WorkerCompensation,
    WorkerObservation,
    WorkerReceipt,
)
from secp_discovery_activation.state import (
    PreparedStateReceipt,
    WorkerStateBackend,
    WorkerStateMetadata,
)
from secp_discovery_activation.status import (
    AWAITING_FINALIZATION,
    DISABLED,
    PREPARED,
    PUBLIC_NODE_PUBLISHED,
    RECOVERY_REQUIRED,
    TLS_READY,
    ActivationObservation,
    derive_status,
)
from secp_discovery_activation.tls import (
    TLSMaterialMetadata,
    ValidatedAdmissionCA,
    ValidatedTLSMaterial,
    import_admission_ca,
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
# SECP-PR5H-A (ADR-027): ISSUANCE is single-valued (always the current head, and the live
# controller must already be at it); VALIDATION accepts the bounded window so an ALREADY-ISSUED
# PR5F offer stays verifiable.  The declared head must still equal the OBSERVED head everywhere,
# so a downgrade substitution refuses closed.
_ISSUED_MIGRATION_HEAD = ISSUED_CONTROLLER_MIGRATION_HEAD
_ACCEPTED_MIGRATION_HEADS = ACCEPTED_CONTROLLER_MIGRATION_HEADS
_CONTROLLER_ROLES = frozenset(
    {
        ROLE_PROFILE,
        ROLE_CONTROLLER_OVERRIDE,
        ROLE_PROXY_CONTRACT,
        ROLE_ADMISSION_CA,
        ROLE_ADMISSION_PROXY_GATE,
        ROLE_ADMISSION_SERVER_CERTIFICATE,
        ROLE_ADMISSION_SERVER_KEY,
    }
)
_WORKER_ROLES = frozenset({ROLE_WORKER_OVERRIDE, ROLE_WORKER_RUNTIME_OVERLAY, ROLE_WORKER_STATE})


class SplitActivationEngineError(DiscoveryActivationError):
    """The split-host state machine failed closed with a bounded reason code."""


@dataclass(frozen=True)
class ControllerDependencies:
    adapter: ControllerActivationAdapter
    handoff_signer: HandoffSigner
    evidence_authenticator: EvidenceAuthenticator
    evidence_trust_root: EvidenceTrustRoot
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


@dataclass(frozen=True)
class WorkerDependencies:
    adapter: WorkerActivationAdapter
    state: WorkerStateBackend
    handoff_signer: HandoffSigner
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


@dataclass(frozen=True)
class _VerifiedControllerFinalization:
    """Authenticated durable aggregate state bound to the current controller runtime."""

    evidence: ActivationEvidence
    offer: ControllerOffer
    worker_result: WorkerResult
    controller_observation: ControllerObservation


def _result(
    operation: str,
    outcome: str,
    *,
    reason: str | None = None,
    recovery: bool = False,
    details: dict[str, object] | None = None,
) -> OperationResult:
    return OperationResult(operation, outcome, reason, recovery, details or {})


def _pending(operation: str, reason: str, **details: object) -> OperationResult:
    return _result(operation, "pending", reason=reason, details=dict(details))


def _recovery(operation: str, reason: str) -> OperationResult:
    return _result(operation, "recovery-required", reason=reason, recovery=True)


def _require_install_inputs(
    operation: str,
    profile: DeploymentProfile,
    gate: WriteGate,
    installation_identity: str,
) -> OperationResult | None:
    refusal = gate.refusal_reason()
    if refusal is not None:
        return _result(operation, "refused", reason=refusal)
    if type(profile) is not DeploymentProfile:
        return _result(operation, "refused", reason="profile_type_invalid")
    if not profile.activation_enabled:
        return _result(operation, "refused", reason="activation_disabled")
    if profile.controller_evidence_key_id is None or profile.worker_evidence_key_id is None:
        return _result(operation, "refused", reason="handoff_trust_pins_required")
    if not _SAFE_ID.fullmatch(installation_identity):
        return _result(operation, "refused", reason="installation_identity_invalid")
    return None


def _plan_from_render(profile: DeploymentProfile, rendered: ActivationRender) -> ActivationPlan:
    """Build the existing deterministic plan without requiring private TLS on the worker host."""

    return ActivationPlan(
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


def _controller_render(
    profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
) -> tuple[ActivationPlan, ActivationRender]:
    if type(tls_material) is not ValidatedTLSMaterial:
        raise SplitActivationEngineError("tls_material_type_invalid")
    rendered = render_activation(profile, tls_material.metadata)
    return _plan_from_render(profile, rendered), rendered


def _artifact_map(rendered: ActivationRender) -> dict[str, str]:
    return {artifact.name: artifact.sha256 for artifact in rendered.artifacts}


def _controller_digests(
    rendered: ActivationRender, tls_material: ValidatedTLSMaterial
) -> dict[str, str]:
    artifacts = _artifact_map(rendered)
    return {
        ROLE_CONTROLLER_OVERRIDE: artifacts["controller_compose_override"],
        ROLE_PROXY_CONTRACT: artifacts["admission_proxy_contract"],
        ROLE_ADMISSION_CA: _sha256(tls_material.ca_certificate_pem()),
        ROLE_ADMISSION_SERVER_CERTIFICATE: _sha256(tls_material.server_certificate_pem()),
    }


def _worker_digests(
    profile: DeploymentProfile,
    worker_override: RenderedArtifact,
    ca_certificate: ValidatedAdmissionCA,
) -> dict[str, str]:
    if profile.worker_runtime_overlay_digest is None:
        raise SplitActivationEngineError("worker_runtime_overlay_digest_missing")
    return {
        ROLE_WORKER_OVERRIDE: worker_override.sha256,
        ROLE_WORKER_RUNTIME_OVERLAY: profile.worker_runtime_overlay_digest,
        ROLE_ADMISSION_CA: ca_certificate.ca_certificate_content_digest,
    }


def _required_runtime_overlay_digest(profile: DeploymentProfile) -> str:
    digest = profile.worker_runtime_overlay_digest
    if digest is None:
        raise SplitActivationEngineError("worker_runtime_overlay_digest_missing")
    return digest


def validate_worker_ca_certificate(
    ca_certificate_pem: bytes, *, now: datetime
) -> ValidatedAdmissionCA:
    """Validate and normalize the only TLS file permitted on the worker host."""

    return import_admission_ca(ca_certificate_pem=ca_certificate_pem, now=now)


def _profile_digest(profile: DeploymentProfile) -> str:
    raw = (
        json.dumps(
            profile.canonical(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    return _sha256(raw)


def _handoff_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise SplitActivationEngineError("handoff_timestamp_invalid") from None
    if parsed.utcoffset() is None or not value.endswith("Z"):
        raise SplitActivationEngineError("handoff_timestamp_invalid")
    return parsed.astimezone(UTC)


def _offer_window(offer: ControllerOffer, now: datetime) -> tuple[datetime, datetime]:
    current = _aware_utc(now)
    issued = _handoff_time(offer.installation_timestamp)
    expires = _handoff_time(offer.expires_at)
    if current < issued:
        raise SplitActivationEngineError("controller_offer_from_future")
    if current > expires:
        raise SplitActivationEngineError("controller_offer_expired")
    return issued, expires


def _validate_result_window(
    offer: ControllerOffer, result: WorkerResult, now: datetime | None
) -> None:
    issued = _handoff_time(offer.installation_timestamp)
    expires = _handoff_time(offer.expires_at)
    result_time = _handoff_time(result.installation_timestamp)
    if result_time < issued:
        raise SplitActivationEngineError("worker_result_precedes_offer")
    if result_time > expires:
        raise SplitActivationEngineError("worker_result_outside_offer_window")
    if now is not None:
        _offer_window(offer, now)
        if result_time > _aware_utc(now):
            raise SplitActivationEngineError("worker_result_from_future")


def _admission_tls(metadata: TLSMaterialMetadata) -> AdmissionTLSEvidence:
    return AdmissionTLSEvidence(
        ca_certificate_fingerprint=metadata.ca_certificate_fingerprint,
        server_certificate_fingerprint=metadata.server_certificate_fingerprint,
        server_public_key_fingerprint=metadata.server_public_key_fingerprint,
        server_dns_identity=metadata.server_dns_identity,
        server_dns_sans=metadata.server_dns_sans,
    )


def _fixed_input_evidence(value: FixedInputBinding | None, reason: str) -> FixedInputEvidence:
    if type(value) is not FixedInputBinding:
        raise SplitActivationEngineError(reason)
    try:
        return FixedInputEvidence(
            content_digest=value.content_digest,
            owner_uid=value.owner_uid,
            owner_gid=value.owner_gid,
            mode=value.mode,
        )
    except Exception:
        raise SplitActivationEngineError(reason) from None


def _runtime_evidence(
    role: Literal["controller_api", "admission_proxy", "ordinary_worker"],
    value: ContainerRuntimeObservation | None,
    *,
    expected_image_digest: str,
    reason: str,
) -> ContainerRuntimeEvidence:
    if (
        type(value) is not ContainerRuntimeObservation
        or not value.verified()
        or value.generation is None
        or value.image_digest != expected_image_digest
        or value.configuration_digest is None
        or value.mounts_digest is None
        or value.networks_digest is None
        or value.compose_project is None
        or value.compose_service is None
        or value.expected_image is not True
    ):
        raise SplitActivationEngineError(reason)
    try:
        return ContainerRuntimeEvidence(
            runtime_role=role,
            generation=value.generation,
            image_digest=value.image_digest,
            configuration_digest=value.configuration_digest,
            mounts_digest=value.mounts_digest,
            networks_digest=value.networks_digest,
            compose_project=value.compose_project,
            compose_service=value.compose_service,
            expected_image=value.expected_image,
            hardening_verified=value.hardening_verified,
            mounts_verified=value.mounts_verified,
            endpoint_binding_verified=value.endpoint_binding_verified,
        )
    except Exception:
        raise SplitActivationEngineError(reason) from None


def _controller_runtime_evidence(
    profile: DeploymentProfile, observation: ControllerObservation
) -> tuple[FixedInputEvidence, tuple[ContainerRuntimeEvidence, ...]]:
    api_digest = profile.controller_api_runtime_image_digest
    proxy_digest = profile.admission_proxy_runtime_image_digest
    if api_digest is None or proxy_digest is None:
        raise SplitActivationEngineError("controller_runtime_image_pin_invalid")
    base = _fixed_input_evidence(
        observation.base_compose_binding, "controller_base_compose_unbound"
    )
    runtimes = (
        _runtime_evidence(
            "controller_api",
            observation.api_runtime,
            expected_image_digest=api_digest,
            reason="controller_api_runtime_unverified",
        ),
        _runtime_evidence(
            "admission_proxy",
            observation.proxy_runtime,
            expected_image_digest=proxy_digest,
            reason="admission_proxy_runtime_unverified",
        ),
    )
    if (
        runtimes[0].compose_project != profile.controller_compose_project
        or runtimes[1].compose_project != profile.controller_compose_project
    ):
        raise SplitActivationEngineError("controller_compose_project_drift")
    return base, runtimes


def _worker_runtime_evidence(
    profile: DeploymentProfile, observation: WorkerObservation
) -> tuple[FixedInputEvidence, ContainerRuntimeEvidence]:
    base = _fixed_input_evidence(observation.base_compose_binding, "worker_base_compose_unbound")
    runtime = _runtime_evidence(
        "ordinary_worker",
        observation.worker_runtime,
        expected_image_digest=profile.ordinary_worker_image_digest,
        reason="ordinary_worker_runtime_unverified",
    )
    if runtime.generation != observation.worker_generation:
        raise SplitActivationEngineError("ordinary_worker_runtime_generation_mismatch")
    if runtime.compose_project != profile.worker_compose_project:
        raise SplitActivationEngineError("worker_compose_project_drift")
    return base, runtime


def _controller_transaction_effects(
    profile: DeploymentProfile, observation: ControllerObservation
) -> bool:
    """Return whether controller-local PR5F effects are visible without trusting artifacts alone."""

    api_runtime = observation.api_runtime
    return bool(
        observation.controller_config_installed
        or observation.proxy_runtime is not None
        or observation.proxy_running
        or observation.tls_ready
        or observation.activation_route_enabled
        or observation.migration_head in _ACCEPTED_MIGRATION_HEADS
        or (
            api_runtime is not None
            and api_runtime.image_digest == profile.controller_api_runtime_image_digest
        )
    )


def _worker_transaction_effects(observation: WorkerObservation) -> bool:
    """Return whether worker-local PR5F configuration/runtime effects are visible."""

    runtime = observation.worker_runtime
    return bool(
        observation.artifacts_prepared
        or observation.worker_config_installed
        or observation.worker_recreation_required
        or observation.worker_generation_changed
        or observation.controlled_integration_enabled
        or observation.worker_managed_bundle_enabled
        or observation.fixed_worker_paths
        or observation.state_mount_read_write_only_worker
        or observation.ca_mount_read_only_worker
        or observation.tls_ready
        or observation.bundle_prep_loop_started
        or (runtime is not None and (runtime.mounts_verified or runtime.endpoint_binding_verified))
    )


def _controller_preflight(
    profile: DeploymentProfile, observation: ControllerObservation
) -> str | None:
    if type(observation) is not ControllerObservation or not (
        observation.inspected and observation.coherent
    ):
        return "controller_observation_incoherent"
    if observation.recovery_required:
        return "prior_recovery_required"
    if _controller_transaction_effects(profile, observation):
        return "controller_transaction_receipt_missing"
    return None


def _controller_postcondition(
    profile: DeploymentProfile,
    observation: ControllerObservation,
    expected_digests: dict[str, str],
) -> str | None:
    if type(observation) is not ControllerObservation or not (
        observation.inspected and observation.coherent
    ):
        return "controller_post_observation_incoherent"
    if observation.recovery_required:
        return "controller_recovery_required"
    if not (
        observation.controller_config_installed
        and observation.proxy_running
        and observation.proxy_healthy
        and observation.private_listener_only
        and observation.activation_route_enabled
        and observation.tls_ready
    ):
        return "controller_postconditions_incomplete"
    if dict(observation.configuration_artifact_digests) != expected_digests:
        return "controller_configuration_drift"
    if (
        not observation.migration_head_ready
        or observation.migration_head not in _ACCEPTED_MIGRATION_HEADS
    ):
        return "controller_migration_head_unverified"
    try:
        _controller_runtime_evidence(profile, observation)
    except SplitActivationEngineError as exc:
        return exc.reason_code
    return None


def _worker_preflight(profile: DeploymentProfile, observation: WorkerObservation) -> str | None:
    if type(observation) is not WorkerObservation or not (
        observation.inspected and observation.coherent
    ):
        return "worker_observation_incoherent"
    if observation.recovery_required:
        return "prior_recovery_required"
    if _worker_transaction_effects(observation):
        return "worker_transaction_receipt_missing"
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
    if not observation.discovery_mount_absent_from_other_containers:
        return "worker_state_cross_container_exposure"
    try:
        _fixed_input_evidence(observation.base_compose_binding, "worker_base_compose_unbound")
    except SplitActivationEngineError as exc:
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


def _worker_postcondition(
    profile: DeploymentProfile,
    before: WorkerObservation,
    after: WorkerObservation,
    expected_digests: dict[str, str],
) -> str | None:
    if type(after) is not WorkerObservation or not (after.inspected and after.coherent):
        return "worker_post_observation_incoherent"
    if after.recovery_required:
        return "worker_recovery_required"
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
        return "live_tls_verification_failed"
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
        return "worker_configuration_drift"
    if before.base_compose_binding != after.base_compose_binding:
        return "worker_base_compose_drift"
    try:
        _worker_runtime_evidence(profile, after)
    except SplitActivationEngineError as exc:
        return exc.reason_code
    return None


def _parse_pair(raw: object, *, kind: str) -> tuple[bytes, bytes]:
    if (
        not isinstance(raw, tuple)
        or len(raw) != 2
        or type(raw[0]) is not bytes
        or type(raw[1]) is not bytes
    ):
        raise SplitActivationEngineError(kind + "_pair_invalid")
    return raw


def _load_controller_offer(
    raw: object, *, expected_key_id: str
) -> tuple[ControllerOffer, bytes, bytes]:
    offer_raw, attestation_raw = _parse_pair(raw, kind="controller_offer")
    offer = parse_controller_offer(offer_raw)
    attestation = parse_handoff_attestation(attestation_raw)
    verify_handoff(offer, attestation, expected_key_id=expected_key_id)
    return offer, offer_raw, attestation_raw


def _load_worker_result(raw: object, *, expected_key_id: str) -> tuple[WorkerResult, bytes, bytes]:
    result_raw, attestation_raw = _parse_pair(raw, kind="worker_result")
    result = parse_worker_result(result_raw)
    attestation = parse_handoff_attestation(attestation_raw)
    verify_handoff(result, attestation, expected_key_id=expected_key_id)
    return result, result_raw, attestation_raw


def _validate_offer(
    profile: DeploymentProfile,
    plan: ActivationPlan,
    rendered: ActivationRender,
    offer: ControllerOffer,
    *,
    admission_tls: AdmissionTLSEvidence,
    expected_controller_digests: dict[str, str],
    now: datetime | None,
) -> None:
    if (
        offer.profile_digest != rendered.manifest.profile_sha256
        or offer.plan_digest != plan.digest()
        or offer.render_manifest_digest != rendered.manifest.sha256
        or offer.controller_artifact_digests != expected_controller_digests
        or offer.admission_tls != admission_tls
    ):
        raise SplitActivationEngineError("controller_offer_binding_mismatch")
    if now is not None:
        _offer_window(offer, now)


def _validate_live_controller_offer(
    profile: DeploymentProfile,
    observation: ControllerObservation,
    offer: ControllerOffer,
) -> None:
    base, runtimes = _controller_runtime_evidence(profile, observation)
    if (
        offer.controller_base_compose != base
        or offer.controller_runtimes != runtimes
        or offer.controller_migration_head != observation.migration_head
        or observation.migration_head not in _ACCEPTED_MIGRATION_HEADS
        or not observation.migration_head_ready
    ):
        raise SplitActivationEngineError("controller_runtime_offer_drift")


def _validate_result(
    profile: DeploymentProfile,
    plan: ActivationPlan,
    rendered: ActivationRender,
    offer: ControllerOffer,
    result: WorkerResult,
    *,
    now: datetime | None,
) -> None:
    expected_worker = {
        ROLE_WORKER_OVERRIDE: _artifact_map(rendered)["worker_compose_override"],
        ROLE_WORKER_RUNTIME_OVERLAY: _required_runtime_overlay_digest(profile),
        ROLE_ADMISSION_CA: offer.controller_artifact_digests[ROLE_ADMISSION_CA],
    }
    if (
        result.controller_offer_digest != offer.digest()
        or result.controller_transaction_id != offer.transaction_id
        or result.profile_digest != rendered.manifest.profile_sha256
        or result.plan_digest != plan.digest()
        or result.render_manifest_digest != rendered.manifest.sha256
        or result.worker_image_digest != profile.ordinary_worker_image_digest
        or result.worker_artifact_digests != expected_worker
        or offer.worker_artifact_digests
        != {
            ROLE_WORKER_OVERRIDE: expected_worker[ROLE_WORKER_OVERRIDE],
            ROLE_WORKER_RUNTIME_OVERLAY: expected_worker[ROLE_WORKER_RUNTIME_OVERLAY],
        }
        or result.admission_ca_fingerprint != offer.admission_tls.ca_certificate_fingerprint
    ):
        raise SplitActivationEngineError("worker_result_binding_mismatch")
    _validate_result_window(offer, result, now)


def _validate_worker_offer(
    profile: DeploymentProfile,
    worker_override: RenderedArtifact,
    ca_certificate: ValidatedAdmissionCA,
    offer: ControllerOffer,
    *,
    now: datetime | None,
) -> None:
    """Validate every offer fact the CA-only worker can independently establish."""

    controller_runtimes = {runtime.runtime_role: runtime for runtime in offer.controller_runtimes}
    api_digest = profile.controller_api_runtime_image_digest
    proxy_digest = profile.admission_proxy_runtime_image_digest
    if (
        offer.profile_digest != _profile_digest(profile)
        or offer.worker_artifact_digests
        != {
            ROLE_WORKER_OVERRIDE: worker_override.sha256,
            ROLE_WORKER_RUNTIME_OVERLAY: profile.worker_runtime_overlay_digest,
        }
        or offer.controller_artifact_digests[ROLE_ADMISSION_CA]
        != ca_certificate.ca_certificate_content_digest
        or offer.admission_tls.ca_certificate_fingerprint
        != ca_certificate.ca_certificate_fingerprint
        or offer.admission_tls.server_dns_identity != profile.admission_certificate_dns_name
        or offer.admission_tls.server_dns_sans != (profile.admission_certificate_dns_name,)
        or api_digest is None
        or proxy_digest is None
        or controller_runtimes["controller_api"].image_digest != api_digest
        or controller_runtimes["admission_proxy"].image_digest != proxy_digest
        or offer.controller_migration_head not in _ACCEPTED_MIGRATION_HEADS
    ):
        raise SplitActivationEngineError("controller_offer_binding_mismatch")
    if now is not None:
        _offer_window(offer, now)


def _validate_existing_worker_result(
    profile: DeploymentProfile,
    worker_override: RenderedArtifact,
    ca_certificate: ValidatedAdmissionCA,
    offer: ControllerOffer,
    result: WorkerResult,
    *,
    now: datetime | None,
) -> None:
    expected_worker = _worker_digests(profile, worker_override, ca_certificate)
    if (
        result.controller_offer_digest != offer.digest()
        or result.controller_transaction_id != offer.transaction_id
        or result.profile_digest != _profile_digest(profile)
        or result.plan_digest != offer.plan_digest
        or result.render_manifest_digest != offer.render_manifest_digest
        or result.worker_image_digest != profile.ordinary_worker_image_digest
        or result.worker_artifact_digests != expected_worker
        or result.admission_ca_fingerprint != ca_certificate.ca_certificate_fingerprint
    ):
        raise SplitActivationEngineError("worker_result_binding_mismatch")
    _validate_result_window(offer, result, now)


def _validate_live_worker_result(
    observation: WorkerObservation,
    state: WorkerStateMetadata,
    result: WorkerResult,
) -> None:
    """Bind a stored signed result to fresh worker-local public and state facts."""

    public = observation.worker_public
    expected_public = result.worker_public_material
    if observation.worker_generation != result.worker_generation:
        raise SplitActivationEngineError("worker_generation_result_mismatch")
    base, runtime = _worker_runtime_evidence_from_result_observation(observation, result)
    if result.worker_base_compose != base or result.worker_runtime != runtime:
        raise SplitActivationEngineError("worker_runtime_result_drift")
    if (
        public is None
        or not public.public_material_only
        or not observation.publication_recorded
        or public.node_id != expected_public.worker_discovery_node_id
        or public.revision != expected_public.worker_discovery_node_revision
        or public.ssh_public_fingerprint != expected_public.ssh_public_fingerprint
        or public.admission_anchor_fingerprint != expected_public.admission_anchor_fingerprint
    ):
        raise SplitActivationEngineError("worker_public_result_drift")
    persistent = result.persistent_state
    if (
        not state.prepared
        or state.owner_uid != persistent.owner_uid
        or state.owner_gid != persistent.owner_gid
        or state.mode != persistent.mode
        or state.key_directory_present != persistent.key_directory_present
        or state.bundle_directory_present != persistent.bundle_directory_present
        or state.key_file_count != persistent.key_file_count
        or state.bundle_file_count != persistent.bundle_file_count
        or state.keys_generated != persistent.keys_generated
        or state.bundle_populated != persistent.bundle_populated
    ):
        raise SplitActivationEngineError("worker_state_result_drift")


def _worker_runtime_evidence_from_result_observation(
    observation: WorkerObservation, result: WorkerResult
) -> tuple[FixedInputEvidence, ContainerRuntimeEvidence]:
    base = _fixed_input_evidence(observation.base_compose_binding, "worker_base_compose_unbound")
    runtime = _runtime_evidence(
        "ordinary_worker",
        observation.worker_runtime,
        expected_image_digest=result.worker_image_digest,
        reason="ordinary_worker_runtime_unverified",
    )
    return base, runtime


def _controller_receipt(adapter: ControllerActivationAdapter) -> ControllerReceipt:
    try:
        receipt = adapter.controller_receipt()
    except Exception:
        raise SplitActivationEngineError("controller_receipt_unavailable") from None
    if type(receipt) is not ControllerReceipt or not receipt.journal_present:
        raise SplitActivationEngineError("controller_receipt_invalid")
    return receipt


def _worker_receipt(adapter: WorkerActivationAdapter) -> WorkerReceipt:
    try:
        receipt = adapter.worker_receipt()
    except Exception:
        raise SplitActivationEngineError("worker_receipt_unavailable") from None
    if type(receipt) is not WorkerReceipt or not receipt.journal_present:
        raise SplitActivationEngineError("worker_receipt_invalid")
    return receipt


def _optional_controller_receipt(
    adapter: ControllerActivationAdapter,
) -> ControllerReceipt | None:
    try:
        receipt = adapter.controller_receipt()
    except DiscoveryActivationError as exc:
        if exc.reason_code in {
            "controller_receipt_unavailable",
            "transaction_journal_missing",
        }:
            return None
        raise
    except Exception:
        raise SplitActivationEngineError("controller_receipt_unavailable") from None
    if type(receipt) is not ControllerReceipt or not receipt.journal_present:
        raise SplitActivationEngineError("controller_receipt_invalid")
    return receipt


def _optional_worker_receipt(adapter: WorkerActivationAdapter) -> WorkerReceipt | None:
    try:
        receipt = adapter.worker_receipt()
    except DiscoveryActivationError as exc:
        if exc.reason_code in {
            "worker_receipt_unavailable",
            "transaction_journal_missing",
        }:
            return None
        raise
    except Exception:
        raise SplitActivationEngineError("worker_receipt_unavailable") from None
    if type(receipt) is not WorkerReceipt or not receipt.journal_present:
        raise SplitActivationEngineError("worker_receipt_invalid")
    return receipt


def _classifications(
    values: tuple[tuple[str, str], ...], expected: frozenset[str], reason: str
) -> dict[str, str]:
    result = dict(values)
    if (
        len(values) != len(result)
        or set(result) != expected
        or any(
            value not in {CLASSIFICATION_CREATED, CLASSIFICATION_ADOPTED}
            for value in result.values()
        )
    ):
        raise SplitActivationEngineError(reason)
    return result


def _validate_controller_receipt_for_offer(
    adapter: ControllerActivationAdapter,
    offer: ControllerOffer,
    *,
    evidence_committed: bool,
) -> ControllerReceipt:
    """Require the live journal to completely bind the signed controller handoff."""

    receipt = _controller_receipt(adapter)
    classifications = _classifications(
        receipt.object_classifications,
        _CONTROLLER_ROLES,
        "controller_receipt_classification_invalid",
    )
    if (
        receipt.transaction_id != offer.transaction_id
        or not receipt.effects_started
        or not receipt.controller_changed
        or not receipt.controller_runtime_changed
        or not receipt.offer_emitted
        or receipt.evidence_committed is not evidence_committed
        or classifications != offer.object_classifications
    ):
        raise SplitActivationEngineError(
            "controller_evidence_receipt_mismatch"
            if evidence_committed
            else "controller_offer_receipt_mismatch"
        )
    return receipt


def _validate_worker_receipt_for_result(
    adapter: WorkerActivationAdapter, result: WorkerResult
) -> WorkerReceipt:
    """Require the live journal to completely bind the signed worker handoff."""

    receipt = _worker_receipt(adapter)
    classifications = _classifications(
        receipt.object_classifications,
        _WORKER_ROLES,
        "worker_receipt_classification_invalid",
    )
    if (
        receipt.transaction_id != result.worker_transaction_id
        or not receipt.effects_started
        or not receipt.worker_config_changed
        or not receipt.worker_recreated
        or not receipt.result_emitted
        or classifications != result.object_classifications
    ):
        raise SplitActivationEngineError("worker_result_receipt_mismatch")
    return receipt


def _build_controller_offer(
    profile: DeploymentProfile,
    plan: ActivationPlan,
    rendered: ActivationRender,
    tls_material: ValidatedTLSMaterial,
    observation: ControllerObservation,
    receipt: ControllerReceipt,
    *,
    timestamp: str,
    installation_identity: str,
) -> ControllerOffer:
    classifications = _classifications(
        receipt.object_classifications,
        _CONTROLLER_ROLES,
        "controller_classification_invalid",
    )
    if not (
        receipt.effects_started
        and receipt.controller_changed
        and receipt.controller_runtime_changed
    ):
        raise SplitActivationEngineError("controller_receipt_effects_invalid")
    controller_base_compose, controller_runtimes = _controller_runtime_evidence(
        profile, observation
    )
    # ISSUANCE requires the CURRENT head on the live controller: accepting an old signed offer must
    # never imply the new schema exists, so a new offer is only issued from a migrated controller.
    if not observation.migration_head_ready or observation.migration_head != _ISSUED_MIGRATION_HEAD:
        raise SplitActivationEngineError("controller_migration_head_unverified")
    issued = _handoff_time(timestamp)
    return ControllerOffer(
        schema="secp.discovery-activation.controller-offer/v1",
        contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        issuer_role="controller",
        sequence=1,
        predecessor_digest=None,
        transaction_id=receipt.transaction_id,
        profile_digest=rendered.manifest.profile_sha256,
        plan_digest=plan.digest(),
        render_manifest_digest=rendered.manifest.sha256,
        controller_artifact_digests=_controller_digests(rendered, tls_material),
        worker_artifact_digests={
            ROLE_WORKER_OVERRIDE: _artifact_map(rendered)["worker_compose_override"],
            ROLE_WORKER_RUNTIME_OVERLAY: _required_runtime_overlay_digest(profile),
        },
        object_classifications=classifications,
        controller_base_compose=controller_base_compose,
        controller_runtimes=controller_runtimes,
        controller_migration_head=_ISSUED_MIGRATION_HEAD,
        admission_tls=_admission_tls(tls_material.metadata),
        installation_timestamp=timestamp,
        expires_at=_timestamp(issued + timedelta(hours=24)),
        installation_identity=installation_identity,
        rollback_journal_present=True,
        internal_tls_verified=True,
        forbidden_infrastructure_contacts_performed=False,
        workflows_submitted=False,
        operator_activated=False,
        run_plan_generation_called=False,
        opentofu_executed=False,
        proxmox_contacted=False,
    )


def controller_install_operation(
    profile: DeploymentProfile,
    tls_material: ValidatedTLSMaterial,
    gate: WriteGate,
    deps: ControllerDependencies,
    *,
    installation_identity: str,
) -> OperationResult:
    """Install controller-local TLS/proxy or finalize a returned worker result."""

    operation = "controller-install"
    refusal = _require_install_inputs(operation, profile, gate, installation_identity)
    if refusal is not None:
        return refusal
    assert profile.controller_evidence_key_id is not None
    assert profile.worker_evidence_key_id is not None
    try:
        plan, rendered = _controller_render(profile, tls_material)
        operation_now = deps.clock()
        if (
            deps.handoff_signer.key_id() != profile.controller_evidence_key_id
            or deps.evidence_authenticator.key_id() != profile.controller_evidence_key_id
        ):
            return _result(operation, "refused", reason="controller_signer_pin_mismatch")

        try:
            committed = deps.adapter.load_activation_evidence()
        except DiscoveryActivationError as exc:
            return _recovery(operation, exc.reason_code)
        if committed is not None:
            try:
                details = _finalize_committed_controller_aggregate(
                    profile,
                    tls_material,
                    deps,
                    already_committed=True,
                )
                return _result(
                    operation,
                    "installed",
                    details=details,
                )
            except DiscoveryActivationError as exc:
                return _recovery(operation, exc.reason_code)
            except Exception:
                return _recovery(operation, "controller_finalization_verification_failed")

        try:
            stored_offer_raw = deps.adapter.load_fixed_controller_offer()
            worker_result_raw = deps.adapter.load_fixed_worker_result_inbox()
        except DiscoveryActivationError as exc:
            return _recovery(operation, exc.reason_code)
        if stored_offer_raw is not None:
            try:
                offer, _offer_raw, _offer_attestation = _load_controller_offer(
                    stored_offer_raw, expected_key_id=profile.controller_evidence_key_id
                )
                expected = _controller_digests(rendered, tls_material)
                _validate_offer(
                    profile,
                    plan,
                    rendered,
                    offer,
                    admission_tls=_admission_tls(tls_material.metadata),
                    expected_controller_digests=expected,
                    now=operation_now,
                )
                controller_after = deps.adapter.observe_controller(profile)
                post_reason = _controller_postcondition(profile, controller_after, expected)
                if post_reason is not None:
                    raise SplitActivationEngineError(post_reason)
                _validate_live_controller_offer(profile, controller_after, offer)
                _validate_controller_receipt_for_offer(
                    deps.adapter, offer, evidence_committed=False
                )
                fence_state = _bound_api_rollback_fence_state(profile, deps, controller_after)
                if fence_state != "engaged":
                    raise SplitActivationEngineError("api_rollback_fence_released_without_evidence")
            except DiscoveryActivationError as exc:
                return _recovery(operation, exc.reason_code)
            except Exception:
                return _recovery(operation, "controller_offer_verification_failed")
            if worker_result_raw is None:
                return _pending(
                    operation,
                    "worker_result_pending",
                    controller_offer_digest=offer.digest(),
                    controller_transaction_id=offer.transaction_id,
                )
            try:
                worker_result, _result_raw, _result_attestation = _load_worker_result(
                    worker_result_raw, expected_key_id=profile.worker_evidence_key_id
                )
                _validate_result(
                    profile,
                    plan,
                    rendered,
                    offer,
                    worker_result,
                    now=operation_now,
                )
                aggregate = _aggregate_evidence(
                    profile,
                    rendered,
                    offer,
                    worker_result,
                    timestamp=_timestamp(operation_now),
                )
                aggregate_attestation = issue_attestation(aggregate, deps.evidence_authenticator)
                # Commit the authoritative aggregate while the live API write fence is still
                # proven engaged.  This durable state is intentionally resumable: a later
                # invocation can authenticate it and perform only the remaining fence release.
                deps.adapter.commit_activation_evidence(
                    evidence_bytes(aggregate),
                    evidence_attestation_bytes(aggregate_attestation),
                )
                details = _finalize_committed_controller_aggregate(
                    profile,
                    tls_material,
                    deps,
                    expected_evidence=aggregate,
                    already_committed=False,
                )
                return _result(
                    operation,
                    "installed",
                    details=details,
                )
            except DiscoveryActivationError as exc:
                return _recovery(operation, exc.reason_code)
            except Exception:
                return _recovery(operation, "worker_result_verification_failed")
        if worker_result_raw is not None:
            return _recovery(operation, "worker_result_without_controller_offer")

        try:
            if _optional_controller_receipt(deps.adapter) is not None:
                return _recovery(operation, "interrupted_controller_transaction")
        except DiscoveryActivationError as exc:
            return _recovery(operation, exc.reason_code)

        before = deps.adapter.observe_controller(profile)
        preflight = _controller_preflight(profile, before)
        if preflight is not None:
            return _result(operation, "refused", reason=preflight)
        staged = False
        try:
            receipt = deps.adapter.stage_controller_rollback(profile, rendered, before)
            staged = True
            if type(receipt) is not ControllerReceipt or not (
                receipt.journal_present and not receipt.effects_started
            ):
                raise SplitActivationEngineError("controller_rollback_journal_invalid")
            deps.adapter.install_controller(profile, rendered, tls_material)
            if not deps.adapter.verify_controller_tls(profile, tls_material):
                raise SplitActivationEngineError("controller_tls_verification_failed")
            after = deps.adapter.observe_controller(profile)
            expected = _controller_digests(rendered, tls_material)
            post_reason = _controller_postcondition(profile, after, expected)
            if post_reason is not None:
                raise SplitActivationEngineError(post_reason)
            if _bound_api_rollback_fence_state(profile, deps, after) != "engaged":
                raise SplitActivationEngineError("api_rollback_fence_released_without_evidence")
            live = _controller_receipt(deps.adapter)
            offer = _build_controller_offer(
                profile,
                plan,
                rendered,
                tls_material,
                after,
                live,
                timestamp=_timestamp(operation_now),
                installation_identity=installation_identity,
            )
            offer_attestation = issue_handoff_attestation(offer, deps.handoff_signer)
            deps.adapter.emit_fixed_controller_offer(
                handoff_bytes(offer), handoff_attestation_bytes(offer_attestation)
            )
            _validate_controller_receipt_for_offer(deps.adapter, offer, evidence_committed=False)
            return _pending(
                operation,
                "worker_result_pending",
                controller_offer_digest=offer.digest(),
                controller_transaction_id=offer.transaction_id,
            )
        except DiscoveryActivationError as exc:
            return _controller_failure(operation, profile, deps.adapter, staged, exc.reason_code)
        except Exception:
            return _controller_failure(
                operation, profile, deps.adapter, staged, "controller_install_error"
            )
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="controller_install_error")


def _controller_failure(
    operation: str,
    profile: DeploymentProfile,
    adapter: ControllerActivationAdapter,
    staged: bool,
    reason: str,
) -> OperationResult:
    if not staged:
        return _result(operation, "refused", reason=reason)
    try:
        receipt = _controller_receipt(adapter)
        if receipt.controller_runtime_changed and not adapter.controller_api_rollback_compatible(
            profile
        ):
            return _recovery(operation, "controller_api_rollback_incompatible_state")
        compensation = adapter.compensate_controller(receipt)
    except Exception:
        return _recovery(operation, "recovery_required")
    if not (
        type(compensation) is ControllerCompensation
        and compensation.proven
        and compensation.previous_artifacts_restored
        and not compensation.residual_controller_state
    ):
        return _recovery(operation, "recovery_required")
    return _result(
        operation,
        "rolled-back",
        reason=reason,
        details={"previous_controller_artifacts_restored": True},
    )


def _build_worker_result(
    profile: DeploymentProfile,
    worker_override: RenderedArtifact,
    ca_certificate: ValidatedAdmissionCA,
    offer: ControllerOffer,
    before: WorkerObservation,
    after: WorkerObservation,
    receipt: WorkerReceipt,
    state_receipt: PreparedStateReceipt,
    state_metadata: WorkerStateMetadata,
    *,
    timestamp: str,
    installation_identity: str,
) -> WorkerResult:
    post_reason = _worker_postcondition(
        profile, before, after, _worker_digests(profile, worker_override, ca_certificate)
    )
    if post_reason is not None:
        raise SplitActivationEngineError(post_reason)
    classifications = _classifications(
        receipt.object_classifications, _WORKER_ROLES, "worker_classification_invalid"
    )
    if classifications[ROLE_WORKER_STATE] != state_receipt.classification:
        raise SplitActivationEngineError("worker_state_classification_mismatch")
    generation = after.worker_generation
    public = after.worker_public
    if generation is None or public is None:
        raise SplitActivationEngineError("worker_result_observation_incomplete")
    worker_base_compose, worker_runtime = _worker_runtime_evidence(profile, after)
    persistent = PersistentStateEvidence(
        path_binding=path_binding_digest(
            ROLE_WORKER_STATE, PRODUCTION_LAYOUT.worker_state_host_path
        ),
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
    )
    return WorkerResult(
        schema="secp.discovery-activation.worker-result/v1",
        contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        issuer_role="worker",
        sequence=2,
        predecessor_digest=offer.digest(),
        controller_offer_digest=offer.digest(),
        controller_transaction_id=offer.transaction_id,
        worker_transaction_id=receipt.transaction_id,
        profile_digest=_profile_digest(profile),
        plan_digest=offer.plan_digest,
        render_manifest_digest=offer.render_manifest_digest,
        worker_image_digest=profile.ordinary_worker_image_digest,
        worker_generation=generation,
        ordinary_task_queue=ORDINARY_TASK_QUEUE,
        worker_artifact_digests=_worker_digests(profile, worker_override, ca_certificate),
        object_classifications=classifications,
        worker_base_compose=worker_base_compose,
        worker_runtime=worker_runtime,
        persistent_state=persistent,
        admission_ca_fingerprint=ca_certificate.ca_certificate_fingerprint,
        worker_public_material=WorkerPublicEvidence(
            ssh_public_fingerprint=public.ssh_public_fingerprint,
            admission_anchor_fingerprint=public.admission_anchor_fingerprint,
            worker_discovery_node_id=public.node_id,
            worker_discovery_node_revision=public.revision,
        ),
        installation_timestamp=timestamp,
        installation_identity=installation_identity,
        rollback_journal_present=True,
        worker_healthy=True,
        mount_isolated=True,
        bundle_prep_loop_started=True,
        database_private_material_absent=True,
        operator_service_present=False,
        operator_queue_polled=after.operator_queue_polled,
        generic_activation_subprocess_sealed=True,
        generic_executor_subprocess_sealed=True,
        plan_only_process_sealed=False,
        real_provisioning_enabled=False,
        forbidden_infrastructure_contacts_performed=False,
        workflows_submitted=False,
        run_plan_generation_called=False,
        opentofu_executed=False,
        proxmox_contacted=False,
    )


def worker_install_operation(
    profile: DeploymentProfile,
    ca_certificate_pem: bytes,
    gate: WriteGate,
    deps: WorkerDependencies,
    *,
    installation_identity: str,
) -> OperationResult:
    """Authenticate an offer, then perform only the worker-local transaction."""

    operation = "worker-install"
    refusal = _require_install_inputs(operation, profile, gate, installation_identity)
    if refusal is not None:
        return refusal
    assert profile.controller_evidence_key_id is not None
    assert profile.worker_evidence_key_id is not None
    try:
        if deps.handoff_signer.key_id() != profile.worker_evidence_key_id:
            return _result(operation, "refused", reason="worker_signer_pin_mismatch")
        try:
            raw_offer = deps.adapter.load_fixed_controller_offer_inbox()
        except DiscoveryActivationError as exc:
            return _recovery(operation, exc.reason_code)
        if raw_offer is None:
            try:
                orphaned_result = deps.adapter.load_fixed_worker_result()
                interrupted = _optional_worker_receipt(deps.adapter)
            except DiscoveryActivationError as exc:
                return _recovery(operation, exc.reason_code)
            if orphaned_result is not None:
                return _recovery(operation, "controller_offer_missing")
            if interrupted is not None:
                return _recovery(operation, "interrupted_worker_transaction")
            return _pending(operation, "controller_offer_pending")
        try:
            offer, _offer_bytes, _offer_attestation = _load_controller_offer(
                raw_offer, expected_key_id=profile.controller_evidence_key_id
            )
            operation_now = deps.clock()
            ca_certificate = validate_worker_ca_certificate(ca_certificate_pem, now=operation_now)
            worker_override = render_worker_compose_override(profile)
            _validate_worker_offer(
                profile,
                worker_override,
                ca_certificate,
                offer,
                now=operation_now,
            )
        except DiscoveryActivationError as exc:
            return _recovery(operation, exc.reason_code)
        except Exception:
            return _recovery(operation, "controller_offer_verification_failed")

        try:
            existing_result_raw = deps.adapter.load_fixed_worker_result()
        except DiscoveryActivationError as exc:
            return _recovery(operation, exc.reason_code)
        if existing_result_raw is not None:
            try:
                existing, _result_bytes, _result_attestation = _load_worker_result(
                    existing_result_raw, expected_key_id=profile.worker_evidence_key_id
                )
                _validate_existing_worker_result(
                    profile,
                    worker_override,
                    ca_certificate,
                    offer,
                    existing,
                    now=operation_now,
                )
                _validate_worker_receipt_for_result(deps.adapter, existing)
                # The live journal is established before state inspection so a damaged state tree
                # on an already-emitted transaction is recovery-required, never a clean refusal.
                state = deps.state.inspect(
                    uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
                )
                observation = deps.adapter.observe_worker(profile)
                synthetic_before = _different_worker_generation(observation)
                reason = _worker_postcondition(
                    profile,
                    synthetic_before,
                    observation,
                    _worker_digests(profile, worker_override, ca_certificate),
                )
                if reason is not None:
                    raise SplitActivationEngineError(reason)
                _validate_live_worker_result(observation, state, existing)
                return _result(
                    operation,
                    "worker-result-emitted",
                    details={"worker_result_digest": existing.digest(), "already_emitted": True},
                )
            except DiscoveryActivationError as exc:
                return _recovery(operation, exc.reason_code)
            except Exception:
                return _recovery(operation, "worker_result_verification_failed")

        try:
            if _optional_worker_receipt(deps.adapter) is not None:
                return _recovery(operation, "interrupted_worker_transaction")
        except DiscoveryActivationError as exc:
            return _recovery(operation, exc.reason_code)

        # Unsafe/partial state on a genuinely new transaction is rejected before the first runtime
        # observation and before any host mutation.
        state = deps.state.inspect(
            uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
        )
        before = deps.adapter.observe_worker(profile)
        preflight = _worker_preflight(profile, before)
        if preflight is not None:
            return _result(operation, "refused", reason=preflight)
        state_receipt: PreparedStateReceipt | None = None
        staged = False
        try:
            state_receipt = deps.state.prepare(
                uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
            )
            receipt = deps.adapter.stage_worker_rollback(
                profile, worker_override, before, state_receipt=state_receipt
            )
            staged = True
            if type(receipt) is not WorkerReceipt or not (
                receipt.journal_present and not receipt.effects_started
            ):
                raise SplitActivationEngineError("worker_rollback_journal_invalid")
            deps.adapter.install_worker(profile, worker_override, ca_certificate)
            if not deps.adapter.verify_live_admission_tls(
                profile,
                ca_certificate,
                expected_server_certificate_fingerprint=(
                    offer.admission_tls.server_certificate_fingerprint
                ),
                expected_server_dns_identity=offer.admission_tls.server_dns_identity,
            ):
                raise SplitActivationEngineError("live_tls_verification_failed")
            deps.adapter.recreate_ordinary_worker(profile)
            assert before.worker_generation is not None
            after = deps.adapter.await_worker_publication(
                profile, previous_generation=before.worker_generation
            )
            post_reason = _worker_postcondition(
                profile,
                before,
                after,
                _worker_digests(profile, worker_override, ca_certificate),
            )
            if post_reason is not None:
                raise SplitActivationEngineError(post_reason)
            state_metadata = deps.state.inspect(
                uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
            )
            if not (state_metadata.prepared and state_metadata.keys_generated):
                raise SplitActivationEngineError("persistent_worker_keys_unproven")
            live = _worker_receipt(deps.adapter)
            if not (live.effects_started and live.worker_config_changed and live.worker_recreated):
                raise SplitActivationEngineError("worker_receipt_effects_invalid")
            result = _build_worker_result(
                profile,
                worker_override,
                ca_certificate,
                offer,
                before,
                after,
                live,
                state_receipt,
                state_metadata,
                timestamp=_timestamp(operation_now),
                installation_identity=installation_identity,
            )
            result_attestation = issue_handoff_attestation(result, deps.handoff_signer)
            deps.adapter.emit_fixed_worker_result(
                handoff_bytes(result), handoff_attestation_bytes(result_attestation)
            )
            _validate_worker_receipt_for_result(deps.adapter, result)
            return _result(
                operation,
                "worker-result-emitted",
                details={
                    "controller_offer_digest": offer.digest(),
                    "worker_result_digest": result.digest(),
                    "worker_transaction_id": result.worker_transaction_id,
                },
            )
        except DiscoveryActivationError as exc:
            return _worker_failure(
                operation,
                profile,
                deps,
                state_receipt=state_receipt,
                staged=staged,
                reason=exc.reason_code,
            )
        except Exception:
            return _worker_failure(
                operation,
                profile,
                deps,
                state_receipt=state_receipt,
                staged=staged,
                reason="worker_install_error",
            )
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="worker_install_error")


def _worker_failure(
    operation: str,
    profile: DeploymentProfile,
    deps: WorkerDependencies,
    *,
    state_receipt: PreparedStateReceipt | None,
    staged: bool,
    reason: str,
) -> OperationResult:
    if not staged:
        if state_receipt is not None:
            try:
                proven = deps.state.compensate(
                    state_receipt,
                    uid=profile.ordinary_runtime_uid,
                    gid=profile.ordinary_runtime_gid,
                )
            except Exception:
                proven = False
            if not proven:
                return _recovery(operation, "recovery_required")
        return _result(operation, "refused", reason=reason)
    try:
        receipt = _worker_receipt(deps.adapter)
        if receipt.worker_recreated and not deps.adapter.worker_api_rollback_compatible(profile):
            return _recovery(operation, "worker_api_rollback_incompatible_state")
        compensation = deps.adapter.compensate_worker(receipt)
    except Exception:
        return _recovery(operation, "recovery_required")
    if not (
        type(compensation) is WorkerCompensation
        and compensation.proven
        and compensation.previous_worker_restored
        and compensation.previous_artifacts_restored
    ):
        return _recovery(operation, "recovery_required")
    runtime_effect = receipt.worker_recreated
    if runtime_effect:
        try:
            retained = deps.state.inspect(
                uid=profile.ordinary_runtime_uid,
                gid=profile.ordinary_runtime_gid,
            )
        except Exception:
            return _recovery(operation, "recovery_required")
        if not (
            retained.present
            and retained.prepared
            and retained.key_directory_present
            and retained.bundle_directory_present
        ):
            return _recovery(operation, "recovery_required")
    if state_receipt is not None and not runtime_effect:
        try:
            state_proven = deps.state.compensate(
                state_receipt,
                uid=profile.ordinary_runtime_uid,
                gid=profile.ordinary_runtime_gid,
            )
        except Exception:
            state_proven = False
        if not state_proven:
            return _recovery(operation, "recovery_required")
    return _result(
        operation,
        "rolled-back",
        reason=reason,
        details={
            "previous_worker_restored": True,
            "previous_worker_artifacts_restored": True,
            "durable_worker_state_retained": bool(
                runtime_effect or compensation.residual_worker_state
            ),
        },
    )


def _aggregate_evidence(
    profile: DeploymentProfile,
    rendered: ActivationRender,
    offer: ControllerOffer,
    result: WorkerResult,
    *,
    timestamp: str,
) -> ActivationEvidence:
    controller_classes = offer.object_classifications
    worker_classes = result.object_classifications
    classifications = controller_classes | worker_classes
    expected_roles = _CONTROLLER_ROLES | _WORKER_ROLES
    if set(classifications) != expected_roles:
        raise SplitActivationEngineError("aggregate_classification_incomplete")
    digests = {
        ROLE_PROFILE: offer.profile_digest,
        ROLE_WORKER_OVERRIDE: result.worker_artifact_digests[ROLE_WORKER_OVERRIDE],
        ROLE_WORKER_RUNTIME_OVERLAY: result.worker_artifact_digests[ROLE_WORKER_RUNTIME_OVERLAY],
        ROLE_CONTROLLER_OVERRIDE: offer.controller_artifact_digests[ROLE_CONTROLLER_OVERRIDE],
        ROLE_PROXY_CONTRACT: offer.controller_artifact_digests[ROLE_PROXY_CONTRACT],
        ROLE_ADMISSION_CA: offer.controller_artifact_digests[ROLE_ADMISSION_CA],
        ROLE_ADMISSION_SERVER_CERTIFICATE: offer.controller_artifact_digests[
            ROLE_ADMISSION_SERVER_CERTIFICATE
        ],
    }
    artifacts = {artifact.name: artifact for artifact in rendered.artifacts}
    specs = (
        (ROLE_PROFILE, PRODUCTION_LAYOUT.profile_path, digests[ROLE_PROFILE], 0, 0, 0o640),
        (
            ROLE_WORKER_OVERRIDE,
            PRODUCTION_LAYOUT.worker_compose_override_path,
            digests[ROLE_WORKER_OVERRIDE],
            0,
            0,
            0o640,
        ),
        (
            ROLE_WORKER_RUNTIME_OVERLAY,
            PRODUCTION_LAYOUT.worker_runtime_overlay_path,
            digests[ROLE_WORKER_RUNTIME_OVERLAY],
            0,
            0,
            0o644,
        ),
        (
            ROLE_CONTROLLER_OVERRIDE,
            PRODUCTION_LAYOUT.controller_compose_override_path,
            digests[ROLE_CONTROLLER_OVERRIDE],
            0,
            0,
            0o640,
        ),
        (
            ROLE_PROXY_CONTRACT,
            PRODUCTION_LAYOUT.proxy_contract_path,
            digests[ROLE_PROXY_CONTRACT],
            artifacts["admission_proxy_contract"].uid,
            artifacts["admission_proxy_contract"].gid,
            artifacts["admission_proxy_contract"].mode,
        ),
        (
            ROLE_ADMISSION_CA,
            PRODUCTION_LAYOUT.ca_certificate_path,
            digests[ROLE_ADMISSION_CA],
            0,
            0,
            0o644,
        ),
        (
            ROLE_ADMISSION_SERVER_CERTIFICATE,
            PRODUCTION_LAYOUT.server_certificate_path,
            digests[ROLE_ADMISSION_SERVER_CERTIFICATE],
            0,
            0,
            0o644,
        ),
        (
            ROLE_ADMISSION_SERVER_KEY,
            PRODUCTION_LAYOUT.server_private_key_path,
            None,
            0,
            profile.admission_proxy_runtime_gid,
            0o640,
        ),
        (
            ROLE_ADMISSION_PROXY_GATE,
            PRODUCTION_LAYOUT.admission_proxy_gate_path,
            None,
            0,
            profile.admission_proxy_runtime_gid,
            0o640,
        ),
        (
            ROLE_WORKER_STATE,
            PRODUCTION_LAYOUT.worker_state_host_path,
            None,
            profile.ordinary_runtime_uid,
            profile.ordinary_runtime_gid,
            0o700,
        ),
    )
    managed = tuple(
        ManagedObjectRecord(
            role=role,
            path_binding=path_binding_digest(role, path),
            content_digest=digest,
            owner_uid=uid,
            owner_gid=gid,
            mode=mode,
            classification=classifications[role],
        )
        for role, path, digest, uid, gid, mode in specs
    )
    return ActivationEvidence(
        contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        activation_status="public-node-published",
        worker_image_digest=profile.ordinary_worker_image_digest,
        worker_generation=result.worker_generation,
        worker_base_compose=result.worker_base_compose,
        worker_runtime=result.worker_runtime,
        ordinary_task_queue=ORDINARY_TASK_QUEUE,
        configuration_artifact_digests=digests,
        managed_objects=managed,
        persistent_state=result.persistent_state,
        admission_tls=offer.admission_tls,
        worker_public_material=result.worker_public_material,
        installation_timestamp=timestamp,
        controller_installation_identity=offer.installation_identity,
        worker_installation_identity=result.installation_identity,
        operator_service_present=False,
        operator_queue_polled=result.operator_queue_polled,
        generic_activation_subprocess_sealed=True,
        generic_executor_subprocess_sealed=True,
        plan_only_process_sealed=False,
        real_provisioning_enabled=False,
        forbidden_infrastructure_contacts_performed=False,
        workflows_submitted=False,
        run_plan_generation_called=False,
        opentofu_executed=False,
        proxmox_contacted=False,
    )


def _safe_fixed_input(value: FixedInputBinding | None) -> dict[str, object] | None:
    if type(value) is not FixedInputBinding:
        return None
    return {
        "content_digest": value.content_digest,
        "owner_uid": value.owner_uid,
        "owner_gid": value.owner_gid,
        "mode": value.mode,
    }


def _safe_runtime(value: ContainerRuntimeObservation | None) -> dict[str, object] | None:
    if type(value) is not ContainerRuntimeObservation:
        return None
    generation = value.generation
    return {
        "present": value.present,
        "generation": (
            {
                "container_id": generation.container_id,
                "restart_count": generation.restart_count,
                "started_at": generation.started_at,
                "generation_digest": generation.digest(),
            }
            if generation is not None
            else None
        ),
        "image_digest": value.image_digest,
        "configuration_digest": value.configuration_digest,
        "mounts_digest": value.mounts_digest,
        "networks_digest": value.networks_digest,
        "compose_project": value.compose_project,
        "compose_service": value.compose_service,
        "expected_image": value.expected_image,
        "hardening_verified": value.hardening_verified,
        "mounts_verified": value.mounts_verified,
        "endpoint_binding_verified": value.endpoint_binding_verified,
    }


def _safe_controller_observation(observation: ControllerObservation) -> dict[str, object]:
    return {
        "inspected": observation.inspected,
        "coherent": observation.coherent,
        "recovery_required": observation.recovery_required,
        "controller_config_installed": observation.controller_config_installed,
        "proxy_running": observation.proxy_running,
        "proxy_healthy": observation.proxy_healthy,
        "private_listener_only": observation.private_listener_only,
        "activation_route_enabled": observation.activation_route_enabled,
        "tls_ready": observation.tls_ready,
        "base_compose_binding": _safe_fixed_input(observation.base_compose_binding),
        "api_runtime": _safe_runtime(observation.api_runtime),
        "admission_proxy_runtime": _safe_runtime(observation.proxy_runtime),
        "migration_head": observation.migration_head,
        "migration_head_ready": observation.migration_head_ready,
        "configuration_artifact_digests": dict(observation.configuration_artifact_digests),
    }


def _safe_worker_observation(observation: WorkerObservation) -> dict[str, object]:
    generation = observation.worker_generation
    public = observation.worker_public
    return {
        "inspected": observation.inspected,
        "coherent": observation.coherent,
        "recovery_required": observation.recovery_required,
        "artifacts_prepared": observation.artifacts_prepared,
        "worker_config_installed": observation.worker_config_installed,
        "worker_recreation_required": observation.worker_recreation_required,
        "worker_present": observation.worker_present,
        "worker_generation": (
            {
                "container_id": generation.container_id,
                "restart_count": generation.restart_count,
                "started_at": generation.started_at,
                "generation_digest": generation.digest(),
            }
            if generation is not None
            else None
        ),
        "worker_image_digest": observation.worker_image_digest,
        "base_compose_binding": _safe_fixed_input(observation.base_compose_binding),
        "worker_runtime": _safe_runtime(observation.worker_runtime),
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
        "ca_mount_read_only_worker": observation.ca_mount_read_only_worker,
        "bundle_prep_loop_started": observation.bundle_prep_loop_started,
        "operator_absent": observation.operator_absent(),
        "safety_seals_valid": observation.safety_seals_valid(),
        "tls_ready": observation.tls_ready,
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
            if public is not None
            else None
        ),
        "database_private_material_absent": observation.database_private_material_absent,
        "bootstrap_status": observation.bootstrap_status,
        "worker_identity_approved": observation.worker_identity_approved,
        "live_read_authorization_approved": (observation.live_read_authorization_approved),
        "bundle_ready": observation.bundle_ready,
        "discovery_contacted": observation.discovery_contacted,
        "candidate_executable": observation.candidate_executable,
        "configuration_artifact_digests": dict(observation.configuration_artifact_digests),
    }


def _worker_status_observation(
    profile: DeploymentProfile, observation: WorkerObservation
) -> ActivationObservation:
    public = observation.worker_public
    return ActivationObservation(
        coherent=observation.coherent,
        activation_enabled=profile.activation_enabled,
        artifacts_prepared=observation.artifacts_prepared,
        tls_ready=observation.tls_ready,
        worker_config_installed=observation.worker_config_installed,
        worker_recreation_required=observation.worker_recreation_required,
        worker_generation_changed=observation.worker_generation_changed,
        worker_running=observation.worker_running,
        worker_healthy=observation.worker_healthy,
        ordinary_queue_exact=observation.ordinary_queues == (ORDINARY_TASK_QUEUE,),
        b8_flags_enabled=(
            observation.controlled_integration_enabled and observation.worker_managed_bundle_enabled
        ),
        required_paths_present=(
            observation.fixed_worker_paths and observation.ca_mount_read_only_worker
        ),
        state_mount_isolated=(
            observation.state_mount_read_write_only_worker
            and observation.discovery_mount_absent_from_other_containers
        ),
        bundle_loop_started=observation.bundle_prep_loop_started,
        operator_absent=observation.operator_absent(),
        safety_seals_valid=observation.safety_seals_valid(),
        keys_generated=observation.keys_generated,
        key_metadata_safe=observation.key_metadata_safe,
        public_node_id=public.node_id if public is not None else None,
        public_node_revision=public.revision if public is not None else None,
        public_node_public_only=bool(public and public.public_material_only),
        publication_recorded=observation.publication_recorded,
        bootstrap_status=observation.bootstrap_status,
        worker_identity_approved=observation.worker_identity_approved,
        live_read_authorization_approved=observation.live_read_authorization_approved,
        bundle_ready=observation.bundle_ready,
        discovery_contacted=observation.discovery_contacted,
        candidate_executable=observation.candidate_executable,
        recovery_required=observation.recovery_required,
    )


def _load_verified_activation_evidence(
    profile: DeploymentProfile, deps: ControllerDependencies
) -> ActivationEvidence:
    raw = deps.adapter.load_activation_evidence()
    if raw is None:
        raise SplitActivationEngineError("activation_evidence_missing")
    evidence_raw, attestation_raw = _parse_pair(raw, kind="activation_evidence")
    evidence = parse_evidence_bytes(evidence_raw)
    attestation = parse_evidence_attestation(attestation_raw)
    verify_evidence(
        evidence,
        attestation,
        deps.evidence_trust_root,
        expected_key_id=profile.controller_evidence_key_id,
    )
    return evidence


def _bound_api_rollback_fence_state(
    profile: DeploymentProfile,
    deps: ControllerDependencies,
    controller_observation: ControllerObservation,
) -> ApiRollbackFenceState:
    """Return an exact live fence state bound to the verified API generation and migration."""

    api_runtime = controller_observation.api_runtime
    generation = None if api_runtime is None else api_runtime.generation
    fence = deps.adapter.observe_api_rollback_fence(profile)
    if (
        type(fence) is not ApiRollbackFenceObservation
        or fence.observation_complete is not True
        or fence.state not in {"engaged", "released"}
        or generation is None
        or fence.api_container_id != generation.container_id
        or fence.migration_head not in _ACCEPTED_MIGRATION_HEADS
        or fence.migration_head != controller_observation.migration_head
    ):
        raise SplitActivationEngineError("api_rollback_fence_unverified")
    return fence.state


def _verify_committed_controller_aggregate(
    profile: DeploymentProfile,
    tls_material: ValidatedTLSMaterial,
    deps: ControllerDependencies,
) -> _VerifiedControllerFinalization:
    """Independently authenticate the durable aggregate and its complete live handoff chain."""

    evidence = _load_verified_activation_evidence(profile, deps)
    plan, rendered = _controller_render(profile, tls_material)
    raw_offer = deps.adapter.load_fixed_controller_offer()
    raw_result = deps.adapter.load_fixed_worker_result_inbox()
    if raw_offer is None:
        raise SplitActivationEngineError("controller_offer_missing")
    if raw_result is None:
        raise SplitActivationEngineError("worker_result_missing")
    assert profile.controller_evidence_key_id is not None
    assert profile.worker_evidence_key_id is not None
    offer, _offer_raw, _offer_attestation = _load_controller_offer(
        raw_offer, expected_key_id=profile.controller_evidence_key_id
    )
    worker_result, _result_raw, _result_attestation = _load_worker_result(
        raw_result, expected_key_id=profile.worker_evidence_key_id
    )
    expected_controller = _controller_digests(rendered, tls_material)
    _validate_offer(
        profile,
        plan,
        rendered,
        offer,
        admission_tls=_admission_tls(tls_material.metadata),
        expected_controller_digests=expected_controller,
        now=None,
    )
    _validate_result(profile, plan, rendered, offer, worker_result, now=None)
    _validate_controller_receipt_for_offer(deps.adapter, offer, evidence_committed=True)
    expected_evidence = _aggregate_evidence(
        profile,
        rendered,
        offer,
        worker_result,
        timestamp=evidence.installation_timestamp,
    )
    if expected_evidence.canonical() != evidence.canonical():
        raise SplitActivationEngineError("aggregate_evidence_chain_mismatch")
    controller_observation = deps.adapter.observe_controller(profile)
    reason = _controller_postcondition(profile, controller_observation, expected_controller)
    if reason is not None:
        raise SplitActivationEngineError(reason)
    _validate_live_controller_offer(profile, controller_observation, offer)
    return _VerifiedControllerFinalization(
        evidence=evidence,
        offer=offer,
        worker_result=worker_result,
        controller_observation=controller_observation,
    )


def _controller_finalization_details(
    verified: _VerifiedControllerFinalization,
    *,
    fence_state: ApiRollbackFenceState,
    already_committed: bool,
) -> dict[str, object]:
    details: dict[str, object] = {
        "evidence_digest": verified.evidence.digest(),
        "controller_offer_digest": verified.offer.digest(),
        "worker_result_digest": verified.worker_result.digest(),
        "worker_discovery_node_id": (
            verified.worker_result.worker_public_material.worker_discovery_node_id
        ),
        "worker_discovery_node_revision": (
            verified.worker_result.worker_public_material.worker_discovery_node_revision
        ),
        "api_rollback_fence_state": fence_state,
    }
    if already_committed:
        details["already_committed"] = True
    return details


def _finalize_committed_controller_aggregate(
    profile: DeploymentProfile,
    tls_material: ValidatedTLSMaterial,
    deps: ControllerDependencies,
    *,
    expected_evidence: ActivationEvidence | None = None,
    already_committed: bool,
) -> dict[str, object]:
    """Resume evidence-first finalization and prove the durable released state."""

    verified = _verify_committed_controller_aggregate(profile, tls_material, deps)
    if (
        expected_evidence is not None
        and verified.evidence.canonical() != expected_evidence.canonical()
    ):
        raise SplitActivationEngineError("committed_evidence_mismatch")
    fence_state = _bound_api_rollback_fence_state(profile, deps, verified.controller_observation)
    if fence_state == "engaged":
        deps.adapter.release_api_rollback_fence(profile)
        # Command success is not finalization proof.  Reauthenticate the complete durable chain,
        # refresh the live controller observation, and independently observe the exact fence.
        verified = _verify_committed_controller_aggregate(profile, tls_material, deps)
        if (
            expected_evidence is not None
            and verified.evidence.canonical() != expected_evidence.canonical()
        ):
            raise SplitActivationEngineError("committed_evidence_mismatch")
        fence_state = _bound_api_rollback_fence_state(
            profile, deps, verified.controller_observation
        )
    if fence_state != "released":
        raise SplitActivationEngineError("api_rollback_fence_not_released")
    return _controller_finalization_details(
        verified, fence_state="released", already_committed=already_committed
    )


def controller_inspect_operation(
    profile: DeploymentProfile, deps: ControllerDependencies
) -> OperationResult:
    """Read one bounded controller-local observation without touching a receipt or outbox."""

    operation = "controller-inspect"
    try:
        observation = deps.adapter.observe_controller(profile)
        if type(observation) is not ControllerObservation:
            raise SplitActivationEngineError("controller_observation_type_invalid")
        return _result(
            operation,
            "inspected",
            details=_safe_controller_observation(observation),
        )
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="controller_observation_failed")


def worker_inspect_operation(
    profile: DeploymentProfile, deps: WorkerDependencies
) -> OperationResult:
    """Validate fixed worker state before returning a bounded runtime observation."""

    operation = "worker-inspect"
    try:
        state = deps.state.inspect(
            uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
        )
        observation = deps.adapter.observe_worker(profile)
        if type(observation) is not WorkerObservation:
            raise SplitActivationEngineError("worker_observation_type_invalid")
        observation = replace(
            observation,
            keys_generated=state.keys_generated,
            key_metadata_safe=bool(observation.key_metadata_safe and state.prepared),
        )
        details = _safe_worker_observation(observation)
        details["persistent_state"] = state.canonical()
        return _result(operation, "inspected", details=details)
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="worker_observation_failed")


def controller_evidence_operation(
    profile: DeploymentProfile, deps: ControllerDependencies
) -> OperationResult:
    """Authenticate aggregate evidence before exposing classifications or ownership facts."""

    operation = "controller-evidence"
    try:
        evidence = _load_verified_activation_evidence(profile, deps)
        return _result(
            operation,
            "verified",
            details={
                "evidence": evidence.canonical(),
                "evidence_digest": evidence.digest(),
                "authenticated": True,
            },
        )
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="evidence_verification_failed")


def controller_verify_operation(
    profile: DeploymentProfile,
    tls_material: ValidatedTLSMaterial,
    deps: ControllerDependencies,
) -> OperationResult:
    """Verify local controller state and the complete authenticated split-host chain."""

    operation = "controller-verify"
    try:
        verified = _verify_committed_controller_aggregate(profile, tls_material, deps)
        fence_state = _bound_api_rollback_fence_state(
            profile, deps, verified.controller_observation
        )
        if fence_state != "released":
            raise SplitActivationEngineError("api_rollback_fence_not_released")
        return _result(
            operation,
            "verified",
            details=_controller_finalization_details(
                verified,
                fence_state=fence_state,
                already_committed=False,
            ),
        )
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="controller_verification_failed")


def worker_evidence_operation(
    profile: DeploymentProfile,
    ca_certificate_pem: bytes,
    deps: WorkerDependencies,
) -> OperationResult:
    """Authenticate the controller/worker handoff chain before exposing worker evidence."""

    operation = "worker-evidence"
    try:
        raw_offer = deps.adapter.load_fixed_controller_offer_inbox()
        raw_result = deps.adapter.load_fixed_worker_result()
        if raw_offer is None:
            return _pending(operation, "controller_offer_pending")
        if raw_result is None:
            return _pending(operation, "worker_result_pending")
        assert profile.controller_evidence_key_id is not None
        assert profile.worker_evidence_key_id is not None
        offer, _offer_raw, _offer_attestation = _load_controller_offer(
            raw_offer, expected_key_id=profile.controller_evidence_key_id
        )
        result, _result_raw, _result_attestation = _load_worker_result(
            raw_result, expected_key_id=profile.worker_evidence_key_id
        )
        ca_certificate = validate_worker_ca_certificate(ca_certificate_pem, now=deps.clock())
        worker_override = render_worker_compose_override(profile)
        _validate_worker_offer(profile, worker_override, ca_certificate, offer, now=None)
        _validate_existing_worker_result(
            profile,
            worker_override,
            ca_certificate,
            offer,
            result,
            now=None,
        )
        return _result(
            operation,
            "verified",
            details={
                "worker_result": result.canonical(),
                "controller_offer_digest": offer.digest(),
                "worker_result_digest": result.digest(),
                "authenticated": True,
            },
        )
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="worker_evidence_verification_failed")


def worker_verify_operation(
    profile: DeploymentProfile,
    ca_certificate_pem: bytes,
    deps: WorkerDependencies,
) -> OperationResult:
    """Verify safe state, local runtime, CA-only trust, and both signed handoffs."""

    operation = "worker-verify"
    try:
        raw_offer = deps.adapter.load_fixed_controller_offer_inbox()
        raw_result = deps.adapter.load_fixed_worker_result()
        if raw_offer is None:
            raise SplitActivationEngineError("controller_offer_missing")
        if raw_result is None:
            raise SplitActivationEngineError("worker_result_missing")
        assert profile.controller_evidence_key_id is not None
        assert profile.worker_evidence_key_id is not None
        offer, _offer_raw, _offer_attestation = _load_controller_offer(
            raw_offer, expected_key_id=profile.controller_evidence_key_id
        )
        result, _result_raw, _result_attestation = _load_worker_result(
            raw_result, expected_key_id=profile.worker_evidence_key_id
        )
        ca_certificate = validate_worker_ca_certificate(ca_certificate_pem, now=deps.clock())
        worker_override = render_worker_compose_override(profile)
        _validate_worker_offer(profile, worker_override, ca_certificate, offer, now=None)
        _validate_existing_worker_result(
            profile,
            worker_override,
            ca_certificate,
            offer,
            result,
            now=None,
        )
        _validate_worker_receipt_for_result(deps.adapter, result)
        # The fixed-layout state check precedes the runtime observation just as it does for install.
        state = deps.state.inspect(
            uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
        )
        observation = deps.adapter.observe_worker(profile)
        synthetic_before = _different_worker_generation(observation)
        reason = _worker_postcondition(
            profile,
            synthetic_before,
            observation,
            _worker_digests(profile, worker_override, ca_certificate),
        )
        if reason is not None:
            raise SplitActivationEngineError(reason)
        _validate_live_worker_result(observation, state, result)
        return _result(
            operation,
            "verified",
            details={
                "worker_result_digest": result.digest(),
                "worker_generation_digest": result.worker_generation.digest(),
                "worker_discovery_node_id": result.worker_public_material.worker_discovery_node_id,
                "worker_discovery_node_revision": (
                    result.worker_public_material.worker_discovery_node_revision
                ),
            },
        )
    except DiscoveryActivationError as exc:
        return _result(operation, "refused", reason=exc.reason_code)
    except Exception:
        return _result(operation, "refused", reason="worker_verification_failed")


def controller_status_operation(
    profile: DeploymentProfile,
    tls_material: ValidatedTLSMaterial | None,
    deps: ControllerDependencies,
) -> OperationResult:
    """Report controller-local progress without advancing the transaction."""

    operation = "controller-status"
    try:
        observation = deps.adapter.observe_controller(profile)
        if type(observation) is not ControllerObservation or not observation.coherent:
            return _recovery(operation, "controller_observation_incoherent")
        if observation.recovery_required:
            return _recovery(operation, "recovery_not_proven")
        receipt = _optional_controller_receipt(deps.adapter)
        raw_offer = deps.adapter.load_fixed_controller_offer()
        raw_result = deps.adapter.load_fixed_worker_result_inbox()
        committed = deps.adapter.load_activation_evidence()
        if not profile.activation_enabled:
            installed = bool(
                receipt is not None
                or raw_offer is not None
                or raw_result is not None
                or committed is not None
                or _controller_transaction_effects(profile, observation)
            )
            if installed:
                return _recovery(operation, "activation_false_with_installed_effects")
            return _result(operation, DISABLED, reason="activation_false")
        if type(tls_material) is not ValidatedTLSMaterial:
            raise SplitActivationEngineError("production_tls_material_unavailable")
        if committed is not None:
            verified = _verify_committed_controller_aggregate(profile, tls_material, deps)
            fence_state = _bound_api_rollback_fence_state(
                profile, deps, verified.controller_observation
            )
            details = _controller_finalization_details(
                verified,
                fence_state=fence_state,
                already_committed=True,
            )
            if fence_state == "engaged":
                return _result(
                    operation,
                    AWAITING_FINALIZATION,
                    reason="aggregate_evidence_verified_fence_engaged",
                    details=details,
                )
            return _result(
                operation,
                PUBLIC_NODE_PUBLISHED,
                reason="aggregate_evidence_verified",
                details=details,
            )
        plan, rendered = _controller_render(profile, tls_material)
        if raw_offer is None:
            if receipt is not None:
                return _recovery(operation, "interrupted_controller_transaction")
            if raw_result is not None:
                return _recovery(operation, "controller_offer_missing")
            if _controller_transaction_effects(profile, observation):
                return _recovery(operation, "controller_transaction_receipt_missing")
            return _result(operation, PREPARED, reason="controller_artifacts_not_installed")
        assert profile.controller_evidence_key_id is not None
        offer, _offer_raw, _offer_attestation = _load_controller_offer(
            raw_offer, expected_key_id=profile.controller_evidence_key_id
        )
        expected = _controller_digests(rendered, tls_material)
        _validate_offer(
            profile,
            plan,
            rendered,
            offer,
            admission_tls=_admission_tls(tls_material.metadata),
            expected_controller_digests=expected,
            now=deps.clock() if raw_result is None else None,
        )
        _validate_controller_receipt_for_offer(deps.adapter, offer, evidence_committed=False)
        reason = _controller_postcondition(profile, observation, expected)
        if reason is not None:
            return _recovery(operation, reason)
        _validate_live_controller_offer(profile, observation, offer)
        if _bound_api_rollback_fence_state(profile, deps, observation) != "engaged":
            return _recovery(operation, "api_rollback_fence_released_without_evidence")
        if raw_result is None:
            return _result(
                operation,
                TLS_READY,
                reason="worker_result_pending",
                details={"controller_offer_digest": offer.digest()},
            )
        assert profile.worker_evidence_key_id is not None
        result, _result_raw, _result_attestation = _load_worker_result(
            raw_result, expected_key_id=profile.worker_evidence_key_id
        )
        _validate_result(profile, plan, rendered, offer, result, now=deps.clock())
        return _result(
            operation,
            PUBLIC_NODE_PUBLISHED,
            reason="aggregate_evidence_pending",
            details={
                "worker_result_digest": result.digest(),
                "worker_discovery_node_id": result.worker_public_material.worker_discovery_node_id,
                "worker_discovery_node_revision": (
                    result.worker_public_material.worker_discovery_node_revision
                ),
            },
        )
    except DiscoveryActivationError as exc:
        return _recovery(operation, exc.reason_code)
    except Exception:
        return _recovery(operation, "controller_status_failed")


def worker_status_operation(
    profile: DeploymentProfile,
    ca_certificate_pem: bytes | None,
    deps: WorkerDependencies,
) -> OperationResult:
    """Derive the worker lifecycle from one coherent observation."""

    operation = "worker-status"
    try:
        state = deps.state.inspect(
            uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
        )
        observation = deps.adapter.observe_worker(profile)
        if type(observation) is not WorkerObservation:
            raise SplitActivationEngineError("worker_observation_type_invalid")
        observation = replace(
            observation,
            keys_generated=state.keys_generated,
            key_metadata_safe=bool(observation.key_metadata_safe and state.prepared),
        )
        raw_offer = deps.adapter.load_fixed_controller_offer_inbox()
        raw_result = deps.adapter.load_fixed_worker_result()
        receipt = _optional_worker_receipt(deps.adapter)
        if not profile.activation_enabled:
            if (
                receipt is not None
                or raw_result is not None
                or _worker_transaction_effects(observation)
            ):
                return _recovery(operation, "activation_false_with_installed_effects")
            report = derive_status(_worker_status_observation(profile, observation))
            details = report.canonical()
            details["persistent_state"] = state.canonical()
            return _result(
                operation,
                report.state,
                reason=report.findings[0] if report.findings else None,
                recovery=report.state == RECOVERY_REQUIRED,
                details=details,
            )
        if profile.activation_enabled and raw_offer is not None:
            if type(ca_certificate_pem) is not bytes:
                raise SplitActivationEngineError("production_tls_ca_unavailable")
            assert profile.controller_evidence_key_id is not None
            offer, _offer_raw, _offer_attestation = _load_controller_offer(
                raw_offer, expected_key_id=profile.controller_evidence_key_id
            )
            ca_certificate = validate_worker_ca_certificate(ca_certificate_pem, now=deps.clock())
            worker_override = render_worker_compose_override(profile)
            _validate_worker_offer(
                profile,
                worker_override,
                ca_certificate,
                offer,
                now=deps.clock() if raw_result is None else None,
            )
            if raw_result is not None:
                assert profile.worker_evidence_key_id is not None
                result, _result_raw, _result_attestation = _load_worker_result(
                    raw_result, expected_key_id=profile.worker_evidence_key_id
                )
                _validate_existing_worker_result(
                    profile,
                    worker_override,
                    ca_certificate,
                    offer,
                    result,
                    now=None,
                )
                _validate_worker_receipt_for_result(deps.adapter, result)
                _validate_live_worker_result(observation, state, result)
            elif receipt is not None:
                raise SplitActivationEngineError("interrupted_worker_transaction")
            elif _worker_transaction_effects(observation):
                raise SplitActivationEngineError("worker_transaction_receipt_missing")
        elif profile.activation_enabled:
            if receipt is not None:
                raise SplitActivationEngineError("interrupted_worker_transaction")
            if raw_result is not None:
                raise SplitActivationEngineError("controller_offer_missing")
            if _worker_transaction_effects(observation):
                raise SplitActivationEngineError("worker_transaction_receipt_missing")
        report = derive_status(_worker_status_observation(profile, observation))
        details = report.canonical()
        details["persistent_state"] = state.canonical()
        return _result(
            operation,
            report.state,
            reason=report.findings[0] if report.findings else None,
            recovery=report.state == RECOVERY_REQUIRED,
            details=details,
        )
    except DiscoveryActivationError as exc:
        return _recovery(operation, exc.reason_code)
    except Exception:
        return _recovery(operation, "worker_status_failed")


def controller_rollback_operation(
    profile: DeploymentProfile, gate: WriteGate, deps: ControllerDependencies
) -> OperationResult:
    operation = "controller-rollback"
    refusal = gate.refusal_reason()
    if refusal is not None:
        return _result(operation, "refused", reason=refusal)
    try:
        raw = deps.adapter.load_activation_evidence()
        receipt = _optional_controller_receipt(deps.adapter)
        if receipt is None:
            if raw is not None or _controller_transaction_effects(
                profile, deps.adapter.observe_controller(profile)
            ):
                return _recovery(operation, "controller_receipt_unavailable")
            return _result(operation, "refused", reason="controller_transaction_missing")
        if raw is None:
            if receipt.evidence_committed:
                return _recovery(operation, "committed_evidence_missing")
            if (
                receipt.controller_runtime_changed
                and not deps.adapter.controller_api_rollback_compatible(profile)
            ):
                return _recovery(operation, "controller_api_rollback_incompatible_state")
            result = deps.adapter.compensate_controller(receipt)
        else:
            evidence_raw, attestation_raw = _parse_pair(raw, kind="activation_evidence")
            evidence = parse_evidence_bytes(evidence_raw)
            attestation = parse_evidence_attestation(attestation_raw)
            verify_evidence(
                evidence,
                attestation,
                deps.evidence_trust_root,
                expected_key_id=profile.controller_evidence_key_id,
            )
            raw_offer = deps.adapter.load_fixed_controller_offer()
            if raw_offer is None:
                return _recovery(operation, "controller_offer_missing")
            assert profile.controller_evidence_key_id is not None
            offer, _offer_raw, _offer_attestation = _load_controller_offer(
                raw_offer, expected_key_id=profile.controller_evidence_key_id
            )
            receipt = _validate_controller_receipt_for_offer(
                deps.adapter, offer, evidence_committed=True
            )
            if (
                offer.profile_digest != _profile_digest(profile)
                or offer.admission_tls != evidence.admission_tls
                or any(
                    evidence.configuration_artifact_digests.get(role) != digest
                    for role, digest in offer.controller_artifact_digests.items()
                )
                or offer.installation_identity != evidence.controller_installation_identity
            ):
                return _recovery(operation, "controller_offer_binding_mismatch")
            if not deps.adapter.controller_api_rollback_compatible(profile):
                return _recovery(operation, "controller_api_rollback_incompatible_state")
            _validate_live_controller_offer(
                profile, deps.adapter.observe_controller(profile), offer
            )
            result = deps.adapter.rollback_controller_committed(evidence, receipt)
        if not (
            type(result) is ControllerCompensation
            and result.proven
            and result.previous_artifacts_restored
            and not result.residual_controller_state
        ):
            return _recovery(operation, "recovery_required")
        return _result(operation, "rolled-back")
    except DiscoveryActivationError as exc:
        return _recovery(operation, exc.reason_code)
    except Exception:
        return _recovery(operation, "recovery_required")


def worker_rollback_operation(
    profile: DeploymentProfile, gate: WriteGate, deps: WorkerDependencies
) -> OperationResult:
    operation = "worker-rollback"
    refusal = gate.refusal_reason()
    if refusal is not None:
        return _result(operation, "refused", reason=refusal)
    try:
        raw = deps.adapter.load_fixed_worker_result()
        receipt = _optional_worker_receipt(deps.adapter)
        if receipt is None:
            if raw is not None or _worker_transaction_effects(deps.adapter.observe_worker(profile)):
                return _recovery(operation, "worker_receipt_unavailable")
            return _result(operation, "refused", reason="worker_transaction_missing")
        if raw is None:
            if receipt.result_emitted:
                return _recovery(operation, "worker_result_missing")
            if receipt.worker_recreated and not deps.adapter.worker_api_rollback_compatible(
                profile
            ):
                return _recovery(operation, "worker_api_rollback_incompatible_state")
            result = deps.adapter.compensate_worker(receipt)
        else:
            assert profile.worker_evidence_key_id is not None
            signed_result, _result_raw, _result_attestation = _load_worker_result(
                raw, expected_key_id=profile.worker_evidence_key_id
            )
            receipt = _validate_worker_receipt_for_result(deps.adapter, signed_result)
            if signed_result.profile_digest != _profile_digest(profile):
                return _recovery(operation, "worker_result_binding_mismatch")
            if not deps.adapter.worker_api_rollback_compatible(profile):
                return _recovery(operation, "worker_api_rollback_incompatible_state")
            state = deps.state.inspect(
                uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
            )
            _validate_live_worker_result(deps.adapter.observe_worker(profile), state, signed_result)
            result = deps.adapter.rollback_worker_committed(receipt)
        if not (
            type(result) is WorkerCompensation
            and result.proven
            and result.previous_worker_restored
            and result.previous_artifacts_restored
        ):
            return _recovery(operation, "recovery_required")
        return _result(
            operation,
            "rolled-back",
            details={"durable_worker_state_retained": result.residual_worker_state},
        )
    except DiscoveryActivationError as exc:
        return _recovery(operation, exc.reason_code)
    except Exception:
        return _recovery(operation, "recovery_required")


def _different_worker_generation(observation: WorkerObservation) -> WorkerObservation:
    generation = observation.worker_generation
    if generation is None:
        return observation
    replacement = "0" * 64 if generation.container_id != "0" * 64 else "1" * 64
    return replace(
        observation,
        worker_generation=type(generation)(
            container_id=replacement,
            restart_count=generation.restart_count,
            started_at=generation.started_at,
        ),
    )


def _timestamp(value: datetime) -> str:
    return _aware_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise SplitActivationEngineError("clock_not_timezone_aware")
    return value.astimezone(UTC)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


__all__ = [
    "SplitActivationEngineError",
    "ControllerDependencies",
    "WorkerDependencies",
    "validate_worker_ca_certificate",
    "controller_install_operation",
    "worker_install_operation",
    "controller_inspect_operation",
    "worker_inspect_operation",
    "controller_verify_operation",
    "worker_verify_operation",
    "controller_status_operation",
    "worker_status_operation",
    "controller_evidence_operation",
    "worker_evidence_operation",
    "controller_rollback_operation",
    "worker_rollback_operation",
]
