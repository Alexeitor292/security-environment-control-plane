"""Role-local adapter boundaries for the two-host B8 activation protocol.

The controller and ordinary worker are different hosts.  These protocols deliberately expose
only operations that can be performed on the named local host.  Cross-host coordination is by
authenticated bytes in code-owned inbox/outbox locations; neither side receives a path, argv,
URL, service name, or generic transport from an operator.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal, Protocol

from secp_discovery_activation import DiscoveryActivationError
from secp_discovery_activation.adapters import (
    ContainerRuntimeObservation,
    FixedInputBinding,
)
from secp_discovery_activation.evidence import (
    ROLE_WORKER_RUNTIME_OVERLAY,
    ActivationEvidence,
    WorkerGeneration,
)
from secp_discovery_activation.profile import DeploymentProfile
from secp_discovery_activation.render import ActivationRender, RenderedArtifact
from secp_discovery_activation.state import PreparedStateReceipt
from secp_discovery_activation.tls import ValidatedAdmissionCA, ValidatedTLSMaterial


class SplitActivationAdapterError(DiscoveryActivationError):
    """A closed role-local deployment operation failed."""


@dataclass(frozen=True)
class ControllerObservation:
    """Bounded controller-host facts; no raw inspection or TLS material is retained."""

    inspected: bool = False
    coherent: bool = False
    recovery_required: bool = False
    controller_config_installed: bool = False
    proxy_running: bool = False
    proxy_healthy: bool = False
    private_listener_only: bool = False
    activation_route_enabled: bool = False
    tls_ready: bool = False
    base_compose_binding: FixedInputBinding | None = None
    api_runtime: ContainerRuntimeObservation | None = None
    proxy_runtime: ContainerRuntimeObservation | None = None
    migration_head: str | None = None
    migration_head_ready: bool = False
    configuration_artifact_digests: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ControllerReceipt:
    """Nonsecret binding to the controller host's private rollback journal."""

    transaction_id: str
    journal_present: bool
    effects_started: bool
    controller_changed: bool
    offer_emitted: bool
    evidence_committed: bool
    operation_count: int
    controller_runtime_changed: bool = False
    object_classifications: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ControllerCompensation:
    proven: bool
    previous_artifacts_restored: bool
    residual_controller_state: bool
    reason_code: str | None = None


ApiRollbackFenceState = Literal["engaged", "released", "unverified"]


@dataclass(frozen=True)
class ApiRollbackFenceObservation:
    """One closed fence state bound to an exact live API generation and migration."""

    observation_complete: bool = False
    state: ApiRollbackFenceState = "unverified"
    api_container_id: str | None = None
    migration_head: str | None = None


@dataclass(frozen=True)
class WorkerNodeObservation:
    """The public-only control-plane projection of an ordinary worker node."""

    node_id: str
    revision: int
    ssh_public_fingerprint: str
    admission_anchor_fingerprint: str
    public_material_only: bool


@dataclass(frozen=True)
class WorkerObservation:
    """Bounded ordinary-worker-host facts used by pre/postcondition checks."""

    inspected: bool = False
    coherent: bool = False
    recovery_required: bool = False
    artifacts_prepared: bool = False
    worker_config_installed: bool = False
    worker_recreation_required: bool = False
    worker_generation_changed: bool = False
    worker_present: bool = False
    worker_generation: WorkerGeneration | None = None
    worker_image_digest: str | None = None
    base_compose_binding: FixedInputBinding | None = None
    worker_runtime: ContainerRuntimeObservation | None = None
    worker_running: bool = False
    worker_healthy: bool = False
    ordinary_queues: tuple[str, ...] = ()
    controlled_integration_enabled: bool = False
    worker_managed_bundle_enabled: bool = False
    fixed_worker_paths: bool = False
    state_mount_read_write_only_worker: bool = False
    ca_mount_read_only_worker: bool = False
    discovery_mount_absent_from_other_containers: bool = False
    bundle_prep_loop_started: bool = False
    operator_service_present: bool = True
    operator_container_present: bool = True
    operator_registration_present: bool = True
    operator_queue_polled: bool = True
    generic_activation_subprocess_sealed: bool = False
    generic_executor_subprocess_sealed: bool = False
    plan_only_process_sealed: bool = True
    real_provisioning_enabled: bool = True
    tls_ready: bool = False
    keys_generated: bool = False
    key_metadata_safe: bool = False
    worker_public: WorkerNodeObservation | None = None
    publication_recorded: bool = False
    database_private_material_absent: bool = False
    bootstrap_status: str | None = None
    worker_identity_approved: bool = False
    live_read_authorization_approved: bool = False
    bundle_ready: bool = False
    discovery_contacted: bool = False
    candidate_executable: bool | None = None
    configuration_artifact_digests: tuple[tuple[str, str], ...] = ()

    def operator_absent(self) -> bool:
        return not (
            self.operator_service_present
            or self.operator_container_present
            or self.operator_registration_present
            or self.operator_queue_polled
        )

    def safety_seals_valid(self) -> bool:
        return bool(
            self.generic_activation_subprocess_sealed
            and self.generic_executor_subprocess_sealed
            and self.plan_only_process_sealed is False
            and self.real_provisioning_enabled is False
        )


@dataclass(frozen=True)
class WorkerReceipt:
    """Nonsecret binding to the worker host's private rollback journal."""

    transaction_id: str
    journal_present: bool
    effects_started: bool
    worker_config_changed: bool
    worker_recreated: bool
    result_emitted: bool
    operation_count: int
    object_classifications: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class WorkerCompensation:
    proven: bool
    previous_worker_restored: bool
    previous_artifacts_restored: bool
    residual_worker_state: bool
    reason_code: str | None = None


class ControllerActivationAdapter(Protocol):
    """Closed controller-host boundary; it has no ordinary-worker mutation methods."""

    def observe_controller(self, profile: DeploymentProfile) -> ControllerObservation: ...

    def stage_controller_rollback(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: ControllerObservation,
    ) -> ControllerReceipt: ...

    def install_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None: ...

    def verify_controller_tls(
        self, profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
    ) -> bool: ...

    def emit_fixed_controller_offer(self, offer: bytes, attestation: bytes) -> None: ...

    def load_fixed_controller_offer(self) -> tuple[bytes, bytes] | None: ...

    def load_fixed_worker_result_inbox(self) -> tuple[bytes, bytes] | None: ...

    def controller_receipt(self) -> ControllerReceipt: ...

    def compensate_controller(self, receipt: ControllerReceipt) -> ControllerCompensation: ...

    def commit_activation_evidence(self, evidence: bytes, attestation: bytes) -> None: ...

    def load_activation_evidence(self) -> tuple[bytes, bytes] | None: ...

    def observe_api_rollback_fence(
        self, profile: DeploymentProfile
    ) -> ApiRollbackFenceObservation: ...

    def controller_api_rollback_compatible(self, profile: DeploymentProfile) -> bool: ...

    def release_api_rollback_fence(self, profile: DeploymentProfile) -> None: ...

    def rollback_controller_committed(
        self, evidence: ActivationEvidence, receipt: ControllerReceipt
    ) -> ControllerCompensation: ...


class WorkerActivationAdapter(Protocol):
    """Closed worker-host boundary; it has no controller mutation methods."""

    def load_fixed_controller_offer_inbox(self) -> tuple[bytes, bytes] | None: ...

    def load_fixed_worker_result(self) -> tuple[bytes, bytes] | None: ...

    def observe_worker(self, profile: DeploymentProfile) -> WorkerObservation: ...

    def stage_worker_rollback(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        before: WorkerObservation,
        *,
        state_receipt: PreparedStateReceipt,
    ) -> WorkerReceipt: ...

    def install_worker(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        ca_certificate: ValidatedAdmissionCA,
    ) -> None: ...

    def verify_live_admission_tls(
        self,
        profile: DeploymentProfile,
        ca_certificate: ValidatedAdmissionCA,
        *,
        expected_server_certificate_fingerprint: str,
        expected_server_dns_identity: str,
    ) -> bool: ...

    def recreate_ordinary_worker(self, profile: DeploymentProfile) -> None: ...

    def await_worker_publication(
        self, profile: DeploymentProfile, *, previous_generation: WorkerGeneration
    ) -> WorkerObservation: ...

    def emit_fixed_worker_result(self, result: bytes, attestation: bytes) -> None: ...

    def worker_receipt(self) -> WorkerReceipt: ...

    def compensate_worker(self, receipt: WorkerReceipt) -> WorkerCompensation: ...

    def worker_api_rollback_compatible(self, profile: DeploymentProfile) -> bool: ...

    def rollback_worker_committed(self, receipt: WorkerReceipt) -> WorkerCompensation: ...


@dataclass
class InMemoryControllerActivationAdapter:
    """Deterministic controller-only fake for state-machine tests."""

    before: ControllerObservation
    after: ControllerObservation
    fail_on: str | None = None
    compensation_proven: bool = True
    rollback_compatible: bool = True
    operations: list[str] = field(default_factory=list)
    controller_offer: tuple[bytes, bytes] | None = None
    worker_result_inbox: tuple[bytes, bytes] | None = None
    activation_evidence: tuple[bytes, bytes] | None = None
    rollback_fence_state: ApiRollbackFenceState = "engaged"
    fence_observation_complete: bool = True
    fence_api_container_id: str | None = None
    fence_migration_head: str | None = None
    _receipt: ControllerReceipt | None = None

    def _fail(self, operation: str) -> None:
        if self.fail_on == operation:
            raise SplitActivationAdapterError("injected_" + operation + "_failure")

    def observe_controller(self, profile: DeploymentProfile) -> ControllerObservation:
        self.operations.append("observe_controller")
        self._fail("observe_controller")
        return self.before if self._receipt is None else self.after

    def stage_controller_rollback(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: ControllerObservation,
    ) -> ControllerReceipt:
        self.operations.append("stage_controller_rollback")
        self._fail("stage_controller_rollback")
        self._receipt = ControllerReceipt(
            transaction_id="00000000-0000-4000-8000-000000000101",
            journal_present=True,
            effects_started=False,
            controller_changed=False,
            offer_emitted=False,
            evidence_committed=False,
            operation_count=0,
            object_classifications=(
                ("activation_profile", "adopted"),
                ("controller_compose_override", "created"),
                ("admission_proxy_contract", "created"),
                ("admission_ca_certificate", "created"),
                ("admission_server_certificate", "created"),
                ("admission_server_key", "created"),
                ("admission_proxy_gate", "created"),
            ),
        )
        return self._receipt

    def _record(
        self,
        operation: str,
        *,
        controller_changed: bool = False,
        controller_runtime_changed: bool = False,
        offer_emitted: bool = False,
        evidence_committed: bool = False,
    ) -> None:
        self.operations.append(operation)
        self._fail(operation)
        if self._receipt is None:
            raise SplitActivationAdapterError("controller_journal_missing")
        self._receipt = replace(
            self._receipt,
            effects_started=True,
            operation_count=self._receipt.operation_count + 1,
            controller_changed=self._receipt.controller_changed or controller_changed,
            controller_runtime_changed=(
                self._receipt.controller_runtime_changed or controller_runtime_changed
            ),
            offer_emitted=self._receipt.offer_emitted or offer_emitted,
            evidence_committed=self._receipt.evidence_committed or evidence_committed,
        )

    def install_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None:
        self._record(
            "install_controller",
            controller_changed=True,
            controller_runtime_changed=True,
        )

    def verify_controller_tls(
        self, profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
    ) -> bool:
        self.operations.append("verify_controller_tls")
        self._fail("verify_controller_tls")
        return self.after.tls_ready

    def emit_fixed_controller_offer(self, offer: bytes, attestation: bytes) -> None:
        self._record("emit_fixed_controller_offer", offer_emitted=True)
        self.controller_offer = (bytes(offer), bytes(attestation))

    def load_fixed_controller_offer(self) -> tuple[bytes, bytes] | None:
        self.operations.append("load_fixed_controller_offer")
        return self.controller_offer

    def load_fixed_worker_result_inbox(self) -> tuple[bytes, bytes] | None:
        self.operations.append("load_fixed_worker_result_inbox")
        return self.worker_result_inbox

    def controller_receipt(self) -> ControllerReceipt:
        self.operations.append("controller_receipt")
        if self._receipt is None:
            raise SplitActivationAdapterError("controller_receipt_unavailable")
        return self._receipt

    def compensate_controller(self, receipt: ControllerReceipt) -> ControllerCompensation:
        self.operations.append("compensate_controller")
        self._fail("compensate_controller")
        return ControllerCompensation(
            proven=self.compensation_proven,
            previous_artifacts_restored=self.compensation_proven,
            residual_controller_state=not self.compensation_proven,
            reason_code=None if self.compensation_proven else "injected_unproven_compensation",
        )

    def commit_activation_evidence(self, evidence: bytes, attestation: bytes) -> None:
        self._record("commit_activation_evidence", evidence_committed=True)
        self.activation_evidence = (bytes(evidence), bytes(attestation))

    def load_activation_evidence(self) -> tuple[bytes, bytes] | None:
        self.operations.append("load_activation_evidence")
        return self.activation_evidence

    def observe_api_rollback_fence(self, profile: DeploymentProfile) -> ApiRollbackFenceObservation:
        self.operations.append("observe_api_rollback_fence")
        self._fail("observe_api_rollback_fence")
        runtime = self.after.api_runtime
        generation = None if runtime is None else runtime.generation
        return ApiRollbackFenceObservation(
            observation_complete=self.fence_observation_complete,
            state=self.rollback_fence_state,
            api_container_id=(
                self.fence_api_container_id
                if self.fence_api_container_id is not None
                else None
                if generation is None
                else generation.container_id
            ),
            migration_head=(
                self.fence_migration_head
                if self.fence_migration_head is not None
                else self.after.migration_head
            ),
        )

    def controller_api_rollback_compatible(self, profile: DeploymentProfile) -> bool:
        self.operations.append("controller_api_rollback_compatible")
        self._fail("controller_api_rollback_compatible")
        return self.rollback_compatible

    def release_api_rollback_fence(self, profile: DeploymentProfile) -> None:
        self.operations.append("release_api_rollback_fence")
        self._fail("release_api_rollback_fence")
        self.rollback_fence_state = "released"

    def rollback_controller_committed(
        self, evidence: ActivationEvidence, receipt: ControllerReceipt
    ) -> ControllerCompensation:
        self.operations.append("rollback_controller_committed")
        return self.compensate_controller(receipt)


@dataclass
class InMemoryWorkerActivationAdapter:
    """Deterministic worker-only fake for state-machine tests."""

    before: WorkerObservation
    after: WorkerObservation
    controller_offer_inbox: tuple[bytes, bytes] | None = None
    fail_on: str | None = None
    compensation_proven: bool = True
    rollback_compatible: bool = True
    operations: list[str] = field(default_factory=list)
    worker_result: tuple[bytes, bytes] | None = None
    _receipt: WorkerReceipt | None = None

    def _fail(self, operation: str) -> None:
        if self.fail_on == operation:
            raise SplitActivationAdapterError("injected_" + operation + "_failure")

    def load_fixed_controller_offer_inbox(self) -> tuple[bytes, bytes] | None:
        self.operations.append("load_fixed_controller_offer_inbox")
        return self.controller_offer_inbox

    def load_fixed_worker_result(self) -> tuple[bytes, bytes] | None:
        self.operations.append("load_fixed_worker_result")
        return self.worker_result

    def observe_worker(self, profile: DeploymentProfile) -> WorkerObservation:
        self.operations.append("observe_worker")
        self._fail("observe_worker")
        return self.before if self._receipt is None else self.after

    def stage_worker_rollback(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        before: WorkerObservation,
        *,
        state_receipt: PreparedStateReceipt,
    ) -> WorkerReceipt:
        self.operations.append("stage_worker_rollback")
        self._fail("stage_worker_rollback")
        self._receipt = WorkerReceipt(
            transaction_id="00000000-0000-4000-8000-000000000201",
            journal_present=True,
            effects_started=False,
            worker_config_changed=False,
            worker_recreated=False,
            result_emitted=False,
            operation_count=0,
            object_classifications=(
                ("worker_compose_override", "created"),
                (ROLE_WORKER_RUNTIME_OVERLAY, "created"),
                ("worker_state", state_receipt.classification),
            ),
        )
        return self._receipt

    def _record(
        self,
        operation: str,
        *,
        worker_config_changed: bool = False,
        worker_recreated: bool = False,
        result_emitted: bool = False,
    ) -> None:
        self.operations.append(operation)
        self._fail(operation)
        if self._receipt is None:
            raise SplitActivationAdapterError("worker_journal_missing")
        self._receipt = replace(
            self._receipt,
            effects_started=True,
            operation_count=self._receipt.operation_count + 1,
            worker_config_changed=self._receipt.worker_config_changed or worker_config_changed,
            worker_recreated=self._receipt.worker_recreated or worker_recreated,
            result_emitted=self._receipt.result_emitted or result_emitted,
        )

    def install_worker(
        self,
        profile: DeploymentProfile,
        worker_override: RenderedArtifact,
        ca_certificate: ValidatedAdmissionCA,
    ) -> None:
        self._record("install_worker", worker_config_changed=True)

    def verify_live_admission_tls(
        self,
        profile: DeploymentProfile,
        ca_certificate: ValidatedAdmissionCA,
        *,
        expected_server_certificate_fingerprint: str,
        expected_server_dns_identity: str,
    ) -> bool:
        self.operations.append("verify_live_admission_tls")
        self._fail("verify_live_admission_tls")
        return self.after.tls_ready

    def recreate_ordinary_worker(self, profile: DeploymentProfile) -> None:
        self._record("recreate_ordinary_worker", worker_recreated=True)

    def await_worker_publication(
        self, profile: DeploymentProfile, *, previous_generation: WorkerGeneration
    ) -> WorkerObservation:
        self.operations.append("await_worker_publication")
        self._fail("await_worker_publication")
        return self.after

    def emit_fixed_worker_result(self, result: bytes, attestation: bytes) -> None:
        self._record("emit_fixed_worker_result", result_emitted=True)
        self.worker_result = (bytes(result), bytes(attestation))

    def worker_receipt(self) -> WorkerReceipt:
        self.operations.append("worker_receipt")
        if self._receipt is None:
            raise SplitActivationAdapterError("worker_receipt_unavailable")
        return self._receipt

    def compensate_worker(self, receipt: WorkerReceipt) -> WorkerCompensation:
        self.operations.append("compensate_worker")
        self._fail("compensate_worker")
        return WorkerCompensation(
            proven=self.compensation_proven,
            previous_worker_restored=self.compensation_proven,
            previous_artifacts_restored=self.compensation_proven,
            residual_worker_state=receipt.worker_recreated,
            reason_code=None if self.compensation_proven else "injected_unproven_compensation",
        )

    def worker_api_rollback_compatible(self, profile: DeploymentProfile) -> bool:
        self.operations.append("worker_api_rollback_compatible")
        self._fail("worker_api_rollback_compatible")
        return self.rollback_compatible

    def rollback_worker_committed(self, receipt: WorkerReceipt) -> WorkerCompensation:
        self.operations.append("rollback_worker_committed")
        return self.compensate_worker(receipt)


__all__ = [
    "SplitActivationAdapterError",
    "ControllerObservation",
    "ControllerReceipt",
    "ControllerCompensation",
    "ApiRollbackFenceState",
    "ApiRollbackFenceObservation",
    "WorkerNodeObservation",
    "WorkerObservation",
    "WorkerReceipt",
    "WorkerCompensation",
    "ControllerActivationAdapter",
    "WorkerActivationAdapter",
    "InMemoryControllerActivationAdapter",
    "InMemoryWorkerActivationAdapter",
]
