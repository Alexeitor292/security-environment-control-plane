"""Closed runtime seams for transactional B8 activation.

The engine consumes typed, bounded observations and typed receipts.  It never accepts an argv,
service name, filesystem path, Compose file, URL, or generic command from a caller.  The shipped
default refuses mutation; tests use the in-memory adapter.  A production local-Compose adapter is
composed separately from the profile's independently pinned executables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from secp_discovery_activation import DiscoveryActivationError
from secp_discovery_activation.evidence import (
    ROLE_WORKER_RUNTIME_OVERLAY,
    ActivationEvidence,
    WorkerGeneration,
)
from secp_discovery_activation.profile import DeploymentProfile
from secp_discovery_activation.render import ActivationRender
from secp_discovery_activation.status import ActivationObservation
from secp_discovery_activation.tls import ValidatedTLSMaterial


class ActivationAdapterError(DiscoveryActivationError):
    """A closed deployment adapter operation failed."""


@dataclass(frozen=True)
class WorkerPublicObservation:
    """Only the public database projection needed for post-activation proof."""

    node_id: str
    revision: int
    ssh_public_fingerprint: str
    admission_anchor_fingerprint: str
    public_material_only: bool


@dataclass(frozen=True)
class FixedInputBinding:
    """Safe content/metadata binding for a fixed, adopted deployment input."""

    content_digest: str
    owner_uid: int
    owner_gid: int
    mode: int


@dataclass(frozen=True)
class ContainerRuntimeObservation:
    """Nonsecret identity/configuration projection for one live container generation."""

    present: bool = False
    generation: WorkerGeneration | None = None
    image_digest: str | None = None
    configuration_digest: str | None = None
    # Root-local rollback binding over the complete Docker configuration.  This is deliberately
    # excluded from reprs and every evidence/status/handoff serializer: unlike the public digest,
    # it may bind credential-bearing environment values.  The production adapter computes it as
    # a domain-separated MAC with a host-local key and persists it only in the 0600 journal.
    private_configuration_binding: str | None = field(default=None, repr=False, compare=False)
    mounts_digest: str | None = None
    networks_digest: str | None = None
    compose_project: str | None = None
    compose_service: str | None = None
    expected_image: bool = False
    hardening_verified: bool = False
    mounts_verified: bool = False
    endpoint_binding_verified: bool = False

    def verified(self) -> bool:
        return bool(
            self.present
            and self.generation is not None
            and self.image_digest is not None
            and self.configuration_digest is not None
            and self.mounts_digest is not None
            and self.networks_digest is not None
            and self.compose_project
            and self.compose_service
            and self.expected_image
            and self.hardening_verified
            and self.mounts_verified
        )


@dataclass(frozen=True)
class HostObservation:
    """One coherent, secret-free controller+worker observation.

    A concrete adapter may gather these facts with several bounded local probes, but it must
    generation-check before/after and return ``coherent=False`` if any observed generation changes.
    No raw environment or container-inspect payload is retained here.
    """

    inspected: bool = False
    coherent: bool = False
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
    artifacts_prepared: bool = False
    worker_config_installed: bool = False
    worker_recreation_required: bool = False
    worker_generation_changed: bool = False
    configuration_artifact_digests: tuple[tuple[str, str], ...] = ()
    keys_generated: bool = False
    key_metadata_safe: bool = False
    worker_public: WorkerPublicObservation | None = None
    publication_recorded: bool = False
    database_private_material_absent: bool = False
    bootstrap_status: str | None = None
    worker_identity_approved: bool = False
    live_read_authorization_approved: bool = False
    bundle_ready: bool = False
    discovery_contacted: bool = False
    candidate_executable: bool | None = None
    recovery_required: bool = False

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

    def status_observation(self, *, activation_enabled: bool) -> ActivationObservation:
        public = self.worker_public
        return ActivationObservation(
            coherent=self.coherent,
            activation_enabled=activation_enabled,
            artifacts_prepared=self.artifacts_prepared,
            tls_ready=self.tls_ready,
            worker_config_installed=self.worker_config_installed,
            worker_recreation_required=self.worker_recreation_required,
            worker_generation_changed=self.worker_generation_changed,
            worker_running=self.worker_running,
            worker_healthy=self.worker_healthy,
            ordinary_queue_exact=self.ordinary_queues == ("secp-orchestration",),
            b8_flags_enabled=(
                self.controlled_integration_enabled and self.worker_managed_bundle_enabled
            ),
            required_paths_present=self.fixed_worker_paths and self.ca_mount_read_only_worker,
            state_mount_isolated=(
                self.state_mount_read_write_only_worker
                and self.discovery_mount_absent_from_other_containers
            ),
            bundle_loop_started=self.bundle_prep_loop_started,
            operator_absent=self.operator_absent(),
            safety_seals_valid=self.safety_seals_valid(),
            keys_generated=self.keys_generated,
            key_metadata_safe=self.key_metadata_safe,
            public_node_id=public.node_id if public else None,
            public_node_revision=public.revision if public else None,
            public_node_public_only=bool(public and public.public_material_only),
            publication_recorded=self.publication_recorded,
            bootstrap_status=self.bootstrap_status,
            worker_identity_approved=self.worker_identity_approved,
            live_read_authorization_approved=self.live_read_authorization_approved,
            bundle_ready=self.bundle_ready,
            discovery_contacted=self.discovery_contacted,
            candidate_executable=self.candidate_executable,
            recovery_required=self.recovery_required,
        )


@dataclass(frozen=True)
class MutationReceipt:
    """Bound, nonsecret receipt handle; rollback content remains private to the adapter journal."""

    transaction_id: str
    journal_present: bool
    effects_started: bool
    controller_changed: bool
    worker_config_changed: bool
    worker_recreated: bool
    evidence_committed: bool
    operation_count: int
    controller_runtime_changed: bool = False
    object_classifications: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CompensationResult:
    proven: bool
    previous_worker_restored: bool
    previous_artifacts_restored: bool
    residual_worker_state: bool
    reason_code: str | None = None


class ActivationAdapter(Protocol):
    """The complete closed deployment boundary used by :mod:`engine`."""

    def observe(self, profile: DeploymentProfile) -> HostObservation: ...

    def stage_rollback(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: HostObservation,
        *,
        state_receipt: dict[str, object],
    ) -> MutationReceipt: ...

    def install_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None: ...

    def verify_internal_tls(
        self, profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
    ) -> bool: ...

    def install_worker(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None: ...

    def recreate_worker(self, profile: DeploymentProfile) -> None: ...

    def await_worker_publication(
        self, profile: DeploymentProfile, *, previous_generation: WorkerGeneration
    ) -> HostObservation: ...

    def receipt(self) -> MutationReceipt: ...

    def compensate(self, receipt: MutationReceipt) -> CompensationResult: ...

    def commit_evidence(self, evidence: bytes, attestation: bytes) -> None: ...

    def load_evidence(self) -> tuple[bytes, bytes] | None: ...

    def rollback_committed(
        self, evidence: ActivationEvidence, receipt: MutationReceipt
    ) -> CompensationResult: ...


class SealedActivationAdapter:
    """Shipped fail-closed fallback.  It can report unavailable state but cannot mutate."""

    def observe(self, profile: DeploymentProfile) -> HostObservation:
        return HostObservation()

    def stage_rollback(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: HostObservation,
        *,
        state_receipt: dict[str, object],
    ) -> MutationReceipt:
        raise ActivationAdapterError("activation_adapter_not_provisioned")

    def install_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None:
        raise ActivationAdapterError("activation_adapter_not_provisioned")

    def verify_internal_tls(
        self, profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
    ) -> bool:
        return False

    def install_worker(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None:
        raise ActivationAdapterError("activation_adapter_not_provisioned")

    def recreate_worker(self, profile: DeploymentProfile) -> None:
        raise ActivationAdapterError("activation_adapter_not_provisioned")

    def await_worker_publication(
        self, profile: DeploymentProfile, *, previous_generation: WorkerGeneration
    ) -> HostObservation:
        return HostObservation()

    def receipt(self) -> MutationReceipt:
        return MutationReceipt("sealed", False, False, False, False, False, False, 0)

    def compensate(self, receipt: MutationReceipt) -> CompensationResult:
        return CompensationResult(True, True, True, False)

    def commit_evidence(self, evidence: bytes, attestation: bytes) -> None:
        raise ActivationAdapterError("activation_adapter_not_provisioned")

    def load_evidence(self) -> tuple[bytes, bytes] | None:
        return None

    def rollback_committed(
        self, evidence: ActivationEvidence, receipt: MutationReceipt
    ) -> CompensationResult:
        raise ActivationAdapterError("activation_adapter_not_provisioned")


@dataclass
class InMemoryActivationAdapter:
    """Stateful fake used to prove the engine's ordering and compensation semantics."""

    before: HostObservation
    after: HostObservation
    fail_on: str | None = None
    malformed_receipt: bool = False
    compensation_proven: bool = True
    rollback_restores_worker: bool = True
    rollback_restores_artifacts: bool = True
    operations: list[str] = field(default_factory=list)
    _receipt: MutationReceipt | None = None
    _evidence: tuple[bytes, bytes] | None = None

    def _fail(self, operation: str) -> None:
        if self.fail_on == operation:
            raise ActivationAdapterError("injected_" + operation + "_failure")

    def observe(self, profile: DeploymentProfile) -> HostObservation:
        self.operations.append("observe")
        self._fail("observe")
        return self.before if self._receipt is None else self.after

    def stage_rollback(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        before: HostObservation,
        *,
        state_receipt: dict[str, object],
    ) -> MutationReceipt:
        self.operations.append("stage_rollback")
        self._fail("stage_rollback")
        self._receipt = MutationReceipt(
            transaction_id="00000000-0000-4000-8000-000000000001",
            journal_present=True,
            effects_started=False,
            controller_changed=False,
            worker_config_changed=False,
            worker_recreated=False,
            evidence_committed=False,
            operation_count=0,
            object_classifications=(
                ("activation_profile", "adopted"),
                ("worker_compose_override", "created"),
                (ROLE_WORKER_RUNTIME_OVERLAY, "created"),
                ("controller_compose_override", "created"),
                ("admission_proxy_contract", "created"),
                ("admission_ca_certificate", "created"),
                ("admission_server_certificate", "created"),
                ("admission_server_key", "created"),
                ("admission_proxy_gate", "created"),
                (
                    "worker_state",
                    str(state_receipt.get("classification", "created")),
                ),
            ),
        )
        return self._receipt

    def _record(self, operation: str, **updates: bool) -> None:
        self.operations.append(operation)
        self._fail(operation)
        if self._receipt is None:
            raise ActivationAdapterError("transaction_journal_missing")
        values = self._receipt.__dict__ | {
            "effects_started": True,
            "operation_count": self._receipt.operation_count + 1,
            **updates,
        }
        self._receipt = MutationReceipt(**values)

    def install_controller(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None:
        self._record("install_controller", controller_changed=True)

    def verify_internal_tls(
        self, profile: DeploymentProfile, tls_material: ValidatedTLSMaterial
    ) -> bool:
        self.operations.append("verify_internal_tls")
        self._fail("verify_internal_tls")
        return self.after.tls_ready

    def install_worker(
        self,
        profile: DeploymentProfile,
        rendered: ActivationRender,
        tls_material: ValidatedTLSMaterial,
    ) -> None:
        self._record("install_worker", worker_config_changed=True)

    def recreate_worker(self, profile: DeploymentProfile) -> None:
        self._record("recreate_worker", worker_recreated=True)

    def await_worker_publication(
        self, profile: DeploymentProfile, *, previous_generation: WorkerGeneration
    ) -> HostObservation:
        self.operations.append("await_worker_publication")
        self._fail("await_worker_publication")
        return self.after

    def receipt(self) -> MutationReceipt:
        self.operations.append("receipt")
        if self.malformed_receipt or self._receipt is None:
            raise ActivationAdapterError("transaction_receipt_unavailable")
        return self._receipt

    def compensate(self, receipt: MutationReceipt) -> CompensationResult:
        self.operations.append("compensate")
        self._fail("compensate")
        return CompensationResult(
            proven=self.compensation_proven,
            previous_worker_restored=self.rollback_restores_worker,
            previous_artifacts_restored=self.rollback_restores_artifacts,
            residual_worker_state=self.after.keys_generated,
            reason_code=None if self.compensation_proven else "injected_unproven_rollback",
        )

    def commit_evidence(self, evidence: bytes, attestation: bytes) -> None:
        self._record("commit_evidence", evidence_committed=True)
        self._evidence = (bytes(evidence), bytes(attestation))

    def load_evidence(self) -> tuple[bytes, bytes] | None:
        self.operations.append("load_evidence")
        return self._evidence

    def rollback_committed(
        self, evidence: ActivationEvidence, receipt: MutationReceipt
    ) -> CompensationResult:
        self.operations.append("rollback_committed")
        return self.compensate(receipt)


__all__ = [
    "ActivationAdapterError",
    "WorkerPublicObservation",
    "HostObservation",
    "MutationReceipt",
    "CompensationResult",
    "ActivationAdapter",
    "SealedActivationAdapter",
    "InMemoryActivationAdapter",
]
