"""Hermetic proofs for the controller/worker split activation state machine."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
import secp_discovery_activation.split_engine as split_engine
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION
from secp_discovery_activation.adapters import ContainerRuntimeObservation, FixedInputBinding
from secp_discovery_activation.engine import WriteGate
from secp_discovery_activation.evidence import (
    EvidenceTrustAnchor,
    EvidenceTrustRoot,
    WorkerGeneration,
    parse_evidence_bytes,
)
from secp_discovery_activation.handoff import (
    attestation_bytes as handoff_attestation_bytes,
)
from secp_discovery_activation.handoff import (
    handoff_bytes,
    issue_handoff_attestation,
    parse_worker_result,
)
from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE
from secp_discovery_activation.profile import parse_deployment_profile
from secp_discovery_activation.split_adapters import (
    ControllerObservation,
    InMemoryControllerActivationAdapter,
    InMemoryWorkerActivationAdapter,
    WorkerNodeObservation,
    WorkerObservation,
)
from secp_discovery_activation.split_engine import (
    ControllerDependencies,
    WorkerDependencies,
    controller_evidence_operation,
    controller_inspect_operation,
    controller_install_operation,
    controller_rollback_operation,
    controller_status_operation,
    controller_verify_operation,
    worker_evidence_operation,
    worker_inspect_operation,
    worker_install_operation,
    worker_rollback_operation,
    worker_status_operation,
    worker_verify_operation,
)
from secp_discovery_activation.state import InMemoryWorkerStateFilesystem
from secp_discovery_activation.tls import (
    generate_tls_material,
    import_admission_ca,
)

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
GATE = WriteGate(write=True, confirm=True)


class _Signer:
    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.generate()
        self._public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def key_id(self) -> str:
        return "sha256:" + hashlib.sha256(self._public).hexdigest()

    def public_key_hex(self) -> str:
        return self._public.hex()

    def attest(self, message: bytes) -> str:
        return self._private.sign(message).hex()

    def trust_root(self) -> EvidenceTrustRoot:
        return EvidenceTrustRoot(
            anchors=(EvidenceTrustAnchor(self.key_id(), self.public_key_hex()),),
            test_only=True,
        )


def _profile(controller: _Signer, worker: _Signer):  # noqa: ANN202
    return parse_deployment_profile(
        {
            "contract_version": PACKAGE_CONTRACT_VERSION,
            "activation_enabled": True,
            "ordinary_worker_image_digest": "sha256:" + "1" * 64,
            "worker_runtime_overlay_digest": "sha256:" + "5" * 64,
            "ordinary_runtime_uid": 1001,
            "ordinary_runtime_gid": 1001,
            "worker_node_organization": "11111111-1111-4111-8111-111111111111",
            "worker_node_label": "worker-test-01",
            "admission_endpoint": "https://admission.internal.test:8443",
            "admission_listener_bind": "10.20.30.40:8443",
            "controller_api_upstream": "http://api:8080",
            "controller_compose_project": "secp-controller",
            "worker_compose_project": "secp-worker",
            "admission_certificate_dns_name": "admission.internal.test",
            "admission_proxy_image": (
                "registry.internal.test/secp/admission-proxy@sha256:" + "2" * 64
            ),
            "admission_proxy_runtime_image_digest": "sha256:" + "8" * 64,
            "controller_api_baseline_image_digest": "sha256:" + "7" * 64,
            "controller_api_runtime_image_digest": "sha256:" + "9" * 64,
            "controller_api_image": "registry.internal.test/secp/api@sha256:" + "6" * 64,
            "admission_proxy_runtime_uid": 1002,
            "admission_proxy_runtime_gid": 1002,
            "controller_evidence_key_id": controller.key_id(),
            "worker_evidence_key_id": worker.key_id(),
            "container_runtime_executable": "/usr/bin/docker",
            "container_runtime_executable_digest": "sha256:" + "3" * 64,
            "compose_executable": "/usr/libexec/docker/cli-plugins/docker-compose",
            "compose_executable_digest": "sha256:" + "4" * 64,
        }
    )


def _generation(character: str, minute: int) -> WorkerGeneration:
    return WorkerGeneration(
        container_id=character * 64,
        restart_count=minute,
        started_at=f"2026-07-19T12:{minute:02d}:00Z",
    )


def _base_compose() -> FixedInputBinding:
    return FixedInputBinding(
        content_digest="sha256:" + "f" * 64,
        owner_uid=0,
        owner_gid=0,
        mode=0o640,
    )


def _runtime(
    *,
    generation: WorkerGeneration,
    image_digest: str,
    service: str,
    mounts_verified: bool = True,
    endpoint_binding_verified: bool = False,
) -> ContainerRuntimeObservation:
    return ContainerRuntimeObservation(
        present=True,
        generation=generation,
        image_digest=image_digest,
        configuration_digest="sha256:" + "a" * 64,
        mounts_digest="sha256:" + "b" * 64,
        networks_digest="sha256:" + "c" * 64,
        compose_project=("secp-worker" if service == "worker" else "secp-controller"),
        compose_service=service,
        expected_image=True,
        hardening_verified=True,
        mounts_verified=mounts_verified,
        endpoint_binding_verified=endpoint_binding_verified,
    )


def _worker_before(profile) -> WorkerObservation:  # noqa: ANN001
    generation = _generation("a", 0)
    return WorkerObservation(
        inspected=True,
        coherent=True,
        worker_present=True,
        worker_generation=generation,
        worker_image_digest=profile.ordinary_worker_image_digest,
        base_compose_binding=_base_compose(),
        worker_runtime=_runtime(
            generation=generation,
            image_digest=profile.ordinary_worker_image_digest,
            service="worker",
            mounts_verified=False,
        ),
        worker_running=True,
        worker_healthy=True,
        ordinary_queues=(ORDINARY_TASK_QUEUE,),
        discovery_mount_absent_from_other_containers=True,
        operator_service_present=False,
        operator_container_present=False,
        operator_registration_present=False,
        operator_queue_polled=False,
        generic_activation_subprocess_sealed=True,
        generic_executor_subprocess_sealed=True,
        plan_only_process_sealed=False,
        real_provisioning_enabled=False,
    )


def _controller_after(profile, tls) -> ControllerObservation:  # noqa: ANN001
    _plan, rendered = split_engine._controller_render(profile, tls)
    return ControllerObservation(
        inspected=True,
        coherent=True,
        controller_config_installed=True,
        proxy_running=True,
        proxy_healthy=True,
        private_listener_only=True,
        activation_route_enabled=True,
        tls_ready=True,
        base_compose_binding=_base_compose(),
        api_runtime=_runtime(
            generation=_generation("c", 0),
            image_digest=profile.controller_api_runtime_image_digest,
            service="api",
        ),
        proxy_runtime=_runtime(
            generation=_generation("d", 0),
            image_digest=profile.admission_proxy_runtime_image_digest,
            service="discovery-admission-proxy",
        ),
        migration_head="b6e2f4a9c1d7",
        migration_head_ready=True,
        configuration_artifact_digests=tuple(
            split_engine._controller_digests(rendered, tls).items()
        ),
    )


def _worker_after(profile, ca_certificate) -> WorkerObservation:  # noqa: ANN001
    worker_override = split_engine.render_worker_compose_override(profile)
    generation = _generation("b", 1)
    return WorkerObservation(
        inspected=True,
        coherent=True,
        artifacts_prepared=True,
        worker_config_installed=True,
        worker_generation_changed=True,
        worker_present=True,
        worker_generation=generation,
        worker_image_digest=profile.ordinary_worker_image_digest,
        base_compose_binding=_base_compose(),
        worker_runtime=_runtime(
            generation=generation,
            image_digest=profile.ordinary_worker_image_digest,
            service="worker",
            endpoint_binding_verified=True,
        ),
        worker_running=True,
        worker_healthy=True,
        ordinary_queues=(ORDINARY_TASK_QUEUE,),
        controlled_integration_enabled=True,
        worker_managed_bundle_enabled=True,
        fixed_worker_paths=True,
        state_mount_read_write_only_worker=True,
        ca_mount_read_only_worker=True,
        discovery_mount_absent_from_other_containers=True,
        bundle_prep_loop_started=True,
        operator_service_present=False,
        operator_container_present=False,
        operator_registration_present=False,
        operator_queue_polled=False,
        generic_activation_subprocess_sealed=True,
        generic_executor_subprocess_sealed=True,
        plan_only_process_sealed=False,
        real_provisioning_enabled=False,
        tls_ready=True,
        keys_generated=True,
        key_metadata_safe=True,
        worker_public=WorkerNodeObservation(
            node_id="22222222-2222-4222-8222-222222222222",
            revision=1,
            ssh_public_fingerprint="SHA256:" + "A" * 43,
            admission_anchor_fingerprint="sha256:" + "b" * 64,
            public_material_only=True,
        ),
        publication_recorded=True,
        database_private_material_absent=True,
        configuration_artifact_digests=tuple(
            split_engine._worker_digests(profile, worker_override, ca_certificate).items()
        ),
    )


class _GeneratingWorkerAdapter(InMemoryWorkerActivationAdapter):
    def __init__(self, *, state: InMemoryWorkerStateFilesystem, **kwargs) -> None:  # noqa: ANN003
        super().__init__(**kwargs)
        self._state = state

    def await_worker_publication(
        self,
        profile,
        *,
        previous_generation: WorkerGeneration,  # noqa: ANN001
    ) -> WorkerObservation:
        observation = super().await_worker_publication(
            profile, previous_generation=previous_generation
        )
        self._state.keys_generated = True
        return observation


def _scenario():  # noqa: ANN202
    controller_signer = _Signer()
    worker_signer = _Signer()
    profile = _profile(controller_signer, worker_signer)
    tls = generate_tls_material(
        dns_identity=profile.admission_certificate_dns_name, validity_days=30, now=NOW
    )
    ca_pem = tls.ca_certificate_pem()
    ca_certificate = import_admission_ca(ca_certificate_pem=ca_pem, now=NOW)
    controller = InMemoryControllerActivationAdapter(
        before=ControllerObservation(inspected=True, coherent=True),
        after=_controller_after(profile, tls),
    )
    state = InMemoryWorkerStateFilesystem()
    worker = _GeneratingWorkerAdapter(
        state=state,
        before=_worker_before(profile),
        after=_worker_after(profile, ca_certificate),
    )
    controller_deps = ControllerDependencies(
        controller,
        controller_signer,
        controller_signer,
        controller_signer.trust_root(),
        lambda: NOW,
    )
    worker_deps = WorkerDependencies(worker, state, worker_signer, lambda: NOW)
    return (
        profile,
        tls,
        ca_pem,
        controller,
        worker,
        controller_deps,
        worker_deps,
        worker_signer,
    )


def _prepare_finalization(  # noqa: ANN202
    *,
    controller_type=InMemoryControllerActivationAdapter,  # noqa: ANN001
):
    scenario = list(_scenario())
    original = scenario[3]
    controller = controller_type(before=original.before, after=original.after)
    scenario[3] = controller
    scenario[5] = replace(scenario[5], adapter=controller)
    profile, tls, ca_pem, _controller, worker, controller_deps, worker_deps, _signer = scenario
    first = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert first.outcome == "pending"
    worker.controller_offer_inbox = controller.controller_offer
    second = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert second.outcome == "worker-result-emitted"
    controller.worker_result_inbox = worker.worker_result
    return tuple(scenario)


class _ProcessInterrupted(BaseException):
    """Model process death, which normal operation exception handlers cannot compensate."""


class _InterruptAfterEvidenceCommitAdapter(InMemoryControllerActivationAdapter):
    def commit_activation_evidence(self, evidence: bytes, attestation: bytes) -> None:
        super().commit_activation_evidence(evidence, attestation)
        if not getattr(self, "_evidence_interrupt_raised", False):
            self._evidence_interrupt_raised = True
            raise _ProcessInterrupted


class _InterruptAfterFenceReleaseAdapter(InMemoryControllerActivationAdapter):
    def release_api_rollback_fence(self, profile) -> None:  # noqa: ANN001
        super().release_api_rollback_fence(profile)
        if not getattr(self, "_release_interrupt_raised", False):
            self._release_interrupt_raised = True
            raise _ProcessInterrupted


class _CorruptEvidenceAfterWriteAdapter(InMemoryControllerActivationAdapter):
    def commit_activation_evidence(self, evidence: bytes, attestation: bytes) -> None:
        super().commit_activation_evidence(evidence, attestation)
        self.activation_evidence = (evidence, b"{}")


class _LoseObservationAfterFenceReleaseAdapter(InMemoryControllerActivationAdapter):
    def release_api_rollback_fence(self, profile) -> None:  # noqa: ANN001
        super().release_api_rollback_fence(profile)
        self.fence_observation_complete = False


def test_full_two_host_sequence_verifies_evidence_before_releasing_fence() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()

    first = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert first.outcome == "pending"
    assert first.reason_code == "worker_result_pending"
    assert controller.activation_evidence is None
    assert controller.operations[-1] == "controller_receipt"
    assert "release_api_rollback_fence" not in controller.operations

    worker.controller_offer_inbox = controller.controller_offer
    second = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert second.outcome == "worker-result-emitted"
    assert worker.operations.index("verify_live_admission_tls") < worker.operations.index(
        "recreate_ordinary_worker"
    )
    assert "release_api_rollback_fence" not in worker.operations

    controller.worker_result_inbox = worker.worker_result
    third = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert third.outcome == "installed"
    assert controller.activation_evidence is not None
    commit_index = controller.operations.index("commit_activation_evidence")
    release_index = controller.operations.index("release_api_rollback_fence")
    assert commit_index < release_index
    assert "load_activation_evidence" in controller.operations[commit_index + 1 : release_index]
    assert "controller_receipt" in controller.operations[commit_index + 1 : release_index]
    assert "observe_controller" in controller.operations[commit_index + 1 : release_index]
    assert "observe_api_rollback_fence" in controller.operations[commit_index + 1 : release_index]
    assert controller.operations.count("release_api_rollback_fence") == 1
    assert controller.operations[-1] == "observe_api_rollback_fence"
    assert controller.rollback_fence_state == "released"
    assert third.details["api_rollback_fence_state"] == "released"
    evidence = parse_evidence_bytes(controller.activation_evidence[0])
    assert evidence.worker_generation == worker.after.worker_generation
    assert evidence.forbidden_infrastructure_contacts_performed is False


def test_write_gate_precedes_all_role_local_observation() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()

    controller_result = controller_install_operation(
        profile,
        tls,
        WriteGate(),
        controller_deps,
        installation_identity="operator.test",
    )
    worker_result = worker_install_operation(
        profile,
        ca_pem,
        WriteGate(),
        worker_deps,
        installation_identity="operator.test",
    )

    assert controller_result.reason_code == "write_authority_required"
    assert worker_result.reason_code == "write_authority_required"
    assert controller.operations == []
    assert worker.operations == []


def test_worker_missing_offer_is_pending_and_malformed_offer_requires_recovery() -> None:
    profile, _tls, ca_pem, _controller, worker, _controller_deps, worker_deps, _signer = _scenario()

    missing = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert missing.outcome == "pending"
    assert missing.recovery_required is False
    assert worker.operations == [
        "load_fixed_controller_offer_inbox",
        "load_fixed_worker_result",
        "worker_receipt",
    ]

    worker.controller_offer_inbox = (b"{}", b"{}")
    malformed = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert malformed.outcome == "recovery-required"
    assert malformed.recovery_required is True
    assert "observe_worker" not in worker.operations


def test_worker_validates_state_before_runtime_observation() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_deps.state.unsafe_reason = "worker_state_root_foreign_or_partial"

    result = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )

    assert result.outcome == "refused"
    assert "observe_worker" not in worker.operations
    assert worker_deps.state.operations == ["inspect"]


def test_worker_failure_compensates_and_unproven_compensation_requires_recovery() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker.fail_on = "recreate_ordinary_worker"
    worker.compensation_proven = False

    result = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.recovery_required is True
    assert "compensate_worker" in worker.operations


def test_controller_rejects_contradictory_worker_result_as_recovery_required() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, worker_signer = (
        _scenario()
    )
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert worker.worker_result is not None
    good = parse_worker_result(worker.worker_result[0])
    contradictory = good.model_copy(update={"profile_digest": "sha256:" + "f" * 64})
    contradictory_attestation = issue_handoff_attestation(contradictory, worker_signer)
    controller.worker_result_inbox = (
        handoff_bytes(contradictory),
        handoff_attestation_bytes(contradictory_attestation),
    )

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert controller.activation_evidence is None
    assert "release_api_rollback_fence" not in controller.operations


def test_controller_refuses_live_offer_drift_before_releasing_rollback_fence() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    controller.worker_result_inbox = worker.worker_result
    assert controller.after.api_runtime is not None
    controller.after = replace(
        controller.after,
        api_runtime=replace(
            controller.after.api_runtime,
            configuration_digest="sha256:" + "0" * 64,
        ),
    )

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "controller_runtime_offer_drift"
    assert "release_api_rollback_fence" not in controller.operations
    assert controller.activation_evidence is None


def test_evidence_commit_failure_occurs_before_any_fence_release() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization()
    )
    controller.fail_on = "commit_activation_evidence"

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "injected_commit_activation_evidence_failure"
    assert controller.activation_evidence is None
    assert controller.rollback_fence_state == "engaged"
    assert "release_api_rollback_fence" not in controller.operations


def test_written_but_unauthenticated_evidence_never_releases_fence() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization(controller_type=_CorruptEvidenceAfterWriteAdapter)
    )

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert controller.activation_evidence is not None
    assert controller.rollback_fence_state == "engaged"
    assert "release_api_rollback_fence" not in controller.operations


def test_restart_after_evidence_commit_resumes_only_fence_finalization() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization(controller_type=_InterruptAfterEvidenceCommitAdapter)
    )

    with pytest.raises(_ProcessInterrupted):
        controller_install_operation(
            profile, tls, GATE, controller_deps, installation_identity="operator.test"
        )

    assert controller.activation_evidence is not None
    assert controller.rollback_fence_state == "engaged"
    assert "release_api_rollback_fence" not in controller.operations
    status = controller_status_operation(profile, tls, controller_deps)
    assert status.outcome == "awaiting-finalization"
    assert status.reason_code == "aggregate_evidence_verified_fence_engaged"
    verify = controller_verify_operation(profile, tls, controller_deps)
    assert verify.outcome == "refused"
    assert verify.reason_code == "api_rollback_fence_not_released"

    resumed = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert resumed.outcome == "installed"
    assert resumed.details["already_committed"] is True
    assert controller.operations.count("commit_activation_evidence") == 1
    assert controller.operations.count("release_api_rollback_fence") == 1
    assert controller.rollback_fence_state == "released"


def test_controller_release_failure_leaves_verified_evidence_and_engaged_fence() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization()
    )
    controller.fail_on = "release_api_rollback_fence"

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "injected_release_api_rollback_fence_failure"
    assert "release_api_rollback_fence" in controller.operations
    assert "commit_activation_evidence" in controller.operations
    assert controller.activation_evidence is not None
    assert controller.rollback_fence_state == "engaged"
    controller.fail_on = None
    status = controller_status_operation(profile, tls, controller_deps)
    assert status.outcome == "awaiting-finalization"


def test_restart_after_successful_release_reverifies_and_is_idempotent() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization(controller_type=_InterruptAfterFenceReleaseAdapter)
    )

    with pytest.raises(_ProcessInterrupted):
        controller_install_operation(
            profile, tls, GATE, controller_deps, installation_identity="operator.test"
        )

    assert controller.activation_evidence is not None
    assert controller.rollback_fence_state == "released"
    assert controller.operations.count("release_api_rollback_fence") == 1
    resumed = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert resumed.outcome == "installed"
    assert resumed.details["already_committed"] is True
    assert controller.operations.count("commit_activation_evidence") == 1
    assert controller.operations.count("release_api_rollback_fence") == 1


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("fence_observation_complete", False),
        ("rollback_fence_state", "unverified"),
        ("fence_migration_head", "stale-migration"),
        ("fence_api_container_id", "f" * 64),
    ],
)
def test_ambiguous_or_stale_fence_observation_requires_recovery(
    attribute: str, value: object
) -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization()
    )
    setattr(controller, attribute, value)

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "api_rollback_fence_unverified"
    assert controller.activation_evidence is None
    assert "release_api_rollback_fence" not in controller.operations


def test_released_fence_without_aggregate_evidence_requires_recovery() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization()
    )
    controller.rollback_fence_state = "released"

    install = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    status = controller_status_operation(profile, tls, controller_deps)

    assert install.outcome == "recovery-required"
    assert install.reason_code == "api_rollback_fence_released_without_evidence"
    assert status.outcome == "recovery-required"
    assert status.reason_code == "api_rollback_fence_released_without_evidence"
    assert controller.activation_evidence is None


def test_released_fence_with_malformed_committed_evidence_requires_recovery() -> None:
    # A corrupt durable state: the fence is released but the committed evidence pair no longer
    # authenticates.  install/status must recover and verify must refuse; the authoritative verifier
    # rejects the evidence before any fence trust, so no fence release is (re)attempted.
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization()
    )
    controller.rollback_fence_state = "released"
    controller.activation_evidence = (b"malformed-evidence", b"malformed-attestation")

    install = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    status = controller_status_operation(profile, tls, controller_deps)
    verify = controller_verify_operation(profile, tls, controller_deps)

    assert install.outcome == "recovery-required"
    assert status.outcome == "recovery-required"
    assert verify.outcome == "refused"
    assert "release_api_rollback_fence" not in controller.operations


def test_command_success_without_fresh_release_observation_is_not_installed() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = (
        _prepare_finalization(controller_type=_LoseObservationAfterFenceReleaseAdapter)
    )

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "api_rollback_fence_unverified"
    assert controller.activation_evidence is not None
    assert controller.rollback_fence_state == "released"
    controller.fence_observation_complete = True
    resumed = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert resumed.outcome == "installed"
    assert controller.operations.count("release_api_rollback_fence") == 1


def test_role_protocols_do_not_expose_cross_role_mutation_methods() -> None:
    controller_methods = set(dir(split_engine.ControllerActivationAdapter))
    worker_methods = set(dir(split_engine.WorkerActivationAdapter))

    assert "install_worker" not in controller_methods
    assert "recreate_ordinary_worker" not in controller_methods
    assert "install_controller" not in worker_methods
    assert "verify_controller_tls" not in worker_methods
    assert "observe_api_rollback_fence" in controller_methods
    assert "observe_api_rollback_fence" not in worker_methods
    assert "release_api_rollback_fence" in controller_methods
    assert "release_api_rollback_fence" not in worker_methods


def test_expired_controller_offer_is_recovery_required_before_worker_observation() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    expired_deps = replace(worker_deps, clock=lambda: NOW + timedelta(hours=25))

    result = worker_install_operation(
        profile, ca_pem, GATE, expired_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "controller_offer_expired"
    assert "observe_worker" not in worker.operations


class _UnsafeAfterRecreationAdapter(_GeneratingWorkerAdapter):
    def await_worker_publication(
        self,
        profile,
        *,
        previous_generation: WorkerGeneration,  # noqa: ANN001
    ) -> WorkerObservation:
        self.operations.append("await_worker_publication")
        self._state.unsafe_reason = "worker_state_key_file_metadata_invalid"
        raise split_engine.SplitActivationEngineError("publication_failed")


def test_failure_after_recreation_requires_safe_retained_state_proof() -> None:
    profile, tls, ca_pem, controller, _worker, controller_deps, worker_deps, signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    state = InMemoryWorkerStateFilesystem()
    worker = _UnsafeAfterRecreationAdapter(
        state=state,
        before=_worker_before(profile),
        after=_worker_after(profile, import_admission_ca(ca_certificate_pem=ca_pem, now=NOW)),
        controller_offer_inbox=controller.controller_offer,
    )
    deps = WorkerDependencies(worker, state, signer, lambda: NOW)

    result = worker_install_operation(
        profile, ca_pem, GATE, deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert "compensate_worker" in worker.operations
    assert state.operations[-1] == "inspect"


def test_role_scoped_read_operations_authenticate_chain_without_mutation() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    controller.worker_result_inbox = worker.worker_result
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    controller_start = len(controller.operations)
    worker_start = len(worker.operations)

    controller_results = (
        controller_inspect_operation(profile, controller_deps),
        controller_evidence_operation(profile, controller_deps),
        controller_verify_operation(profile, tls, controller_deps),
        controller_status_operation(profile, tls, controller_deps),
    )
    worker_results = (
        worker_inspect_operation(profile, worker_deps),
        worker_evidence_operation(profile, ca_pem, worker_deps),
        worker_verify_operation(profile, ca_pem, worker_deps),
        worker_status_operation(profile, ca_pem, worker_deps),
    )

    assert [item.operation for item in controller_results] == [
        "controller-inspect",
        "controller-evidence",
        "controller-verify",
        "controller-status",
    ]
    assert [item.operation for item in worker_results] == [
        "worker-inspect",
        "worker-evidence",
        "worker-verify",
        "worker-status",
    ]
    assert [item.outcome for item in controller_results[:3]] == [
        "inspected",
        "verified",
        "verified",
    ]
    assert [item.outcome for item in worker_results[:3]] == [
        "inspected",
        "verified",
        "verified",
    ]
    controller_read_only = {
        "observe_controller",
        "load_activation_evidence",
        "load_fixed_controller_offer",
        "load_fixed_worker_result_inbox",
        "controller_receipt",
        "observe_api_rollback_fence",
    }
    worker_read_only = {
        "observe_worker",
        "load_fixed_controller_offer_inbox",
        "load_fixed_worker_result",
        "worker_receipt",
    }
    assert set(controller.operations[controller_start:]) <= controller_read_only
    assert set(worker.operations[worker_start:]) <= worker_read_only


def test_explicit_rollback_recovers_interrupted_journals_without_final_evidence() -> None:
    profile, tls, _ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    _plan, rendered = split_engine._controller_render(profile, tls)
    controller.stage_controller_rollback(profile, rendered, controller.before)
    worker_override = split_engine.render_worker_compose_override(profile)
    state_receipt = worker_deps.state.prepare(
        uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
    )
    worker.stage_worker_rollback(
        profile,
        worker_override,
        worker.before,
        state_receipt=state_receipt,
    )

    controller_result = controller_rollback_operation(profile, GATE, controller_deps)
    worker_result = worker_rollback_operation(profile, GATE, worker_deps)

    assert controller_result.outcome == "rolled-back"
    assert worker_result.outcome == "rolled-back"
    assert "compensate_controller" in controller.operations
    assert "compensate_worker" in worker.operations
    assert controller.activation_evidence is None
    assert worker.worker_result is None


def test_committed_controller_rollback_requires_database_compatibility_proof() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    controller.worker_result_inbox = worker.worker_result
    completed = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert completed.outcome == "installed"

    controller.rollback_compatible = False
    refused = controller_rollback_operation(profile, GATE, controller_deps)

    assert refused.outcome == "recovery-required"
    assert refused.reason_code == "controller_api_rollback_incompatible_state"
    assert "controller_api_rollback_compatible" in controller.operations
    assert "rollback_controller_committed" not in controller.operations

    controller.rollback_compatible = True
    recovered = controller_rollback_operation(profile, GATE, controller_deps)
    assert recovered.outcome == "rolled-back"
    assert "rollback_controller_committed" in controller.operations


def test_runtime_started_controller_compensation_requires_database_compatibility() -> None:
    profile, tls, _ca_pem, controller, _worker, controller_deps, _worker_deps, _signer = _scenario()
    controller.fail_on = "verify_controller_tls"
    controller.rollback_compatible = False

    result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "controller_api_rollback_incompatible_state"
    assert "controller_api_rollback_compatible" in controller.operations
    assert "compensate_controller" not in controller.operations


def test_committed_worker_rollback_requires_database_compatibility_proof() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    installed = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert installed.outcome == "worker-result-emitted"

    worker.rollback_compatible = False
    refused = worker_rollback_operation(profile, GATE, worker_deps)

    assert refused.outcome == "recovery-required"
    assert refused.reason_code == "worker_api_rollback_incompatible_state"
    assert "worker_api_rollback_compatible" in worker.operations
    assert "rollback_worker_committed" not in worker.operations

    worker.rollback_compatible = True
    recovered = worker_rollback_operation(profile, GATE, worker_deps)
    assert recovered.outcome == "rolled-back"
    assert "rollback_worker_committed" in worker.operations


def test_recreated_worker_failure_requires_database_compatibility_before_compensation() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker.fail_on = "await_worker_publication"
    worker.rollback_compatible = False

    result = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )

    assert result.outcome == "recovery-required"
    assert result.reason_code == "worker_api_rollback_incompatible_state"
    assert "worker_api_rollback_compatible" in worker.operations
    assert "compensate_worker" not in worker.operations


def test_install_requires_rollback_after_an_interrupted_journal() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    _plan, rendered = split_engine._controller_render(profile, tls)
    controller.stage_controller_rollback(profile, rendered, controller.before)

    controller_result = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )

    assert controller_result.outcome == "recovery-required"
    assert controller_result.reason_code == "interrupted_controller_transaction"
    assert "install_controller" not in controller.operations

    # The same invariant holds on the worker after it has authenticated a valid offer.
    controller._receipt = None  # noqa: SLF001 - reset the deterministic peer fixture
    first = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert first.outcome == "pending"
    worker.controller_offer_inbox = controller.controller_offer
    worker_override = split_engine.render_worker_compose_override(profile)
    state_receipt = worker_deps.state.prepare(
        uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
    )
    worker.stage_worker_rollback(
        profile,
        worker_override,
        worker.before,
        state_receipt=state_receipt,
    )

    worker_result = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )

    assert worker_result.outcome == "recovery-required"
    assert worker_result.reason_code == "interrupted_worker_transaction"
    assert "install_worker" not in worker.operations


def test_committed_operations_require_the_live_durable_receipt() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    controller.worker_result_inbox = worker.worker_result
    committed = controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert committed.outcome == "installed"

    controller._receipt = None  # noqa: SLF001 - simulate a lost durable journal
    worker._receipt = None  # noqa: SLF001 - simulate a lost durable journal

    controller_results = (
        controller_install_operation(
            profile, tls, GATE, controller_deps, installation_identity="operator.test"
        ),
        controller_verify_operation(profile, tls, controller_deps),
        controller_status_operation(profile, tls, controller_deps),
        controller_rollback_operation(profile, GATE, controller_deps),
    )
    worker_results = (
        worker_install_operation(
            profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
        ),
        worker_verify_operation(profile, ca_pem, worker_deps),
        worker_status_operation(profile, ca_pem, worker_deps),
        worker_rollback_operation(profile, GATE, worker_deps),
    )

    assert [result.reason_code for result in controller_results] == [
        "controller_receipt_unavailable"
    ] * 4
    assert [result.reason_code for result in worker_results] == ["worker_receipt_unavailable"] * 4
    assert [result.outcome for result in controller_results] == [
        "recovery-required",
        "refused",
        "recovery-required",
        "recovery-required",
    ]
    assert [result.outcome for result in worker_results] == [
        "recovery-required",
        "refused",
        "recovery-required",
        "recovery-required",
    ]
    assert "rollback_controller_committed" not in controller.operations
    assert "rollback_worker_committed" not in worker.operations


def test_complete_receipt_must_bind_the_signed_handoff_and_commit_state() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    controller.worker_result_inbox = worker.worker_result
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    assert controller._receipt is not None  # noqa: SLF001
    assert worker._receipt is not None  # noqa: SLF001

    controller._receipt = replace(  # noqa: SLF001
        controller._receipt, evidence_committed=False
    )
    worker._receipt = replace(worker._receipt, worker_recreated=False)  # noqa: SLF001

    controller_result = controller_verify_operation(profile, tls, controller_deps)
    worker_result = worker_verify_operation(profile, ca_pem, worker_deps)

    assert controller_result.reason_code == "controller_evidence_receipt_mismatch"
    assert worker_result.reason_code == "worker_result_receipt_mismatch"


def test_status_reports_staged_journals_and_receiptless_runtime_as_recovery() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    _plan, rendered = split_engine._controller_render(profile, tls)
    controller.stage_controller_rollback(profile, rendered, controller.before)

    staged_controller = controller_status_operation(profile, tls, controller_deps)

    assert staged_controller.outcome == "recovery-required"
    assert staged_controller.reason_code == "interrupted_controller_transaction"

    controller._receipt = None  # noqa: SLF001 - simulate journal loss with d8 still live
    migration_only = ControllerObservation(
        inspected=True,
        coherent=True,
        migration_head="b6e2f4a9c1d7",
        migration_head_ready=True,
    )
    controller.before = migration_only
    controller.after = migration_only
    receiptless_controller = controller_status_operation(profile, tls, controller_deps)

    assert receiptless_controller.outcome == "recovery-required"
    assert receiptless_controller.reason_code == "controller_transaction_receipt_missing"

    fresh = _scenario()
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = fresh
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    worker_override = split_engine.render_worker_compose_override(profile)
    state_receipt = worker_deps.state.prepare(
        uid=profile.ordinary_runtime_uid, gid=profile.ordinary_runtime_gid
    )
    worker.stage_worker_rollback(
        profile,
        worker_override,
        worker.before,
        state_receipt=state_receipt,
    )

    staged_worker = worker_status_operation(profile, ca_pem, worker_deps)

    assert staged_worker.outcome == "recovery-required"
    assert staged_worker.reason_code == "interrupted_worker_transaction"

    worker._receipt = None  # noqa: SLF001 - simulate journal loss with worker effects live
    worker.before = worker.after
    receiptless_worker = worker_status_operation(profile, ca_pem, worker_deps)

    assert receiptless_worker.outcome == "recovery-required"
    assert receiptless_worker.reason_code == "worker_transaction_receipt_missing"


def test_stored_worker_result_is_rejected_after_public_key_rotation() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    emitted = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert emitted.outcome == "worker-result-emitted"
    assert worker.after.worker_public is not None
    worker.after = replace(
        worker.after,
        worker_public=replace(
            worker.after.worker_public,
            admission_anchor_fingerprint="sha256:" + "c" * 64,
        ),
    )

    repeated = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    verified = worker_verify_operation(profile, ca_pem, worker_deps)
    status = worker_status_operation(profile, ca_pem, worker_deps)

    assert repeated.outcome == "recovery-required"
    assert repeated.reason_code == "worker_public_result_drift"
    assert verified.outcome == "refused"
    assert verified.reason_code == "worker_public_result_drift"
    assert status.outcome == "recovery-required"
    assert status.reason_code == "worker_public_result_drift"


def test_worker_status_requires_a_receipt_before_deriving_post_commit_stages() -> None:
    profile, tls, ca_pem, controller, worker, controller_deps, worker_deps, _signer = _scenario()
    controller_install_operation(
        profile, tls, GATE, controller_deps, installation_identity="operator.test"
    )
    worker.controller_offer_inbox = controller.controller_offer
    installed = worker_install_operation(
        profile, ca_pem, GATE, worker_deps, installation_identity="operator.test"
    )
    assert installed.outcome == "worker-result-emitted"
    committed_result = worker.worker_result
    committed_receipt = worker._receipt  # noqa: SLF001 - deterministic journal fixture
    assert committed_result is not None and committed_receipt is not None
    base = _worker_after(profile, import_admission_ca(ca_certificate_pem=ca_pem, now=NOW))
    early = WorkerObservation(inspected=True, coherent=True)
    runtime = replace(base, keys_generated=False, worker_public=None)
    cases = (
        (profile.model_copy(update={"activation_enabled": False}), early, False, False, "disabled"),
        (profile, early, False, False, "prepared"),
        (
            profile,
            replace(early, artifacts_prepared=True, tls_ready=True),
            False,
            False,
            "recovery-required",
        ),
        (
            profile,
            replace(
                early,
                artifacts_prepared=True,
                tls_ready=True,
                worker_config_installed=True,
                worker_recreation_required=True,
            ),
            False,
            False,
            "recovery-required",
        ),
        (
            profile,
            replace(
                early,
                artifacts_prepared=True,
                tls_ready=True,
                worker_config_installed=True,
                worker_generation_changed=True,
            ),
            False,
            False,
            "recovery-required",
        ),
        (profile, runtime, True, False, "recovery-required"),
        (profile, replace(base, publication_recorded=False), True, True, "recovery-required"),
        (profile, base, True, True, "awaiting-bootstrap-session"),
        (profile, replace(base, bootstrap_status="pending"), True, True, "awaiting-proof"),
        (
            profile,
            replace(base, bootstrap_status="completed"),
            True,
            True,
            "awaiting-authorization",
        ),
        (
            profile,
            replace(
                base,
                bootstrap_status="bound",
                worker_identity_approved=True,
                live_read_authorization_approved=True,
            ),
            True,
            True,
            "awaiting-bundle",
        ),
        (
            profile,
            replace(
                base,
                bootstrap_status="bound",
                worker_identity_approved=True,
                live_read_authorization_approved=True,
                bundle_ready=True,
            ),
            True,
            True,
            "bundle-ready",
        ),
        (
            profile,
            replace(
                base,
                bootstrap_status="bound",
                worker_identity_approved=True,
                live_read_authorization_approved=True,
                bundle_ready=True,
                discovery_contacted=True,
                candidate_executable=False,
            ),
            True,
            True,
            "discovery-contacted",
        ),
        (profile, replace(base, recovery_required=True), True, True, "recovery-required"),
    )
    observed: list[str] = []
    expected: list[str] = []
    for case_profile, observation, keys_generated, complete, expected_state in cases:
        worker.before = observation
        worker.after = observation
        worker.worker_result = committed_result if complete else None
        worker._receipt = committed_receipt if complete else None  # noqa: SLF001
        worker_deps.state.present = keys_generated
        worker_deps.state.prepared = keys_generated
        worker_deps.state.keys_generated = keys_generated
        result = worker_status_operation(case_profile, ca_pem, worker_deps)
        observed.append(result.outcome)
        expected.append(expected_state)

    assert observed == expected
