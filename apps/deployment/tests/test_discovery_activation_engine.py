"""Hermetic transaction, rollback, and operation tests for PR5F activation."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
import secp_discovery_activation.engine as engine_module
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION
from secp_discovery_activation.adapters import (
    ContainerRuntimeObservation,
    FixedInputBinding,
    HostObservation,
    InMemoryActivationAdapter,
    MutationReceipt,
    WorkerPublicObservation,
)
from secp_discovery_activation.engine import (
    EngineDependencies,
    WriteGate,
    build_plan,
    evidence_operation,
    install_operation,
    plan_operation,
    render_operation,
    rollback_operation,
    status_operation,
    verify_operation,
)
from secp_discovery_activation.evidence import (
    EvidenceTrustAnchor,
    EvidenceTrustRoot,
    WorkerGeneration,
)
from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE
from secp_discovery_activation.profile import parse_deployment_profile
from secp_discovery_activation.state import InMemoryWorkerStateFilesystem
from secp_discovery_activation.tls import generate_tls_material

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
INSTALL_GATE = WriteGate(write=True, confirm=True)


def _profile(*, enabled: bool | None = True):  # noqa: ANN202
    raw: dict[str, object] = {
        "contract_version": PACKAGE_CONTRACT_VERSION,
        "ordinary_worker_image_digest": "sha256:" + "1" * 64,
        "worker_runtime_overlay_digest": "sha256:" + "5" * 64,
        "ordinary_runtime_uid": 1001,
        "ordinary_runtime_gid": 1001,
        "worker_node_organization": "11111111-1111-4111-8111-111111111111",
        "worker_node_label": "site-worker-01",
        "admission_endpoint": "https://admission.internal.test:8443",
        "admission_listener_bind": "10.20.30.40:8443",
        "controller_api_upstream": "http://api:8080",
        "controller_compose_project": "secp-controller",
        "worker_compose_project": "secp-worker",
        "admission_certificate_dns_name": "admission.internal.test",
        "admission_proxy_image": ("registry.internal.test/secp/admission-proxy@sha256:" + "2" * 64),
        "admission_proxy_runtime_image_digest": "sha256:" + "8" * 64,
        "controller_api_baseline_image_digest": "sha256:" + "7" * 64,
        "controller_api_runtime_image_digest": "sha256:" + "9" * 64,
        "controller_api_image": "registry.internal.test/secp/api@sha256:" + "6" * 64,
        "admission_proxy_runtime_uid": 1002,
        "admission_proxy_runtime_gid": 1002,
        "container_runtime_executable": "/usr/bin/docker",
        "container_runtime_executable_digest": "sha256:" + "3" * 64,
        "compose_executable": "/usr/libexec/docker/cli-plugins/docker-compose",
        "compose_executable_digest": "sha256:" + "4" * 64,
    }
    if enabled is not None:
        raw["activation_enabled"] = enabled
    return parse_deployment_profile(raw)


@pytest.fixture(scope="module")
def tls_material():  # noqa: ANN201
    return generate_tls_material(dns_identity="admission.internal.test", validity_days=30, now=NOW)


class _Signer:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()

    def key_id(self) -> str:
        return "activation-engine-test"

    def attest(self, message: bytes) -> str:
        return self.private.sign(message).hex()

    def trust_root(self) -> EvidenceTrustRoot:
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return EvidenceTrustRoot(
            anchors=(EvidenceTrustAnchor(self.key_id(), public.hex()),), test_only=True
        )


def _generation(character: str, *, restart: int = 0, minute: int = 0) -> WorkerGeneration:
    return WorkerGeneration(
        container_id=character * 64,
        restart_count=restart,
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
    profile,  # noqa: ANN001
    generation: WorkerGeneration,
    *,
    mounts_verified: bool,
    endpoint_binding_verified: bool,
) -> ContainerRuntimeObservation:
    return ContainerRuntimeObservation(
        present=True,
        generation=generation,
        image_digest=profile.ordinary_worker_image_digest,
        configuration_digest="sha256:" + "a" * 64,
        mounts_digest="sha256:" + "b" * 64,
        networks_digest="sha256:" + "c" * 64,
        compose_project=profile.worker_compose_project,
        compose_service="worker",
        expected_image=True,
        hardening_verified=True,
        mounts_verified=mounts_verified,
        endpoint_binding_verified=endpoint_binding_verified,
    )


def _before(profile) -> HostObservation:  # noqa: ANN001
    generation = _generation("a")
    return HostObservation(
        inspected=True,
        coherent=True,
        worker_present=True,
        worker_generation=generation,
        worker_image_digest=profile.ordinary_worker_image_digest,
        base_compose_binding=_base_compose(),
        worker_runtime=_runtime(
            profile,
            generation,
            mounts_verified=False,
            endpoint_binding_verified=False,
        ),
        worker_running=True,
        worker_healthy=True,
        ordinary_queues=(ORDINARY_TASK_QUEUE,),
        operator_service_present=False,
        operator_container_present=False,
        operator_registration_present=False,
        operator_queue_polled=False,
        generic_activation_subprocess_sealed=True,
        generic_executor_subprocess_sealed=True,
        plan_only_process_sealed=False,
        real_provisioning_enabled=False,
    )


def _after(profile, tls_material, **updates: object) -> HostObservation:  # noqa: ANN001
    _plan, rendered = build_plan(profile, tls_material)
    expected = engine_module._expected_artifact_digests(profile, rendered, tls_material)
    generation = _generation("b", minute=1)
    values: dict[str, object] = {
        "inspected": True,
        "coherent": True,
        "worker_present": True,
        "worker_generation": generation,
        "worker_image_digest": profile.ordinary_worker_image_digest,
        "base_compose_binding": _base_compose(),
        "worker_runtime": _runtime(
            profile,
            generation,
            mounts_verified=True,
            endpoint_binding_verified=True,
        ),
        "worker_running": True,
        "worker_healthy": True,
        "ordinary_queues": (ORDINARY_TASK_QUEUE,),
        "controlled_integration_enabled": True,
        "worker_managed_bundle_enabled": True,
        "fixed_worker_paths": True,
        "state_mount_read_write_only_worker": True,
        "ca_mount_read_only_worker": True,
        "discovery_mount_absent_from_other_containers": True,
        "bundle_prep_loop_started": True,
        "operator_service_present": False,
        "operator_container_present": False,
        "operator_registration_present": False,
        "operator_queue_polled": False,
        "generic_activation_subprocess_sealed": True,
        "generic_executor_subprocess_sealed": True,
        "plan_only_process_sealed": False,
        "real_provisioning_enabled": False,
        "tls_ready": True,
        "artifacts_prepared": True,
        "worker_config_installed": True,
        "configuration_artifact_digests": tuple(expected.items()),
        "keys_generated": True,
        "key_metadata_safe": True,
        "worker_public": WorkerPublicObservation(
            node_id="11111111-1111-4111-8111-111111111111",
            revision=2,
            ssh_public_fingerprint="SHA256:" + "A" * 43,
            admission_anchor_fingerprint="sha256:" + "b" * 64,
            public_material_only=True,
        ),
        "database_private_material_absent": True,
    }
    values.update(updates)
    return HostObservation(**values)


class _GeneratingAdapter(InMemoryActivationAdapter):
    """The worker recreation seam generates durable keys before publication returns."""

    def __init__(self, *, state: InMemoryWorkerStateFilesystem, **kwargs) -> None:  # noqa: ANN003
        super().__init__(**kwargs)
        self.state_backend = state

    def await_worker_publication(
        self,
        profile,
        *,
        previous_generation: WorkerGeneration,  # noqa: ANN001
    ) -> HostObservation:
        observation = super().await_worker_publication(
            profile, previous_generation=previous_generation
        )
        self.state_backend.keys_generated = True
        return observation


def _scenario(tls_material, *, after_updates=None, fail_on=None):  # noqa: ANN001, ANN202
    profile = _profile()
    state = InMemoryWorkerStateFilesystem()
    after = _after(profile, tls_material, **(after_updates or {}))
    adapter = _GeneratingAdapter(
        state=state,
        before=_before(profile),
        after=after,
        fail_on=fail_on,
    )
    signer = _Signer()
    deps = EngineDependencies(
        adapter=adapter,
        state=state,
        evidence_authenticator=signer,
        evidence_trust_root=signer.trust_root(),
        clock=lambda: NOW,
    )
    return profile, state, adapter, deps


def _install(profile, tls_material, deps):  # noqa: ANN001, ANN202
    return install_operation(
        profile,
        tls_material,
        INSTALL_GATE,
        deps,
        installation_identity="operator.test",
    )


def test_activation_is_false_by_default_and_install_is_inert(tls_material) -> None:  # noqa: ANN001
    profile = _profile(enabled=None)
    assert profile.activation_enabled is False
    state = InMemoryWorkerStateFilesystem()
    adapter = InMemoryActivationAdapter(before=HostObservation(), after=HostObservation())
    signer = _Signer()
    deps = EngineDependencies(adapter, state, signer, signer.trust_root(), lambda: NOW)

    result = _install(profile, tls_material, deps)

    assert result.outcome == "refused" and result.reason_code == "activation_disabled"
    assert state.operations == [] and adapter.operations == []


def test_plan_and_render_are_deterministic_and_have_no_host_side_effects(tls_material) -> None:  # noqa: ANN001
    profile = _profile()
    first_plan = plan_operation(profile, tls_material)
    second_plan = plan_operation(profile, tls_material)
    first_render = render_operation(profile, tls_material)
    second_render = render_operation(profile, tls_material)

    assert first_plan.canonical() == second_plan.canonical()
    assert first_render.canonical() == second_render.canonical()
    assert first_plan.details["external_contacts_during_plan"] is False
    assert first_plan.details["host_mutations_during_plan"] is False
    serialized = json.dumps(first_render.canonical())
    assert "PRIVATE KEY" not in serialized
    assert "BEGIN CERTIFICATE" not in serialized


@pytest.mark.parametrize(
    ("gate", "reason"),
    [
        (WriteGate(), "write_authority_required"),
        (WriteGate(write=True), "explicit_confirmation_required"),
    ],
)
def test_install_write_gate_refuses_before_any_observation(tls_material, gate, reason) -> None:  # noqa: ANN001
    profile, state, adapter, deps = _scenario(tls_material)

    result = install_operation(
        profile, tls_material, gate, deps, installation_identity="operator.test"
    )

    assert result.reason_code == reason
    assert state.operations == [] and adapter.operations == []


def test_unsafe_worker_state_refuses_before_adapter_or_docker_observation(tls_material) -> None:  # noqa: ANN001
    profile, state, adapter, deps = _scenario(tls_material)
    state.present = True
    state.unsafe_reason = "worker_state_root_symlink"

    result = _install(profile, tls_material, deps)

    assert result.outcome == "refused"
    assert result.reason_code == "worker_state_root_symlink"
    assert state.operations == ["inspect"]
    assert adapter.operations == []
    assert state.present is True


def test_successful_transaction_stages_rollback_before_any_mutation_and_commits_evidence_last(
    tls_material,
) -> None:  # noqa: ANN001
    profile, state, adapter, deps = _scenario(tls_material)

    result = _install(profile, tls_material, deps)

    assert result.outcome == "installed" and result.reason_code is None
    assert adapter.operations == [
        "observe",
        "stage_rollback",
        "install_controller",
        "verify_internal_tls",
        "install_worker",
        "recreate_worker",
        "await_worker_publication",
        "receipt",
        "commit_evidence",
        "load_evidence",
        "observe",
        "receipt",
    ]
    assert adapter.operations.index("stage_rollback") < adapter.operations.index(
        "install_controller"
    )
    assert adapter.operations.index("verify_internal_tls") < adapter.operations.index(
        "recreate_worker"
    )
    assert adapter.operations.index("commit_evidence") > adapter.operations.index("receipt")
    assert state.keys_generated is True and state.present is True
    assert result.details["worker_state_classification"] == "created"


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"worker_healthy": False}, "worker_health_failed"),
        ({"worker_public": None}, "public_worker_node_missing_or_unsafe"),
        ({"ordinary_queues": ("secp-controlled-live-v1",)}, "ordinary_queue_drift"),
        ({"state_mount_read_write_only_worker": False}, "worker_mount_isolation_failed"),
        ({"operator_service_present": True}, "operator_appeared"),
        ({"generic_activation_subprocess_sealed": False}, "safety_seal_posture_invalid"),
        ({"configuration_artifact_digests": ()}, "configuration_artifact_drift"),
        ({"controlled_integration_enabled": False}, "b8_flags_not_enabled"),
        ({"bundle_prep_loop_started": False}, "bundle_prep_loop_not_started"),
        ({"key_metadata_safe": False}, "worker_key_metadata_invalid"),
        ({"database_private_material_absent": False}, "database_private_material_unproven"),
    ],
)
def test_post_recreation_failures_restore_previous_worker_and_retain_generated_state(
    tls_material,
    updates: dict[str, object],
    reason: str,  # noqa: ANN001
) -> None:
    profile, state, adapter, deps = _scenario(tls_material, after_updates=updates)

    result = _install(profile, tls_material, deps)

    assert result.outcome == "rolled-back"
    assert result.reason_code == reason
    assert result.recovery_required is False
    assert "recreate_worker" in adapter.operations
    assert adapter.operations[-1] == "compensate"
    assert result.details["previous_worker_restored"] is True
    assert result.details["previous_artifacts_restored"] is True
    assert state.keys_generated is True and state.present is True
    assert "compensate" not in state.operations


def test_tls_failure_rolls_back_before_recreation_and_removes_empty_created_state(
    tls_material,
) -> None:  # noqa: ANN001
    profile, state, adapter, deps = _scenario(
        tls_material, after_updates={"tls_ready": False, "keys_generated": False}
    )

    result = _install(profile, tls_material, deps)

    assert result.outcome == "rolled-back"
    assert result.reason_code == "internal_tls_verification_failed"
    assert "recreate_worker" not in adapter.operations
    assert adapter.operations[-1] == "compensate"
    assert state.present is False and state.prepared is False
    assert state.operations[-1] == "compensate"


@pytest.mark.parametrize("failure", ["install_controller", "install_worker"])
def test_partial_artifact_writes_compensate_before_worker_recreation(
    tls_material,
    failure: str,  # noqa: ANN001
) -> None:
    profile, state, adapter, deps = _scenario(tls_material, fail_on=failure)

    result = _install(profile, tls_material, deps)

    assert result.outcome == "rolled-back"
    assert result.reason_code == f"injected_{failure}_failure"
    assert "compensate" in adapter.operations
    assert "recreate_worker" not in adapter.operations
    assert state.present is False


def test_missing_or_malformed_live_receipt_after_effects_is_recovery_required(tls_material) -> None:  # noqa: ANN001
    profile, state, adapter, deps = _scenario(tls_material)
    adapter.malformed_receipt = True

    result = _install(profile, tls_material, deps)

    assert result.outcome == "recovery-required"
    assert result.recovery_required is True
    assert result.reason_code == "recovery_required"
    assert "recreate_worker" in adapter.operations
    assert state.keys_generated is True


def test_unproven_or_failed_compensation_is_recovery_required(tls_material) -> None:  # noqa: ANN001
    profile, _state, adapter, deps = _scenario(tls_material, fail_on="recreate_worker")
    adapter.compensation_proven = False

    result = _install(profile, tls_material, deps)

    assert result.outcome == "recovery-required" and result.recovery_required is True

    profile, _state, adapter, deps = _scenario(tls_material, fail_on="recreate_worker")

    def compensation_failed(_receipt):  # noqa: ANN001, ANN202
        adapter.operations.append("compensate")
        raise RuntimeError("injected closed failure")

    adapter.compensate = compensation_failed  # type: ignore[method-assign]
    result = _install(profile, tls_material, deps)
    assert result.outcome == "recovery-required" and result.recovery_required is True


def test_failed_state_compensation_before_adapter_journal_is_recovery_required(
    tls_material,
) -> None:  # noqa: ANN001
    profile, state, _adapter, deps = _scenario(tls_material, fail_on="stage_rollback")
    state.compensation_succeeds = False

    result = _install(profile, tls_material, deps)

    assert result.outcome == "recovery-required" and result.recovery_required is True
    assert state.present is True


def test_signed_evidence_verify_status_and_rollback_retain_durable_keys(tls_material) -> None:  # noqa: ANN001
    profile, state, adapter, deps = _scenario(tls_material)
    assert _install(profile, tls_material, deps).outcome == "installed"

    evidence = evidence_operation(deps)
    verified = verify_operation(profile, deps)
    rolled_back = rollback_operation(profile, INSTALL_GATE, deps)

    assert evidence.outcome == "verified"
    assert evidence.details["attestation"] == {
        "algorithm": "ed25519",
        "key_id": "activation-engine-test",
        "verified": True,
    }
    assert "signature" not in evidence.details["attestation"]
    assert verified.outcome == "verified"
    assert rolled_back.outcome == "rolled-back"
    assert rolled_back.details["durable_worker_state_retained"] is True
    assert state.keys_generated is True and state.present is True
    assert adapter.operations[-2:] == ["rollback_committed", "compensate"]


def test_tampered_evidence_is_refused_before_status_or_rollback_trusts_classification(
    tls_material,
) -> None:  # noqa: ANN001
    profile, _state, adapter, deps = _scenario(tls_material)
    assert _install(profile, tls_material, deps).outcome == "installed"
    assert adapter._evidence is not None
    raw_evidence, raw_attestation = adapter._evidence
    document = json.loads(raw_evidence)
    document["persistent_state"]["classification"] = "adopted"
    for record in document["managed_objects"]:
        if record["role"] == "worker_state":
            record["classification"] = "adopted"
    adapter._evidence = (json.dumps(document, sort_keys=True).encode(), raw_attestation)

    evidence = evidence_operation(deps)
    status = status_operation(profile, deps)
    rollback = rollback_operation(profile, INSTALL_GATE, deps)

    assert evidence.outcome == "refused"
    assert status.outcome == "recovery-required" and status.recovery_required is True
    assert rollback.outcome == "refused"
    assert "rollback_committed" not in adapter.operations[-3:]


def test_missing_evidence_for_installed_artifacts_is_recovery_required(tls_material) -> None:  # noqa: ANN001
    profile, _state, adapter, deps = _scenario(tls_material)
    # No install/evidence, but the coherent host observation says both installed artifacts exist.
    adapter._receipt = MutationReceipt("tx", True, True, True, True, True, False, 3)

    result = status_operation(profile, deps)

    assert result.outcome == "recovery-required"
    assert result.reason_code == "installed_evidence_missing"
    assert result.recovery_required is True


def test_missing_receipt_or_failed_committed_rollback_is_recovery_required(tls_material) -> None:  # noqa: ANN001
    profile, _state, adapter, deps = _scenario(tls_material)
    assert _install(profile, tls_material, deps).outcome == "installed"
    adapter.malformed_receipt = True
    missing = rollback_operation(profile, INSTALL_GATE, deps)
    assert missing.outcome == "recovery-required" and missing.recovery_required is True

    profile, _state, adapter, deps = _scenario(tls_material)
    assert _install(profile, tls_material, deps).outcome == "installed"
    adapter.compensation_proven = False
    failed = rollback_operation(profile, INSTALL_GATE, deps)
    assert failed.outcome == "recovery-required" and failed.recovery_required is True


def test_generation_or_artifact_drift_refuses_verification(tls_material) -> None:  # noqa: ANN001
    profile, _state, adapter, deps = _scenario(tls_material)
    assert _install(profile, tls_material, deps).outcome == "installed"
    adapter.after = replace(adapter.after, worker_generation=_generation("d", minute=2))
    assert verify_operation(profile, deps).reason_code == "worker_generation_evidence_drift"

    adapter.after = replace(
        adapter.after,
        worker_generation=_generation("b", minute=1),
        configuration_artifact_digests=(),
    )
    assert verify_operation(profile, deps).reason_code == "configuration_artifact_drift"
