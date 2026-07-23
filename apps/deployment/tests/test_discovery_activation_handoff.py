"""Hermetic security tests for the signed two-host activation handoff."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secp_commissioning.canonical import sha256_digest
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION, PACKAGE_IMPLEMENTATION_ID
from secp_discovery_activation.evidence import (
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
    AdmissionTLSEvidence,
    ContainerRuntimeEvidence,
    FixedInputEvidence,
    PersistentStateEvidence,
    WorkerGeneration,
    WorkerPublicEvidence,
)
from secp_discovery_activation.handoff import (
    ActivationHandoffError,
    ControllerOffer,
    WorkerResult,
    attestation_bytes,
    handoff_bytes,
    issue_handoff_attestation,
    parse_controller_offer,
    parse_handoff_attestation,
    parse_worker_result,
    verify_handoff,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64


def _fixed_input() -> FixedInputEvidence:
    return FixedInputEvidence(content_digest=SHA_D, owner_uid=0, owner_gid=0, mode=0o640)


def _runtime(role: str, image: str, generation: WorkerGeneration) -> ContainerRuntimeEvidence:
    return ContainerRuntimeEvidence(
        runtime_role=role,
        generation=generation,
        image_digest=image,
        configuration_digest=SHA_A,
        mounts_digest=SHA_B,
        networks_digest=SHA_C,
        compose_project="secp",
        compose_service={
            "controller_api": "api",
            "admission_proxy": "discovery-admission-proxy",
            "ordinary_worker": "worker",
        }[role],
        expected_image=True,
        hardening_verified=True,
        mounts_verified=True,
        endpoint_binding_verified=role == "ordinary_worker",
    )


class _Signer:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self._public = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def key_id(self) -> str:
        return "sha256:" + hashlib.sha256(self._public).hexdigest()

    def public_key_hex(self) -> str:
        return self._public.hex()

    def attest(self, message: bytes) -> str:
        return self._key.sign(message).hex()


def _tls() -> AdmissionTLSEvidence:
    return AdmissionTLSEvidence(
        ca_certificate_fingerprint=SHA_A,
        server_certificate_fingerprint=SHA_B,
        server_public_key_fingerprint=SHA_C,
        server_dns_identity="admission.internal.test",
        server_dns_sans=("admission.internal.test",),
    )


def _offer() -> ControllerOffer:
    api_generation = WorkerGeneration(
        container_id="a" * 64,
        restart_count=0,
        started_at="2026-07-19T12:00:00Z",
    )
    proxy_generation = WorkerGeneration(
        container_id="b" * 64,
        restart_count=0,
        started_at="2026-07-19T12:00:00Z",
    )
    return ControllerOffer(
        schema="secp.discovery-activation.controller-offer/v1",
        contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        issuer_role="controller",
        sequence=1,
        predecessor_digest=None,
        transaction_id="00000000-0000-4000-8000-000000000001",
        profile_digest=SHA_A,
        plan_digest=SHA_B,
        render_manifest_digest=SHA_C,
        controller_artifact_digests={
            ROLE_CONTROLLER_OVERRIDE: SHA_A,
            ROLE_PROXY_CONTRACT: SHA_B,
            ROLE_ADMISSION_CA: SHA_C,
            ROLE_ADMISSION_SERVER_CERTIFICATE: SHA_D,
        },
        worker_artifact_digests={
            ROLE_WORKER_OVERRIDE: SHA_A,
            ROLE_WORKER_RUNTIME_OVERLAY: SHA_B,
        },
        object_classifications={
            ROLE_PROFILE: "adopted",
            ROLE_CONTROLLER_OVERRIDE: "created",
            ROLE_PROXY_CONTRACT: "created",
            ROLE_ADMISSION_CA: "created",
            ROLE_ADMISSION_SERVER_CERTIFICATE: "created",
            ROLE_ADMISSION_SERVER_KEY: "created",
            ROLE_ADMISSION_PROXY_GATE: "created",
        },
        controller_base_compose=_fixed_input(),
        controller_runtimes=(
            _runtime("controller_api", SHA_C, api_generation),
            _runtime("admission_proxy", SHA_D, proxy_generation),
        ),
        controller_migration_head="b6e2f4a9c1d7",
        admission_tls=_tls(),
        installation_timestamp="2026-07-19T12:00:00Z",
        expires_at="2026-07-20T12:00:00Z",
        installation_identity="controller.operator.test",
        rollback_journal_present=True,
        internal_tls_verified=True,
        forbidden_infrastructure_contacts_performed=False,
        workflows_submitted=False,
        operator_activated=False,
        run_plan_generation_called=False,
        opentofu_executed=False,
        proxmox_contacted=False,
    )


def _result(offer: ControllerOffer) -> WorkerResult:
    generation = WorkerGeneration(
        container_id="e" * 64,
        restart_count=1,
        started_at="2026-07-19T12:01:00Z",
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
        worker_transaction_id="00000000-0000-4000-8000-000000000002",
        profile_digest=offer.profile_digest,
        plan_digest=offer.plan_digest,
        render_manifest_digest=offer.render_manifest_digest,
        worker_image_digest=SHA_D,
        worker_generation=generation,
        ordinary_task_queue="secp-orchestration",
        worker_artifact_digests={
            ROLE_WORKER_OVERRIDE: SHA_A,
            ROLE_WORKER_RUNTIME_OVERLAY: SHA_B,
            ROLE_ADMISSION_CA: SHA_C,
        },
        object_classifications={
            ROLE_WORKER_OVERRIDE: "created",
            ROLE_WORKER_RUNTIME_OVERLAY: "created",
            ROLE_WORKER_STATE: "created",
        },
        worker_base_compose=_fixed_input(),
        worker_runtime=_runtime("ordinary_worker", SHA_D, generation),
        persistent_state=PersistentStateEvidence(
            path_binding=sha256_digest({"fixed": "worker-state"}),
            owner_uid=1001,
            owner_gid=1001,
            mode=0o700,
            key_directory_present=True,
            bundle_directory_present=True,
            key_file_count=4,
            bundle_file_count=0,
            keys_generated=True,
            bundle_populated=False,
            classification="created",
        ),
        admission_ca_fingerprint=SHA_A,
        worker_public_material=WorkerPublicEvidence(
            ssh_public_fingerprint="SHA256:" + "A" * 43,
            admission_anchor_fingerprint=SHA_B,
            worker_discovery_node_id="00000000-0000-4000-8000-000000000003",
            worker_discovery_node_revision=1,
        ),
        installation_timestamp="2026-07-19T12:02:00Z",
        installation_identity="worker.operator.test",
        rollback_journal_present=True,
        worker_healthy=True,
        mount_isolated=True,
        bundle_prep_loop_started=True,
        database_private_material_absent=True,
        operator_service_present=False,
        operator_queue_polled=False,
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


@pytest.mark.parametrize("factory,parser", [(_offer, parse_controller_offer)])
def test_controller_offer_round_trip_is_canonical_and_secret_free(factory, parser) -> None:  # noqa: ANN001
    offer = factory()
    raw = handoff_bytes(offer)

    assert parser(raw) == offer
    assert raw.endswith(b"\n")
    assert b"PRIVATE KEY" not in raw
    assert b"BEGIN CERTIFICATE" not in raw
    assert b'"admission_endpoint"' not in raw.lower()


def test_worker_result_round_trip_and_predecessor_binding() -> None:
    offer = _offer()
    result = _result(offer)

    assert parse_worker_result(handoff_bytes(result)) == result
    assert result.controller_offer_digest == offer.digest()
    assert result.controller_transaction_id == offer.transaction_id


def test_detached_signature_requires_independently_pinned_key_id() -> None:
    signer = _Signer()
    offer = _offer()
    attestation = issue_handoff_attestation(offer, signer)

    verify_handoff(offer, attestation, expected_key_id=signer.key_id())
    assert parse_handoff_attestation(attestation_bytes(attestation)) == attestation

    with pytest.raises(ActivationHandoffError) as exc:
        verify_handoff(offer, attestation, expected_key_id=SHA_D)
    assert exc.value.reason_code == "handoff_signer_not_pinned"


def test_tampered_handoff_is_refused_even_when_attestation_is_well_formed() -> None:
    signer = _Signer()
    offer = _offer()
    attestation = issue_handoff_attestation(offer, signer)
    tampered = offer.model_copy(update={"plan_digest": SHA_D})

    with pytest.raises(ActivationHandoffError) as exc:
        verify_handoff(tampered, attestation, expected_key_id=signer.key_id())
    assert exc.value.reason_code == "handoff_signature_invalid"


def test_duplicate_unknown_and_effectful_payloads_refuse() -> None:
    raw = handoff_bytes(_offer())
    duplicate = raw.replace(b'{"admission_tls":', b'{"schema":"duplicate","admission_tls":', 1)
    with pytest.raises(ActivationHandoffError):
        parse_controller_offer(duplicate)

    value = json.loads(raw)
    value["operator_activated"] = True
    with pytest.raises(ActivationHandoffError):
        parse_controller_offer(json.dumps(value).encode("ascii"))

    value = json.loads(raw)
    value["private_key"] = "forbidden"
    with pytest.raises(ActivationHandoffError):
        parse_controller_offer(json.dumps(value).encode("ascii"))
