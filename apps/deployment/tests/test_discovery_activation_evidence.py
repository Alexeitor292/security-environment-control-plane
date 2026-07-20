"""Detached-authentication and metadata tests for PR5F activation evidence."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION, PACKAGE_IMPLEMENTATION_ID
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
    ActivationEvidenceError,
    AdmissionTLSEvidence,
    ContainerRuntimeEvidence,
    EvidenceTrustAnchor,
    EvidenceTrustRoot,
    FixedInputEvidence,
    ManagedObjectRecord,
    PersistentStateEvidence,
    WorkerGeneration,
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

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SSH_FP = "SHA256:" + "A" * 43
NODE_ID = "11111111-1111-4111-8111-111111111111"


class _Signer:
    def __init__(self, *, key_id: str = "activation-evidence-test") -> None:
        self._key = Ed25519PrivateKey.generate()
        self._key_id = key_id

    def key_id(self) -> str:
        return self._key_id

    def attest(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def trust_root(self) -> EvidenceTrustRoot:
        public = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return EvidenceTrustRoot(
            anchors=(EvidenceTrustAnchor(self._key_id, public.hex()),), test_only=True
        )


_PATHS = {
    ROLE_PROFILE: PRODUCTION_LAYOUT.profile_path,
    ROLE_WORKER_OVERRIDE: PRODUCTION_LAYOUT.worker_compose_override_path,
    ROLE_WORKER_RUNTIME_OVERLAY: PRODUCTION_LAYOUT.worker_runtime_overlay_path,
    ROLE_CONTROLLER_OVERRIDE: PRODUCTION_LAYOUT.controller_compose_override_path,
    ROLE_PROXY_CONTRACT: PRODUCTION_LAYOUT.proxy_contract_path,
    ROLE_ADMISSION_CA: PRODUCTION_LAYOUT.ca_certificate_path,
    ROLE_ADMISSION_SERVER_CERTIFICATE: PRODUCTION_LAYOUT.server_certificate_path,
    ROLE_ADMISSION_SERVER_KEY: PRODUCTION_LAYOUT.server_private_key_path,
    ROLE_ADMISSION_PROXY_GATE: PRODUCTION_LAYOUT.admission_proxy_gate_path,
    ROLE_WORKER_STATE: PRODUCTION_LAYOUT.worker_state_host_path,
}


def _managed_objects(classification: str = CLASSIFICATION_CREATED):
    specs = (
        (ROLE_PROFILE, SHA_A, 0, 0, 0o640),
        (ROLE_WORKER_OVERRIDE, SHA_A, 0, 0, 0o640),
        (ROLE_WORKER_RUNTIME_OVERLAY, SHA_A, 0, 0, 0o644),
        (ROLE_CONTROLLER_OVERRIDE, SHA_A, 0, 0, 0o640),
        (ROLE_PROXY_CONTRACT, SHA_A, 0, 1002, 0o640),
        (ROLE_ADMISSION_CA, SHA_A, 0, 0, 0o644),
        (ROLE_ADMISSION_SERVER_CERTIFICATE, SHA_A, 0, 0, 0o644),
        (ROLE_ADMISSION_SERVER_KEY, None, 0, 1002, 0o640),
        (ROLE_ADMISSION_PROXY_GATE, None, 0, 1002, 0o640),
        (ROLE_WORKER_STATE, None, 1001, 1001, 0o700),
    )
    return tuple(
        ManagedObjectRecord(
            role=role,
            path_binding=path_binding_digest(role, _PATHS[role]),
            content_digest=content,
            owner_uid=uid,
            owner_gid=gid,
            mode=mode,
            classification=classification,
        )
        for role, content, uid, gid, mode in specs
    )


def _evidence(*, classification: str = CLASSIFICATION_CREATED) -> ActivationEvidence:
    configuration_roles = (
        ROLE_PROFILE,
        ROLE_WORKER_OVERRIDE,
        ROLE_WORKER_RUNTIME_OVERLAY,
        ROLE_CONTROLLER_OVERRIDE,
        ROLE_PROXY_CONTRACT,
        ROLE_ADMISSION_CA,
        ROLE_ADMISSION_SERVER_CERTIFICATE,
    )
    generation = WorkerGeneration(
        container_id="c" * 64,
        restart_count=0,
        started_at="2026-07-19T12:00:00Z",
    )
    return ActivationEvidence(
        contract_version=PACKAGE_CONTRACT_VERSION,
        implementation_id=PACKAGE_IMPLEMENTATION_ID,
        activation_status="public-node-published",
        worker_image_digest=SHA_B,
        worker_generation=generation,
        worker_base_compose=FixedInputEvidence(
            content_digest="sha256:" + "f" * 64,
            owner_uid=0,
            owner_gid=0,
            mode=0o640,
        ),
        worker_runtime=ContainerRuntimeEvidence(
            runtime_role="ordinary_worker",
            generation=generation,
            image_digest=SHA_B,
            configuration_digest="sha256:" + "1" * 64,
            mounts_digest="sha256:" + "2" * 64,
            networks_digest="sha256:" + "3" * 64,
            compose_project="secp",
            compose_service="worker",
            expected_image=True,
            hardening_verified=True,
            mounts_verified=True,
            endpoint_binding_verified=True,
        ),
        ordinary_task_queue=ORDINARY_TASK_QUEUE,
        configuration_artifact_digests={role: SHA_A for role in configuration_roles},
        managed_objects=_managed_objects(classification),
        persistent_state=PersistentStateEvidence(
            path_binding=path_binding_digest(
                ROLE_WORKER_STATE, PRODUCTION_LAYOUT.worker_state_host_path
            ),
            owner_uid=1001,
            owner_gid=1001,
            mode=0o700,
            key_directory_present=True,
            bundle_directory_present=True,
            key_file_count=4,
            bundle_file_count=0,
            keys_generated=True,
            bundle_populated=False,
            classification=classification,
        ),
        admission_tls=AdmissionTLSEvidence(
            ca_certificate_fingerprint=SHA_A,
            server_certificate_fingerprint=SHA_B,
            server_public_key_fingerprint="sha256:" + "d" * 64,
            server_dns_identity="admission.internal.test",
            server_dns_sans=("admission.internal.test",),
        ),
        worker_public_material=WorkerPublicEvidence(
            ssh_public_fingerprint=SSH_FP,
            admission_anchor_fingerprint="sha256:" + "e" * 64,
            worker_discovery_node_id=NODE_ID,
            worker_discovery_node_revision=3,
        ),
        installation_timestamp="2026-07-19T12:05:00Z",
        controller_installation_identity="controller.operator.test",
        worker_installation_identity="worker.operator.test",
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


def test_detached_signature_round_trip_authenticates_before_evidence_is_trusted() -> None:
    signer = _Signer()
    evidence = _evidence()
    attestation = issue_attestation(evidence, signer)

    parsed_evidence = parse_evidence_bytes(evidence_bytes(evidence))
    parsed_attestation = parse_attestation_bytes(attestation_bytes(attestation))
    verify_evidence(parsed_evidence, parsed_attestation, signer.trust_root())

    assert parsed_evidence.canonical() == evidence.canonical()
    assert parsed_attestation.key_id == "activation-evidence-test"


def test_evidence_contains_only_safe_metadata_and_never_private_or_raw_artifacts() -> None:
    raw = evidence_bytes(_evidence())
    text = raw.decode("utf-8")

    assert len(raw) < 256 * 1024
    for forbidden in (
        "PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "database_url",
        "raw_environment",
        "docker inspect",
        "proxmox_endpoint",
        PRODUCTION_LAYOUT.worker_state_host_path,
        PRODUCTION_LAYOUT.server_private_key_path,
    ):
        assert forbidden not in text
    assert "path_binding" in text
    assert "server_certificate_fingerprint" in text


def test_created_adopted_classification_tamper_parses_but_fails_signature() -> None:
    signer = _Signer()
    original = _evidence(classification=CLASSIFICATION_CREATED)
    attestation = issue_attestation(original, signer)
    document = original.canonical()
    document["persistent_state"]["classification"] = CLASSIFICATION_ADOPTED
    for item in document["managed_objects"]:
        item["classification"] = CLASSIFICATION_ADOPTED
    tampered = parse_evidence_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    )

    with pytest.raises(ActivationEvidenceError) as exc:
        verify_evidence(tampered, attestation, signer.trust_root())

    assert exc.value.reason_code == "evidence_attestation_invalid"


@pytest.mark.parametrize(("field", "value"), [("owner_uid", 0), ("mode", 0o750)])
def test_ownership_or_mode_tamper_is_rejected_during_strict_parse(field: str, value: int) -> None:
    document = _evidence().canonical()
    state = next(item for item in document["managed_objects"] if item["role"] == ROLE_WORKER_STATE)
    state[field] = value
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(ActivationEvidenceError) as exc:
        parse_evidence_bytes(raw)

    assert exc.value.reason_code.startswith("evidence_invalid:managed_objects")


@pytest.mark.parametrize("field", ["classification", "owner_uid", "owner_gid", "path_binding"])
def test_duplicate_persistent_state_metadata_must_match_authenticated_object_record(
    field: str,
) -> None:
    document = _evidence().canonical()
    replacements = {
        "classification": CLASSIFICATION_ADOPTED,
        "owner_uid": 1003,
        "owner_gid": 1003,
        "path_binding": "sha256:" + "f" * 64,
    }
    document["persistent_state"][field] = replacements[field]
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(ActivationEvidenceError):
        parse_evidence_bytes(raw)


def test_wrong_key_unknown_key_and_signature_tamper_fail_closed() -> None:
    signer = _Signer()
    evidence = _evidence()
    attestation = issue_attestation(evidence, signer)
    wrong = _Signer()

    with pytest.raises(ActivationEvidenceError):
        verify_evidence(evidence, attestation, wrong.trust_root())

    tampered = attestation.model_copy(update={"signature": "0" * 128})
    with pytest.raises(ActivationEvidenceError):
        verify_evidence(evidence, tampered, signer.trust_root())

    with pytest.raises(ActivationEvidenceError) as exc:
        verify_evidence(evidence, attestation, signer.trust_root(), expected_key_id="different-key")
    assert exc.value.reason_code == "evidence_attestation_key_mismatch"


def test_malformed_duplicate_oversized_and_forbidden_evidence_are_closed() -> None:
    with pytest.raises(ActivationEvidenceError, match="evidence_malformed"):
        parse_evidence_bytes(b"{")
    with pytest.raises(ActivationEvidenceError, match="evidence_duplicate_key"):
        parse_evidence_bytes(b'{"contract_version":"a","contract_version":"b"}')
    with pytest.raises(ActivationEvidenceError, match="evidence_size_invalid"):
        parse_evidence_bytes(b"x" * (256 * 1024 + 1))

    document = _evidence().canonical()
    document["database_password"] = "do-not-store"
    with pytest.raises(ActivationEvidenceError):
        parse_evidence_bytes(json.dumps(document).encode())


def test_attestation_repr_and_parsed_output_are_signature_bounded() -> None:
    signer = _Signer()
    attestation = issue_attestation(_evidence(), signer)
    raw = attestation_bytes(attestation)

    assert len(raw) < 16 * 1024
    assert len(attestation.signature) == 128
    with pytest.raises(ActivationEvidenceError, match="attestation_size_invalid"):
        parse_attestation_bytes(b"x" * (16 * 1024 + 1))
