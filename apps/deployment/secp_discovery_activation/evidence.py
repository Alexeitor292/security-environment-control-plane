"""Strict, nonsecret, detached-signed evidence for B8 activation.

The evidence record contains only exact identities, public fingerprints, closed status facts, and
topology-safe path bindings.  It never carries endpoint values, environment payloads, certificate
PEM, key material, credential material, or a Docker inspect document.  An on-disk record is not
trusted until its canonical bytes and detached Ed25519 signature verify against a provisioned trust
anchor.  In particular, created/adopted classification and ownership are authenticated facts, not
self-asserted rollback authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from secp_commissioning.canonical import (
    canonical_json,
    is_sha256_digest,
    sha256_bytes,
    sha256_digest,
)
from secp_commissioning.descriptor import scan_forbidden

from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    DiscoveryActivationError,
)
from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE, PRODUCTION_LAYOUT

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_SHA_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_EVIDENCE_BYTES = 256 * 1024
_MAX_ATTESTATION_BYTES = 16 * 1024

CLASSIFICATION_CREATED = "created"
CLASSIFICATION_ADOPTED = "adopted"
_CLASSIFICATIONS = frozenset({CLASSIFICATION_CREATED, CLASSIFICATION_ADOPTED})

ROLE_PROFILE = "activation_profile"
ROLE_WORKER_OVERRIDE = "worker_compose_override"
ROLE_WORKER_RUNTIME_OVERLAY = "worker_runtime_overlay"
ROLE_CONTROLLER_OVERRIDE = "controller_compose_override"
ROLE_PROXY_CONTRACT = "admission_proxy_contract"
ROLE_ADMISSION_CA = "admission_ca_certificate"
ROLE_ADMISSION_SERVER_CERTIFICATE = "admission_server_certificate"
ROLE_ADMISSION_SERVER_KEY = "admission_server_key"
ROLE_ADMISSION_PROXY_GATE = "admission_proxy_gate"
ROLE_WORKER_STATE = "worker_state"
_OBJECT_ROLES = frozenset(
    {
        ROLE_PROFILE,
        ROLE_WORKER_OVERRIDE,
        ROLE_WORKER_RUNTIME_OVERLAY,
        ROLE_CONTROLLER_OVERRIDE,
        ROLE_PROXY_CONTRACT,
        ROLE_ADMISSION_CA,
        ROLE_ADMISSION_SERVER_CERTIFICATE,
        ROLE_ADMISSION_SERVER_KEY,
        ROLE_ADMISSION_PROXY_GATE,
        ROLE_WORKER_STATE,
    }
)
_NO_CONTENT_DIGEST = frozenset(
    {ROLE_ADMISSION_SERVER_KEY, ROLE_ADMISSION_PROXY_GATE, ROLE_WORKER_STATE}
)


class ActivationEvidenceError(DiscoveryActivationError):
    """Evidence parsing, semantics, or authentication failed closed."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def path_binding_digest(role: str, absolute_path: str) -> str:
    """Bind a closed object role to its code-owned path without retaining the path."""

    if role not in _OBJECT_ROLES:
        raise ActivationEvidenceError("evidence_object_role_invalid")
    return sha256_digest(
        {"v": "secp.discovery-activation.path/v1", "role": role, "path": absolute_path}
    )


class ManagedObjectRecord(_Strict):
    role: str
    path_binding: str
    content_digest: str | None
    owner_uid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    owner_gid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    mode: Annotated[int, Field(ge=0, le=0o7777, strict=True)]
    classification: str

    @field_validator("role")
    @classmethod
    def _v_role(cls, value: str) -> str:
        if value not in _OBJECT_ROLES:
            raise ValueError("unknown activation object role")
        return value

    @field_validator("path_binding")
    @classmethod
    def _v_binding(cls, value: str) -> str:
        if not is_sha256_digest(value):
            raise ValueError("invalid path binding")
        return value

    @field_validator("content_digest")
    @classmethod
    def _v_content(cls, value: str | None) -> str | None:
        if value is not None and not is_sha256_digest(value):
            raise ValueError("invalid content digest")
        return value

    @field_validator("classification")
    @classmethod
    def _v_classification(cls, value: str) -> str:
        if value not in _CLASSIFICATIONS:
            raise ValueError("invalid ownership classification")
        return value

    @model_validator(mode="after")
    def _v_role_content(self) -> ManagedObjectRecord:
        if (self.role in _NO_CONTENT_DIGEST) != (self.content_digest is None):
            raise ValueError("object content binding posture invalid")
        if self.role == ROLE_WORKER_STATE:
            if self.mode != 0o700 or self.owner_uid == 0 or self.owner_gid == 0:
                raise ValueError("worker state ownership invalid")
        elif self.role in {ROLE_ADMISSION_SERVER_KEY, ROLE_ADMISSION_PROXY_GATE}:
            if self.mode != 0o640 or self.owner_uid != 0 or self.owner_gid == 0:
                raise ValueError("private deployment material ownership invalid")
        elif self.role == ROLE_PROXY_CONTRACT:
            if self.mode != 0o640 or self.owner_uid != 0 or self.owner_gid == 0:
                raise ValueError("proxy contract ownership invalid")
        elif self.role in (
            ROLE_ADMISSION_CA,
            ROLE_ADMISSION_SERVER_CERTIFICATE,
            ROLE_WORKER_RUNTIME_OVERLAY,
        ):
            if self.mode != 0o644 or self.owner_uid != 0 or self.owner_gid != 0:
                raise ValueError("certificate ownership invalid")
        elif self.owner_uid != 0 or self.owner_gid != 0 or self.mode != 0o640:
            raise ValueError("root artifact ownership invalid")
        return self


class WorkerGeneration(_Strict):
    container_id: str
    restart_count: Annotated[int, Field(ge=0, le=10**9, strict=True)]
    started_at: str

    @field_validator("container_id")
    @classmethod
    def _v_container_id(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("container id invalid")
        return value

    @field_validator("started_at")
    @classmethod
    def _v_started(cls, value: str) -> str:
        _require_timestamp(value, "container start timestamp invalid")
        return value

    def digest(self) -> str:
        return sha256_digest(self.model_dump(mode="json"))


class FixedInputEvidence(_Strict):
    """Content and metadata binding for one fixed, adopted base Compose input."""

    content_digest: str
    owner_uid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    owner_gid: Annotated[int, Field(ge=0, le=2**31 - 1, strict=True)]
    mode: Annotated[int, Field(ge=0, le=0o7777, strict=True)]

    @model_validator(mode="after")
    def _v_fixed_input(self) -> FixedInputEvidence:
        if (
            not is_sha256_digest(self.content_digest)
            or self.owner_uid != 0
            or self.mode not in {0o600, 0o640, 0o644}
        ):
            raise ValueError("fixed input binding invalid")
        return self


class ContainerRuntimeEvidence(_Strict):
    """Bounded proof of the exact live runtime generation selected by Compose."""

    runtime_role: Literal["controller_api", "admission_proxy", "ordinary_worker"]
    generation: WorkerGeneration
    image_digest: str
    configuration_digest: str
    mounts_digest: str
    networks_digest: str
    compose_project: str
    compose_service: str
    expected_image: bool
    hardening_verified: bool
    mounts_verified: bool
    endpoint_binding_verified: bool

    @field_validator("image_digest", "configuration_digest", "mounts_digest", "networks_digest")
    @classmethod
    def _v_digest(cls, value: str) -> str:
        if not is_sha256_digest(value):
            raise ValueError("container runtime digest invalid")
        return value

    @field_validator("compose_project", "compose_service")
    @classmethod
    def _v_compose_identity(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("container Compose identity invalid")
        return value

    @model_validator(mode="after")
    def _v_runtime(self) -> ContainerRuntimeEvidence:
        if not (self.expected_image and self.hardening_verified and self.mounts_verified):
            raise ValueError("container runtime posture invalid")
        if self.runtime_role == "ordinary_worker" and not self.endpoint_binding_verified:
            raise ValueError("worker endpoint binding invalid")
        return self


class PersistentStateEvidence(_Strict):
    path_binding: str
    owner_uid: Annotated[int, Field(ge=1, le=65533, strict=True)]
    owner_gid: Annotated[int, Field(ge=1, le=65533, strict=True)]
    mode: Annotated[int, Field(ge=0, le=0o7777, strict=True)]
    key_directory_present: bool
    bundle_directory_present: bool
    key_file_count: Annotated[int, Field(ge=0, le=4, strict=True)]
    bundle_file_count: Annotated[int, Field(ge=0, le=4, strict=True)]
    keys_generated: bool
    bundle_populated: bool
    classification: str

    @field_validator("path_binding")
    @classmethod
    def _v_binding(cls, value: str) -> str:
        if not is_sha256_digest(value):
            raise ValueError("state path binding invalid")
        return value

    @field_validator("classification")
    @classmethod
    def _v_classification(cls, value: str) -> str:
        if value not in _CLASSIFICATIONS:
            raise ValueError("state classification invalid")
        return value

    @model_validator(mode="after")
    def _v_state(self) -> PersistentStateEvidence:
        if self.mode != 0o700:
            raise ValueError("state mode invalid")
        if not (self.key_directory_present and self.bundle_directory_present):
            raise ValueError("state directories incomplete")
        if self.keys_generated != (self.key_file_count == 4):
            raise ValueError("state key count inconsistent")
        if self.bundle_populated != (self.bundle_file_count == 4):
            raise ValueError("state bundle count inconsistent")
        return self


class AdmissionTLSEvidence(_Strict):
    ca_certificate_fingerprint: str
    server_certificate_fingerprint: str
    server_public_key_fingerprint: str
    server_dns_identity: str
    server_dns_sans: tuple[str, ...]

    @field_validator(
        "ca_certificate_fingerprint",
        "server_certificate_fingerprint",
        "server_public_key_fingerprint",
    )
    @classmethod
    def _v_fingerprint(cls, value: str) -> str:
        if not _SHA_FINGERPRINT.fullmatch(value):
            raise ValueError("TLS fingerprint invalid")
        return value

    @field_validator("server_dns_sans", mode="before")
    @classmethod
    def _v_sans_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _v_identity(self) -> AdmissionTLSEvidence:
        if self.server_dns_sans != (self.server_dns_identity,):
            raise ValueError("TLS identity/SAN mismatch")
        return self


class WorkerPublicEvidence(_Strict):
    ssh_public_fingerprint: str
    admission_anchor_fingerprint: str
    worker_discovery_node_id: str
    worker_discovery_node_revision: Annotated[int, Field(ge=1, le=2**31 - 1, strict=True)]

    @field_validator("ssh_public_fingerprint")
    @classmethod
    def _v_ssh(cls, value: str) -> str:
        if not _SSH_FINGERPRINT.fullmatch(value):
            raise ValueError("SSH public fingerprint invalid")
        return value

    @field_validator("admission_anchor_fingerprint")
    @classmethod
    def _v_anchor(cls, value: str) -> str:
        if not _SHA_FINGERPRINT.fullmatch(value):
            raise ValueError("admission public fingerprint invalid")
        return value

    @field_validator("worker_discovery_node_id")
    @classmethod
    def _v_node_id(cls, value: str) -> str:
        if not _UUID.fullmatch(value):
            raise ValueError("worker node id invalid")
        return value


class ActivationEvidence(_Strict):
    contract_version: str
    implementation_id: str
    activation_status: str
    worker_image_digest: str
    worker_generation: WorkerGeneration
    worker_base_compose: FixedInputEvidence
    worker_runtime: ContainerRuntimeEvidence
    ordinary_task_queue: str
    configuration_artifact_digests: dict[str, str]
    managed_objects: tuple[ManagedObjectRecord, ...]
    persistent_state: PersistentStateEvidence
    admission_tls: AdmissionTLSEvidence
    worker_public_material: WorkerPublicEvidence
    installation_timestamp: str
    controller_installation_identity: str
    worker_installation_identity: str
    operator_service_present: bool
    operator_queue_polled: bool
    generic_activation_subprocess_sealed: bool
    generic_executor_subprocess_sealed: bool
    plan_only_process_sealed: bool
    real_provisioning_enabled: bool
    # Required controller-database and pinned internal-admission observations are reported by the
    # positive readiness/publication fields above.  This flag is deliberately scoped to the
    # forbidden target/orchestration/state/secret infrastructure that activation must never touch.
    forbidden_infrastructure_contacts_performed: bool
    workflows_submitted: bool
    run_plan_generation_called: bool
    opentofu_executed: bool
    proxmox_contacted: bool

    @field_validator("managed_objects", mode="before")
    @classmethod
    def _v_objects_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("worker_image_digest")
    @classmethod
    def _v_image(cls, value: str) -> str:
        if not is_sha256_digest(value):
            raise ValueError("worker image digest invalid")
        return value

    @field_validator("installation_timestamp")
    @classmethod
    def _v_timestamp(cls, value: str) -> str:
        _require_timestamp(value, "installation timestamp invalid")
        return value

    @field_validator("controller_installation_identity", "worker_installation_identity")
    @classmethod
    def _v_identity(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("installation identity invalid")
        return value

    @model_validator(mode="after")
    def _v_semantics(self) -> ActivationEvidence:
        if self.contract_version != PACKAGE_CONTRACT_VERSION:
            raise ValueError("activation evidence contract invalid")
        if self.implementation_id != PACKAGE_IMPLEMENTATION_ID:
            raise ValueError("activation evidence implementation invalid")
        if self.activation_status != "public-node-published":
            raise ValueError("activation evidence status invalid")
        if self.ordinary_task_queue != ORDINARY_TASK_QUEUE:
            raise ValueError("ordinary queue invalid")
        if (
            self.worker_runtime.runtime_role != "ordinary_worker"
            or self.worker_runtime.generation != self.worker_generation
            or self.worker_runtime.image_digest != self.worker_image_digest
        ):
            raise ValueError("worker runtime evidence mismatch")
        expected_digest_roles = {
            ROLE_PROFILE,
            ROLE_WORKER_OVERRIDE,
            ROLE_WORKER_RUNTIME_OVERLAY,
            ROLE_CONTROLLER_OVERRIDE,
            ROLE_PROXY_CONTRACT,
            ROLE_ADMISSION_CA,
            ROLE_ADMISSION_SERVER_CERTIFICATE,
        }
        if set(self.configuration_artifact_digests) != expected_digest_roles:
            raise ValueError("configuration artifact digest set incomplete")
        if any(not is_sha256_digest(v) for v in self.configuration_artifact_digests.values()):
            raise ValueError("configuration artifact digest invalid")
        if {record.role for record in self.managed_objects} != _OBJECT_ROLES:
            raise ValueError("managed object record set incomplete")
        if len(self.managed_objects) != len(_OBJECT_ROLES):
            raise ValueError("managed object record duplicate")
        if self.operator_service_present is not False or self.operator_queue_polled is not False:
            raise ValueError("operator absence invalid")
        if not self.persistent_state.keys_generated:
            raise ValueError("published activation evidence requires persistent keys")
        state_record = next(
            record for record in self.managed_objects if record.role == ROLE_WORKER_STATE
        )
        if state_record.classification != self.persistent_state.classification:
            raise ValueError("state classification mismatch")
        if (
            state_record.path_binding != self.persistent_state.path_binding
            or state_record.owner_uid != self.persistent_state.owner_uid
            or state_record.owner_gid != self.persistent_state.owner_gid
            or state_record.mode != self.persistent_state.mode
        ):
            raise ValueError("state metadata binding mismatch")
        paths = {
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
        if any(
            record.path_binding != path_binding_digest(record.role, paths[record.role])
            for record in self.managed_objects
        ):
            raise ValueError("managed object path binding mismatch")
        proxy_record = next(
            record for record in self.managed_objects if record.role == ROLE_PROXY_CONTRACT
        )
        key_record = next(
            record for record in self.managed_objects if record.role == ROLE_ADMISSION_SERVER_KEY
        )
        gate_record = next(
            record for record in self.managed_objects if record.role == ROLE_ADMISSION_PROXY_GATE
        )
        if not (proxy_record.owner_gid == key_record.owner_gid == gate_record.owner_gid):
            raise ValueError("proxy group binding mismatch")
        record_digests = {
            record.role: record.content_digest
            for record in self.managed_objects
            if record.content_digest is not None
        }
        if record_digests != self.configuration_artifact_digests:
            raise ValueError("configuration object digest mismatch")
        if (
            self.generic_activation_subprocess_sealed is not True
            or self.generic_executor_subprocess_sealed is not True
            or self.plan_only_process_sealed is not False
            or self.real_provisioning_enabled is not False
        ):
            raise ValueError("safety seal posture invalid")
        for field_name in (
            "forbidden_infrastructure_contacts_performed",
            "workflows_submitted",
            "run_plan_generation_called",
            "opentofu_executed",
            "proxmox_contacted",
        ):
            if getattr(self, field_name) is not False:
                raise ValueError("effect flag invalid")
        return self

    def canonical(self) -> dict[str, object]:
        return self.model_dump(mode="json")

    def digest(self) -> str:
        return sha256_digest(self.canonical())


class EvidenceAttestation(_Strict):
    algorithm: str
    key_id: str
    signature: Annotated[str, Field(min_length=128, max_length=128, strict=True)]

    @model_validator(mode="after")
    def _v_attestation(self) -> EvidenceAttestation:
        if self.algorithm != "ed25519":
            raise ValueError("attestation algorithm invalid")
        if not _SAFE_ID.fullmatch(self.key_id) or not re.fullmatch(
            r"[0-9a-f]{128}", self.signature
        ):
            raise ValueError("attestation value invalid")
        return self

    def canonical(self) -> dict[str, str]:
        return self.model_dump(mode="json")


def evidence_message(evidence: ActivationEvidence) -> bytes:
    return canonical_json(
        {
            "v": "secp.discovery-activation.evidence-attestation/v1",
            "evidence_sha256": sha256_bytes(evidence_bytes(evidence)),
            "controller_installation_identity": evidence.controller_installation_identity,
            "worker_installation_identity": evidence.worker_installation_identity,
            "installation_timestamp": evidence.installation_timestamp,
            "managed_objects": [
                record.model_dump(mode="json") for record in evidence.managed_objects
            ],
        }
    ).encode("utf-8")


def evidence_bytes(evidence: ActivationEvidence) -> bytes:
    return canonical_json(evidence.canonical()).encode("utf-8")


def attestation_bytes(attestation: EvidenceAttestation) -> bytes:
    return canonical_json(attestation.canonical()).encode("utf-8")


class EvidenceAuthenticator(Protocol):
    def key_id(self) -> str: ...

    def attest(self, message: bytes) -> str: ...


class SealedEvidenceAuthenticator:
    """Fail-closed default until a host-local reviewed key provider is composed."""

    def key_id(self) -> str:
        raise ActivationEvidenceError("evidence_authenticator_not_provisioned")

    def attest(self, message: bytes) -> str:
        raise ActivationEvidenceError("evidence_authenticator_not_provisioned")


@dataclass(frozen=True)
class EvidenceTrustAnchor:
    key_id: str
    public_key_hex: str


@dataclass(frozen=True)
class EvidenceTrustRoot:
    anchors: tuple[EvidenceTrustAnchor, ...]
    test_only: bool = False

    def verify(self, *, key_id: str, message: bytes, signature: str) -> bool:
        for anchor in self.anchors:
            if anchor.key_id != key_id:
                continue
            try:
                public = bytes.fromhex(anchor.public_key_hex)
                signed = bytes.fromhex(signature)
                if len(public) != 32 or len(signed) != 64:
                    return False
                Ed25519PublicKey.from_public_bytes(public).verify(signed, message)
                return True
            except Exception:
                return False
        return False


SHIPPED_EVIDENCE_TRUST_ROOT = EvidenceTrustRoot(anchors=())


def issue_attestation(
    evidence: ActivationEvidence, authenticator: EvidenceAuthenticator
) -> EvidenceAttestation:
    key_id = authenticator.key_id()
    if not _SAFE_ID.fullmatch(key_id):
        raise ActivationEvidenceError("evidence_authenticator_identity_invalid")
    signature = authenticator.attest(evidence_message(evidence))
    try:
        return EvidenceAttestation(algorithm="ed25519", key_id=key_id, signature=signature)
    except ValidationError:
        raise ActivationEvidenceError("evidence_authenticator_signature_invalid") from None


def parse_evidence_bytes(raw: bytes) -> ActivationEvidence:
    parsed = _parse_json(raw, _MAX_EVIDENCE_BYTES, "evidence")
    if not isinstance(parsed, dict):
        raise ActivationEvidenceError("evidence_not_object")
    try:
        scan_forbidden(parsed)
        return ActivationEvidence.model_validate(parsed)
    except ValidationError as exc:
        raise ActivationEvidenceError("evidence_invalid:" + _safe_field(exc)) from None
    except Exception:
        raise ActivationEvidenceError("evidence_forbidden_content") from None


def parse_attestation_bytes(raw: bytes) -> EvidenceAttestation:
    parsed = _parse_json(raw, _MAX_ATTESTATION_BYTES, "attestation")
    if not isinstance(parsed, dict):
        raise ActivationEvidenceError("attestation_not_object")
    try:
        scan_forbidden(parsed)
        return EvidenceAttestation.model_validate(parsed)
    except ValidationError as exc:
        raise ActivationEvidenceError("attestation_invalid:" + _safe_field(exc)) from None
    except Exception:
        raise ActivationEvidenceError("attestation_forbidden_content") from None


def verify_evidence(
    evidence: ActivationEvidence,
    attestation: EvidenceAttestation,
    trust_root: EvidenceTrustRoot,
    *,
    expected_key_id: str | None = None,
) -> None:
    """Authenticate before a caller uses classification, uid/gid, mode, or rollback authority."""

    if type(evidence) is not ActivationEvidence or type(attestation) is not EvidenceAttestation:
        raise ActivationEvidenceError("evidence_type_invalid")
    if type(trust_root) is not EvidenceTrustRoot:
        raise ActivationEvidenceError("evidence_trust_root_invalid")
    if expected_key_id is not None and attestation.key_id != expected_key_id:
        raise ActivationEvidenceError("evidence_attestation_key_mismatch")
    if not trust_root.verify(
        key_id=attestation.key_id,
        message=evidence_message(evidence),
        signature=attestation.signature,
    ):
        raise ActivationEvidenceError("evidence_attestation_invalid")


def _parse_json(raw: bytes, limit: int, what: str) -> object:
    if not isinstance(raw, bytes) or not (1 <= len(raw) <= limit):
        raise ActivationEvidenceError(what + "_size_invalid")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except _DuplicateKey:
        raise ActivationEvidenceError(what + "_duplicate_key") from None
    except (UnicodeDecodeError, ValueError):
        raise ActivationEvidenceError(what + "_malformed") from None


class _DuplicateKey(ValueError):
    pass


def _reject_duplicates(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _require_timestamp(value: str, reason: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ValueError(reason) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(reason)


def _safe_field(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "document"
    loc = errors[0].get("loc", ())
    if errors[0].get("type") == "extra_forbidden":
        loc = loc[:-1]
    field = ".".join(str(p) for p in loc if isinstance(p, str)) or "document"
    return re.sub(r"[^A-Za-z0-9_.]", "", field)[:56]


__all__ = [
    "ActivationEvidenceError",
    "ManagedObjectRecord",
    "WorkerGeneration",
    "FixedInputEvidence",
    "ContainerRuntimeEvidence",
    "PersistentStateEvidence",
    "AdmissionTLSEvidence",
    "WorkerPublicEvidence",
    "ActivationEvidence",
    "EvidenceAttestation",
    "EvidenceAuthenticator",
    "SealedEvidenceAuthenticator",
    "EvidenceTrustAnchor",
    "EvidenceTrustRoot",
    "SHIPPED_EVIDENCE_TRUST_ROOT",
    "path_binding_digest",
    "evidence_bytes",
    "attestation_bytes",
    "issue_attestation",
    "parse_evidence_bytes",
    "parse_attestation_bytes",
    "verify_evidence",
    "CLASSIFICATION_CREATED",
    "CLASSIFICATION_ADOPTED",
    "ROLE_PROFILE",
    "ROLE_WORKER_OVERRIDE",
    "ROLE_WORKER_RUNTIME_OVERLAY",
    "ROLE_CONTROLLER_OVERRIDE",
    "ROLE_PROXY_CONTRACT",
    "ROLE_ADMISSION_CA",
    "ROLE_ADMISSION_SERVER_CERTIFICATE",
    "ROLE_ADMISSION_SERVER_KEY",
    "ROLE_ADMISSION_PROXY_GATE",
    "ROLE_WORKER_STATE",
]
