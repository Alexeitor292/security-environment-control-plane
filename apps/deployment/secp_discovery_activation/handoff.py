"""Authenticated, secret-free handoffs for the two-host activation protocol.

The controller and ordinary worker are separate physical hosts.  This module defines the only
cross-host payloads they exchange: a controller TLS-ready offer and a worker activation result.
Transport is intentionally out of scope; production commands read and write fixed inbox/outbox
locations.  Neither payload contains an endpoint, certificate, private key, raw environment, Docker
inspection, credential, or target value.

Every handoff is detached-signed with a host-local Ed25519 evidence key.  The peer accepts the
included public key only when its SHA-256 key id equals the independently reviewed key-id pin in the
deployment profile.  Classification and mode facts are therefore authenticated before use.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from secp_commissioning.canonical import is_sha256_digest, sha256_digest

from secp_discovery_activation import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    DiscoveryActivationError,
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
    AdmissionTLSEvidence,
    ContainerRuntimeEvidence,
    FixedInputEvidence,
    PersistentStateEvidence,
    WorkerGeneration,
    WorkerPublicEvidence,
)
from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE
from secp_discovery_activation.migration_heads import ControllerMigrationHead

CONTROLLER_OFFER_SCHEMA = "secp.discovery-activation.controller-offer/v1"
WORKER_RESULT_SCHEMA = "secp.discovery-activation.worker-result/v1"
HANDOFF_ATTESTATION_SCHEMA = "secp.discovery-activation.handoff-attestation/v1"

_MAX_HANDOFF_BYTES = 256 * 1024
_MAX_ATTESTATION_BYTES = 16 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_CLASSIFICATIONS = frozenset({CLASSIFICATION_CREATED, CLASSIFICATION_ADOPTED})
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

#: Prefix marking a seal-posture refusal so ``parse_worker_result`` can surface WHICH seal failed
#: without widening the module's rule that every reason code is bounded and non-sensitive.
#:
#: Every other validation failure here collapses to a single ``worker_result_invalid``, which is
#: correct for a cross-host boundary: an error message must never carry attacker-influenced text.
#: But collapsing the seal posture too would mean an operator learns only that "something on the
#: worker host is unsafe" — and `unsealed` (the surface was exercised and did not refuse) calls for
#: a different response than `undetermined` (the derivation could not run). The name is therefore
#: carried through :func:`_bounded`, which admits only the safe-identifier shape this module
#: already enforces elsewhere, so nothing free-form can reach a log or a screen.
_SEAL_MARKER = "seal_posture:"
#: At most this many failing seals are named. The document is size-bounded but its seal list is
#: not, and a reason code is not a report.
_SEAL_DETAIL = 8


def _bounded(value: str) -> str:
    """A seal name or state, or ``unnamed`` when it is not the shape this module permits.

    The pairs arrive from the PEER host. Echoing one into a reason code without constraining its
    shape would turn a bounded error channel into an arbitrary-text one, which is the thing the
    whole module is careful about.
    """
    return value if _SAFE_ID.fullmatch(value) else "unnamed"


class ActivationHandoffError(DiscoveryActivationError):
    """A cross-host handoff failed closed with a bounded reason code."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise ValueError("timestamp invalid") from None
    if parsed.utcoffset() is None or not value.endswith("Z"):
        raise ValueError("timestamp invalid")
    return value


def _timestamp_value(value: str) -> datetime:
    _timestamp(value)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _digest_map(value: dict[str, str], expected: frozenset[str]) -> dict[str, str]:
    if set(value) != expected or any(not is_sha256_digest(item) for item in value.values()):
        raise ValueError("artifact digest set invalid")
    return value


def _classification_map(value: dict[str, str], expected: frozenset[str]) -> dict[str, str]:
    if set(value) != expected or any(item not in _CLASSIFICATIONS for item in value.values()):
        raise ValueError("object classification set invalid")
    return value


def _transaction_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError):
        raise ValueError("transaction id invalid") from None
    if str(parsed) != value or parsed.version != 4:
        raise ValueError("transaction id invalid")
    return value


class ControllerOffer(_Strict):
    """Controller-local TLS-ready commit offered to the worker host."""

    contract_schema: Literal["secp.discovery-activation.controller-offer/v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    contract_version: str
    implementation_id: str
    issuer_role: Literal["controller"]
    sequence: Literal[1]
    predecessor_digest: None
    transaction_id: str
    profile_digest: str
    plan_digest: str
    render_manifest_digest: str
    controller_artifact_digests: dict[str, str]
    worker_artifact_digests: dict[str, str]
    object_classifications: dict[str, str]
    controller_base_compose: FixedInputEvidence
    controller_runtimes: tuple[ContainerRuntimeEvidence, ...]
    # SECP-PR5H-A (ADR-027): the bounded rolling-upgrade window.  Validation accepts the legacy
    # PR5F head so an ALREADY-ISSUED signed offer stays verifiable; ISSUANCE emits only the
    # current head, and the declared head must still equal the OBSERVED controller head, so a
    # downgrade substitution is refused rather than silently accepted.
    controller_migration_head: ControllerMigrationHead
    admission_tls: AdmissionTLSEvidence
    installation_timestamp: str
    expires_at: str
    installation_identity: str
    rollback_journal_present: bool
    internal_tls_verified: bool
    forbidden_infrastructure_contacts_performed: bool
    workflows_submitted: bool
    operator_activated: bool
    run_plan_generation_called: bool
    opentofu_executed: bool
    proxmox_contacted: bool

    @field_validator("profile_digest", "plan_digest", "render_manifest_digest")
    @classmethod
    def _v_digest(cls, value: str) -> str:
        if not is_sha256_digest(value):
            raise ValueError("handoff digest invalid")
        return value

    @field_validator("transaction_id")
    @classmethod
    def _v_transaction_id(cls, value: str) -> str:
        return _transaction_id(value)

    @field_validator("controller_artifact_digests")
    @classmethod
    def _v_artifacts(cls, value: dict[str, str]) -> dict[str, str]:
        return _digest_map(
            value,
            frozenset(
                {
                    ROLE_CONTROLLER_OVERRIDE,
                    ROLE_PROXY_CONTRACT,
                    ROLE_ADMISSION_CA,
                    ROLE_ADMISSION_SERVER_CERTIFICATE,
                }
            ),
        )

    @field_validator("worker_artifact_digests")
    @classmethod
    def _v_worker_artifacts(cls, value: dict[str, str]) -> dict[str, str]:
        # The worker independently renders the override and imports the complete content-addressed
        # runtime overlay from fixed local paths.  Signing both digests lets that host reject
        # controller/worker drift while receiving only the CA certificate; the admission server
        # certificate never needs to be copied to the worker host.
        return _digest_map(value, frozenset({ROLE_WORKER_OVERRIDE, ROLE_WORKER_RUNTIME_OVERLAY}))

    @field_validator("object_classifications")
    @classmethod
    def _v_classifications(cls, value: dict[str, str]) -> dict[str, str]:
        return _classification_map(value, _CONTROLLER_ROLES)

    @field_validator("controller_runtimes", mode="before")
    @classmethod
    def _v_controller_runtimes_tuple(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("installation_timestamp", "expires_at")
    @classmethod
    def _v_timestamp(cls, value: str) -> str:
        return _timestamp(value)

    @field_validator("installation_identity")
    @classmethod
    def _v_identity(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("installation identity invalid")
        return value

    @model_validator(mode="after")
    def _v_semantics(self) -> ControllerOffer:
        if (
            self.contract_version != PACKAGE_CONTRACT_VERSION
            or self.implementation_id != PACKAGE_IMPLEMENTATION_ID
            or self.rollback_journal_present is not True
            or self.internal_tls_verified is not True
        ):
            raise ValueError("controller offer posture invalid")
        if any(
            (
                self.forbidden_infrastructure_contacts_performed,
                self.workflows_submitted,
                self.operator_activated,
                self.run_plan_generation_called,
                self.opentofu_executed,
                self.proxmox_contacted,
            )
        ):
            raise ValueError("controller offer effect posture invalid")
        issued = _timestamp_value(self.installation_timestamp)
        expires = _timestamp_value(self.expires_at)
        if not issued < expires <= issued + timedelta(hours=24):
            raise ValueError("controller offer validity invalid")
        if len(self.controller_runtimes) != 2 or {
            runtime.runtime_role for runtime in self.controller_runtimes
        } != {"controller_api", "admission_proxy"}:
            raise ValueError("controller runtime evidence invalid")
        return self

    def canonical(self) -> dict[str, object]:
        return self.model_dump(mode="json", by_alias=True)

    def digest(self) -> str:
        return sha256_digest(self.canonical())


class WorkerResult(_Strict):
    """Worker-local successful activation result returned to the controller host."""

    contract_schema: Literal["secp.discovery-activation.worker-result/v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    contract_version: str
    implementation_id: str
    issuer_role: Literal["worker"]
    sequence: Literal[2]
    predecessor_digest: str
    controller_offer_digest: str
    controller_transaction_id: str
    worker_transaction_id: str
    profile_digest: str
    plan_digest: str
    render_manifest_digest: str
    worker_image_digest: str
    worker_generation: WorkerGeneration
    ordinary_task_queue: str
    worker_artifact_digests: dict[str, str]
    object_classifications: dict[str, str]
    worker_base_compose: FixedInputEvidence
    worker_runtime: ContainerRuntimeEvidence
    persistent_state: PersistentStateEvidence
    admission_ca_fingerprint: str
    worker_public_material: WorkerPublicEvidence
    installation_timestamp: str
    installation_identity: str
    rollback_journal_present: bool
    worker_healthy: bool
    mount_isolated: bool
    bundle_prep_loop_started: bool
    database_private_material_absent: bool
    operator_service_present: bool
    operator_queue_polled: bool
    #: The per-seal states the worker host's probe actually OBSERVED, as ``(name, state)`` pairs.
    #:
    #: This replaces four booleans — ``generic_activation_subprocess_sealed``,
    #: ``generic_executor_subprocess_sealed``, ``plan_only_process_sealed`` and
    #: ``real_provisioning_enabled`` — and the replacement ADDS information rather than reshaping
    #: it, because those four were never four facts. Every one of them was set from a single
    #: ``probe.seals_valid``, two of them negated, and ``seals_valid`` is itself one whole-dict
    #: equality. Four names, four validator clauses, and one bit behind all of them.
    #:
    #: Worse, and the reason this is a wire-contract change rather than a tidy-up: the producer
    #: did not consult the probe at all. ``split_engine`` built this document with four hardcoded
    #: ``True/True/False/False`` literals, so the worker host SIGNED an attestation of a safety
    #: posture nothing on that host had observed — and ``_v_semantics`` "validated" it by requiring
    #: exactly those literals. A signed cross-host safety claim checked against itself.
    #:
    #: Two of the old names did not even correspond to seals the probe produces:
    #: ``plan_only_process_sealed`` had to be ``False`` here while the probe requires
    #: ``plan_only_process_gated`` to be ``sealed``, and ``apply_execution_absent`` — the seal the
    #: hold point actually needs — appeared under no name at all.
    #:
    #: VERSIONING. A pre-collapse document is REFUSED, not reinterpreted: ``_v_semantics`` already
    #: rejects any ``contract_version`` that is not the current one, so bumping that constant is
    #: the whole compatibility story. ``contract_schema`` deliberately stays at
    #: ``worker-result/v1`` because it names the document FAMILY, not its shape; the version field
    #: is the gate, and it is the one that is enforced. Refusing is a decision we make for a stated
    #: reason; reconstructing four states out of booleans that were never four observations would
    #: be fabrication wearing the new format's credibility.
    seal_states: tuple[tuple[str, str], ...]
    forbidden_infrastructure_contacts_performed: bool
    workflows_submitted: bool
    run_plan_generation_called: bool
    opentofu_executed: bool
    proxmox_contacted: bool

    @field_validator(
        "controller_offer_digest",
        "predecessor_digest",
        "profile_digest",
        "plan_digest",
        "render_manifest_digest",
        "worker_image_digest",
        "admission_ca_fingerprint",
    )
    @classmethod
    def _v_digest(cls, value: str) -> str:
        if not is_sha256_digest(value):
            raise ValueError("worker result digest invalid")
        return value

    @field_validator("controller_transaction_id", "worker_transaction_id")
    @classmethod
    def _v_transaction_id(cls, value: str) -> str:
        return _transaction_id(value)

    @field_validator("worker_artifact_digests")
    @classmethod
    def _v_artifacts(cls, value: dict[str, str]) -> dict[str, str]:
        return _digest_map(
            value,
            frozenset({ROLE_WORKER_OVERRIDE, ROLE_WORKER_RUNTIME_OVERLAY, ROLE_ADMISSION_CA}),
        )

    @field_validator("object_classifications")
    @classmethod
    def _v_classifications(cls, value: dict[str, str]) -> dict[str, str]:
        return _classification_map(value, _WORKER_ROLES)

    @field_validator("installation_timestamp")
    @classmethod
    def _v_timestamp(cls, value: str) -> str:
        return _timestamp(value)

    @field_validator("installation_identity")
    @classmethod
    def _v_identity(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("installation identity invalid")
        return value

    @field_validator("seal_states", mode="before")
    @classmethod
    def _v_seal_states_shape(cls, value: object) -> object:
        """Accept the JSON form of the pairs, and refuse anything that is not a pair of strings.

        This document is serialized, signed, transported and re-parsed, and ``model_dump(mode=
        "json")`` turns a tuple of tuples into a LIST OF LISTS. Under ``strict=True`` that no
        longer validates, so without this the document could not survive its own round trip — it
        would be produced successfully and refused on arrival, which reads exactly like tampering.
        """
        if not isinstance(value, list | tuple):
            return value
        coerced: list[tuple[str, str]] = []
        for item in value:
            if not isinstance(item, list | tuple) or len(item) != 2:
                raise ValueError("worker result seal state entry malformed")
            name, state = item
            if not isinstance(name, str) or not isinstance(state, str) or not name or not state:
                raise ValueError("worker result seal state entry malformed")
            coerced.append((name, state))
        return tuple(coerced)

    @model_validator(mode="after")
    def _v_semantics(self) -> WorkerResult:
        if (
            self.contract_version != PACKAGE_CONTRACT_VERSION
            or self.implementation_id != PACKAGE_IMPLEMENTATION_ID
            or self.ordinary_task_queue != ORDINARY_TASK_QUEUE
            or self.rollback_journal_present is not True
            or self.worker_healthy is not True
            or self.mount_isolated is not True
            or self.bundle_prep_loop_started is not True
            or self.database_private_material_absent is not True
            or self.operator_service_present is not False
            or self.operator_queue_polled is not False
        ):
            raise ValueError("worker result posture invalid")
        # The seal posture, checked against what ARRIVED rather than against four literals.
        #
        # Empty refuses instead of passing: `all()` over nothing is True, so a document carrying no
        # seals would otherwise assert a held posture by carrying no evidence of one. That is the
        # same failure mode as the old four booleans, reached by a different route.
        if not self.seal_states:
            raise ValueError(_SEAL_MARKER + "absent")
        # NAME the seals that did not hold. A bare "posture invalid" tells the operator that
        # something on the worker host is unsafe and not which thing, and `unsealed` (the surface
        # was exercised and did not refuse) calls for a different response than `undetermined`
        # (the derivation could not run). Any spelling other than `sealed` fails closed here, so a
        # typo or an unknown state is refused rather than silently treated as held.
        failing = tuple(
            f"{_bounded(name)}={_bounded(state)}"
            for name, state in self.seal_states
            if state != "sealed"
        )
        if failing:
            raise ValueError(_SEAL_MARKER + "invalid:" + ",".join(sorted(failing)[:_SEAL_DETAIL]))
        if self.object_classifications[ROLE_WORKER_STATE] != self.persistent_state.classification:
            raise ValueError("worker state classification mismatch")
        if (
            self.worker_runtime.runtime_role != "ordinary_worker"
            or self.worker_runtime.generation != self.worker_generation
            or self.worker_runtime.image_digest != self.worker_image_digest
        ):
            raise ValueError("worker runtime evidence mismatch")
        if self.predecessor_digest != self.controller_offer_digest:
            raise ValueError("worker result predecessor mismatch")
        if any(
            (
                self.forbidden_infrastructure_contacts_performed,
                self.workflows_submitted,
                self.run_plan_generation_called,
                self.opentofu_executed,
                self.proxmox_contacted,
            )
        ):
            raise ValueError("worker result effect posture invalid")
        return self

    def canonical(self) -> dict[str, object]:
        return self.model_dump(mode="json", by_alias=True)

    def digest(self) -> str:
        return sha256_digest(self.canonical())


class HandoffAttestation(_Strict):
    contract_schema: Literal["secp.discovery-activation.handoff-attestation/v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    algorithm: Literal["Ed25519"]
    key_id: str
    public_key_hex: str
    signature: str

    @model_validator(mode="after")
    def _v_attestation(self) -> HandoffAttestation:
        if (
            not is_sha256_digest(self.key_id)
            or not _HEX64.fullmatch(self.public_key_hex)
            or not _HEX128.fullmatch(self.signature)
        ):
            raise ValueError("handoff attestation invalid")
        raw = bytes.fromhex(self.public_key_hex)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != self.key_id:
            raise ValueError("handoff attestation key id mismatch")
        return self

    def canonical(self) -> dict[str, str]:
        return self.model_dump(mode="json", by_alias=True)


class HandoffSigner(Protocol):
    def key_id(self) -> str: ...

    def public_key_hex(self) -> str: ...

    def attest(self, message: bytes) -> str: ...


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def handoff_bytes(value: ControllerOffer | WorkerResult) -> bytes:
    return _canonical_bytes(value.canonical())


def attestation_bytes(value: HandoffAttestation) -> bytes:
    return _canonical_bytes(value.canonical())


def _message(kind: str, digest: str) -> bytes:
    return _canonical_bytes(
        {
            "domain": "secp.discovery-activation.cross-host-handoff/v1",
            "kind": kind,
            "digest": digest,
        }
    )


def issue_handoff_attestation(
    value: ControllerOffer | WorkerResult, signer: HandoffSigner
) -> HandoffAttestation:
    if type(value) not in {ControllerOffer, WorkerResult}:
        raise ActivationHandoffError("handoff_type_invalid")
    kind = "controller-offer" if type(value) is ControllerOffer else "worker-result"
    try:
        attestation = HandoffAttestation(
            schema="secp.discovery-activation.handoff-attestation/v1",
            algorithm="Ed25519",
            key_id=signer.key_id(),
            public_key_hex=signer.public_key_hex(),
            signature=signer.attest(_message(kind, value.digest())),
        )
    except DiscoveryActivationError:
        raise
    except Exception:
        raise ActivationHandoffError("handoff_attestation_failed") from None
    return attestation


def verify_handoff(
    value: ControllerOffer | WorkerResult,
    attestation: HandoffAttestation,
    *,
    expected_key_id: str,
) -> None:
    if (
        type(value) not in {ControllerOffer, WorkerResult}
        or type(attestation) is not HandoffAttestation
    ):
        raise ActivationHandoffError("handoff_type_invalid")
    if not is_sha256_digest(expected_key_id) or attestation.key_id != expected_key_id:
        raise ActivationHandoffError("handoff_signer_not_pinned")
    kind = "controller-offer" if type(value) is ControllerOffer else "worker-result"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(attestation.public_key_hex)).verify(
            bytes.fromhex(attestation.signature), _message(kind, value.digest())
        )
    except Exception:
        raise ActivationHandoffError("handoff_signature_invalid") from None


class _DuplicateKey(ValueError):
    pass


def _reject_duplicates(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _parse(raw: bytes, *, limit: int, what: str) -> object:
    if not isinstance(raw, bytes) or not (1 <= len(raw) <= limit):
        raise ActivationHandoffError(what + "_size_invalid")
    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates)
    except (_DuplicateKey, UnicodeDecodeError, ValueError):
        raise ActivationHandoffError(what + "_invalid") from None


def parse_controller_offer(raw: bytes) -> ControllerOffer:
    try:
        return ControllerOffer.model_validate(
            _parse(raw, limit=_MAX_HANDOFF_BYTES, what="controller_offer")
        )
    except ValidationError:
        raise ActivationHandoffError("controller_offer_invalid") from None


def _seal_posture_reason(exc: ValidationError) -> str | None:
    """The bounded seal-posture code, if that is why validation failed.

    Pydantic wraps a validator's ``ValueError`` message, so the marker is recovered from the error
    list rather than from the exception's string form — which also carries the input value and
    must never be surfaced.
    """
    for error in exc.errors():
        message = str(error.get("msg", ""))
        index = message.find(_SEAL_MARKER)
        if index >= 0:
            return message[index:]
    return None


def parse_worker_result(raw: bytes) -> WorkerResult:
    try:
        return WorkerResult.model_validate(
            _parse(raw, limit=_MAX_HANDOFF_BYTES, what="worker_result")
        )
    except ValidationError as exc:
        raise ActivationHandoffError(_seal_posture_reason(exc) or "worker_result_invalid") from None


def parse_handoff_attestation(raw: bytes) -> HandoffAttestation:
    try:
        return HandoffAttestation.model_validate(
            _parse(raw, limit=_MAX_ATTESTATION_BYTES, what="handoff_attestation")
        )
    except ValidationError:
        raise ActivationHandoffError("handoff_attestation_invalid") from None


__all__ = [
    "CONTROLLER_OFFER_SCHEMA",
    "WORKER_RESULT_SCHEMA",
    "HANDOFF_ATTESTATION_SCHEMA",
    "ActivationHandoffError",
    "ControllerOffer",
    "WorkerResult",
    "HandoffAttestation",
    "HandoffSigner",
    "handoff_bytes",
    "attestation_bytes",
    "issue_handoff_attestation",
    "verify_handoff",
    "parse_controller_offer",
    "parse_worker_result",
    "parse_handoff_attestation",
]
