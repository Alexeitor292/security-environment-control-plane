"""Plan-execution JIT secret resolution — TWO separate credentials (B1B-PR5B, ADR-022 §10/§7).

This is a SEPARATE resolver seam from the read-only-preflight resolver and from the plan-secret
readiness SELF-TEST: readiness authority is never reused as execution authority. It resolves exactly
two credentials, each with its own dedicated purpose, its own capability, and its own independently
verified contract:

* ``provider_plan_read`` — the READ-ONLY provider (Proxmox) plan credential.
* ``state_backend_plan`` — the SEPARATE remote-state-backend plan credential.

Each resolution independently re-verifies, against the authoritative contract, the exact purpose,
target reference, credential binding id + version, the ``dedicated_operation`` binding source (never
the generic ``secret_ref`` fallback), manifest/dossier agreement, worker identity, resolver
activation, resolver contract version, reference scheme, operation fingerprint, and expiry. The
provider and state credentials remain SEPARATE typed :class:`SecretMaterial` objects; neither value
ever crosses into the other's projection.

The shipped default (:class:`SealedPlanSecretResolver`) enforces the contract and then ALWAYS fails
closed — it resolves nothing, reads no environment, and contacts no backend. Nothing here persists,
logs, audits, serializes, or hashes a secret, a reference, or a backend response.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import NoReturn, Protocol, SupportsIndex, runtime_checkable

from secp_worker.preflight.secret_resolution import SecretMaterial
from secp_worker.secrets import SecretResolutionError

# The reviewed plan-execution resolver contract version. A self-declared version is not sufficient:
# the resolver activation is verified against the reviewed composition (see composition.py).
PLAN_EXECUTION_RESOLVER_CONTRACT_VERSION = "secp-002b-1b-pr5b/plan-execution-resolver/v1"

# The only two purposes a plan-execution resolver may act on. Apply/destroy purposes are
# unrepresentable.
_SUPPORTED_REFERENCE_SCHEMES = frozenset({"openbao", "vault", "secretref"})


class PlanExecutionResolutionPurpose(str, Enum):
    """The two SEPARATE plan-execution credential purposes (never apply/destroy)."""

    provider_plan_read = "provider_plan_read"
    state_backend_plan = "state_backend_plan"


class PlanSecretResolutionUnavailable(SecretResolutionError):
    """The sealed default: no production plan-execution resolver is configured (fail closed)."""


class PlanResolutionContractViolation(SecretResolutionError):
    """The request does not match the authoritative plan-execution binding (bounded reason only)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"plan resolution contract violation: {reason_code}")
        self.reason_code = reason_code


class PlanCredentialReference:
    """An opaque plan-execution credential-reference locator, never the secret value.

    Redacted in every string/repr form and non-serializable. Only a future worker-only backend
    adapter would read the underlying locator; nothing in this PR does.
    """

    __slots__ = ("__ref", "__scheme")

    def __init__(self, reference: str, *, scheme: str) -> None:
        self.__ref = reference
        self.__scheme = scheme

    @property
    def is_blank(self) -> bool:
        return not (isinstance(self.__ref, str) and self.__ref.strip() != "")

    @property
    def scheme(self) -> str:
        return self.__scheme

    def reveal_reference(self) -> str:
        """Return the opaque locator for a FUTURE worker-only backend adapter only."""
        return self.__ref

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PlanCredentialReference):
            return NotImplemented
        return self.__ref == other.__ref and self.__scheme == other.__scheme

    def __hash__(self) -> int:
        return hash(("PlanCredentialReference", self.__ref, self.__scheme))

    def __repr__(self) -> str:
        return "PlanCredentialReference(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("PlanCredentialReference cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("PlanCredentialReference cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("PlanCredentialReference cannot be pickled")


@dataclass(frozen=True, repr=False)
class PlanExecutionResolutionContract:
    """The immutable, redacted authoritative facts ONE plan-execution resolution is bound to."""

    purpose: PlanExecutionResolutionPurpose
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    provisioning_manifest_id: uuid.UUID
    provisioning_manifest_content_hash: str
    activation_dossier_id: uuid.UUID
    activation_dossier_hash: str
    credential_binding_id: uuid.UUID
    credential_binding_version: int
    binding_source: str  # must be "dedicated_operation"
    worker_identity_registration_id: uuid.UUID
    worker_identity_version: int
    resolver_contract_version: str
    operation_fingerprint: str
    authorization_expiry: str  # canonical ISO-8601 UTC ending in "Z"
    execution_lease_id: uuid.UUID
    attempt_number: int
    credential_reference: PlanCredentialReference

    def __repr__(self) -> str:
        return (
            "PlanExecutionResolutionContract("
            f"purpose={self.purpose.value!r}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"credential_binding_id={self.credential_binding_id!s}, "
            f"credential_binding_version={self.credential_binding_version!r}, "
            f"operation_fingerprint={self.operation_fingerprint!r}, "
            "credential_reference=<redacted>)"
        )


# Module-private token: only this module (via the post-verification factory) can build a request.
_PLAN_RESOLUTION_TOKEN = object()


class TrustedPlanResolutionRequest:
    """The request handed across the plan-execution resolver boundary. Worker-constructed only."""

    __slots__ = ("__contract",)

    def __init__(self, contract: PlanExecutionResolutionContract, *, token: object) -> None:
        if token is not _PLAN_RESOLUTION_TOKEN:
            raise TypeError(
                "TrustedPlanResolutionRequest is worker-constructed only; call "
                "build_trusted_plan_resolution_request() after the binding is derived"
            )
        self.__contract = contract

    @property
    def contract(self) -> PlanExecutionResolutionContract:
        return self.__contract

    def __repr__(self) -> str:
        return "TrustedPlanResolutionRequest(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("TrustedPlanResolutionRequest cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("TrustedPlanResolutionRequest cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("TrustedPlanResolutionRequest cannot be pickled")


def build_trusted_plan_resolution_request(
    contract: PlanExecutionResolutionContract,
) -> TrustedPlanResolutionRequest:
    """Build the ONLY trusted plan-execution request from an authoritative contract."""
    return TrustedPlanResolutionRequest(contract, token=_PLAN_RESOLUTION_TOKEN)


def derive_reference_scheme(reference: str) -> str:
    """Derive and validate the reference scheme (``vault``/``openbao``/``secretref``), or refuse."""
    if not isinstance(reference, str) or not reference.strip():
        raise PlanResolutionContractViolation("credential_reference_missing")
    head = reference.split("://", 1)[0] if "://" in reference else reference.split(":", 1)[0]
    scheme = head.strip().lower()
    if scheme not in _SUPPORTED_REFERENCE_SCHEMES:
        raise PlanResolutionContractViolation("reference_scheme_unsupported")
    return scheme


def assert_plan_resolution_authorized(  # noqa: C901, PLR0912 - one explicit refusal per bound fact
    candidate: PlanExecutionResolutionContract,
    authoritative: PlanExecutionResolutionContract,
    *,
    now: datetime,
) -> None:
    """Refuse unless ``candidate`` matches ``authoritative`` on every binding fact (bounded reason).

    Independent, per-fact checks: purpose; organization; target; manifest id + content hash;
    dossier id + hash; credential binding id + version; the ``dedicated_operation`` binding source
    (never the generic ``secret_ref`` fallback); worker identity + version; resolver contract
    version; reference scheme; operation fingerprint; execution lease + attempt; a non-blank
    matching opaque reference; and an unexpired authorization.
    """
    if candidate.purpose != authoritative.purpose:
        raise PlanResolutionContractViolation("purpose_mismatch")
    if candidate.organization_id != authoritative.organization_id:
        raise PlanResolutionContractViolation("wrong_organization")
    if candidate.execution_target_id != authoritative.execution_target_id:
        raise PlanResolutionContractViolation("wrong_execution_target")
    if candidate.provisioning_manifest_id != authoritative.provisioning_manifest_id:
        raise PlanResolutionContractViolation("wrong_manifest")
    if (
        candidate.provisioning_manifest_content_hash
        != authoritative.provisioning_manifest_content_hash
    ):
        raise PlanResolutionContractViolation("manifest_hash_mismatch")
    if candidate.activation_dossier_id != authoritative.activation_dossier_id:
        raise PlanResolutionContractViolation("wrong_dossier")
    if candidate.activation_dossier_hash != authoritative.activation_dossier_hash:
        raise PlanResolutionContractViolation("dossier_hash_mismatch")
    if candidate.credential_binding_id != authoritative.credential_binding_id:
        raise PlanResolutionContractViolation("wrong_credential_binding")
    if candidate.credential_binding_version != authoritative.credential_binding_version:
        raise PlanResolutionContractViolation("credential_binding_version_mismatch")
    # The binding MUST be a dedicated-operation binding; a legacy generic secret_ref never resolves.
    if candidate.binding_source != "dedicated_operation":
        raise PlanResolutionContractViolation("binding_source_not_dedicated")
    if authoritative.binding_source != "dedicated_operation":
        raise PlanResolutionContractViolation("binding_source_not_dedicated")
    if candidate.worker_identity_registration_id != authoritative.worker_identity_registration_id:
        raise PlanResolutionContractViolation("worker_identity_mismatch")
    if candidate.worker_identity_version != authoritative.worker_identity_version:
        raise PlanResolutionContractViolation("worker_identity_version_mismatch")
    if candidate.resolver_contract_version != PLAN_EXECUTION_RESOLVER_CONTRACT_VERSION:
        raise PlanResolutionContractViolation("resolver_contract_mismatch")
    if authoritative.resolver_contract_version != PLAN_EXECUTION_RESOLVER_CONTRACT_VERSION:
        raise PlanResolutionContractViolation("resolver_contract_mismatch")
    if candidate.operation_fingerprint != authoritative.operation_fingerprint:
        raise PlanResolutionContractViolation("operation_fingerprint_mismatch")
    if candidate.execution_lease_id != authoritative.execution_lease_id:
        raise PlanResolutionContractViolation("lease_mismatch")
    if candidate.attempt_number != authoritative.attempt_number:
        raise PlanResolutionContractViolation("attempt_mismatch")
    if candidate.credential_reference.scheme not in _SUPPORTED_REFERENCE_SCHEMES:
        raise PlanResolutionContractViolation("reference_scheme_unsupported")
    if candidate.credential_reference.is_blank:
        raise PlanResolutionContractViolation("credential_reference_missing")
    if candidate.credential_reference != authoritative.credential_reference:
        raise PlanResolutionContractViolation("credential_reference_mismatch")
    if _parse_canonical_utc(candidate.authorization_expiry) <= now:
        raise PlanResolutionContractViolation("authorization_expired")


# --- the typed, verified resolver ACTIVATION + non-serializable resolver CAPABILITY -------------

# The reviewed resolver implementation identity. A self-declared registration is not sufficient: the
# activation's digest must equal this exact digest.
PLAN_EXECUTION_RESOLVER_REGISTRATION = "secp-002b-1b-pr5b/plan-execution-resolver/v1"


def plan_execution_resolver_digest() -> str:
    """The stable digest of the reviewed plan-execution resolver implementation identity."""
    import hashlib

    return "sha256:" + hashlib.sha256(PLAN_EXECUTION_RESOLVER_REGISTRATION.encode()).hexdigest()


@dataclass(frozen=True)
class PlanResolverActivation:
    """A reviewed activation authorizing ONE resolver for one purpose (verified, not merely set)."""

    purpose: PlanExecutionResolutionPurpose
    resolver_registration: str
    resolver_digest: str
    worker_identity_registration_id: uuid.UUID
    worker_identity_version: int


def verify_plan_resolver_activation(
    activation: object,
    *,
    purpose: PlanExecutionResolutionPurpose,
    worker_identity_registration_id: uuid.UUID,
    worker_identity_version: int,
) -> PlanResolverActivation:
    """Refuse unless ``activation`` is a real, reviewed activation for the exact purpose + worker.

    A ``None`` or non-:class:`PlanResolverActivation` value, a self-declared registration, a wrong
    digest, or a worker mismatch fails closed — the composition seam is VERIFIED, never merely
    non-null.
    """
    if not isinstance(activation, PlanResolverActivation):
        raise PlanResolutionContractViolation("resolver_activation_invalid")
    if activation.purpose != purpose:
        raise PlanResolutionContractViolation("resolver_activation_purpose_mismatch")
    if activation.resolver_registration != PLAN_EXECUTION_RESOLVER_REGISTRATION:
        raise PlanResolutionContractViolation("resolver_activation_registration_invalid")
    if activation.resolver_digest != plan_execution_resolver_digest():
        raise PlanResolutionContractViolation("resolver_activation_digest_invalid")
    if activation.worker_identity_registration_id != worker_identity_registration_id:
        raise PlanResolutionContractViolation("resolver_activation_worker_mismatch")
    if activation.worker_identity_version != worker_identity_version:
        raise PlanResolutionContractViolation("resolver_activation_worker_mismatch")
    return activation


_RESOLVER_CAPABILITY_TOKEN = object()


class PlanExecutionResolverCapability:
    """A worker-only, non-serializable proof that a resolver may act for one exact operation."""

    __slots__ = ("__contract", "__activation")

    def __init__(
        self,
        token: object,
        contract: PlanExecutionResolutionContract,
        activation: PlanResolverActivation,
    ) -> None:
        if token is not _RESOLVER_CAPABILITY_TOKEN:
            raise TypeError(
                "PlanExecutionResolverCapability is issued only by issue_plan_resolver_capability"
            )
        self.__contract = contract
        self.__activation = activation

    @property
    def contract(self) -> PlanExecutionResolutionContract:
        return self.__contract

    @property
    def activation(self) -> PlanResolverActivation:
        return self.__activation

    def __repr__(self) -> str:
        return "PlanExecutionResolverCapability(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("PlanExecutionResolverCapability cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("PlanExecutionResolverCapability cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("PlanExecutionResolverCapability cannot be pickled")


def issue_plan_resolver_capability(
    *,
    contract: PlanExecutionResolutionContract,
    activation: object,
    worker_identity_registration_id: uuid.UUID,
    worker_identity_version: int,
) -> PlanExecutionResolverCapability:
    """Issue a resolver capability after VERIFYING the activation against the reviewed digest."""
    verified = verify_plan_resolver_activation(
        activation,
        purpose=contract.purpose,
        worker_identity_registration_id=worker_identity_registration_id,
        worker_identity_version=worker_identity_version,
    )
    return PlanExecutionResolverCapability(_RESOLVER_CAPABILITY_TOKEN, contract, verified)


@runtime_checkable
class WorkerPlanSecretResolver(Protocol):
    """The worker-only adapter seam a FUTURE production plan-execution resolver will implement."""

    def resolve(
        self,
        request: TrustedPlanResolutionRequest,
        *,
        expectation: PlanExecutionResolutionContract,
        capability: PlanExecutionResolverCapability,
        now: datetime,
    ) -> SecretMaterial: ...


class SealedPlanSecretResolver:
    """The shipped, sealed plan-execution resolver. Enforces the contract, then ALWAYS fails closed.

    It resolves nothing, reads no environment, and contacts no backend. It exists so a plan-only
    execution deterministically terminates before any real secret manager is touched.
    """

    def resolve(
        self,
        request: TrustedPlanResolutionRequest,
        *,
        expectation: PlanExecutionResolutionContract,
        capability: PlanExecutionResolverCapability,
        now: datetime,
    ) -> SecretMaterial:
        # Defense in depth: verify the capability + request BEFORE failing (the request/expectation
        # are INDEPENDENT objects; the capability's own contract must also agree).
        if not isinstance(capability, PlanExecutionResolverCapability):
            raise PlanResolutionContractViolation("resolver_capability_invalid")
        assert_plan_resolution_authorized(request.contract, expectation, now=now)
        assert_plan_resolution_authorized(capability.contract, expectation, now=now)
        raise PlanSecretResolutionUnavailable(
            "no production plan-execution secret resolver is configured"
        )


def _parse_canonical_utc(value: str) -> datetime:
    try:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise PlanResolutionContractViolation("authorization_expiry_malformed") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
