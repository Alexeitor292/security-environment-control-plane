"""Worker-only sealed secret-resolution contract for the read-only staging preflight (SECP-B2-1).

This is the FINAL sealed, worker-only secret-resolution interface. A future, separately reviewed
activation PR can bind a production secret backend to it — but nothing here resolves a real secret,
constructs a transport, reads an environment variable, opens a socket/subprocess, or contacts any
backend. The shipped default (:class:`SealedUnavailableResolver`) always fails closed, so every
read-only preflight still terminates as ``credential_unavailable`` before transport construction.

Trust model
-----------
The only trust anchor is the authoritative worker binding verifier
(``load_and_verify_live_read_authorization``). A :class:`TrustedResolutionRequest` can be built
**only** by :func:`build_trusted_resolution_request`, which requires a
``VerifiedLiveReadAuthorization`` produced by that verifier. A caller cannot hand-craft a request
and have it treated as trusted: the constructor is sealed behind a module-private token, and the
resolver re-checks the request against an independently derived authoritative
:class:`ResolutionContract` on every field before it would ever resolve.

Nothing in this module carries or returns a real credential. :class:`SecretMaterial` is a
non-serializable, non-repr-safe wrapper intended solely for a future direct worker-to-transport
handoff; production code in this PR never constructs one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, NoReturn, Protocol, SupportsIndex, runtime_checkable

from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    PROXMOX_READONLY_POLICY_VERSION,
)

from secp_worker.secrets import SecretResolutionError

if TYPE_CHECKING:  # imported for typing only — avoids a hard runtime import of the plugin chain
    from secp_worker.onboarding.live_authorization import VerifiedLiveReadAuthorization


class ResolutionPurpose(str, Enum):
    """Closed catalog of secret-resolution purposes. Only one is permitted in this phase."""

    readonly_staging_preflight = "readonly_staging_preflight"


# The only purpose a resolver may act on in this phase. A future purpose requires its own review.
SUPPORTED_PURPOSES: frozenset[ResolutionPurpose] = frozenset(
    {ResolutionPurpose.readonly_staging_preflight}
)


class SecretResolutionUnavailable(SecretResolutionError):
    """The sealed default: no production secret backend is configured (always fail closed)."""


class ResolutionContractViolation(SecretResolutionError):
    """The presented request does not match the authoritative binding it claims to resolve for.

    Carries only a generic ``reason_code`` — never a credential, reference value, endpoint,
    identity value, or secret. A subclass of :class:`SecretResolutionError` so the worker
    orchestration's existing fail-closed handling maps it to ``credential_unavailable``.
    """

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"resolution contract violation: {reason_code}")
        self.reason_code = reason_code


class TrustedCredentialReference:
    """An opaque credential-reference locator (e.g. a secret-manager key), never the secret value.

    It is bound by exact equality but is redacted in every string/repr form and cannot be
    serialized. Only a future backend adapter would read the underlying locator via
    :meth:`reveal_reference`; nothing in this PR does.
    """

    __slots__ = ("__ref",)

    def __init__(self, reference: str) -> None:
        self.__ref = reference

    @property
    def is_blank(self) -> bool:
        return not (isinstance(self.__ref, str) and self.__ref.strip() != "")

    def reveal_reference(self) -> str:
        """Return the opaque locator for a FUTURE worker-only backend adapter only."""
        return self.__ref

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TrustedCredentialReference):
            return NotImplemented
        return self.__ref == other.__ref

    def __hash__(self) -> int:
        return hash(("TrustedCredentialReference", self.__ref))

    def __repr__(self) -> str:
        return "TrustedCredentialReference(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("TrustedCredentialReference cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("TrustedCredentialReference cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("TrustedCredentialReference cannot be pickled")


class SecretMaterial:
    """Opaque, non-serializable secret wrapper for a FUTURE worker-to-transport handoff only.

    It intentionally has no ``__dict__``, no JSON/dict form, and a redacted ``repr``/``str``. It
    cannot be pickled or persisted through ORM/API/audit paths. Production code in this PR NEVER
    constructs one (the sealed resolver always fails closed); tests and a future backend adapter
    are the only constructors.
    """

    __slots__ = ("__secret",)

    def __init__(self, secret: str) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("secret material must be a non-empty string")
        self.__secret = secret

    def reveal_secret(self) -> str:
        """Return the secret for a FUTURE worker/transport handoff only (never logged/persisted)."""
        return self.__secret

    def __repr__(self) -> str:
        return "SecretMaterial(<redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return "SecretMaterial(<redacted>)"

    def __getstate__(self) -> NoReturn:
        raise TypeError("SecretMaterial cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretMaterial cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("SecretMaterial cannot be pickled")


@dataclass(frozen=True, repr=False)
class ResolutionContract:
    """The immutable, redacted set of authoritative facts a resolution is bound to.

    Every field is derived from authoritative records by the worker. The opaque
    ``credential_reference`` is redacted in ``repr``. Two contracts are equal only if every
    binding field (including the opaque reference) matches; the resolver uses that to refuse any
    request that does not match the authoritative binding.
    """

    purpose: ResolutionPurpose
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    authorization_expiry: str  # canonical ISO-8601 UTC, e.g. "2026-07-02T00:00:00Z"
    operation_fingerprint: str
    contract_version: str
    endpoint_policy_version: str
    credential_reference: TrustedCredentialReference

    def __repr__(self) -> str:
        return (
            "ResolutionContract("
            f"purpose={self.purpose.value!r}, "
            f"organization_id={self.organization_id!s}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"onboarding_id={self.onboarding_id!s}, "
            f"authorization_id={self.authorization_id!s}, "
            f"authorization_version={self.authorization_version!r}, "
            f"authorization_expiry={self.authorization_expiry!r}, "
            f"operation_fingerprint={self.operation_fingerprint!r}, "
            f"contract_version={self.contract_version!r}, "
            f"endpoint_policy_version={self.endpoint_policy_version!r}, "
            "credential_reference=<redacted>)"
        )


# Module-private token: only code in this module can pass it, so only this module (via the
# post-verification factory) can construct a TrustedResolutionRequest.
_CONSTRUCTION_TOKEN = object()


class TrustedResolutionRequest:
    """The request handed across the resolver boundary. Worker-constructed only.

    It wraps a :class:`ResolutionContract`. It cannot be instantiated directly — only
    :func:`build_trusted_resolution_request` (which requires a verified binding) may build one, so
    a caller-supplied request can never be a trust anchor. It is redacted and non-serializable.
    """

    __slots__ = ("__contract",)

    def __init__(self, contract: ResolutionContract, *, token: object) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError(
                "TrustedResolutionRequest is worker-constructed only; call "
                "build_trusted_resolution_request() after the binding verifier succeeds"
            )
        self.__contract = contract

    @property
    def contract(self) -> ResolutionContract:
        return self.__contract

    def __repr__(self) -> str:
        return "TrustedResolutionRequest(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("TrustedResolutionRequest cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("TrustedResolutionRequest cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("TrustedResolutionRequest cannot be pickled")


def build_resolution_contract(
    *,
    verified: VerifiedLiveReadAuthorization,
    purpose: ResolutionPurpose,
    operation_fingerprint: str,
    now: datetime,
) -> ResolutionContract:
    """Derive the authoritative :class:`ResolutionContract` from a VERIFIED binding.

    Runs the pinned policy check (contract + endpoint-policy versions must equal the app-side
    constants) as part of construction, before any secret-resolution boundary is reached. Every
    identity/label field is taken from the verifier output, never from caller-supplied values.
    """
    if purpose not in SUPPORTED_PURPOSES:
        raise ResolutionContractViolation("unsupported_purpose")
    if not (isinstance(operation_fingerprint, str) and operation_fingerprint.strip()):
        raise ResolutionContractViolation("operation_fingerprint_missing")

    binding = verified.binding
    target = verified.execution_target
    # Policy check (pinned): only the exact live-read contract + read-only endpoint policy pass.
    if binding.collector_contract_version != LIVE_READ_COLLECTOR_CONTRACT_VERSION:
        raise ResolutionContractViolation("unsupported_contract_version")
    if binding.endpoint_allowlist_version != PROXMOX_READONLY_POLICY_VERSION:
        raise ResolutionContractViolation("unsupported_endpoint_policy_version")

    reference = TrustedCredentialReference(target.secret_ref or "")
    if reference.is_blank:
        raise ResolutionContractViolation("credential_reference_missing")

    expiry = _parse_canonical_utc(binding.authorization_expiry)
    if expiry <= now:
        raise ResolutionContractViolation("authorization_expired")

    return ResolutionContract(
        purpose=purpose,
        organization_id=target.organization_id,
        execution_target_id=uuid.UUID(str(binding.execution_target_id)),
        onboarding_id=uuid.UUID(str(binding.onboarding_id)),
        authorization_id=uuid.UUID(str(binding.authorization_id)),
        authorization_version=binding.authorization_version,
        authorization_expiry=binding.authorization_expiry,
        operation_fingerprint=operation_fingerprint,
        contract_version=binding.collector_contract_version,
        endpoint_policy_version=binding.endpoint_allowlist_version,
        credential_reference=reference,
    )


def build_trusted_resolution_request(
    *,
    verified: VerifiedLiveReadAuthorization,
    purpose: ResolutionPurpose,
    operation_fingerprint: str,
    now: datetime,
) -> TrustedResolutionRequest:
    """Build the ONLY trusted request, from a verified binding, after the verifier has succeeded."""
    contract = build_resolution_contract(
        verified=verified,
        purpose=purpose,
        operation_fingerprint=operation_fingerprint,
        now=now,
    )
    return TrustedResolutionRequest(contract, token=_CONSTRUCTION_TOKEN)


def assert_resolution_authorized(
    candidate: ResolutionContract,
    authoritative: ResolutionContract,
    *,
    now: datetime,
) -> None:
    """Refuse unless ``candidate`` matches ``authoritative`` on every binding field.

    Raises :class:`ResolutionContractViolation` with a generic reason code (no value leakage) for:
    unsupported/mismatched purpose; wrong organization/target/onboarding; wrong authorization
    identity or version; wrong operation fingerprint; wrong contract/endpoint-policy labels;
    blank or mismatched opaque reference; expired authorization.
    """
    if candidate.purpose not in SUPPORTED_PURPOSES:
        raise ResolutionContractViolation("unsupported_purpose")
    if authoritative.purpose not in SUPPORTED_PURPOSES:
        raise ResolutionContractViolation("unsupported_purpose")
    if candidate.purpose != authoritative.purpose:
        raise ResolutionContractViolation("purpose_mismatch")
    if candidate.organization_id != authoritative.organization_id:
        raise ResolutionContractViolation("wrong_organization")
    if candidate.execution_target_id != authoritative.execution_target_id:
        raise ResolutionContractViolation("wrong_execution_target")
    if candidate.onboarding_id != authoritative.onboarding_id:
        raise ResolutionContractViolation("wrong_onboarding")
    if candidate.authorization_id != authoritative.authorization_id:
        raise ResolutionContractViolation("wrong_authorization")
    if candidate.authorization_version != authoritative.authorization_version:
        raise ResolutionContractViolation("authorization_version_mismatch")
    if candidate.operation_fingerprint != authoritative.operation_fingerprint:
        raise ResolutionContractViolation("operation_fingerprint_mismatch")
    if candidate.contract_version != authoritative.contract_version:
        raise ResolutionContractViolation("contract_version_mismatch")
    if candidate.endpoint_policy_version != authoritative.endpoint_policy_version:
        raise ResolutionContractViolation("endpoint_policy_version_mismatch")
    # Pinned policy check (independent of the authoritative side): only the exact labels pass.
    if candidate.contract_version != LIVE_READ_COLLECTOR_CONTRACT_VERSION:
        raise ResolutionContractViolation("unsupported_contract_version")
    if candidate.endpoint_policy_version != PROXMOX_READONLY_POLICY_VERSION:
        raise ResolutionContractViolation("unsupported_endpoint_policy_version")
    if candidate.credential_reference.is_blank:
        raise ResolutionContractViolation("credential_reference_missing")
    if candidate.credential_reference != authoritative.credential_reference:
        raise ResolutionContractViolation("credential_reference_mismatch")
    if candidate.authorization_expiry != authoritative.authorization_expiry:
        raise ResolutionContractViolation("authorization_expiry_mismatch")
    expiry = _parse_canonical_utc(candidate.authorization_expiry)
    if expiry <= now:
        raise ResolutionContractViolation("authorization_expired")


@runtime_checkable
class WorkerSecretResolver(Protocol):
    """The narrow worker-only adapter seam a FUTURE production resolver will implement.

    It receives a worker-built :class:`TrustedResolutionRequest` and the independently derived
    authoritative :class:`ResolutionContract`, must confirm they match, and only then would return
    :class:`SecretMaterial`. The shipped default never returns material. Injected in tests only.
    """

    def resolve(
        self,
        request: TrustedResolutionRequest,
        *,
        expectation: ResolutionContract,
        now: datetime,
    ) -> SecretMaterial: ...


class SealedUnavailableResolver:
    """The shipped, sealed worker resolver. Enforces the contract, then ALWAYS fails closed.

    It resolves nothing, reads no environment, contacts no backend, and never returns
    :class:`SecretMaterial`. It exists so a read-only preflight deterministically terminates as
    ``credential_unavailable`` instead of weakening the credential model with an insecure store.
    """

    def resolve(
        self,
        request: TrustedResolutionRequest,
        *,
        expectation: ResolutionContract,
        now: datetime,
    ) -> SecretMaterial:
        # Defense in depth: even though this resolver never resolves, it still verifies the
        # request matches the authoritative binding BEFORE the fail-closed boundary.
        assert_resolution_authorized(request.contract, expectation, now=now)
        # Redacted: never echoes the reference locator or any value (there is none).
        raise SecretResolutionUnavailable(
            "no production secret resolver is configured for read-only preflight"
        )


def _parse_canonical_utc(value: str) -> datetime:
    try:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise ResolutionContractViolation("authorization_expiry_malformed") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
