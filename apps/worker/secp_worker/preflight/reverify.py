"""Worker-only independent authoritative re-verification for secret resolution (SECP-B2-4).

This closes the SECP-B2-1 review finding that a ``TrustedResolutionRequest`` (or a caller-built
"expected contract") must never be treated as authorization proof. A future secret resolver must,
**at resolution time**, re-load the authoritative records and re-run the SECP-002B-1B-6 binding
verifier — deriving the authoritative :class:`ResolutionContract` from the database + the pinned
app-side constants, never from the request or the passed expectation.

This module contacts nothing, resolves no secret, and constructs no transport. It only re-reads
the worker's own authoritative records and re-runs the pure verifier.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LIVE_VERIFIED_LEVEL,
    PROXMOX_READONLY_POLICY_VERSION,
    connection_identity_hash,
)
from secp_api.models import ExecutionTarget, LiveReadAuthorization, TargetOnboarding
from sqlalchemy.orm import Session

from secp_worker.onboarding.live_authorization import (
    LiveReadAuthorizationContract,
    LiveReadAuthorizationLoadRequest,
    LiveReadAuthorizationRefused,
    load_and_verify_live_read_authorization,
)
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    build_resolution_contract,
)


@dataclass(frozen=True, repr=False)
class ReverifiedAuthority:
    """The authoritative result of an independent DB re-verification (redacted references).

    ``contract`` is the authoritative :class:`ResolutionContract` derived from the freshly
    re-verified records. ``target_credential_reference`` and ``binding_credential_reference`` are
    the two additional opaque references a resolver must bind three-ways against the request. None
    of these values is ever logged, serialized, persisted, hashed, audited, or rendered.
    """

    contract: ResolutionContract
    target_credential_reference: TrustedCredentialReference
    binding_credential_reference: TrustedCredentialReference

    def __repr__(self) -> str:
        return "ReverifiedAuthority(contract=<redacted>, references=<redacted>)"


class _SessionRepository:
    """Authoritative record loader backed by the worker's DB session (not caller-supplied)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_execution_target(self, target_id: uuid.UUID) -> ExecutionTarget | None:
        return self._session.get(ExecutionTarget, target_id)

    def get_target_onboarding(self, onboarding_id: uuid.UUID) -> TargetOnboarding | None:
        return self._session.get(TargetOnboarding, onboarding_id)

    def get_live_read_authorization(
        self, authorization_id: uuid.UUID
    ) -> LiveReadAuthorization | None:
        return self._session.get(LiveReadAuthorization, authorization_id)


class _ConnectionHashProvider:
    """Provider-neutral connection-identity hash over the target's stored secret-free config."""

    def current_connection_hash(self, execution_target: ExecutionTarget) -> str:
        return connection_identity_hash(execution_target.config or {})


class DbAuthoritativeReverifier:
    """Re-loads authoritative records + re-runs the binding verifier at resolution time.

    Worker-only; constructed with the worker's own DB session (never caller-supplied). It derives
    the authoritative :class:`ResolutionContract` from the re-verified records + the pinned app-side
    constants — never from the request or a passed expectation. Any drift/expiry/revocation raises a
    fail-closed :class:`SecretResolutionUnavailable`.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def reverify(self, contract: ResolutionContract, *, now: datetime) -> ReverifiedAuthority:
        load_request = LiveReadAuthorizationLoadRequest(
            organization_id=contract.organization_id,
            execution_target_id=contract.execution_target_id,
            onboarding_id=contract.onboarding_id,
            authorization_id=contract.authorization_id,
            authorization_version=contract.authorization_version,
        )
        expected_contract = LiveReadAuthorizationContract(
            evidence_source=LIVE_READ_EVIDENCE_SOURCE,
            verification_level=LIVE_VERIFIED_LEVEL,
            collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
            endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        )
        try:
            verified = load_and_verify_live_read_authorization(
                request=load_request,
                repository=_SessionRepository(self._session),
                connection_hash_provider=_ConnectionHashProvider(),
                expected_contract=expected_contract,
                now=now,
            )
        except LiveReadAuthorizationRefused as exc:
            # Fail closed with a generic, secret-free reason; the request is not trusted.
            raise SecretResolutionUnavailable("authoritative re-verification refused") from exc

        authoritative = build_resolution_contract(
            verified=verified,
            purpose=contract.purpose,
            operation_fingerprint=contract.operation_fingerprint,
            now=now,
        )
        return ReverifiedAuthority(
            contract=authoritative,
            target_credential_reference=TrustedCredentialReference(
                verified.execution_target.secret_ref or ""
            ),
            binding_credential_reference=TrustedCredentialReference(
                verified.binding.credential_ref or ""
            ),
        )
