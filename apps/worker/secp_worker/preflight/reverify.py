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

from secp_api.enums import ReadonlyPreflightStatus
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LIVE_VERIFIED_LEVEL,
    PROXMOX_READONLY_POLICY_VERSION,
    connection_identity_hash,
)
from secp_api.models import (
    ExecutionTarget,
    LiveReadAuthorization,
    ReadonlyStagingPreflight,
    TargetOnboarding,
)
from sqlalchemy.orm import Session

from secp_worker.onboarding.live_authorization import (
    LiveReadAuthorizationContract,
    LiveReadAuthorizationLoadRequest,
    LiveReadAuthorizationRefused,
    load_and_verify_live_read_authorization,
)
from secp_worker.preflight.fingerprint import compute_operation_fingerprint
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    ResolutionPurpose,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    build_resolution_contract,
)

# A read-only-preflight work item is only eligible for secret resolution while it is being
# processed (queued/claimed/running). A terminal preflight (completed/failed/refused) is refused.
_ELIGIBLE_PREFLIGHT_STATUSES = frozenset(
    {
        ReadonlyPreflightStatus.queued,
        ReadonlyPreflightStatus.claimed,
        ReadonlyPreflightStatus.running,
    }
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
    """Independently derives the authoritative resolution facts from the durable WORK ITEM.

    Worker-only; constructed with the worker's own DB session (never caller-supplied). The ONLY
    candidate-controlled input it trusts is the work-item id (``preflight_id``) — a locator, not a
    capability. It loads the ``ReadonlyStagingPreflight`` by that id, refuses if it is missing or
    not eligible, re-runs the SECP-002B-1B-6 verifier using the WORK ITEM's own identity fields,
    derives the only allowed purpose from the work-item type, recomputes the operation fingerprint
    from the loaded work item, and builds the authoritative :class:`ResolutionContract` solely from
    the work item + the re-verified records + the pinned app constants. It trusts no candidate
    purpose, fingerprint, expiry, version label, or reference. Any drift/expiry/revocation/mismatch
    raises a fail-closed :class:`SecretResolutionUnavailable`.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def reverify(self, candidate: ResolutionContract, *, now: datetime) -> ReverifiedAuthority:
        # 1. Load the durable work item by its id (a locator only). Refuse if missing/ineligible.
        preflight = self._session.get(ReadonlyStagingPreflight, candidate.preflight_id)
        if preflight is None or preflight.status not in _ELIGIBLE_PREFLIGHT_STATUSES:
            raise SecretResolutionUnavailable("work item not found or not eligible")

        # 2. The candidate must name the work item's own identity — otherwise it is not this
        #    operation and we fail closed before deriving anything from the candidate.
        if (
            candidate.organization_id != preflight.organization_id
            or candidate.execution_target_id != preflight.execution_target_id
            or candidate.onboarding_id != preflight.onboarding_id
            or candidate.authorization_id != preflight.live_read_authorization_id
            or candidate.authorization_version != preflight.authorization_version
        ):
            raise SecretResolutionUnavailable("work item identity mismatch")

        # 3. Re-run the authoritative binding verifier using the WORK ITEM's own identity fields.
        load_request = LiveReadAuthorizationLoadRequest(
            organization_id=preflight.organization_id,
            execution_target_id=preflight.execution_target_id,
            onboarding_id=preflight.onboarding_id,
            authorization_id=preflight.live_read_authorization_id,
            authorization_version=preflight.authorization_version,
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
            raise SecretResolutionUnavailable("authoritative re-verification refused") from exc

        # 4. Derive the only allowed purpose from the WORK-ITEM TYPE (never the candidate), and
        #    recompute the operation fingerprint from the loaded work item.
        purpose = ResolutionPurpose.readonly_staging_preflight
        fingerprint = compute_operation_fingerprint(preflight)

        # 5. Build the authoritative contract solely from the work item + verified records + pinned
        #    constants.
        authoritative = build_resolution_contract(
            verified=verified,
            purpose=purpose,
            operation_fingerprint=fingerprint,
            preflight_id=preflight.id,
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
