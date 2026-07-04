"""Worker-only sealed resolver-activation capability verifier (SECP-B2-4.1).

Immediately before a (future) resolution, worker code must independently re-load the durable
``ResolverActivationAuthorization`` and its evidence from the authoritative database and re-check
EVERY bound fact against the work item + the pinned constants + the recomputed evidence fingerprint.
Only when all checks pass is a redacted, non-serializable :class:`ResolverActivationCapability`
produced — and even then, this PR does not wire it into shipped runtime: the shipped defaults
(``DenyingWorkerIdentityVerifier`` + ``SealedActivationGate``) still stop before lease acquisition
and no resolution occurs. The capability cannot be constructed by API/UI callers, settings,
environment, a database edit alone, or a test without explicit test-only injection (its constructor
is sealed behind a module-private token). It contacts nothing and resolves no secret.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import NoReturn, SupportsIndex

from secp_api.enums import ResolverActivationStatus
from secp_api.models import (
    ReadonlyStagingPreflight,
    ResolverActivationAuthorization,
    ResolverActivationEvidence,
)
from secp_api.resolver_activation_contract import (
    RESOLVER_ACTIVATION_PURPOSE,
    RESOLVER_ADAPTER_CONTRACT_VERSION,
    compute_evidence_fingerprint,
    compute_operation_fingerprint,
    evidence_is_complete,
)
from sqlalchemy import select
from sqlalchemy.orm import Session


class ActivationAuthorizationRefused(Exception):
    """Fail-closed refusal carrying only a closed, secret-free reason code (no value leakage)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"resolver activation refused: {reason_code}")
        self.reason_code = reason_code


_CAPABILITY_TOKEN = object()


class ResolverActivationCapability:
    """A redacted, non-serializable proof that a resolver-activation authorization was independently
    re-verified. Worker-constructed only (sealed token). Carries only safe identifiers."""

    __slots__ = ("__authorization_id", "__operation_fingerprint")

    def __init__(
        self, *, authorization_id: object, operation_fingerprint: str, token: object
    ) -> None:
        if token is not _CAPABILITY_TOKEN:
            raise TypeError(
                "ResolverActivationCapability is worker-constructed only after re-verification"
            )
        self.__authorization_id = authorization_id
        self.__operation_fingerprint = operation_fingerprint

    @property
    def authorization_id(self) -> object:
        return self.__authorization_id

    @property
    def operation_fingerprint(self) -> str:
        return self.__operation_fingerprint

    def __repr__(self) -> str:
        return "ResolverActivationCapability(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("ResolverActivationCapability cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ResolverActivationCapability cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ResolverActivationCapability cannot be pickled")


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def load_and_verify_activation_capability(
    session: Session,
    *,
    preflight: ReadonlyStagingPreflight,
    resolver_contract_version: str,
    now: datetime,
) -> ResolverActivationCapability:
    """Re-load + independently re-verify the resolver-activation authorization for a work item.

    Every bound fact is re-checked against the loaded work item, the pinned constants, and the
    recomputed evidence fingerprint. Any missing/terminal/expired/mismatched fact fails closed.
    """
    row = session.execute(
        select(ResolverActivationAuthorization).where(
            ResolverActivationAuthorization.preflight_id == preflight.id,
            ResolverActivationAuthorization.status == ResolverActivationStatus.approved,
        )
    ).scalar_one_or_none()
    if row is None:
        raise ActivationAuthorizationRefused("authorization_not_approved")
    if row.status != ResolverActivationStatus.approved:
        raise ActivationAuthorizationRefused("authorization_not_approved")
    if _as_utc(row.authorization_expiry) <= now:
        raise ActivationAuthorizationRefused("authorization_expired")

    if row.organization_id != preflight.organization_id:
        raise ActivationAuthorizationRefused("wrong_organization")
    if row.execution_target_id != preflight.execution_target_id:
        raise ActivationAuthorizationRefused("wrong_execution_target")
    if row.onboarding_id != preflight.onboarding_id:
        raise ActivationAuthorizationRefused("wrong_onboarding")
    if row.live_read_authorization_id != preflight.live_read_authorization_id:
        raise ActivationAuthorizationRefused("wrong_authorization")
    if row.live_read_authorization_version != preflight.authorization_version:
        raise ActivationAuthorizationRefused("authorization_version_mismatch")
    if row.preflight_id != preflight.id:
        raise ActivationAuthorizationRefused("preflight_mismatch")
    if row.purpose != RESOLVER_ACTIVATION_PURPOSE:
        raise ActivationAuthorizationRefused("wrong_purpose")
    if row.resolver_adapter_contract_version != RESOLVER_ADAPTER_CONTRACT_VERSION:
        raise ActivationAuthorizationRefused("contract_version_mismatch")
    if resolver_contract_version != RESOLVER_ADAPTER_CONTRACT_VERSION:
        raise ActivationAuthorizationRefused("contract_version_mismatch")
    if row.operation_fingerprint != compute_operation_fingerprint(preflight):
        raise ActivationAuthorizationRefused("operation_fingerprint_mismatch")

    evidence = list(
        session.execute(
            select(ResolverActivationEvidence)
            .where(ResolverActivationEvidence.authorization_id == row.id)
            .order_by(ResolverActivationEvidence.kind)
        )
        .scalars()
        .all()
    )
    if not evidence_is_complete(evidence):
        raise ActivationAuthorizationRefused("evidence_incomplete")
    if row.evidence_fingerprint != compute_evidence_fingerprint(evidence):
        raise ActivationAuthorizationRefused("evidence_fingerprint_mismatch")

    return ResolverActivationCapability(
        authorization_id=row.id,
        operation_fingerprint=row.operation_fingerprint,
        token=_CAPABILITY_TOKEN,
    )
