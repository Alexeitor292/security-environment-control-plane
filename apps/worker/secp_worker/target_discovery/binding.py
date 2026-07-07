"""Pre-SSH bundle-to-job authorization + binding gate for read-only discovery (SECP-B6 F-BIND).

Before any host contact, the worker must prove the mounted bundle is authorized for the EXACT
claimed discovery job. A bundle carries a non-secret :class:`BundleBindingAnchor` (organization /
execution target / onboarding / enrollment / live-read authorization IDs). This module compares that
anchor to the claimed job's authoritative enrollment AND independently re-runs the SECP-002B-1B-6
live-read authorization verifier (organization, target, onboarding, status, expiry, version,
connection-hash drift, boundary-hash drift). Any mismatch or unverified authorization fails closed
with a CLOSED reason BEFORE the SSH executor is ever engaged.

It contacts no host, resolves no secret, constructs no transport, and imports no mutation-capable
module — only the authoritative DB records (read via the worker's own session) and the pure
verifier. So a global worker composition holding one mounted target bundle cannot use it for another
queued job.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol, runtime_checkable

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
    TargetDiscoveryEnrollment,
    TargetOnboarding,
)
from sqlalchemy.orm import Session

from secp_worker.mounted_bundle import BundleBindingAnchor
from secp_worker.onboarding.live_authorization import (
    LiveReadAuthorizationContract,
    LiveReadAuthorizationLoadRequest,
    LiveReadAuthorizationRefused,
    load_and_verify_live_read_authorization,
)
from secp_worker.ssh_channel import BootstrapBundleUnavailable

# The pinned, app-owned expected live-read contract (identical to the preflight re-verifier's).
_EXPECTED_CONTRACT = LiveReadAuthorizationContract(
    evidence_source=LIVE_READ_EVIDENCE_SOURCE,
    verification_level=LIVE_VERIFIED_LEVEL,
    collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
)


@runtime_checkable
class BundleAnchorSource(Protocol):
    """Deployment-local seam yielding the mounted bundle's non-secret authorization anchor."""

    def load_anchor(self) -> BundleBindingAnchor: ...

    def dispose(self) -> None: ...


class DiscoveryBindingRefused(Exception):
    """Fail-closed bundle-binding refusal carrying ONLY a closed reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"discovery bundle binding refused: {reason_code}")
        self.reason_code = reason_code


class _SessionRepository:
    """Authoritative record loader backed by the worker's own DB session (never caller-supplied)."""

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


def authorize_discovery_bundle(
    session: Session,
    enrollment: TargetDiscoveryEnrollment,
    anchor_source: BundleAnchorSource,
    *,
    now: datetime,
) -> None:
    """Prove the mounted bundle is authorized for this exact job, else raise a binding refusal.

    Reads the bundle's non-secret anchor (local file read; no host contact), requires it to name the
    claimed enrollment's exact organization/target/onboarding/enrollment, then re-runs the
    authoritative live-read authorization verifier. Disposes the anchor source on every path.
    """
    try:
        try:
            anchor = anchor_source.load_anchor()
        except BootstrapBundleUnavailable as exc:
            raise DiscoveryBindingRefused(
                getattr(exc, "reason_code", "bootstrap_unavailable")
            ) from None

        # Structural identity binding: the anchor must name THIS claimed job. A bundle minted for
        # another organization/target/onboarding/enrollment can never be used here.
        if anchor.organization_id != enrollment.organization_id:
            raise DiscoveryBindingRefused("bundle_organization_mismatch")
        if anchor.execution_target_id != enrollment.execution_target_id:
            raise DiscoveryBindingRefused("bundle_target_mismatch")
        if anchor.onboarding_id != enrollment.onboarding_id:
            raise DiscoveryBindingRefused("bundle_onboarding_mismatch")
        if anchor.enrollment_id != enrollment.id:
            raise DiscoveryBindingRefused("bundle_enrollment_mismatch")

        # Authoritative re-verification: an approved, unexpired, version-valid, connection- and
        # boundary-hash-matching live-read authorization for this target/onboarding must exist.
        request = LiveReadAuthorizationLoadRequest(
            organization_id=anchor.organization_id,
            execution_target_id=anchor.execution_target_id,
            onboarding_id=anchor.onboarding_id,
            authorization_id=anchor.authorization_id,
            authorization_version=anchor.authorization_version,
        )
        try:
            load_and_verify_live_read_authorization(
                request=request,
                repository=_SessionRepository(session),
                connection_hash_provider=_ConnectionHashProvider(),
                expected_contract=_EXPECTED_CONTRACT,
                now=now,
            )
        except LiveReadAuthorizationRefused as exc:
            # Preserve the closed sub-reason (authorization_missing / _revoked / _expired /
            # version drift / connection_hash_drift / boundary_hash_drift / ...).
            raise DiscoveryBindingRefused(f"live_read_{exc.reason_code}") from None
    finally:
        anchor_source.dispose()
