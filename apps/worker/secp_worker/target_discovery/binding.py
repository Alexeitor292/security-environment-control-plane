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
    normalize_target_host,
    ssh_endpoint_binding_hash,
)
from secp_api.models import (
    ExecutionTarget,
    LiveReadAuthorization,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
)
from sqlalchemy.orm import Session

from secp_worker.mounted_bundle import PreparedDiscoveryBundle
from secp_worker.onboarding.live_authorization import (
    LiveReadAuthorizationContract,
    LiveReadAuthorizationLoadRequest,
    LiveReadAuthorizationRefused,
    load_and_verify_live_read_authorization,
)

# The pinned, app-owned expected live-read contract (identical to the preflight re-verifier's).
_EXPECTED_CONTRACT = LiveReadAuthorizationContract(
    evidence_source=LIVE_READ_EVIDENCE_SOURCE,
    verification_level=LIVE_VERIFIED_LEVEL,
    collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
)


@runtime_checkable
class DiscoveryBundlePreparer(Protocol):
    """Deployment-local seam yielding ONE strictly-validated discovery bundle snapshot in 2 phases:
    :meth:`prepare_metadata` validates the NON-secret manifest/binding (pre-admission) and
    :meth:`finalize_key_material` reads the private key material ONLY after admission (SECP-B6
    item-4)."""

    def prepare_metadata(self) -> PreparedDiscoveryBundle: ...

    def finalize_key_material(self) -> None: ...

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


def authorize_prepared_discovery_bundle(
    session: Session,
    enrollment: TargetDiscoveryEnrollment,
    prepared: PreparedDiscoveryBundle,
    *,
    now: datetime,
) -> None:
    """Prove the ALREADY-PREPARED bundle snapshot is authorized for this exact job, else refuse.

    Enforces (all BEFORE any host contact, no host contact here):
      F-BIND — the anchor names the claimed enrollment's exact org/target/onboarding/enrollment, and
               an approved, unexpired, version-valid, connection/boundary-hash-matching live-read
               authorization exists (SECP-002B-1B-6 verifier);
      MB-2   — the manifest ``ssh_host`` equals the authoritative target host, and the SSH
               endpoint-binding digest recomputed from the validated manifest equals BOTH the
               bundle's ``binding.json`` digest AND the approved authorization's stored digest.
    Does not dispose (the engine owns the prepared snapshot's lifecycle).
    """
    anchor = prepared.anchor
    # The endpoint binding (MB-2) uses only the NON-secret manifest metadata (host/port/fingerprint)
    # — available from the pre-admission metadata phase, never the private key material.
    ssh = prepared.endpoint

    # Structural identity binding: the anchor must name THIS claimed job.
    if anchor.organization_id != enrollment.organization_id:
        raise DiscoveryBindingRefused("bundle_organization_mismatch")
    if anchor.execution_target_id != enrollment.execution_target_id:
        raise DiscoveryBindingRefused("bundle_target_mismatch")
    if anchor.onboarding_id != enrollment.onboarding_id:
        raise DiscoveryBindingRefused("bundle_onboarding_mismatch")
    if anchor.enrollment_id != enrollment.id:
        raise DiscoveryBindingRefused("bundle_enrollment_mismatch")

    # Authoritative live-read authorization re-verification.
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
        raise DiscoveryBindingRefused(f"live_read_{exc.reason_code}") from None

    # MB-2: bind the SSH destination to the authoritative target authorization.
    target = session.get(ExecutionTarget, enrollment.execution_target_id)
    if target is None:
        raise DiscoveryBindingRefused("execution_target_missing")
    try:
        normalized = normalize_target_host(target.config or {})
    except ValueError:
        raise DiscoveryBindingRefused("target_host_unresolvable") from None
    if ssh.ssh_host.lower() != normalized:
        raise DiscoveryBindingRefused("bundle_target_endpoint_mismatch")
    computed = ssh_endpoint_binding_hash(
        normalized_target_host=normalized,
        ssh_host=ssh.ssh_host,
        ssh_port=int(ssh.ssh_port),
        host_key_fingerprint=ssh.host_key_fingerprint,
    )
    if computed != anchor.endpoint_binding_hash:
        raise DiscoveryBindingRefused("endpoint_binding_manifest_mismatch")
    auth = session.get(LiveReadAuthorization, anchor.authorization_id)
    if auth is None or auth.endpoint_binding_hash != computed:
        raise DiscoveryBindingRefused("endpoint_binding_unauthorized")
