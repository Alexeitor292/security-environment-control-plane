"""Worker-only, explicitly-invoked staging-live canaries (SECP-B2-5-pre).

Two controlled operations, unavailable in normal runtime. Neither re-implements the authorization
chain: both DRIVE the existing governed ``run_readonly_preflight`` orchestration, so every canary
inherits — with no bypass and no duplicated security logic — the full durable chain (authoritative
live-read re-verification -> three-way credential-reference binding -> mandatory verified worker
identity -> explicit activation gate -> durable resolver-activation capability -> operation
budget/lease -> begin-attempt) before any secret is resolved or any transport is built.

* The OpenBao readiness canary drives the chain with a probe resolver that, ONLY once the chain has
  reached the resolver boundary, proves OpenBao authentication via a self-test and then FAILS CLOSED
  without resolving a secret. No Proxmox credential is resolved and no Proxmox is contacted.
* The Proxmox transport canary drives the chain with the concrete OpenBao resolver AND a single-GET
  collection runner, so it runs ONLY after a valid identity, activation, and a RESOLVED staging-only
  credential; it performs exactly ONE allowlisted GET through the existing hardened transport,
  persists NO raw response, and records ONLY safe facts via the immutable live-evidence boundary.

Because the Proxmox credential is resolved THROUGH OpenBao, no Proxmox contact can structurally
occur before OpenBao authentication. The intended operational order is nonetheless explicit: run the
OpenBao readiness canary, then the Proxmox transport canary, then the first full staging preflight.
Both canaries are testable with mocked injected transports/backends; nothing real is contacted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api.enums import (
    LivePreflightCheckCode,
    LivePreflightEvidenceStatus,
    LivePreflightFindingStatus,
    ResolverActivationStatus,
)
from secp_api.models import (
    ReadonlyStagingPreflight,
    ResolutionLease,
    ResolverActivationAuthorization,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_worker.preflight.backends.openbao_resolver import (
    OpenBaoWorkerSecretResolver,
    ResolverSelfTestResult,
)
from secp_worker.preflight.fingerprint import compute_operation_fingerprint
from secp_worker.preflight.live_evidence_writer import LivePreflightEvidenceContext
from secp_worker.preflight.orchestration import PreflightResult, run_readonly_preflight
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    SecretMaterial,
    SecretResolutionUnavailable,
    TrustedResolutionRequest,
)
from secp_worker.preflight.worker_identity_attestation import RegisteredWorkerIdentityVerifier
from secp_worker.staging_live.composition import (
    HardenedTransportFactory,
    ReadOnlyCollector,
    StagingLiveComposition,
)


@dataclass(frozen=True)
class CanaryResult:
    """A CLOSED, redacted canary result. ``reason_code`` is a backend-generated closed code
    or a closed preflight-outcome label — never an endpoint, secret, raw response, or free text.
    ``evidence_id`` is set only when a durable live-evidence record was written."""

    ok: bool
    reason_code: str
    evidence_id: object | None = None


class _OpenBaoReadinessProbe:
    """A ``WorkerSecretResolver`` that, once the chain reaches the resolver boundary, proves
    OpenBao authentication via a self-test and then fails closed WITHOUT resolving a secret. It
    contacts no Proxmox and returns no :class:`SecretMaterial`."""

    def __init__(self, resolver: OpenBaoWorkerSecretResolver) -> None:
        self._resolver = resolver
        self.result: ResolverSelfTestResult | None = None

    def resolve(
        self,
        request: TrustedResolutionRequest,
        *,
        expectation: ResolutionContract,
        now: datetime,
    ) -> SecretMaterial:
        # Prove OpenBao authentication only. No secret is resolved and nothing is returned.
        self.result = self._resolver.self_test(now=now)
        raise SecretResolutionUnavailable("openbao_readiness_probe_no_resolution")


class _SingleGetCollectionRunner:
    """A ``PreflightCollectionRunner`` that performs exactly ONE allowlisted GET via the injected
    hardened transport and returns ONLY safe facts. Persists no raw response."""

    def __init__(
        self,
        *,
        transport_factory: HardenedTransportFactory,
        collector: ReadOnlyCollector,
        declared_boundary: dict,
    ) -> None:
        self._transport_factory = transport_factory
        self._collector = collector
        self._declared_boundary = declared_boundary

    def run(
        self,
        *,
        verified: object,
        credential: SecretMaterial,
        capability: object,
        now: datetime,
    ) -> dict:
        transport = self._transport_factory(verified, credential.reveal_secret())
        observed = self._collector.collect(transport, declared_boundary=self._declared_boundary)
        # Return ONLY safe booleans + bounded counts derived from the observed inventory. The raw
        # inventory (node/storage/network names) is discarded here and never leaves this method.
        return _safe_readiness_facts(observed if isinstance(observed, dict) else {})


def _safe_readiness_facts(observed: dict) -> dict:
    """Reduce an observed inventory to ONLY safe booleans + bounded counts (never a name/value)."""
    body = observed.get("observed", observed) if isinstance(observed, dict) else {}
    nodes = body.get("nodes") if isinstance(body, dict) else None
    storage = body.get("storage") if isinstance(body, dict) else None
    segments = body.get("network_segments") if isinstance(body, dict) else None
    return {
        "api_reachable": True,
        "readonly_policy_enforced": True,
        "node_count": len(nodes) if isinstance(nodes, list) else 0,
        "storage_count": len(storage) if isinstance(storage, list) else 0,
        "network_segment_count": len(segments) if isinstance(segments, list) else 0,
    }


def run_openbao_readiness_canary(
    session: Session,
    *,
    preflight_id: uuid.UUID,
    composition: StagingLiveComposition,
    now: datetime | None = None,
) -> CanaryResult:
    """Drive the governed chain and prove OpenBao authentication at the resolver boundary WITHOUT
    resolving a Proxmox credential or contacting Proxmox. Returns a closed redacted result."""
    now = now or datetime.now(UTC)
    probe = _OpenBaoReadinessProbe(composition.secret_resolver)
    result: PreflightResult = run_readonly_preflight(
        session,
        preflight_id,
        secret_resolver=probe,
        identity_verifier=composition.identity_verifier,
        activation_gate=composition.activation_gate,
        now=now,
    )
    if probe.result is None:
        # The durable chain failed BEFORE the resolver boundary; OpenBao was never contacted.
        return CanaryResult(ok=False, reason_code=result.outcome.value)
    return CanaryResult(ok=bool(probe.result.ok), reason_code=str(probe.result.reason_code))


def run_proxmox_transport_canary(
    session: Session,
    *,
    preflight_id: uuid.UUID,
    composition: StagingLiveComposition,
    declared_boundary: dict,
    now: datetime | None = None,
) -> CanaryResult:
    """Drive the governed chain with the OpenBao resolver AND a single-GET collection runner.
    Runs the single allowlisted GET only after a valid identity, activation, and RESOLVED staging
    credential, then persists ONLY safe facts via the immutable live-evidence boundary. The evidence
    context is assembled from the AUTHORITATIVE durable records (never caller input)."""
    now = now or datetime.now(UTC)
    runner = _SingleGetCollectionRunner(
        transport_factory=composition.transport_factory,
        collector=composition.collector,
        declared_boundary=declared_boundary,
    )
    result: PreflightResult = run_readonly_preflight(
        session,
        preflight_id,
        secret_resolver=composition.secret_resolver,
        collection_runner=runner,
        identity_verifier=composition.identity_verifier,
        activation_gate=composition.activation_gate,
        now=now,
    )
    if result.outcome.value != "ready":
        # Chain/resolution/collection failed closed; no evidence is written for a non-ready outcome.
        return CanaryResult(ok=False, reason_code=result.outcome.value)
    context = _build_evidence_context(session, preflight_id, composition, now)
    if context is None:
        # The governed run succeeded but an authoritative binding record could not be re-loaded.
        return CanaryResult(ok=False, reason_code="evidence_context_unavailable")
    facts, checks = _safe_canary_facts(result.readiness_facts or {})
    row = composition.evidence_writer.write(
        session,
        context=context,
        status=LivePreflightEvidenceStatus.passed,
        facts=facts,
        checks=checks,
        now=now,
    )
    return CanaryResult(ok=True, reason_code="collected", evidence_id=row.id)


def _build_evidence_context(
    session: Session,
    preflight_id: uuid.UUID,
    composition: StagingLiveComposition,
    now: datetime,
) -> LivePreflightEvidenceContext | None:
    """Assemble the live-evidence context SOLELY from authoritative durable records after the
    governed chain has completed: the preflight, the approved activation authorization, the verified
    worker identity (re-verified, read-only), and the durable resolution lease. Returns ``None`` if
    any required record is missing (fail closed — no evidence is written)."""
    pf = session.get(ReadonlyStagingPreflight, preflight_id)
    if pf is None:
        return None
    fingerprint = compute_operation_fingerprint(pf)
    activation = session.execute(
        select(ResolverActivationAuthorization).where(
            ResolverActivationAuthorization.preflight_id == pf.id,
            ResolverActivationAuthorization.status == ResolverActivationStatus.approved,
        )
    ).scalar_one_or_none()
    lease = session.execute(
        select(ResolutionLease).where(
            ResolutionLease.live_read_authorization_id == pf.live_read_authorization_id,
            ResolutionLease.authorization_version == pf.authorization_version,
            ResolutionLease.operation_fingerprint == fingerprint,
        )
    ).scalar_one_or_none()
    if activation is None or lease is None:
        return None
    # Re-verify identity (read-only) to bind the durable registration id + version — never a claim.
    identity = composition.identity_verifier.verify(session, preflight=pf, now=now)
    return LivePreflightEvidenceContext(
        organization_id=pf.organization_id,
        preflight_id=pf.id,
        execution_target_id=pf.execution_target_id,
        onboarding_id=pf.onboarding_id,
        live_read_authorization_id=pf.live_read_authorization_id,
        live_read_authorization_version=pf.authorization_version,
        resolver_activation_authorization_id=activation.id,
        resolver_activation_authorization_version=activation.authorization_version,
        worker_identity_registration_id=identity.registration_id,
        worker_identity_version=identity.identity_version,
        resolution_lease_id=lease.id,
        operation_fingerprint=fingerprint,
        collector_contract_version=pf.collector_contract_version,
        endpoint_allowlist_version=pf.endpoint_allowlist_version,
        resolver_contract_version=activation.resolver_adapter_contract_version,
    )


def _safe_canary_facts(readiness_facts: dict) -> tuple[dict, list]:
    """Map the orchestration's already-safe readiness facts (booleans/bounded counts only) to the
    live-evidence fact schema, and attach closed GET-only/no-redirect check codes. Never a node/
    storage/network name, endpoint, or raw value."""
    rf = readiness_facts if isinstance(readiness_facts, dict) else {}
    facts = {
        "api_reachable": bool(rf.get("api_reachable", False)),
        "readonly_policy_enforced": bool(rf.get("readonly_policy_enforced", False)),
        "node_count": int(rf.get("node_count", 0) or 0),
        "storage_count": int(rf.get("storage_count", 0) or 0),
        "network_segment_count": int(rf.get("network_segment_count", 0) or 0),
    }
    checks = [
        {
            "code": LivePreflightCheckCode.get_only_enforced.value,
            "status": LivePreflightFindingStatus.passed.value,
        },
        {
            "code": LivePreflightCheckCode.no_redirect_followed.value,
            "status": LivePreflightFindingStatus.passed.value,
        },
        {
            # A generic inventory GET can NEVER by itself prove full network segregation.
            "code": LivePreflightCheckCode.fully_segregated_isolation.value,
            "status": LivePreflightFindingStatus.unverifiable.value,
        },
    ]
    return facts, checks


# Re-export the verifier type so the staging-live composition can be assembled from this package.
__all__ = [
    "CanaryResult",
    "RegisteredWorkerIdentityVerifier",
    "run_openbao_readiness_canary",
    "run_proxmox_transport_canary",
]
