"""Worker-owned read-only staging-preflight orchestration (SECP-B2-0).

Given one authoritative preflight record, this:

1. re-verifies the authoritative (target, onboarding, live-read authorization) binding via the
   existing SECP-002B-1B-6 verifier (fail-closed on stale/drifted/expired/revoked/invalid);
2. resolves the target's opaque credential reference via an INJECTED worker resolver (a sealed
   resolver in this PR — always fails closed as ``credential_unavailable``);
3. only if a credential is available AND a collection runner is injected, runs the sealed GET-only
   collection path and derives ONLY safe readiness facts (booleans/counts).

It contacts nothing by itself, constructs no transport, and imports no HTTP/socket/subprocess
code. The collection runner (the sole path that could touch a real transport) is worker-injected
and is never reached in this PR because the sealed resolver fails first.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from secp_api.enums import ReadonlyPreflightOutcome
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
    VerifiedLiveReadAuthorization,
    load_and_verify_live_read_authorization,
)
from secp_worker.preflight.secret_resolution import (
    ResolutionPurpose,
    SecretMaterial,
    WorkerSecretResolver,
    build_resolution_contract,
    build_trusted_resolution_request,
)
from secp_worker.secrets import SecretResolutionError

# Verifier reason codes that map to specific authorization terminals; everything else is not_ready.
_AUTHORIZATION_TERMINALS = {
    "authorization_expired": ReadonlyPreflightOutcome.authorization_expired,
    "authorization_revoked": ReadonlyPreflightOutcome.authorization_revoked,
    "authorization_missing": ReadonlyPreflightOutcome.authorization_invalid,
    "authorization_draft": ReadonlyPreflightOutcome.authorization_invalid,
    "authorization_not_approved": ReadonlyPreflightOutcome.authorization_invalid,
    "authorization_version_drift": ReadonlyPreflightOutcome.authorization_invalid,
    "authorization_expiry_malformed": ReadonlyPreflightOutcome.authorization_invalid,
}


class _DbRepository:
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
    """Provider-neutral: hashes the target's stored secret-free connection config (no plugin)."""

    def current_connection_hash(self, execution_target: ExecutionTarget) -> str:
        return connection_identity_hash(execution_target.config or {})


@runtime_checkable
class PreflightCollectionRunner(Protocol):
    """Worker-injected seam that runs the sealed GET-only collection and returns safe facts.

    Only reached when a credential is available (never in this PR — the sealed resolver fails
    first). A real implementation lives in a future activation PR and returns ONLY booleans/counts.
    """

    def run(
        self,
        *,
        verified: VerifiedLiveReadAuthorization,
        credential: SecretMaterial,
        now: datetime,
    ) -> dict: ...


@dataclass(frozen=True)
class PreflightResult:
    outcome: ReadonlyPreflightOutcome
    readiness_facts: dict | None = None


def run_readonly_preflight(
    session: Session,
    preflight_id: uuid.UUID,
    *,
    secret_resolver: WorkerSecretResolver,
    collection_runner: PreflightCollectionRunner | None = None,
    now: datetime | None = None,
) -> PreflightResult:
    """Verify + (fail-closed) resolve + optionally collect. Returns a closed outcome + safe facts.

    Never raises for expected failures; unexpected errors are mapped to ``worker_internal_failure``
    by the caller. No endpoint/host/config value is ever returned in ``readiness_facts``.
    """
    from secp_api.models import ReadonlyStagingPreflight

    now = now or datetime.now(UTC)
    pf = session.get(ReadonlyStagingPreflight, preflight_id)
    if pf is None:
        return PreflightResult(ReadonlyPreflightOutcome.worker_internal_failure)

    request = LiveReadAuthorizationLoadRequest(
        organization_id=pf.organization_id,
        execution_target_id=pf.execution_target_id,
        onboarding_id=pf.onboarding_id,
        authorization_id=pf.live_read_authorization_id,
        authorization_version=pf.authorization_version,
    )
    expected_contract = LiveReadAuthorizationContract(
        evidence_source=LIVE_READ_EVIDENCE_SOURCE,
        verification_level=LIVE_VERIFIED_LEVEL,
        collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
    )

    # 1. Authoritative verification (fail closed). Reuses the SECP-002B-1B-6 verifier.
    try:
        verified = load_and_verify_live_read_authorization(
            request=request,
            repository=_DbRepository(session),
            connection_hash_provider=_ConnectionHashProvider(),
            expected_contract=expected_contract,
            now=now,
        )
    except LiveReadAuthorizationRefused as refused:
        outcome = _AUTHORIZATION_TERMINALS.get(
            refused.reason_code, ReadonlyPreflightOutcome.not_ready
        )
        return PreflightResult(outcome)

    # 2. Secret-resolution boundary (SECP-B2-1). The trusted resolution request is constructed
    #    ONLY here, AFTER the verifier above succeeded — a caller cannot supply it as a trust
    #    anchor. Building it also runs the pinned policy check (contract + endpoint-policy labels).
    #    The independently derived authoritative contract is passed alongside so the resolver must
    #    confirm the request matches the binding before it would ever resolve. The sealed resolver
    #    always fails closed here -> credential_unavailable. No transport is built.
    fingerprint = _operation_fingerprint(pf)
    try:
        resolution_request = build_trusted_resolution_request(
            verified=verified,
            purpose=ResolutionPurpose.readonly_staging_preflight,
            operation_fingerprint=fingerprint,
            now=now,
        )
        expectation = build_resolution_contract(
            verified=verified,
            purpose=ResolutionPurpose.readonly_staging_preflight,
            operation_fingerprint=fingerprint,
            now=now,
        )
        credential = secret_resolver.resolve(resolution_request, expectation=expectation, now=now)
    except SecretResolutionError:
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 3. Collection is worker-only and injected; unreachable in this PR (sealed resolver above).
    if collection_runner is None:
        # A credential was resolvable but no collection runner is wired: activation-incomplete.
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)
    try:
        facts = collection_runner.run(verified=verified, credential=credential, now=now)
    except _PolicyOrTlsRefusal:
        return PreflightResult(ReadonlyPreflightOutcome.tls_or_policy_refused)
    return PreflightResult(ReadonlyPreflightOutcome.ready, readiness_facts=_safe_facts(facts))


def _operation_fingerprint(pf: object) -> str:
    """Deterministic, secret-free ``sha256:`` fingerprint of the preflight work item.

    Derived only from durable identity fields (never config, endpoints, credentials, or secret
    references). Binds a resolution request to the exact queued operation it was issued for.
    """
    identity = {
        "preflight_id": str(getattr(pf, "id", "")),
        "organization_id": str(getattr(pf, "organization_id", "")),
        "execution_target_id": str(getattr(pf, "execution_target_id", "")),
        "onboarding_id": str(getattr(pf, "onboarding_id", "")),
        "authorization_id": str(getattr(pf, "live_read_authorization_id", "")),
        "authorization_version": getattr(pf, "authorization_version", None),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class _PolicyOrTlsRefusal(Exception):
    """A collection runner raises this for a TLS/allowlist/policy refusal (safe, secret-free)."""


# Only these safe, non-identifying readiness fact keys may be persisted/returned.
_ALLOWED_FACT_KEYS = frozenset(
    {
        "api_reachable",
        "readonly_policy_enforced",
        "node_count",
        "storage_count",
        "network_segment_count",
        "tls_verified",
    }
)


def _safe_facts(facts: dict) -> dict:
    """Keep ONLY the closed set of safe boolean/count facts; drop anything else defensively."""
    out: dict[str, object] = {}
    for key in _ALLOWED_FACT_KEYS:
        if key in facts:
            value = facts[key]
            if isinstance(value, bool) or isinstance(value, int):
                out[key] = value
    return out
