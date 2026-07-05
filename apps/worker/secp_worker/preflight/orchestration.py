"""Worker-owned read-only staging-preflight orchestration (SECP-B2-0 / B2-4.2).

Given one authoritative preflight record, this:

1. re-verifies the authoritative (target, onboarding, live-read authorization) binding via the
   existing SECP-002B-1B-6 verifier (fail-closed on stale/drifted/expired/revoked/invalid);
2. verifies worker identity + the sealed activation gate (shipped defaults deny/disable), then
   independently re-verifies the durable app-owned resolver-activation authorization + its complete
   evidence (SECP-B2-4.1) — MANDATORY and load-bearing BEFORE any durable lease is acquired
   (SECP-B2-4.2); any missing/invalid/expired/mismatched activation fails closed as
   ``credential_unavailable``;
3. resolves the target's opaque credential reference via an INJECTED worker resolver (the sealed
   resolver in shipped runtime — always fails closed as ``credential_unavailable``);
4. only if a credential is available AND a collection runner is injected, runs the sealed GET-only
   collection path (the single governed handoff, passed the verified activation capability) and
   derives ONLY safe readiness facts (booleans/counts).

It contacts nothing by itself, constructs no transport, and imports no HTTP/socket/subprocess/
OpenBao/Proxmox client code. The shipped runtime stops at the deny-by-default worker identity
(step 4 below) BEFORE the activation check, the lease, the resolver, or the collector — every
preflight still terminates as ``credential_unavailable`` with no lease row, no attempt, no secret
material, and no contact.
"""

from __future__ import annotations

import hmac
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
from secp_api.resolver_activation_contract import RESOLVER_ADAPTER_CONTRACT_VERSION
from sqlalchemy.orm import Session

from secp_worker.onboarding.live_authorization import (
    LiveReadAuthorizationContract,
    LiveReadAuthorizationLoadRequest,
    LiveReadAuthorizationRefused,
    VerifiedLiveReadAuthorization,
    load_and_verify_live_read_authorization,
)
from secp_worker.preflight.activation_authorization import (
    ActivationAuthorizationRefused,
    ResolverActivationCapability,
    load_and_verify_activation_capability,
)
from secp_worker.preflight.activation_gate import (
    ResolutionActivationDisabled,
    ResolutionActivationGate,
    SealedActivationGate,
)
from secp_worker.preflight.fingerprint import compute_operation_fingerprint
from secp_worker.preflight.identity import (
    DenyingWorkerIdentityVerifier,
    WorkerIdentityUnavailable,
    WorkerIdentityVerifier,
)
from secp_worker.preflight.lease import (
    LeaseRefused,
    OperationKey,
    acquire_lease,
    begin_attempt,
)
from secp_worker.preflight.secret_resolution import (
    ResolutionPurpose,
    SecretMaterial,
    TrustedResolutionRequest,
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

    Only reached when a credential is available (never in shipped runtime — the sealed resolver
    fails first). The governed orchestration OWNS this single handoff and passes the independently
    re-verified ``ResolverActivationCapability`` into it, so no collector can run without a durable,
    approved, evidence-complete activation authorization (SECP-B2-4.2). A real implementation lives
    in a future activation PR and returns ONLY booleans/counts.
    """

    def run(
        self,
        *,
        verified: VerifiedLiveReadAuthorization,
        credential: SecretMaterial,
        capability: ResolverActivationCapability,
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
    identity_verifier: WorkerIdentityVerifier | None = None,
    activation_gate: ResolutionActivationGate | None = None,
    now: datetime | None = None,
) -> PreflightResult:
    """Verify + (fail-closed) resolve + optionally collect. Returns a closed outcome + safe facts.

    Never raises for expected failures; unexpected errors are mapped to ``worker_internal_failure``
    by the caller. No endpoint/host/config value is ever returned in ``readiness_facts``.

    ``identity_verifier`` and ``activation_gate`` default to the SHIPPED SEALED defaults
    (:class:`DenyingWorkerIdentityVerifier`, :class:`SealedActivationGate`), which fail closed
    **before** any durable lease is acquired — so shipped runtime never reaches lease acquisition or
    begin-attempt, and every preflight still terminates as ``credential_unavailable``. Tests may
    inject an approved identity + gate to exercise the durable lease transitions; that path still
    ends at the sealed resolver and produces no secret material, transport, collector, or contact.
    """
    identity_verifier = identity_verifier or DenyingWorkerIdentityVerifier()
    activation_gate = activation_gate or SealedActivationGate()
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

    # 2. Pinned policy check (SECP-B2-1). The trusted resolution request + the independently
    #    derived authoritative contract are built ONLY here, AFTER the verifier above succeeded,
    #    from the freshly re-verified authoritative records — a caller-supplied "expected contract"
    #    is NEVER used as a trust anchor, and the request object is never proof of authorization.
    #    Building runs the pinned collector-contract + endpoint-policy checks.
    fingerprint = compute_operation_fingerprint(pf)
    try:
        resolution_request = build_trusted_resolution_request(
            verified=verified,
            purpose=ResolutionPurpose.readonly_staging_preflight,
            operation_fingerprint=fingerprint,
            preflight_id=pf.id,
            now=now,
        )
        expectation = build_resolution_contract(
            verified=verified,
            purpose=ResolutionPurpose.readonly_staging_preflight,
            operation_fingerprint=fingerprint,
            preflight_id=pf.id,
            now=now,
        )
    except SecretResolutionError:
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 3. Credential-reference three-way binding (SECP-B2-3): the authoritative target reference, the
    #    re-verified live-read binding reference, and the request reference must all be equal
    #    (constant-time). Any mismatch fails closed BEFORE identity, gate, lease, or resolution. The
    #    three values are never logged, serialized, persisted, hashed, audited, or rendered.
    if not _three_way_reference_match(verified, resolution_request):
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 4. Worker-identity verification (SECP-B2-3). The SHIPPED default denies -> fail closed here,
    #    BEFORE any durable lease is acquired. No environment/host/network/certificate is read.
    try:
        identity = identity_verifier.verify()
    except WorkerIdentityUnavailable:
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 5. Sealed activation gate (SECP-B2-3). The SHIPPED default is disabled -> fail closed here,
    #    BEFORE any durable lease is acquired. It cannot be enabled by env/config/Compose/flags/DB.
    try:
        activation_gate.check()
    except ResolutionActivationDisabled:
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 5b. MANDATORY durable resolver-activation authorization (SECP-B2-4.1/B2-4.2). Independently
    #     re-load + re-verify the app-owned activation authorization + its complete evidence from
    #     the authoritative records, BEFORE any durable lease is acquired or attempt consumed. The
    #     verifier binds org, execution target, onboarding, live-read authorization id + version,
    #     preflight id, purpose, operation fingerprint, and resolver-adapter contract version, and
    #     recomputes the evidence fingerprint. A missing/draft/revoked/expired/incomplete/mismatched
    #     authorization fails closed with the SAME safe outcome as the sealed chain
    #     (``credential_unavailable``) — the closed refusal reason is never surfaced, so no
    #     activation/evidence/reference/backend detail leaks. The returned capability is redacted,
    #     non-serializable, and worker-constructed only; it cannot be forged by API/UI/config/DB.
    #     The shipped runtime never reaches this step (identity denies at step 4).
    try:
        capability = load_and_verify_activation_capability(
            session,
            preflight=pf,
            resolver_contract_version=RESOLVER_ADAPTER_CONTRACT_VERSION,
            now=now,
        )
    except ActivationAuthorizationRefused:
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 6-7. Durable lease acquisition + begin-attempt (SECP-B2-3). Reached ONLY with an approved
    #      identity + gate + a verified activation capability (tests/future). begin-attempt is the
    #      only transition that consumes the fixed N=3 durable budget keyed by (authorization_id,
    #      authorization_version, operation_fingerprint). Shipped runtime never gets here.
    key = OperationKey(
        live_read_authorization_id=pf.live_read_authorization_id,
        authorization_version=pf.authorization_version,
        operation_fingerprint=fingerprint,
    )
    try:
        lease = acquire_lease(
            session,
            organization_id=pf.organization_id,
            key=key,
            worker_identity_id=identity.worker_identity_id,
            authorization_expiry=verified.authorization.authorization_expiry,
            now=now,
        )
        begin_attempt(session, lease, now=now)
    except LeaseRefused:
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 8. Secret-resolution boundary (SECP-B2-1, still sealed). The sealed resolver always fails
    #    closed here -> credential_unavailable. No transport is built and no material is produced.
    try:
        credential = secret_resolver.resolve(resolution_request, expectation=expectation, now=now)
    except SecretResolutionError:
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)

    # 9. Collection is worker-only, injected, and OWNED by this governed orchestration; it is
    #    unreachable in shipped runtime (the sealed resolver fails above). The verified activation
    #    capability is passed into the single handoff so no collector can run without a durable,
    #    approved, evidence-complete activation authorization — there is no separate bypassable
    #    collection track.
    if collection_runner is None:
        # A credential was resolvable but no collection runner is wired: activation-incomplete.
        return PreflightResult(ReadonlyPreflightOutcome.credential_unavailable)
    try:
        facts = collection_runner.run(
            verified=verified, credential=credential, capability=capability, now=now
        )
    except _PolicyOrTlsRefusal:
        return PreflightResult(ReadonlyPreflightOutcome.tls_or_policy_refused)
    return PreflightResult(ReadonlyPreflightOutcome.ready, readiness_facts=_safe_facts(facts))


def _three_way_reference_match(
    verified: VerifiedLiveReadAuthorization, request: TrustedResolutionRequest
) -> bool:
    """Constant-time three-way equality of the opaque credential reference (SECP-B2-3).

    Compares the authoritative ``ExecutionTarget.secret_ref``, the re-verified live-read binding
    reference, and the request's ``TrustedCredentialReference``. The values are never logged,
    serialized, persisted, hashed, audited, or rendered — only compared and discarded.
    """
    target_ref = verified.execution_target.secret_ref or ""
    binding_ref = verified.binding.credential_ref or ""
    request_ref = request.contract.credential_reference.reveal_reference()
    if not (target_ref and binding_ref and request_ref):
        return False
    match_tb = hmac.compare_digest(target_ref, binding_ref)
    match_br = hmac.compare_digest(binding_ref, request_ref)
    return match_tb and match_br


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
