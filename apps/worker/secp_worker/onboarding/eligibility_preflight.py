"""Worker-owned controlled read-only eligibility preflight orchestration (SECP-002B-1B, B1B-PR3).

The single worker seam that turns an explicit operator-authorized disposable-lab target into
immutable, redacted, expiry-bound live eligibility evidence and then STOPS. It is **sealed by
default**: the shipped composition (:func:`sealed_eligibility_composition`) disables the activation
gate and injects no transport/resolver/collector, so no shipped runtime path can reach a real
target. Only a separately-reviewed activation composition (constructed out of band on the
controlled-integration worker) can enable it.

Boundary / non-goals (enforced by the boundary tests):

* It NEVER runs OpenTofu, executes a subprocess, mutates infrastructure, resolves a provisioning
  credential, constructs the real toolchain verifier, or creates a real activation grant. It
  imports no OpenTofu runner, process executor, mutation transport, or provisioning-activation
  module.
* It contacts a target ONLY through the existing, dormant Path B controlled read-only transport
  (:func:`secp_worker.onboarding.live_readonly.run_live_readonly_collection`), which is itself
  default-disabled and technically incapable of mutation (GET-only closed allowlist, TLS-verify,
  no redirects). No new SSH/HTTP/SDK/provider/subprocess client is introduced here.
* Path B stays dormant unless this seam is explicitly activated; the two paths are never both
  activated and there is no fallback from the live path to simulated evidence.

Ordering (fail closed; every privileged seam runs only AFTER its gate):

  seal → controlled-integration posture → authoritative-record + authorization verification (drift/
  expiry/version/contract) → worker-identity binding → operation fingerprint → reusable-evidence
  short-circuit → started audit → **the ONLY target contact** (Path B read-only collection) →
  deterministic policy evaluation → immutable persistence → completed audit → STOP.

A gate refusal contacts nothing, persists no evidence, and records a secret-free
``eligibility_preflight_refused`` audit with a closed reason category (§9/§10).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api import audit
from secp_api.eligibility_policy import (
    ELIGIBILITY_POLICY_VERSION,
    EligibilityGateFacts,
    eligibility_operation_fingerprint,
    evaluate_eligibility,
)
from secp_api.enums import (
    AuditAction,
    EligibilityOutcome,
    EligibilityReasonCategory,
    VerificationLevel,
    WorkerIdentityStatus,
)
from secp_api.live_read_contract import connection_identity_hash
from secp_api.target_evidence import LIVE_READONLY_EVIDENCE_SOURCE, TARGET_EVIDENCE_SCHEMA_VERSION
from secp_plugin_proxmox.live_collector import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
)
from secp_plugin_proxmox.readonly_policy import PROXMOX_READONLY_POLICY_VERSION
from sqlalchemy.orm import Session

from secp_worker.onboarding.live_authorization import (
    LiveReadAuthorizationContract,
    LiveReadAuthorizationLoadRequest,
    LiveReadAuthorizationRefused,
    load_and_verify_live_read_authorization,
)
from secp_worker.onboarding.live_readonly import (
    InvalidLiveReadBinding,
    LiveReadAuthorizationDenied,
    LiveReadAuthorizationVerifier,
    LiveReadCollectionDisabled,
    LiveReadCollectionGate,
    LiveReadTargetCollector,
    TransportFactory,
    run_live_readonly_collection,
)
from secp_worker.secrets import SecretResolver

_R = EligibilityReasonCategory

# Closed mapping from a shared-verifier refusal reason to a secret-free eligibility reason category.
_AUTH_REASON_CATEGORY: dict[str, EligibilityReasonCategory] = {
    "authorization_missing": _R.authorization_invalid,
    "execution_target_missing": _R.authorization_invalid,
    "onboarding_missing": _R.authorization_invalid,
    "wrong_organization": _R.authorization_invalid,
    "wrong_execution_target": _R.authorization_invalid,
    "wrong_onboarding": _R.authorization_invalid,
    "target_not_active": _R.onboarding_not_active,
    "onboarding_not_active": _R.onboarding_not_active,
    "target_credential_reference_missing": _R.authorization_invalid,
    "authorization_draft": _R.authorization_invalid,
    "authorization_revoked": _R.authorization_invalid,
    "authorization_expired": _R.authorization_invalid,
    "authorization_not_approved": _R.authorization_invalid,
    "authorization_version_drift": _R.authorization_invalid,
    "connection_hash_drift": _R.config_drift,
    "boundary_hash_drift": _R.boundary_drift,
    "evidence_source_drift": _R.authorization_invalid,
    "verification_level_drift": _R.authorization_invalid,
    "collector_contract_version_drift": _R.contract_version_mismatch,
    "endpoint_allowlist_version_drift": _R.policy_version_mismatch,
}


class EligibilityPreflightRefused(Exception):
    """Internal control-flow signal carrying a closed, secret-free reason category."""

    def __init__(self, category: EligibilityReasonCategory) -> None:
        super().__init__(f"eligibility preflight refused: {category.value}")
        self.category = category


@dataclass(frozen=True, repr=False)
class EligibilityPreflightRequest:
    """Closed ids/version pinned into one preflight attempt. Carries NO config, boundary, endpoint,
    credential/secret reference, or observation — those are derived only from authoritative records.
    """

    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int
    worker_identity_registration_id: uuid.UUID

    def __repr__(self) -> str:
        return (
            "EligibilityPreflightRequest("
            f"organization_id={self.organization_id!s}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"onboarding_id={self.onboarding_id!s}, "
            f"authorization_id={self.authorization_id!s}, "
            f"authorization_version={self.authorization_version!r})"
        )


@dataclass(frozen=True)
class EligibilityPreflightGate:
    """Default-**disabled** activation gate. A disabled gate refuses before any authoritative-record
    load, authorization verification, worker-identity check, transport, resolver, or collector."""

    enabled: bool = False


@dataclass(frozen=True)
class EligibilityPreflightComposition:
    """The reviewed set of injected seams. The shipped default is fully sealed: a disabled gate and
    no transport/resolver/collector/verifier, so the seam refuses before touching anything."""

    gate: EligibilityPreflightGate = EligibilityPreflightGate()
    live_read_gate: LiveReadCollectionGate = LiveReadCollectionGate()
    secret_resolver: SecretResolver | None = None
    transport_factory: TransportFactory | None = None
    collector: LiveReadTargetCollector | None = None
    authorization_verifier: LiveReadAuthorizationVerifier | None = None


def sealed_eligibility_composition() -> EligibilityPreflightComposition:
    """The shipped, sealed composition: gate disabled, no transport/resolver/collector/verifier."""
    return EligibilityPreflightComposition()


def build_eligibility_composition(settings=None) -> EligibilityPreflightComposition:
    """Deployment-local composition factory used by the durable Temporal activity.

    SHIPPED DEFAULT: fully **sealed** (:func:`sealed_eligibility_composition`) — so the durable path
    runs end to end (records loaded, seam invoked) but refuses at the seal before any transport,
    resolver, collector, or target contact. This is the load-bearing seal: it is NEVER derived from
    an environment flag, the API, or the database. A future, separately-reviewed activation injects
    the real, gated composition HERE — behind the controlled-integration posture AND out-of-band
    reviewed material — so no single env flag can enable execution (mirrors the SealedActivationGate
    / sealed_discovery_composition precedent). ``settings`` is accepted for parity with discovery
    and to make the future two-factor gate explicit; in B1B-PR3 it wires nothing.
    """
    return sealed_eligibility_composition()


@dataclass(frozen=True)
class EligibilityPreflightResult:
    """Closed, secret-free outcome of one attempt (safe for audit and the read model)."""

    outcome: str  # EligibilityOutcome value
    reason_category: str | None = None
    preflight_id: uuid.UUID | None = None
    evidence_hash: str | None = None
    reused: bool = False


class _SessionRepository:
    """Adapter exposing the authoritative records to the shared verifier (read-only)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_execution_target(self, target_id: uuid.UUID):
        from secp_api.models import ExecutionTarget

        return self._session.get(ExecutionTarget, target_id)

    def get_target_onboarding(self, onboarding_id: uuid.UUID):
        from secp_api.models import TargetOnboarding

        return self._session.get(TargetOnboarding, onboarding_id)

    def get_live_read_authorization(self, authorization_id: uuid.UUID):
        from secp_api.models import LiveReadAuthorization

        return self._session.get(LiveReadAuthorization, authorization_id)


class _ConnectionHashProvider:
    """Provider-neutral current connection-hash seam (never hashes credential refs)."""

    def current_connection_hash(self, execution_target) -> str:
        return connection_identity_hash(execution_target.config or {})


def _reusable_valid_preflight(
    session: Session, request: EligibilityPreflightRequest, fingerprint: str, now: datetime
):
    """Return an existing, still-valid live-eligibility preflight for this exact operation, or None.

    A record is reusable only if it is bound to the same operation fingerprint AND has not expired,
    so an exact retry within the TTL does not re-contact the target (§10). A changed binding yields
    a different fingerprint (no match); an expired record is not reused.
    """
    from secp_api.models import TargetPreflight

    existing = (
        session.query(TargetPreflight)
        .filter(
            TargetPreflight.onboarding_id == request.onboarding_id,
            TargetPreflight.operation_fingerprint == fingerprint,
        )
        .one_or_none()
    )
    if existing is None:
        return None
    expires_at = existing.evidence_expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            return None
    return existing


def _verify_worker_identity(session: Session, request: EligibilityPreflightRequest, now: datetime):
    """Return the APPROVED, unexpired worker-identity registration named by the request, or fail
    closed (the durable trust anchor for this org; it authenticates no real worker)."""
    from secp_api.models import WorkerIdentityRegistration

    reg = session.get(WorkerIdentityRegistration, request.worker_identity_registration_id)
    if (
        reg is None
        or reg.organization_id != request.organization_id
        or reg.status != WorkerIdentityStatus.approved
    ):
        raise EligibilityPreflightRefused(_R.worker_identity_untrusted)
    expiry = reg.expiry
    if expiry is not None:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if expiry <= now:
            raise EligibilityPreflightRefused(_R.worker_identity_untrusted)
    return reg


def run_real_eligibility_preflight(
    session: Session,
    *,
    request: EligibilityPreflightRequest,
    composition: EligibilityPreflightComposition | None = None,
    now: datetime | None = None,
) -> EligibilityPreflightResult:
    """Run the sealed-by-default controlled read-only eligibility preflight, then STOP.

    Returns a closed :class:`EligibilityPreflightResult`. On any gate refusal it contacts nothing,
    persists no evidence, and records a secret-free ``eligibility_preflight_refused`` audit.
    """
    composition = composition or sealed_eligibility_composition()
    now = now or datetime.now(UTC)

    audit.record(
        session,
        action=AuditAction.eligibility_preflight_requested,
        resource_type="target_onboarding",
        resource_id=request.onboarding_id,
        organization_id=request.organization_id,
        actor="worker",
        data={
            "execution_target_id": str(request.execution_target_id),
            "authorization_id": str(request.authorization_id),
            "authorization_version": request.authorization_version,
        },
    )

    def refuse(category: EligibilityReasonCategory) -> EligibilityPreflightResult:
        audit.record(
            session,
            action=AuditAction.eligibility_preflight_refused,
            resource_type="target_onboarding",
            resource_id=request.onboarding_id,
            organization_id=request.organization_id,
            actor="worker",
            outcome="refused",
            data={
                "execution_target_id": str(request.execution_target_id),
                "authorization_id": str(request.authorization_id),
                "reason_category": category.value,
            },
        )
        return EligibilityPreflightResult(
            outcome=EligibilityOutcome.refused.value, reason_category=category.value
        )

    try:
        # 0. SEAL — a disabled gate refuses before any record load, verification, or seam is used.
        if not composition.gate.enabled:
            raise EligibilityPreflightRefused(_R.sealed)

        # 1. AUTHORITATIVE RECORDS + AUTHORIZATION — reuse the shared SECP-002B-1B-6 verifier. It
        #    loads the records (never caller config), enforces org/target/onboarding agreement,
        #    target+onboarding ACTIVE, approved/unexpired/unrevoked authorization, version drift,
        #    connection-hash + boundary-hash drift, and the contract/allowlist versions. Any failure
        #    fails closed BEFORE the transport/resolver/collector exist.
        expected_contract = LiveReadAuthorizationContract(
            evidence_source=LIVE_READ_EVIDENCE_SOURCE,
            verification_level=VerificationLevel.live_verified.value,
            collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
            endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
        )
        try:
            verified = load_and_verify_live_read_authorization(
                request=LiveReadAuthorizationLoadRequest(
                    organization_id=request.organization_id,
                    execution_target_id=request.execution_target_id,
                    onboarding_id=request.onboarding_id,
                    authorization_id=request.authorization_id,
                    authorization_version=request.authorization_version,
                ),
                repository=_SessionRepository(session),
                connection_hash_provider=_ConnectionHashProvider(),
                expected_contract=expected_contract,
                now=now,
            )
        except LiveReadAuthorizationRefused as exc:
            raise EligibilityPreflightRefused(
                _AUTH_REASON_CATEGORY.get(exc.reason_code, _R.authorization_invalid)
            ) from exc

        # 2. WORKER IDENTITY — an approved, unexpired durable registration must back this attempt.
        worker_identity = _verify_worker_identity(session, request, now)

        # 3. OPERATION FINGERPRINT — over the COMPLETE verified binding (org/target/config/onboard/
        #    boundary/authorization id+version+expiry/worker-identity id+version/contract+allowlist/
        #    policy versions, toolchain-when-bound [None], dossier placeholder). A change to any
        #    binding yields a new operation.
        fingerprint = eligibility_operation_fingerprint(
            organization_id=str(request.organization_id),
            execution_target_id=str(verified.execution_target.id),
            target_config_hash=verified.binding.target_config_hash,
            onboarding_id=str(verified.onboarding.id),
            boundary_hash=verified.binding.boundary_hash,
            authorization_id=str(verified.authorization.id),
            authorization_version=verified.authorization.authorization_version,
            authorization_expiry=verified.binding.authorization_expiry,
            worker_identity_registration_id=str(worker_identity.id),
            worker_identity_version=worker_identity.identity_version,
            evidence_source=LIVE_READONLY_EVIDENCE_SOURCE,
            verification_level=VerificationLevel.live_verified.value,
            collector_contract_version=verified.binding.collector_contract_version,
            endpoint_allowlist_version=verified.binding.endpoint_allowlist_version,
            policy_version=ELIGIBILITY_POLICY_VERSION,
            toolchain_profile_hash=None,
        )

        # 4. REUSABLE-EVIDENCE SHORT-CIRCUIT — an exact retry within the TTL is not re-collected;
        #    it returns the durable record and records NO duplicate success audit (§10).
        reusable = _reusable_valid_preflight(session, request, fingerprint, now)
        if reusable is not None:
            return EligibilityPreflightResult(
                outcome=reusable.eligibility_outcome or EligibilityOutcome.eligible.value,
                preflight_id=reusable.id,
                evidence_hash=reusable.evidence_hash,
                reused=True,
            )

        # 5. STARTED — every gate has passed; the target contact is about to happen exactly once.
        audit.record(
            session,
            action=AuditAction.eligibility_preflight_started,
            resource_type="target_onboarding",
            resource_id=request.onboarding_id,
            organization_id=request.organization_id,
            actor="worker",
            data={
                "execution_target_id": str(request.execution_target_id),
                "operation_fingerprint": fingerprint,
            },
        )

        # 6. THE ONLY TARGET CONTACT — the existing, dormant, mutation-incapable Path B read-only
        #    collection. A missing seam or a disabled inner gate fails closed (no evidence).
        if (
            not composition.live_read_gate.enabled
            or composition.secret_resolver is None
            or composition.transport_factory is None
            or composition.collector is None
            or composition.authorization_verifier is None
        ):
            raise EligibilityPreflightRefused(_R.gate_incomplete)
        try:
            observed = run_live_readonly_collection(
                gate=composition.live_read_gate,
                binding=verified.binding,
                execution_target=verified.execution_target,
                onboarding=verified.onboarding,
                secret_resolver=composition.secret_resolver,
                transport_factory=composition.transport_factory,
                collector=composition.collector,
                authorization_verifier=composition.authorization_verifier,
                now=now,
            )
        except LiveReadCollectionDisabled as exc:
            raise EligibilityPreflightRefused(_R.gate_incomplete) from exc
        except LiveReadAuthorizationDenied as exc:
            raise EligibilityPreflightRefused(_R.authorization_invalid) from exc
        except InvalidLiveReadBinding as exc:
            raise EligibilityPreflightRefused(_R.collection_failed) from exc
        if not isinstance(observed, dict):
            raise EligibilityPreflightRefused(_R.collection_failed)

        # 7. DETERMINISTIC POLICY — over the freshly observed evidence and the verified gate facts.
        evidence_payload = {
            "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
            "evidence_source": LIVE_READONLY_EVIDENCE_SOURCE,
            "verification_level": VerificationLevel.live_verified.value,
            "observed": observed,
        }
        evaluation = evaluate_eligibility(
            boundary=verified.onboarding.declared_boundary,
            evidence_payload=evidence_payload,
            gate=EligibilityGateFacts(
                target_identity_verified=True,
                config_drift=False,
                boundary_drift=False,
                authorization_expired=False,
                # The read-only collection completed via the resolved credential, so read capability
                # is proven; finer-grained privilege gaps surface as unverifiable observable
                # dimensions (fail closed), never as a fabricated pass.
                credential_read_capability_proven=True,
            ),
        )

        # 8. IMMUTABLE PERSISTENCE — the WORKER-ONLY recorder (unreachable from the API) reuses the
        #    TargetEvidenceRecord + TargetPreflight tables. It takes the TYPED evaluation (carrying
        #    the exact validated payload + findings), the record-derived bindings, and the
        #    fingerprint — never a caller dict — derives passed/checks from the policy, refuses
        #    non-live payloads, and is exact-once per (onboarding, operation_fingerprint).
        from secp_worker.onboarding.eligibility_recorder import record_live_eligibility_evidence

        pf = record_live_eligibility_evidence(
            session,
            onboarding=verified.onboarding,
            target=verified.execution_target,
            evaluation=evaluation,
            operation_fingerprint=fingerprint,
            collector_identity=f"worker:{worker_identity.id}",
            live_read_authorization_id=verified.authorization.id,
            live_read_authorization_version=verified.authorization.authorization_version,
            worker_identity_registration_id=worker_identity.id,
            now=now,
        )
        return EligibilityPreflightResult(
            outcome=evaluation.outcome,
            preflight_id=pf.id,
            evidence_hash=pf.evidence_hash,
        )
    except EligibilityPreflightRefused as exc:
        return refuse(exc.category)


def resolve_eligibility_preflight_request(
    session: Session, onboarding_id: uuid.UUID, now: datetime
) -> tuple[EligibilityPreflightRequest | None, EligibilityReasonCategory | None]:
    """Resolve stable identifiers into an :class:`EligibilityPreflightRequest` from AUTHORITATIVE
    records (worker session), or return a closed refusal reason. The durable activity passes only
    ``onboarding_id``; this loads the onboarding → target, the current approved+unexpired preflight-
    track live-read authorization, and the single approved+unexpired worker-identity registration.
    Nothing is caller-supplied; the seam re-verifies every binding before any contact.
    """
    from secp_api.enums import LiveReadAuthorizationStatus, WorkerIdentityStatus
    from secp_api.models import (
        LiveReadAuthorization,
        TargetOnboarding,
        WorkerIdentityRegistration,
    )
    from sqlalchemy import select

    ob = session.get(TargetOnboarding, onboarding_id)
    if ob is None:
        return None, _R.onboarding_not_active

    # Current approved, unexpired, preflight-track (endpoint_binding_hash IS NULL) authorization,
    # highest version. Expiry is compared portably (SQLite stores naive UTC).
    candidates = (
        session.execute(
            select(LiveReadAuthorization)
            .where(
                LiveReadAuthorization.onboarding_id == ob.id,
                LiveReadAuthorization.execution_target_id == ob.execution_target_id,
                LiveReadAuthorization.status == LiveReadAuthorizationStatus.approved,
                LiveReadAuthorization.endpoint_binding_hash.is_(None),
            )
            .order_by(LiveReadAuthorization.authorization_version.desc())
        )
        .scalars()
        .all()
    )
    authorization = next((a for a in candidates if _unexpired(a.authorization_expiry, now)), None)
    if authorization is None:
        return None, _R.authorization_invalid

    # Exactly one approved, unexpired worker-identity registration for the org (0 or >1 → refuse).
    registrations = [
        r
        for r in session.execute(
            select(WorkerIdentityRegistration).where(
                WorkerIdentityRegistration.organization_id == ob.organization_id,
                WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
            )
        )
        .scalars()
        .all()
        if _unexpired(r.expiry, now)
    ]
    if len(registrations) != 1:
        return None, _R.worker_identity_untrusted

    return (
        EligibilityPreflightRequest(
            organization_id=ob.organization_id,
            execution_target_id=ob.execution_target_id,
            onboarding_id=ob.id,
            authorization_id=authorization.id,
            authorization_version=authorization.authorization_version,
            worker_identity_registration_id=registrations[0].id,
        ),
        None,
    )


def _unexpired(value: datetime | None, now: datetime) -> bool:
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value > now
