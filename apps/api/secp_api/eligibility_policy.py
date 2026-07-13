"""Pure, versioned, deterministic read-only eligibility policy (SECP-002B-1B, B1B-PR3).

Provider-neutral and side-effect free. Given a declared onboarding boundary, an already-collected,
already-normalized, secret-free ``observed`` target-evidence payload, and a small set of
server-derived gate facts, it evaluates every MANDATORY eligibility dimension EXPLICITLY and returns
a single closed :class:`~secp_api.enums.EligibilityOutcome`. There is no partial credit and no
score: ``eligible`` requires every dimension to pass explicitly; any unobservable fact fails closed
to ``unverifiable``; an explicit boundary violation is ``ineligible``; expiry/drift/gate-refusal
produce ``expired`` / ``drifted`` / ``refused`` respectively.

This module performs NO I/O and imports NO worker/plugin/transport/subprocess/secret code. It never
sees an endpoint, credential, raw provider body, or secret — only the normalized observed structure
(the same shape :func:`secp_api.target_evidence.compare_boundary_to_evidence` consumes) plus closed
gate facts. Caller assertions alone never yield ``eligible``: the observed comparison and the proven
read capability are required, and both originate from the gated worker collection, not the caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta

from secp_api.enums import (
    EligibilityDimension,
    EligibilityOutcome,
    EligibilityReasonCategory,
    EvidenceStatus,
    IsolationProfile,
    VerificationLevel,
)
from secp_api.onboarding import OnboardingBoundarySpec
from secp_api.target_evidence import (
    CHECK_CIDRS,
    CHECK_ISOLATION,
    CHECK_NETWORK_SEGMENTS,
    CHECK_NODES,
    CHECK_QUOTAS,
    CHECK_STORAGE,
    CHECK_VMID_RANGE,
    LIVE_READONLY_EVIDENCE_SOURCE,
    compare_boundary_to_evidence,
    validate_target_evidence_payload,
)

# Bump on ANY change to the dimension set or the deterministic decision rules. Persisted with the
# evidence and folded into the idempotency fingerprint so a policy change invalidates old evidence.
ELIGIBILITY_POLICY_VERSION = "secp-002b-1b-pr3/eligibility-policy/v1"

# Conservative bounded TTL for a live eligibility evidence record (§6). Deliberately short: a live
# target can drift, so evidence becomes ``expired`` well before any downstream real-lab consumption.
ELIGIBILITY_EVIDENCE_TTL = timedelta(hours=6)


# A placeholder for the future deployment-local activation-dossier binding (ADR-020 §D). No dossier
# is modeled in B1B-PR3, so the fingerprint pins this stable literal; a future PR that models a real
# dossier hash replaces it here, which (correctly) invalidates every prior eligibility fingerprint.
ELIGIBILITY_ACTIVATION_DOSSIER_PLACEHOLDER = "no-activation-dossier/b1b-pr3"


def eligibility_operation_fingerprint(
    *,
    organization_id: str,
    execution_target_id: str,
    target_config_hash: str,
    onboarding_id: str,
    boundary_hash: str,
    authorization_id: str,
    authorization_version: int,
    authorization_expiry: str,
    worker_identity_registration_id: str,
    worker_identity_version: int,
    evidence_source: str,
    verification_level: str,
    collector_contract_version: str,
    endpoint_allowlist_version: str,
    policy_version: str,
    toolchain_profile_hash: str | None = None,
    activation_dossier_hash: str = ELIGIBILITY_ACTIVATION_DOSSIER_PLACEHOLDER,
) -> str:
    """Deterministic, secret-free exact-once fingerprint over the COMPLETE immutable binding (§10).

    Includes EVERY security-relevant immutable binding — organization, target + config hash,
    onboarding + boundary hash, authorization id/version/canonical-expiry, worker-identity
    registration id + version, evidence source, verification level, collector-contract and
    endpoint-allowlist versions, the eligibility policy version, the toolchain-profile hash WHEN
    bound (empty when unbound, as for read-only eligibility), and the activation-dossier binding
    (a stable placeholder in B1B-PR3). Any change to any of them — authorization expiry, a policy
    bump, a worker-identity rotation, a contract/allowlist bump — yields a NEW operation; an exact
    retry of the same operation yields the same fingerprint. Never includes a secret/endpoint/token.
    """
    canonical = "|".join(
        (
            "secp-002b-1b-pr3/eligibility-operation/v2",
            organization_id,
            execution_target_id,
            target_config_hash,
            onboarding_id,
            boundary_hash,
            authorization_id,
            str(authorization_version),
            authorization_expiry,
            worker_identity_registration_id,
            str(worker_identity_version),
            evidence_source,
            verification_level,
            collector_contract_version,
            endpoint_allowlist_version,
            policy_version,
            toolchain_profile_hash or "",
            activation_dossier_hash,
        )
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_PASS = EvidenceStatus.passed.value
_FAIL = EvidenceStatus.failed.value
_UNVERIFIABLE = EvidenceStatus.unverifiable.value

# A generic, redaction-safe detail per dimension+status. Value-free strings only (no endpoint, IP,
# CIDR, hostname, or provider inventory token) so they pass the preflight-detail redaction gate.
_DETAIL = {
    _PASS: "declared boundary dimension is observed and satisfied",
    _FAIL: "declared boundary dimension is not observed",
    _UNVERIFIABLE: "declared boundary dimension could not be verified from bounded observations",
}


@dataclass(frozen=True)
class DimensionFinding:
    """One mandatory dimension's closed result. All fields are closed codes — never a raw value."""

    dimension: str  # EligibilityDimension value
    status: str  # EvidenceStatus value: pass / fail / unverifiable
    reason: str  # EligibilityReasonCategory value, or "" when passed


@dataclass(frozen=True)
class EligibilityGateFacts:
    """Server-derived, secret-free gate facts the policy folds in (never caller-asserted).

    Every field is produced by the worker orchestration AFTER the controlled gate chain and the
    live read-only collection — the caller cannot set them to force an ``eligible`` result.
    """

    # Dimension A: the collection binding's target/config/org matched the authoritative record.
    target_identity_verified: bool
    # Dimension I inputs: recomputed hashes still agree with the current records.
    config_drift: bool
    boundary_drift: bool
    # Invalidation input: the live-read authorization was still unexpired at collection time.
    authorization_expired: bool
    # Dimension H: True = a real read-only call proved read capability; False = privilege proven
    # insufficient; None = capability could not be proven (unverifiable, fail closed).
    credential_read_capability_proven: bool | None


@dataclass(frozen=True)
class EligibilityEvaluation:
    """The complete, deterministic policy result.

    ``evidence_payload`` is the EXACT validated live target-evidence payload the policy evaluated —
    the recorder persists only this (never a separately-supplied, caller-controlled dict), so live
    evidence is bound to what the evaluator actually saw from the gated worker collection.
    """

    outcome: str  # EligibilityOutcome value
    policy_version: str
    dimensions: tuple[DimensionFinding, ...]
    evidence_payload: dict
    # The boundary↔evidence comparison findings the policy already computed. Carried so the recorder
    # persists the EXACT findings the policy scored — never re-running the comparison (no drift).
    findings: tuple[dict, ...] = ()

    def as_preflight_checks(self) -> list[dict]:
        """Redacted ``{check,status,detail}`` items for a ``TargetPreflight.checks`` payload.

        The ``check`` name is the closed dimension code; ``detail`` is a value-free generic string.
        Statuses map ``pass``/``fail``/``unverifiable`` onto the preflight ``PreflightCheckStatus``
        vocabulary (``passed``/``failed``/``unverifiable``) at the call site.
        """
        return [
            {"check": f.dimension, "status": f.status, "detail": _DETAIL[f.status]}
            for f in self.dimensions
        ]


def _status_of(findings: list[dict], check: str) -> str:
    for f in findings:
        if f.get("check") == check:
            return str(f.get("status"))
    return _UNVERIFIABLE


def _bool_observation(observed: dict, section: str, key: str) -> bool | None:
    """Read a strict-bool nested observation; ``None`` when absent or not a real bool (fail closed).

    A count/int/str/None is treated as unverifiable — the observed fact must be an explicit,
    dedicated boolean produced by the normalizer, never inferred.
    """
    node = observed.get(section)
    if not isinstance(node, dict):
        return None
    value = node.get(key)
    return value if isinstance(value, bool) else None


def _dimension(dim: EligibilityDimension, status: str, reason: str = "") -> DimensionFinding:
    return DimensionFinding(dimension=dim.value, status=status, reason=reason)


def evaluate_eligibility(
    *,
    boundary: dict,
    evidence_payload: dict | None,
    gate: EligibilityGateFacts,
) -> EligibilityEvaluation:
    """Evaluate the mandatory dimensions and return a single closed outcome (fail closed).

    ``boundary`` is the declared onboarding boundary dict; ``evidence_payload`` is the already
    validated live target-evidence payload (the controlled live read-only evidence source with
    ``verification_level=live_verified``) whose ``observed`` section the comparison consumes.
    """
    # Fail closed if the boundary or the payload is missing/malformed: every dimension is
    # unverifiable. compare_boundary_to_evidence already returns all-unverifiable for such inputs.
    try:
        spec = OnboardingBoundarySpec.model_validate(boundary)
    except Exception:
        spec = None

    # The observed comparison is the single source of truth for the observable dimensions. It is
    # provider-neutral, deterministic, and fails closed to ``unverifiable`` for missing evidence.
    findings = compare_boundary_to_evidence(boundary, evidence_payload)

    observed: dict = {}
    if isinstance(evidence_payload, dict):
        try:
            observed = validate_target_evidence_payload(evidence_payload).get("observed") or {}
        except Exception:
            observed = {}
    if not isinstance(observed, dict):
        observed = {}

    dims: list[DimensionFinding] = []

    # A. Target identity — proven by the gate (binding matched the authoritative record).
    dims.append(
        _dimension(EligibilityDimension.target_identity, _PASS)
        if gate.target_identity_verified
        else _dimension(
            EligibilityDimension.target_identity,
            _FAIL,
            EligibilityReasonCategory.hash_disagreement.value,
        )
    )

    # B. Node boundary — the first lab permits EXACTLY ONE allowed node, and it must be observed.
    node_status = _status_of(findings, CHECK_NODES)
    declared_nodes = spec.nodes if spec is not None else []
    if len(declared_nodes) != 1:
        dims.append(
            _dimension(
                EligibilityDimension.node_boundary,
                _FAIL,
                EligibilityReasonCategory.boundary_drift.value,
            )
        )
    else:
        dims.append(_dimension(EligibilityDimension.node_boundary, node_status))

    # C. Storage boundary + disposability — declared storage observed AND an explicit, dedicated
    # ``disposability.storage`` observation proven True. The storage id list (``observed.storage``)
    # drives the boundary comparison; disposability is a SEPARATE explicit boolean observation
    # (never inferred from the id list). Absent disposability observation → unverifiable.
    storage_status = _status_of(findings, CHECK_STORAGE)
    disposable = _bool_observation(observed, "disposability", "storage")
    if storage_status != _PASS:
        dims.append(_dimension(EligibilityDimension.storage_boundary, storage_status))
    elif disposable is True:
        dims.append(_dimension(EligibilityDimension.storage_boundary, _PASS))
    elif disposable is False:
        dims.append(
            _dimension(
                EligibilityDimension.storage_boundary,
                _FAIL,
                EligibilityReasonCategory.boundary_drift.value,
            )
        )
    else:
        dims.append(
            _dimension(
                EligibilityDimension.storage_boundary,
                _UNVERIFIABLE,
                EligibilityReasonCategory.unobservable.value,
            )
        )

    # D. Network / VLAN / CIDR — both the segment allowlist and the CIDR reservations must be
    # observed. The stricter of the two statuses governs (fail beats unverifiable beats pass).
    net_status = _worst(
        _status_of(findings, CHECK_NETWORK_SEGMENTS), _status_of(findings, CHECK_CIDRS)
    )
    dims.append(_dimension(EligibilityDimension.network_segments, net_status))

    # E. Route + isolation posture — fully-segregated, deny-external, no route to protected, and no
    # default route. The comparison proves the first three; the dedicated ``no_default_route``
    # observation must also be explicitly True (absent → unverifiable, fail closed).
    dims.append(_route_isolation_dimension(spec, findings, observed))

    # F. VM-ID range — declared range within the observed range AND no collision. The dedicated
    # ``collision`` observation must be explicitly False (absent → unverifiable, fail closed).
    vmid_status = _status_of(findings, CHECK_VMID_RANGE)
    collision = _bool_observation(observed, "vmid_range", "collision")
    if vmid_status != _PASS:
        dims.append(_dimension(EligibilityDimension.vmid_range, vmid_status))
    elif collision is False:
        dims.append(_dimension(EligibilityDimension.vmid_range, _PASS))
    elif collision is True:
        dims.append(
            _dimension(
                EligibilityDimension.vmid_range,
                _FAIL,
                EligibilityReasonCategory.boundary_drift.value,
            )
        )
    else:
        dims.append(
            _dimension(
                EligibilityDimension.vmid_range,
                _UNVERIFIABLE,
                EligibilityReasonCategory.unobservable.value,
            )
        )

    # G. Quotas / capacity — observed capacity meets every declared quota.
    dims.append(_dimension(EligibilityDimension.quotas, _status_of(findings, CHECK_QUOTAS)))

    # H. Credential / read capability — proven ONLY by a real read-only call; never caller-asserted.
    cap = gate.credential_read_capability_proven
    if cap is True:
        dims.append(_dimension(EligibilityDimension.credential_read_capability, _PASS))
    elif cap is False:
        dims.append(
            _dimension(
                EligibilityDimension.credential_read_capability,
                _FAIL,
                EligibilityReasonCategory.authorization_invalid.value,
            )
        )
    else:
        dims.append(
            _dimension(
                EligibilityDimension.credential_read_capability,
                _UNVERIFIABLE,
                EligibilityReasonCategory.unobservable.value,
            )
        )

    # I. Onboarding / config drift — the recomputed hashes still agree with the current records.
    if gate.config_drift or gate.boundary_drift:
        dims.append(
            _dimension(
                EligibilityDimension.onboarding_drift,
                _FAIL,
                EligibilityReasonCategory.config_drift.value
                if gate.config_drift
                else EligibilityReasonCategory.boundary_drift.value,
            )
        )
    else:
        dims.append(_dimension(EligibilityDimension.onboarding_drift, _PASS))

    outcome = _decide_outcome(dims, gate)
    return EligibilityEvaluation(
        outcome=outcome.value,
        policy_version=ELIGIBILITY_POLICY_VERSION,
        dimensions=tuple(dims),
        # Carry the EXACT payload + findings the policy evaluated so the recorder persists only them
        # — never a separately-supplied caller dict, nor a re-run comparison that could diverge.
        evidence_payload=evidence_payload if isinstance(evidence_payload, dict) else {},
        findings=tuple(findings),
    )


def _worst(*statuses: str) -> str:
    if _FAIL in statuses:
        return _FAIL
    if _UNVERIFIABLE in statuses:
        return _UNVERIFIABLE
    return _PASS


def _route_isolation_dimension(
    spec: OnboardingBoundarySpec | None, findings: list[dict], observed: dict
) -> DimensionFinding:
    isolation_status = _status_of(findings, CHECK_ISOLATION)
    # The declared boundary must itself demand full segregation + deny-external; anything else is a
    # boundary the first lab must not pass on.
    if spec is None or spec.isolation_profile != IsolationProfile.fully_segregated:
        return _dimension(
            EligibilityDimension.route_isolation,
            _FAIL,
            EligibilityReasonCategory.boundary_drift.value,
        )
    if isolation_status != _PASS:
        return _dimension(EligibilityDimension.route_isolation, isolation_status)
    # The comparison proved profile+deny+route_to_protected==False; require the dedicated
    # ``no_default_route`` observation to also be explicitly True (absent → unverifiable).
    no_default_route = _bool_observation(observed, "isolation", "no_default_route")
    if no_default_route is True:
        return _dimension(EligibilityDimension.route_isolation, _PASS)
    if no_default_route is False:
        return _dimension(
            EligibilityDimension.route_isolation,
            _FAIL,
            EligibilityReasonCategory.boundary_drift.value,
        )
    return _dimension(
        EligibilityDimension.route_isolation,
        _UNVERIFIABLE,
        EligibilityReasonCategory.unobservable.value,
    )


def _decide_outcome(dims: list[DimensionFinding], gate: EligibilityGateFacts) -> EligibilityOutcome:
    """Deterministic closed decision. Precedence: expired > drifted > ineligible > unverifiable >
    eligible. Every mandatory dimension must pass explicitly for ``eligible``."""
    if gate.authorization_expired:
        return EligibilityOutcome.expired
    if gate.config_drift or gate.boundary_drift:
        return EligibilityOutcome.drifted
    statuses = {d.status for d in dims}
    if _FAIL in statuses:
        return EligibilityOutcome.ineligible
    if _UNVERIFIABLE in statuses:
        return EligibilityOutcome.unverifiable
    return EligibilityOutcome.eligible


# --- §8 pure validation helper: is a durable live-eligibility evidence record still valid? --------


@dataclass(frozen=True)
class LiveEligibilityEvidenceView:
    """A read-only, secret-free projection of a durable live-eligibility evidence pair, used by the
    pure validity helper. Carries only closed/redacted fields — never a raw observation or secret.
    """

    evidence_source: str
    verification_level: str
    outcome: str
    policy_version: str
    findings_pass: bool
    evidence_hash_matches: bool
    expired: bool
    drifted: bool


def live_eligibility_evidence_is_valid(view: LiveEligibilityEvidenceView) -> bool:
    """Pure, deterministic: does this durable record still satisfy live eligibility? Fail closed.

    Only ``verification_level=live_verified`` evidence from the controlled live read-only evidence
    source (``LIVE_READONLY_EVIDENCE_SOURCE``), with an ``eligible`` outcome, matching hash,
    passing findings, not expired, and not drifted, is valid. A simulated / fake / expired /
    drifted / hash-mismatched record is NEVER valid — fake evidence can never satisfy eligibility.
    """
    return (
        view.evidence_source == LIVE_READONLY_EVIDENCE_SOURCE
        and view.verification_level == VerificationLevel.live_verified.value
        and view.outcome == EligibilityOutcome.eligible.value
        and view.policy_version == ELIGIBILITY_POLICY_VERSION
        and view.findings_pass
        and view.evidence_hash_matches
        and not view.expired
        and not view.drifted
    )
