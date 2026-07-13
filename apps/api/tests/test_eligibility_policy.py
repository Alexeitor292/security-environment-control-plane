"""Pure eligibility-policy unit tests (SECP-002B-1B, B1B-PR3).

Deterministic, provider-neutral, no I/O. Exercises every mandatory dimension, the closed outcome
precedence, fail-closed on unobservable facts, and the §8 validity helper. These tests never
construct a transport, never contact anything, and never persist.
"""

from __future__ import annotations

import copy

from secp_api.eligibility_policy import (
    ELIGIBILITY_POLICY_VERSION,
    EligibilityGateFacts,
    LiveEligibilityEvidenceView,
    evaluate_eligibility,
    live_eligibility_evidence_is_valid,
)
from secp_api.enums import (
    EligibilityDimension,
    EligibilityOutcome,
    EvidenceStatus,
    VerificationLevel,
)
from secp_api.target_evidence import LIVE_READONLY_EVIDENCE_SOURCE, TARGET_EVIDENCE_SCHEMA_VERSION

# A minimal single-node, fully-segregated declared boundary (the first-lab shape).
BOUNDARY: dict = {
    "nodes": ["labnode"],
    "storage": ["labstore"],
    "network_segments": ["labseg"],
    "cidrs": ["10.9.0.0/24"],
    "vmid_range": {"start": 9000, "end": 9100},
    "quotas": {
        "max_teams": 1,
        "max_vms": 4,
        "max_containers": 2,
        "max_total_vcpu": 8,
        "max_total_memory_mb": 8192,
        "max_total_disk_gb": 100,
    },
    "external_connectivity": {"policy": "deny"},
    "credential_scope": "least_privilege",
}


def _good_observed() -> dict:
    """Observed dict that satisfies EVERY observable dimension for BOUNDARY, including the explicit,
    approved dedicated observations (disposability / vmid collision / no-default-route)."""
    return {
        "nodes": ["labnode"],
        "storage": ["labstore"],
        "network_segments": ["labseg"],
        "cidr_reservations": ["10.9.0.0/24"],
        "vmid_range": {"start": 8000, "end": 9999, "collision": False},
        "quotas": {
            "max_teams": 2,
            "max_vms": 8,
            "max_containers": 4,
            "max_total_vcpu": 16,
            "max_total_memory_mb": 16384,
            "max_total_disk_gb": 200,
        },
        "isolation": {
            "profile": "fully_segregated",
            "external_connectivity_policy": "deny",
            "route_to_protected": False,
            "no_default_route": True,
        },
        "disposability": {"storage": True},
    }


def _live_payload(observed: dict) -> dict:
    return {
        "schema_version": TARGET_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": LIVE_READONLY_EVIDENCE_SOURCE,
        "verification_level": VerificationLevel.live_verified.value,
        "observed": observed,
    }


def _proven_gate() -> EligibilityGateFacts:
    return EligibilityGateFacts(
        target_identity_verified=True,
        config_drift=False,
        boundary_drift=False,
        authorization_expired=False,
        credential_read_capability_proven=True,
    )


def _status_map(ev) -> dict:
    return {d.dimension: d.status for d in ev.dimensions}


def test_all_dimensions_pass_yields_eligible():
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.eligible.value
    assert ev.policy_version == ELIGIBILITY_POLICY_VERSION
    statuses = _status_map(ev)
    # Every mandatory dimension is present and explicitly passed.
    assert set(statuses) == {d.value for d in EligibilityDimension}
    assert all(s == EvidenceStatus.passed.value for s in statuses.values())


def test_missing_isolation_observation_is_unverifiable_not_eligible():
    observed = _good_observed()
    observed.pop("isolation")
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.unverifiable.value
    assert _status_map(ev)[EligibilityDimension.route_isolation.value] == (
        EvidenceStatus.unverifiable.value
    )


def test_missing_no_default_route_boolean_is_unverifiable():
    observed = _good_observed()
    observed["isolation"].pop("no_default_route")
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.unverifiable.value


def test_missing_disposability_is_unverifiable():
    observed = _good_observed()
    observed.pop("disposability")
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert _status_map(ev)[EligibilityDimension.storage_boundary.value] == (
        EvidenceStatus.unverifiable.value
    )
    assert ev.outcome == EligibilityOutcome.unverifiable.value


def test_vmid_collision_is_ineligible():
    observed = _good_observed()
    observed["vmid_range"]["collision"] = True
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.ineligible.value
    assert _status_map(ev)[EligibilityDimension.vmid_range.value] == EvidenceStatus.failed.value


def test_multi_node_boundary_is_ineligible():
    boundary = copy.deepcopy(BOUNDARY)
    boundary["nodes"] = ["labnode", "other"]
    ev = evaluate_eligibility(
        boundary=boundary, evidence_payload=_live_payload(_good_observed()), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.ineligible.value
    assert _status_map(ev)[EligibilityDimension.node_boundary.value] == EvidenceStatus.failed.value


def test_declared_node_not_observed_is_ineligible():
    observed = _good_observed()
    observed["nodes"] = ["someoneelse"]
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.ineligible.value


def test_unproven_credential_capability_is_unverifiable():
    gate = EligibilityGateFacts(
        target_identity_verified=True,
        config_drift=False,
        boundary_drift=False,
        authorization_expired=False,
        credential_read_capability_proven=None,
    )
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=gate
    )
    assert ev.outcome == EligibilityOutcome.unverifiable.value
    assert _status_map(ev)[EligibilityDimension.credential_read_capability.value] == (
        EvidenceStatus.unverifiable.value
    )


def test_expired_authorization_takes_precedence():
    gate = EligibilityGateFacts(
        target_identity_verified=True,
        config_drift=False,
        boundary_drift=False,
        authorization_expired=True,
        credential_read_capability_proven=True,
    )
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=gate
    )
    assert ev.outcome == EligibilityOutcome.expired.value


def test_drift_takes_precedence_over_dimension_pass():
    gate = EligibilityGateFacts(
        target_identity_verified=True,
        config_drift=True,
        boundary_drift=False,
        authorization_expired=False,
        credential_read_capability_proven=True,
    )
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=gate
    )
    assert ev.outcome == EligibilityOutcome.drifted.value
    assert _status_map(ev)[EligibilityDimension.onboarding_drift.value] == (
        EvidenceStatus.failed.value
    )


def test_missing_payload_is_unverifiable_all_dimensions():
    ev = evaluate_eligibility(boundary=BOUNDARY, evidence_payload=None, gate=_proven_gate())
    assert ev.outcome == EligibilityOutcome.unverifiable.value


def test_target_identity_failure_is_ineligible():
    gate = EligibilityGateFacts(
        target_identity_verified=False,
        config_drift=False,
        boundary_drift=False,
        authorization_expired=False,
        credential_read_capability_proven=True,
    )
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=gate
    )
    assert ev.outcome == EligibilityOutcome.ineligible.value
    assert (
        _status_map(ev)[EligibilityDimension.target_identity.value] == EvidenceStatus.failed.value
    )


def test_preflight_checks_are_redaction_safe():
    from secp_api.onboarding import detail_is_secret_bearing

    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=_proven_gate()
    )
    checks = ev.as_preflight_checks()
    assert len(checks) == len(EligibilityDimension)
    for c in checks:
        assert not detail_is_secret_bearing(c["detail"])
        assert c["check"] in {d.value for d in EligibilityDimension}


# --- §8 validity helper -------------------------------------------------------------------------


def _valid_view(**overrides) -> LiveEligibilityEvidenceView:
    base = dict(
        evidence_source=LIVE_READONLY_EVIDENCE_SOURCE,
        verification_level=VerificationLevel.live_verified.value,
        outcome=EligibilityOutcome.eligible.value,
        policy_version=ELIGIBILITY_POLICY_VERSION,
        findings_pass=True,
        evidence_hash_matches=True,
        expired=False,
        drifted=False,
    )
    base.update(overrides)
    return LiveEligibilityEvidenceView(**base)


def test_valid_live_eligibility_evidence_is_valid():
    assert live_eligibility_evidence_is_valid(_valid_view()) is True


def test_simulated_evidence_never_valid_for_live_eligibility():
    assert (
        live_eligibility_evidence_is_valid(
            _valid_view(
                evidence_source="simulated_target_evidence",
                verification_level=VerificationLevel.simulated.value,
            )
        )
        is False
    )


def test_non_eligible_outcome_is_invalid():
    for bad in (
        EligibilityOutcome.ineligible.value,
        EligibilityOutcome.unverifiable.value,
        EligibilityOutcome.expired.value,
        EligibilityOutcome.drifted.value,
        EligibilityOutcome.refused.value,
    ):
        assert live_eligibility_evidence_is_valid(_valid_view(outcome=bad)) is False


def test_expiry_drift_hash_findings_invalidate():
    assert live_eligibility_evidence_is_valid(_valid_view(expired=True)) is False
    assert live_eligibility_evidence_is_valid(_valid_view(drifted=True)) is False
    assert live_eligibility_evidence_is_valid(_valid_view(evidence_hash_matches=False)) is False
    assert live_eligibility_evidence_is_valid(_valid_view(findings_pass=False)) is False
    assert live_eligibility_evidence_is_valid(_valid_view(policy_version="other")) is False
