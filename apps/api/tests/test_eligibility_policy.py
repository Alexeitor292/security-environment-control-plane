"""Pure eligibility-policy unit tests (SECP-002B-1B, B1B-PR3).

Deterministic, provider-neutral, no I/O. Exercises every mandatory dimension, the closed outcome
precedence, fail-closed on unobservable facts, and the §8 validity helper. These tests never
construct a transport, never contact anything, and never persist.
"""

from __future__ import annotations

import copy

from secp_api.eligibility_policy import (
    ELIGIBILITY_POLICY_VERSION,
    EligibilityEvaluation,
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


# --- B1B-PR5A §6: per-dimension evidence source (A/B/C) + live VM-ID collision -------------------


def _source_map(ev) -> dict:
    return {d.dimension: d.source for d in ev.dimensions}


def test_each_passed_dimension_carries_an_allowed_evidence_source():
    from secp_api.enums import EligibilityEvidenceSource

    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.eligible.value
    sources = _source_map(ev)
    allowed = {
        EligibilityEvidenceSource.observed_live.value,
        EligibilityEvidenceSource.approved_deployment_control.value,
    }
    # Every mandatory dimension is proven by an allowed source; none is 'unsupported'.
    assert all(s in allowed for s in sources.values())
    # Observed-live dimensions are proven on the wire; deployment-control from approved facts/obs.
    assert sources[EligibilityDimension.node_boundary.value] == (
        EligibilityEvidenceSource.observed_live.value
    )
    assert sources[EligibilityDimension.credential_read_capability.value] == (
        EligibilityEvidenceSource.observed_live.value
    )
    assert sources[EligibilityDimension.vmid_range.value] == (
        EligibilityEvidenceSource.approved_deployment_control.value
    )


def test_an_unverifiable_dimension_is_classified_unsupported():
    from secp_api.enums import EligibilityEvidenceSource

    observed = _good_observed()
    observed.pop("disposability")  # storage_boundary becomes unverifiable
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert _source_map(ev)[EligibilityDimension.storage_boundary.value] == (
        EligibilityEvidenceSource.unsupported.value
    )


def test_a_live_used_vmid_inside_the_declared_range_overrides_an_asserted_no_collision():
    """A live Path B observation of a colliding VM-ID makes the dimension FAIL even when the
    dedicated ``collision`` boolean asserts no collision — the live fact wins (§6)."""
    observed = _good_observed()
    # Assert no collision, but observe a live VM-ID (9050) INSIDE the declared range [9000, 9100].
    observed["vmid_range"]["collision"] = False
    observed["vmid_range"]["used_vmids"] = [105, 9050, 12000]
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.ineligible.value
    assert _status_map(ev)[EligibilityDimension.vmid_range.value] == EvidenceStatus.failed.value


def test_a_live_used_vmid_list_clear_of_the_range_passes_vmid():
    observed = _good_observed()
    observed["vmid_range"].pop("collision", None)  # no asserted bool; rely on the live observation
    observed["vmid_range"]["used_vmids"] = [105, 200, 12000]  # all outside [9000, 9100]
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.eligible.value
    assert _status_map(ev)[EligibilityDimension.vmid_range.value] == EvidenceStatus.passed.value


def test_every_mandatory_dimension_is_present_in_the_result():
    from secp_api.eligibility_policy import MANDATORY_ELIGIBILITY_DIMENSIONS

    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=_proven_gate()
    )
    present = {d.dimension for d in ev.dimensions}
    assert present == {d.value for d in MANDATORY_ELIGIBILITY_DIMENSIONS}


# --- B1B-PR5A amendment §2: evidence-source conflict precedence ----------------------------------


def test_a_live_vmid_collision_failure_is_observed_live_sourced_and_dominates():
    from secp_api.enums import EligibilityEvidenceSource

    observed = _good_observed()
    observed["vmid_range"]["collision"] = False  # an asserted "no collision" a dossier might trust
    observed["vmid_range"]["used_vmids"] = [9050]  # a LIVE collision inside [9000, 9100]
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    # A live-observed failure dominates: no approved control proof can rescue it.
    assert ev.outcome == EligibilityOutcome.ineligible.value
    vmid = next(d for d in ev.dimensions if d.dimension == EligibilityDimension.vmid_range.value)
    assert vmid.status == EvidenceStatus.failed.value
    assert vmid.source == EligibilityEvidenceSource.observed_live.value


def test_a_live_missing_network_segment_is_an_observed_live_failure():
    from secp_api.enums import EligibilityEvidenceSource

    observed = _good_observed()
    # The live observation was made, but the declared segment/CIDR is absent → a live FAILURE.
    observed["network_segments"] = ["someone-elses-seg"]
    observed["cidr_reservations"] = ["10.99.0.0/24"]
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.ineligible.value
    net = next(
        d for d in ev.dimensions if d.dimension == EligibilityDimension.network_segments.value
    )
    assert net.status == EvidenceStatus.failed.value
    assert net.source == EligibilityEvidenceSource.observed_live.value


def test_a_live_route_violation_dominates_a_valid_no_default_route_control_proof():
    from secp_api.enums import EligibilityEvidenceSource

    observed = _good_observed()
    # A valid approved control proof (no_default_route True) is present, but the LIVE isolation
    # comparison shows a route to a protected network → an observed_live failure that dominates.
    observed["isolation"]["route_to_protected"] = True
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(observed), gate=_proven_gate()
    )
    assert ev.outcome == EligibilityOutcome.ineligible.value
    route = next(
        d for d in ev.dimensions if d.dimension == EligibilityDimension.route_isolation.value
    )
    assert route.status == EvidenceStatus.failed.value
    assert route.source == EligibilityEvidenceSource.observed_live.value


def test_a_supplementable_dimension_passes_via_approved_deployment_control():
    from secp_api.enums import EligibilityEvidenceSource

    # Storage disposability is a supplementable (deployment-control) observation. With the live
    # storage id observed AND the approved disposability proof True, the dimension passes by ctrl.
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=_proven_gate()
    )
    storage = next(
        d for d in ev.dimensions if d.dimension == EligibilityDimension.storage_boundary.value
    )
    assert storage.status == EvidenceStatus.passed.value
    assert storage.source == EligibilityEvidenceSource.approved_deployment_control.value


def test_the_source_policy_forbids_control_proof_for_observed_live_only_dimensions():
    from secp_api.eligibility_policy import dimension_allows_deployment_control

    # Observed-live REQUIRED — a dossier/control proof can never supplement these.
    for dim in (
        EligibilityDimension.node_boundary,
        EligibilityDimension.network_segments,
        EligibilityDimension.credential_read_capability,
    ):
        assert dimension_allows_deployment_control(dim.value) is False
    # Supplementable dimensions permit an approved control proof.
    for dim in (
        EligibilityDimension.storage_boundary,
        EligibilityDimension.route_isolation,
        EligibilityDimension.vmid_range,
        EligibilityDimension.quotas,
    ):
        assert dimension_allows_deployment_control(dim.value) is True
    # An unknown dimension is never supplementable (fail closed).
    assert dimension_allows_deployment_control("not_a_dimension") is False


def test_the_evaluator_takes_no_caller_source_and_computes_it_deterministically():
    import inspect

    from secp_api.eligibility_policy import evaluate_eligibility as _eval

    # The caller cannot choose a dimension's source: the signature has no source parameter.
    params = set(inspect.signature(_eval).parameters)
    assert params == {"boundary", "evidence_payload", "gate"}


def test_the_dimension_source_result_hash_changes_when_a_source_changes():
    # Two evaluations with the SAME failing result but a DIFFERENT source (live vs dedicated) must
    # produce a different canonical source/result hash — source is bound into the hash (§2).
    live = _good_observed()
    live["vmid_range"]["used_vmids"] = [9050]  # live collision → observed_live FAIL
    ded = _good_observed()
    ded["vmid_range"]["collision"] = True  # asserted collision → approved-deployment-control FAIL
    ev_live = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(live), gate=_proven_gate()
    )
    ev_ded = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(ded), gate=_proven_gate()
    )
    # Same failing status, different source → different hash.
    live_vmid = next(d for d in ev_live.dimensions if d.dimension == "vmid_range")
    ded_vmid = next(d for d in ev_ded.dimensions if d.dimension == "vmid_range")
    assert live_vmid.status == ded_vmid.status == EvidenceStatus.failed.value
    assert live_vmid.source != ded_vmid.source
    assert ev_live.dimension_source_result_hash() != ev_ded.dimension_source_result_hash()


def test_the_dimension_source_result_hash_changes_when_a_dimension_is_omitted():
    ev = evaluate_eligibility(
        boundary=BOUNDARY, evidence_payload=_live_payload(_good_observed()), gate=_proven_gate()
    )
    full = ev.dimension_source_result_hash()
    # Omitting any dimension's (result, source) triple changes the canonical hash.
    trimmed = EligibilityEvaluation(
        outcome=ev.outcome,
        policy_version=ev.policy_version,
        dimensions=ev.dimensions[:-1],
        evidence_payload=ev.evidence_payload,
        findings=ev.findings,
    )
    assert trimmed.dimension_source_result_hash() != full


def test_the_durable_evidence_package_hash_binds_the_per_dimension_source():
    # Amendment §2: the per-dimension source is folded into the DURABLE evidence-package hash, so
    # tampering with a source (same result) changes the persisted hash. Backward-compatible: a
    # caller that omits source is unaffected.
    from secp_api.onboarding import build_evidence_package, evidence_package_hash

    base = dict(
        onboarding_id="o",
        boundary_hash="b",
        target_config_hash="t",
        scope_policy_hash="s",
        toolchain_profile_id=None,
        toolchain_profile_hash=None,
        verification_level="live_verified",
        collector_kind="provider_worker",
        collector_identity="ci",
        evidence_version=1,
    )
    obs = [{"check": "node_boundary", "status": "passed", "detail": "d", "source": "observed_live"}]
    ctl = [
        {
            "check": "node_boundary",
            "status": "passed",
            "detail": "d",
            "source": "approved_deployment_control",
        }
    ]
    none = [{"check": "node_boundary", "status": "passed", "detail": "d"}]
    h_obs = evidence_package_hash(build_evidence_package(checks=obs, **base))
    h_ctl = evidence_package_hash(build_evidence_package(checks=ctl, **base))
    h_none = evidence_package_hash(build_evidence_package(checks=none, **base))
    assert h_obs != h_ctl  # same result, different SOURCE → different durable hash
    assert h_none != h_obs  # legacy (source-less) checks hash differently and stay stable
