"""Hermetic contract tests for the two-host acceptance evidence document.

These create no host, start no container, and contact nothing. They pin the properties a reader of
an acceptance evidence document is entitled to rely on:

* the closed vocabularies are actually closed, and a check is only valid under its own stage;
* a positive observation and a refusal are structurally distinguishable, and neither can be forged
  into the other;
* the verdict is DERIVED from what was recorded — there is no way to assert ``passed``;
* the document is nonsecret by construction (the forbidden-secret scan runs on load);
* the digest is stable across wall-clock time but changes with any recorded observation.
"""

from __future__ import annotations

import pytest
from secp_acceptance import ACCEPTANCE_CONTRACT_VERSION, AcceptanceError
from secp_acceptance.evidence import (
    ACCEPTANCE_EVIDENCE_SCHEMA,
    FleetRecord,
    ReleaseRecord,
    canonical_bytes,
    evidence_from_bytes,
    evidence_from_dict,
)
from secp_acceptance.reasons import (
    CHECKS,
    CHECKS_BY_STAGE,
    HARNESS_REASONS,
    PRODUCT_REASONS,
    RUN_FAILED,
    RUN_PASSED,
    STAGE_FLEET,
    STAGE_QUEUES,
    STAGES,
)
from secp_acceptance.recorder import AcceptanceRecorder

_FLEET = FleetRecord(
    host_image_identity="sha256:" + "1" * 64,
    controller_host_identity="sha256:" + "2" * 64,
    worker_host_identity="sha256:" + "3" * 64,
    network_identity="sha256:" + "4" * 64,
    hosts_created=2,
    hosts_destroyed=2,
    nested_container_runtime=True,
    real_service_manager=True,
)
_RELEASE = ReleaseRecord(
    role="worker",
    baseline_aggregate="sha256:" + "5" * 64,
    successor_aggregate="sha256:" + "6" * 64,
    baseline_source_sha="a" * 40,
    successor_source_sha="b" * 40,
    successor_parent_sha="a" * 40,
    signing_anchor_id="secp-acceptance-ephemeral-anchor/v1",
    test_only_anchor=True,
)


def _cover(rec: AcceptanceRecorder, stage: str) -> None:
    """Record every check the stage declares as observed."""
    rec.open_stage(stage)
    for check in CHECKS_BY_STAGE[stage]:
        rec.observe(check, stage, {"check": check})


# --------------------------------------------------------------------------- vocabularies


def test_every_check_belongs_to_exactly_one_stage():
    seen: dict[str, str] = {}
    for stage, checks in CHECKS_BY_STAGE.items():
        for check in checks:
            assert check not in seen, f"{check} declared by both {seen.get(check)} and {stage}"
            seen[check] = stage
    assert set(seen) == set(CHECKS)


def test_every_declared_stage_is_a_known_stage():
    assert set(CHECKS_BY_STAGE) == set(STAGES)


def test_reason_vocabularies_are_disjoint():
    assert not (HARNESS_REASONS & PRODUCT_REASONS)


def test_no_stage_declares_zero_checks():
    for stage, checks in CHECKS_BY_STAGE.items():
        assert checks, f"stage {stage} declares no checks, so opening it would prove nothing"


# --------------------------------------------------------------------------- recorder semantics


def test_a_check_cannot_be_recorded_under_a_foreign_stage():
    rec = AcceptanceRecorder()
    rec.open_stage(STAGE_FLEET)
    # a real queue check, filed under the fleet stage
    with pytest.raises(AcceptanceError) as exc:
        rec.observe("operator_queue_has_zero_pollers", STAGE_FLEET, {})
    assert exc.value.reason_code == "acceptance_evidence_unknown_check"


def test_a_check_cannot_be_recorded_before_its_stage_is_opened():
    rec = AcceptanceRecorder()
    with pytest.raises(AcceptanceError) as exc:
        rec.observe("hosts_are_distinct", STAGE_FLEET, {})
    assert exc.value.reason_code == "acceptance_evidence_unknown_stage"


def test_a_check_cannot_be_recorded_twice():
    rec = AcceptanceRecorder()
    rec.open_stage(STAGE_FLEET)
    rec.observe("hosts_are_distinct", STAGE_FLEET, {})
    with pytest.raises(AcceptanceError) as exc:
        rec.observe("hosts_are_distinct", STAGE_FLEET, {})
    assert exc.value.reason_code == "acceptance_evidence_duplicate_check"


def test_an_absent_refusal_is_unproven_not_a_pass():
    rec = AcceptanceRecorder()
    rec.open_stage("failure_injection")
    ok = rec.expect_refusal(
        "wrong_role_bundle_refused",
        "failure_injection",
        expected="release_role_mismatch",
        actual=None,
        observation={},
    )
    assert ok is False
    record = rec._checks[0]
    assert record.outcome == "unproven"
    assert record.reason_code == "acceptance_expected_refusal_absent"


def test_a_refusal_with_the_wrong_code_is_unproven_not_a_pass():
    rec = AcceptanceRecorder()
    rec.open_stage("failure_injection")
    ok = rec.expect_refusal(
        "wrong_role_bundle_refused",
        "failure_injection",
        expected="release_role_mismatch",
        actual="release_artifact_digest_mismatch",
        observation={},
    )
    assert ok is False
    assert rec._checks[0].reason_code == "acceptance_unexpected_reason_code"


def test_a_refusal_with_the_expected_code_is_recorded_as_refused():
    rec = AcceptanceRecorder()
    rec.open_stage("failure_injection")
    ok = rec.expect_refusal(
        "wrong_role_bundle_refused",
        "failure_injection",
        expected="release_role_mismatch",
        actual="release_role_mismatch",
        observation={},
    )
    assert ok is True
    assert rec._checks[0].outcome == "refused"
    assert rec._checks[0].reason_code == "release_role_mismatch"


# --------------------------------------------------------------------------- the verdict


def test_a_fully_covered_run_passes():
    rec = AcceptanceRecorder()
    for stage in STAGES:
        _cover(rec, stage)
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.outcome == RUN_PASSED
    assert ev.coverage_complete()
    assert ev.unproven() == ()


def test_an_incompletely_covered_stage_fails_the_run():
    rec = AcceptanceRecorder()
    rec.open_stage(STAGE_QUEUES)
    rec.observe("ordinary_queue_has_live_poller", STAGE_QUEUES, {})
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.outcome == RUN_FAILED
    assert "operator_queue_has_zero_pollers" in ev.missing_checks()


def test_one_unproven_check_fails_the_whole_run():
    rec = AcceptanceRecorder()
    rec.open_stage(STAGE_QUEUES)
    for check in CHECKS_BY_STAGE[STAGE_QUEUES]:
        if check == "operator_queue_has_zero_pollers":
            rec.unproven(
                check,
                STAGE_QUEUES,
                reason_code="acceptance_observation_unavailable",
                observation={},
            )
        else:
            rec.observe(check, STAGE_QUEUES, {})
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.outcome == RUN_FAILED
    assert ev.unproven() == ("operator_queue_has_zero_pollers",)


def test_a_passed_document_cannot_be_hand_written_with_missing_checks():
    """The loader is the authority, not the recorder — a hand-built ``passed`` document that omits
    a declared check is refused on load."""
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_QUEUES)
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    payload = ev.canonical()
    payload["checks"] = payload["checks"][:-1]
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_incomplete"


# --------------------------------------------------------------------------- document properties


def test_the_document_round_trips_through_canonical_bytes():
    rec = AcceptanceRecorder()
    for stage in STAGES:
        _cover(rec, stage)
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert evidence_from_bytes(canonical_bytes(ev)).digest() == ev.digest()


def test_the_digest_ignores_wall_clock_but_tracks_observations():
    rec_a = AcceptanceRecorder(started_at="2026-01-01T00:00:00+00:00")
    rec_b = AcceptanceRecorder(started_at="2027-06-30T12:00:00+00:00")
    for rec in (rec_a, rec_b):
        _cover(rec, STAGE_FLEET)
    a = rec_a.seal(fleet=_FLEET, release=_RELEASE)
    b = rec_b.seal(fleet=_FLEET, release=_RELEASE)
    assert a.digest() == b.digest(), "two identical runs must be comparable across days"

    rec_c = AcceptanceRecorder()
    rec_c.open_stage(STAGE_FLEET)
    for check in CHECKS_BY_STAGE[STAGE_FLEET]:
        # one observation differs -> a different content address
        rec_c.observe(check, STAGE_FLEET, {"check": check, "extra": "changed"})
    assert rec_c.seal(fleet=_FLEET, release=_RELEASE).digest() != a.digest()


def test_the_four_prohibitions_are_recorded_and_only_one_value_is_admissible():
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_FLEET)
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    for flag in ("proxmox_contacted", "opentofu_executed", "trust_roots_modified"):
        assert getattr(ev, flag) is False
        payload = ev.canonical()
        payload[flag] = True
        with pytest.raises(AcceptanceError) as exc:
            evidence_from_dict(payload)
        assert exc.value.reason_code == "acceptance_evidence_forbidden_value"
    # the one stated positively: flipping it FALSE must refuse just as hard
    assert ev.ephemeral_material_only is True
    payload = ev.canonical()
    payload["ephemeral_material_only"] = False
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_forbidden_value"


def test_no_evidence_field_name_can_trip_the_forbidden_secret_scan():
    """The document must survive its own loader.

    A field named ``*credential*``/``*token*``/``*secret*`` would make every run refuse on load —
    and would only be discovered at the end of a 20-minute acceptance run. Assert the whole shape,
    including the nested records, against the same scan the loader applies.
    """
    from secp_commissioning.descriptor import scan_forbidden

    rec = AcceptanceRecorder()
    for stage in STAGES:
        _cover(rec, stage)
    rec.declare_gap(
        gap="example_gap",
        stage=STAGE_FLEET,
        substitute="a stand-in",
        why="a reason",
        weakens=("hosts_are_distinct",),
    )
    scan_forbidden(rec.seal(fleet=_FLEET, release=_RELEASE).canonical())


def test_a_secret_shaped_field_refuses_on_load():
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_FLEET)
    payload = rec.seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["operator_token"] = "abc"
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_forbidden_value"


def test_an_unknown_reason_code_refuses_on_load():
    rec = AcceptanceRecorder()
    rec.open_stage(STAGE_FLEET)
    for check in CHECKS_BY_STAGE[STAGE_FLEET]:
        rec.observe(check, STAGE_FLEET, {})
    payload = rec.seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["outcome"] = RUN_FAILED
    payload["checks"][0]["outcome"] = "refused"
    payload["checks"][0]["reason_code"] = "some_reason_nobody_reviewed"
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_unknown_reason"


def test_an_observed_check_may_not_carry_a_reason_code():
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_FLEET)
    payload = rec.seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["checks"][0]["reason_code"] = "acceptance_observation_unavailable"
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_invalid"


def test_a_duplicate_check_refuses_on_load():
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_FLEET)
    payload = rec.seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["outcome"] = RUN_FAILED
    payload["checks"].append(dict(payload["checks"][0]))
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_duplicate_check"


def test_a_gap_must_name_the_checks_it_weakens():
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_QUEUES)
    with pytest.raises(AcceptanceError):
        rec.declare_gap(gap="empty_gap", stage=STAGE_QUEUES, substitute="x", why="y", weakens=())


def test_a_gap_naming_an_unknown_check_refuses():
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_QUEUES)
    with pytest.raises(AcceptanceError) as exc:
        rec.declare_gap(
            gap="bad_gap",
            stage=STAGE_QUEUES,
            substitute="x",
            why="y",
            weakens=("no_such_check",),
        )
    assert exc.value.reason_code == "acceptance_evidence_unknown_check"


def test_schema_and_contract_versions_are_bound_into_the_document():
    rec = AcceptanceRecorder()
    _cover(rec, STAGE_FLEET)
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.schema_version == ACCEPTANCE_EVIDENCE_SCHEMA
    assert ev.harness_contract_version == ACCEPTANCE_CONTRACT_VERSION
    payload = ev.canonical()
    payload["schema_version"] = "secp.acceptance.two-host-evidence/v2"
    with pytest.raises(AcceptanceError):
        evidence_from_dict(payload)
