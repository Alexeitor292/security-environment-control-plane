"""The operator prerequisite ladder, queue-separation report, and provenance command (WS-E).

These prove the three things a supported operator surface must be able to say, WITHOUT ever
approaching activation: which prerequisite blocks next and what class of change would close it,
whether the two task queues are separated, and which implementation aggregate is installed.

The load-bearing test here is :func:`test_ladder_first_blocking_rung_agrees_with_status` — the
ladder and ``_resolve_status`` derive the reported status independently, and this asserts they
agree across every failure mode. If someone reorders one without the other, it fails.

Nothing in this module builds a composition aggregate, constructs a ``Worker``, calls
``run_plan_generation``, resolves a credential, or contacts any infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from _deploy_support import host_evidence, valid_expected, valid_profile
from secp_operator_deployment.cli import VerifyDeps, run
from secp_operator_deployment.verify import (
    PREREQUISITE_LADDER,
    PROVENANCE_EXIT_CODES,
    REMEDIATION_OPERATOR,
    REMEDIATION_REVIEWED_CODE,
    REMEDIATION_REVIEWED_DEPLOYMENT,
    STATUS_EXIT_CODES,
    _queue_section,
    build_prerequisite_ladder,
    build_provenance_report,
    build_verification,
    next_blocking_prerequisite,
)


def _prepared(**over):
    d = dict(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=True,
        host_observation=host_evidence(),
    )
    d.update(over)
    return build_verification(**d)


def _spec(spec_id: str):
    return next(p for p in PREREQUISITE_LADDER if p.id == spec_id)


# --------------------------------------------------------------------------- ladder shape


def test_ladder_specs_are_well_formed():
    ids = [p.id for p in PREREQUISITE_LADDER]
    assert len(ids) == len(set(ids)), "prerequisite ids must be unique"
    for p in PREREQUISITE_LADDER:
        assert p.dimension in {"A", "B", "C", "D", "E", "F"}
        assert p.remediation in {
            REMEDIATION_REVIEWED_CODE,
            REMEDIATION_REVIEWED_DEPLOYMENT,
            REMEDIATION_OPERATOR,
        }
        # A blocking rung must name the EXACT status it produces; a non-blocking rung must not.
        if p.blocking:
            assert p.status_when_unmet in STATUS_EXIT_CODES
        else:
            assert p.status_when_unmet is None


def test_dimensions_d_and_e_never_block():
    """Runtime provisioning and composition readiness are reported but never gate prepared."""
    for p in PREREQUISITE_LADDER:
        if p.dimension in {"D", "E"}:
            assert p.blocking is False


def test_prepared_host_has_no_blocking_prerequisite():
    report = _prepared()
    assert report["status"] == "sealed_prepared"
    pre = report["prerequisites"]
    assert pre["next_blocking"] is None
    assert pre["blocking_unmet_count"] == 0
    # D and E remain honestly unmet on a prepared-but-unprovisioned host.
    assert pre["unmet_count"] == 2
    unmet = {r["id"] for r in pre["ladder"] if not r["satisfied"]}
    assert unmet == {"runtime_provisioned", "compositions_verified"}


def test_ladder_reports_every_rung_not_just_the_first_gap():
    """An operator sees the whole remaining path, not one gap at a time."""
    report = _prepared(profile=None, expected=None, installed_trust_ok=False)
    ladder = report["prerequisites"]["ladder"]
    assert len(ladder) == len(PREREQUISITE_LADDER)
    assert [r["id"] for r in ladder] == [p.id for p in PREREQUISITE_LADDER]
    assert report["prerequisites"]["blocking_unmet_count"] >= 3


# --------------------------------------------------------------------------- the core invariant


@pytest.mark.parametrize(
    ("overrides", "expected_rung"),
    [
        ({"profile": None}, "profile_installed"),
        ({"profile": None, "profile_load_reason": "profile_not_json"}, "profile_schema_valid"),
        ({"expected": None}, "expected_identities_installed"),
        ({"installed_trust_ok": False}, "installed_package_trusted"),
        ({"host_observation": None}, "host_observed"),
        ({"host_observation": host_evidence(coherent=False)}, "host_observation_coherent"),
        ({"host_observation": host_evidence(enabled=True)}, "operator_prepared_and_disabled"),
        ({"host_observation": host_evidence(ordinary=False)}, "ordinary_worker_running"),
    ],
)
def test_ladder_first_blocking_rung_agrees_with_status(overrides, expected_rung):
    """The ladder and ``_resolve_status`` are independent derivations — they must never diverge."""
    report = _prepared(**overrides)
    pre = report["prerequisites"]
    assert pre["next_blocking"] == expected_rung
    assert _spec(expected_rung).status_when_unmet == report["status"]
    assert report["exit_code"] == STATUS_EXIT_CODES[report["status"]]
    assert pre["next_blocking_reason_code"], "a blocking rung must carry a bounded reason code"


def test_identity_mismatch_is_reached_when_profile_and_expected_disagree():
    report = _prepared(expected=valid_expected(release_source_sha="c" * 40))
    assert report["prerequisites"]["next_blocking"] == "identity_agreement"
    assert report["status"] == "identity_mismatch"
    assert _spec("identity_agreement").status_when_unmet == "identity_mismatch"


def test_every_blocking_rung_carries_a_catalogued_reason_when_unmet():
    """All-unmet: every rung's fallback reason code must be in the catalogue."""
    ladder = build_prerequisite_ladder(
        seals={"seals_correct": False},
        profile={"present": False, "schema_valid": False, "reason_code": None},
        identity={"expected_provided": False, "agrees": False, "reason_code": None},
        installed_trust_ok=False,
        installed_trust_reason=None,
        host={"attempted": False, "inspected": False, "coherent": False},
        runtime_provisioned=False,
        runtime_reason=None,
        compositions_supplied=False,
        compositions_verified=False,
        compositions_reason=None,
    )
    assert len(ladder) == len(PREREQUISITE_LADDER)
    for row in ladder:
        assert row["satisfied"] is False
        assert row["reason_code"], f"{row['id']} produced no reason code"
        assert row["reason_catalogued"] is True, f"{row['id']} -> {row['reason_code']}"


def test_next_blocking_prerequisite_skips_non_blocking_rungs():
    ladder = [
        {"id": "d", "blocking": False, "satisfied": False},
        {"id": "b", "blocking": True, "satisfied": False},
    ]
    assert next_blocking_prerequisite(ladder)["id"] == "b"
    assert next_blocking_prerequisite([{"id": "x", "blocking": True, "satisfied": True}]) is None


def test_seal_drift_is_not_operator_closable():
    """The one property that stops an operator hunting for a flag that does not exist."""
    assert _spec("seals_correct").remediation == REMEDIATION_REVIEWED_CODE
    assert _spec("seals_correct").dimension == "F"


# --------------------------------------------------------------------------- queue separation


def test_queue_separation_reports_booleans_and_never_a_queue_name():
    report = _prepared()
    queue = report["queue_separation"]
    assert queue == {
        "ok": True,
        "ordinary_configured": True,
        "operator_configured": True,
        "distinct": True,
        "reason_code": None,
    }
    # The queue NAMES are profile values and must never be emitted.
    import json

    blob = json.dumps(report)
    assert "secp-orchestration" not in blob
    assert "secp-controlled-live-v1" not in blob


def test_queue_separation_unavailable_without_a_parsed_profile():
    queue = _prepared(profile=None)["queue_separation"]
    assert queue["ok"] is False
    assert queue["reason_code"] == "queue_separation_unavailable"


def test_queue_separation_refuses_a_shared_queue():
    """Defence in depth: the profile validator already refuses this at parse time."""

    @dataclass
    class _Shared:
        ordinary_task_queue: str = "same-queue"
        operator_task_queue: str = "same-queue"

    queue = _queue_section(True, _Shared())
    assert queue["ok"] is False
    assert queue["distinct"] is False
    assert queue["reason_code"] == "queue_not_distinct"


# --------------------------------------------------------------------------- provenance


def test_provenance_ok_when_installed_matches_source():
    report = build_provenance_report(
        source_aggregate="sha256:" + "a" * 64,
        installed_aggregate="sha256:" + "a" * 64,
        installed_trust_ok=True,
        covered_module_count=14,
    )
    assert report["status"] == "provenance_ok"
    assert report["exit_code"] == 0
    assert report["agreement"]["source_equals_installed"] is True
    assert report["package_artifact"]["covered_module_count"] == 14


def test_provenance_untrusted_when_the_dir_fd_walk_refused():
    report = build_provenance_report(
        source_aggregate="sha256:" + "a" * 64,
        installed_aggregate=None,
        installed_trust_ok=False,
        installed_trust_reason="manifest_ancestor_not_root_owned",
        covered_module_count=14,
    )
    assert report["status"] == "provenance_untrusted"
    assert report["exit_code"] == PROVENANCE_EXIT_CODES["provenance_untrusted"] == 15
    assert report["installed_aggregate"]["reason_code"] == "manifest_ancestor_not_root_owned"


def test_provenance_untrusted_on_aggregate_disagreement():
    report = build_provenance_report(
        source_aggregate="sha256:" + "a" * 64,
        installed_aggregate="sha256:" + "b" * 64,
        installed_trust_ok=True,
        covered_module_count=14,
    )
    assert report["status"] == "provenance_untrusted"
    assert report["agreement"]["source_equals_installed"] is False
    assert report["agreement"]["reason_code"] == "manifest_installed_aggregate_mismatch"


def test_provenance_unavailable_without_a_source_aggregate():
    report = build_provenance_report(
        source_aggregate=None, source_reason="manifest_inventory_mismatch"
    )
    assert report["status"] == "provenance_unavailable"
    assert report["exit_code"] == 20
    assert report["source_aggregate"]["reason_code"] == "manifest_inventory_mismatch"


def test_provenance_declares_it_had_no_effects():
    report = build_provenance_report(source_aggregate="sha256:" + "a" * 64)
    assert report["effects_of_this_provenance_check"] == {
        "worker_constructed": False,
        "workflow_submitted": False,
        "run_plan_generation_called": False,
        "secret_resolver_constructed": False,
        "external_contact_performed": False,
        "host_mutated": False,
    }


# --------------------------------------------------------------------------- CLI wiring


def test_cli_provenance_returns_the_report_and_matching_exit_code():
    deps = VerifyDeps(
        source_aggregate="sha256:" + "a" * 64,
        installed_aggregate="sha256:" + "a" * 64,
        installed_trust_ok=True,
    )
    code, payload = run(["provenance", "--json"], deps)
    assert payload["phase"] == "provenance"
    assert code == PROVENANCE_EXIT_CODES[payload["status"]] == 0


def test_cli_provenance_exit_code_tracks_an_untrusted_install():
    deps = VerifyDeps(
        source_aggregate="sha256:" + "a" * 64,
        installed_aggregate=None,
        installed_trust_ok=False,
        installed_trust_reason="manifest_trust_non_posix",
    )
    code, payload = run(["provenance"], deps)
    assert payload["status"] == "provenance_untrusted"
    assert code == 15


def test_cli_verify_still_reports_the_ladder():
    deps = VerifyDeps(
        profile=valid_profile(),
        expected=valid_expected(),
        installed_trust_ok=True,
        host_observation=host_evidence(),
    )
    code, payload = run(["verify", "--json"], deps)
    assert code == 0
    assert payload["prerequisites"]["next_blocking"] is None


def test_cli_still_exposes_exactly_two_read_only_commands():
    from secp_operator_deployment.cli import _HANDLERS

    assert set(_HANDLERS) == {"verify", "provenance"}
