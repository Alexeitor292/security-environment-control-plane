"""The operator prerequisite ladder, queue-separation report, and provenance command (WS-E).

These prove the three things a supported operator surface must be able to say, WITHOUT ever
approaching activation: which prerequisite blocks next and what class of change would close it,
whether the two task queues are separated, and which implementation aggregate is installed.

``PREREQUISITE_LADDER`` and ``_resolve_status`` are independent derivations of the same reported
status, and two tests keep them from diverging.
:func:`test_ladder_first_blocking_rung_agrees_with_status` breaks exactly ONE prerequisite at a
time through ``build_verification``, which pins that builder's wiring but cannot see a reorder —
relative order only matters when two checks are unmet at once.
:func:`test_ladder_order_matches_resolve_status_under_cumulative_faults` breaks a rung and every
rung below it at the pure layer, which is what pins the ORDER. Both are needed; neither subsumes
the other.

That the second one pins the order is itself proved rather than asserted:
:func:`test_every_reordering_of_resolve_status_is_detected` re-derives, on every run, that only the
identity ordering of the nine guards reproduces the pinned status vector. It runs against a
transcribed model, so the model is bound to the real function twice — agreement over all 1024 flag
combinations, and a guard count taken from the AST — because an unbound model would prove a
property of the transcription rather than of the code.

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
    _resolve_status,
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


# --------------------------------------------------------------------------- ladder ORDER

_LADDER_FLAGS = (
    "seals_correct",
    "profile_present",
    "profile_schema_valid",
    "expected_provided",
    "identity_agrees",
    "installed_trust_ok",
    "host_attempted",
    "host_coherent",
    "host_prepared",
    "host_ordinary",
)

#: flag -> (rung id, status ``_resolve_status`` must return when it is the first unmet rung)
_CUMULATIVE = {
    "seals_correct": ("seals_correct", "seals_unsafe"),
    "profile_present": ("profile_installed", "sealed_but_unprovisioned"),
    "profile_schema_valid": ("profile_schema_valid", "profile_invalid"),
    "expected_provided": ("expected_identities_installed", "sealed_but_unprovisioned"),
    "identity_agrees": ("identity_agreement", "identity_mismatch"),
    "installed_trust_ok": ("installed_package_trusted", "install_untrusted"),
    "host_attempted": ("host_observed", "sealed_but_unprovisioned"),
    "host_coherent": ("host_observation_coherent", "host_unavailable"),
    "host_prepared": ("operator_prepared_and_disabled", "host_not_ready"),
    "host_ordinary": ("ordinary_worker_running", "host_not_ready"),
}


def _sections_from_flags(f: dict) -> dict:
    """The section dicts ``build_prerequisite_ladder`` and ``_resolve_status`` consume, built from
    a flat flag map. NOTE both host-observation sub-flags are tied to one flag, ``host_coherent``:
    ``_resolve_status`` only ever reads them as a conjunction."""
    return {
        "seals": {"seals_correct": f["seals_correct"]},
        "profile": {
            "present": f["profile_present"],
            "schema_valid": f["profile_schema_valid"],
            "reason_code": None,
        },
        "identity": {
            "expected_provided": f["expected_provided"],
            "agrees": f["identity_agrees"],
            "reason_code": None,
        },
        "installed_trust_ok": f["installed_trust_ok"],
        "host": {
            "attempted": f["host_attempted"],
            "inspected": f["host_coherent"],
            "coherent": f["host_coherent"],
            "operator_prepared_and_disabled": f["host_prepared"],
            "ordinary_running_and_healthy": f["host_ordinary"],
        },
    }


def _cumulative_sections(index: int) -> dict:
    """Sections in which every flag BEFORE ``index`` is satisfied, and the flag at ``index`` and
    every flag after it is unmet."""
    return _sections_from_flags({name: (i < index) for i, name in enumerate(_LADDER_FLAGS)})


def _resolve_kwargs(s: dict) -> dict:
    """The exact keyword arguments ``_resolve_status`` takes, from a section dict."""
    return {
        "seals": s["seals"],
        "installed_trust_ok": s["installed_trust_ok"],
        "profile_present": s["profile"]["present"],
        "profile_schema_valid": s["profile"]["schema_valid"],
        "expected_provided": s["identity"]["expected_provided"],
        "identity_agrees": s["identity"]["agrees"],
        "host": s["host"],
    }


@pytest.mark.parametrize("index", range(len(_LADDER_FLAGS)))
def test_ladder_order_matches_resolve_status_under_cumulative_faults(index):
    """The single-fault matrix above cannot see an ordering change: relative order only matters
    when two checks are unmet at once. Here rung ``index`` and everything below it are unmet, so
    the first-unmet rung is unambiguous and its status pins the order. Every one of the
    9! = 362,880 orderings of ``_resolve_status``'s nine GUARDS is detected by this matrix — nine
    guards over ten flags, because the host-observation and host-readiness guards are each a
    conjunction of two. That result is not a comment: it is re-derived on every run by
    :func:`test_every_reordering_of_resolve_status_is_detected`, so it cannot lapse silently if a
    tenth guard is added or a status string is reused.

    Driven at the PURE layer rather than through ``build_verification``, which cannot reach rung 1
    at all: ``_read_seals()`` reads the real constants, so ``seals_correct`` cannot be driven false
    from there.
    """
    s = _cumulative_sections(index)
    rung_id, expected_status = _CUMULATIVE[_LADDER_FLAGS[index]]

    ladder = build_prerequisite_ladder(
        seals=s["seals"],
        profile=s["profile"],
        identity=s["identity"],
        installed_trust_ok=s["installed_trust_ok"],
        installed_trust_reason=None,
        host=s["host"],
        runtime_provisioned=False,
        runtime_reason=None,
        compositions_supplied=False,
        compositions_verified=False,
        compositions_reason=None,
    )
    status = _resolve_status(**_resolve_kwargs(s))

    assert next_blocking_prerequisite(ladder)["id"] == rung_id
    # The cross-check: the ladder's own declared status for that rung.
    assert _spec(rung_id).status_when_unmet == status
    # A third, INDEPENDENT pin — a coordinated edit must now defeat three places, not two.
    assert status == expected_status


# --------------------------------------------------------------------------- the ordering proof,
# re-derived on every run rather than asserted in prose

#: ``_resolve_status`` transcribed as (name, satisfied-predicate, status when NOT satisfied). This
#: is a MODEL, so it is bound to the real function two ways below — by agreement over every flag
#: combination, and by guard count. Without those binds the permutation result would be a property
#: of this transcription rather than of the code.
_GUARDS = (
    ("seals_correct", lambda k: k["seals"]["seals_correct"], "seals_unsafe"),
    ("profile_present", lambda k: k["profile_present"], "sealed_but_unprovisioned"),
    ("profile_schema_valid", lambda k: k["profile_schema_valid"], "profile_invalid"),
    ("expected_provided", lambda k: k["expected_provided"], "sealed_but_unprovisioned"),
    ("identity_agrees", lambda k: k["identity_agrees"], "identity_mismatch"),
    ("installed_trust_ok", lambda k: k["installed_trust_ok"], "install_untrusted"),
    ("host_attempted", lambda k: k["host"]["attempted"], "sealed_but_unprovisioned"),
    (
        "host_observation",
        lambda k: k["host"]["inspected"] and k["host"]["coherent"],
        "host_unavailable",
    ),
    (
        "host_readiness",
        lambda k: (
            k["host"]["operator_prepared_and_disabled"]
            and k["host"]["ordinary_running_and_healthy"]
        ),
        "host_not_ready",
    ),
)


def _model_resolve(order, kwargs: dict) -> str:
    for _name, satisfied, status in order:
        if not satisfied(kwargs):
            return status
    return "sealed_prepared"


def test_the_model_agrees_with_the_real_resolve_status_on_every_flag_combination():
    """First bind: over all 2**10 = 1024 flag combinations, not just the cumulative ten.

    If ``_resolve_status`` gains a guard, drops one, or changes a returned status, the model stops
    agreeing here — so the permutation proof below can never be measuring a stale transcription.
    """
    for bits in range(2 ** len(_LADDER_FLAGS)):
        flags = {name: bool(bits >> i & 1) for i, name in enumerate(_LADDER_FLAGS)}
        kwargs = _resolve_kwargs(_sections_from_flags(flags))
        assert _model_resolve(_GUARDS, kwargs) == _resolve_status(**kwargs), flags


def test_the_model_has_exactly_one_guard_per_branch_in_resolve_status():
    """Second bind: a tenth guard must not slip past the permutation proof unnoticed."""
    import ast
    import inspect

    from secp_operator_deployment import verify

    fn = ast.parse(inspect.getsource(verify._resolve_status)).body[0]
    branches = [node for node in fn.body if isinstance(node, ast.If)]
    assert len(branches) == len(_GUARDS) == 9


def test_every_reordering_of_resolve_status_is_detected():
    """The measured claim, re-derived: of the 9! orderings of the nine guards, ONLY the identity
    reproduces the status vector the cumulative matrix pins. Every other ordering changes at least
    one of the ten reported statuses and is therefore caught."""
    from itertools import permutations

    states = [_resolve_kwargs(_cumulative_sections(i)) for i in range(len(_LADDER_FLAGS))]
    canonical = [_model_resolve(_GUARDS, s) for s in states]

    # The vector is the one the parametrised matrix above already pins, independently.
    assert canonical == [_CUMULATIVE[flag][1] for flag in _LADDER_FLAGS]

    undetected = [
        tuple(g[0] for g in perm)
        for perm in permutations(_GUARDS)
        if [_model_resolve(perm, s) for s in states] == canonical
    ]
    assert undetected == [tuple(g[0] for g in _GUARDS)], (
        f"{len(undetected) - 1} non-identity ordering(s) reproduce the pinned status vector; "
        "the cumulative matrix no longer pins the order"
    )


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
