"""The controlled-live QUEUE isolation check (WS-E).

The program constraint this command exists to validate — *the controlled-live operator queue must
be disabled and isolated from the ordinary Temporal queue* — is one an operator has to be able to
CHECK, and checking it must never be a way to cause the thing it is checking against. So the
properties pinned here are, in order of what they protect:

* :func:`test_the_queue_command_submits_nothing_and_starts_no_consumer` — the tripwire suite. The
  report's ``effects_of_this_queue_check`` section is a CLAIM; these tests are the observation. The
  operator run hook, the composition builders and the real command runner are each replaced by a
  tripwire that RECORDS and raises if reached, and the assertion is made on the record.
  ``temporalio`` — the only way to submit a workflow or run a worker — rests on two static import
  scans, which are environment-independent and hold for any import shape. The ``main`` exit code
  catches one shape too, a bare ``import temporalio``, but not a guarded one; and an
  imported-module snapshot catches none, since the extra is installed in no environment this suite
  runs in. The reasoning is at the tripwire itself.
* :func:`test_the_guard_order_is_exactly_the_ladder_order_on_every_fact_combination` — the ordering
  proof, exhaustive over all 64 combinations of the six facts rather than sampled. ``QUEUE_LADDER``
  and ``_resolve_queue_status`` are independent derivations of the same order; if either moves, or
  gains or loses a guard, this fails. That makes the order self-enforcing rather than a docstring
  claim, which is the same standard the prerequisite ladder is held to.
* :func:`test_no_queue_name_reaches_the_operators_terminal` — this is the module most tempted to
  print a queue name, and queue names are profile values.
* the stop observations are checked against the reviewed constants THEMSELVES, so a stop that was
  quietly opened cannot be reported closed.

Nothing here constructs a ``Worker``, builds a composition aggregate, calls ``run_plan_generation``,
resolves a credential, or contacts Temporal, Proxmox, OpenBao, remote state or PostgreSQL.
"""

from __future__ import annotations

import itertools
import json

import pytest
from _deploy_support import (
    OPERATOR_QUEUE,
    ORDINARY_QUEUE,
    host_evidence,
    valid_expected,
    valid_profile,
)
from secp_operator_deployment.cli import build_parser, main, run
from secp_operator_deployment.queue_check import (
    QUEUE_EXIT_CODES,
    QUEUE_LADDER,
    STOP_UNOBSERVABLE,
    SUBMISSION_STOPS,
    _resolve_queue_status,
    build_queue_report,
    observe_submission_stops,
)
from secp_operator_deployment.verify import (
    REMEDIATION_CLASSES,
    REMEDIATION_REVIEWED_CODE,
    build_provenance_report,
    classify_reason_code,
)

_QUEUE_NAMES = (ORDINARY_QUEUE, OPERATOR_QUEUE)


def _report(**over):  # noqa: ANN003, ANN201
    """A queue report over a prepared, isolated, dormant deployment unless overridden."""
    kwargs = dict(
        profile=valid_profile(), expected=valid_expected(), host_observation=host_evidence()
    )
    kwargs.update(over)
    return build_queue_report(**kwargs)


def _prepared_context(**over):  # noqa: ANN003, ANN201
    from secp_operator_deployment.production_context import VerifyContext

    kwargs = dict(
        profile=valid_profile(),
        profile_load_reason=None,
        expected=valid_expected(),
        installed_trust_ok=True,
        installed_trust_reason=None,
        attestation=None,
        host_observation=host_evidence(),
    )
    kwargs.update(over)
    return VerifyContext(**kwargs)


# --------------------------------------------------------------------------- the ordering proof


_FACTS = (
    "stops_closed",
    "isolation_observable",
    "queues_isolated",
    "queue_authority_validated",
    "consumer_observable",
    "consumer_dormant",
)


def test_the_ladder_names_exactly_the_facts_the_resolver_takes():
    """Guard the guard: the proof below is only meaningful if the two lists describe one thing."""
    assert tuple(r.id for r in QUEUE_LADDER) == (
        "submission_stops_closed",
        "isolation_observable",
        "queues_isolated",
        "queue_authority_validated",
        "consumer_observable",
        "operator_consumer_dormant",
    )
    assert len(QUEUE_LADDER) == len(_FACTS)


@pytest.mark.parametrize("combo", list(itertools.product((True, False), repeat=len(_FACTS))))
def test_the_guard_order_is_exactly_the_ladder_order_on_every_fact_combination(combo):
    """Exhaustive, not sampled: 2**6 = 64 combinations.

    Relative order can only be observed when two facts are unmet at once, which is exactly what a
    single-fault matrix cannot see — so the whole lattice is walked. The expected status is derived
    ONLY from ``QUEUE_LADDER``; the actual comes from ``_resolve_queue_status``. Reordering either,
    or changing a ``status_when_unmet``, fails here.
    """
    kwargs = dict(zip(_FACTS, combo, strict=True))
    expected = next(
        (
            rung.status_when_unmet
            for rung, satisfied in zip(QUEUE_LADDER, combo, strict=True)
            if not satisfied
        ),
        "queue_isolated_and_dormant",
    )
    assert _resolve_queue_status(**kwargs) == expected, kwargs


def test_every_ladder_status_is_reachable_and_priced():
    """A status nothing can return, or one with no exit code, is a lie in the contract."""
    reachable = {
        _resolve_queue_status(**dict(zip(_FACTS, combo, strict=True)))
        for combo in itertools.product((True, False), repeat=len(_FACTS))
    }
    assert reachable == set(QUEUE_EXIT_CODES)
    assert QUEUE_EXIT_CODES["queue_isolated_and_dormant"] == 0
    # A reviewed stop that is open shares the escalate code with a drifted seal, deliberately.
    assert QUEUE_EXIT_CODES["queue_stops_open"] == 20


def test_every_ladder_rung_is_well_formed():
    for rung in QUEUE_LADDER:
        assert rung.status_when_unmet in QUEUE_EXIT_CODES, rung.id
        assert rung.remediation in REMEDIATION_CLASSES, rung.id
        assert rung.dimension in {"B", "C", "F"}, rung.id


# --------------------------------------------------------------------------- the submission stops


def test_the_stops_are_observed_from_the_reviewed_constants_not_declared():
    """Read the constants HERE, independently, and require the report to agree with them.

    If a stop were quietly opened and the report kept saying ``closed``, this is what catches it.
    """
    from secp_operator_deployment.runner import _OPERATOR_ACTIVATION_SEALED
    from secp_operator_deployment.runtime_seams import (
        REVIEWED_RUNTIME_PROVIDERS,
        SealedControlledLiveRuntime,
    )
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        unconfigured_plan_execution_composition,
        verify_plan_execution_composition,
    )

    def _shipped_composition_refuses() -> bool:
        try:
            verify_plan_execution_composition(unconfigured_plan_execution_composition())
        except PlanExecutionCompositionError:
            return True
        return False

    rows = {r["id"]: r for r in observe_submission_stops()}
    assert set(rows) == {s.id for s in SUBMISSION_STOPS}

    assert rows["operator_activation_seal"]["closed"] is bool(_OPERATOR_ACTIVATION_SEALED)
    assert rows["reviewed_runtime_provider_set_empty"]["closed"] is (
        len(REVIEWED_RUNTIME_PROVIDERS) == 0
    )
    assert rows["shipped_runtime_sealed"]["closed"] is (
        not SealedControlledLiveRuntime().provisioned()
    )
    # Re-derived by exercising the validator, not by reading a flag. The stop is closed only if
    # the shipped composition genuinely cannot be verified.
    assert (
        rows["plan_execution_composition_unconfigured"]["closed"] is _shipped_composition_refuses()
    )

    # The observed VALUES travel with the verdict, so a reader can check it rather than take it.
    assert rows["reviewed_runtime_provider_set_empty"]["observed"] == {
        "reviewed_runtime_provider_count": len(REVIEWED_RUNTIME_PROVIDERS)
    }


def test_all_four_stops_are_closed_on_the_shipped_package():
    rows = observe_submission_stops()
    assert [r["closed"] for r in rows] == [True, True, True, True]
    assert _report()["submission_stops"]["all_closed"] is True


def test_no_stop_is_operator_closable():
    """The whole point of the class. If any stop read ``operator_host_action``, the report would be
    telling an operator that opening the controlled-live path is theirs to do."""
    for spec in SUBMISSION_STOPS:
        assert spec.remediation == REMEDIATION_REVIEWED_CODE, spec.id
    for row in observe_submission_stops():
        assert row["remediation"] == REMEDIATION_REVIEWED_CODE, row["id"]


def test_every_stop_refusal_code_is_catalogued():
    """The preview names the code the REAL path refuses with, so it must classify like any other."""
    for spec in SUBMISSION_STOPS:
        assert classify_reason_code(spec.reason_code) is not None, spec.id
    assert classify_reason_code(STOP_UNOBSERVABLE) is not None
    assert classify_reason_code("submission_stop_open") is not None


def test_an_unobservable_stop_is_reported_open_not_passed(monkeypatch):
    """Fail closed: a stop whose constant cannot be READ is not a stop."""
    from secp_operator_deployment import queue_check

    def _boom():
        raise RuntimeError("unreadable")

    monkeypatch.setitem(queue_check._OBSERVERS, "operator_activation_seal", _boom)
    rows = {r["id"]: r for r in observe_submission_stops()}
    assert rows["operator_activation_seal"]["closed"] is False
    assert rows["operator_activation_seal"]["reason_code"] == STOP_UNOBSERVABLE
    assert rows["operator_activation_seal"]["observed"] == {}

    report = _report()
    assert report["status"] == "queue_stops_open"
    assert report["exit_code"] == 20
    assert report["submission_stops"]["first_open"] == "operator_activation_seal"


def test_an_open_stop_drives_escalation_regardless_of_everything_else():
    """A perfectly isolated, perfectly dormant deployment with an open stop is NOT ok."""
    stops = [dict(r) for r in observe_submission_stops()]
    stops[0]["closed"] = False
    report = _report(stops=stops)
    assert report["status"] == "queue_stops_open"
    assert report["submission_stops"]["first_open"] == stops[0]["id"]
    assert report["submission_stops"]["first_open_reason_code"] == "submission_stop_open"
    assert report["isolation"]["ok"] is True  # isolation was fine; the stop still wins


def test_the_preview_names_the_first_stop_that_would_fire():
    report = _report()
    preview = report["submission_preview"]
    assert preview["submission_performed"] is False
    assert preview["would_be_refused"] is True
    assert preview["first_refusing_stop"] == SUBMISSION_STOPS[0].id
    assert preview["refusal_reason_code"] == SUBMISSION_STOPS[0].reason_code
    assert preview["consumer_would_poll_operator_queue"] is False
    # The preview is derived from observations, and says so.
    assert preview["basis"] == "observed_reviewed_code_constants"


def test_with_every_stop_open_the_preview_refuses_to_claim_a_refusal():
    """The preview must not invent a stop. With none closed it says so, rather than reassuring."""
    stops = [dict(r, closed=False) for r in observe_submission_stops()]
    report = _report(stops=stops)
    assert report["submission_preview"]["would_be_refused"] is False
    assert report["submission_preview"]["first_refusing_stop"] is None
    assert report["submission_preview"]["refusal_reason_code"] is None
    assert report["status"] == "queue_stops_open"


def test_an_empty_stop_list_is_not_treated_as_all_closed():
    """``all(())`` is True — the trap this pins. No stops observed means nothing is known."""
    report = _report(stops=[])
    assert report["submission_stops"]["all_closed"] is False
    assert report["status"] == "queue_stops_open"


# --------------------------------------------------------------------------- isolation (dim B)


def test_a_prepared_isolated_deployment_is_clean():
    report = _report()
    assert report["status"] == "queue_isolated_and_dormant"
    assert report["exit_code"] == 0
    assert report["isolation"] == {
        "ok": True,
        "ordinary_configured": True,
        "operator_configured": True,
        "distinct": True,
        "authority": "deployment_profile",
        "reason_code": None,
    }
    assert report["queue_authority"] == {
        "validated": True,
        "expected_provided": True,
        "authority": "deployment_profile_expected_pins_and_worker_setting",
        "reason_code": None,
    }


def test_missing_or_drifted_queue_authority_cannot_report_success():
    missing = _report(expected=None)
    assert missing["status"] == "queue_unverified"
    assert missing["queue_authority"]["reason_code"] == "expected_identities_not_provisioned"

    drifted = _report(
        profile=valid_profile(ordinary_task_queue="drifted-ordinary"),
        expected=valid_expected(ordinary_task_queue="drifted-ordinary"),
    )
    assert drifted["isolation"]["ok"] is True
    assert drifted["queue_authority"]["validated"] is False
    assert drifted["queue_authority"]["reason_code"] == "expected_ordinary_queue_not_worker_queue"
    assert drifted["status"] == "queue_unverified"


def test_isolation_names_the_artefact_it_read_on_every_path():
    """The split is expressed TWICE: this pair lives in the profile/plan, while a running worker
    polls ``Settings.temporal_task_queue`` / ``temporal_operator_task_queue``, which is not read
    here. Without naming the authority, a green ``isolation`` reads as a claim about the running
    process — which only consumer dormancy, observed from the host, can make."""
    for kwargs in ({}, dict(profile=None), dict(host_observation=None)):
        assert _report(**kwargs)["isolation"]["authority"] == "deployment_profile", kwargs


def test_an_absent_profile_is_unverified_not_isolated():
    """The dangerous failure mode is reporting isolation that was never observed."""
    report = _report(profile=None)
    assert report["status"] == "queue_unverified"
    assert report["exit_code"] == 10
    assert report["isolation"]["ok"] is False
    assert report["isolation"]["reason_code"] == "queue_separation_unavailable"


def test_a_foreign_profile_object_is_refused_without_attribute_access():
    """A duck-typed profile must never be read for queue values."""

    class _Forged:
        ordinary_task_queue = "shared"
        operator_task_queue = "shared"

        def __getattribute__(self, name):  # noqa: ANN001, ANN204
            raise AssertionError(f"foreign profile was read: {name}")

    report = _report(profile=_Forged())
    assert report["status"] == "queue_unverified"
    assert report["isolation"]["reason_code"] == "queue_separation_unavailable"


def test_a_shared_queue_is_reported_not_isolated():
    """Parse-time validation refuses this, so the object is built directly: this section is the
    defence-in-depth report, and it must not depend on the parser having caught it."""

    class _Shared:
        ordinary_task_queue = ORDINARY_QUEUE
        operator_task_queue = ORDINARY_QUEUE

    from secp_operator_deployment.queue_check import _queue_section

    isolation = _queue_section(True, _Shared())
    assert isolation["ok"] is False
    assert isolation["distinct"] is False
    assert isolation["reason_code"] == "queue_not_distinct"
    assert classify_reason_code(isolation["reason_code"]) == {
        "dimension": "B",
        "remediation": "reviewed_deployment_material",
    }


# --------------------------------------------------------------------------- consumer (dim C)


@pytest.mark.parametrize(
    ("evidence_kwargs", "status", "reason"),
    [
        (dict(enabled=True), "queue_operator_consuming", "operator_consumer_active"),
        (dict(running=True), "queue_operator_consuming", "operator_consumer_active"),
        (dict(enabled=True, running=True), "queue_operator_consuming", "operator_consumer_active"),
        (dict(inspected=False), "queue_unverified", "operator_consumer_unobservable"),
        (dict(coherent=False), "queue_unverified", "operator_consumer_unobservable"),
    ],
)
def test_a_consuming_or_unobservable_operator_unit_refuses_cleanly(evidence_kwargs, status, reason):
    report = _report(host_observation=host_evidence(**evidence_kwargs))
    assert report["status"] == status
    assert report["exit_code"] == QUEUE_EXIT_CODES[status]
    assert report["operator_consumer"]["reason_code"] == reason
    assert report["operator_consumer"]["dormant"] is False
    assert classify_reason_code(reason)["dimension"] == "C"


def test_an_absent_unit_is_dormant_even_though_verify_calls_it_not_prepared():
    """The one host state where this check and ``verify``'s rung differ — and they differ correctly.

    ``verify`` wants the unit installed-but-disabled (a PREPARED host). This check asks only
    whether anything consumes the queue, and an absent unit consumes nothing. Merging the two would
    make one of the answers wrong.
    """
    from secp_operator_deployment.verify import _host_section

    evidence = host_evidence(present=False)
    assert _host_section(evidence)["operator_prepared_and_disabled"] is False

    report = _report(host_observation=evidence)
    assert report["operator_consumer"]["dormant"] is True
    assert report["operator_consumer"]["unit_present"] is False
    assert report["status"] == "queue_isolated_and_dormant"


def test_an_unobserved_host_reports_null_rather_than_a_guessed_state():
    report = _report(host_observation=None)
    consumer = report["operator_consumer"]
    assert consumer["observed"] is False
    assert consumer["unit_present"] is None
    assert consumer["unit_enabled"] is None
    assert consumer["unit_running"] is None
    assert report["submission_preview"]["consumer_would_poll_operator_queue"] is None
    assert report["status"] == "queue_unverified"


def test_a_foreign_host_observation_is_refused_by_exact_type():
    class _Forged:
        inspected = True
        coherent = True
        operator_present = True
        operator_enabled = False
        operator_running = False
        ordinary_running = True

    report = _report(host_observation=_Forged())
    assert report["status"] == "queue_unverified"
    assert report["operator_consumer"]["reason_code"] == "host_observation_type_invalid"


# --------------------------------------------------------------------------- secrecy + determinism


def test_no_queue_name_reaches_the_operators_terminal():
    """Queue names are profile values. This is the report most tempted to print them."""
    for kwargs in (
        {},
        dict(host_observation=host_evidence(running=True)),
        dict(profile=None),
        dict(host_observation=None),
    ):
        blob = json.dumps(_report(**kwargs), sort_keys=True)
        for name in _QUEUE_NAMES:
            assert name not in blob, (name, kwargs)


def test_the_report_is_byte_identical_across_runs():
    a = json.dumps(_report(), sort_keys=True, separators=(",", ":"))
    b = json.dumps(_report(), sort_keys=True, separators=(",", ":"))
    assert a == b


def test_the_report_is_json_serializable_and_carries_no_object_references():
    blob = json.dumps(_report(), sort_keys=True)
    assert json.loads(blob)["phase"] == "queue"
    assert "object at 0x" not in blob


def test_a_caller_cannot_mutate_the_observed_stops_through_the_report():
    stops = observe_submission_stops()
    report = build_queue_report(
        profile=valid_profile(), host_observation=host_evidence(), stops=stops
    )
    report["submission_stops"]["ladder"][0]["closed"] = False
    assert stops[0]["closed"] is True


# --------------------------------------------------------------------------- the CLI surface


@pytest.fixture
def prepared_context(monkeypatch):
    from secp_operator_deployment import production_context

    ctx = production_context.VerifyContext(
        profile=valid_profile(),
        expected=valid_expected(),
        profile_load_reason=None,
        installed_trust_ok=True,
        installed_trust_reason=None,
        attestation=None,
        host_observation=host_evidence(),
    )
    monkeypatch.setattr(production_context, "load_verify_context", lambda: ctx)
    return ctx


def test_queue_accepts_only_json_and_no_queue_or_path_argument():
    parsed = vars(build_parser().parse_args(["queue"]))
    assert set(parsed) == {"command", "json"}
    for argv in (
        ["queue", "--queue", "secp-controlled-live-v1"],
        ["queue", "--profile", "/tmp/x.json"],
        ["queue", "--task-queue", "x"],
        ["queue", "--submit"],
        ["queue", "--activate"],
        ["queue", "/tmp/x"],
    ):
        with pytest.raises(SystemExit):
            build_parser().parse_args(argv)


def test_main_queue_json_is_one_deterministic_line_with_the_reports_exit_code(
    prepared_context, capsys
):
    code = main(["queue", "--json"])
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    payload = json.loads(out)
    assert payload["phase"] == "queue"
    assert payload["status"] == "queue_isolated_and_dormant"
    assert code == payload["exit_code"] == QUEUE_EXIT_CODES[payload["status"]] == 0
    assert out == json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    for name in _QUEUE_NAMES:
        assert name not in out


def test_main_queue_human_output_is_bounded_and_leaks_no_queue_name(prepared_context, capsys):
    main(["queue"])
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    assert "queue_isolated_and_dormant" in out
    for name in _QUEUE_NAMES:
        assert name not in out


def test_main_queue_output_is_byte_identical_across_runs(prepared_context, capsys):
    main(["queue", "--json"])
    first = capsys.readouterr().out
    main(["queue", "--json"])
    assert capsys.readouterr().out == first


def test_main_queue_refuses_when_the_context_carries_no_expected_pins(monkeypatch, capsys):
    """The CLI-level half of the authority rung, kept separate from the report-level half.

    ``_queue_kwargs`` threading ``expected`` out of the resolved context is the seam that decides
    whether the rung sees pins at all. Were that key dropped, every report-level authority test
    would stay green while the real command silently fell back to the unprovisioned path — so this
    drives the actual CLI and asserts the REFUSAL, not a report built with explicit inputs.
    """
    from secp_operator_deployment import production_context

    ctx = production_context.VerifyContext(
        profile=valid_profile(),
        expected=None,
        profile_load_reason=None,
        installed_trust_ok=True,
        installed_trust_reason=None,
        attestation=None,
        host_observation=host_evidence(),
    )
    monkeypatch.setattr(production_context, "load_verify_context", lambda: ctx)

    code = main(["queue", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "queue_unverified"
    assert code == payload["exit_code"] == QUEUE_EXIT_CODES["queue_unverified"] == 10
    assert payload["queue_authority"] == {
        "validated": False,
        "expected_provided": False,
        "authority": "deployment_profile_expected_pins_and_worker_setting",
        "reason_code": "expected_identities_not_provisioned",
    }
    # The unsafe near-miss: isolation alone was green, and on its own would have reported success.
    assert payload["isolation"]["ok"] is True


# --------------------------------------------------------------------------- the tripwires
#
# ``effects_of_this_queue_check`` is a claim. These are the observation.


def test_the_queue_command_submits_nothing_and_starts_no_consumer(prepared_context, monkeypatch):
    """Measure, do not trust: every path that could submit, start a consumer, build a composition
    aggregate or shell out is a tripwire, and the assertion is made on what the tripwires RECORD."""
    from secp_operator_deployment import compositions, host_process, runner

    # The tripwires RECORD as well as raise, and the assertion below is made on the record.
    #
    # ``RealCommandRunner.run`` is the reason: it sits on a seam INSIDE ``load_verify_context``,
    # every step of which is wrapped in ``except Exception``. That is correct fail-closed behaviour
    # and it also swallows a raising tripwire whole — so this one could never have failed the test,
    # whatever it caught. A decorative assertion inside a test named for a safety property is not
    # neutral: a maintainer reads it as guarding the command-runner path. The other two seams are
    # outside the loader and do propagate; recording costs them nothing.
    reached: list[str] = []

    def _tripwire(name):  # noqa: ANN001, ANN202
        def _fail(*a, **k):  # noqa: ANN002, ANN003, ANN202
            reached.append(name)
            raise AssertionError(f"the queue check reached {name}")

        return _fail

    monkeypatch.setattr(runner, "run_operator_worker", _tripwire("run_operator_worker"))
    monkeypatch.setattr(
        compositions,
        "build_controlled_live_compositions",
        _tripwire("build_controlled_live_compositions"),
    )
    monkeypatch.setattr(
        host_process.RealCommandRunner, "run", _tripwire("RealCommandRunner.run"), raising=False
    )

    assert main(["queue", "--json"]) == 0

    assert reached == [], f"the queue check reached a tripwired seam: {reached}"

    # ``temporalio`` is the ONLY way to submit a workflow or run a worker. What covers that, stated
    # as what each guard PROVES rather than as what some other guard fails to see:
    #
    #   * NO module in this package imports ``temporalio``, structurally, at any depth —
    #     ``test_deployment_boundary.test_no_temporalio_imports_anywhere``, an AST import scan whose
    #     own reach is proven by ``test_the_boundary_scan_reaches_into_subpackages``. It is
    #     environment-independent, so it holds in an environment that HAS the extra installed.
    #   * the queue-check module names no submission symbol in an import or call shape —
    #     ``test_the_queue_check_module_calls_and_imports_no_submission_symbol``, at the bottom of
    #     this file.
    #   * the assertion above that ``main`` returned 0 — for ONE import shape, named exactly,
    #     because the three behave differently and only one of them lands here (measured, each
    #     injected into ``queue_check.py`` in turn):
    #       - a bare import DEFERRED into a function on the queue path -> ``ImportError`` where the
    #         extra is absent, ``cli.py``'s bounded guard turns it into ``UNAVAILABLE_EXIT_CODE``
    #         (20), and this assertion fails. This is the shape the exit code catches.
    #       - a bare import at MODULE level -> this file imports ``queue_check`` at module level,
    #         so it never reaches the assertion; the whole file fails at COLLECTION instead. Loud,
    #         but not this guard.
    #       - a GUARDED ``try: import temporalio / except Exception: pass`` -> raises nothing,
    #         ``main`` returns 0, and this assertion PASSES. That is how an optional dependency is
    #         normally written, so it is the likelier shape rather than a contrived one, and the
    #         two static scans above are the only things that fail on it.
    #     So this is a real runtime observation of one narrow shape — not the guard the property
    #     rests on. The static scans are, because they are blind to none of the three.
    #   * the tripwires above — the INDIRECT reach, which a source scan genuinely cannot see.
    #
    # A ``sys.modules`` delta across the ``main()`` call used to sit here, credited both in this
    # file and in the runbook with observing that no such module was imported. It observed nothing:
    # ``temporalio`` is an optional extra (``[project.optional-dependencies] worker``) and every CI
    # job installs ``.[dev]`` only, so the key can never appear and the assertion can never fail.
    # Even where it IS installed the result would depend on collection order — the snapshot was
    # taken twenty-odd tests into this file, after earlier tests had already driven the same
    # loader, so it would pass in a full-file run and fail when run alone. Removed rather than
    # conditioned: the four guards above already cover the property in every environment.


def test_the_queue_command_reads_the_same_context_verify_does_exactly_once(monkeypatch):
    """The no-added-contact-surface claim, observed. One loader, called once per invocation."""
    from secp_operator_deployment import production_context

    calls = []
    ctx = production_context.VerifyContext(
        profile=valid_profile(),
        expected=valid_expected(),
        profile_load_reason=None,
        installed_trust_ok=True,
        installed_trust_reason=None,
        attestation=None,
        host_observation=host_evidence(),
    )

    def _counted():  # noqa: ANN202
        calls.append(1)
        return ctx

    monkeypatch.setattr(production_context, "load_verify_context", _counted)
    assert main(["queue", "--json"]) == 0
    assert len(calls) == 1


_STRUCTURAL_PROPERTIES = frozenset(
    {
        "worker_constructed",
        "workflow_submitted",
        "run_plan_generation_called",
        "secret_resolver_constructed",
        "composition_aggregate_built",
    }
)


def test_the_structural_properties_are_all_false_and_none_were_reached():
    """These must not grow a truthy field: a ``True`` here would be an admission."""
    effects = _report()["effects_of_this_queue_check"]
    assert set(effects) == {
        "measured_this_invocation",
        "code_structural_properties",
        "host_mutation",
    }
    section = effects["code_structural_properties"]
    assert set(section) == _STRUCTURAL_PROPERTIES | {"basis", "owning_guards"}
    assert all(section[name] is False for name in _STRUCTURAL_PROPERTIES)


def test_the_asserted_properties_are_not_labelled_or_placed_as_measurements():
    """The rename is the point, so it is pinned rather than left to reviewer memory.

    ``structural_invariants`` sat beside ``measured_this_invocation`` under a name that read as an
    observation, while being six hardcoded ``False`` literals that no input to the builder carried.
    The properties still hold — they are proven by the guards named below — but the report must not
    borrow the credibility of the measured half for the asserted half. This fails if the section is
    renamed back, folded into the measured block, or given a name containing "measured".
    """
    effects = _report()["effects_of_this_queue_check"]
    assert "structural_invariants" not in effects
    assert not any("measured" in key for key in effects["code_structural_properties"])
    # The measured half stays exactly what it was: counted, and only counted.
    assert set(effects["measured_this_invocation"]) == {
        "host_commands_executed",
        "local_host_contact_performed",
    }
    assert effects["code_structural_properties"]["basis"] == (
        "shipped_source_structure_not_this_invocation"
    )


def test_no_host_mutation_claim_is_made_anywhere_in_either_report():
    """``host_mutated: False`` was the one actively MISLEADING literal, and it must not return.

    The package spawns subprocesses and one argv tail — ``profile.ordinary_health_command`` — is
    DEPLOYMENT-SUPPLIED, so whether the host is mutated is not this package's to answer. The
    expected-identities pin does not close it: it constrains drift from the expected argv, never
    what that argv does. The absence of a claim is reported explicitly so that "no key" and "we
    checked and it was fine" can never be confused.
    """
    for report, effects_key in (
        (_report(), "effects_of_this_queue_check"),
        (build_provenance_report(), "effects_of_this_provenance_check"),
    ):
        effects = report[effects_key]
        assert "host_mutated" not in json.dumps(report, sort_keys=True)
        assert effects["host_mutation"]["claimed"] is None
        assert isinstance(effects["host_mutation"]["basis"], str)
        assert effects["host_mutation"]["basis"]


def test_every_named_owning_guard_exists_and_covers_exactly_the_asserted_properties():
    """A citation to a guard that does not exist is worse than no citation.

    Keyed BY PROPERTY deliberately: a single blanket citation would let one guard's credibility
    cover properties it never touches. This resolves each named guard to a real test function, so
    renaming or deleting a guard fails here instead of leaving the report citing a ghost.
    """
    import importlib

    for report, effects_key in (
        (_report(), "effects_of_this_queue_check"),
        (build_provenance_report(), "effects_of_this_provenance_check"),
    ):
        section = report[effects_key]["code_structural_properties"]
        properties = set(section) - {"basis", "owning_guards"}
        # Every asserted property carries a guard, and no guard names a property that is not
        # asserted — so adding a literal without a proof, or vice versa, fails.
        assert set(section["owning_guards"]) == properties

        for prop, ref in section["owning_guards"].items():
            module_name, _, func_name = ref.rpartition(".")
            module = importlib.import_module(module_name)
            guard = getattr(module, func_name, None)
            assert callable(guard), f"{prop} cites {ref}, which is not a test function"


# --- the contact statement is MEASURED, not declared ---------------------------------------------
#
# The bug this replaces: `external_contact_performed` was hardcoded False. On a provisioned POSIX
# host the queue command runs `systemctl show`, `docker inspect` and `docker exec <container>
# <health argv>` while resolving its inputs — so the report asserted "no external contact" on
# exactly the host where contact happens. It is now derived from a count taken as the commands run.


@pytest.mark.parametrize("executed", [0, 1, 3, 17])
def test_the_contact_statement_tracks_the_measured_command_count(executed):
    measured = _report(host_commands_executed=executed)["effects_of_this_queue_check"][
        "measured_this_invocation"
    ]
    assert measured["host_commands_executed"] == executed
    assert measured["local_host_contact_performed"] is (executed > 0)


def test_a_report_over_injected_inputs_truthfully_claims_no_contact():
    """Injected inputs resolve no context, so zero is the honest answer — not a convenient one."""
    measured = _report()["effects_of_this_queue_check"]["measured_this_invocation"]
    assert measured["host_commands_executed"] == 0
    assert measured["local_host_contact_performed"] is False


def test_the_counting_runner_counts_every_invocation_including_a_failing_one():
    """A command that started and then failed still made contact. Counting only successes would
    understate exactly the case an operator most needs to know about."""
    from secp_operator_deployment.production_context import _CountingCommandRunner

    class _Boom:
        def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001, ANN201
            raise RuntimeError("host command failed")

    counter = _CountingCommandRunner(_Boom())
    for _ in range(3):
        with pytest.raises(RuntimeError):
            counter.run(object(), [], timeout_seconds=1, max_output_bytes=1)
    assert counter.calls == 3


def test_the_counting_runner_delegates_unchanged_and_returns_the_inner_result():
    """A wrapper that altered the call would corrupt the observation it exists to measure."""
    from secp_operator_deployment.production_context import _CountingCommandRunner

    seen = []

    class _Recorder:
        def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001, ANN201
            seen.append((pin, tuple(argv_tail), timeout_seconds, max_output_bytes))
            return "inner-result"

    counter = _CountingCommandRunner(_Recorder())
    pin = object()
    assert counter.run(pin, ["show", "x"], timeout_seconds=5, max_output_bytes=99) == "inner-result"
    assert seen == [(pin, ("show", "x"), 5, 99)]
    assert counter.calls == 1


def test_the_real_loader_counts_the_host_commands_it_actually_runs(monkeypatch):
    """The WIRING, driven end to end through the real ``load_verify_context``.

    This is the gap that made the whole measurement severable. Every other test either hands an
    integer to a pure builder or monkeypatches the loader away; the single test that ran the real
    loader asserted the count was ZERO (the refusing-filesystem path). So both
    ``host_commands_executed = counting.calls`` and ``command_runner=counting`` could be reverted
    and the suite stayed green — restoring the original defect, now wearing a measurement's
    credibility.

    Here the loader runs for real over a seeded in-memory filesystem and a scripted runner: the
    profile and pins resolve, the adapters are built, and the observation executes commands. The
    count must be non-zero and must equal what the scripted runner actually served.
    """
    from _deploy_support import prepared_host_runner, seeded_production_fs
    from secp_operator_deployment import production_context

    runner = prepared_host_runner()
    calls = {"n": 0}
    inner_run = runner.run

    def _counted(*a, **k):  # noqa: ANN002, ANN003, ANN202
        calls["n"] += 1
        return inner_run(*a, **k)

    runner.run = _counted  # type: ignore[method-assign]
    monkeypatch.setattr(production_context, "_production_fs", lambda: seeded_production_fs())
    monkeypatch.setattr(production_context, "_command_runner", lambda: runner)

    ctx = production_context.load_verify_context()

    assert ctx.host_observation is not None, "the observation did not run; the test proves nothing"
    assert calls["n"] > 0, "the scripted runner was never called"
    # The recorded count must be the REAL number of commands, not a constant that happens to be
    # non-zero: it is compared against an independent tally taken at the runner itself.
    assert ctx.host_commands_executed == calls["n"]


def test_the_real_loader_reports_contact_through_to_both_reports(monkeypatch):
    """And the count must survive into what an operator actually reads — in both commands."""
    from _deploy_support import prepared_host_runner, seeded_production_fs
    from secp_operator_deployment import production_context

    monkeypatch.setattr(production_context, "_production_fs", lambda: seeded_production_fs())
    monkeypatch.setattr(production_context, "_command_runner", prepared_host_runner)

    _code, queue_payload = run(["queue", "--json"], None)
    _code, verify_payload = run(["verify", "--json"], None)

    for payload, key in (
        (queue_payload, "effects_of_this_queue_check"),
        (verify_payload, "effects_of_this_verification"),
    ):
        measured = payload[key]["measured_this_invocation"]
        assert measured["host_commands_executed"] > 0, key
        assert measured["local_host_contact_performed"] is True, key


def test_the_cli_carries_the_measured_count_from_the_resolved_context(monkeypatch):
    """End to end: a context reporting executed commands must surface as contact in the report."""
    from secp_operator_deployment import production_context

    ctx = _prepared_context(host_commands_executed=4)
    monkeypatch.setattr(production_context, "load_verify_context", lambda: ctx)

    _code, payload = run(["queue", "--json"], None)
    measured = payload["effects_of_this_queue_check"]["measured_this_invocation"]
    assert measured["host_commands_executed"] == 4
    assert measured["local_host_contact_performed"] is True


def test_the_queue_check_module_calls_and_imports_no_submission_symbol():
    """A source scan of this module for CALL and IMPORT shapes — not bare substrings.

    Stated exactly, because the difference bit once already: an earlier substring form of this test
    failed on ``"run_plan_generation_called"``, a KEY in the effects section. Naming a symbol in a
    report key is not reaching it, so matching the name alone measures the wrong thing. What is
    measured here is ``import temporalio`` / ``from temporalio ...`` and the call shape
    ``symbol(``.

    Its limit, plainly: this proves the module does not CALL these by name here. It cannot see an
    indirect reach — that is what the tripwire test above is for, and the two are kept separate
    because they fail for different reasons.
    """
    import pathlib
    import re

    src = (
        pathlib.Path(__file__).resolve().parents[1] / "secp_operator_deployment" / "queue_check.py"
    ).read_text(encoding="utf-8")
    code_only = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))

    assert not re.search(r"^\s*(import|from)\s+temporalio\b", code_only, re.MULTILINE)
    for symbol in (
        "start_workflow",
        "execute_workflow",
        "run_plan_generation",
        "run_operator_worker",
        "build_controlled_live_compositions",
        "_load_installed_runtime",
    ):
        assert not re.search(rf"\b{symbol}\s*\(", code_only), symbol
