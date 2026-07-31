"""The controlled-live QUEUE isolation check (WS-E).

The program constraint this command exists to validate — *the controlled-live operator queue must
be disabled and isolated from the ordinary Temporal queue* — is one an operator has to be able to
CHECK, and checking it must never be a way to cause the thing it is checking against. So the
properties pinned here are, in order of what they protect:

* :func:`test_the_queue_command_submits_nothing_and_starts_no_consumer` — the tripwire suite. The
  report's ``effects_of_this_queue_check`` section is a CLAIM; these tests are the observation. The
  operator run hook, the composition builders and the real command runner are each replaced by a
  tripwire that RECORDS and raises if reached, and the assertion is made on the record.
  ``temporalio`` — the only way to submit a workflow or run a worker — is covered by two STATIC
  scans instead, for the reason given at the tripwire itself: it is an optional extra installed in
  no environment this suite runs in, so no runtime observation of this process can see it.
* :func:`test_the_guard_order_is_exactly_the_ladder_order_on_every_fact_combination` — the ordering
  proof, exhaustive over all 32 combinations of the five facts rather than sampled. ``QUEUE_LADDER``
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
from _deploy_support import OPERATOR_QUEUE, ORDINARY_QUEUE, host_evidence, valid_profile
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
    classify_reason_code,
)

_QUEUE_NAMES = (ORDINARY_QUEUE, OPERATOR_QUEUE)


def _report(**over):  # noqa: ANN003, ANN201
    """A queue report over a prepared, isolated, dormant deployment unless overridden."""
    kwargs = dict(profile=valid_profile(), host_observation=host_evidence())
    kwargs.update(over)
    return build_queue_report(**kwargs)


def _prepared_context(**over):  # noqa: ANN003, ANN201
    from secp_operator_deployment.production_context import VerifyContext

    kwargs = dict(
        profile=valid_profile(),
        profile_load_reason=None,
        expected=None,
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
    "consumer_observable",
    "consumer_dormant",
)


def test_the_ladder_names_exactly_the_facts_the_resolver_takes():
    """Guard the guard: the proof below is only meaningful if the two lists describe one thing."""
    assert tuple(r.id for r in QUEUE_LADDER) == (
        "submission_stops_closed",
        "isolation_observable",
        "queues_isolated",
        "consumer_observable",
        "operator_consumer_dormant",
    )
    assert len(QUEUE_LADDER) == len(_FACTS)


@pytest.mark.parametrize("combo", list(itertools.product((True, False), repeat=len(_FACTS))))
def test_the_guard_order_is_exactly_the_ladder_order_on_every_fact_combination(combo):
    """Exhaustive, not sampled: 2**5 = 32 combinations.

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
    from secp_worker.plan_gen.composition import PlanExecutionGate

    rows = {r["id"]: r for r in observe_submission_stops()}
    assert set(rows) == {s.id for s in SUBMISSION_STOPS}

    assert rows["operator_activation_seal"]["closed"] is bool(_OPERATOR_ACTIVATION_SEALED)
    assert rows["reviewed_runtime_provider_set_empty"]["closed"] is (
        len(REVIEWED_RUNTIME_PROVIDERS) == 0
    )
    assert rows["shipped_runtime_sealed"]["closed"] is (
        not SealedControlledLiveRuntime().provisioned()
    )
    assert rows["plan_execution_gate_default_disabled"]["closed"] is (
        not PlanExecutionGate().enabled
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
        profile_load_reason=None,
        expected=None,
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

    # ``temporalio`` is the ONLY way to submit a workflow or run a worker, and this test used to
    # assert a ``sys.modules`` delta across the ``main()`` call above, credited — here and in the
    # runbook — with observing that no such module was imported. It observed nothing.
    # ``temporalio`` is an optional extra installed in NO environment this suite runs in, CI
    # included, so the key can never appear and the assertion can never fail. Worse, the failure
    # was ORDER-DEPENDENT even in principle: the snapshot is taken twenty-odd tests into this file,
    # after earlier tests have already driven the same loader, so with the extra installed it would
    # pass in a full-file run and fail when run alone. A guard whose result depends on collection
    # order is not a guard, and one that reads as a strong runtime observation is worse than none.
    #
    # The property is real; it is carried STATICALLY by two scans that do fail when the code moves:
    #   * ``test_deployment_boundary.test_no_temporalio_imports_anywhere`` — an AST import scan over
    #     every ``.py`` in the package at ANY depth, so the import cannot be added anywhere in it,
    #     and its own coverage is proven by ``test_the_boundary_scan_reaches_into_subpackages``;
    #   * ``test_the_queue_check_module_calls_and_imports_no_submission_symbol`` at the bottom of
    #     this file — the import and call shapes in the queue-check module specifically.
    # Those cover the static reach. The tripwires above are what cover the indirect one, which is
    # the half a source scan genuinely cannot see — so the two are kept, and the delta is not.


def test_the_queue_command_reads_the_same_context_verify_does_exactly_once(monkeypatch):
    """The no-added-contact-surface claim, observed. One loader, called once per invocation."""
    from secp_operator_deployment import production_context

    calls = []
    ctx = production_context.VerifyContext(
        profile=valid_profile(),
        profile_load_reason=None,
        expected=None,
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


def test_the_structural_invariants_are_all_false_and_none_were_reached():
    """These must not grow a truthy field: a ``True`` here would be an admission."""
    effects = _report()["effects_of_this_queue_check"]
    assert set(effects) == {"measured_this_invocation", "structural_invariants"}
    assert set(effects["structural_invariants"]) == {
        "worker_constructed",
        "workflow_submitted",
        "run_plan_generation_called",
        "secret_resolver_constructed",
        "composition_aggregate_built",
        "host_mutated",
    }
    assert all(v is False for v in effects["structural_invariants"].values())


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
