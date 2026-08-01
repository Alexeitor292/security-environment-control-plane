"""The operator plane and the worker plane share ONE queue contract — proven at runtime.

This is the integration branch's cross-stream proof. The two streams it joins read the ordinary
queue name through different artefacts and, before this branch, neither could observe the other
drifting (see ``apps/deployment/tests/test_operator_worker_queue_binding.py`` for the mechanism and
the pre-change measurement).

WHY THIS FILE DOES NOT COMPARE NAMES
------------------------------------
Asserting that two constants both spell "secp-orchestration" is exactly the check that was already
passing while the contract was open. So the binding here is taken from the CONSTRUCTED worker: the
shipped entrypoint is driven with a fake Temporal, the ``task_queue`` argument handed to the
``Worker`` constructor is RECORDED, and the operator plane's authority is required to equal that
recorded argument. The subject is a value that a running worker produced, not a literal.

WHY THE OBSERVATIONS ARE POSITIVE
---------------------------------
"The operator queue was never polled" is not asserted from the absence of a log line or the absence
of a string. Every ``Worker`` construction is recorded, and the assertions are made on the record:
the construction count is EXACTLY one, that one construction names the ordinary queue, and the
readiness call the worker made — which the entrypoint issues only after the worker is confirmed
running — names the same queue. A worker that never started produces a count of zero and no
readiness call, and fails all three; that case is RUN here rather than argued, which is what makes
the observation mean something.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys
import threading

import pytest

pytest.importorskip("temporalio")

# The deployment suite's fixtures build a VALID profile/pins pair whose digests match the actual
# package manifest. Reproducing that here would mean a second copy that could drift from the one the
# deployment plane actually validates against — the exact failure mode this file exists to close.
# Its directory is not on ``pythonpath`` (only the package dir is), so it is added once here.
_DEPLOY_TESTS = pathlib.Path(__file__).resolve().parents[1] / "apps" / "deployment" / "tests"
sys.path.insert(0, str(_DEPLOY_TESTS))

ORDINARY = "secp-orchestration"
#: The real deployed operator-queue value. Legitimate, and deliberately CONFIGURED in the run below
#: so that "the worker did not poll it" is a statement about a queue that was actually available to
#: be polled, rather than about an empty string that could not have been polled either way.
OPERATOR = "secp-controlled-live-v1"

_LEGACY_STARTERS = (
    "_start_staging_lab_consumer",
    "_start_readonly_preflight_consumer",
    "_start_deployment_consumer",
    "_start_discovery_consumer",
    "_start_discovery_bundle_prep",
)


class _RecordingWorker:
    """Records every construction. A list, not a dict: the COUNT is part of the evidence, and a
    dict would silently keep only the last of several constructions."""

    constructions: list[dict] = []

    def __init__(self, client, *, task_queue, workflows, activities):  # noqa: ANN001, ANN204
        type(self).constructions.append(
            {
                "task_queue": task_queue,
                "workflows": list(workflows),
                "activities": list(activities),
            }
        )

    async def run(self):  # noqa: ANN202
        # Must NOT complete on the first event-loop turn. ``_run_temporal`` yields once and treats
        # an already-finished ``run()`` as an immediate startup failure/shutdown, returning BEFORE
        # readiness is marked — so a run() that returns instantly gets the Worker constructed but
        # never exercises the polling path, and the readiness evidence below would be empty for a
        # reason that has nothing to do with which queue was polled.
        for _ in range(3):
            await asyncio.sleep(0)
        return None


def _run_shipped_worker(monkeypatch, tmp_path, *, operator_queue: str):
    """Drive the SHIPPED entrypoint with a fake Temporal.

    Returns ``(constructions, ready_calls, settings)``. Readiness is captured as the CALL, not as
    the marker file: ``_run_temporal`` clears the marker in a ``finally``, so by the time the run
    returns the file is gone on every path — reading it afterwards would report the same empty
    result for a worker that started and one that never did, which is precisely the confusion these
    tests exist to prevent.
    """
    import temporalio.client
    import temporalio.worker
    from secp_api.config import Settings
    from secp_worker import health, main

    settings = Settings(temporal_task_queue=ORDINARY, temporal_operator_task_queue=operator_queue)

    _RecordingWorker.constructions = []
    ready_calls: list[str] = []
    real_mark_ready = health.mark_ready

    def _recording_mark_ready(queue):  # noqa: ANN001, ANN202
        ready_calls.append(queue)
        return real_mark_ready(queue)

    monkeypatch.setattr(health, "mark_ready", _recording_mark_ready)

    async def _fake_connect(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        return object()

    async def _noop():  # noqa: ANN202
        return None

    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(temporalio.client.Client, "connect", _fake_connect)
    monkeypatch.setattr(temporalio.worker, "Worker", _RecordingWorker)
    for name in _LEGACY_STARTERS:
        monkeypatch.setattr(main, name, lambda _ev: None)
    monkeypatch.setattr(main, "_run_outbox_publisher_loop", _noop)

    ready_file = tmp_path / "secp-worker.ready"
    monkeypatch.setenv("SECP_WORKER_READY_FILE", str(ready_file))

    asyncio.run(main._run_temporal(threading.Event()))

    return list(_RecordingWorker.constructions), ready_calls, settings


# --------------------------------------------------------------- (1) one contract, read at runtime


def test_the_operator_authority_equals_the_queue_the_worker_was_constructed_on(
    monkeypatch, tmp_path
):
    """The load-bearing cross-plane assertion.

    ``worker_ordinary_task_queue`` is the value the operator plane anchors its trusted pins to. The
    right-hand side is not a constant — it is the argument a ``Worker`` was actually built with.
    """
    from secp_operator_deployment.identities import worker_ordinary_task_queue

    constructions, _, _ = _run_shipped_worker(monkeypatch, tmp_path, operator_queue=OPERATOR)

    assert len(constructions) == 1
    assert worker_ordinary_task_queue() == constructions[0]["task_queue"]


def test_the_operator_pins_accept_exactly_the_constructed_queue_and_refuse_its_neighbours(
    monkeypatch, tmp_path
):
    """Run the operator's real cross-check against the queue the worker was built on.

    Accepting the constructed value alone is weak — a check that accepted everything would also
    accept it. So the near-miss neighbours are required to be REFUSED, with the exact reason code.
    """
    from _deploy_support import valid_expected
    from secp_operator_deployment.identities import IdentityError, assert_expected_package_identity

    constructions, _, _ = _run_shipped_worker(monkeypatch, tmp_path, operator_queue=OPERATOR)
    constructed = constructions[0]["task_queue"]

    assert_expected_package_identity(valid_expected(ordinary_task_queue=constructed))  # accepted

    refusals = set()
    for near_miss in (constructed + "-v2", constructed.upper(), constructed.rstrip("n"), OPERATOR):
        with pytest.raises(IdentityError) as exc:
            assert_expected_package_identity(valid_expected(ordinary_task_queue=near_miss))
        refusals.add(exc.value.reason_code)
    # Membership, not a count: an equal number of refusals carrying a different code would mean the
    # refusals came from somewhere else entirely.
    assert refusals == {"expected_ordinary_queue_not_worker_queue"}


# ------------------------------------------ (2) the ordinary worker never polls the operator queue


def test_the_worker_started_and_polled_only_the_ordinary_queue(monkeypatch, tmp_path):
    """A POSITIVE observation, stated as what was seen.

    Observed: exactly one ``Worker`` construction; its ``task_queue`` is the ordinary queue; and the
    worker marked itself ready for that same queue. The operator queue was configured to its real
    deployed value throughout, so it was available to be polled and was not.

    This could NOT be satisfied by a worker that never started: that produces zero constructions and
    zero readiness calls, and each of the three assertions below fails on it. The companion test
    below runs that case rather than leaving the reasoning to the reader.
    """
    constructions, ready_calls, settings = _run_shipped_worker(
        monkeypatch, tmp_path, operator_queue=OPERATOR
    )

    assert len(constructions) == 1, "the shipped worker was not constructed exactly once"
    assert constructions[0]["task_queue"] == ORDINARY
    # Readiness is marked only AFTER the Worker is constructed and CONFIRMED running, so this is a
    # second, independent witness that the worker reached functional polling on that queue.
    assert ready_calls == [ORDINARY]

    # The operator queue was configured and distinct — so "not polled" is a real negative.
    assert settings.temporal_operator_task_queue == OPERATOR
    assert OPERATOR != ORDINARY
    queues_polled = [c["task_queue"] for c in constructions]
    assert OPERATOR not in queues_polled
    assert queues_polled == [ORDINARY]  # exact, not a floor


def test_a_worker_that_never_started_would_fail_the_observation_above(monkeypatch, tmp_path):
    """Prove the previous test's discriminating power instead of asserting it.

    The entrypoint is made to fail before construction; the same evidence is gathered and shown to
    be EMPTY. Without this, 'a worker that never started would fail' is a claim about a
    counterfactual nobody ran.
    """
    import temporalio.client
    import temporalio.worker
    from secp_api.config import Settings
    from secp_worker import health, main

    _RecordingWorker.constructions = []
    ready_calls: list[str] = []

    async def _failing_connect(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("temporal unreachable")

    monkeypatch.setattr(main, "get_settings", lambda: Settings(temporal_task_queue=ORDINARY))
    monkeypatch.setattr(temporalio.client.Client, "connect", _failing_connect)
    monkeypatch.setattr(temporalio.worker, "Worker", _RecordingWorker)
    monkeypatch.setattr(health, "mark_ready", lambda q: ready_calls.append(q))
    ready_file = tmp_path / "secp-worker.ready"
    monkeypatch.setenv("SECP_WORKER_READY_FILE", str(ready_file))

    with pytest.raises(RuntimeError):
        asyncio.run(main._run_temporal(threading.Event()))

    # The SAME two pieces of evidence the test above asserts on, gathered the same way, both empty.
    assert _RecordingWorker.constructions == []  # zero, not "not the operator queue"
    assert ready_calls == []
    assert not ready_file.exists()


def test_the_entrypoint_never_reads_the_operator_queue_on_the_loaded_object():
    """Structural companion to the runtime observation, keyed on the COMPILED function.

    ``co_names`` is read off the loaded code object, so a mention of the setting in a docstring or
    comment — which ``main`` deliberately contains, to explain the omission — cannot satisfy it.
    """
    from secp_worker import main

    names = set(main._run_temporal.__code__.co_names)
    assert "temporal_task_queue" in names
    assert "temporal_operator_task_queue" not in names
    # Non-vacuity: the sentinel really is the kind of name that appears in co_names, so its absence
    # is evidence rather than an artefact of looking in the wrong place.
    assert "temporal_host" in names


# ------------------------------------------------------- (3) the operator side stays sealed + still


def test_the_reviewed_submission_stops_are_all_closed():
    """Every stop is READ from its reviewed constant, and all four must be closed."""
    from secp_operator_deployment.queue_check import SUBMISSION_STOPS, observe_submission_stops

    rows = observe_submission_stops()
    assert len(rows) == len(SUBMISSION_STOPS) == 4
    open_stops = {r["id"] for r in rows if not r["closed"]}
    assert open_stops == set()  # membership, so a swapped stop cannot hide behind an equal count
    unobservable = {r["id"] for r in rows if r["reason_code"] is not None}
    assert unobservable == set()


def test_a_prepared_host_reports_the_operator_dormant_and_the_check_can_say_otherwise():
    """Disabled + stopped, and the report is shown capable of the opposite verdict.

    A dormancy check that returned "dormant" for every input would pass the first half. The second
    half drives an ENABLED+RUNNING host through the same builder and requires the contrary status.
    """
    from _deploy_support import host_evidence, valid_profile
    from secp_operator_deployment.queue_check import build_queue_report

    dormant = build_queue_report(
        profile=valid_profile(), host_observation=host_evidence(enabled=False, running=False)
    )
    assert dormant["operator_consumer"]["unit_enabled"] is False
    assert dormant["operator_consumer"]["unit_running"] is False
    assert dormant["operator_consumer"]["dormant"] is True
    assert dormant["status"] == "queue_isolated_and_dormant"
    assert dormant["exit_code"] == 0
    assert dormant["submission_preview"]["submission_performed"] is False

    active = build_queue_report(
        profile=valid_profile(), host_observation=host_evidence(enabled=True, running=True)
    )
    assert active["operator_consumer"]["dormant"] is False
    assert active["status"] == "queue_operator_consuming"
    assert active["exit_code"] == 14


def test_the_operator_activation_seal_is_closed():
    from secp_operator_deployment import runner

    assert runner._OPERATOR_ACTIVATION_SEALED is True
