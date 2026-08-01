"""Containment is THREE-valued: contained / breached / **unprovable**.

WHAT WAS WRONG
--------------
``RealManagementHostObserver`` probed the ordinary worker's self-declared served queues and, on any
probe failure, returned ``True`` — "assume a breach". Fail-closed, and therefore SAFE. But the
verdict it produced was indistinguishable from an actual observation of the worker polling the
controlled-live queue.

That is not a hypothetical. An interpreter path that does not resolve inside the worker image makes
the probe exit non-zero, and the old code turned that into a reported **containment breach on the
exact isolation property this program exists to guarantee**. A false "cannot certify" is an
inconvenience; a false "breach" is an alarm that gets acted on, so the damage runs in the direction
the old code chose.

THE RULE THIS ENCODES
---------------------
When a verification step can fail for the same reason as the thing it verifies, its answer is
uninformative and must surface as a THIRD state — never folded into either verdict. The probe that
could not ask must say "I could not ask", and say WHY.

WHAT DELIBERATELY DID NOT CHANGE
--------------------------------
Fail-closed behaviour. ``unprovable`` still refuses to certify and still exits non-zero;
``ordinary_polls_operator_queue`` is still True for it, so no existing consumer becomes more
permissive. Only the legibility of the reason changed.

THE DIRECTION THIS FIX COULD DO DAMAGE
--------------------------------------
Making a REAL breach look like an infrastructure hiccup would be strictly worse than the defect
being fixed. :func:`test_a_real_breach_is_never_absorbed_into_unprovable` is the guard against
exactly that, and it is mutation-verified rather than asserted.
"""

from __future__ import annotations

import pytest
from _mgmt_support import prepared_worker_world
from secp_management import ManagementError
from secp_management.adapters import (
    CONTAINMENT_BREACHED,
    CONTAINMENT_CONTAINED,
    CONTAINMENT_UNPROVABLE,
    CONTAINMENT_VERDICTS,
    resolve_queue_containment,
)
from secp_management.engine import _refusal_exit_code
from secp_management.transaction import EXIT_CONTAINMENT_UNPROVABLE, EXIT_OK, EXIT_REFUSED
from test_management_status import _worker_status
from test_real_observer_production import CommandResult, ObserverRunner, _observer

#: The two bounded causes. They are DIFFERENT remediations, which is why one code would not do:
#: the first means the runtime ran the probe and it refused; the second means the runtime itself
#: could not be invoked.
PROBE_FAILED = "queue_probe_command_failed"
RUNTIME_UNAVAILABLE = "queue_probe_runtime_unavailable"


class _QueueProbeRunner(ObserverRunner):
    """``ObserverRunner`` with the queue probe's two failure modes injectable.

    Subclassed rather than adding knobs to the shared fake: every other suite uses it, and this
    file must not change what they exercise.
    """

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001,ANN201
        a = tuple(argv_tail)
        if a and a[0] == "exec" and a[-1] == "queues":
            if self.k.get("probe_runtime_fault"):
                raise RuntimeError("container runtime could not be invoked")
            if self.k.get("probe_exit_nonzero"):
                return CommandResult(126, "")  # e.g. the interpreter path does not resolve
        return super().run(
            pin, argv_tail, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes
        )


def _observe(**knobs: object):  # noqa: ANN201
    return _observer(_QueueProbeRunner(**knobs)).observe_worker()


# ------------------------------------------------------- (1) all three verdicts are REACHABLE


def test_a_clean_host_is_observed_contained() -> None:
    obs = _observe()
    assert obs.ordinary_queue_containment == CONTAINMENT_CONTAINED
    assert obs.ordinary_queue_containment_reason is None
    assert obs.ordinary_polls_operator_queue is False  # certifies


def test_a_worker_serving_the_operator_queue_is_observed_breached() -> None:
    obs = _observe(polls_operator=True)
    assert obs.ordinary_queue_containment == CONTAINMENT_BREACHED
    assert obs.ordinary_queue_containment_reason is None  # observed, so there is no "why it failed"
    assert obs.ordinary_polls_operator_queue is True  # refuses


@pytest.mark.parametrize(
    ("knob", "expected_reason"),
    [("probe_exit_nonzero", PROBE_FAILED), ("probe_runtime_fault", RUNTIME_UNAVAILABLE)],
)
def test_a_probe_that_could_not_complete_is_unprovable_and_names_why(
    knob: str, expected_reason: str
) -> None:
    """The state that did not exist before, reachable by BOTH of its causes."""
    obs = _observe(**{knob: True})
    assert obs.ordinary_queue_containment == CONTAINMENT_UNPROVABLE
    assert obs.ordinary_queue_containment_reason == expected_reason
    assert obs.ordinary_polls_operator_queue is True  # STILL refuses — fail-closed is unchanged


def test_all_three_verdicts_are_produced_by_the_real_observer() -> None:
    """A third state nothing can produce is dead vocabulary.

    Asserted as set equality against the closed vocabulary, so a verdict that became unreachable
    fails here rather than lingering as a value the code can name but never emit.
    """
    produced = {
        _observe().ordinary_queue_containment,
        _observe(polls_operator=True).ordinary_queue_containment,
        _observe(probe_exit_nonzero=True).ordinary_queue_containment,
    }
    assert produced == set(CONTAINMENT_VERDICTS)


def test_the_two_causes_are_distinct_codes() -> None:
    """Naming WHY is the requirement; one code for both causes would only name THAT."""
    assert PROBE_FAILED != RUNTIME_UNAVAILABLE
    assert (
        _observe(probe_exit_nonzero=True).ordinary_queue_containment_reason
        != _observe(probe_runtime_fault=True).ordinary_queue_containment_reason
    )


# --------------------------------------- (2) the direction this fix could do damage


def test_a_real_breach_is_never_absorbed_into_unprovable() -> None:
    """The load-bearing safety property of the FIX itself.

    Making a genuine breach look like an infrastructure hiccup would be strictly worse than the
    defect being repaired. The probe succeeds here — it is a real observation — and must report
    ``breached``, never ``unprovable``, and must carry no failure reason.
    """
    obs = _observe(polls_operator=True)
    assert obs.ordinary_queue_containment == CONTAINMENT_BREACHED
    assert obs.ordinary_queue_containment != CONTAINMENT_UNPROVABLE
    assert obs.ordinary_queue_containment_reason is None

    # And the operator is still shown the BREACH, not a probe-failure reason.
    _code, status = _worker_status(
        prepared_worker_world(
            ordinary_polls_operator_queue=True, ordinary_queue_containment=CONTAINMENT_BREACHED
        )
    )
    assert status["dimensions"]["queue_containment"] == CONTAINMENT_BREACHED
    assert status["dimensions"]["queue_containment_reason"] is None


def test_a_stopped_worker_is_contained_not_unprovable() -> None:
    """Nothing running can poll nothing. That is an OBSERVATION, not an unfinished probe.

    Calling it ``unprovable`` would make an ordinary stopped worker indistinguishable from a broken
    probe — re-creating the same confusion one state over.
    """
    obs = _observe(ordinary_down=True)
    assert obs.ordinary_queue_containment == CONTAINMENT_CONTAINED
    assert obs.ordinary_queue_containment_reason is None


# ------------------------------------------------ (3) the operator-facing verdict + exit code


def test_the_operator_report_distinguishes_the_two_refusals_and_both_exit_nonzero() -> None:
    """End-to-end through ``secpctl status worker`` — the form an operator actually meets.

    Both refuse and both exit non-zero (fail-closed, unchanged). What is new is that the report
    says WHICH happened, and for ``unprovable`` says why.
    """
    breach_code, breached = _worker_status(
        prepared_worker_world(
            ordinary_polls_operator_queue=True, ordinary_queue_containment=CONTAINMENT_BREACHED
        )
    )
    unprov_code, unprovable = _worker_status(
        prepared_worker_world(
            ordinary_polls_operator_queue=True,
            ordinary_queue_containment=CONTAINMENT_UNPROVABLE,
            ordinary_queue_containment_reason=PROBE_FAILED,
        )
    )

    # Distinguishable in the report...
    assert breached["dimensions"]["queue_containment"] == CONTAINMENT_BREACHED
    assert unprovable["dimensions"]["queue_containment"] == CONTAINMENT_UNPROVABLE
    assert unprovable["dimensions"]["queue_containment_reason"] == PROBE_FAILED
    assert (
        breached["dimensions"]["queue_containment"] != unprovable["dimensions"]["queue_containment"]
    )

    # ...and IDENTICAL in their fail-closed effect: neither certifies, both non-zero.
    for code, report in ((breach_code, breached), (unprov_code, unprovable)):
        assert report["ok"] is False
        assert report["dimensions"]["no_operator_queue_polling"] is False
        assert code != 0

    # Control: a clean host certifies and reports contained, so the refusals above are about the
    # verdict rather than about this path never passing.
    ok_code, ok = _worker_status(prepared_worker_world())
    assert ok["dimensions"]["queue_containment"] == CONTAINMENT_CONTAINED
    assert ok["dimensions"]["queue_containment_reason"] is None
    assert ok["dimensions"]["no_operator_queue_polling"] is True
    assert ok_code == 0


# ------------------------------------------------- (3b) the exit code, DERIVED not transcribed


def test_the_verdict_to_exit_code_mapping_is_closed_and_derived_by_running_it() -> None:
    """verdict -> exit code, built by RUNNING each path rather than by typing the pairs.

    A table of expected pairs written by hand is a second copy of the mapping that agrees with
    itself; this drives ``secpctl status worker`` three times and reads what actually came back.
    Compared as a whole dict so a fourth verdict, a changed code, or a collapsed pair all fail.
    """
    observed = {
        CONTAINMENT_CONTAINED: _worker_status(prepared_worker_world())[0],
        CONTAINMENT_BREACHED: _worker_status(
            prepared_worker_world(
                ordinary_polls_operator_queue=True,
                ordinary_queue_containment=CONTAINMENT_BREACHED,
            )
        )[0],
        CONTAINMENT_UNPROVABLE: _worker_status(
            prepared_worker_world(
                ordinary_polls_operator_queue=True,
                ordinary_queue_containment=CONTAINMENT_UNPROVABLE,
                ordinary_queue_containment_reason=PROBE_FAILED,
            )
        )[0],
    }
    assert observed == {
        CONTAINMENT_CONTAINED: EXIT_OK,
        CONTAINMENT_BREACHED: EXIT_REFUSED,
        CONTAINMENT_UNPROVABLE: EXIT_CONTAINMENT_UNPROVABLE,
    }
    # The vocabulary and the mapping cover exactly the same verdicts — a verdict with no exit code
    # would exit as a generic refusal and be invisible to a shell.
    assert set(observed) == set(CONTAINMENT_VERDICTS)


def test_the_new_exit_code_is_additive_and_collides_with_nothing() -> None:
    """``secpctl`` is ONE binary with ONE exit-code namespace.

    ``enrollment_cli`` owns 3-9 and ``cli.py`` imports both it and ``transaction``, so a reused
    number would mean two conditions with one code in the same program.
    """
    from secp_management import enrollment_cli

    taken = {
        value
        for name, value in vars(enrollment_cli).items()
        if name.startswith("EXIT_") and isinstance(value, int)
    }
    assert EXIT_CONTAINMENT_UNPROVABLE not in taken
    assert EXIT_CONTAINMENT_UNPROVABLE not in {EXIT_OK, EXIT_REFUSED}
    assert EXIT_CONTAINMENT_UNPROVABLE != 0  # never mistakable for success


def test_every_other_refusal_still_exits_as_it_did() -> None:
    """Additive means additive: an unrelated refusal must be untouched.

    Without this, "distinct code for unprovable" could have been implemented by re-routing every
    refusal, which would be a silent contract change for every existing consumer.
    """
    code, report = _worker_status(prepared_worker_world(operator_running=True))
    assert report["ok"] is False
    assert code == EXIT_REFUSED  # NOT the new code
    assert _refusal_exit_code("some_unrelated_reason") == EXIT_REFUSED
    assert _refusal_exit_code(None) == EXIT_REFUSED


# ---------------------------------------------------------- (4) back-compat of the resolver


def test_an_observation_predating_the_field_is_read_as_contained_or_breached_never_unprovable() -> (
    None
):
    """``resolve_queue_containment`` must never INVENT the third state.

    Only the probe knows it could not ask. Deriving "unprovable" from a bare boolean would
    manufacture the very ambiguity this change removes, in the opposite direction.
    """

    class _Legacy:
        ordinary_queue_containment = ""
        ordinary_queue_containment_reason = None

        def __init__(self, polls: bool) -> None:
            self.ordinary_polls_operator_queue = polls

    assert resolve_queue_containment(_Legacy(False)) == CONTAINMENT_CONTAINED  # type: ignore[arg-type]
    assert resolve_queue_containment(_Legacy(True)) == CONTAINMENT_BREACHED  # type: ignore[arg-type]
    for polls in (True, False):
        assert resolve_queue_containment(_Legacy(polls)) != CONTAINMENT_UNPROVABLE  # type: ignore[arg-type]


def test_an_unrecognised_verdict_falls_back_to_the_fail_closed_boolean() -> None:
    """A garbage verdict must not be trusted as a pass."""

    class _Garbage:
        ordinary_queue_containment = "definitely-fine-honest"
        ordinary_queue_containment_reason = None
        ordinary_polls_operator_queue = True

    assert resolve_queue_containment(_Garbage()) == CONTAINMENT_BREACHED  # type: ignore[arg-type]


def test_management_error_reason_codes_stay_bounded() -> None:
    """The ``why`` is a bounded code, never an upstream message or host string."""
    for code in (PROBE_FAILED, RUNTIME_UNAVAILABLE):
        assert ManagementError(code).reason_code == code
        assert code.replace("_", "").isalnum()
        assert " " not in code and "/" not in code
