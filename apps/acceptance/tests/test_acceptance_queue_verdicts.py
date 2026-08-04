"""The queues stage's verdict vocabulary and its ONE encoding into the evidence document.

This file exists because of a single failure mode: the three containment values collapsing into
two. ``unprovable`` folded into ``breached`` is a FALSE ALARM on the exact isolation property the
management plane exists to guarantee — and false alarms get acted on. ``breached`` folded into
``unprovable`` is the opposite and worse: the most serious finding the queues stage can produce,
recorded identically to a transport error.

So the guards here are about DISTINCTNESS and about NON-VACUITY, not about whether the words are
spelled right. Two of them are load-bearing in a way worth naming before changing anything:

* :func:`test_the_three_verdicts_encode_to_three_distinct_records` is the anti-collapse guard. It
  compares the encodings pairwise rather than asserting each against a literal, so an edit that made
  two verdicts encode identically fails here even if both new values are individually plausible.
* :func:`test_the_encoding_table_covers_exactly_the_product_verdicts` is the anti-drift guard. The
  vocabulary is the PRODUCT's, so a fourth containment verdict added in ``secp_management`` must
  fail the harness build rather than falling through to a default.
"""

from __future__ import annotations

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.queues import (
    VERDICT_ENCODING,
    VERDICT_HELD,
    VERDICT_UNPROVABLE,
    VERDICT_VIOLATED,
    VERDICTS,
    QueueVerdict,
    encode_verdict,
    record_verdict,
)
from secp_acceptance.reasons import (
    ALL_REASONS,
    CHECKS_BY_STAGE,
    OUTCOME_OBSERVED,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
    PASSING_OUTCOMES,
    STAGE_QUEUES,
)
from secp_acceptance.recorder import AcceptanceRecorder

#: A cause that is a real member of the closed vocabulary, used wherever the specific code does not
#: matter to the property under test.
_CAUSE = "acceptance_observation_unavailable"


def _one_of_each() -> dict[str, QueueVerdict]:
    return {
        VERDICT_HELD: QueueVerdict(VERDICT_HELD),
        VERDICT_VIOLATED: QueueVerdict(VERDICT_VIOLATED, cause=_CAUSE),
        VERDICT_UNPROVABLE: QueueVerdict(VERDICT_UNPROVABLE, cause=_CAUSE),
    }


# --------------------------------------------------------------------------- the vocabulary itself


def test_the_verdict_vocabulary_is_the_products_own_constants():
    """NOT copies. A rename in ``secp_management.adapters`` must break the harness build.

    Compared by VALUE against a fresh import, because that is the whole claim: these three names are
    aliases, so if someone replaces the binding with three literals that happen to match today, this
    keeps passing — and correctly so, until the product renames one, at which point it fails. The
    identity of the source is what :func:`test_the_vocabulary_is_bound_not_restated` covers.
    """
    from secp_management.adapters import (
        CONTAINMENT_BREACHED,
        CONTAINMENT_CONTAINED,
        CONTAINMENT_UNPROVABLE,
    )

    assert VERDICT_HELD == CONTAINMENT_CONTAINED
    assert VERDICT_VIOLATED == CONTAINMENT_BREACHED
    assert VERDICT_UNPROVABLE == CONTAINMENT_UNPROVABLE


def test_the_vocabulary_is_bound_not_restated():
    """The harness must not carry its own copy of the three strings.

    Checked as source text, because the property is "this module does not declare these literals" —
    importing it would prove only that the values agree today, which is exactly what a copy also
    does. The bind happens in ``_product_containment_verdicts``, which is an import and a return.
    """
    import inspect

    from secp_acceptance import queues

    source = inspect.getsource(queues._product_containment_verdicts)
    for literal in (VERDICT_HELD, VERDICT_VIOLATED, VERDICT_UNPROVABLE):
        assert f'"{literal}"' not in source and f"'{literal}'" not in source, (
            f"{literal!r} is written as a literal in the binding function. The point of that "
            f"function is that the harness holds no copy of the product's vocabulary."
        )


def test_the_three_verdicts_are_pairwise_distinct():
    assert len(set(VERDICTS)) == 3


def test_the_encoding_table_covers_exactly_the_product_verdicts():
    """ANTI-DRIFT. A fourth containment verdict in the product must fail here, not default.

    Derived from ``CONTAINMENT_VERDICTS`` rather than from :data:`VERDICTS`, so the expectation is
    not produced by the same module under test — a mutation that dropped a row from the encoding
    table and a member from ``VERDICTS`` in step would otherwise still pass.
    """
    from secp_management.adapters import CONTAINMENT_VERDICTS

    assert set(VERDICT_ENCODING) == set(CONTAINMENT_VERDICTS)


# --------------------------------------------------------------------------- anti-collapse


def test_the_three_verdicts_encode_to_three_distinct_records():
    """THE guard this file exists for. No two verdicts may produce the same evidence record.

    Pairwise, not against literals: the property is that a reader can tell the three apart, and an
    edit that made two of them agree is a failure regardless of what the agreed value is.
    """
    encoded = {verdict: encode_verdict(v) for verdict, v in _one_of_each().items()}
    assert len(set(encoded.values())) == 3, (
        f"two verdicts encode identically, so a reader of the evidence cannot tell them apart: "
        f"{encoded}"
    )


def test_exactly_one_verdict_can_ever_be_a_pass():
    """``held`` is the only verdict that may produce ``observed``.

    ``violated`` and ``unprovable`` must both land on an outcome a ``passed`` run cannot contain.
    The evidence loader refuses a ``passed`` document carrying any ``unproven`` check, so this is
    what makes the queues stage unable to pass on either a violation or an outage.
    """
    passes = [
        verdict for verdict, v in _one_of_each().items() if encode_verdict(v)[0] == OUTCOME_OBSERVED
    ]
    assert passes == [VERDICT_HELD]


def test_neither_a_violation_nor_an_outage_is_ever_recorded_as_refused():
    """``refused`` means "the product refused, and that refusal IS the expected result".

    Neither a queue-isolation violation nor a failed probe is an expected refusal, so borrowing that
    outcome would make the queues stage look like a successful failure-injection.
    """
    for verdict in (VERDICT_VIOLATED, VERDICT_UNPROVABLE):
        outcome, _ = encode_verdict(_one_of_each()[verdict])
        assert outcome != OUTCOME_REFUSED
        assert outcome not in PASSING_OUTCOMES


def test_a_violation_and_an_outage_no_longer_share_an_outcome():
    """THE line that documented the gap, now documenting its closure.

    This test previously asserted ``violated_outcome == outage_outcome`` with a note that a fourth
    outcome would change exactly this line. The fourth outcome landed, so it did. A proven breach
    and a probe that could not run are now separated at the OUTCOME level, not merely by reason
    code — which is what makes them distinguishable to a reader who filters on outcome.
    """
    violated_outcome, violated_reason = encode_verdict(_one_of_each()[VERDICT_VIOLATED])
    outage_outcome, outage_reason = encode_verdict(_one_of_each()[VERDICT_UNPROVABLE])
    assert violated_outcome == OUTCOME_VIOLATED
    assert outage_outcome == OUTCOME_UNPROVEN
    assert violated_outcome != outage_outcome
    assert violated_reason != outage_reason
    assert violated_reason is not None and outage_reason is not None


def test_a_violation_carries_the_contracts_single_prohibited_state_code():
    """One code for every violated check, by the contract's design: the CHECK ID already names the
    property, and a per-check code set would grow past review."""
    _, reason = encode_verdict(_one_of_each()[VERDICT_VIOLATED])
    assert reason == "acceptance_prohibited_state_observed"
    assert reason in ALL_REASONS


def test_the_producers_specific_cause_survives_into_the_observation():
    """The contract's single violated code is the DOCUMENT's reason. The producer's more specific
    tell — which of the four operator-unit signs fired, say — must not be silently dropped on the
    way there, so the funnel puts it in the bounded observation the check asserted on."""
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    captured: dict = {}

    class _Capturing(AcceptanceRecorder):
        def violated(self, check, stage, *, reason_code, observation):  # type: ignore[override]
            captured.update({"reason_code": reason_code, "observation": dict(observation)})
            super().violated(check, stage, reason_code=reason_code, observation=observation)

    run = _Capturing()
    run.open_stage(STAGE_QUEUES)
    record_verdict(
        run,
        "operator_unit_never_activated",
        QueueVerdict(VERDICT_VIOLATED, cause="worker_operator_not_disabled_stopped"),
    )
    assert captured["reason_code"] == "acceptance_prohibited_state_observed"
    assert captured["observation"]["observed_cause"] == "worker_operator_not_disabled_stopped"


def test_an_outage_carries_the_cause_the_producer_observed_not_a_fixed_code():
    """The two containment causes have different remediations, so the encoding must not flatten
    them into one generic code."""
    encodings = {
        cause: encode_verdict(QueueVerdict(VERDICT_UNPROVABLE, cause=cause))[1]
        for cause in ("queue_probe_command_failed", "queue_probe_runtime_unavailable")
    }
    assert encodings == {
        "queue_probe_command_failed": "queue_probe_command_failed",
        "queue_probe_runtime_unavailable": "queue_probe_runtime_unavailable",
    }


# --------------------------------------------------------------------------- verdict coherence


def test_a_held_verdict_may_not_carry_a_cause():
    """A positive observation that also carries a refusal reason is incoherent — the same rule
    ``CheckRecord`` applies, enforced early so it cannot travel as far as the recorder."""
    with pytest.raises(AcceptanceError):
        QueueVerdict(VERDICT_HELD, cause=_CAUSE)


@pytest.mark.parametrize("verdict", [VERDICT_VIOLATED, VERDICT_UNPROVABLE])
def test_a_non_held_verdict_must_carry_a_cause(verdict: str):
    with pytest.raises(AcceptanceError):
        QueueVerdict(verdict)


def test_a_cause_outside_the_closed_vocabulary_is_refused():
    with pytest.raises(AcceptanceError):
        QueueVerdict(VERDICT_UNPROVABLE, cause="something_i_just_made_up")


def test_an_unknown_verdict_is_refused():
    with pytest.raises(AcceptanceError):
        QueueVerdict("probably_fine")


# --------------------------------------------------------------------------- the recorder funnel


def test_recording_a_held_verdict_produces_an_observed_check():
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    record_verdict(recorder, "ordinary_queue_has_live_poller", QueueVerdict(VERDICT_HELD))
    sealed = recorder._checks[0]
    assert sealed.outcome == OUTCOME_OBSERVED
    assert sealed.reason_code is None
    assert sealed.stage == STAGE_QUEUES


@pytest.mark.parametrize(
    ("verdict", "expected_outcome"),
    [(VERDICT_VIOLATED, OUTCOME_VIOLATED), (VERDICT_UNPROVABLE, OUTCOME_UNPROVEN)],
)
def test_recording_a_non_held_verdict_is_never_a_pass(verdict: str, expected_outcome: str):
    """The property that matters most: neither a violation nor an outage can produce a passing run.

    Recorded through the real recorder, so this asserts on what the EVIDENCE says rather than on
    what the encoding returned — the recorder is what a run actually calls. The two land on
    DIFFERENT outcomes now; the property they SHARE is membership — neither is in
    ``PASSING_OUTCOMES``, which is the allowlist the run verdict is derived from.
    """
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    record_verdict(recorder, "operator_queue_has_zero_pollers", QueueVerdict(verdict, cause=_CAUSE))
    sealed = recorder._checks[0]
    assert sealed.outcome == expected_outcome
    assert sealed.outcome not in PASSING_OUTCOMES
    assert sealed.reason_code is not None


def test_a_check_from_another_stage_cannot_be_filed_under_queues():
    """A queue proof filed under a check the queues stage does not declare would be read later as if
    some other stage had proven it."""
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    with pytest.raises(AcceptanceError):
        record_verdict(recorder, "worker_status_ok", QueueVerdict(VERDICT_HELD))


def test_every_queues_check_is_recordable_through_the_funnel():
    """NON-VACUITY for the funnel. All six declared checks must be reachable through it, or a check
    would have to be recorded some other way — and the single-funnel property would be fiction."""
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    for check in CHECKS_BY_STAGE[STAGE_QUEUES]:
        record_verdict(recorder, check, QueueVerdict(VERDICT_HELD))
    assert recorder.missing() == ()


def _seal(recorder: AcceptanceRecorder):
    from secp_acceptance.evidence import FleetRecord, ReleaseRecord

    return recorder.seal(
        fleet=FleetRecord(
            host_image_identity="sha256:" + "0" * 64,
            controller_host_identity="sha256:" + "1" * 64,
            worker_host_identity="sha256:" + "2" * 64,
            network_identity="sha256:" + "3" * 64,
            hosts_created=2,
            hosts_destroyed=2,
            nested_container_runtime=True,
            real_service_manager=True,
        ),
        release=ReleaseRecord(
            role="worker",
            baseline_aggregate="sha256:" + "4" * 64,
            baseline_source_sha="a" * 40,
            signing_anchor_id="test-anchor",
            test_only_anchor=True,
        ),
    )


# THESE TWO ASSERT AT CHECK LEVEL, NOT RUN LEVEL, AND THAT IS DELIBERATE.
#
# They used to assert on ``evidence.outcome`` (``passed`` / ``failed``). That stopped being
# meaningful when the contract made a passing run require ALL NINE stages: a single-stage seal is
# now ``failed`` no matter what its checks say — measured, not assumed — so ``assert outcome ==
# "failed"`` had become satisfiable by a stage whose every check was ``observed``. A canary that
# cannot distinguish the thing it was watching for is worse than no canary, because it still looks
# like coverage. The run-level rule is the contract's property and E owns its tests; what THIS
# stage owns is which outcome each of its checks lands on.


def test_every_held_verdict_lands_on_a_passing_outcome():
    """The positive control. If the encoding could never produce a passing check, every guard above
    would be satisfied by a stage that can only fail."""
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    for check in CHECKS_BY_STAGE[STAGE_QUEUES]:
        record_verdict(recorder, check, QueueVerdict(VERDICT_HELD))
    evidence = _seal(recorder)
    assert evidence.not_passing() == ()
    assert evidence.violated() == ()
    assert evidence.unproven() == ()
    assert evidence.coverage_complete()


def test_one_violated_check_is_enough_to_make_the_stage_not_passing():
    """The MUTATION of the control above: flip one verdict and it must leave the passing set.

    Asserts on ``not_passing()`` and ``violated()`` rather than on the run outcome, so an encoding
    that mapped ``violated`` to ``observed`` fails here — which the old run-level assertion would no
    longer have caught.
    """
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    checks = CHECKS_BY_STAGE[STAGE_QUEUES]
    record_verdict(recorder, checks[0], QueueVerdict(VERDICT_VIOLATED, cause=_CAUSE))
    for check in checks[1:]:
        record_verdict(recorder, check, QueueVerdict(VERDICT_HELD))
    evidence = _seal(recorder)
    assert evidence.violated() == (checks[0],)
    assert evidence.not_passing() == (checks[0],)
    # ...and it is NOT filed as an outage: that is the whole point of the fourth outcome
    assert evidence.unproven() == ()


def test_an_outage_is_not_filed_as_a_violation():
    """The opposite direction, so the two are pinned apart from both sides."""
    recorder = AcceptanceRecorder()
    recorder.open_stage(STAGE_QUEUES)
    checks = CHECKS_BY_STAGE[STAGE_QUEUES]
    record_verdict(recorder, checks[0], QueueVerdict(VERDICT_UNPROVABLE, cause=_CAUSE))
    for check in checks[1:]:
        record_verdict(recorder, check, QueueVerdict(VERDICT_HELD))
    evidence = _seal(recorder)
    assert evidence.unproven() == (checks[0],)
    assert evidence.violated() == ()
    assert evidence.not_passing() == (checks[0],)
