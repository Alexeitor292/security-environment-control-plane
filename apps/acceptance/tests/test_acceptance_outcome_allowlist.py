"""A run passes only on outcomes that were REVIEWED as passing.

WHY THIS FILE EXISTS
--------------------
The verdict predicate used to be a denylist: *pass unless something is ``unproven``*. That shape
looks equivalent to the allowlist and is not, in one specific and load-bearing way — **every outcome
added to the vocabulary becomes a passing outcome by default.**

That is not hypothetical. Adding ``violated`` as a one-line vocabulary edit (the obvious way to do
it, and the way it was originally scoped) was measured to produce a document carrying a PROVEN
VIOLATION that sealed and loaded as ``passed``. The closed vocabulary was the only thing holding
that shut, and it stops holding in exactly the commit that widens it.

So the predicate is now stated over :data:`~secp_acceptance.reasons.PASSING_OUTCOMES`, and this file
proves the property that matters: an outcome nobody reviewed CANNOT pass, whether or not anyone
remembers to come back here.
"""

from __future__ import annotations

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import FleetRecord, ReleaseRecord, evidence_from_dict
from secp_acceptance.reasons import (
    CHECKS_BY_STAGE,
    OUTCOME_OBSERVED,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
    OUTCOMES,
    PASSING_OUTCOMES,
    RUN_FAILED,
    RUN_PASSED,
    STAGE_FAILURE_INJECTION,
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
    baseline_source_sha="a" * 40,
    signing_anchor_id="sha256:" + "7" * 64,
    test_only_anchor=True,
)


def _fully_covered() -> AcceptanceRecorder:
    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            rec.observe(check, stage, {"check": check})
    return rec


# --------------------------------------------------------------------------- the vocabulary


def test_the_passing_outcomes_are_a_strict_subset_of_the_vocabulary():
    """If these were equal, the allowlist would permit everything and prove nothing."""
    assert PASSING_OUTCOMES < OUTCOMES
    assert PASSING_OUTCOMES == {OUTCOME_OBSERVED, OUTCOME_REFUSED}


def test_the_two_failing_outcomes_are_both_outside_the_allowlist():
    """``unproven`` (could not look) and ``violated`` (looked, saw the bad thing) are opposites, and
    neither may pass. They are separate values so a reader can tell which happened."""
    assert OUTCOME_UNPROVEN not in PASSING_OUTCOMES
    assert OUTCOME_VIOLATED not in PASSING_OUTCOMES
    assert OUTCOME_UNPROVEN != OUTCOME_VIOLATED


# --------------------------------------------------------------------------- the verdict


def test_a_violated_check_fails_the_run_at_seal():
    rec = AcceptanceRecorder()
    rec.open_stage(STAGE_QUEUES)
    for check in CHECKS_BY_STAGE[STAGE_QUEUES]:
        if check == "operator_queue_has_zero_pollers":
            rec.violated(
                check,
                STAGE_QUEUES,
                reason_code="acceptance_prohibited_state_observed",
                observation={"pollers": 1},
            )
        else:
            rec.observe(check, STAGE_QUEUES, {})
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.outcome == RUN_FAILED
    assert ev.violated() == ("operator_queue_has_zero_pollers",)
    # and it is NOT reported as a failure to look
    assert ev.unproven() == ()


def test_a_violated_check_cannot_be_hand_written_into_a_passed_document():
    """The loader is the authority. A document asserting ``passed`` while carrying a violation is
    refused on load, not merely disbelieved."""
    ev = _fully_covered().seal(fleet=_FLEET, release=_RELEASE)
    assert ev.outcome == RUN_PASSED  # control: it really was passing before the edit
    payload = ev.canonical()
    payload["checks"][0]["outcome"] = OUTCOME_VIOLATED
    payload["checks"][0]["reason_code"] = "acceptance_prohibited_state_observed"
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_incomplete"


def test_violated_and_unproven_are_reported_separately_on_the_document():
    """The two failure modes must be distinguishable by a reader without decoding reason codes."""
    rec = AcceptanceRecorder()
    rec.open_stage(STAGE_QUEUES)
    checks = list(CHECKS_BY_STAGE[STAGE_QUEUES])
    rec.violated(
        checks[0], STAGE_QUEUES, reason_code="acceptance_prohibited_state_observed", observation={}
    )
    rec.unproven(
        checks[1], STAGE_QUEUES, reason_code="acceptance_observation_unavailable", observation={}
    )
    for check in checks[2:]:
        rec.observe(check, STAGE_QUEUES, {})
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.violated() == (checks[0],)
    assert ev.unproven() == (checks[1],)
    assert set(ev.not_passing()) == {checks[0], checks[1]}


# --------------------------------------------------------------------------- the real property


def test_an_outcome_NOBODY_REVIEWED_cannot_pass(monkeypatch):
    """THE test in this file, and the one that outlives everything else here.

    Simulate the next person widening the vocabulary: a fifth outcome is added to ``OUTCOMES`` and
    nothing else is touched — no predicate updated, no test written, this file not read. Under the
    old denylist that document sealed and loaded as ``passed``. Under the allowlist it must fail
    CLOSED, because the new value is simply not in ``PASSING_OUTCOMES``.

    Patched on the evidence module, which is where the loader resolves the name — patching
    ``reasons`` alone would leave the already-bound import untouched and the test would prove
    nothing.
    """
    import secp_acceptance.evidence as evidence_module

    ev = _fully_covered().seal(fleet=_FLEET, release=_RELEASE)
    assert ev.outcome == RUN_PASSED

    monkeypatch.setattr(
        evidence_module, "OUTCOMES", frozenset(OUTCOMES | {"tolerated"}), raising=True
    )
    payload = ev.canonical()
    payload["checks"][0]["outcome"] = "tolerated"
    payload["checks"][0]["reason_code"] = "acceptance_observation_unavailable"

    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_incomplete"


def test_the_fifth_outcome_probe_is_not_vacuous(monkeypatch):
    """CONTROL for the test above.

    If the unknown outcome were rejected merely for being outside ``OUTCOMES``, the previous test
    would pass without saying anything about the ALLOWLIST — it would be measuring the closed
    vocabulary, which is a different guard. Here the same value is admitted to the vocabulary and
    the document is marked ``failed``: it must then LOAD FINE. That is what proves the refusal above
    came from the pass predicate and not from vocabulary membership.
    """
    import secp_acceptance.evidence as evidence_module

    ev = _fully_covered().seal(fleet=_FLEET, release=_RELEASE)
    monkeypatch.setattr(
        evidence_module, "OUTCOMES", frozenset(OUTCOMES | {"tolerated"}), raising=True
    )
    payload = ev.canonical()
    payload["outcome"] = RUN_FAILED
    payload["checks"][0]["outcome"] = "tolerated"
    payload["checks"][0]["reason_code"] = "acceptance_observation_unavailable"

    loaded = evidence_from_dict(payload)  # a FAILED run may carry any known outcome
    assert loaded.outcome == RUN_FAILED
    assert payload["checks"][0]["check"] in loaded.not_passing()


def test_the_recorder_verdict_uses_the_same_allowlist(monkeypatch):
    """The recorder and the loader must not disagree about what passes.

    ``seal`` sealing a ``passed`` document the loader then refuses would make the loader's guarantee
    decorative — and the recorder is where the verdict is DERIVED, so a denylist left behind here
    would reintroduce the whole defect one layer up.
    """
    import secp_acceptance.recorder as recorder_module

    rec = _fully_covered()
    monkeypatch.setattr(
        recorder_module, "PASSING_OUTCOMES", frozenset({OUTCOME_OBSERVED}), raising=True
    )
    # every check is `observed`, so narrowing the allowlist to exactly that must still pass...
    assert rec.seal(fleet=_FLEET, release=_RELEASE).outcome == RUN_PASSED

    # ...and widening the recorded set beyond it must not
    rec2 = AcceptanceRecorder()
    rec2.open_stage(STAGE_FAILURE_INJECTION)
    for check in CHECKS_BY_STAGE[STAGE_FAILURE_INJECTION]:
        rec2.expect_refusal(
            check,
            STAGE_FAILURE_INJECTION,
            expected="release_role_mismatch",
            actual="release_role_mismatch",
            observation={},
        )
    assert rec2.seal(fleet=_FLEET, release=_RELEASE).outcome == RUN_FAILED
