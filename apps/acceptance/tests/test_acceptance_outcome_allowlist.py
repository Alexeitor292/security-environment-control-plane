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


def _fully_covered(*, skip: str | None = None) -> AcceptanceRecorder:
    """A recorder covering ALL NINE stages as ``observed``, optionally leaving one check unrecorded.

    Every run-level outcome assertion in this file builds on this rather than on a single stage, and
    that is load-bearing rather than tidiness. ``seal`` requires all nine stages, so a single-stage
    recorder ALWAYS seals ``failed`` no matter what its checks say — which makes
    ``assert outcome == RUN_FAILED`` on a partial recorder vacuously true and unable to fail. See
    :func:`test_a_partial_recorder_always_fails_so_its_outcome_proves_nothing`.
    """
    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            if check != skip:
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


def test_a_partial_recorder_always_fails_so_its_outcome_proves_nothing():
    """THE TRAP, pinned so nobody falls into it again.

    ``seal`` requires all nine stages, so a recorder that opened one stage seals ``failed`` even
    when every check it holds is ``observed``. An ``assert outcome == RUN_FAILED`` written against
    such a recorder therefore passes for a reason unrelated to whatever it meant to watch, and would
    keep passing if the thing it watches regressed entirely.

    This bit a canary in the queues stage — a test built specifically to catch a false green, which
    had itself quietly become one. Any run-level outcome assertion must be built on a NINE-stage
    recorder (see :func:`_fully_covered`) or replaced by a check-level assertion.
    """
    partial = AcceptanceRecorder()
    partial.open_stage(STAGE_QUEUES)
    for check in CHECKS_BY_STAGE[STAGE_QUEUES]:
        partial.observe(check, STAGE_QUEUES, {})
    sealed = partial.seal(fleet=_FLEET, release=_RELEASE)

    assert sealed.outcome == RUN_FAILED
    # ...but for the STAGE COUNT, not for anything about the checks: nothing is missing and nothing
    # failed. That is precisely what makes the outcome unusable as evidence about the checks.
    assert sealed.coverage_complete()
    assert sealed.not_passing() == ()


def test_a_violated_check_fails_the_run_at_seal():
    """Built on all nine stages, so the ``failed`` verdict is caused by the VIOLATION.

    On a single-stage recorder this assertion would hold even if ``violated`` were recorded as
    ``observed``, because the stage count alone would fail the run.
    """
    rec = _fully_covered(skip="operator_queue_has_zero_pollers")
    rec.violated(
        "operator_queue_has_zero_pollers",
        STAGE_QUEUES,
        reason_code="acceptance_prohibited_state_observed",
        observation={"pollers": 1},
    )
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.outcome == RUN_FAILED
    assert ev.violated() == ("operator_queue_has_zero_pollers",)
    # every stage present and every other check passing — the violation is the ONLY cause
    assert set(ev.stages_attempted) == STAGES
    assert ev.coverage_complete()
    assert ev.not_passing() == ("operator_queue_has_zero_pollers",)
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
    checks = list(CHECKS_BY_STAGE[STAGE_QUEUES])
    rec = _fully_covered(skip=checks[0])
    rec.violated(
        checks[0], STAGE_QUEUES, reason_code="acceptance_prohibited_state_observed", observation={}
    )
    ev = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert ev.violated() == (checks[0],)
    assert ev.unproven() == ()

    other = _fully_covered(skip=checks[1])
    other.unproven(
        checks[1], STAGE_QUEUES, reason_code="acceptance_observation_unavailable", observation={}
    )
    document = other.seal(fleet=_FLEET, release=_RELEASE)
    assert document.unproven() == (checks[1],)
    assert document.violated() == ()

    # Recorded identically apart from the verb, and the document still tells them apart. Built as
    # two complete nine-stage runs so each accessor is answering about a run that is otherwise
    # entirely passing — on a partial recorder both would be swamped by missing checks.
    assert ev.not_passing() == (checks[0],)
    assert document.not_passing() == (checks[1],)


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


def _fully_covered_with_real_refusals() -> AcceptanceRecorder:
    """All nine stages covered, with the failure-injection stage carrying REAL ``refused`` checks.

    :func:`_fully_covered` records everything as ``observed``, which cannot exercise the ``refused``
    half of the allowlist at all. This recorder holds both passing outcomes, so narrowing
    ``PASSING_OUTCOMES`` to ``{observed}`` is the ONLY thing that can change the verdict — the
    nine-stage requirement is satisfied either way.
    """
    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            if stage == STAGE_FAILURE_INJECTION:
                rec.expect_refusal(
                    check,
                    stage,
                    expected="release_role_mismatch",
                    actual="release_role_mismatch",
                    observation={"check": check},
                )
            else:
                rec.observe(check, stage, {"check": check})
    return rec


def test_the_recorder_verdict_uses_the_same_allowlist(monkeypatch):
    """The recorder and the loader must not disagree about what passes.

    ``seal`` sealing a ``passed`` document the loader then refuses would make the loader's guarantee
    decorative — and the recorder is where the verdict is DERIVED, so a denylist left behind here
    would reintroduce the whole defect one layer up.

    SENSITIVITY, WHICH THIS TEST PREVIOUSLY LACKED
    ----------------------------------------------
    The second arm used to build a ONE-stage recorder of ``refused`` checks and assert ``failed``.
    That assertion held identically with and without the narrowing — the nine-stage rule failed the
    run either way — so it could not detect whether narrowing ``PASSING_OUTCOMES`` did anything at
    all, inside the guard protecting the allowlist. Found by acc-C-queues.

    Both arms now use the SAME nine-stage recorder, so the allowlist is the only variable and the
    verdict genuinely flips on it.
    """
    import secp_acceptance.evidence as evidence_module
    import secp_acceptance.recorder as recorder_module

    # Baseline: `refused` IS a passing outcome, so a complete run carrying refusals PASSES.
    baseline = _fully_covered_with_real_refusals().seal(fleet=_FLEET, release=_RELEASE)
    assert baseline.outcome == RUN_PASSED
    assert {record.outcome for record in baseline.checks} == {OUTCOME_OBSERVED, OUTCOME_REFUSED}
    assert baseline.not_passing() == ()

    # Narrow the allowlist to `observed` alone. NOTHING else changes — same stages, same checks.
    # BOTH modules are patched because each binds the name at import, and the whole subject of this
    # test is that the two must not disagree; patching one would leave the loader answering from the
    # real allowlist while the recorder used the narrowed one.
    narrowed_allowlist = frozenset({OUTCOME_OBSERVED})
    monkeypatch.setattr(recorder_module, "PASSING_OUTCOMES", narrowed_allowlist, raising=True)
    monkeypatch.setattr(evidence_module, "PASSING_OUTCOMES", narrowed_allowlist, raising=True)

    narrowed = _fully_covered_with_real_refusals().seal(fleet=_FLEET, release=_RELEASE)
    assert narrowed.outcome == RUN_FAILED, (
        "narrowing PASSING_OUTCOMES did not change the verdict, so this test is not measuring the "
        "allowlist"
    )
    # the LOADER's view moved with the recorder's — that agreement is the property under test
    assert set(narrowed.not_passing()) == set(CHECKS_BY_STAGE[STAGE_FAILURE_INJECTION])

    # A run of purely `observed` checks is unaffected by the narrowing — the control that shows the
    # flip above came from the refusals and not from the patch breaking sealing outright.
    assert _fully_covered().seal(fleet=_FLEET, release=_RELEASE).outcome == RUN_PASSED
