"""A lifecycle observation that was not made must never read as one that was.

The hermetic contract of :mod:`secp_acceptance.lifecycle`. Same discipline as
``test_acceptance_residue.py``, applied to the rest of the stage: every question has three answers
and the third one — *we did not get an answer* — must stay distinguishable from both of the others.

THE TWO CONFUSIONS PINNED HERE
------------------------------
1. **A command that did not run is not a refusal.** ``secpctl`` refuses with exit 2 and a bounded
   ``reason_code``, and for the failure-injection stage that refusal IS the expected result. If a
   missing entrypoint or an unreachable host also read as a refusal, every failure-injection check
   would be satisfiable without the product doing anything — an unfalsifiable assertion in the one
   stage whose whole purpose is falsifying.

2. **An absent document is not an unreadable one.** ``sha256sum`` fails identically for "the file is
   gone" and "the probe could not run". That ambiguity is exactly what produced a false clean
   teardown in this harness once, so the probe prints a POSITIVE token for each real state and
   anything else is unreadable.

WHY THE FAKE HOST IS DELIBERATELY DUMB
--------------------------------------
``_FakeHost`` returns canned :class:`~secp_acceptance.shell.Result` objects and records the argv it
was asked to run. It does not simulate a shell. Tests that need to know what the probe SCRIPT does
on a real host cannot be written here at all, and pretending otherwise would be the worse error —
those live in the container tier, against a real one.
"""

from __future__ import annotations

import json

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.lifecycle import (
    CHANGED,
    DOC_ABSENT,
    DOC_PRESENT,
    DOC_UNREADABLE,
    REPORT_OK,
    REPORT_REFUSED,
    REPORT_UNREADABLE,
    RESTORATION_UNPROVEN,
    RESTORED,
    DocumentSnapshot,
    DocumentState,
    Report,
    RestorationVerdict,
    document_snapshot,
    expected_installation_id,
    managed_document_paths,
    outcome_for_restoration,
    restoration_verdict,
    secpctl,
)
from secp_acceptance.reasons import (
    OUTCOME_OBSERVED,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
    PASSING_OUTCOMES,
)
from secp_acceptance.shell import Result

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
KINDS = tuple(kind for kind, _path in managed_document_paths("worker"))


class _FakeHost:
    """A host that answers with canned results and records what it was asked."""

    def __init__(self, answers: list[Result] | None = None, default: Result | None = None) -> None:
        self.answers = list(answers or [])
        self.default = default or Result(exit_code=0, stdout="", stderr="")
        self.calls: list[tuple[str, ...]] = []

    def exec(self, argv, *, timeout: int = 600, check: bool = False) -> Result:  # noqa: ANN001
        self.calls.append(tuple(argv))
        return self.answers.pop(0) if self.answers else self.default


def _json_result(exit_code: int, payload: object) -> Result:
    return Result(exit_code=exit_code, stdout=json.dumps(payload), stderr="")


# --------------------------------------------------------------------------- the secpctl seam


def test_a_successful_command_yields_its_parsed_report():
    host = _FakeHost([_json_result(0, {"command": "status", "ok": True})])

    report = secpctl(host, ("status", "worker"))

    assert report.status == REPORT_OK
    assert report.ok is True
    assert report.readable is True
    assert report.reason_code is None
    assert report.flag("ok") is True


def test_a_bounded_refusal_is_a_refusal_and_carries_its_reason():
    """Exit 2 with a bounded code is the EXPECTED result of every failure-injection check."""
    host = _FakeHost([_json_result(2, {"reason_code": "worker_upgrade_not_linear_successor"})])

    report = secpctl(host, ("bootstrap", "worker", "--bundle", "B"))

    assert report.status == REPORT_REFUSED
    assert report.ok is False
    assert report.readable is True
    assert report.reason_code == "worker_upgrade_not_linear_successor"


@pytest.mark.parametrize("exit_code", [1, 3, 126, 127, 255])
def test_a_command_that_never_reached_its_reporting_path_is_unreadable(exit_code: int):
    """THE confusion this seam exists to prevent.

    A missing entrypoint, a killed process or an unreachable host must not read as "the product
    refused" — that would let every failure-injection check pass without the product doing anything.
    """
    host = _FakeHost([_json_result(exit_code, {"reason_code": "looks_like_a_refusal"})])

    report = secpctl(host, ("status", "worker"))

    assert report.status == REPORT_UNREADABLE
    assert report.readable is False
    assert report.reason_code is None, "a non-reporting exit status must not yield a reason code"


def test_a_refusal_without_a_bounded_reason_is_unreadable_not_a_refusal():
    """Exit 2 promises a reason code. Without one the refusal cannot be attributed, and inventing
    one would be the harness making up the product's answer."""
    host = _FakeHost([_json_result(2, {"command": "bootstrap"})])

    report = secpctl(host, ("bootstrap", "worker", "--bundle", "B"))

    assert report.status == REPORT_UNREADABLE
    assert report.reason_code is None


@pytest.mark.parametrize(
    "stdout", ["", "not json at all", "[]", '"a string"', "null", "{oops", "0"]
)
def test_output_that_is_not_a_json_object_is_unreadable(stdout: str):
    """Human-rendered output (the shape you get without ``--json``) parses as no report at all."""
    host = _FakeHost([Result(exit_code=0, stdout=stdout, stderr="")])

    assert secpctl(host, ("status", "worker")).status == REPORT_UNREADABLE


def test_the_json_flag_is_appended_so_a_caller_cannot_forget_it():
    """Without it the CLI renders human text, and every invocation would be unreadable."""
    host = _FakeHost([_json_result(0, {})])

    secpctl(host, ("status", "worker"))

    assert host.calls[0] == ("secpctl", "status", "worker", "--json")


def test_an_explicit_json_flag_is_not_duplicated():
    host = _FakeHost([_json_result(0, {})])

    secpctl(host, ("status", "worker", "--json"))

    assert host.calls[0].count("--json") == 1


# --------------------------------------------------------------------------- report field access


def test_a_missing_field_is_reported_absent_rather_than_false():
    """THE reason ``field`` returns presence separately.

    A report with no ``operator_disabled`` must not read as an operator that is not disabled. That
    is the same confusion as an unreachable daemon reading as a clean machine, one level up.
    """
    report = Report(REPORT_OK, 0, {"dimensions": {"ok": True}})

    present, value = report.field("dimensions", "operator_disabled")
    assert present is False
    assert value is None
    assert report.flag("dimensions", "operator_disabled") is None


def test_a_present_false_field_is_distinguishable_from_an_absent_one():
    """The control. If these were the same, the assertion above would be meaningless."""
    report = Report(REPORT_OK, 0, {"dimensions": {"operator_disabled": False}})

    assert report.field("dimensions", "operator_disabled") == (True, False)
    assert report.flag("dimensions", "operator_disabled") is False


@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, [], {}])
def test_a_non_boolean_field_is_not_coerced_into_a_verdict(value: object):
    """Truthiness would let a drifted report shape read as a pass. A field carrying the STRING
    ``"false"`` is a contract this harness does not understand, and guessing is how that goes
    unnoticed."""
    assert Report(REPORT_OK, 0, {"d": value}).flag("d") is None


def test_field_traversal_stops_at_a_non_mapping():
    assert Report(REPORT_OK, 0, {"a": 5}).field("a", "b") == (False, None)


def test_an_unreadable_report_exposes_no_fields_at_all():
    """An unreadable report carries an empty payload, so no caller can read a stale value out of
    one and mistake it for an observation."""
    host = _FakeHost([Result(exit_code=127, stdout='{"ok": true}', stderr="")])

    report = secpctl(host, ("status", "worker"))

    assert report.payload == {}
    assert report.flag("ok") is None


# --------------------------------------------------------------------------- document paths


def test_the_document_set_is_read_from_the_engine_not_restated():
    """A copied list would keep passing after the product added a sixth managed document, and the
    rollback proofs would silently stop covering it."""
    from secp_management.engine import _DOC_ORDER

    assert KINDS == tuple(_DOC_ORDER)
    assert len(KINDS) == 5


def test_every_document_path_is_absolute_and_role_scoped():
    worker = dict(managed_document_paths("worker"))
    controller = dict(managed_document_paths("controller"))
    for kind, path in worker.items():
        assert path.startswith("/"), f"{kind} path is not absolute"
        assert path != controller[kind], f"{kind} resolves to the same path for both roles"


# --------------------------------------------------------------------------- document probing


def _probe_result(state: str, digest: str = DIGEST_A) -> Result:
    if state == DOC_PRESENT:
        return Result(exit_code=0, stdout=f"PRESENT\n{digest}  /some/path\n", stderr="")
    if state == DOC_ABSENT:
        return Result(exit_code=0, stdout="ABSENT\n", stderr="")
    return Result(exit_code=1, stdout="", stderr="")


def test_a_present_document_yields_its_digest():
    host = _FakeHost(default=_probe_result(DOC_PRESENT))

    snapshot = document_snapshot(host, "worker")

    assert snapshot.complete is True
    assert snapshot.present_kinds == KINDS
    assert all(doc.digest == DIGEST_A for doc in snapshot.documents)


def test_an_absent_document_is_settled_not_unreadable():
    """Proven absence is what the rollback-removed check needs. If absence were unreadable, that
    check could never be settled at all."""
    host = _FakeHost(default=_probe_result(DOC_ABSENT))

    snapshot = document_snapshot(host, "worker")

    assert snapshot.complete is True, "a proven-absent document is settled, not unknown"
    assert snapshot.present_kinds == ()
    assert snapshot.unreadable_kinds == ()


def test_a_probe_that_could_not_run_is_unreadable_not_absent():
    """THE second confusion. ``sha256sum`` fails identically for "gone" and "could not run", so a
    failed probe must never be recorded as a proven absence."""
    host = _FakeHost(default=_probe_result(DOC_UNREADABLE))

    snapshot = document_snapshot(host, "worker")

    assert snapshot.complete is False
    assert snapshot.unreadable_kinds == KINDS


@pytest.mark.parametrize(
    "stdout",
    [
        "PRESENT\n",  # claimed present, no digest line
        "PRESENT\nnot-a-digest  /p\n",  # digest is not hex
        "PRESENT\n" + "a" * 63 + "  /p\n",  # wrong length
        "MAYBE\n",  # neither token
        "",  # nothing at all
        "\n\n",  # only blank lines
    ],
)
def test_a_probe_answer_it_cannot_parse_is_unreadable(stdout: str):
    """A PRESENT with no usable digest is not a document we can compare. Saying so is the
    difference between "unchanged" and "we never actually read it"."""
    host = _FakeHost(default=Result(exit_code=0, stdout=stdout, stderr=""))

    assert document_snapshot(host, "worker").complete is False


def test_the_probe_passes_the_path_as_an_argument_never_as_script_text():
    """The path is code-owned, but the seam's rule is that no value is interpolated into shell text.
    ``sh -c SCRIPT sh PATH`` keeps the script a constant and the path an argument."""
    host = _FakeHost(default=_probe_result(DOC_ABSENT))

    document_snapshot(host, "worker")

    paths = {path for _kind, path in managed_document_paths("worker")}
    for call in host.calls:
        assert call[0] == "sh" and call[1] == "-c"
        script, argv0, path = call[2], call[3], call[4]
        assert argv0 == "sh"
        assert path in paths
        assert path not in script, "the path was interpolated into the script text"


def test_the_snapshot_projection_carries_no_path_or_document_body():
    host = _FakeHost(default=_probe_result(DOC_PRESENT))

    projection = document_snapshot(host, "worker").observation()

    rendered = repr(projection)
    for _kind, path in managed_document_paths("worker"):
        assert path not in rendered
    assert DIGEST_A not in rendered, "per-document digests must be folded, not listed"
    assert str(projection["content_identity"]).startswith("sha256:")


# --------------------------------------------------------------------------- restoration


def _snapshot(role: str = "worker", **overrides: DocumentState) -> DocumentSnapshot:
    docs = tuple(overrides.get(kind, DocumentState(kind, DOC_PRESENT, DIGEST_A)) for kind in KINDS)
    return DocumentSnapshot(role=role, documents=docs)


def test_identical_snapshots_prove_the_documents_were_restored():
    verdict = restoration_verdict(_snapshot(), _snapshot())

    assert verdict.verdict == RESTORED
    assert verdict.differing == ()
    assert outcome_for_restoration(verdict) == (OUTCOME_OBSERVED, None)


def test_a_changed_digest_is_a_proven_failure_to_restore():
    """We read BOTH sides and they disagree. That is knowledge of a defect, not absence of
    evidence — the failed upgrade did not put the document back."""
    after = _snapshot(**{KINDS[0]: DocumentState(KINDS[0], DOC_PRESENT, DIGEST_B)})

    verdict = restoration_verdict(_snapshot(), after)

    assert verdict.verdict == CHANGED
    assert verdict.differing == (KINDS[0],)
    outcome, code = outcome_for_restoration(verdict)
    assert outcome == OUTCOME_VIOLATED
    assert code


def test_a_document_that_vanished_is_also_a_proven_failure_to_restore():
    """State changes count, not only digest changes. A document the failed upgrade deleted and did
    not put back is exactly the thing this check exists to catch."""
    after = _snapshot(**{KINDS[4]: DocumentState(KINDS[4], DOC_ABSENT, None)})

    verdict = restoration_verdict(_snapshot(), after)

    assert verdict.verdict == CHANGED
    assert verdict.differing == (KINDS[4],)


def test_a_state_change_alone_is_enough_to_fail_the_comparison():
    """Found by mutation, not by design: dropping the STATE comparison and keeping only the digest
    one passed the entire suite, because every other case here happens to differ in digest too.

    Under the probe's own invariants the two comparisons are redundant — it emits ``present`` only
    WITH a valid digest, and ``absent`` only with ``None``. But ``DocumentState`` is public, and a
    hand-built or future ``present``-with-no-digest would compare EQUAL to an absent one, reporting
    "restored" over a document that had vanished. This is the case that keeps that line honest.
    """
    before = _snapshot(**{KINDS[3]: DocumentState(KINDS[3], DOC_PRESENT, None)})
    after = _snapshot(**{KINDS[3]: DocumentState(KINDS[3], DOC_ABSENT, None)})

    verdict = restoration_verdict(before, after)

    assert verdict.verdict == CHANGED, "a present->absent change with no digest went unnoticed"
    assert verdict.differing == (KINDS[3],)


def test_an_incomplete_snapshot_can_prove_nothing_either_way():
    """What we did not read might be the document that changed, so neither conclusion is available.
    This is never a pass."""
    after = _snapshot(**{KINDS[2]: DocumentState(KINDS[2], DOC_UNREADABLE, None)})

    verdict = restoration_verdict(_snapshot(), after)

    assert verdict.verdict == RESTORATION_UNPROVEN
    assert KINDS[2] in verdict.differing
    outcome, code = outcome_for_restoration(verdict)
    assert outcome == OUTCOME_UNPROVEN
    assert code == "acceptance_observation_unavailable"


def test_an_unreadable_before_snapshot_is_just_as_disqualifying():
    """The capture side matters as much as the comparison side: with no baseline there is nothing
    to have been restored TO."""
    before = _snapshot(**{KINDS[1]: DocumentState(KINDS[1], DOC_UNREADABLE, None)})

    assert restoration_verdict(before, _snapshot()).verdict == RESTORATION_UNPROVEN


def test_comparing_snapshots_of_different_roles_refuses():
    """Rather than answering confidently about two unrelated installations."""
    with pytest.raises(AcceptanceError) as caught:
        restoration_verdict(_snapshot("worker"), _snapshot("controller"))
    assert caught.value.reason_code == "acceptance_observation_malformed"


def _verdict_named(name: str) -> RestorationVerdict:
    return RestorationVerdict(name, "acceptance_observation_malformed", ())


@pytest.mark.parametrize("name", [RESTORED, CHANGED, RESTORATION_UNPROVEN])
def test_the_restoration_mapping_is_one_way_over_every_verdict(name: str):
    """Only ``restored`` may reach a passing outcome, and ``refused`` is unreachable because
    nothing here is a product refusal.

    Every verdict is built the SAME way — by hand, with an identical reason code — so the mapping
    is what differs between the cases and not how the input was constructed.
    """
    outcome, _code = outcome_for_restoration(_verdict_named(name))

    assert outcome != OUTCOME_REFUSED
    assert (outcome in PASSING_OUTCOMES) is (name == RESTORED)


def test_the_three_verdicts_map_to_three_different_outcomes():
    """They must stay mutually distinguishable. Two of them collapsing onto one outcome would hide
    either "we could not check" behind "it failed", or the reverse."""
    outcomes = {
        name: outcome_for_restoration(_verdict_named(name))[0]
        for name in (RESTORED, CHANGED, RESTORATION_UNPROVEN)
    }

    assert len(set(outcomes.values())) == 3
    assert outcomes[RESTORED] == OUTCOME_OBSERVED
    assert outcomes[CHANGED] == OUTCOME_VIOLATED
    assert outcomes[RESTORATION_UNPROVEN] == OUTCOME_UNPROVEN


def test_an_unrecognised_restoration_verdict_raises_rather_than_defaulting():
    """A default here would be a silent extra path to a pass."""
    with pytest.raises(AcceptanceError):
        outcome_for_restoration(_verdict_named("probably_fine"))


# --------------------------------------------------------------------------- identity binding


def test_the_installation_id_is_derived_by_the_engine_itself():
    """Delegated, not re-implemented — a restated formula would agree with itself after someone
    changed the real one."""
    from secp_management.engine import _installation_id

    aggregate = "sha256:" + "9" * 64
    assert expected_installation_id("worker", aggregate) == _installation_id("worker", aggregate)


def test_a_different_release_produces_a_different_installation_id():
    """The premise of the upgrade-identity check: if these collided, "the identity changed" would
    be unobservable and the check could never fail."""
    baseline = expected_installation_id("worker", "sha256:" + "1" * 64)
    successor = expected_installation_id("worker", "sha256:" + "2" * 64)
    assert baseline != successor


def test_the_role_participates_in_the_identity():
    aggregate = "sha256:" + "3" * 64
    assert expected_installation_id("worker", aggregate) != expected_installation_id(
        "controller", aggregate
    )


@pytest.mark.parametrize(("role", "aggregate"), [("", "sha256:x"), ("worker", "")])
def test_an_empty_input_refuses_rather_than_deriving_a_plausible_identity(
    role: str, aggregate: str
):
    """An identity derived from nothing is still a well-formed-looking string, which is the worst
    possible thing to compare a real report against."""
    with pytest.raises(AcceptanceError):
        expected_installation_id(role, aggregate)
