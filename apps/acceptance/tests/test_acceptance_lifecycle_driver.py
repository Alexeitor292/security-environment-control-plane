"""Every path through the lifecycle driver records exactly once per check.

The stage contract is that opening a stage commits the run to covering every check it declares. A
driver that returns early, or that takes a branch nobody wrote a test for, silently under-covers —
and an under-covered stage is not a failing stage, it is a stage whose absence a reader has to
notice. So the property pinned hardest here is not "the right outcome" but "an outcome at all, once,
on every path".

THE RECORDER IS A COUNTER, NOT A MOCK
-------------------------------------
``_Recorder`` implements the driver's structural protocol and records what it was told, in order.
It asserts nothing by itself; the tests read it. That is deliberate — a recorder that enforced its
own expectations would be a second implementation of the contract, and the tests would then be
measuring the fake.

WHAT IS NOT TESTED HERE, STATED PLAINLY
---------------------------------------
Whether the real ``secpctl`` produces these report shapes. That is a fact about a real host and it
is settled in the container tier, against a real one. These tests pin the driver's LOGIC given a
report; they cannot and do not pin the product's behaviour.
"""

from __future__ import annotations

import json

import pytest
from secp_acceptance.lifecycle_driver import (
    INJECTIONS,
    UNOBSERVED,
    StageRecorder,
    drive_dry_run_default,
    drive_failure_injection,
    drive_restart,
    drive_rollback,
    drive_upgrade,
)
from secp_acceptance.shell import Result

WORKER_CHECKS = (
    "restart_worker_still_healthy",
    "upgrade_classified_managed_upgrade",
    "upgrade_written_and_reobserved",
    "upgrade_operator_still_disabled",
    "rollback_plan_lists_documents",
    "rollback_removed_documents",
)


class _Recorder:
    """Records what it was told, in order. Enforces nothing — the tests read it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []  # (check, outcome, reason)
        self.observations: dict[str, object] = {}

    def observed(self, check: str, observation: object) -> None:
        self.calls.append((check, "observed", ""))
        self.observations[check] = observation

    def unproven(self, check: str, *, reason: str, observation: object) -> None:
        self.calls.append((check, "unproven", reason))
        self.observations[check] = observation

    def violated(self, check: str, *, observation: object) -> None:
        self.calls.append((check, "violated", "acceptance_prohibited_state_observed"))
        self.observations[check] = observation

    def expect_refusal(
        self, check: str, *, expected: str, actual: str | None, observation: object
    ) -> bool:
        """Mirrors the recorder contract: only the EXPECTED code is a pass.

        Deliberately reimplements the branch rather than always appending "refused" — a fake that
        recorded every refusal as a pass would make every assertion below vacuous, which is the
        exact defect the real verb exists to prevent.
        """
        self.observations[check] = observation
        if actual is None:
            self.calls.append((check, "unproven", "acceptance_expected_refusal_absent"))
            return False
        if actual != expected:
            self.calls.append((check, "unproven", "acceptance_unexpected_reason_code"))
            return False
        self.calls.append((check, "refused", actual))
        return True

    def outcome(self, check: str) -> str:
        for name, outcome, _reason in self.calls:
            if name == check:
                return outcome
        return "absent"

    def reason(self, check: str) -> str:
        for name, _outcome, reason in self.calls:
            if name == check:
                return reason
        return ""

    @property
    def checks(self) -> list[str]:
        return [check for check, _o, _r in self.calls]


class _Host:
    """Answers ``secpctl`` and the document probe from canned replies keyed by the verb."""

    def __init__(self, replies: dict[str, Result], probe: Result | None = None) -> None:
        self.replies = replies
        self.probe = probe or Result(exit_code=0, stdout="ABSENT\n", stderr="")
        #: Consumed one reply at a time, so successive SNAPSHOTS can differ. Empty means every
        #: probe uses ``probe``.
        self.probe_sequence: list[Result] = []
        self.calls: list[tuple[str, ...]] = []

    def exec(self, argv, *, timeout: int = 600, check: bool = False) -> Result:  # noqa: ANN001
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[0] == "sh":
            return self.probe_sequence.pop(0) if self.probe_sequence else self.probe
        key = " ".join(a for a in argv[1:] if not a.startswith("--"))
        for prefix, reply in self.replies.items():
            if key.startswith(prefix):
                return reply
        return Result(exit_code=127, stdout="", stderr="")


def _json(exit_code: int, payload: object) -> Result:
    return Result(exit_code=exit_code, stdout=json.dumps(payload), stderr="")


def _present(digest: str = "a" * 64) -> Result:
    return Result(exit_code=0, stdout=f"PRESENT\n{digest}  /p\n", stderr="")


def _release(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "present": True,
        "role": "worker",
        "source_sha": "a" * 40,
        "aggregate_digest": "sha256:" + "1" * 64,
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- the protocol


def test_the_counting_recorder_satisfies_the_drivers_protocol():
    """CONTROL. If it did not, every test below would be exercising a shape the real recorder does
    not have, and the integration would break on arrival."""
    assert isinstance(_Recorder(), StageRecorder)


# --------------------------------------------------------------------------- restart


def test_a_healthy_worker_after_a_real_restart_is_observed():
    recorder = _Recorder()
    host = _Host({"status worker": _json(0, {"ok": True, "dimensions": {"drift": None}})})

    drive_restart(recorder, host, {"restarted": True})

    assert recorder.outcome("restart_worker_still_healthy") == "observed"


def test_an_unhealthy_worker_after_a_restart_is_a_violation():
    """We looked and the worker came back unhealthy. That is the state the check rules out, and
    filing it as "we could not tell" would understate a real regression."""
    recorder = _Recorder()
    host = _Host(
        {"status worker": _json(2, {"ok": False, "reason_code": "worker_ordinary_not_ready"})}
    )

    drive_restart(recorder, host, {"restarted": True})

    assert recorder.outcome("restart_worker_still_healthy") == "violated"


def test_a_restart_that_did_not_happen_proves_nothing_about_durability():
    """Health after a reboot that never occurred is not evidence. Recorded, never omitted."""
    recorder = _Recorder()
    host = _Host({"status worker": _json(0, {"ok": True})})

    drive_restart(recorder, host, {"restarted": False})

    assert recorder.outcome("restart_worker_still_healthy") == "unproven"
    assert recorder.reason("restart_worker_still_healthy") == UNOBSERVED
    assert host.calls == [], "the status command must not run when the restart did not"


def test_a_report_with_no_ok_field_is_unreadable_not_unhealthy():
    """THE distinction. A missing field is not a False one — unproven, never violated."""
    recorder = _Recorder()
    host = _Host({"status worker": _json(0, {"dimensions": {}})})

    drive_restart(recorder, host, {"restarted": True})

    assert recorder.outcome("restart_worker_still_healthy") == "unproven"


def test_an_unreachable_host_is_unproven_not_a_violation():
    recorder = _Recorder()
    host = _Host({})  # every command exits 127

    drive_restart(recorder, host, {"restarted": True})

    assert recorder.outcome("restart_worker_still_healthy") == "unproven"


# --------------------------------------------------------------------------- upgrade


def _upgrade_host(*, classification: str = "managed_upgrade", write_ok: bool = True) -> _Host:
    new = "sha256:" + "2" * 64
    return _Host(
        {
            "bootstrap worker": (
                _json(0, {"classification": classification, "mode": "dry_run"})
                if write_ok
                else _json(0, {"classification": classification, "mode": "dry_run"})
            ),
            "evidence worker": _json(
                0,
                {
                    "authenticated": True,
                    "release_aggregate_digest": new,
                    "installation_id": _expected(new),
                },
            ),
        }
    )


def _expected(aggregate: str) -> str:
    from secp_acceptance.lifecycle import expected_installation_id

    return expected_installation_id("worker", aggregate)


class _Dormant:
    verdict = "held"
    observation = {"present": True, "enabled": False}
    cause = None


class _Activated:
    verdict = "violated"
    observation = {"present": True, "enabled": True}
    cause = "worker_operator_not_disabled_stopped"


def test_a_linear_successor_upgrade_records_all_three_checks():
    recorder = _Recorder()
    new = "sha256:" + "2" * 64
    host = _upgrade_host()

    drive_upgrade(
        recorder,
        host,
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(aggregate_digest=new),
        operator_dormancy=_Dormant(),
    )

    assert recorder.checks == [
        "upgrade_classified_managed_upgrade",
        "upgrade_written_and_reobserved",
        "upgrade_operator_still_disabled",
    ]
    assert all(outcome == "observed" for _c, outcome, _r in recorder.calls)


def test_a_refused_upgrade_still_records_all_three_checks():
    """THE coverage property. A refusal must not leave two checks silently absent — an
    under-covered stage is not a failing stage, it is one whose absence a reader has to notice."""
    recorder = _Recorder()
    host = _Host(
        {"bootstrap worker": _json(2, {"reason_code": "worker_upgrade_not_linear_successor"})}
    )

    drive_upgrade(
        recorder,
        host,
        baseline=_release(),
        successor={"parent_sha": "c" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(),
        operator_dormancy=_Dormant(),
    )

    assert len(recorder.calls) == 3
    assert recorder.reason("upgrade_classified_managed_upgrade") == (
        "worker_upgrade_not_linear_successor"
    )
    assert recorder.outcome("upgrade_written_and_reobserved") == "unproven"


def test_a_refused_upgrade_writes_nothing_to_the_host():
    """A classification that refused means the host was never touched, and the driver must not
    then attempt the write anyway."""
    recorder = _Recorder()
    host = _Host({"bootstrap worker": _json(2, {"reason_code": "worker_upgrade_prior_drifted"})})

    drive_upgrade(
        recorder,
        host,
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(),
    )

    assert not any("--write" in call for call in host.calls)


def test_a_wrong_classification_on_a_genuinely_linear_successor_is_a_violation():
    """We handed it a real successor and it called the operation something else. Observed-false."""
    recorder = _Recorder()
    host = _upgrade_host(classification="fresh")

    drive_upgrade(
        recorder,
        host,
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(),
        operator_dormancy=_Dormant(),
    )

    assert recorder.outcome("upgrade_classified_managed_upgrade") == "violated"


def test_a_wrong_classification_on_an_unproven_lineage_is_not_a_violation():
    """The asymmetry that keeps the violation honest.

    With no baseline we do not know what the product SHOULD have said, so a non-managed
    classification proves nothing — and accusing it would be manufacturing a defect out of an
    absent reading.
    """
    recorder = _Recorder()
    host = _upgrade_host(classification="fresh")

    drive_upgrade(
        recorder,
        host,
        baseline=_release(present=False),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(),
        operator_dormancy=_Dormant(),
    )

    assert recorder.outcome("upgrade_classified_managed_upgrade") == "unproven"


def test_an_activated_operator_unit_after_an_upgrade_is_a_violation():
    recorder = _Recorder()
    new = "sha256:" + "2" * 64

    drive_upgrade(
        recorder,
        _upgrade_host(),
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(aggregate_digest=new),
        operator_dormancy=_Activated(),
    )

    assert recorder.outcome("upgrade_operator_still_disabled") == "violated"


def test_an_unobservable_operator_unit_is_unproven_not_dormant():
    """An absent dormancy reading must never read as a dormant operator — the collapse the queue
    stream's three-valued classifier exists to prevent, preserved across the seam."""
    recorder = _Recorder()
    new = "sha256:" + "2" * 64

    drive_upgrade(
        recorder,
        _upgrade_host(),
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(aggregate_digest=new),
        operator_dormancy=None,
    )

    assert recorder.outcome("upgrade_operator_still_disabled") == "unproven"


@pytest.mark.parametrize(
    "dormancy", [_Dormant(), _Activated(), None], ids=["held", "violated", "unobservable"]
)
def test_every_dormancy_verdict_records_exactly_once(dormancy):
    recorder = _Recorder()

    drive_upgrade(
        recorder,
        _upgrade_host(),
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(aggregate_digest="sha256:" + "2" * 64),
        operator_dormancy=dormancy,
    )

    assert recorder.checks.count("upgrade_operator_still_disabled") == 1


# --------------------------------------------------------------------------- rollback


def test_a_clean_uninstall_records_both_rollback_checks_observed():
    recorder = _Recorder()
    bindings = ["b1", "b2"]
    host = _Host(
        {
            "rollback worker": _json(0, {"mode": "dry_run", "removable_bindings": bindings}),
        }
    )
    # the plan must leave documents untouched, then the write must remove them: present, present,
    # absent across the three snapshots
    host.probe = _present()

    drive_rollback(recorder, host)

    assert recorder.checks == [
        "rollback_plan_lists_documents",
        "rollback_removed_documents",
    ]


def test_documents_still_present_after_a_reported_removal_is_a_violation():
    """The product said it removed them and they are still there. Observed-false, and exactly the
    claim a reported-only check would have missed."""
    recorder = _Recorder()
    host = _Host(
        {
            "rollback worker": _json(
                0, {"mode": "dry_run", "removable_bindings": ["b1"], "removed_bindings": ["b1"]}
            )
        }
    )
    host.probe = _present()  # every snapshot says PRESENT, including after the write

    drive_rollback(recorder, host)

    assert recorder.outcome("rollback_removed_documents") == "violated"


def test_an_unreadable_snapshot_after_removal_is_unproven_not_a_violation():
    """A probe that could not run is not a document that is still there."""
    recorder = _Recorder()
    host = _Host(
        {
            "rollback worker": _json(
                0, {"mode": "dry_run", "removable_bindings": ["b1"], "removed_bindings": ["b1"]}
            )
        }
    )
    host.probe = Result(exit_code=1, stdout="", stderr="")

    drive_rollback(recorder, host)

    assert recorder.outcome("rollback_removed_documents") == "unproven"


def test_a_refused_rollback_records_both_checks():
    recorder = _Recorder()
    host = _Host(
        {"rollback worker": _json(2, {"reason_code": "rollback_refused_adopted_installation"})}
    )

    drive_rollback(recorder, host)

    assert len(recorder.calls) == 2
    assert recorder.reason("rollback_plan_lists_documents") == (
        "rollback_refused_adopted_installation"
    )


def test_an_unreachable_host_still_records_both_rollback_checks():
    recorder = _Recorder()

    drive_rollback(recorder, _Host({}))

    assert len(recorder.calls) == 2
    assert all(outcome == "unproven" for _c, outcome, _r in recorder.calls)


# --------------------------------------------------------------------------- coverage


def test_no_driver_path_records_a_check_twice():
    """One record per check, per the recorder's own duplicate-check refusal. A driver that recorded
    twice would raise at the real recorder, at the end of a long container run."""
    recorder = _Recorder()
    host = _upgrade_host()

    drive_restart(recorder, host, {"restarted": True})
    drive_upgrade(
        recorder,
        host,
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(aggregate_digest="sha256:" + "2" * 64),
        operator_dormancy=_Dormant(),
    )
    drive_rollback(recorder, host)

    assert len(recorder.checks) == len(set(recorder.checks))


def test_the_three_drivers_together_cover_the_six_management_plane_checks():
    """The stage's own coverage claim, measured rather than asserted in prose."""
    recorder = _Recorder()
    host = _upgrade_host()

    drive_restart(recorder, host, {"restarted": True})
    drive_upgrade(
        recorder,
        host,
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(aggregate_digest="sha256:" + "2" * 64),
        operator_dormancy=_Dormant(),
    )
    drive_rollback(recorder, host)

    assert set(recorder.checks) == set(WORKER_CHECKS)


def test_those_six_are_a_strict_subset_of_the_stage_and_the_rest_are_named():
    """The three NOT covered here need an enrollment to exist. Naming them keeps the gap explicit
    rather than leaving a reader to diff two lists."""
    from secp_acceptance.reasons import CHECKS_BY_STAGE, STAGE_LIFECYCLE

    declared = set(CHECKS_BY_STAGE[STAGE_LIFECYCLE])
    assert set(WORKER_CHECKS) < declared
    assert declared - set(WORKER_CHECKS) == {
        "restart_enrollment_state_survived",
        "recovery_required_on_demand",
        "recovery_required_terminal",
    }


def test_an_absent_dormancy_verdict_says_why_it_could_not_be_settled():
    """The fall-through would ALSO record ``unproven``, so the outcome alone cannot show the guard
    is doing anything. What it adds is the reason a reader gets: ``operator_unit_observed: False``
    rather than an empty observation that explains nothing.

    Found by mutation — deleting the guard changed no outcome and failed no test.
    """
    recorder = _Recorder()

    drive_upgrade(
        recorder,
        _upgrade_host(),
        baseline=_release(),
        successor={"parent_sha": "a" * 40},
        successor_dir="/bundle",
        observe_release=lambda: _release(aggregate_digest="sha256:" + "2" * 64),
        operator_dormancy=None,
    )

    assert recorder.outcome("upgrade_operator_still_disabled") == "unproven"
    assert recorder.observations["upgrade_operator_still_disabled"] == {
        "operator_unit_observed": False
    }


def test_a_dry_run_that_mutated_documents_fails_the_plan_check():
    """THE reason the plan check re-reads the documents afterwards.

    A ``rollback`` reporting ``dry_run`` while removing a document would satisfy the report and the
    binding list. Only the second snapshot catches it — and without this case, dropping that
    comparison changed nothing and failed no test.
    """
    recorder = _Recorder()
    host = _Host({"rollback worker": _json(0, {"mode": "dry_run", "removable_bindings": ["b1"]})})
    # snapshot 1: five present. snapshot 2, after the "dry run": the first document is gone.
    host.probe_sequence = (
        [_present()] * 5 + [Result(exit_code=0, stdout="ABSENT\n", stderr="")] + [_present()] * 4
    )

    drive_rollback(recorder, host)

    assert recorder.outcome("rollback_plan_lists_documents") != "observed", (
        "a plan that removed a document while reporting dry_run was accepted"
    )


# --------------------------------------------------------------------------- failure injection


def _refusing(code: str) -> _Host:
    return _Host({"bootstrap worker": _json(2, {"reason_code": code})})


def test_each_injection_records_refused_with_its_own_bounded_code():
    recorder = _Recorder()
    for check, expected, _note in INJECTIONS:
        drive_failure_injection(recorder, _refusing(expected), bundles={check: "/b"})

    assert [outcome for _c, outcome, _r in recorder.calls if outcome == "refused"] == [
        "refused"
    ] * len(INJECTIONS)


def test_a_refusal_with_the_WRONG_code_is_not_a_pass():
    """THE property the whole stage rests on.

    "The product refused" and "the product refused for the reason that makes this test meaningful"
    are different claims. A bundle rejected for being unreadable rather than wrong-role would
    otherwise let this stage report that the product validates roles.
    """
    recorder = _Recorder()
    check, _expected, _note = INJECTIONS[0]

    drive_failure_injection(
        recorder, _refusing("release_artifact_digest_mismatch"), bundles={check: "/b"}
    )

    assert recorder.outcome(check) == "unproven"
    assert recorder.reason(check) == "acceptance_unexpected_reason_code"


def test_a_product_that_does_not_refuse_at_all_is_the_worst_outcome():
    """An installer that ACCEPTED a wrong-role bundle. Never a pass, never silently dropped."""
    recorder = _Recorder()
    check, _expected, _note = INJECTIONS[0]
    host = _Host({"bootstrap worker": _json(0, {"mode": "dry_run", "classification": "fresh"})})

    drive_failure_injection(recorder, host, bundles={check: "/b"})

    assert recorder.outcome(check) == "unproven"
    assert recorder.reason(check) == "acceptance_expected_refusal_absent"


def test_an_unreachable_host_is_not_read_as_a_refusal():
    """A command that never ran must not satisfy an assertion that the product refused — otherwise
    every injection passes on a broken fleet."""
    recorder = _Recorder()
    check, _expected, _note = INJECTIONS[0]

    drive_failure_injection(recorder, _Host({}), bundles={check: "/b"})

    assert recorder.outcome(check) == "unproven"
    assert recorder.reason(check) == "acceptance_expected_refusal_absent"


def test_a_missing_bundle_is_recorded_not_skipped():
    """The stage contract commits the run to every declared check; a missing fixture is a fact
    about the run, not a licence to omit."""
    recorder = _Recorder()

    drive_failure_injection(recorder, _refusing("release_role_mismatch"), bundles={})

    assert len(recorder.calls) == len(INJECTIONS)
    assert all(outcome == "unproven" for _c, outcome, _r in recorder.calls)


def test_every_injection_expects_a_distinct_product_code():
    """Two rows sharing a code would make one unfalsifiable — it would pass on its sibling's
    defect being found."""
    codes = [expected for _c, expected, _n in INJECTIONS]
    assert len(set(codes)) == len(codes)


def test_every_expected_code_is_a_real_product_reason():
    """A code the product no longer emits turns its row into a branch that can never be taken."""
    from secp_acceptance.reasons import PRODUCT_REASONS

    for _check, expected, _note in INJECTIONS:
        assert expected in PRODUCT_REASONS


def test_every_injection_names_a_declared_failure_injection_check():
    from secp_acceptance.reasons import CHECKS_BY_STAGE, STAGE_FAILURE_INJECTION

    declared = set(CHECKS_BY_STAGE[STAGE_FAILURE_INJECTION])
    for check, _expected, _note in INJECTIONS:
        assert check in declared


# --------------------------------------------------------------------------- the dry-run default


def test_a_declared_dry_run_enrollment_is_observed():
    recorder = _Recorder()
    host = _Host({"worker enroll": _json(0, {"mode": "dry_run"})})

    drive_dry_run_default(recorder, host, "/inv.json")

    assert recorder.outcome("enroll_without_write_confirm_is_dry_run") == "observed"


def test_an_enrollment_that_wrote_without_being_asked_is_a_violation():
    """The prohibited state, positively observed: the default mutated."""
    recorder = _Recorder()
    host = _Host({"worker enroll": _json(0, {"mode": "written"})})

    drive_dry_run_default(recorder, host, "/inv.json")

    assert recorder.outcome("enroll_without_write_confirm_is_dry_run") == "violated"


def test_an_unreadable_enrollment_report_proves_nothing_about_the_default():
    recorder = _Recorder()

    drive_dry_run_default(recorder, _Host({}), "/inv.json")

    assert recorder.outcome("enroll_without_write_confirm_is_dry_run") == "unproven"
