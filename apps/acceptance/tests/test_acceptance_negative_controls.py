"""Every declared negative control must run, and must fail in the way it declared.

TWO SEPARATE PROPERTIES, AND THE SECOND IS THE ONE THAT ROTS
------------------------------------------------------------
1. The judging is correct — a control that passed is caught, a control that failed for the wrong
   reason is not accepted as proof.
2. Every DECLARED control is actually executed by the workflow. A control that is listed here and
   run by nothing is invisible: `judge_all` would report it ``unproven``, but only if something
   fed it results, and nothing would.

The second is the inversion this program keeps arriving at — declare first, prove execution
separately — and it is the same shape as the container-tier node pin.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml
from secp_acceptance import AcceptanceError
from secp_acceptance.negative_controls import (
    DECLARED_CONTROLS,
    NegativeControl,
    NegativeControlResult,
    assert_controls_demonstrated,
    judge_all,
    judge_control,
)
from secp_acceptance.reasons import (
    HARNESS_REASONS,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
)

_CONTROL = DECLARED_CONTROLS[0]


def _result(**overrides) -> NegativeControlResult:
    """A result that satisfies the first declared control, before overrides."""
    base = {
        "control_id": _CONTROL.control_id,
        "exit_code": 1,
        "reason_codes_present": (_CONTROL.expected_reason,),
        "nodes_total": 13,
        "nodes_failed": 13,
        "nodes_skipped": 0,
    }
    return NegativeControlResult(**{**base, **overrides})


# --------------------------------------------------------------------------- the declarations


def test_every_declared_control_names_a_bounded_reason():
    """A control that "fails somehow" proves only that something is broken. The point is that the
    specific mechanism under demonstration refused."""
    assert DECLARED_CONTROLS
    for control in DECLARED_CONTROLS:
        assert control.expected_reason in HARNESS_REASONS
        assert control.induces.strip(), f"{control.control_id} does not say what it induces"


def test_a_control_declaring_an_unknown_reason_is_refused_at_construction():
    """The vocabulary is closed here too, and it fails at BUILD rather than at judging time."""
    with pytest.raises(AcceptanceError) as exc:
        NegativeControl(control_id="bogus", induces="x", expected_reason="a_code_nobody_reviewed")
    assert exc.value.reason_code == "acceptance_evidence_unknown_reason"


def test_control_ids_are_unique():
    ids = [control.control_id for control in DECLARED_CONTROLS]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- the judging


def test_a_control_that_failed_correctly_is_a_PASS():
    """Polarity check. For a negative control, refusing IS success."""
    verdict = judge_control(_CONTROL, _result())
    assert verdict.outcome == OUTCOME_REFUSED
    assert verdict.passed is True


def test_a_control_that_PASSED_is_the_most_serious_result():
    """THE failure this clause exists for. The control exited 0, so the gate it demonstrates is now
    unverified — and a CI summary looks identical to when it worked."""
    verdict = judge_control(_CONTROL, _result(exit_code=0))
    assert verdict.outcome == OUTCOME_VIOLATED
    assert verdict.reason_code == "acceptance_negative_control_did_not_fail"
    assert verdict.passed is False


def test_a_control_that_failed_for_the_WRONG_reason_is_not_proof():
    """It failed — but not via the mechanism under demonstration, so it demonstrates nothing.

    The same distinction ``expect_refusal`` draws between "the product refused" and "the product
    refused for the reason that makes this test meaningful".
    """
    verdict = judge_control(
        _CONTROL, _result(reason_codes_present=("acceptance_host_create_failed",))
    )
    assert verdict.outcome == OUTCOME_UNPROVEN
    assert verdict.reason_code == "acceptance_unexpected_reason_code"
    assert verdict.passed is False


def test_a_control_that_SKIPPED_its_way_to_failure_is_unproven():
    """A skip proves nothing about itself. A control that "failed" by skipping has not demonstrated
    its mechanism, whatever the exit code says."""
    verdict = judge_control(_CONTROL, _result(nodes_failed=12, nodes_skipped=1))
    assert verdict.outcome == OUTCOME_UNPROVEN
    assert verdict.passed is False


def test_a_control_where_only_SOME_nodes_failed_is_unproven():
    """The declared control breaks a precondition the whole tier depends on, so a partial failure
    means something other than the induced condition was in play."""
    verdict = judge_control(_CONTROL, _result(nodes_failed=7))
    assert verdict.outcome == OUTCOME_UNPROVEN
    assert verdict.passed is False


def test_a_control_that_collected_NOTHING_is_unproven_not_a_pass():
    """Zero nodes cannot demonstrate anything — and ``0 failed of 0`` satisfies a naive count
    comparison, which is exactly how an empty run reads as a working control."""
    verdict = judge_control(_CONTROL, _result(nodes_total=0, nodes_failed=0))
    assert verdict.outcome == OUTCOME_UNPROVEN
    assert verdict.passed is False


def test_a_control_with_NO_result_is_unproven_not_absent():
    verdict = judge_control(_CONTROL, None)
    assert verdict.outcome == OUTCOME_UNPROVEN
    assert verdict.reason_code == "acceptance_negative_control_missing"


def test_judging_iterates_the_DECLARATIONS_not_the_results():
    """A control that produced nothing must appear in the report as ``unproven``, not vanish.

    Iterating results instead would make a silently-removed control disappear from the output
    entirely, which is the failure this clause is supposed to catch.
    """
    verdicts = judge_all({})
    assert len(verdicts) == len(DECLARED_CONTROLS)
    assert all(v.outcome == OUTCOME_UNPROVEN for v in verdicts)


def test_the_enforcing_form_accepts_a_correctly_demonstrated_control():
    """The control for the test below — without it, an implementation that raised unconditionally
    would satisfy every negative case and prove nothing."""
    assert_controls_demonstrated({_CONTROL.control_id: _result()})  # does not raise


@pytest.mark.parametrize(
    ("label", "results"),
    [
        ("the control passed", {_CONTROL.control_id: _result(exit_code=0)}),
        ("a node skipped", {_CONTROL.control_id: _result(nodes_skipped=1)}),
        ("nothing was collected", {_CONTROL.control_id: _result(nodes_total=0, nodes_failed=0)}),
        ("no result at all", {}),
    ],
)
def test_the_enforcing_form_raises_on_anything_that_is_not_a_refusal(
    label: str, results: dict[str, NegativeControlResult]
):
    with pytest.raises(AcceptanceError):
        assert_controls_demonstrated(results)


# --------------------------------------------------------------------------- execution is proven


def _acceptance_workflow_text() -> str:
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file() and (parent / "infra").is_dir():
            return (parent / ".github" / "workflows" / "acceptance.yml").read_text(encoding="utf-8")
    raise AssertionError("repository root not found from the test file location")


def _control_job() -> dict:
    return yaml.safe_load(_acceptance_workflow_text())["jobs"]["prove-the-tier-can-fail"]


def _step_env(job: dict) -> dict[str, str]:
    """Every environment variable any step of the job SETS, as parsed YAML keys."""
    env: dict[str, str] = {}
    for step in job.get("steps", []):
        env.update({str(k): str(v) for k, v in (step.get("env") or {}).items()})
    return env


def test_every_declared_control_is_actually_EXECUTED_by_the_workflow():
    """A control declared here and run by nothing is invisible.

    KEYED ON THE PARSED ENV KEY, NOT ON A SUBSTRING
    -----------------------------------------------
    This asserted ``"DOCKER_HOST" in text`` and was measured to survive renaming the variable to
    ``DOCKER_HOST_DISABLED`` — the substring is still present, so the guard reported the control as
    executed while the workflow no longer induced anything. A substring match cannot answer "is this
    variable SET", which is a structural question about the YAML; the same lesson acc-B-enrollment
    reached from interned strings and acc-D-lifecycle from ``grep -l`` matching a docstring.

    Keyed on the induced CONDITION rather than the control's id, because the id is a label this
    module chose and the workflow has no reason to carry it — keying on that would be a guard
    agreeing with itself.
    """
    env = _step_env(_control_job())
    assert "DOCKER_HOST" in env, (
        f"no step of the negative-control job SETS DOCKER_HOST, so nothing induces an unreachable "
        f"container runtime and the declared control is executed by nothing. Env keys set: "
        f"{sorted(env)}"
    )
    assert env["DOCKER_HOST"].startswith("tcp://127.0.0.1:"), (
        f"DOCKER_HOST is set to {env['DOCKER_HOST']!r}, which is not an unreachable local port — "
        f"the control may be pointing at a REAL daemon and demonstrating nothing"
    )
    assert _CONTROL.expected_reason in _acceptance_workflow_text(), (
        f"the workflow does not assert on {_CONTROL.expected_reason}, so the control could fail "
        f"for any reason at all and still go green"
    )


def test_the_workflow_control_refuses_skips_and_pins_the_node_count():
    """The two properties `judge_control` enforces must also be enforced where the control runs."""
    run_text = "\n".join(str(step.get("run", "")) for step in _control_job()["steps"])
    assert "skipped" in run_text
    assert "EXPECTED_CONTAINER_NODES" in run_text


def test_the_workflow_reader_is_not_vacuous():
    """CONTROL for the readers above, in both directions.

    A reader returning nothing would satisfy an ``in`` assertion never, but would satisfy the
    ``not in`` shape always — and an env reader that returned every string in the file would satisfy
    the key assertions vacuously. Both are pinned.
    """
    text = _acceptance_workflow_text()
    assert len(text) > 1000
    assert "prove-the-tier-can-fail" in yaml.safe_load(text)["jobs"]

    env = _step_env(_control_job())
    assert env, (
        "the env reader found no variables at all; the key assertions would be unfalsifiable"
    )
    # it reads KEYS, not arbitrary text: a value present in the file is not a key
    assert "prove-the-tier-can-fail" not in env
    assert "a_string_that_is_definitely_not_in_this_workflow_9f3a" not in env
