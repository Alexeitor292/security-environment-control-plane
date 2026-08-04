"""Completion-gate clause C4: every negative control must actually fail.

A GATE NOBODY HAS SEEN FAIL IS NOT A GATE
-----------------------------------------
The acceptance harness's guarantees are all of the form "this run would have caught X". That claim
is worth nothing unless some run demonstrably DOES catch X. So the harness runs negative controls:
deliberately broken conditions whose required result is a loud, bounded refusal.

The failure mode this module exists for is subtle and total: **a negative control that silently
starts passing.** It exits 0, its job goes green, and the gate it was demonstrating is now
unverified — while the CI summary looks exactly as it did when the control worked. Nothing in a
passing report distinguishes "the control fired correctly" from "the control stopped firing".

DECLARED HERE, EXECUTION GUARDED SEPARATELY
-------------------------------------------
The controls are declared in this module, and a required-gate test proves the workflow actually runs
every one of them. That inversion matters: a control that is merely *listed somewhere* and executed
by nothing is invisible, exactly as an appended-when-convenient stage witness would be. Declaring
first and proving execution second is the same shape as the container-tier node pin.

THREE-VALUED, WITH THE POLARITY INVERTED
----------------------------------------
For a negative control, FAILING is the pass. So the contract's own vocabulary maps on directly, and
the mapping is worth reading twice:

``refused``  — the control failed with the reason it declared. This is SUCCESS.
``violated`` — the control PASSED. The harness looked and saw the ruled-out state: a gate that no
               longer bites. This is the most serious result this module can produce.
``unproven`` — no result, or a result that could not be read. Never a pass.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_acceptance import AcceptanceError
from secp_acceptance.reasons import (
    HARNESS_REASONS,
    OUTCOME_REFUSED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
)

#: Sentinel for "every collected node must fail", used when a control breaks a precondition the
#: whole tier depends on rather than a single behaviour.
ALL_NODES = "all"


@dataclass(frozen=True)
class NegativeControl:
    """One deliberately broken condition, and the refusal it must produce.

    ``expected_reason`` must be a member of the closed harness vocabulary. A control that "fails
    somehow" proves only that something is broken; the point is that the SPECIFIC mechanism under
    demonstration is what refused.
    """

    control_id: str
    induces: str
    expected_reason: str
    expected_failing_nodes: str | int = ALL_NODES

    def __post_init__(self) -> None:
        if self.expected_reason not in HARNESS_REASONS:
            raise AcceptanceError("acceptance_evidence_unknown_reason")


@dataclass(frozen=True)
class NegativeControlResult:
    """What a negative-control run actually produced."""

    control_id: str
    exit_code: int
    reason_codes_present: tuple[str, ...]
    nodes_total: int
    nodes_failed: int
    nodes_skipped: int


@dataclass(frozen=True)
class ControlVerdict:
    control_id: str
    outcome: str
    reason_code: str | None

    @property
    def passed(self) -> bool:
        """A negative control passes by REFUSING. Stated as a property so no caller can reach
        success by testing ``outcome != VIOLATED`` and quietly accept ``unproven``."""
        return self.outcome == OUTCOME_REFUSED


#: The controls this harness declares. Each must be executed by the acceptance workflow, which
#: ``test_acceptance_negative_controls.py`` proves.
DECLARED_CONTROLS: tuple[NegativeControl, ...] = (
    NegativeControl(
        control_id="unreachable_container_runtime",
        induces=(
            "DOCKER_HOST points at a closed port, so every docker invocation fails while the "
            "runner's own daemon is untouched and no state is destroyed"
        ),
        expected_reason="acceptance_container_runtime_unavailable",
        expected_failing_nodes=ALL_NODES,
    ),
)


def judge_control(control: NegativeControl, result: NegativeControlResult | None) -> ControlVerdict:
    """Judge one negative control against its declared requirement."""
    if result is None:
        return ControlVerdict(
            control.control_id, OUTCOME_UNPROVEN, "acceptance_negative_control_missing"
        )
    if result.nodes_total <= 0:
        # Zero nodes cannot demonstrate anything, and "0 failed of 0" would otherwise satisfy a
        # naive count comparison.
        return ControlVerdict(
            control.control_id, OUTCOME_UNPROVEN, "acceptance_negative_control_missing"
        )
    if result.exit_code == 0:
        return ControlVerdict(
            control.control_id, OUTCOME_VIOLATED, "acceptance_negative_control_did_not_fail"
        )
    if result.nodes_skipped:
        # A skip is the shape this whole harness refuses: it proves nothing about itself and renders
        # as a tick. A control that "failed" by skipping has not demonstrated its mechanism.
        return ControlVerdict(
            control.control_id, OUTCOME_UNPROVEN, "acceptance_negative_control_did_not_fail"
        )
    if control.expected_reason not in result.reason_codes_present:
        # It failed, but not for the reason that makes the control meaningful — the same distinction
        # `expect_refusal` draws, and for the same reason.
        return ControlVerdict(
            control.control_id, OUTCOME_UNPROVEN, "acceptance_unexpected_reason_code"
        )
    expected = control.expected_failing_nodes
    required = result.nodes_total if expected == ALL_NODES else expected
    if result.nodes_failed != required:
        return ControlVerdict(
            control.control_id, OUTCOME_UNPROVEN, "acceptance_negative_control_did_not_fail"
        )
    return ControlVerdict(control.control_id, OUTCOME_REFUSED, control.expected_reason)


def judge_all(results: dict[str, NegativeControlResult]) -> tuple[ControlVerdict, ...]:
    """Judge every DECLARED control. A control with no result is ``unproven``, never absent.

    Iterating the declarations rather than the results is the load-bearing choice: iterating results
    would make a control that produced nothing simply vanish from the report, which is precisely how
    a silently-removed control escapes notice.
    """
    return tuple(
        judge_control(control, results.get(control.control_id)) for control in DECLARED_CONTROLS
    )


def assert_controls_demonstrated(results: dict[str, NegativeControlResult]) -> None:
    """Raise unless every declared negative control failed in the way it declared."""
    for verdict in judge_all(results):
        if not verdict.passed:
            assert verdict.reason_code is not None
            raise AcceptanceError(verdict.reason_code)


__all__ = [
    "ALL_NODES",
    "DECLARED_CONTROLS",
    "ControlVerdict",
    "NegativeControl",
    "NegativeControlResult",
    "assert_controls_demonstrated",
    "judge_all",
    "judge_control",
]
