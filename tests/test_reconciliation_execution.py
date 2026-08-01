"""Execution, convergence, idempotence, partial failure and reset-intent authorization.

Each section pins one claim, and each is written so the *weak* form of the claim would fail it:

* convergence is established by **re-observing and re-classifying**, never by reading the
  executor's own report — a test that asserted `report.outcome is applied` would be testing the
  executor's opinion of itself;
* idempotence asserts the second run reports ``no_op``, not merely that nothing broke;
* partial failure asserts every planned step is accounted for and the operator is given a bounded
  next action, not merely that an exception surfaced;
* the reset intent is required on exactly the paths that can write.
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta

import pytest
from reconciliation_support import (
    COLLECTOR_DIGEST,
    INSTANCE_ID,
    NOW,
    PROVIDER,
    desired,
    edge,
    network,
    node,
    scope,
)
from secp_plugin_simulator import reconciliation as simulator
from secp_reconciliation.v1 import (
    ConvergenceState,
    DriftKind,
    ElementKind,
    ExecutionOutcome,
    ObservationFidelity,
    OperatorNextStep,
    PlanDisposition,
    ReconciliationRefused,
    RefusalCode,
    ResetScope,
    StepFailureReason,
    StepStatus,
    build_reset_intent,
    plan_from_states,
    residual_kinds,
    verify_convergence,
)

WINDOW = timedelta(hours=1)


def _observe(world, **overrides):
    """Re-observe the world exactly as any collector would. The fidelity is supplied by the
    caller, never manufactured by the simulator."""
    fields = {
        "instance_id": INSTANCE_ID,
        "provider": PROVIDER,
        "collector_digest": COLLECTOR_DIGEST,
        "observed_at": NOW,
        "fidelity": ObservationFidelity.complete,
    }
    fields.update(overrides)
    return simulator.observe(world=world, **fields)


def _intent(plan, **overrides):
    fields = {
        "plan": plan,
        "reset_scope": ResetScope.element_set,
        "issued_at": NOW,
        "expires_at": NOW + WINDOW,
    }
    fields.update(overrides)
    return build_reset_intent(**fields)


def _reconcile(wanted, world, reconciliation_scope=None, now=NOW):
    """Plan against a real observation of the world, then execute under a matching intent."""
    active = reconciliation_scope or scope()
    _, _, plan = plan_from_states(scope=active, desired=wanted, observed=_observe(world), now=now)
    intent = _intent(plan) if plan.actions else None
    after, report = simulator.execute(
        scope=active, plan=plan, desired=wanted, world=world, intent=intent, now=now
    )
    return plan, after, report


# --- 1. Convergence, measured rather than reported ----------------------------------------------


def test_convergence_is_established_by_reobserving_not_by_the_executors_report() -> None:
    wanted = desired(network(), node(), edge())
    plan, after, report = _reconcile(wanted, simulator.SimulatedWorld())
    assert report.outcome is ExecutionOutcome.applied

    # The claim under test: re-observe the world and put it through the ordinary gate and
    # classifier. Nothing here consults `report`.
    verdict = verify_convergence(scope=scope(), desired=wanted, reobserved=_observe(after), now=NOW)
    assert verdict.state is ConvergenceState.converged
    assert verdict.converged()
    assert residual_kinds(verdict) == ()
    assert verdict.operator_next_step is OperatorNextStep.none_required
    assert dict(verdict.residual_counts_by_kind) == {kind.value: 0 for kind in DriftKind}


def test_a_world_that_did_not_converge_is_reported_as_drift_remaining() -> None:
    """The negative control for the test above. If `verify_convergence` returned `converged` for
    everything, the assertion above would pass while proving nothing."""
    wanted = desired(network(), node())
    _, after, _ = _reconcile(wanted, simulator.SimulatedWorld())
    # something changed the world after the fact, behind the reconciler's back
    tampered = simulator.SimulatedWorld(
        elements=tuple(e for e in after.elements if e.ref != "attacker-1")
    )
    verdict = verify_convergence(
        scope=scope(), desired=wanted, reobserved=_observe(tampered), now=NOW
    )
    assert verdict.state is ConvergenceState.drift_remains
    assert residual_kinds(verdict) == (DriftKind.missing,)
    assert verdict.operator_next_step is OperatorNextStep.reobserve_and_replan


def test_an_unverifiable_reobservation_is_unknown_convergence_not_successful_convergence() -> None:
    """The fail-closed member. A stale re-observation must not be able to certify convergence, and
    must not masquerade as a negative result either."""
    wanted = desired(network())
    _, after, _ = _reconcile(wanted, simulator.SimulatedWorld())
    stale = _observe(after, observed_at=NOW - timedelta(hours=1))

    verdict = verify_convergence(scope=scope(), desired=wanted, reobserved=stale, now=NOW)
    assert verdict.state is ConvergenceState.unverifiable
    assert verdict.converged() is False
    assert verdict.refusal_code == RefusalCode.observation_stale.value
    assert verdict.report_digest == ""

    # and the identical world, freshly observed, *does* converge -- so the refusal above is about
    # the observation's provenance, not about the world being wrong
    fresh = verify_convergence(scope=scope(), desired=wanted, reobserved=_observe(after), now=NOW)
    assert fresh.state is ConvergenceState.converged


@pytest.mark.parametrize(
    ("fidelity", "expected"),
    [
        (ObservationFidelity.partial, RefusalCode.observation_incomplete),
        (ObservationFidelity.unverified, RefusalCode.observation_unverified),
    ],
)
def test_a_reobservation_the_collector_will_not_vouch_for_cannot_certify_convergence(
    fidelity, expected
) -> None:
    wanted = desired(network())
    _, after, _ = _reconcile(wanted, simulator.SimulatedWorld())
    verdict = verify_convergence(
        scope=scope(), desired=wanted, reobserved=_observe(after, fidelity=fidelity), now=NOW
    )
    assert verdict.state is ConvergenceState.unverifiable
    assert verdict.refusal_code == expected.value


# --- 2. Idempotence, where the evidence shows the second run did nothing -------------------------


def test_the_second_reconciliation_reports_no_op_rather_than_repeating_the_work() -> None:
    """ "Ran twice and the system is still fine" is the weak claim. This asserts the stronger one:
    the second run's plan had nothing in it and its report says `no_op`, not `applied`."""
    wanted = desired(network(), node(), edge())
    first_plan, converged_world, first_report = _reconcile(wanted, simulator.SimulatedWorld())
    assert first_report.outcome is ExecutionOutcome.applied
    assert first_report.changed_anything() is True
    assert len(first_plan.actions) == 3

    second_plan, after, second_report = _reconcile(wanted, converged_world)
    assert second_plan.actions == ()
    assert second_plan.disposition is PlanDisposition.converged
    assert second_report.outcome is ExecutionOutcome.no_op
    assert second_report.steps == ()
    assert second_report.changed_anything() is False
    assert simulator.world_digest(after) == simulator.world_digest(converged_world)
    assert second_report.operator_next_step is OperatorNextStep.none_required


def test_a_no_op_report_is_distinguishable_from_a_report_that_repeated_the_same_work() -> None:
    """The distinction the vocabulary exists for. Replaying the *first* plan against the already
    converged world is safe -- the world does not move -- but it is not a no-op: every step ran
    again. The two cases must not produce the same evidence."""
    wanted = desired(network(), node())
    first_plan, converged_world, _ = _reconcile(wanted, simulator.SimulatedWorld())

    replayed_world, replay = simulator.execute(
        scope=scope(),
        plan=first_plan,
        desired=wanted,
        world=converged_world,
        intent=_intent(first_plan),
        now=NOW,
    )
    _, _, genuine_no_op = _reconcile(wanted, converged_world)

    # both left the world alone ...
    assert replay.changed_anything() is False
    assert genuine_no_op.changed_anything() is False
    assert simulator.world_digest(replayed_world) == simulator.world_digest(converged_world)
    # ... but only one of them actually did nothing, and the evidence says so
    assert replay.outcome is ExecutionOutcome.applied
    assert genuine_no_op.outcome is ExecutionOutcome.no_op
    assert replay.counts_by_status()[StepStatus.applied] == 2
    assert genuine_no_op.counts_by_status()[StepStatus.applied] == 0
    assert replay.report_digest != genuine_no_op.report_digest


# --- 3. Partial failure leaves a legible, bounded state ------------------------------------------


def test_a_step_that_fails_mid_plan_leaves_every_step_accounted_for() -> None:
    # both nodes are attached to a network the desired state never declares, so nothing in the
    # plan creates it and the very first step fails on a real structural invariant
    wanted = desired(
        node(network_attachment="a-network-nobody-declared"),
        node("sensor-1", network_attachment="a-network-nobody-declared"),
    )
    _, _, plan = plan_from_states(
        scope=scope(),
        desired=wanted,
        observed=_observe(simulator.SimulatedWorld()),
        now=NOW,
    )
    assert len(plan.actions) == 2

    after, report = simulator.execute(
        scope=scope(),
        plan=plan,
        desired=wanted,
        world=simulator.SimulatedWorld(),
        intent=_intent(plan),
        now=NOW,
    )

    assert report.outcome is ExecutionOutcome.partial
    # every planned step is present -- "absent from the report" must never mean "did not need doing"
    assert len(report.steps) == len(plan.actions)
    statuses = [step.status for step in report.steps]
    assert statuses == [StepStatus.failed, StepStatus.not_attempted]
    assert report.steps[0].failure_reason is StepFailureReason.dependency_absent
    assert report.steps[1].failure_reason is None
    # the counts are derived from the steps, not typed
    assert report.counts_by_status() == {
        StepStatus.failed: 1,
        StepStatus.not_attempted: 1,
        StepStatus.applied: 0,
    }
    # and the operator is told what to do, in bounded terms
    assert report.operator_next_step is OperatorNextStep.resolve_dependency_then_replan
    # the world is legibly unchanged rather than half-written and silent
    assert report.changed_anything() is False
    assert after.elements == ()


def test_a_partial_execution_reports_the_work_that_did_land() -> None:
    """Half-applied must be visible *as* half-applied, which is the case the evidence contract
    exists for. The middle step fails on a real structural invariant: the node is attached to a
    network the desired state never declares, so nothing in the plan ever creates it.

    This is the sharper of the two partial-failure tests. The one above leaves the world untouched,
    where "nothing happened" and "cleanly refused" look alike; here work genuinely landed before
    the failure, so the report has to distinguish applied from not-attempted or the operator
    cannot tell what state they are in.
    """
    wanted = desired(network(), node(network_attachment="a-network-nobody-declared"), edge())
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    assert [action.element_kind for action in plan.actions] == [
        ElementKind.network,
        ElementKind.node,
        ElementKind.edge,
    ]

    after, report = simulator.execute(
        scope=scope(),
        plan=plan,
        desired=wanted,
        world=simulator.SimulatedWorld(),
        intent=_intent(plan),
        now=NOW,
    )

    assert report.outcome is ExecutionOutcome.partial
    assert [step.status for step in report.steps] == [
        StepStatus.applied,
        StepStatus.failed,
        StepStatus.not_attempted,
    ]
    assert report.steps[1].failure_reason is StepFailureReason.dependency_absent
    assert report.counts_by_status() == {
        StepStatus.failed: 1,
        StepStatus.not_attempted: 1,
        StepStatus.applied: 1,
    }
    # work landed, and the world says so independently of the step list
    assert report.changed_anything() is True
    assert [element.ref for element in after.elements] == ["team-network"]
    assert report.operator_next_step is OperatorNextStep.resolve_dependency_then_replan


def test_a_partial_execution_is_not_convergent_and_says_so_when_reobserved() -> None:
    """The two mechanisms agree: the execution report says `partial`, and an independent
    re-observation says drift remains. Neither is derived from the other."""
    wanted = desired(
        node(network_attachment="a-network-nobody-declared"),
        node("sensor-1", network_attachment="a-network-nobody-declared"),
    )
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    after, report = simulator.execute(
        scope=scope(),
        plan=plan,
        desired=wanted,
        world=simulator.SimulatedWorld(),
        intent=_intent(plan),
        now=NOW,
    )
    assert report.outcome is ExecutionOutcome.partial

    verdict = verify_convergence(scope=scope(), desired=wanted, reobserved=_observe(after), now=NOW)
    assert verdict.state is ConvergenceState.drift_remains
    assert DriftKind.missing in residual_kinds(verdict)


# --- 4. Reset intent, end to end -----------------------------------------------------------------


def test_a_plan_that_would_change_something_cannot_execute_without_an_intent() -> None:
    wanted = desired(network())
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    assert plan.actions
    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            scope=scope(),
            plan=plan,
            desired=wanted,
            world=simulator.SimulatedWorld(),
            intent=None,
            now=NOW,
        )
    assert raised.value.code is RefusalCode.execution_unauthorized


def test_an_intent_issued_for_a_different_plan_does_not_authorize_this_one() -> None:
    wanted = desired(network())
    other = desired(node("sensor-1", network_attachment=""))
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    _, _, other_plan = plan_from_states(
        scope=scope(), desired=other, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    assert other_plan.plan_digest != plan.plan_digest

    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            scope=scope(),
            plan=plan,
            desired=wanted,
            world=simulator.SimulatedWorld(),
            intent=_intent(other_plan),
            now=NOW,
        )
    assert raised.value.code is RefusalCode.reset_intent_plan_mismatch


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        (NOW - timedelta(seconds=1), RefusalCode.reset_intent_not_yet_valid),
        (NOW + WINDOW, RefusalCode.reset_intent_expired),
        (NOW + WINDOW + timedelta(hours=5), RefusalCode.reset_intent_expired),
    ],
)
def test_an_intent_only_authorizes_inside_its_own_validity_window(moment, expected) -> None:
    wanted = desired(network())
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            scope=scope(),
            plan=plan,
            desired=wanted,
            world=simulator.SimulatedWorld(),
            intent=_intent(plan),
            now=moment,
        )
    assert raised.value.code is expected


def test_the_execution_report_binds_the_intent_that_authorized_it() -> None:
    wanted = desired(network())
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    intent = _intent(plan)
    _, report = simulator.execute(
        scope=scope(),
        plan=plan,
        desired=wanted,
        world=simulator.SimulatedWorld(),
        intent=intent,
        now=NOW,
    )
    assert report.intent_digest == intent.intent_digest
    assert report.plan_digest == plan.plan_digest


def test_an_intent_cannot_authorize_a_plan_that_was_edited_after_it_was_issued() -> None:
    """The intent binds `plan_digest`, and the plan's own integrity is checked first — so editing
    the plan after the intent was issued fails on integrity rather than sliding through on a
    digest field that was never recomputed."""
    wanted = desired(network(), node())
    _, _, plan = plan_from_states(
        scope=scope(), desired=wanted, observed=_observe(simulator.SimulatedWorld()), now=NOW
    )
    intent = _intent(plan)
    edited = dataclasses.replace(plan, actions=plan.actions[:1])
    assert edited.plan_digest == intent.plan_digest  # the binding still *looks* satisfied

    with pytest.raises(ReconciliationRefused) as raised:
        simulator.execute(
            scope=scope(),
            plan=edited,
            desired=wanted,
            world=simulator.SimulatedWorld(),
            intent=intent,
            now=NOW,
        )
    assert raised.value.code is RefusalCode.plan_integrity_invalid
