"""Execution outcomes, convergence verification and reset-intent authorization (v1).

This module is provider-neutral and executes nothing. It defines the *shape* an executor's report
must take and the *measurement* that decides whether an instance converged, so a future real
executor is held to the same contract as the simulator rather than inventing its own.

Three properties are load-bearing here, and each exists because its opposite is the easy mistake:

* **Convergence is measured, never reported.** :func:`verify_convergence` takes a *fresh
  observation* and re-runs the ordinary verification and classification path over it. An executor
  saying "I applied everything" is not evidence that anything converged — it is evidence about the
  executor. When the re-observation cannot itself be verified the verdict is ``unverifiable``,
  which is deliberately not ``drift_remains`` and, above all, not ``converged``.

* **A no-op is distinguishable from a repeat.** :class:`~secp_reconciliation.v1.codes.
  ExecutionOutcome` separates ``no_op`` from ``applied``, and every step carries a status. "Ran
  twice and the system is still fine" is a weaker claim than "the second run did nothing", and
  only the second is idempotence.

* **A partial execution is legible.** Every planned step appears in the report with exactly one
  status — ``applied``, ``failed`` or ``not_attempted`` — plus a bounded next step the operator can
  act on. A report that says only *that* something failed is not actionable.

Every value that leaves this module is a version, a closed code, a count, a digest, a canonical
timestamp or an authored (desired-side) element reference. No provider identity, no facet value.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from secp_reconciliation.v1.classify import DriftReport, classify_drift
from secp_reconciliation.v1.codes import (
    DRIFT_KIND_ORDER,
    NEXT_STEP_FOR_CONVERGENCE,
    NEXT_STEP_FOR_STEP_FAILURE,
    STEP_STATUS_ORDER,
    ActionKind,
    ConvergenceState,
    DriftKind,
    ElementKind,
    ExecutionOutcome,
    OperatorNextStep,
    ReconciliationRefused,
    RefusalCode,
    ResetScope,
    StepFailureReason,
    StepStatus,
)
from secp_reconciliation.v1.digest import as_utc, canonical_utc, document_digest
from secp_reconciliation.v1.planner import ReconciliationPlan, require_plan_integrity
from secp_reconciliation.v1.reset import ResetIntent
from secp_reconciliation.v1.state import (
    DesiredState,
    ObservedState,
    ReconciliationScope,
    observed_state_digest,
    verify_inputs,
)

EXECUTION_REPORT_SCHEMA_VERSION = "secp-recon/execution-report/v1"
CONVERGENCE_VERDICT_SCHEMA_VERSION = "secp-recon/convergence-verdict/v1"

_STEP_STATUS_RANK = {status: index for index, status in enumerate(STEP_STATUS_ORDER)}


# --- Reset-intent authorization -----------------------------------------------------------------


def verify_reset_intent(
    *,
    intent: ResetIntent,
    plan: ReconciliationPlan,
    now: datetime,
) -> None:
    """Fail-closed check that this intent authorizes *this* plan, right now.

    The intent binds an exact ``plan_digest``, so an intent issued for one plan cannot authorize
    another. The plan's own integrity is re-checked first: without that, a tampered plan whose
    digest field still held the authorized value would present a matching intent and pass.
    """
    require_plan_integrity(plan)
    if intent.plan_digest != plan.plan_digest:
        raise ReconciliationRefused(RefusalCode.reset_intent_plan_mismatch)
    moment = as_utc(now)
    if moment < as_utc(datetime.fromisoformat(intent.issued_at)):
        raise ReconciliationRefused(RefusalCode.reset_intent_not_yet_valid)
    if moment >= as_utc(datetime.fromisoformat(intent.expires_at)):
        raise ReconciliationRefused(RefusalCode.reset_intent_expired)


def require_execution_authorized(
    *,
    plan: ReconciliationPlan,
    intent: ResetIntent | None,
    now: datetime,
) -> None:
    """Gate every execution: a plan that would change something needs an authorization.

    A converged plan changes nothing, so there is nothing for an intent to authorize -- and
    :func:`~secp_reconciliation.v1.reset.build_reset_intent` correctly refuses to issue a vacuous
    one. Demanding an intent unconditionally would therefore make the converged case unexecutable
    and ``no_op`` unreachable, while demanding it only when actions exist keeps an authorization on
    every path that can actually write. The plan's integrity is checked either way, so the no-intent
    path is not a way around it.

    This lives in the contract rather than in the executor on purpose: it is the rule, not one
    executor's implementation of the rule.
    """
    if intent is not None:
        verify_reset_intent(intent=intent, plan=plan, now=now)
        return
    require_plan_integrity(plan)
    if plan.actions:
        raise ReconciliationRefused(RefusalCode.execution_unauthorized)


# --- Execution reporting ------------------------------------------------------------------------


@dataclass(frozen=True)
class StepOutcome:
    """What became of one planned step. ``element_ref`` is always a desired-side reference."""

    status: StepStatus
    kind: ActionKind
    element_kind: ElementKind
    element_ref: str
    failure_reason: StepFailureReason | None = None


@dataclass(frozen=True)
class ExecutionReport:
    """The complete, bounded account of one execution attempt.

    ``steps`` covers every action the plan declared — nothing is omitted on the grounds that it did
    not run, because "absent from the report" and "did not need doing" would then be the same
    thing.
    """

    schema_version: str
    instance_id: str
    execution_surface: str
    outcome: ExecutionOutcome
    steps: tuple[StepOutcome, ...]
    plan_digest: str
    intent_digest: str
    world_digest_before: str
    world_digest_after: str
    operator_next_step: OperatorNextStep
    executed_at: str
    report_digest: str

    def counts_by_status(self) -> dict[StepStatus, int]:
        counts = {status: 0 for status in STEP_STATUS_ORDER}
        for step in self.steps:
            counts[step.status] += 1
        return counts

    def changed_anything(self) -> bool:
        """Whether this execution moved the world at all, decided by the world's content address
        rather than by the step list — so a step that "applied" without changing anything cannot
        make a no-op look like work."""
        return self.world_digest_before != self.world_digest_after


def next_step_for(steps: tuple[StepOutcome, ...]) -> OperatorNextStep:
    """The bounded action an operator should take, derived from the most blocking step outcome.

    Total over what can appear: a failed step maps through
    :data:`~secp_reconciliation.v1.codes.NEXT_STEP_FOR_STEP_FAILURE`, and an execution with no
    failure needs nothing further from the operator.
    """
    for step in steps:
        if step.status is StepStatus.failed and step.failure_reason is not None:
            return NEXT_STEP_FOR_STEP_FAILURE[step.failure_reason]
    return OperatorNextStep.none_required


def outcome_for(steps: tuple[StepOutcome, ...]) -> ExecutionOutcome:
    """Whether the attempt applied everything, did nothing, or stopped part way."""
    if any(step.status is StepStatus.failed for step in steps):
        return ExecutionOutcome.partial
    if any(step.status is StepStatus.applied for step in steps):
        return ExecutionOutcome.applied
    return ExecutionOutcome.no_op


def build_execution_report(
    *,
    instance_id: str,
    execution_surface: str,
    steps: tuple[StepOutcome, ...],
    plan_digest: str,
    intent_digest: str,
    world_digest_before: str,
    world_digest_after: str,
    executed_at: datetime,
) -> ExecutionReport:
    """Assemble a content-addressed execution report. Outcome and next step are *derived* from the
    step outcomes rather than passed in, so a caller cannot report a rosier verdict than its own
    steps support."""
    outcome = outcome_for(steps)
    operator_next_step = next_step_for(steps)
    moment = canonical_utc(executed_at)
    body = {
        "instance_id": instance_id,
        "execution_surface": execution_surface,
        "outcome": outcome.value,
        "steps": [
            [
                step.status.value,
                step.kind.value,
                step.element_kind.value,
                step.element_ref,
                step.failure_reason.value if step.failure_reason is not None else "",
            ]
            for step in steps
        ],
        "plan_digest": plan_digest,
        "intent_digest": intent_digest,
        "world_digest_before": world_digest_before,
        "world_digest_after": world_digest_after,
        "operator_next_step": operator_next_step.value,
        "executed_at": moment,
    }
    return ExecutionReport(
        schema_version=EXECUTION_REPORT_SCHEMA_VERSION,
        instance_id=instance_id,
        execution_surface=execution_surface,
        outcome=outcome,
        steps=steps,
        plan_digest=plan_digest,
        intent_digest=intent_digest,
        world_digest_before=world_digest_before,
        world_digest_after=world_digest_after,
        operator_next_step=operator_next_step,
        executed_at=moment,
        report_digest=document_digest(EXECUTION_REPORT_SCHEMA_VERSION, body),
    )


# --- Convergence, measured by re-observation ----------------------------------------------------


@dataclass(frozen=True)
class ConvergenceVerdict:
    """Whether the instance converged, established from a fresh observation of it.

    ``refusal_code`` is populated only when the re-observation could not be verified, in which case
    ``state`` is ``unverifiable``. It is the bounded code the ordinary gate raised — the verdict
    never invents one and never downgrades an unverifiable result into a negative one.
    """

    schema_version: str
    state: ConvergenceState
    residual_counts_by_kind: tuple[tuple[str, int], ...]
    reobserved_digest: str
    report_digest: str
    operator_next_step: OperatorNextStep
    refusal_code: str
    verdict_digest: str

    def converged(self) -> bool:
        return self.state is ConvergenceState.converged


def _verdict(
    *,
    state: ConvergenceState,
    residual: tuple[tuple[str, int], ...],
    reobserved_digest: str,
    report_digest: str,
    refusal_code: str,
) -> ConvergenceVerdict:
    operator_next_step = NEXT_STEP_FOR_CONVERGENCE[state]
    body = {
        "state": state.value,
        "residual_counts_by_kind": {name: count for name, count in residual},
        "reobserved_digest": reobserved_digest,
        "report_digest": report_digest,
        "operator_next_step": operator_next_step.value,
        "refusal_code": refusal_code,
    }
    return ConvergenceVerdict(
        schema_version=CONVERGENCE_VERDICT_SCHEMA_VERSION,
        state=state,
        residual_counts_by_kind=residual,
        reobserved_digest=reobserved_digest,
        report_digest=report_digest,
        operator_next_step=operator_next_step,
        refusal_code=refusal_code,
        verdict_digest=document_digest(CONVERGENCE_VERDICT_SCHEMA_VERSION, body),
    )


def verify_convergence(
    *,
    scope: ReconciliationScope,
    desired: DesiredState,
    reobserved: ObservedState,
    now: datetime,
) -> ConvergenceVerdict:
    """Decide convergence by re-observing and re-classifying — never by asking the executor.

    ``reobserved`` must be a *fresh* observation taken after the execution. It goes through the
    same :func:`~secp_reconciliation.v1.state.verify_inputs` gate as any other observation, so a
    stale, incomplete or inconsistent re-observation yields ``unverifiable`` rather than a
    convergence claim resting on evidence the contract would otherwise have refused.
    """
    empty_residual = tuple((kind.value, 0) for kind in DRIFT_KIND_ORDER)
    try:
        pair = verify_inputs(scope=scope, desired=desired, observed=reobserved, now=now)
    except ReconciliationRefused as refusal:
        return _verdict(
            state=ConvergenceState.unverifiable,
            residual=empty_residual,
            reobserved_digest=observed_state_digest(reobserved),
            report_digest="",
            refusal_code=refusal.code.value,
        )

    report: DriftReport = classify_drift(pair)
    counts = report.counts_by_kind()
    residual = tuple((kind.value, counts[kind]) for kind in DRIFT_KIND_ORDER)
    state = ConvergenceState.converged if report.findings == () else ConvergenceState.drift_remains
    return _verdict(
        state=state,
        residual=residual,
        reobserved_digest=report.observed_digest,
        report_digest=report.report_digest,
        refusal_code="",
    )


def residual_kinds(verdict: ConvergenceVerdict) -> tuple[DriftKind, ...]:
    """The drift kinds still present after execution, in severity order."""
    present = {name for name, count in verdict.residual_counts_by_kind if count}
    return tuple(kind for kind in DRIFT_KIND_ORDER if kind.value in present)


__all__ = [
    "CONVERGENCE_VERDICT_SCHEMA_VERSION",
    "EXECUTION_REPORT_SCHEMA_VERSION",
    "ConvergenceVerdict",
    "ExecutionReport",
    "ResetScope",
    "StepOutcome",
    "build_execution_report",
    "require_execution_authorized",
    "next_step_for",
    "outcome_for",
    "residual_kinds",
    "verify_convergence",
    "verify_reset_intent",
]
