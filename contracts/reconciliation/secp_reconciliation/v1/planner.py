"""Reconciliation planning (v1): a verified pair + its drift report -> a plan. Planning only.

The planner produces a description of what *would* converge the instance. It executes nothing,
contacts nothing, and holds no port, transport or context through which it could.

Its refusal boundaries are the point of the module. It refuses — never returning a partial or
best-effort plan — when:

* the drift report was not produced from this exact verified pair;
* any ``identity_conflict`` drift exists: the same reference denotes incompatible things, and no
  create-or-update sequence can resolve that without an operator deciding what the reference means;
* any ``indeterminate`` drift exists: a desired facet has no observed evidence, so planning would
  be guessing. This is the "unverifiable input refuses rather than passes quietly" boundary, one
  step further in than the input gate — the observation was well-formed, it was just silent about
  something the plan would have to act on;
* the plan would exceed the scope's declared change budget.

An element observed inside the scope but absent from the desired state is **deferred**, never
planned. :class:`~secp_reconciliation.v1.codes.ActionKind` has no removal member, so this is not a
policy the planner applies — it is a shape the plan cannot express. The plan says so in its
disposition (``operator_decision_required``) rather than quietly converging around it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from secp_reconciliation.v1.classify import DriftReport, classify_drift
from secp_reconciliation.v1.codes import (
    ACTION_FOR_DRIFT_KIND,
    ACTION_KIND_ORDER,
    DRIFT_REASON_ORDER,
    ELEMENT_KIND_ORDER,
    ActionKind,
    DriftKind,
    DriftReason,
    ElementKind,
    PlanDisposition,
    ReconciliationRefused,
    RefusalCode,
)
from secp_reconciliation.v1.digest import document_digest
from secp_reconciliation.v1.state import (
    DesiredState,
    ObservedState,
    ReconciliationScope,
    VerifiedStatePair,
    desired_state_digest,
    observed_state_digest,
    require_verified,
    verify_inputs,
)

RECONCILIATION_PLAN_SCHEMA_VERSION = "secp-recon/reconciliation-plan/v1"

# Drift kinds the planner refuses on, in the order it checks them. Both are unactionable for the
# same underlying reason: the plan would have to invent a decision the evidence does not support.
REFUSING_DRIFT_KINDS: tuple[tuple[DriftKind, RefusalCode], ...] = (
    (DriftKind.identity_conflict, RefusalCode.identity_conflict_unresolvable),
    (DriftKind.indeterminate, RefusalCode.drift_indeterminate),
)

_ACTION_RANK = {kind: index for index, kind in enumerate(ACTION_KIND_ORDER)}
_ELEMENT_KIND_RANK = {kind: index for index, kind in enumerate(ELEMENT_KIND_ORDER)}
_REASON_RANK = {reason: index for index, reason in enumerate(DRIFT_REASON_ORDER)}


@dataclass(frozen=True)
class PlannedAction:
    """One bounded step. ``element_ref`` is always an authored, desired-side reference."""

    kind: ActionKind
    element_kind: ElementKind
    element_ref: str
    reasons: tuple[DriftReason, ...]


@dataclass(frozen=True)
class DeferredElement:
    """Drift the plan deliberately does not act on. Bounded to a kind and a reason — an unmanaged
    element's identity is provider-supplied and never enters the plan."""

    element_kind: ElementKind
    reason: DriftReason


@dataclass(frozen=True)
class ReconciliationPlan:
    """What would converge the instance, bound to the exact inputs it was derived from."""

    schema_version: str
    instance_id: str
    execution_surface: str
    disposition: PlanDisposition
    actions: tuple[PlannedAction, ...]
    deferred: tuple[DeferredElement, ...]
    desired_digest: str
    observed_digest: str
    report_digest: str
    plan_digest: str

    def action_counts(self) -> dict[ActionKind, int]:
        counts = {kind: 0 for kind in ACTION_KIND_ORDER}
        for action in self.actions:
            counts[action.kind] += 1
        return counts

    def element_kind_counts(self) -> dict[ElementKind, int]:
        counts = {kind: 0 for kind in ELEMENT_KIND_ORDER}
        for action in self.actions:
            counts[action.element_kind] += 1
        return counts


def _plan_document(
    *,
    instance_id: str,
    execution_surface: str,
    disposition: PlanDisposition,
    actions: tuple[PlannedAction, ...],
    deferred: tuple[DeferredElement, ...],
    desired_digest: str,
    observed_digest: str,
    report_digest: str,
) -> dict:
    return {
        "instance_id": instance_id,
        "execution_surface": execution_surface,
        "disposition": disposition.value,
        "actions": [
            [
                action.kind.value,
                action.element_kind.value,
                action.element_ref,
                [reason.value for reason in action.reasons],
            ]
            for action in actions
        ],
        "deferred": [[item.element_kind.value, item.reason.value] for item in deferred],
        "desired_digest": desired_digest,
        "observed_digest": observed_digest,
        "report_digest": report_digest,
    }


def plan_reconciliation(pair: VerifiedStatePair, report: DriftReport) -> ReconciliationPlan:
    """Turn a verified pair and its drift report into a plan, or refuse with a bounded code."""
    require_verified(pair)

    desired_digest = desired_state_digest(pair.desired)
    observed_digest = observed_state_digest(pair.observed)
    if report.desired_digest != desired_digest or report.observed_digest != observed_digest:
        raise ReconciliationRefused(RefusalCode.verification_token_invalid)

    present = report.kinds_present()
    for kind, refusal in REFUSING_DRIFT_KINDS:
        if kind in present:
            raise ReconciliationRefused(refusal)

    reasons_by_element: dict[tuple[ElementKind, str], list[DriftReason]] = {}
    action_kind_by_element: dict[tuple[ElementKind, str], ActionKind] = {}
    deferred: list[DeferredElement] = []
    for finding in report.findings:
        if finding.kind is DriftKind.unmanaged:
            deferred.append(
                DeferredElement(element_kind=finding.element_kind, reason=finding.reason)
            )
            continue
        key = (finding.element_kind, finding.element_ref)
        reasons_by_element.setdefault(key, []).append(finding.reason)
        action_kind_by_element[key] = ACTION_FOR_DRIFT_KIND[finding.kind]

    actions = tuple(
        sorted(
            (
                PlannedAction(
                    kind=action_kind_by_element[key],
                    element_kind=key[0],
                    element_ref=key[1],
                    reasons=tuple(sorted(reasons, key=lambda r: _REASON_RANK[r])),
                )
                for key, reasons in reasons_by_element.items()
            ),
            key=lambda action: (
                _ACTION_RANK[action.kind],
                _ELEMENT_KIND_RANK[action.element_kind],
                action.element_ref,
            ),
        )
    )
    if len(actions) > pair.scope.max_actions:
        raise ReconciliationRefused(RefusalCode.change_budget_exceeded)

    ordered_deferred = tuple(
        sorted(
            deferred, key=lambda item: (_ELEMENT_KIND_RANK[item.element_kind], item.reason.value)
        )
    )
    if ordered_deferred:
        disposition = PlanDisposition.operator_decision_required
    elif actions:
        disposition = PlanDisposition.actionable
    else:
        disposition = PlanDisposition.converged

    document = _plan_document(
        instance_id=pair.scope.instance_id,
        execution_surface=pair.scope.execution_surface,
        disposition=disposition,
        actions=actions,
        deferred=ordered_deferred,
        desired_digest=desired_digest,
        observed_digest=observed_digest,
        report_digest=report.report_digest,
    )
    return ReconciliationPlan(
        schema_version=RECONCILIATION_PLAN_SCHEMA_VERSION,
        instance_id=pair.scope.instance_id,
        execution_surface=pair.scope.execution_surface,
        disposition=disposition,
        actions=actions,
        deferred=ordered_deferred,
        desired_digest=desired_digest,
        observed_digest=observed_digest,
        report_digest=report.report_digest,
        plan_digest=document_digest(RECONCILIATION_PLAN_SCHEMA_VERSION, document),
    )


def plan_from_states(
    *,
    scope: ReconciliationScope,
    desired: DesiredState,
    observed: ObservedState,
    now: datetime,
) -> tuple[VerifiedStatePair, DriftReport, ReconciliationPlan]:
    """Verify, classify and plan in one call. Returns the intermediate artefacts too, because the
    evidence document binds all three."""
    pair = verify_inputs(scope=scope, desired=desired, observed=observed, now=now)
    report = classify_drift(pair)
    return (pair, report, plan_reconciliation(pair, report))
