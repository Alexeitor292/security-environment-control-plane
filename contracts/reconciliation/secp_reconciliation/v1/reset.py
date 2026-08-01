"""The reset intent contract (v1): structured, versioned, machine-readable, digest-safe.

A reset intent is the *authorization* artefact, not the payload. Like the control plane's existing
change-set approvals, it binds an exact content address — here the ``plan_digest``, which in turn
binds the exact desired state, observation and drift report the plan came from. Every value it
carries is a version, a closed code, a count, a digest, a canonical timestamp or the control
plane's own ``instance_id``: no element reference, no facet value, no provider identity. Its exact
key set is pinned by ``tests/test_reconciliation_drift_and_planning.py``.

It also has its own refusal boundaries. An instance-wide reset over a plan that has deferred
elements would sweep across resources the planner deliberately declined to touch, so it refuses;
an intent that authorizes nothing, or whose validity window is empty, refuses too rather than
sitting around as a vacuous authorization that could later be reinterpreted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from secp_reconciliation.v1.codes import (
    ACTION_KIND_ORDER,
    CONTRACT_VERSION,
    ELEMENT_KIND_ORDER,
    PlanDisposition,
    ReconciliationRefused,
    RefusalCode,
    ResetScope,
)
from secp_reconciliation.v1.digest import as_utc, canonical_utc, document_digest
from secp_reconciliation.v1.planner import ReconciliationPlan

RESET_INTENT_SCHEMA_VERSION = "secp-recon/reset-intent/v1"


@dataclass(frozen=True)
class ResetIntent:
    """A bounded, content-addressed authorization to reconcile one instance."""

    schema_version: str
    contract_version: str
    instance_id: str
    reset_scope: ResetScope
    execution_surface: str
    disposition: PlanDisposition
    desired_digest: str
    observed_digest: str
    report_digest: str
    plan_digest: str
    action_counts: tuple[tuple[str, int], ...]
    element_kind_counts: tuple[tuple[str, int], ...]
    deferred_count: int
    issued_at: str
    expires_at: str
    intent_digest: str

    def document(self) -> dict:
        """The machine-readable form. Every value is a version, a closed code, a count, a digest
        or a canonical timestamp."""
        return {
            "schema_version": self.schema_version,
            "contract_version": self.contract_version,
            "instance_id": self.instance_id,
            "reset_scope": self.reset_scope.value,
            "execution_surface": self.execution_surface,
            "disposition": self.disposition.value,
            "desired_digest": self.desired_digest,
            "observed_digest": self.observed_digest,
            "report_digest": self.report_digest,
            "plan_digest": self.plan_digest,
            "action_counts": {name: count for name, count in self.action_counts},
            "element_kind_counts": {name: count for name, count in self.element_kind_counts},
            "deferred_count": self.deferred_count,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "intent_digest": self.intent_digest,
        }


def build_reset_intent(
    *,
    plan: ReconciliationPlan,
    reset_scope: ResetScope,
    issued_at: datetime,
    expires_at: datetime,
) -> ResetIntent:
    """Build a reset intent for an exact plan, or refuse with a bounded code."""
    if as_utc(expires_at) <= as_utc(issued_at):
        raise ReconciliationRefused(RefusalCode.reset_window_invalid)
    if not plan.actions:
        raise ReconciliationRefused(RefusalCode.reset_scope_unsafe)
    if reset_scope is ResetScope.instance and plan.deferred:
        raise ReconciliationRefused(RefusalCode.reset_scope_unsafe)

    action_counts = tuple((kind.value, plan.action_counts()[kind]) for kind in ACTION_KIND_ORDER)
    element_kind_counts = tuple(
        (kind.value, plan.element_kind_counts()[kind]) for kind in ELEMENT_KIND_ORDER
    )
    body = {
        "contract_version": CONTRACT_VERSION,
        "instance_id": plan.instance_id,
        "reset_scope": reset_scope.value,
        "execution_surface": plan.execution_surface,
        "disposition": plan.disposition.value,
        "desired_digest": plan.desired_digest,
        "observed_digest": plan.observed_digest,
        "report_digest": plan.report_digest,
        "plan_digest": plan.plan_digest,
        "action_counts": {name: count for name, count in action_counts},
        "element_kind_counts": {name: count for name, count in element_kind_counts},
        "deferred_count": len(plan.deferred),
        "issued_at": canonical_utc(issued_at),
        "expires_at": canonical_utc(expires_at),
    }
    return ResetIntent(
        schema_version=RESET_INTENT_SCHEMA_VERSION,
        contract_version=CONTRACT_VERSION,
        instance_id=plan.instance_id,
        reset_scope=reset_scope,
        execution_surface=plan.execution_surface,
        disposition=plan.disposition,
        desired_digest=plan.desired_digest,
        observed_digest=plan.observed_digest,
        report_digest=plan.report_digest,
        plan_digest=plan.plan_digest,
        action_counts=action_counts,
        element_kind_counts=element_kind_counts,
        deferred_count=len(plan.deferred),
        issued_at=canonical_utc(issued_at),
        expires_at=canonical_utc(expires_at),
        intent_digest=document_digest(RESET_INTENT_SCHEMA_VERSION, body),
    )
