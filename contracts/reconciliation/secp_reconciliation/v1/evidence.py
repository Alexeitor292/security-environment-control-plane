"""The reconciliation evidence contract (v1): structured, versioned, machine-readable, digest-safe.

Evidence records what a reconciliation decided and what it decided it *from*, in a form safe to
persist, serve and audit. Like the control plane's existing redacted evidence documents, every
value is a version, a closed code, a count, a digest or a canonical timestamp — never an element
reference, a facet value, a provider identity, a path, an endpoint, an address, key material or an
exception. Drift is therefore auditable as a distribution over the closed vocabularies without the
evidence itself becoming a channel for what was observed.

A refusal produces evidence too. A reconciliation that refused is a fact worth keeping, and its
document records the bounded code plus whether a fresh observation could plausibly clear it.
"""

from __future__ import annotations

from datetime import datetime

from secp_reconciliation.v1.classify import DRIFT_REPORT_SCHEMA_VERSION, DriftReport
from secp_reconciliation.v1.codes import (
    ACTION_KIND_ORDER,
    CONTRACT_VERSION,
    DRIFT_KIND_ORDER,
    DRIFT_REASON_ORDER,
    ELEMENT_KIND_ORDER,
    RETRYABLE_WITH_FRESH_OBSERVATION,
    RefusalCode,
)
from secp_reconciliation.v1.digest import canonical_utc, document_digest
from secp_reconciliation.v1.planner import RECONCILIATION_PLAN_SCHEMA_VERSION, ReconciliationPlan
from secp_reconciliation.v1.state import ReconciliationScope, scope_digest

RECONCILIATION_EVIDENCE_SCHEMA_VERSION = "secp-recon/reconciliation-evidence/v1"
REFUSAL_EVIDENCE_SCHEMA_VERSION = "secp-recon/reconciliation-refusal-evidence/v1"

# The contract versions an evidence document attributes its verdict to. A change to either moves
# every subsequent evidence digest, so evidence produced by different logic can never be conflated.
_PRODUCER_VERSIONS = {
    "contract_version": CONTRACT_VERSION,
    "classifier_version": DRIFT_REPORT_SCHEMA_VERSION,
    "planner_version": RECONCILIATION_PLAN_SCHEMA_VERSION,
}


def build_reconciliation_evidence(
    *,
    scope: ReconciliationScope,
    report: DriftReport,
    plan: ReconciliationPlan,
    evaluated_at: datetime,
) -> dict:
    """Evidence for a reconciliation that produced a plan. Counts and digests only."""
    kind_counts = report.counts_by_kind()
    reason_counts = report.counts_by_reason()
    action_counts = plan.action_counts()
    element_counts = plan.element_kind_counts()
    body = {
        **_PRODUCER_VERSIONS,
        "outcome": "planned",
        "instance_id": scope.instance_id,
        "scope_digest": scope_digest(scope),
        "execution_surface": plan.execution_surface,
        "desired_digest": plan.desired_digest,
        "observed_digest": plan.observed_digest,
        "report_digest": plan.report_digest,
        "plan_digest": plan.plan_digest,
        "disposition": plan.disposition.value,
        "drift_counts_by_kind": {kind.value: kind_counts[kind] for kind in DRIFT_KIND_ORDER},
        "drift_counts_by_reason": {
            reason.value: reason_counts[reason] for reason in DRIFT_REASON_ORDER
        },
        "action_counts": {kind.value: action_counts[kind] for kind in ACTION_KIND_ORDER},
        "action_element_counts": {kind.value: element_counts[kind] for kind in ELEMENT_KIND_ORDER},
        "deferred_count": len(plan.deferred),
        "evaluated_at": canonical_utc(evaluated_at),
    }
    return {
        "schema_version": RECONCILIATION_EVIDENCE_SCHEMA_VERSION,
        **body,
        "evidence_digest": document_digest(RECONCILIATION_EVIDENCE_SCHEMA_VERSION, body),
    }


def build_refusal_evidence(
    *,
    scope: ReconciliationScope,
    code: RefusalCode,
    evaluated_at: datetime,
) -> dict:
    """Evidence for a reconciliation that refused. The bounded code and nothing about the input
    that caused it."""
    body = {
        **_PRODUCER_VERSIONS,
        "outcome": "refused",
        "instance_id": scope.instance_id,
        "scope_digest": scope_digest(scope),
        "refusal_code": code.value,
        "retryable_with_fresh_observation": code in RETRYABLE_WITH_FRESH_OBSERVATION,
        "evaluated_at": canonical_utc(evaluated_at),
    }
    return {
        "schema_version": REFUSAL_EVIDENCE_SCHEMA_VERSION,
        **body,
        "evidence_digest": document_digest(REFUSAL_EVIDENCE_SCHEMA_VERSION, body),
    }
