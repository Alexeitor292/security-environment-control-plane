"""Reconciliation and drift contract — version 1.

Desired versus observed state, drift classification, reconciliation planning, and the reset-intent
and evidence documents. Provider-neutral throughout: the vocabulary is the control plane's own
topology projection (ADR-008), not any provider's object model.

The package is layered so each layer can only do one thing:

* :mod:`~secp_reconciliation.v1.state` verifies inputs and refuses; nothing unverified gets past it.
* :mod:`~secp_reconciliation.v1.classify` compares and is total over drift: it declines to
  classify no disagreement, and it never reads an absent observation as agreement. It refuses only
  on a verification token whose contents were swapped after verification.
* :mod:`~secp_reconciliation.v1.planner` plans and refuses; it executes nothing and holds no port
  or transport through which it could.
* :mod:`~secp_reconciliation.v1.reset` and :mod:`~secp_reconciliation.v1.evidence` emit versioned,
  content-addressed documents carrying only versions, closed codes, counts, digests and timestamps.
* :mod:`~secp_reconciliation.v1.topology_adapter` is the sole module importing the plugin contract.
  It is deliberately **not** re-exported here: importing ``secp_reconciliation.v1`` must not drag
  the plugin contract in, so a consumer of the core takes on no dependency it did not ask for.

Execution lives outside this package entirely, on a simulator that cannot reach a provider.
"""

from secp_reconciliation.v1.classify import (
    DRIFT_REPORT_SCHEMA_VERSION,
    DriftFinding,
    DriftReport,
    classify_drift,
)
from secp_reconciliation.v1.codes import (
    ACTION_FOR_DRIFT_KIND,
    ACTION_KIND_ORDER,
    CONTRACT_VERSION,
    DIVERGENCE_REASON_BY_FACET,
    DRIFT_KIND_ORDER,
    DRIFT_REASON_ORDER,
    DRIFT_REASONS_BY_KIND,
    ELEMENT_KIND_ORDER,
    FACETS_BY_ELEMENT_KIND,
    RETRYABLE_WITH_FRESH_OBSERVATION,
    ActionKind,
    DriftKind,
    DriftReason,
    ElementKind,
    ExecutionSurface,
    FacetName,
    ObservationFidelity,
    PlanDisposition,
    ReconciliationRefused,
    RefusalCode,
    ResetScope,
)
from secp_reconciliation.v1.digest import (
    canonical_json,
    canonical_utc,
    document_digest,
    is_content_digest,
    sha256_digest,
)
from secp_reconciliation.v1.evidence import (
    RECONCILIATION_EVIDENCE_SCHEMA_VERSION,
    REFUSAL_EVIDENCE_SCHEMA_VERSION,
    build_reconciliation_evidence,
    build_refusal_evidence,
)
from secp_reconciliation.v1.planner import (
    RECONCILIATION_PLAN_SCHEMA_VERSION,
    REFUSING_DRIFT_KINDS,
    DeferredElement,
    PlannedAction,
    ReconciliationPlan,
    plan_digest_of,
    plan_from_states,
    plan_reconciliation,
    require_plan_integrity,
    require_planned_under,
)
from secp_reconciliation.v1.reset import (
    RESET_INTENT_SCHEMA_VERSION,
    ResetIntent,
    build_reset_intent,
)
from secp_reconciliation.v1.state import (
    MAX_CLOCK_SKEW_SECONDS,
    DesiredState,
    ObservedState,
    ReconciliationScope,
    StateElement,
    VerifiedStatePair,
    desired_state_digest,
    encode_edge_ref,
    facet_digest,
    observed_state_digest,
    require_verified,
    scope_digest,
    verify_inputs,
)

__all__ = [
    "ACTION_FOR_DRIFT_KIND",
    "ACTION_KIND_ORDER",
    "CONTRACT_VERSION",
    "DIVERGENCE_REASON_BY_FACET",
    "DRIFT_KIND_ORDER",
    "DRIFT_REASONS_BY_KIND",
    "DRIFT_REASON_ORDER",
    "DRIFT_REPORT_SCHEMA_VERSION",
    "ELEMENT_KIND_ORDER",
    "FACETS_BY_ELEMENT_KIND",
    "MAX_CLOCK_SKEW_SECONDS",
    "RECONCILIATION_EVIDENCE_SCHEMA_VERSION",
    "RECONCILIATION_PLAN_SCHEMA_VERSION",
    "REFUSAL_EVIDENCE_SCHEMA_VERSION",
    "REFUSING_DRIFT_KINDS",
    "RESET_INTENT_SCHEMA_VERSION",
    "RETRYABLE_WITH_FRESH_OBSERVATION",
    "ActionKind",
    "DeferredElement",
    "DesiredState",
    "DriftFinding",
    "DriftKind",
    "DriftReason",
    "DriftReport",
    "ElementKind",
    "ExecutionSurface",
    "FacetName",
    "ObservationFidelity",
    "ObservedState",
    "PlanDisposition",
    "PlannedAction",
    "ReconciliationPlan",
    "ReconciliationRefused",
    "ReconciliationScope",
    "RefusalCode",
    "ResetIntent",
    "ResetScope",
    "StateElement",
    "VerifiedStatePair",
    "build_reconciliation_evidence",
    "build_refusal_evidence",
    "build_reset_intent",
    "canonical_json",
    "canonical_utc",
    "classify_drift",
    "desired_state_digest",
    "document_digest",
    "encode_edge_ref",
    "facet_digest",
    "is_content_digest",
    "observed_state_digest",
    "plan_digest_of",
    "plan_from_states",
    "plan_reconciliation",
    "require_plan_integrity",
    "require_planned_under",
    "require_verified",
    "scope_digest",
    "sha256_digest",
    "verify_inputs",
]
