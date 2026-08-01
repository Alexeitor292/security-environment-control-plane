"""The closed vocabularies of the reconciliation contract (v1).

Every set here is **closed and exhaustively ordered**. Drift is never described in prose: a finding
carries a :class:`DriftKind` plus one bounded :class:`DriftReason`, and a refusal carries one
bounded :class:`RefusalCode` and nothing else — no path, endpoint, address, key material, provider
value, or raw exception (the control plane's existing redacted-refusal convention).

Provider neutrality is structural rather than declared:

* :class:`ElementKind` is the neutral topology projection every provider populates (ADR-008) —
  there is no member for a provider-shaped object (no VM, no datastore, no bridge, no realm).
* :class:`FacetName` names the *property being compared*, never a provider field
  (``address_space``/``address``, not CIDR/IP-address columns).
* :class:`ExecutionSurface` has exactly **one** member, ``simulator``. The plan model therefore
  cannot express a real-provider execution surface: reaching one is not a disabled option, it is
  an unrepresentable one.
* :class:`ActionKind` has exactly **two** members, ``create`` and ``update``. The planner is
  structurally incapable of emitting a removal, so an unmanaged element observed inside the scope
  can only ever be *deferred* to an operator decision — never silently destroyed (Charter: adoption
  and removal of pre-existing assets are an explicit opt-in workflow, never the default).
"""

from __future__ import annotations

from enum import Enum

CONTRACT_VERSION = "secp-recon/v1"


class ElementKind(str, Enum):
    """The neutral projection every provider populates. Compared, never interpreted."""

    network = "network"
    node = "node"
    edge = "edge"


class FacetName(str, Enum):
    """A comparable property of an element. Neutral names — never a provider field name."""

    # network
    name = "name"
    address_space = "address_space"
    isolation = "isolation"
    team_binding = "team_binding"
    # node
    node_class = "node_class"
    role = "role"
    image = "image"
    network_attachment = "network_attachment"
    address = "address"
    attributes = "attributes"


class DriftKind(str, Enum):
    """The closed set of ways desired and observed state can disagree."""

    identity_conflict = "identity_conflict"
    indeterminate = "indeterminate"
    unmanaged = "unmanaged"
    missing = "missing"
    divergent = "divergent"


class DriftReason(str, Enum):
    """The bounded reason a finding exists. Carries no value, ever."""

    element_kind_conflict = "element_kind_conflict"
    facet_evidence_absent = "facet_evidence_absent"
    element_unmanaged = "element_unmanaged"
    element_absent = "element_absent"
    facet_name_mismatch = "facet_name_mismatch"
    facet_address_space_mismatch = "facet_address_space_mismatch"
    facet_isolation_mismatch = "facet_isolation_mismatch"
    facet_team_binding_mismatch = "facet_team_binding_mismatch"
    facet_node_class_mismatch = "facet_node_class_mismatch"
    facet_role_mismatch = "facet_role_mismatch"
    facet_image_mismatch = "facet_image_mismatch"
    facet_network_attachment_mismatch = "facet_network_attachment_mismatch"
    facet_address_mismatch = "facet_address_mismatch"
    facet_attributes_mismatch = "facet_attributes_mismatch"


class ActionKind(str, Enum):
    """What a planned action would do. There is deliberately no removal member."""

    create = "create"
    update = "update"


class PlanDisposition(str, Enum):
    """Whether the plan, taken whole, converges the instance."""

    converged = "converged"
    actionable = "actionable"
    operator_decision_required = "operator_decision_required"


class ObservationFidelity(str, Enum):
    """What the collector is willing to attest about its own observation."""

    complete = "complete"
    partial = "partial"
    unverified = "unverified"


class ExecutionSurface(str, Enum):
    """Where a plan may be executed. v1 has exactly one member."""

    simulator = "simulator"


class ResetScope(str, Enum):
    """The breadth a reset intent authorizes."""

    instance = "instance"
    element_set = "element_set"


class RefusalCode(str, Enum):
    """The closed set of reasons the planner refuses to produce a plan. Fail closed: an input the
    contract cannot verify refuses here rather than reaching classification or planning."""

    contract_version_unsupported = "reconciliation_contract_version_unsupported"
    scope_invalid = "reconciliation_scope_invalid"
    execution_surface_sealed = "reconciliation_execution_surface_sealed"
    desired_unverified = "reconciliation_desired_unverified"
    desired_state_inconsistent = "reconciliation_desired_state_inconsistent"
    instance_mismatch = "reconciliation_instance_mismatch"
    provider_mismatch = "reconciliation_provider_mismatch"
    observation_unverified = "reconciliation_observation_unverified"
    observation_incomplete = "reconciliation_observation_incomplete"
    observation_stale = "reconciliation_observation_stale"
    observed_state_inconsistent = "reconciliation_observed_state_inconsistent"
    verification_token_invalid = "reconciliation_verification_token_invalid"
    identity_conflict_unresolvable = "reconciliation_identity_conflict_unresolvable"
    drift_indeterminate = "reconciliation_drift_indeterminate"
    change_budget_exceeded = "reconciliation_change_budget_exceeded"
    reset_scope_unsafe = "reconciliation_reset_scope_unsafe"
    reset_window_invalid = "reconciliation_reset_window_invalid"


class ReconciliationRefused(Exception):
    """A fail-closed refusal. It carries **only** the bounded code.

    ``args`` is exactly ``(code.value,)`` and the sole attribute is ``code``, so a refusal cannot
    become a channel for a rejected input, a provider value, or a raw upstream exception — not via
    ``str()``, ``repr()``, ``args``, or ``__dict__``.
    """

    def __init__(self, code: RefusalCode) -> None:
        super().__init__(code.value)
        self.code = code


# --- Ordering -----------------------------------------------------------------------------------
# Drift-kind precedence, most blocking first. One element may raise several findings (two facets
# can diverge independently), so this order is not a partition of elements: it is the total
# severity ordering findings sort by, and it decides which kind a report's summary leads with.
DRIFT_KIND_ORDER: tuple[DriftKind, ...] = (
    DriftKind.identity_conflict,
    DriftKind.indeterminate,
    DriftKind.unmanaged,
    DriftKind.missing,
    DriftKind.divergent,
)

# Reason ordering inside a kind. Findings sort by (kind index, reason index, element ref).
DRIFT_REASON_ORDER: tuple[DriftReason, ...] = (
    DriftReason.element_kind_conflict,
    DriftReason.facet_evidence_absent,
    DriftReason.element_unmanaged,
    DriftReason.element_absent,
    DriftReason.facet_name_mismatch,
    DriftReason.facet_address_space_mismatch,
    DriftReason.facet_isolation_mismatch,
    DriftReason.facet_team_binding_mismatch,
    DriftReason.facet_node_class_mismatch,
    DriftReason.facet_role_mismatch,
    DriftReason.facet_image_mismatch,
    DriftReason.facet_network_attachment_mismatch,
    DriftReason.facet_address_mismatch,
    DriftReason.facet_attributes_mismatch,
)

# Dependency order: a network exists before a node attaches to it, and both exist before an edge
# relates them. Actions are emitted in this order, so a plan reads in the order it would be applied.
ELEMENT_KIND_ORDER: tuple[ElementKind, ...] = (
    ElementKind.network,
    ElementKind.node,
    ElementKind.edge,
)

ACTION_KIND_ORDER: tuple[ActionKind, ...] = (ActionKind.create, ActionKind.update)


# --- Complete partitions ------------------------------------------------------------------------
# Which reasons may appear under which drift kind. Complete (every reason appears) and disjoint
# (no reason appears twice), so a reason determines its kind and a new reason cannot be added
# without deciding what it means.
DRIFT_REASONS_BY_KIND: dict[DriftKind, tuple[DriftReason, ...]] = {
    DriftKind.identity_conflict: (DriftReason.element_kind_conflict,),
    DriftKind.indeterminate: (DriftReason.facet_evidence_absent,),
    DriftKind.unmanaged: (DriftReason.element_unmanaged,),
    DriftKind.missing: (DriftReason.element_absent,),
    DriftKind.divergent: (
        DriftReason.facet_name_mismatch,
        DriftReason.facet_address_space_mismatch,
        DriftReason.facet_isolation_mismatch,
        DriftReason.facet_team_binding_mismatch,
        DriftReason.facet_node_class_mismatch,
        DriftReason.facet_role_mismatch,
        DriftReason.facet_image_mismatch,
        DriftReason.facet_network_attachment_mismatch,
        DriftReason.facet_address_mismatch,
        DriftReason.facet_attributes_mismatch,
    ),
}

# Which facets each element kind compares. Complete over FacetName (their union is every member,
# so a facet cannot be declared and then never compared); kinds may share a facet, as network and
# node both do for ``name``. An edge has no facets because its identity *is* the relationship, so
# once matched there is nothing left to compare.
FACETS_BY_ELEMENT_KIND: dict[ElementKind, tuple[FacetName, ...]] = {
    ElementKind.network: (
        FacetName.name,
        FacetName.address_space,
        FacetName.isolation,
        FacetName.team_binding,
    ),
    ElementKind.node: (
        FacetName.name,
        FacetName.node_class,
        FacetName.role,
        FacetName.image,
        FacetName.network_attachment,
        FacetName.address,
        FacetName.attributes,
    ),
    ElementKind.edge: (),
}

# The bounded reason a divergent facet reports. Total over FacetName.
DIVERGENCE_REASON_BY_FACET: dict[FacetName, DriftReason] = {
    FacetName.name: DriftReason.facet_name_mismatch,
    FacetName.address_space: DriftReason.facet_address_space_mismatch,
    FacetName.isolation: DriftReason.facet_isolation_mismatch,
    FacetName.team_binding: DriftReason.facet_team_binding_mismatch,
    FacetName.node_class: DriftReason.facet_node_class_mismatch,
    FacetName.role: DriftReason.facet_role_mismatch,
    FacetName.image: DriftReason.facet_image_mismatch,
    FacetName.network_attachment: DriftReason.facet_network_attachment_mismatch,
    FacetName.address: DriftReason.facet_address_mismatch,
    FacetName.attributes: DriftReason.facet_attributes_mismatch,
}

# The action that closes each actionable drift kind. Total over the kinds the planner may act on;
# `identity_conflict` and `indeterminate` refuse, and `unmanaged` is deferred, so none appears.
ACTION_FOR_DRIFT_KIND: dict[DriftKind, ActionKind] = {
    DriftKind.missing: ActionKind.create,
    DriftKind.divergent: ActionKind.update,
}

# Refusals a *fresh observation* could plausibly clear. Every other refusal needs a change to the
# desired state, the scope, or an operator decision — retrying the same call cannot help.
RETRYABLE_WITH_FRESH_OBSERVATION: frozenset[RefusalCode] = frozenset(
    {
        RefusalCode.observation_unverified,
        RefusalCode.observation_incomplete,
        RefusalCode.observation_stale,
        RefusalCode.observed_state_inconsistent,
    }
)
