"""Desired versus observed state, the declared scope, and the verification gate (v1).

One neutral element shape describes both sides. *Desired* elements are authored control-plane
content; *observed* elements are whatever a collector reports. They are compared, never merged,
and the asymmetry is deliberate and load-bearing everywhere downstream:

    a desired element's ``ref`` is authored, so it may appear in a finding, an action or a plan;
    an observed element's ``ref`` is provider-supplied, so it never leaves this module.

Nothing here reaches a provider, a database, a clock or a filesystem. ``now`` is a parameter, so
every function is deterministic and no ambient clock can decide whether an observation is fresh.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from secp_reconciliation.v1.codes import (
    CONTRACT_VERSION,
    FACETS_BY_ELEMENT_KIND,
    ElementKind,
    ExecutionSurface,
    FacetName,
    ObservationFidelity,
    ReconciliationRefused,
    RefusalCode,
)
from secp_reconciliation.v1.digest import (
    as_utc,
    canonical_utc,
    document_digest,
    is_content_digest,
)

DESIRED_STATE_SCHEMA_VERSION = "secp-recon/desired-state/v1"
OBSERVED_STATE_SCHEMA_VERSION = "secp-recon/observed-state/v1"
SCOPE_SCHEMA_VERSION = "secp-recon/reconciliation-scope/v1"
VERIFICATION_SCHEMA_VERSION = "secp-recon/verified-state-pair/v1"
ATTRIBUTES_SCHEMA_VERSION = "secp-recon/attributes/v1"

# An observation timestamped later than ``now`` by more than this cannot be reconciled against a
# clock this contract trusts, so it is unverifiable rather than merely odd.
MAX_CLOCK_SKEW_SECONDS = 60

EDGE_REF_SEPARATOR = "->"
EDGE_REF_KIND_SEPARATOR = "|"

_ALLOWED_FACETS: dict[ElementKind, frozenset[FacetName]] = {
    kind: frozenset(facets) for kind, facets in FACETS_BY_ELEMENT_KIND.items()
}


@dataclass(frozen=True)
class StateElement:
    """One neutral element and the facet values compared for it.

    ``facets`` is an ordered tuple of ``(FacetName, value)`` pairs. A facet that is *absent* is
    distinct from a facet whose value is empty: absence on the observed side means the collector
    produced no evidence for it, which classifies as ``indeterminate`` and refuses — it never
    silently reads as agreement.
    """

    kind: ElementKind
    ref: str
    facets: tuple[tuple[FacetName, str], ...] = ()

    def facet_map(self) -> dict[FacetName, str]:
        return {name: value for name, value in self.facets}


@dataclass(frozen=True)
class DesiredState:
    """Authored desired state for exactly one instance.

    ``definition_digest`` binds the immutable source that produced these elements (an environment
    version, a published topology). It is provenance the contract *checks* — a malformed or absent
    digest refuses as unverified rather than being accepted on trust.
    """

    instance_id: str
    definition_digest: str
    elements: tuple[StateElement, ...] = ()


@dataclass(frozen=True)
class ObservedState:
    """A collector's report about one instance.

    ``fidelity`` is the collector's own attestation about its coverage and ``collector_digest``
    binds which collector/policy produced the report. Both are checked: only a ``complete``
    observation carrying a well-formed collector digest may be reconciled.
    """

    instance_id: str
    provider: str
    collector_digest: str
    observed_at: datetime
    fidelity: ObservationFidelity
    elements: tuple[StateElement, ...] = ()


@dataclass(frozen=True)
class ReconciliationScope:
    """The declared bounds a reconciliation runs inside. There is no implicit scope.

    ``max_actions`` is a hard change budget: a plan that would exceed it refuses rather than
    emitting an unexpectedly large change set. ``execution_surface`` must name a surface this
    contract version admits, and v1 admits only the simulator.
    """

    instance_id: str
    provider: str
    execution_surface: str
    max_actions: int
    observation_max_age_seconds: int
    contract_version: str = CONTRACT_VERSION


@dataclass(frozen=True)
class VerifiedStatePair:
    """Desired + observed state that has passed :func:`verify_inputs`, plus the digest binding it.

    Classification and planning accept only this token, so unverified state has no route into
    either. ``verification_digest`` is recomputed by both, so a hand-built token whose contents
    were swapped after verification refuses with ``verification_token_invalid``.
    """

    scope: ReconciliationScope
    desired: DesiredState
    observed: ObservedState
    evaluated_at: datetime
    verification_digest: str


# --- Edge references ------------------------------------------------------------------------


def encode_edge_ref(source_ref: str, target_ref: str, edge_kind: str) -> str:
    """Neutral, deterministic reference for a relationship element."""
    return source_ref + EDGE_REF_SEPARATOR + target_ref + EDGE_REF_KIND_SEPARATOR + edge_kind


def decode_edge_ref(ref: str) -> tuple[str | None, str | None]:
    """Endpoints of an encoded edge ref, or ``(None, None)`` when it is not one."""
    body, separator, _ = ref.partition(EDGE_REF_KIND_SEPARATOR)
    if not separator:
        return (None, None)
    source, arrow, target = body.partition(EDGE_REF_SEPARATOR)
    if not arrow or not source or not target:
        return (None, None)
    return (source, target)


# --- Content addressing -------------------------------------------------------------------------


def facet_digest(attributes: dict[str, str]) -> str:
    """Digest of a free-form attribute map, used as the ``attributes`` facet value.

    Attributes are provider-influenced, so they are compared as one content address rather than
    key by key: a mismatch is then reportable without any attribute name or value entering a
    finding.
    """
    ordered = {key: attributes[key] for key in sorted(attributes)}
    return document_digest(ATTRIBUTES_SCHEMA_VERSION, {"attributes": ordered})


def _element_document(element: StateElement) -> dict:
    return {
        "kind": element.kind.value,
        "ref": element.ref,
        "facets": [[name.value, value] for name, value in element.facets],
    }


def desired_state_digest(desired: DesiredState) -> str:
    """Content address of the desired elements, in the order the caller declared them."""
    return document_digest(
        DESIRED_STATE_SCHEMA_VERSION,
        {
            "instance_id": desired.instance_id,
            "definition_digest": desired.definition_digest,
            "elements": [_element_document(element) for element in desired.elements],
        },
    )


def observed_state_digest(observed: ObservedState) -> str:
    """Content address of the observation, including its fidelity and collector provenance."""
    return document_digest(
        OBSERVED_STATE_SCHEMA_VERSION,
        {
            "instance_id": observed.instance_id,
            "provider": observed.provider,
            "collector_digest": observed.collector_digest,
            "observed_at": canonical_utc(observed.observed_at),
            "fidelity": observed.fidelity.value,
            "elements": [_element_document(element) for element in observed.elements],
        },
    )


def scope_digest(scope: ReconciliationScope) -> str:
    """Content address of the declared scope."""
    return document_digest(
        SCOPE_SCHEMA_VERSION,
        {
            "instance_id": scope.instance_id,
            "provider": scope.provider,
            "execution_surface": scope.execution_surface,
            "max_actions": scope.max_actions,
            "observation_max_age_seconds": scope.observation_max_age_seconds,
            "contract_version": scope.contract_version,
        },
    )


def verification_digest(
    *,
    scope: ReconciliationScope,
    desired: DesiredState,
    observed: ObservedState,
    evaluated_at: datetime,
) -> str:
    """Digest binding the exact scope, desired state, observation and evaluation instant that were
    verified together."""
    return document_digest(
        VERIFICATION_SCHEMA_VERSION,
        {
            "scope_digest": scope_digest(scope),
            "desired_digest": desired_state_digest(desired),
            "observed_digest": observed_state_digest(observed),
            "evaluated_at": canonical_utc(evaluated_at),
        },
    )


# --- Verification gate --------------------------------------------------------------------------


def _duplicate_refs(elements: tuple[StateElement, ...]) -> bool:
    """A ref is the instance-local identity, unique across element kinds — that is precisely what
    makes "same ref, different kind" classifiable as an identity conflict rather than as an
    unrelated pair of elements."""
    seen: set[str] = set()
    for element in elements:
        if element.ref in seen:
            return True
        seen.add(element.ref)
    return False


def _malformed_elements(elements: tuple[StateElement, ...]) -> bool:
    """An element this contract cannot compare: an unknown element kind, an empty ref, a facet
    that its kind does not compare, a repeated facet, or a non-string facet value."""
    for element in elements:
        allowed = _ALLOWED_FACETS.get(element.kind)
        if allowed is None or not element.ref:
            return True
        names = [name for name, _ in element.facets]
        if len(names) != len(set(names)):
            return True
        for name, value in element.facets:
            if not isinstance(value, str) or name not in allowed:
                return True
    return False


def _endpoint_present(endpoint: str, present: set[tuple[ElementKind, str]]) -> bool:
    return (ElementKind.node, endpoint) in present or (ElementKind.network, endpoint) in present


def _dangling_edges(elements: tuple[StateElement, ...]) -> bool:
    """An edge whose endpoints are not both present as elements of the same state."""
    present = {(element.kind, element.ref) for element in elements}
    for element in elements:
        if element.kind is not ElementKind.edge:
            continue
        source, target = decode_edge_ref(element.ref)
        if source is None or target is None:
            return True
        if not _endpoint_present(source, present) or not _endpoint_present(target, present):
            return True
    return False


def verify_inputs(
    *,
    scope: ReconciliationScope,
    desired: DesiredState,
    observed: ObservedState,
    now: datetime,
) -> VerifiedStatePair:
    """Fail-closed gate. Refuses with one bounded :class:`RefusalCode` — never a rejected value.

    The order is deliberate and is what "fail closed" means here: the contract version, then the
    declared scope and its execution surface, then desired provenance and consistency, then
    identity agreement, then the observation's provenance, fidelity, freshness and consistency.
    An input this gate cannot verify refuses; it never falls through to classification, where an
    absent observation would otherwise read as agreement.
    """
    if scope.contract_version != CONTRACT_VERSION:
        raise ReconciliationRefused(RefusalCode.contract_version_unsupported)
    if not scope.instance_id or not scope.provider:
        raise ReconciliationRefused(RefusalCode.scope_invalid)
    if scope.max_actions < 0 or scope.observation_max_age_seconds <= 0:
        raise ReconciliationRefused(RefusalCode.scope_invalid)
    if scope.execution_surface != ExecutionSurface.simulator.value:
        raise ReconciliationRefused(RefusalCode.execution_surface_sealed)

    if not desired.instance_id or not is_content_digest(desired.definition_digest):
        raise ReconciliationRefused(RefusalCode.desired_unverified)
    if _malformed_elements(desired.elements) or _duplicate_refs(desired.elements):
        raise ReconciliationRefused(RefusalCode.desired_state_inconsistent)
    if _dangling_edges(desired.elements):
        raise ReconciliationRefused(RefusalCode.desired_state_inconsistent)

    if desired.instance_id != scope.instance_id or observed.instance_id != scope.instance_id:
        raise ReconciliationRefused(RefusalCode.instance_mismatch)
    if observed.provider != scope.provider:
        raise ReconciliationRefused(RefusalCode.provider_mismatch)

    if not is_content_digest(observed.collector_digest):
        raise ReconciliationRefused(RefusalCode.observation_unverified)
    if observed.fidelity is ObservationFidelity.unverified:
        raise ReconciliationRefused(RefusalCode.observation_unverified)
    age_seconds = (as_utc(now) - as_utc(observed.observed_at)).total_seconds()
    if age_seconds < -MAX_CLOCK_SKEW_SECONDS:
        raise ReconciliationRefused(RefusalCode.observation_unverified)
    if observed.fidelity is not ObservationFidelity.complete:
        raise ReconciliationRefused(RefusalCode.observation_incomplete)
    if age_seconds > scope.observation_max_age_seconds:
        raise ReconciliationRefused(RefusalCode.observation_stale)
    if _malformed_elements(observed.elements) or _duplicate_refs(observed.elements):
        raise ReconciliationRefused(RefusalCode.observed_state_inconsistent)
    if _dangling_edges(observed.elements):
        raise ReconciliationRefused(RefusalCode.observed_state_inconsistent)

    return VerifiedStatePair(
        scope=scope,
        desired=desired,
        observed=observed,
        evaluated_at=now,
        verification_digest=verification_digest(
            scope=scope, desired=desired, observed=observed, evaluated_at=now
        ),
    )


def require_verified(pair: VerifiedStatePair) -> None:
    """Recompute and check a pair's binding digest. Every consumer calls this first, so a token
    whose contents were swapped after verification refuses instead of being trusted."""
    expected = verification_digest(
        scope=pair.scope,
        desired=pair.desired,
        observed=pair.observed,
        evaluated_at=pair.evaluated_at,
    )
    if expected != pair.verification_digest:
        raise ReconciliationRefused(RefusalCode.verification_token_invalid)
