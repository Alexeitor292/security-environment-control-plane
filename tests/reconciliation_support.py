"""Shared builders for the reconciliation-contract tests (not a test module).

Deliberately minimal: the tests below assert on exact values, so these builders keep every input
explicit and every default boring. ``omit`` exists because "a facet the observation is silent
about" is a first-class case the contract must not read as agreement.
"""

from __future__ import annotations

from datetime import UTC, datetime

from secp_reconciliation.v1 import (
    CONTRACT_VERSION,
    DesiredState,
    ElementKind,
    FacetName,
    ObservationFidelity,
    ObservedState,
    ReconciliationScope,
    StateElement,
    encode_edge_ref,
    facet_digest,
)

DEFINITION_DIGEST = "sha256:" + "11" * 32
COLLECTOR_DIGEST = "sha256:" + "22" * 32
INSTANCE_ID = "instance-1"
PROVIDER = "simulator"
NOW = datetime(2026, 7, 31, 12, 0, 0, tzinfo=UTC)


def _facets(pairs: list[tuple[FacetName, str]], omit: tuple[FacetName, ...]) -> tuple:
    return tuple((name, value) for name, value in pairs if name not in omit)


def network(
    ref: str = "team-network",
    *,
    name: str = "team network",
    address_space: str = "10.20.0.0/24",
    isolated: bool = True,
    team: str = "team-1",
    omit: tuple[FacetName, ...] = (),
) -> StateElement:
    return StateElement(
        kind=ElementKind.network,
        ref=ref,
        facets=_facets(
            [
                (FacetName.name, name),
                (FacetName.address_space, address_space),
                (FacetName.isolation, "isolated" if isolated else "shared"),
                (FacetName.team_binding, team),
            ],
            omit,
        ),
    )


def node(
    ref: str = "attacker-1",
    *,
    name: str = "attacker one",
    node_class: str = "attacker",
    role: str = "kali",
    image: str = "kali:2026.1",
    network_attachment: str = "team-network",
    address: str = "10.20.0.10",
    attributes: dict[str, str] | None = None,
    omit: tuple[FacetName, ...] = (),
) -> StateElement:
    return StateElement(
        kind=ElementKind.node,
        ref=ref,
        facets=_facets(
            [
                (FacetName.name, name),
                (FacetName.node_class, node_class),
                (FacetName.role, role),
                (FacetName.image, image),
                (FacetName.network_attachment, network_attachment),
                (FacetName.address, address),
                (FacetName.attributes, facet_digest(attributes or {})),
            ],
            omit,
        ),
    )


def edge(
    source: str = "attacker-1",
    target: str = "team-network",
    kind: str = "network",
) -> StateElement:
    return StateElement(kind=ElementKind.edge, ref=encode_edge_ref(source, target, kind))


def scope(**overrides) -> ReconciliationScope:
    base = {
        "instance_id": INSTANCE_ID,
        "provider": PROVIDER,
        "execution_surface": "simulator",
        "max_actions": 50,
        "observation_max_age_seconds": 300,
        "contract_version": CONTRACT_VERSION,
    }
    base.update(overrides)
    return ReconciliationScope(**base)


def desired(*elements: StateElement, **overrides) -> DesiredState:
    base = {
        "instance_id": INSTANCE_ID,
        "definition_digest": DEFINITION_DIGEST,
        "elements": elements,
    }
    base.update(overrides)
    return DesiredState(**base)


def observed(*elements: StateElement, **overrides) -> ObservedState:
    base = {
        "instance_id": INSTANCE_ID,
        "provider": PROVIDER,
        "collector_digest": COLLECTOR_DIGEST,
        "observed_at": NOW,
        "fidelity": ObservationFidelity.complete,
        "elements": elements,
    }
    base.update(overrides)
    return ObservedState(**base)
