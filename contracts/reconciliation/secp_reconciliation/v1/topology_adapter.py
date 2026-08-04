"""The single seam between the plugin contract's topology and reconciliation state (v1).

Every other module in this package imports nothing but the standard library. This one — and only
this one — imports :mod:`secp_plugin_api`, so the dependency on the plugin contract (and, through
it, on pydantic) has exactly one named place to live and be reviewed. The rest of the package can
therefore be checked as a closed, dependency-free core.

The mapping is a projection, not an interpretation: ``InstanceTopology`` is already the
provider-neutral shape every provider populates (ADR-008), and this restates it as elements and
facets so desired and observed sides compare identically. Field names are renamed to the neutral
facet vocabulary (``address_space``, ``address``, ``node_class``) rather than carried through, so
nothing downstream inherits a transport- or provider-shaped name.
"""

from __future__ import annotations

from datetime import datetime

from secp_plugin_api.v1.models import InstanceTopology

from secp_reconciliation.v1.codes import ElementKind, FacetName, ObservationFidelity
from secp_reconciliation.v1.state import (
    DesiredState,
    ObservedState,
    StateElement,
    encode_edge_ref,
    facet_digest,
)

ISOLATION_ISOLATED = "isolated"
ISOLATION_SHARED = "shared"


def topology_elements(topology: InstanceTopology) -> tuple[StateElement, ...]:
    """Project a neutral topology into comparable elements, in dependency order."""
    elements: list[StateElement] = []
    for network in topology.networks:
        elements.append(
            StateElement(
                kind=ElementKind.network,
                ref=network.ref,
                facets=(
                    (FacetName.name, network.name),
                    (FacetName.address_space, network.cidr),
                    (
                        FacetName.isolation,
                        ISOLATION_ISOLATED if network.isolated else ISOLATION_SHARED,
                    ),
                    (FacetName.team_binding, network.team_ref or ""),
                ),
            )
        )
    for node in topology.nodes:
        elements.append(
            StateElement(
                kind=ElementKind.node,
                ref=node.ref,
                facets=(
                    (FacetName.name, node.name),
                    (FacetName.node_class, node.kind.value),
                    (FacetName.role, node.role),
                    (FacetName.image, node.image),
                    (FacetName.network_attachment, node.network_ref),
                    (FacetName.address, node.ip_address),
                    (FacetName.attributes, facet_digest(node.attributes)),
                ),
            )
        )
    for edge in topology.edges:
        elements.append(
            StateElement(
                kind=ElementKind.edge,
                ref=encode_edge_ref(edge.source_ref, edge.target_ref, edge.kind.value),
            )
        )
    return tuple(elements)


def desired_from_topology(
    *,
    instance_id: str,
    definition_digest: str,
    topology: InstanceTopology,
) -> DesiredState:
    """Desired state from an authored topology, bound to the digest of its immutable source."""
    return DesiredState(
        instance_id=instance_id,
        definition_digest=definition_digest,
        elements=topology_elements(topology),
    )


def observed_from_topology(
    *,
    instance_id: str,
    provider: str,
    collector_digest: str,
    observed_at: datetime,
    fidelity: ObservationFidelity,
    topology: InstanceTopology,
) -> ObservedState:
    """Observed state from a collector's topology report, carrying the collector's own attestation
    about coverage. The fidelity is passed through unchanged — this adapter never upgrades a
    partial or unverified observation into a complete one."""
    return ObservedState(
        instance_id=instance_id,
        provider=provider,
        collector_digest=collector_digest,
        observed_at=observed_at,
        fidelity=fidelity,
        elements=topology_elements(topology),
    )
