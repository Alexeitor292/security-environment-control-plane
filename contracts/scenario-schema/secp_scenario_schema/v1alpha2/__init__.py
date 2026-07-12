"""Scenario schema version controlplane.security/v1alpha2 (ADR-016 / SECP-B10).

Additive successor to v1alpha1: carries every v1alpha1 field forward unchanged
and adds the optional ``spec.topology`` and ``spec.publicationProvenance`` blocks
used by the publication composition contract.
"""

from secp_scenario_schema.v1alpha2.models import (
    API_VERSION,
    PUBLICATION_CONTRACT_VERSION,
    TOPOLOGY_SCHEMA_VERSION,
    EnvironmentDefinition,
    PublicationProvenance,
    Spec,
    TopologyDocument,
    TopologyEdge,
    TopologyNetwork,
    TopologyNode,
    TopologyZone,
)

__all__ = [
    "API_VERSION",
    "PUBLICATION_CONTRACT_VERSION",
    "TOPOLOGY_SCHEMA_VERSION",
    "EnvironmentDefinition",
    "PublicationProvenance",
    "Spec",
    "TopologyDocument",
    "TopologyEdge",
    "TopologyNetwork",
    "TopologyNode",
    "TopologyZone",
]
