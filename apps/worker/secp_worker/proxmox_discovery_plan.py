"""Which operations to run, and in what order, given what has been observed so far.

Discovery cannot be one flat list: ``/nodes/{node}/storage`` needs a node name and
``/cluster/sdn/vnets/{vnet}/subnets`` needs a vnet id, and neither exists before the run starts.
That makes the plan a function of prior observations — which is precisely the situation in which a
caller-supplied identifier would be indistinguishable from a discovered one.

So every dynamic segment is passed through :func:`validated_segment` with a ``sourced_from`` naming
the response it came from. The rule enforced is PROVENANCE, not shape: a perfectly well-formed node
name that nothing observed is refused exactly like a malformed one.

Three phases, and the boundaries are where a dependency actually exists rather than where a tidy
grouping would fall:

1. everything that needs no identifier — version, cluster status, node index, the SDN authority
   preflight, the cluster-wide indexes;
2. everything that needs a node name;
3. everything that needs a storage id, a vnet id or a zone id.

The plan is bounded. An enumeration is capped per list by :data:`MAX_DYNAMIC_EXPANSION`, and the
whole plan by :data:`MAX_PLANNED_OPERATIONS` — a cluster reporting thousands of objects is a
malformed or hostile answer, not a large cluster, and an unbounded expansion turns one authorised
read into a stampede. Exceeding either raises rather than truncating: a silently shortened plan
produces a snapshot that looks complete, which is the failure this whole layer exists to prevent.
"""

from __future__ import annotations

from collections.abc import Mapping

from secp_api.discovery_observation import Observation

from secp_worker.proxmox_discovery_operations import (
    MAX_DYNAMIC_EXPANSION,
    GetClusterFirewallGroupsOperation,
    GetClusterFirewallOptionsOperation,
    GetClusterResourcesOperation,
    GetClusterStatusOperation,
    GetNodeAptVersionsOperation,
    GetNodeLxcOperation,
    GetNodeNetworkOperation,
    GetNodeQemuOperation,
    GetNodesOperation,
    GetNodeStatusOperation,
    GetNodeStorageOperation,
    GetNodeVersionOperation,
    GetStorageContentOperation,
    GetVersionOperation,
    OperationParameterError,
    validated_segment,
)
from secp_worker.proxmox_sdn_operations import (
    GetEffectivePermissionsOperation,
    GetNodeSdnBridgesOperation,
    GetNodeSdnZonesOperation,
    GetSdnControllersOperation,
    GetSdnFabricsOperation,
    GetSdnIpamStatusOperation,
    GetSdnRootOperation,
    GetSdnSubnetsOperation,
    GetSdnVnetsOperation,
    GetSdnZonesOperation,
)

#: Ceiling on the whole plan. Deliberately generous enough for a real lab cluster and far below
#: anything that could be used to amplify one authorised read.
MAX_PLANNED_OPERATIONS = 512

#: The provenance labels recorded on every dynamic identifier. Each names the exact response the
#: value came from, so a refusal says which read was trusted rather than merely that one was.
SOURCE_NODE_INDEX = "response:/nodes"
SOURCE_NODE_STORAGE = "response:/nodes/{node}/storage"
SOURCE_SDN_VNETS = "response:/cluster/sdn/vnets"
SOURCE_SDN_ZONES = "response:/cluster/sdn/zones"


class DiscoveryPlanError(Exception):
    """The plan could not be built. A closed reason code, never a host or a path."""


def phase_one_operations() -> tuple[object, ...]:
    """Everything answerable without a discovered identifier.

    ``/cluster/sdn`` is here rather than with the SDN reads because it is the authority preflight:
    its result decides whether an empty index below may be read as absence at all.
    """
    return (
        GetVersionOperation(),
        GetClusterStatusOperation(),
        GetNodesOperation(),
        GetSdnRootOperation(),
        GetEffectivePermissionsOperation(),
        GetClusterResourcesOperation(),
        GetClusterFirewallOptionsOperation(),
        GetClusterFirewallGroupsOperation(),
        GetSdnZonesOperation(),
        GetSdnVnetsOperation(),
        GetSdnControllersOperation(),
        GetSdnIpamStatusOperation(),
        GetSdnFabricsOperation(),
    )


def phase_two_operations(observations: Mapping[str, Observation]) -> tuple[object, ...]:
    """Everything that needs a node name, for every node the target named."""
    nodes = _identifiers(observations, "node_names", source=SOURCE_NODE_INDEX)
    operations: list[object] = []
    for node in nodes:
        operations.extend(
            (
                GetNodeStatusOperation(node, SOURCE_NODE_INDEX),
                GetNodeVersionOperation(node, SOURCE_NODE_INDEX),
                GetNodeAptVersionsOperation(node, SOURCE_NODE_INDEX),
                GetNodeNetworkOperation(node, SOURCE_NODE_INDEX),
                GetNodeStorageOperation(node, SOURCE_NODE_INDEX),
                GetNodeQemuOperation(node, SOURCE_NODE_INDEX),
                GetNodeLxcOperation(node, SOURCE_NODE_INDEX),
                GetNodeSdnZonesOperation(node, SOURCE_NODE_INDEX),
            )
        )
    return _bounded(operations)


def phase_three_operations(observations: Mapping[str, Observation]) -> tuple[object, ...]:
    """Everything that needs a storage id, a vnet id or a zone id."""
    operations: list[object] = []

    for node, storages in _node_keyed(observations, "storage_ids").items():
        checked_node = _segment(node, field="node", source=SOURCE_NODE_INDEX)
        for storage in storages[:MAX_DYNAMIC_EXPANSION]:
            checked = _segment(storage, field="storage", source=SOURCE_NODE_STORAGE)
            operations.append(
                GetStorageContentOperation(checked_node, checked, SOURCE_NODE_STORAGE)
            )

    for vnet in _keys(observations, "existing_vnets", source=SOURCE_SDN_VNETS):
        operations.append(GetSdnSubnetsOperation(vnet, SOURCE_SDN_VNETS))

    zones = _keys(observations, "existing_sdn_zones", source=SOURCE_SDN_ZONES)
    for node in _identifiers(observations, "node_names", source=SOURCE_NODE_INDEX):
        for zone in zones:
            operations.append(GetNodeSdnBridgesOperation(node, zone, SOURCE_SDN_ZONES))

    return _bounded(operations)


PHASES = (phase_one_operations, phase_two_operations, phase_three_operations)


def _bounded(operations: list[object]) -> tuple[object, ...]:
    if len(operations) > MAX_PLANNED_OPERATIONS:
        # Raising rather than truncating: a silently shortened plan produces a snapshot that LOOKS
        # complete, and the required-fact evaluator has no way to tell it was cut short.
        raise DiscoveryPlanError("discovery_plan_too_large")
    return tuple(operations)


def _segment(value: object, *, field: str, source: str) -> str:
    try:
        return validated_segment(value, field=field, sourced_from=source)
    except OperationParameterError as exc:
        raise DiscoveryPlanError(str(exc.args[0])) from None


def _usable(observations: Mapping[str, Observation], name: str) -> object | None:
    observation = observations.get(name)
    return observation.value if observation is not None and observation.is_usable else None


def _identifiers(
    observations: Mapping[str, Observation], name: str, *, source: str
) -> tuple[str, ...]:
    """A validated, bounded list of identifiers from a usable observation of ``name``."""
    value = _usable(observations, name)
    if not isinstance(value, (list, tuple)):
        return ()
    if len(value) > MAX_DYNAMIC_EXPANSION:
        raise DiscoveryPlanError(f"dynamic_identifier_list_too_large:{name}")
    return tuple(_segment(item, field=name, source=source) for item in value)


def _keys(observations: Mapping[str, Observation], name: str, *, source: str) -> tuple[str, ...]:
    """The same, for a fact whose identifiers are the KEYS of a mapping."""
    value = _usable(observations, name)
    if not isinstance(value, dict):
        return ()
    keys = sorted(value)
    if len(keys) > MAX_DYNAMIC_EXPANSION:
        raise DiscoveryPlanError(f"dynamic_identifier_list_too_large:{name}")
    return tuple(_segment(key, field=name, source=source) for key in keys)


def _node_keyed(observations: Mapping[str, Observation], name: str) -> dict[str, tuple[str, ...]]:
    value = _usable(observations, name)
    if not isinstance(value, dict):
        return {}
    if len(value) > MAX_DYNAMIC_EXPANSION:
        raise DiscoveryPlanError(f"dynamic_identifier_list_too_large:{name}")
    return {
        str(node): tuple(str(item) for item in items)
        for node, items in value.items()
        if isinstance(items, (list, tuple))
    }
