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

The plan is bounded, and NOTHING is silently shortened — a truncated inventory still reads as a
complete answer, and the identifiers past the cut are exactly the ones a collision check would have
caught. Exceeding a bound produces one of two visible outcomes and never a shorter list:

* a whole-plan or node-list overflow RAISES :class:`DiscoveryPlanError`, which stops further phases
  while keeping every observation already gathered;
* a per-node inventory overflow produces a :class:`BoundedInventoryRefusal`, which skips that
  node's dependent reads entirely, degrades every fact they would have fed, records the OBSERVED
  size so a reader knows by how much the answer is incomplete, and travels into the signed
  commitment as a contribution like any other.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

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


@dataclass(frozen=True)
class BoundedInventoryRefusal:
    """An enumeration that exceeded its bound, recorded rather than shortened.

    Truncating an inventory is the worst available option: the fact still reads ``observed``, the
    shortened list still looks like a complete answer, and the identifiers past the cut are exactly
    the ones a collision check would have caught. The refusal instead carries the OBSERVED size —
    the minimum known count — so a reader knows both that the answer is incomplete and by how much.
    """

    subject: str
    operation_code: str
    rendered_path: str
    field_codes: tuple[str, ...]
    reason: str
    observed_size: int


def _bounded_refusal(
    *,
    subject: str,
    operation_code: str,
    rendered_path: str,
    field_codes: tuple[str, ...],
    observed_size: int,
    bound: int,
    kind: str,
) -> BoundedInventoryRefusal:
    return BoundedInventoryRefusal(
        subject=subject,
        operation_code=operation_code,
        rendered_path=rendered_path,
        field_codes=field_codes,
        reason=(f"inventory_exceeds_bound:{kind}:{subject}:observed={observed_size}:bound={bound}"),
        observed_size=observed_size,
    )


def phase_one_operations() -> tuple[tuple[object, ...], tuple[BoundedInventoryRefusal, ...]]:
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
    ), ()


def phase_two_operations(
    observations: Mapping[str, Observation],
    already_planned: int = 0,
) -> tuple[tuple[object, ...], tuple[BoundedInventoryRefusal, ...]]:
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
    return _bounded(operations, already_planned), ()


def phase_three_operations(
    observations: Mapping[str, Observation],
    already_planned: int = 0,
) -> tuple[tuple[object, ...], tuple[BoundedInventoryRefusal, ...]]:
    """Everything that needs a storage id, a vnet id or a zone id.

    Returns the operations AND any bounded refusals. A node whose storage list exceeds the bound
    contributes NO storage-content operations and one refusal naming the observed size — it used to
    contribute the first 64 silently, which left ``iso_and_container_template_availability`` reading
    as a complete answer for a node whose remaining storages nobody looked at.
    """
    operations: list[object] = []
    refusals: list[BoundedInventoryRefusal] = []

    for node, storages in _node_keyed(observations, "storage_ids").items():
        checked_node = _segment(node, field="node", source=SOURCE_NODE_INDEX)
        if len(storages) > MAX_DYNAMIC_EXPANSION:
            refusals.append(
                _bounded_refusal(
                    subject=checked_node,
                    operation_code=GetStorageContentOperation.operation_code,
                    rendered_path=GetStorageContentOperation.path_template,
                    field_codes=GetStorageContentOperation.observation_field_codes,
                    observed_size=len(storages),
                    bound=MAX_DYNAMIC_EXPANSION,
                    kind="storage",
                )
            )
            continue
        for storage in storages:
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

    return _bounded(operations, already_planned), tuple(refusals)


PHASES = (phase_one_operations, phase_two_operations, phase_three_operations)


def _bounded(operations: list[object], already_planned: int = 0) -> tuple[object, ...]:
    """The ceiling is on the WHOLE plan, not on each phase.

    Called once per phase, it used to compare only that phase's count — so the documented limit of
    512 was in practice 13 + 512 + 512. The running total is passed in.
    """
    if len(operations) + already_planned > MAX_PLANNED_OPERATIONS:
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
