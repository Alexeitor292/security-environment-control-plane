"""Simulator Plugin implementation.

Deterministic, side-effect-isolated, idempotent. Given an immutable environment
definition and a set of target instances (one per team), it computes a normalized
per-team topology and persists it through the contract's ResourcePort. The same
inputs always yield the same plan (Charter §6; ADR-003).
"""

from __future__ import annotations

import ipaddress

from secp_plugin_api.v1 import (
    ApplyResult,
    Capability,
    DestroyResult,
    HealthReport,
    InstancePlan,
    InstanceTopology,
    ObservedState,
    PluginContext,
    PluginPlan,
    ResetResult,
    TargetInstance,
    TopologyEdge,
    TopologyNetwork,
    TopologyNode,
    ValidationResult,
)
from secp_plugin_api.v1.models import EdgeKind, NodeKind
from secp_scenario_schema import validate_definition
from secp_scenario_schema.validator import SchemaValidationError

PLUGIN_NAME = "simulator"
PLUGIN_VERSION = "0.1.0"
CONTRACT_VERSION = "1"
DEFAULT_BASE_CIDR = "10.20.0.0/16"


class SimulatorPlugin:
    """Reference plugin that realises topology as simulated database records."""

    name = PLUGIN_NAME
    version = PLUGIN_VERSION
    simulated = True

    # --- read-only capabilities (control plane may call directly) ------------

    def health(self) -> HealthReport:
        return HealthReport(
            name=PLUGIN_NAME,
            version=PLUGIN_VERSION,
            contract_version=CONTRACT_VERSION,
            healthy=True,
            simulated=True,
            capabilities=[
                Capability.validate.value,
                Capability.plan.value,
                Capability.apply.value,
                Capability.status.value,
                Capability.reset.value,
                Capability.destroy.value,
                Capability.health.value,
            ],
            detail="Simulated provider. Creates only database records, never real infra.",
        )

    def validate(self, spec: dict) -> ValidationResult:
        try:
            definition = validate_definition(spec)
        except SchemaValidationError as exc:
            return ValidationResult(ok=False, errors=list(exc.errors))

        warnings: list[str] = []
        if PLUGIN_NAME not in definition.spec.requiredPlugins:
            warnings.append(
                "definition does not list 'simulator' in requiredPlugins; "
                "the simulator can still realise it"
            )
        return ValidationResult(ok=True, warnings=warnings)

    def plan(self, spec: dict, targets: list[TargetInstance]) -> PluginPlan:
        definition = validate_definition(spec)
        instances = [
            self._plan_instance(definition, target)
            for target in sorted(targets, key=lambda t: t.team_index)
        ]
        return PluginPlan(
            plugin=PLUGIN_NAME,
            contract_version=CONTRACT_VERSION,
            instances=instances,
        )

    def status(self, instance_id: str, context: PluginContext) -> ObservedState:
        topo = context.resources.read_instance_topology(instance_id)
        nodes_up = sum(1 for _ in topo.nodes)
        return ObservedState(
            instance_id=instance_id,
            lifecycle_state="running" if topo.nodes else "destroyed",
            nodes_total=len(topo.nodes),
            nodes_up=nodes_up,
            networks_total=len(topo.networks),
            topology=topo,
        )

    # --- side-effecting capabilities (worker boundary only) ------------------

    def apply(self, plan: PluginPlan, context: PluginContext) -> ApplyResult:
        applied: list[str] = []
        created = {"networks": 0, "nodes": 0, "edges": 0}
        for instance_plan in plan.instances:
            # Idempotent: replace fully realises the desired topology, so applying
            # twice converges to the same state.
            context.resources.replace_instance_topology(
                instance_plan.instance_id, instance_plan.desired
            )
            applied.append(instance_plan.instance_id)
            created["networks"] += len(instance_plan.desired.networks)
            created["nodes"] += len(instance_plan.desired.nodes)
            created["edges"] += len(instance_plan.desired.edges)
        return ApplyResult(
            ok=True,
            instances_applied=applied,
            created=created,
            message=f"realised {len(applied)} simulated instance(s)",
        )

    def reset(self, plan: PluginPlan, instance_id: str, context: PluginContext) -> ResetResult:
        instance_plan = next((i for i in plan.instances if i.instance_id == instance_id), None)
        if instance_plan is None:
            return ResetResult(
                ok=False,
                instance_id=instance_id,
                message="instance not found in plan",
            )
        before = context.resources.read_instance_topology(instance_id)
        # Rebuild deterministically from baseline. Because the desired topology is
        # a pure function of the (immutable) definition, repeated resets converge
        # to an identical baseline => idempotent.
        context.resources.replace_instance_topology(instance_id, instance_plan.desired)
        after = context.resources.read_instance_topology(instance_id)
        noop = _topology_equal(before, after)
        return ResetResult(
            ok=True,
            instance_id=instance_id,
            idempotent_noop=noop,
            message="reset to baseline",
        )

    def destroy(self, instance_ids: list[str], context: PluginContext) -> DestroyResult:
        destroyed: list[str] = []
        any_present = False
        for instance_id in instance_ids:
            existing = context.resources.read_instance_topology(instance_id)
            if existing.nodes or existing.networks:
                any_present = True
            # Idempotent: clearing already-empty topology is a safe no-op.
            context.resources.clear_instance_topology(instance_id)
            destroyed.append(instance_id)
        return DestroyResult(
            ok=True,
            instances_destroyed=destroyed,
            idempotent_noop=not any_present,
            message="cleared simulated topology",
        )

    # --- deterministic planning helpers --------------------------------------

    def _plan_instance(self, definition, target: TargetInstance) -> InstancePlan:
        spec = definition.spec
        team_index = target.team_index
        networks_by_name: dict[str, TopologyNetwork] = {}
        networks: list[TopologyNetwork] = []
        for net in spec.networks:
            cidr = self._allocate_cidr(net, team_index)
            tnet = TopologyNetwork(
                ref=net.name,
                name=f"{target.team_ref}-{net.name}",
                cidr=cidr,
                team_ref=target.team_ref if net.cidrStrategy.value == "per-team" else None,
                isolated=net.isolated and spec.teams.isolationPolicy.value == "strict",
            )
            networks.append(tnet)
            networks_by_name[net.name] = tnet

        nodes: list[TopologyNode] = []
        edges: list[TopologyEdge] = []
        # Deterministic IP allocation: .10+ within each network, by role order.
        host_counter: dict[str, int] = {n.name: 10 for n in spec.networks}
        for role in spec.roles:
            net = networks_by_name[role.network]
            for i in range(role.count):
                host = host_counter[role.network]
                host_counter[role.network] += 1
                ip = self._host_ip(net.cidr, host)
                ref = f"{role.name}-{i}" if role.count > 1 else role.name
                node = TopologyNode(
                    ref=ref,
                    name=f"{target.team_ref}-{ref}",
                    kind=NodeKind(role.kind.value),
                    role=role.name,
                    image=role.image,
                    network_ref=role.network,
                    ip_address=ip,
                    attributes={
                        "team_ref": target.team_ref,
                        "vulnerability_packs": ",".join(role.vulnerabilityPacks),
                    },
                )
                nodes.append(node)
                edges.append(
                    TopologyEdge(
                        source_ref=ref,
                        target_ref=role.network,
                        kind=EdgeKind.network,
                    )
                )

        # Sensors monitor every target/attacker node in the same instance.
        sensor_refs = [n.ref for n in nodes if n.kind == NodeKind.sensor]
        monitored = [n.ref for n in nodes if n.kind in (NodeKind.target, NodeKind.attacker)]
        for s in sensor_refs:
            for m in monitored:
                edges.append(TopologyEdge(source_ref=s, target_ref=m, kind=EdgeKind.monitors))

        desired = InstanceTopology(networks=networks, nodes=nodes, edges=edges)
        return InstancePlan(
            instance_id=target.instance_id,
            instance_ref=target.instance_ref,
            team_ref=target.team_ref,
            desired=desired,
            summary={
                "networks": len(networks),
                "nodes": len(nodes),
                "edges": len(edges),
            },
        )

    def _allocate_cidr(self, net, team_index: int) -> str:
        base = ipaddress.ip_network(net.baseCidr or DEFAULT_BASE_CIDR, strict=False)
        if net.cidrStrategy.value == "shared":
            # All teams share one /24 carved from the base.
            return str(next(base.subnets(new_prefix=24)))
        subnets = base.subnets(new_prefix=24)
        for idx, subnet in enumerate(subnets):
            if idx == team_index:
                return str(subnet)
        raise ValueError(f"team_index {team_index} exceeds available /24 subnets")

    @staticmethod
    def _host_ip(cidr: str, host: int) -> str:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network.network_address + host)


def _topology_equal(a: InstanceTopology, b: InstanceTopology) -> bool:
    return a.model_dump() == b.model_dump()
