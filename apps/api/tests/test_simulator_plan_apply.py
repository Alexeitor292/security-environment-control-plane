"""AC5.2/5.3/5.6 — simulator plan determinism, apply behavior, no real infra.

These tests exercise the plugin in isolation through a fake in-memory ResourcePort,
proving the plugin is decoupled from the control-plane database (ADR-003).
"""

from __future__ import annotations

import pytest
from secp_plugin_api.v1 import InstanceTopology, PluginContext, TargetInstance
from secp_plugin_simulator import SimulatorPlugin


class FakePort:
    """In-memory ResourcePort: proves the plugin never touches real infra/DB."""

    def __init__(self) -> None:
        self.store: dict[str, InstanceTopology] = {}

    def replace_instance_topology(self, instance_id, topology) -> None:
        self.store[instance_id] = topology.model_copy(deep=True)

    def clear_instance_topology(self, instance_id) -> None:
        self.store.pop(instance_id, None)

    def read_instance_topology(self, instance_id) -> InstanceTopology:
        return self.store.get(instance_id, InstanceTopology())


def _targets(n=2):
    return [
        TargetInstance(
            instance_id=f"i{i}", instance_ref=f"i{i}", team_ref=f"team{i + 1}", team_index=i
        )
        for i in range(n)
    ]


@pytest.fixture
def spec(valid_definition):
    return valid_definition


def test_plan_is_deterministic(spec):
    plugin = SimulatorPlugin()
    p1 = plugin.plan(spec, _targets())
    p2 = plugin.plan(spec, _targets())
    assert p1.model_dump() == p2.model_dump()


def test_plan_allocates_per_team_cidrs(spec):
    plugin = SimulatorPlugin()
    plan = plugin.plan(spec, _targets())
    cidrs = [n.cidr for ip in plan.instances for n in ip.desired.networks]
    assert cidrs == ["10.20.0.0/24", "10.20.1.0/24"]
    assert plan.total_nodes == 6  # 3 roles x 2 teams
    assert plan.total_networks == 2


def test_apply_persists_topology_through_port(spec):
    plugin = SimulatorPlugin()
    port = FakePort()
    plan = plugin.plan(spec, _targets())
    result = plugin.apply(plan, PluginContext(resources=port))
    assert result.ok
    assert set(result.instances_applied) == {"i0", "i1"}
    assert result.created["nodes"] == 6
    # status reads back observed state from the port.
    observed = plugin.status("i0", PluginContext(resources=port))
    assert observed.nodes_total == 3
    assert observed.networks_total == 1


def test_apply_is_idempotent(spec):
    plugin = SimulatorPlugin()
    port = FakePort()
    plan = plugin.plan(spec, _targets())
    plugin.apply(plan, PluginContext(resources=port))
    first = port.read_instance_topology("i0").model_dump()
    plugin.apply(plan, PluginContext(resources=port))  # apply again
    second = port.read_instance_topology("i0").model_dump()
    assert first == second  # no duplication


def test_health_reports_simulated_and_capabilities():
    report = SimulatorPlugin().health()
    assert report.simulated is True
    assert report.healthy is True
    assert "apply" in report.capabilities and "destroy" in report.capabilities


def test_sensor_monitors_edges_present(spec):
    plugin = SimulatorPlugin()
    plan = plugin.plan(spec, _targets(1))
    edges = plan.instances[0].desired.edges
    monitors = [e for e in edges if e.kind.value == "monitors"]
    # one wazuh sensor monitoring attacker + web-server => 2 monitors edges
    assert len(monitors) == 2
