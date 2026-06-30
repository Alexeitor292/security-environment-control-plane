"""AC5.1 — contract conformance suite.

This suite is the executable definition of "a correct plugin". It runs against the
Simulator today and MUST run against every future plugin (Proxmox, OpenTofu runner,
etc.). See ADR-003.
"""

from __future__ import annotations

import pytest
from secp_plugin_api.v1 import (
    InstanceTopology,
    PluginContext,
    PluginProtocol,
    TargetInstance,
)
from secp_plugin_simulator import SimulatorPlugin

# Future plugins get added to this list and inherit the whole suite.
PLUGINS: list[PluginProtocol] = [SimulatorPlugin()]


class _Port:
    def __init__(self):
        self.store = {}

    def replace_instance_topology(self, instance_id, topology):
        self.store[instance_id] = topology.model_copy(deep=True)

    def clear_instance_topology(self, instance_id):
        self.store.pop(instance_id, None)

    def read_instance_topology(self, instance_id):
        return self.store.get(instance_id, InstanceTopology())


@pytest.fixture(params=PLUGINS, ids=lambda p: p.name)
def plugin(request):
    return request.param


def _spec(valid_definition):
    return valid_definition


def test_implements_protocol(plugin):
    assert isinstance(plugin, PluginProtocol)


def test_health_contract(plugin):
    report = plugin.health()
    assert report.name == plugin.name
    assert report.contract_version == "1"
    assert isinstance(report.capabilities, list) and report.capabilities


def test_validate_accepts_valid_spec(plugin, valid_definition):
    result = plugin.validate(valid_definition)
    assert result.ok is True


def test_validate_rejects_invalid_spec(plugin):
    result = plugin.validate({"apiVersion": "bad", "kind": "Nope"})
    assert result.ok is False
    assert result.errors


def test_plan_status_apply_reset_destroy_cycle(plugin, valid_definition):
    port = _Port()
    targets = [TargetInstance(instance_id="x0", instance_ref="x0", team_ref="team1", team_index=0)]
    plan = plugin.plan(valid_definition, targets)
    assert plan.contract_version == "1"

    apply_result = plugin.apply(plan, PluginContext(resources=port))
    assert apply_result.ok

    observed = plugin.status("x0", PluginContext(resources=port))
    assert observed.nodes_total > 0

    reset_result = plugin.reset(plan, "x0", PluginContext(resources=port))
    assert reset_result.ok

    destroy_result = plugin.destroy(["x0"], PluginContext(resources=port))
    assert destroy_result.ok
    # After destroy, status reports an empty/destroyed instance.
    observed_after = plugin.status("x0", PluginContext(resources=port))
    assert observed_after.nodes_total == 0


def test_destroy_idempotent_at_plugin_level(plugin, valid_definition):
    port = _Port()
    r1 = plugin.destroy(["never-existed"], PluginContext(resources=port))
    assert r1.ok and r1.idempotent_noop is True
