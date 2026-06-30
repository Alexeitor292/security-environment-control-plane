"""Proof #3 + Slice 6 — read-only Proxmox plugin and GET-only transport.

Uses a fake transport; no real endpoint is contacted. Placeholders only
(proxmox.example.test, documentation ranges).
"""

from __future__ import annotations

import pytest
from secp_plugin_api.v1 import (
    DiscoveryRequest,
    InstanceTopology,
    PluginContext,
    ProviderCredential,
    UnsupportedCapabilityError,
)
from secp_plugin_proxmox import ProxmoxPlugin
from secp_plugin_proxmox.transport import HttpxReadOnlyTransport, MutatingRequestRefused

FAKE_INVENTORY = {
    "/nodes": [
        {"node": "node-a", "status": "online", "maxmem": 1, "maxcpu": 4},
        {"node": "node-b", "status": "online"},
    ],
    "/nodes/node-a/qemu": [{"vmid": 100, "name": "vm-a", "status": "running", "cores": 2}],
    "/nodes/node-a/lxc": [{"vmid": 200, "name": "ct-a", "status": "running"}],
    "/nodes/node-a/storage": [{"storage": "store-x", "active": 1, "type": "dir"}],
    "/nodes/node-b/qemu": [],
    "/nodes/node-b/lxc": [],
    "/nodes/node-b/storage": [],
}

GOOD_CONFIG = {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True}


class FakeTransport:
    def __init__(self, data: dict):
        self.data = data
        self.calls: list[tuple[str, str]] = []

    def get(self, path: str, params: dict | None = None):
        self.calls.append(("GET", path))
        return self.data.get(path, [])


def _capturing_factory():
    created: list[FakeTransport] = []

    def factory(config, token):
        t = FakeTransport(FAKE_INVENTORY)
        created.append(t)
        return t

    return factory, created


class _FakeHttpClient:
    """Records whether .get was called; .get must never run for a refused method."""

    def __init__(self):
        self.get_called = False

    def get(self, *a, **k):  # pragma: no cover - must not be called
        self.get_called = True
        raise AssertionError("GET should not be issued in this test")

    def close(self):
        pass


def _req(scope=None):
    return DiscoveryRequest(target_id="t-1", plugin_name="proxmox", config=GOOD_CONFIG, scope=scope)


def test_health_advertises_only_readonly_capabilities():
    report = ProxmoxPlugin().health()
    assert report.simulated is False
    assert set(report.capabilities) == {"validate", "health", "discover", "status"}
    assert "apply" not in report.capabilities
    assert "destroy" not in report.capabilities


def test_discover_normalizes_inventory():
    factory, _ = _capturing_factory()
    plugin = ProxmoxPlugin(transport_factory=factory)
    result = plugin.discover(_req(), ProviderCredential.from_secret("tok"))
    assert result.ok
    by_type = result.summary["by_type"]
    assert by_type == {"node": 2, "vm": 1, "container": 1, "storage": 1}
    vm = next(r for r in result.resources if r.resource_type == "vm")
    assert vm.provider_external_id == "node-a/100"
    assert vm.parent_ref == "node-a"
    # only the small allowed attribute set is copied
    assert set(vm.attributes) <= {"cores", "maxmem", "template"}


def test_discover_issues_only_get_requests():
    factory, created = _capturing_factory()
    plugin = ProxmoxPlugin(transport_factory=factory)
    plugin.discover(_req(), ProviderCredential.from_secret("tok"))
    assert created, "transport should have been created"
    methods = {m for t in created for (m, _path) in t.calls}
    assert methods == {"GET"}, f"discovery must issue GET only, saw {methods}"


def test_scope_filter_restricts_resources():
    factory, _ = _capturing_factory()
    plugin = ProxmoxPlugin(transport_factory=factory)
    result = plugin.discover(
        _req(scope={"resource_types": ["node"]}), ProviderCredential.from_secret("t")
    )
    assert {r.resource_type for r in result.resources} == {"node"}

    factory2, _ = _capturing_factory()
    plugin2 = ProxmoxPlugin(transport_factory=factory2)
    result2 = plugin2.discover(
        _req(scope={"nodes": ["node-a"]}), ProviderCredential.from_secret("t")
    )
    nodes = {r.provider_external_id.split("/")[0] for r in result2.resources}
    assert nodes == {"node-a"}


def test_transport_refuses_non_get_before_sending():
    client = _FakeHttpClient()
    transport = HttpxReadOnlyTransport(
        base_url="https://proxmox.example.test:8006", token="tok", client=client
    )
    for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        with pytest.raises(MutatingRequestRefused):
            transport.request(method, "/nodes")
    assert client.get_called is False  # nothing was ever sent


def test_mutating_capabilities_hard_fail():
    plugin = ProxmoxPlugin()
    ctx = PluginContext(resources=_EmptyPort())
    for call in (
        lambda: plugin.plan({}, []),
        lambda: plugin.apply(None, ctx),
        lambda: plugin.reset(None, "i", ctx),
        lambda: plugin.destroy(["i"], ctx),
    ):
        with pytest.raises(UnsupportedCapabilityError):
            call()


def test_validate_target():
    plugin = ProxmoxPlugin()
    assert plugin.validate_target(GOOD_CONFIG).ok is True
    bad = plugin.validate_target({"base_url": "ftp://nope"})
    assert bad.ok is False and bad.errors
    insecure = plugin.validate_target(
        {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": False}
    )
    assert insecure.ok is False
    unsupported = plugin.validate_target({**GOOD_CONFIG, "extra": True})
    assert unsupported.ok is False
    bad_scope = plugin.validate_target(GOOD_CONFIG, {"resource_types": ["vm", "secret"]})
    assert bad_scope.ok is False


class _EmptyPort:
    def replace_instance_topology(self, instance_id, topology):  # pragma: no cover
        pass

    def clear_instance_topology(self, instance_id):  # pragma: no cover
        pass

    def read_instance_topology(self, instance_id):
        return InstanceTopology()
