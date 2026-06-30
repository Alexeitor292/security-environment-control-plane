"""Slice 5 — discovery contract extension (optional protocol, typed errors)."""

from __future__ import annotations

from secp_plugin_api.v1 import (
    DiscoveredResource,
    DiscoveryProtocol,
    DiscoveryRequest,
    DiscoveryResult,
    ProviderCredential,
    UnsupportedCapabilityError,
)
from secp_plugin_proxmox import ProxmoxPlugin
from secp_plugin_simulator import SimulatorPlugin


def test_discovery_protocol_is_optional():
    # The Proxmox plugin implements discovery; the Simulator does not.
    assert isinstance(ProxmoxPlugin(), DiscoveryProtocol)
    assert not isinstance(SimulatorPlugin(), DiscoveryProtocol)


def test_unsupported_capability_error_carries_context():
    err = UnsupportedCapabilityError("proxmox", "apply")
    assert err.plugin == "proxmox" and err.capability == "apply"
    assert "apply" in str(err)


def test_provider_credential_repr_is_redacted():
    cred = ProviderCredential(secret="super-secret-token")
    assert "super-secret-token" not in repr(cred)
    assert "super-secret-token" not in str(cred)
    assert "redacted" in repr(cred)
    # the value is still usable programmatically
    assert cred.secret == "super-secret-token"


def test_discovery_models_construct():
    req = DiscoveryRequest(
        target_id="t", plugin_name="proxmox", config={"base_url": "https://x.example.test"}
    )
    res = DiscoveryResult(
        ok=True,
        resources=[
            DiscoveredResource(resource_type="node", provider_external_id="n1", display_name="n1")
        ],
        summary={"total": 1},
    )
    assert req.scope is None
    assert res.resources[0].resource_type == "node"
