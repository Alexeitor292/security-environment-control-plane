"""MOCK transport for the Proxmox plugin — verification/local-development only.

Returns canned, placeholder inventory and contacts NO network. Enabled only when
``SECP_PROVIDER_MOCK=1`` so the Temporal discovery path can be demonstrated
end-to-end without any real Proxmox endpoint. Never used in production.
"""

from __future__ import annotations

from typing import Any

# Placeholder inventory only (no real hosts/IDs).
MOCK_INVENTORY: dict[str, Any] = {
    "/nodes": [
        {"node": "mock-node-1", "status": "online", "maxcpu": 8, "maxmem": 1},
        {"node": "mock-node-2", "status": "online"},
    ],
    "/nodes/mock-node-1/qemu": [
        {"vmid": 101, "name": "mock-vm-a", "status": "running", "cores": 2},
        {"vmid": 102, "name": "mock-vm-b", "status": "stopped", "cores": 4},
    ],
    "/nodes/mock-node-1/lxc": [{"vmid": 201, "name": "mock-ct-a", "status": "running"}],
    "/nodes/mock-node-1/storage": [{"storage": "mock-store", "active": 1, "type": "dir"}],
    "/nodes/mock-node-2/qemu": [],
    "/nodes/mock-node-2/lxc": [],
    "/nodes/mock-node-2/storage": [],
}


class MockProxmoxTransport:
    """A GET-only transport returning canned inventory; never touches a network."""

    def get(self, path: str, params: dict | None = None) -> Any:
        return MOCK_INVENTORY.get(path, [])


def mock_transport_factory(config: dict, token: str) -> MockProxmoxTransport:
    return MockProxmoxTransport()
