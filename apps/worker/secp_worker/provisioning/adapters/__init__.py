"""Worker-only provisioning adapters (SECP-002B-1A, ADR-013).

Provider-specific workspace rendering lives HERE, never in ``apps/api`` or the core
domain models (Charter Invariant 9). Each adapter converts an immutable, secret-free
``ProvisioningManifest`` + ``ToolchainProfile`` into deterministic, secret-free workspace
files. No adapter imports a provider SDK, opens a network connection, or embeds a real
endpoint / credential — endpoint and token are referenced only as input variables.
"""

from secp_worker.provisioning.adapters.base import (
    AdapterError,
    ProvisioningAdapter,
    get_adapter,
)
from secp_worker.provisioning.adapters.proxmox import ProxmoxAdapter

__all__ = ["AdapterError", "ProvisioningAdapter", "ProxmoxAdapter", "get_adapter"]
