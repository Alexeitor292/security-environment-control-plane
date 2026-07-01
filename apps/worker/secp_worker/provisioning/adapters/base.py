"""Provisioning adapter contract (SECP-002B-1A, ADR-013).

An adapter renders a deterministic, secret-free workspace from an immutable manifest +
toolchain profile. It is worker-only and provider-neutral at this seam; concrete
adapters (e.g. Proxmox) live alongside this module.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class AdapterError(Exception):
    """Adapter failure. Messages are redacted (never include secrets)."""


@runtime_checkable
class ProvisioningAdapter(Protocol):
    """Render a secret-free workspace for one provider family."""

    adapter_kind: str

    def render(self, manifest: dict, profile: dict) -> dict[str, str]:
        """Return ``{relative_path: file_content}`` — deterministic and secret-free."""
        ...


def get_adapter(adapter_kind: str) -> ProvisioningAdapter:
    """Return the worker adapter for ``adapter_kind`` (imported lazily, worker-only)."""
    if adapter_kind == "proxmox":
        from secp_worker.provisioning.adapters.proxmox import ProxmoxAdapter

        return ProxmoxAdapter()
    raise AdapterError(f"no provisioning adapter for adapter_kind '{adapter_kind}'")
