"""Typed, finite host-bootstrap operation contract (SECP-B3).

The bootstrap channel executes ONLY app-owned typed operations. There is no operation
that accepts an arbitrary shell snippet, command string, path, URL, username, bridge name, or free
argument from an API/UI caller. Each operation is a frozen dataclass with validated, bounded fields;
it renders to a discrete-token argv (never a shell string, so there is no interpolation or injection
surface), and every generated resource name is confined to the lab's SECP ownership namespace.

This module renders commands; it does NOT execute them. Execution is a separate, sealed worker-only
seam supplied out of band on the isolated worker. Nothing here performs I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from secp_worker.staging_live.bootstrap.ownership import SecpOwnershipNamespace


class HostOperationError(ValueError):
    """Raised for an out-of-contract or unsafe host operation. Never echoes a raw value."""


# ``operation_code`` is a ``ClassVar`` on every operation, NOT an ``__init__`` field: it is a fixed
# per-type discriminator that a caller can never pass or override at construction, so it cannot be
# spoofed to mislead a future executor that dispatches on it.
@dataclass(frozen=True)
class ProbeNestedVirtualization:
    """Read-only probe of host nested-virtualization support. Takes no caller argument."""

    operation_code: ClassVar[str] = "probe_nested_virtualization"


@dataclass(frozen=True)
class CreateIsolatedBridge:
    """Create ONE isolated, ownership-tagged bridge. The bridge NAME is generated from the namespace
    and a bounded index — never caller-supplied. No physical port, host IP, gateway, or DNS."""

    bridge_index: int
    operation_code: ClassVar[str] = "create_isolated_bridge"


@dataclass(frozen=True)
class ApplyDefaultDenyFirewall:
    """Apply a default-deny firewall chain scoped to the lab's ownership namespace."""

    operation_code: ClassVar[str] = "apply_default_deny_firewall"


@dataclass(frozen=True)
class RemoveOwnedBridge:
    """Teardown inverse of :class:`CreateIsolatedBridge`: remove ONLY the owned generated bridge."""

    bridge_index: int
    operation_code: ClassVar[str] = "remove_owned_bridge"


HostBootstrapOperation = (
    ProbeNestedVirtualization | CreateIsolatedBridge | ApplyDefaultDenyFirewall | RemoveOwnedBridge
)


@dataclass(frozen=True)
class RenderedHostCommand:
    """A safe, discrete-token command. ``argv`` is a tuple of already-separated tokens — NOT a shell
    string — so no token can inject additional commands. ``operation_code`` is a closed label."""

    operation_code: str
    argv: tuple[str, ...]


def render_host_command(
    operation: HostBootstrapOperation, namespace: SecpOwnershipNamespace
) -> RenderedHostCommand:
    """Render a typed operation into a discrete-token argv confined to the ownership namespace.

    Every token is either a fixed app-owned verb or a namespace-generated / validated value; no
    caller-supplied free string is ever interpolated. An unknown operation fails closed.
    """
    argv: tuple[str, ...]
    if isinstance(operation, ProbeNestedVirtualization):
        # Read-only capability probe; the executor maps this closed verb to a safe host inspection.
        argv = ("secp-host", "probe", "nested-virtualization")
    elif isinstance(operation, CreateIsolatedBridge):
        name = namespace.resource_name("bridge", operation.bridge_index)
        argv = (
            "secp-host",
            "bridge",
            "create",
            "--name",
            name,
            "--owner-tag",
            namespace.ownership_tag,
            "--no-uplink",
            "--no-gateway",
            "--no-dns",
        )
    elif isinstance(operation, ApplyDefaultDenyFirewall):
        argv = (
            "secp-host",
            "firewall",
            "default-deny",
            "--owner-tag",
            namespace.ownership_tag,
        )
    elif isinstance(operation, RemoveOwnedBridge):
        name = namespace.resource_name("bridge", operation.bridge_index)
        argv = (
            "secp-host",
            "bridge",
            "remove",
            "--name",
            name,
            "--owner-tag",
            namespace.ownership_tag,
        )
    else:  # pragma: no cover - exhaustiveness guard
        raise HostOperationError("unknown_host_operation")
    return RenderedHostCommand(operation_code=operation.operation_code, argv=argv)
