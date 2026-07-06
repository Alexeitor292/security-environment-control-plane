"""Sealed, fail-closed discovery seams + typed, bounded discovery facts (SECP-B5).

The :class:`HostProbeSource` is the boundary to the real, read-only Proxmox probe execution — its
shipped default REFUSES, so discovery contacts nothing until a worker-local bootstrap bundle is
mounted and a real read-only probe executor is supplied out of band. The facts it returns are typed,
bounded, and secret-free (booleans/bounded ints/safe tokens only) — raw host output never crosses
this
boundary. Nothing here performs I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from secp_worker.deployment.locators import ResourceLocator


class ProbeSourceUnavailable(Exception):
    """The read-only probe backend is sealed/unavailable — fail closed (never assume facts)."""

    def __init__(self, reason_code: str = "probe_source_sealed") -> None:
        super().__init__(f"probe source unavailable: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class StorageOption:
    """A discovered storage pool: safe id + bounded free capacity + whether it can hold guest
    images."""

    storage: str
    avail_mb: int
    usable: bool


@dataclass(frozen=True)
class InventoryFacts:
    """The typed, bounded, secret-free host inventory gathered by the read-only probes. Contains NO
    endpoint, address, credential, raw output, or unbounded blob."""

    version_major: int
    version_minor: int
    is_clustered: bool
    node: str
    node_count: int
    cpu_total: int
    mem_total_mb: int
    mem_free_mb: int
    nested_available: bool
    storages: tuple[StorageOption, ...] = field(default_factory=tuple)
    used_vmids: frozenset[int] = field(default_factory=frozenset)


@dataclass(frozen=True)
class LocatorPresence:
    """Whether the exact candidate object exists, and the ownership marker observed on it (if any).
    Absent → free to allocate; present with OUR marker → reusable; present otherwise → occupied."""

    present: bool
    owner_marker: str | None = None


@runtime_checkable
class HostProbeSource(Protocol):
    """Runs the CLOSED read-only probe set over the hardened SSH channel and returns typed facts. A
    real implementation is the read-only probe executor; the shipped default refuses (sealed)."""

    def read_inventory(self) -> InventoryFacts: ...

    def probe_candidate_presence(
        self, locators: tuple[ResourceLocator, ...]
    ) -> dict[str, LocatorPresence]: ...


class SealedHostProbeSource:
    """The shipped default: NO probe backend. Refuses — reads nothing, contacts nothing."""

    def read_inventory(self) -> InventoryFacts:
        raise ProbeSourceUnavailable()

    def probe_candidate_presence(
        self, locators: tuple[ResourceLocator, ...]
    ) -> dict[str, LocatorPresence]:
        raise ProbeSourceUnavailable()
