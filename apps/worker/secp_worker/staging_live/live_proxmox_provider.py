"""Worker-only live Proxmox provisioning provider — ownership boundary skeleton (SECP-B3).

DELIBERATELY UNWIRED and sealed by default. This establishes the safety boundary a live provider
enforces, without contacting any host: it discovers a target through an injected inventory reader
(sealed default refuses); it REFUSES a target that is clustered, ambiguous (not exactly one node),
unable to meet isolation policy, undersized against an app-owned capacity profile, or already
contaminated with a CONFLICTING SECP ownership tag; it names/tags every resource it creates from
the lab's :class:`SecpOwnershipNamespace`; and it will mutate or delete ONLY resources it can prove
are SECP-owned by THIS lab. The concrete hardened HTTPS/TLS mutating transport and the create/delete
calls are layered in a later PR; here the transport is a sealed contract.

No HTTP/socket/subprocess code is imported; nothing is contacted at import, construction, or test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from secp_worker.staging_live.bootstrap.ownership import SecpOwnershipNamespace


class LiveProxmoxProviderError(Exception):
    """Fail-closed provider error. Closed reason only — never a host/endpoint/credential value."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"live proxmox provider refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class TargetInventory:
    """Safe, discovered facts about a Proxmox target. Contains only booleans/bounded counts
    and ownership tags — never a host, endpoint, node name, storage id, VMID, or credential."""

    node_reachable: bool
    is_clustered: bool
    node_count: int
    isolation_capable: bool
    nested_virtualization: str  # "available" | "absent" | "unknown"
    available_vmids: int
    free_vcpus: int
    free_memory_mb: int
    free_disk_gb: int
    existing_ownership_tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CapacityProfile:
    """App-owned bounded capacity requirement (NOT a user's infrastructure value)."""

    required_vmids: int
    required_vcpus: int
    required_memory_mb: int
    required_disk_gb: int


@dataclass(frozen=True)
class TargetAssessment:
    """A closed eligibility outcome. ``reason_code`` is a closed refusal label when not ok."""

    ok: bool
    reason_code: str


def assess_target(
    inventory: TargetInventory,
    *,
    profile: CapacityProfile,
    namespace: SecpOwnershipNamespace,
) -> TargetAssessment:
    """Fail-closed target eligibility. Refuses unreachable / clustered / ambiguous / isolation-
    incapable / undersized / conflicting-ownership targets with a closed reason code."""
    if not inventory.node_reachable:
        return TargetAssessment(False, "target_unreachable")
    if inventory.is_clustered:
        return TargetAssessment(False, "target_is_clustered")
    if inventory.node_count != 1:
        return TargetAssessment(False, "ambiguous_node_selection")
    if not inventory.isolation_capable:
        return TargetAssessment(False, "isolation_policy_unsatisfiable")
    if (
        inventory.available_vmids < profile.required_vmids
        or inventory.free_vcpus < profile.required_vcpus
        or inventory.free_memory_mb < profile.required_memory_mb
        or inventory.free_disk_gb < profile.required_disk_gb
    ):
        return TargetAssessment(False, "insufficient_capacity")
    # Contamination: any existing SECP-owned resource carrying a DIFFERENT lab's tag is a conflict.
    if any(not namespace.owns(tag) for tag in inventory.existing_ownership_tags):
        return TargetAssessment(False, "conflicting_secp_ownership")
    return TargetAssessment(True, "eligible")


@runtime_checkable
class ProxmoxInventoryReader(Protocol):
    """Injected, strictly-allowlisted inventory reader (a real one uses the hardened GET-only API; a
    fake is used in tests). The shipped default refuses."""

    def read_inventory(self) -> TargetInventory: ...


class SealedProxmoxInventoryReader:
    """The shipped default: NO reader. Refuses — contacts nothing."""

    def read_inventory(self) -> TargetInventory:
        raise LiveProxmoxProviderError("inventory_reader_sealed")


@runtime_checkable
class ProxmoxApiTransport(Protocol):
    """Sealed contract for the hardened HTTPS/TLS mutating transport (no redirects, ``trust_env``
    disabled, bounded timeout, closed method/path/body allowlist). Implementation lands in a
    later PR; the shipped default refuses so nothing can mutate a host in this PR."""

    def apply_owned(self, *, operation_code: str, owner_tag: str) -> None: ...


class SealedProxmoxApiTransport:
    """The shipped default mutating transport: refuses every mutation; no host is contacted."""

    def apply_owned(self, *, operation_code: str, owner_tag: str) -> None:
        raise LiveProxmoxProviderError("api_transport_sealed")


class LiveProxmoxProvider:
    """The ownership-bounded provider. Constructed with a namespace + injected inventory reader +
    capacity profile + a mutating transport (sealed by default). It assesses eligibility, names/tags
    owned resources, and refuses to mutate anything it cannot prove is SECP-owned by this lab."""

    def __init__(
        self,
        *,
        namespace: SecpOwnershipNamespace,
        inventory_reader: ProxmoxInventoryReader,
        capacity_profile: CapacityProfile,
        api_transport: ProxmoxApiTransport | None = None,
    ) -> None:
        self._namespace = namespace
        self._reader = inventory_reader
        self._profile = capacity_profile
        self._transport = api_transport or SealedProxmoxApiTransport()

    def assess(self) -> TargetAssessment:
        return assess_target(
            self._reader.read_inventory(), profile=self._profile, namespace=self._namespace
        )

    def owned_resource_name(self, kind: str, index: int) -> str:
        return self._namespace.resource_name(kind, index)

    def assert_mutable(self, resource_tag: object) -> None:
        """Fail closed unless the resource is provably SECP-owned by THIS lab. This is the single
        gate through which any mutation/deletion must pass, so a non-SECP resource is never touched.
        """
        if not self._namespace.owns(resource_tag):
            raise LiveProxmoxProviderError("resource_not_secp_owned")


class SealedLiveProxmoxProvider:
    """The shipped default provider: refuses assessment and every mutation. Constructs no transport,
    reads no inventory, contacts nothing. Normal runtime uses this."""

    def assess(self) -> TargetAssessment:
        raise LiveProxmoxProviderError("live_provider_sealed")

    def assert_mutable(self, resource_tag: object) -> None:
        raise LiveProxmoxProviderError("live_provider_sealed")
