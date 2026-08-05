"""The Proxmox desired-state model — pure data, compiled before anything is touched.

This module extends the provider-neutral range contract in
:mod:`secp_api.range_providers.base` with the vocabulary a Proxmox target actually needs: cluster
and node identity, QEMU guests, SDN zones/VNets/subnets, firewall objects, and the ownership
metadata that decides what SECP is allowed to modify.

Three rules shape every type here, and each one exists because the opposite is the cheap mistake:

**Unknown stays unknown.** Nothing in this module defaults a capacity, a storage id, a template, a
VLAN range, or a reachability claim. Every input that the compiler cannot derive is an explicit
``| None`` that, when absent, produces a :class:`BlockedPlan` naming the exact missing prerequisite.
A guessed default here becomes a wrong VM on someone's cluster.

**A matching name is never proof of ownership.** :class:`Ownership` is a seven-field tuple that is
stamped into the object and re-read from live observation. :func:`is_owned_by_secp` compares the
whole tuple. An object whose name matches perfectly but whose ownership tag is absent or foreign is
NOT ours — see :class:`ObjectProvenance`.

**Published is not reachable.** :class:`GuestAddress` keeps ``published_address`` and
``probe_address`` as separate fields with no fallback between them, because a probe that "passes"
by being pointed at the published address proves nothing about reachability.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

from secp_api.range_enums import RangeResourceKind

#: Proxmox VM/CT ids are cluster-unique and bounded by the platform itself.
VMID_MIN = 100
VMID_MAX = 999_999_999

#: Proxmox rejects VLAN tag 0, and 4095 is reserved.
VLAN_MIN = 2
VLAN_MAX = 4094

#: SDN object names are far more restricted than guest names: max 8 chars for a zone, and
#: alphanumeric only. Getting this wrong fails at apply, not at plan, so it is validated here.
_ZONE_NAME_RE = re.compile(r"^[a-z][a-z0-9]{0,7}$")
_VNET_NAME_RE = re.compile(r"^[a-z][a-z0-9]{0,7}$")
#: Guest names are DNS labels.
_GUEST_NAME_RE = re.compile(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
#: Firewall security-group and IPSet names.
_FIREWALL_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,26}$")


class ProxmoxModelError(ValueError):
    """A desired-state value was structurally invalid. Never contains secrets."""


class GuestKind(str, Enum):
    """What kind of guest a workload runs in.

    ``qemu`` is the only kind the first compiler generation emits. ``lxc`` is modelled because the
    ownership, IPAM and firewall handling are identical and modelling it later would mean changing
    the persisted allocation ledger. The compiler refuses to emit ``lxc`` unless the caller opts in
    AND the target was observed to support it.
    """

    qemu = "qemu"
    lxc = "lxc"


class CloneStrategy(str, Enum):
    """How a guest is derived from its template.

    ``linked`` is cheap but binds the clone's lifetime to the template's disk; a template deleted
    or migrated out from under a linked clone destroys the clone. ``full`` is the only strategy
    safe across template churn, so it is what the compiler picks when the caller expresses no
    preference — the conservative default, not the cheap one.
    """

    full = "full"
    linked = "linked"


class SegmentRole(str, Enum):
    """What a network segment is *for*. Drives the firewall intent, not just labelling."""

    #: Shared boundary carrying scoring/control traffic. Reachable from every team, one way.
    scoring = "scoring"
    #: A team's offensive workstations.
    attacker = "attacker"
    #: A team's intentionally vulnerable machines.
    vulnerable = "vulnerable"
    #: Optional passive collector for a team.
    sensor = "sensor"


class FirewallVerdict(str, Enum):
    accept = "ACCEPT"
    drop = "DROP"
    reject = "REJECT"


class FirewallDirection(str, Enum):
    inbound = "IN"
    outbound = "OUT"


class ObjectProvenance(str, Enum):
    """Who an observed object belongs to. The compiler acts on ``secp_owned`` and nothing else."""

    #: Carries a complete SECP ownership tag matching the current scope.
    secp_owned = "secp_owned"
    #: Carries a complete SECP ownership tag for a DIFFERENT org/target/range/generation.
    secp_foreign_scope = "secp_foreign_scope"
    #: Exists, carries no SECP ownership tag at all. Never modified, never removed.
    untagged = "untagged"
    #: Carries a tag that could not be parsed. Treated exactly as ``untagged``.
    unreadable = "unreadable"


# --------------------------------------------------------------------------------------
# Ownership
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Ownership:
    """The immutable SECP ownership stamp carried by every generated object.

    ``generation`` is the desired-state generation: it increments when the compiled topology
    changes. ``operation_generation`` increments per lifecycle operation (deploy/reset/destroy)
    against the same desired state. They are separate because a reset must be able to prove it is
    reconciling THIS desired state, while still being distinguishable from the deploy that created
    it.
    """

    organization_id: str
    target_id: str
    range_id: str
    generation: int
    operation_generation: int
    resource_kind: RangeResourceKind
    #: ``None`` for shared objects (the scoring segment, the SDN zone) that no single team owns.
    team_ref: str | None = None

    def __post_init__(self) -> None:
        for name in ("organization_id", "target_id", "range_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ProxmoxModelError(f"ownership.{name} must be a non-empty string")
        if self.generation < 0 or self.operation_generation < 0:
            raise ProxmoxModelError("ownership generations must be non-negative")

    def as_tags(self) -> dict[str, str]:
        """The stamp as flat key/value tags, which is how Proxmox can actually carry it.

        Emitted into guest ``description`` blocks and SDN/firewall comments. Deterministic key
        order so the rendered artifact is byte-stable across runs.
        """
        tags = {
            "secp.org": self.organization_id,
            "secp.target": self.target_id,
            "secp.range": self.range_id,
            "secp.generation": str(self.generation),
            "secp.operation_generation": str(self.operation_generation),
            "secp.kind": self.resource_kind.value,
        }
        if self.team_ref is not None:
            tags["secp.team"] = self.team_ref
        return dict(sorted(tags.items()))

    def scope_key(self) -> tuple[str, str, str, str, int]:
        """The IPAM scope this ownership allocates within.

        Deliberately excludes ``operation_generation`` and ``resource_kind``: a reset must resolve
        to the SAME allocations as the deploy it is reconciling, or every reset would renumber the
        range.
        """
        return (
            self.organization_id,
            self.target_id,
            self.range_id,
            self.team_ref or "",
            self.generation,
        )


def is_owned_by_secp(
    observed_tags: dict[str, str] | None,
    expected: Ownership,
) -> ObjectProvenance:
    """Classify an observed object by its tags alone. The object's NAME is never consulted.

    This function is the single place that decides whether SECP may touch a live object. It is
    intentionally strict: a partial tag set is ``unreadable``, not "probably ours". The caller acts
    only on :attr:`ObjectProvenance.secp_owned`.
    """
    if not observed_tags:
        return ObjectProvenance.untagged
    required = ("secp.org", "secp.target", "secp.range", "secp.generation")
    if any(key not in observed_tags for key in required):
        # Some SECP keys but not all: a truncated description, a hand-edited object, or a
        # different tool's namespace collision. Never assume.
        return (
            ObjectProvenance.unreadable
            if any(key.startswith("secp.") for key in observed_tags)
            else ObjectProvenance.untagged
        )
    try:
        generation = int(observed_tags["secp.generation"])
    except (TypeError, ValueError):
        return ObjectProvenance.unreadable
    matches = (
        observed_tags["secp.org"] == expected.organization_id
        and observed_tags["secp.target"] == expected.target_id
        and observed_tags["secp.range"] == expected.range_id
        and generation == expected.generation
        and observed_tags.get("secp.team") == expected.team_ref
    )
    return ObjectProvenance.secp_owned if matches else ObjectProvenance.secp_foreign_scope


# --------------------------------------------------------------------------------------
# Target identity and observed capability
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ProxmoxTargetIdentity:
    """Which Proxmox this desired state is compiled FOR.

    ``cluster_fingerprint`` is what makes a compiled plan non-portable on purpose: a plan compiled
    against one cluster must never be applied to another, and a fingerprint mismatch is a hard
    refusal rather than a warning.
    """

    target_id: str
    cluster_name: str
    cluster_fingerprint: str
    #: The management address of the Proxmox API itself. Every compiled segment must be unable to
    #: reach it, and no allocated subnet may overlap it.
    management_cidrs: tuple[str, ...]
    #: Bridges carrying the management plane. The compiler EXCLUDES these when choosing a bridge
    #: for the scenario SDN zone. Without this the obvious "pick the first bridge present on every
    #: node" lands on ``vmbr0`` — which on a stock Proxmox install is precisely the management
    #: bridge — and quietly bridges the scenario into the management plane.
    management_bridges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.management_cidrs:
            raise ProxmoxModelError(
                "target identity must declare at least one management CIDR; without it the "
                "compiler cannot prove scenario segments are isolated from the management plane"
            )
        for cidr in self.management_cidrs:
            ipaddress.ip_network(cidr, strict=True)


@dataclass(frozen=True)
class NodeObservation:
    """One cluster node as live discovery actually saw it.

    Every capacity field is ``| None``. ``None`` means "not observed", which blocks placement — it
    never means zero and never means unlimited.
    """

    node_name: str
    online: bool
    cpu_cores_total: int | None = None
    memory_bytes_total: int | None = None
    #: Storage ids observed on this node, with the content types each accepts.
    storages: tuple[StorageObservation, ...] = ()
    #: Linux bridges observed on this node.
    bridges: tuple[str, ...] = ()


@dataclass(frozen=True)
class StorageObservation:
    storage_id: str
    #: e.g. ``("images", "rootdir")``. Empty means not observed, not "accepts everything".
    content_types: tuple[str, ...] = ()
    available_bytes: int | None = None
    shared: bool | None = None


@dataclass(frozen=True)
class TemplateObservation:
    """A template that was actually seen, with the id needed to clone it."""

    template_ref: str
    vmid: int
    node_name: str
    guest_kind: GuestKind


@dataclass(frozen=True)
class TargetObservation:
    """Everything live discovery proved about the target, and nothing it did not.

    This is the compiler's ONLY source of truth about the environment. Fields that were not
    collected stay ``None`` and the compiler blocks. In particular ``sdn_supported`` being ``None``
    is not "probably yes" — Proxmox SDN is a separate, optionally-installed component, and
    compiling VNets for a cluster without it produces a plan that fails at apply.
    """

    identity: ProxmoxTargetIdentity
    nodes: tuple[NodeObservation, ...] = ()
    templates: tuple[TemplateObservation, ...] = ()
    #: Whether the SDN feature is present and usable. ``None`` = not observed.
    sdn_supported: bool | None = None
    #: Whether the cluster firewall is enabled. ``None`` = not observed.
    firewall_supported: bool | None = None
    #: VLAN tags observed already in use anywhere on the cluster. ``None`` = not observed, which
    #: blocks VLAN allocation entirely rather than risking a collision.
    vlan_tags_in_use: tuple[int, ...] | None = None
    #: Every VM/CT id observed cluster-wide. ``None`` = not observed → VMID allocation blocks.
    vmids_in_use: tuple[int, ...] | None = None
    #: MAC addresses observed on existing guests. ``None`` = not observed → MAC allocation blocks.
    macs_in_use: tuple[str, ...] | None = None
    #: IPv4 networks already routed/served on the cluster. ``None`` = not observed → subnet
    #: allocation blocks.
    subnets_in_use: tuple[str, ...] | None = None
    #: SDN zone/VNet names observed. ``None`` = not observed → name allocation blocks.
    sdn_names_in_use: tuple[str, ...] | None = None
    #: Firewall security-group and IPSet names observed. ``None`` = not observed → blocks.
    firewall_names_in_use: tuple[str, ...] | None = None

    def node(self, node_name: str) -> NodeObservation | None:
        for candidate in self.nodes:
            if candidate.node_name == node_name:
                return candidate
        return None

    def online_nodes(self) -> tuple[NodeObservation, ...]:
        return tuple(node for node in self.nodes if node.online)


# --------------------------------------------------------------------------------------
# Blocked planning — the shape of "we will not guess"
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MissingPrerequisite:
    """One named, closed reason the plan cannot be compiled.

    ``reason_id`` is a stable machine key so the API can render actionable guidance without string
    matching. ``observation`` names the exact discovery field that would unblock it — this is the
    field the operator or a later discovery stage must actually produce.
    """

    reason_id: str
    observation: str
    detail: str

    def __post_init__(self) -> None:
        if not self.reason_id or not self.observation:
            raise ProxmoxModelError("a missing prerequisite must name a reason id and observation")


@dataclass(frozen=True)
class BlockedPlan:
    """A closed refusal to compile, naming every missing prerequisite at once.

    Deliberately reports ALL missing prerequisites rather than the first: an operator fixing one
    field at a time through six round-trips against a real cluster is the failure mode this
    replaces.
    """

    missing: tuple[MissingPrerequisite, ...]

    def __post_init__(self) -> None:
        if not self.missing:
            raise ProxmoxModelError("a blocked plan must name at least one missing prerequisite")

    @property
    def reason_ids(self) -> tuple[str, ...]:
        return tuple(sorted({item.reason_id for item in self.missing}))

    def describe(self) -> str:
        lines = [f"cannot compile: {len(self.missing)} unmet prerequisite(s)"]
        lines.extend(
            f"  - [{item.reason_id}] {item.detail} (needs observation: {item.observation})"
            for item in sorted(self.missing, key=lambda i: (i.reason_id, i.observation))
        )
        return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Network desired state
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SdnZoneSpec:
    """The SDN zone every scenario VNet lives in. Created by SECP, never a pre-existing one."""

    name: str
    #: The node-local bridge the zone rides on. This is a SCENARIO bridge, never the management
    #: bridge — :func:`assert_management_plane_untouched` enforces that.
    bridge: str
    nodes: tuple[str, ...]
    ownership: Ownership
    mtu: int | None = None

    def __post_init__(self) -> None:
        if not _ZONE_NAME_RE.match(self.name):
            raise ProxmoxModelError(
                f"SDN zone name {self.name!r} is invalid: max 8 chars, lowercase alphanumeric, "
                "must start with a letter"
            )
        if not self.nodes:
            raise ProxmoxModelError(f"SDN zone {self.name!r} must be bound to at least one node")


@dataclass(frozen=True)
class SubnetSpec:
    """A scenario subnet with its gateway and the guest-usable address window.

    ``gateway`` is always the first usable address and is excluded from the guest window, so a
    guest can never be handed the gateway's address.
    """

    cidr: str
    gateway: str
    #: Whether SECP provides routing off this subnet at all. Default deny: false.
    routed: bool = False

    def __post_init__(self) -> None:
        network = ipaddress.ip_network(self.cidr, strict=True)
        gateway = ipaddress.ip_address(self.gateway)
        if gateway not in network:
            raise ProxmoxModelError(f"gateway {self.gateway} is not inside subnet {self.cidr}")

    @property
    def network(self) -> ipaddress.IPv4Network:
        network = ipaddress.ip_network(self.cidr, strict=True)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ProxmoxModelError(f"subnet {self.cidr} must be IPv4")
        return network


@dataclass(frozen=True)
class VNetSpec:
    """One isolated layer-2 segment: a VNet, its VLAN tag, and its subnet."""

    name: str
    zone_name: str
    vlan_tag: int
    subnet: SubnetSpec
    role: SegmentRole
    ownership: Ownership
    alias: str = ""

    def __post_init__(self) -> None:
        if not _VNET_NAME_RE.match(self.name):
            raise ProxmoxModelError(
                f"VNet name {self.name!r} is invalid: max 8 chars, lowercase alphanumeric, "
                "must start with a letter"
            )
        if not VLAN_MIN <= self.vlan_tag <= VLAN_MAX:
            raise ProxmoxModelError(
                f"VLAN tag {self.vlan_tag} outside the usable range {VLAN_MIN}-{VLAN_MAX}"
            )


@dataclass(frozen=True)
class NicSpec:
    """One guest NIC bound to exactly one VNet, with a generated MAC and a reserved address."""

    index: int
    vnet_name: str
    mac_address: str
    model: str = "virtio"
    firewall: bool = True

    def __post_init__(self) -> None:
        if self.index < 0:
            raise ProxmoxModelError("NIC index must be non-negative")
        if not _MAC_RE.match(self.mac_address):
            raise ProxmoxModelError(f"MAC {self.mac_address!r} is not a valid EUI-48 address")


_MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


@dataclass(frozen=True)
class GuestAddress:
    """A guest's addresses, keeping *published* and *probe* strictly separate.

    ``published_address`` is what a scoreboard or a participant is told to use.
    ``probe_address`` is what readiness verification actually connects to. There is deliberately no
    fallback from one to the other: a readiness check that quietly probes the published address
    proves the address was published, not that the guest is reachable. This repo has already paid
    for that bug once.
    """

    published_address: str
    probe_address: str | None = None

    def __post_init__(self) -> None:
        ipaddress.ip_address(self.published_address)
        if self.probe_address is not None:
            ipaddress.ip_address(self.probe_address)

    @property
    def probe_is_distinct(self) -> bool:
        return self.probe_address is not None and self.probe_address != self.published_address


# --------------------------------------------------------------------------------------
# Guest desired state
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DiskSpec:
    """One virtual disk pinned to an OBSERVED storage id."""

    slot: str
    size_gb: int
    storage_id: str
    discard: bool = True
    ssd_emulation: bool = False

    def __post_init__(self) -> None:
        if self.size_gb <= 0:
            raise ProxmoxModelError(f"disk {self.slot} must have a positive size")


@dataclass(frozen=True)
class CloudInitSpec:
    """Cloud-init settings. Secret-free by construction.

    There is no password field and there never will be one: a manifest carrying a guest password
    would be persisted, hashed and rendered into a workspace. Only public keys travel here.
    """

    user: str
    ssh_authorized_keys: tuple[str, ...] = ()
    #: Nameservers reachable from INSIDE the segment. Empty means the guest gets none, which is the
    #: correct default for an isolated segment with no egress.
    nameservers: tuple[str, ...] = ()
    search_domain: str | None = None
    #: Set only when the segment is routed; a gateway on an unrouted segment is a lie.
    gateway: str | None = None

    def __post_init__(self) -> None:
        for key in self.ssh_authorized_keys:
            # Checked before the format test: a private key fails the prefix check too, and
            # "must be OpenSSH public keys" would bury the fact that secret material was passed in.
            if "PRIVATE KEY" in key:
                raise ProxmoxModelError("cloud-init received private key material")
            if not key.startswith(("ssh-", "ecdsa-", "sk-")):
                raise ProxmoxModelError("cloud-init ssh keys must be OpenSSH public keys")


@dataclass(frozen=True)
class GuestSpec:
    """One desired guest, fully resolved: no field is left for apply-time invention."""

    guest_ref: str
    name: str
    kind: GuestKind
    vmid: int
    node_name: str
    template_ref: str
    clone_strategy: CloneStrategy
    cpu_cores: int
    memory_mb: int
    disks: tuple[DiskSpec, ...]
    nics: tuple[NicSpec, ...]
    address: GuestAddress
    ownership: Ownership
    cloud_init: CloudInitSpec | None = None
    start_on_deploy: bool = True
    #: Seconds to wait for readiness to be OBSERVED. Never a substitute for observing it.
    readiness_timeout_seconds: int = 300

    def __post_init__(self) -> None:
        if not _GUEST_NAME_RE.match(self.name):
            raise ProxmoxModelError(f"guest name {self.name!r} is not a valid DNS label")
        if not VMID_MIN <= self.vmid <= VMID_MAX:
            raise ProxmoxModelError(f"vmid {self.vmid} outside the Proxmox range")
        if self.cpu_cores <= 0 or self.memory_mb <= 0:
            raise ProxmoxModelError(f"guest {self.guest_ref} must have positive cpu and memory")
        if not self.nics:
            raise ProxmoxModelError(
                f"guest {self.guest_ref} has no NIC; a guest with no segment cannot be isolated "
                "into one and must not be compiled"
            )
        indexes = [nic.index for nic in self.nics]
        if len(set(indexes)) != len(indexes):
            raise ProxmoxModelError(f"guest {self.guest_ref} has duplicate NIC indexes")


# --------------------------------------------------------------------------------------
# Firewall desired state
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IpSetSpec:
    """A named set of CIDRs referenced by rules, so intent is readable at the rule site."""

    name: str
    cidrs: tuple[str, ...]
    ownership: Ownership
    comment: str = ""

    def __post_init__(self) -> None:
        if not _FIREWALL_NAME_RE.match(self.name):
            raise ProxmoxModelError(f"IPSet name {self.name!r} is invalid")
        for cidr in self.cidrs:
            ipaddress.ip_network(cidr, strict=False)


@dataclass(frozen=True)
class FirewallRuleSpec:
    """One rule. ``position`` is explicit because firewall semantics are order-dependent.

    Leaving ordering implicit in list position is how a deny ends up below the allow that defeats
    it, so the compiler assigns and the renderer respects an explicit position.
    """

    position: int
    direction: FirewallDirection
    verdict: FirewallVerdict
    comment: str
    source: str | None = None
    dest: str | None = None
    proto: str | None = None
    dport: str | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.position < 0:
            raise ProxmoxModelError("firewall rule position must be non-negative")
        if not self.comment:
            raise ProxmoxModelError(
                "every firewall rule must carry a comment; an unexplained rule cannot be reviewed"
            )


@dataclass(frozen=True)
class SecurityGroupSpec:
    """A named, ordered rule group attached to the NICs of one segment."""

    name: str
    rules: tuple[FirewallRuleSpec, ...]
    ownership: Ownership
    comment: str = ""

    def __post_init__(self) -> None:
        if not _FIREWALL_NAME_RE.match(self.name):
            raise ProxmoxModelError(f"security group name {self.name!r} is invalid")
        positions = [rule.position for rule in self.rules]
        if len(set(positions)) != len(positions):
            raise ProxmoxModelError(
                f"security group {self.name!r} has duplicate rule positions; rule order would be "
                "undefined"
            )

    def ordered_rules(self) -> tuple[FirewallRuleSpec, ...]:
        return tuple(sorted(self.rules, key=lambda rule: rule.position))

    @property
    def default_policy_is_deny(self) -> bool:
        """True when the group's LAST rule in each direction is a catch-all drop.

        Checked structurally rather than trusted, because "default deny" configured as a datacenter
        policy that some other tool later flips is not a property this plan can rely on.
        """
        ordered = self.ordered_rules()
        for direction in (FirewallDirection.inbound, FirewallDirection.outbound):
            in_direction = [rule for rule in ordered if rule.direction == direction]
            if not in_direction:
                return False
            last = in_direction[-1]
            is_catch_all = last.source is None and last.dest is None and last.dport is None
            if not (
                is_catch_all and last.verdict in (FirewallVerdict.drop, FirewallVerdict.reject)
            ):
                return False
        return True


@dataclass(frozen=True)
class EgressGatewaySpec:
    """Controlled egress. Absent by default; present only when an approved plan asked for it."""

    vnet_name: str
    #: Exact destinations permitted out. A wildcard is not expressible on purpose.
    allowed_destinations: tuple[str, ...]
    allowed_ports: tuple[str, ...]
    ownership: Ownership
    approval_reference: str = ""

    def __post_init__(self) -> None:
        if not self.approval_reference:
            raise ProxmoxModelError(
                "egress requires an explicit approval reference; egress that nobody approved is "
                "exactly what the default-deny posture exists to prevent"
            )
        if not self.allowed_destinations:
            raise ProxmoxModelError("egress must name at least one allowed destination")
        for dest in self.allowed_destinations:
            ipaddress.ip_network(dest, strict=False)


# --------------------------------------------------------------------------------------
# The compiled result
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SegregatedNetworkPlan:
    """The compiled network: one zone, N VNets, the firewall objects that isolate them."""

    zone: SdnZoneSpec
    vnets: tuple[VNetSpec, ...]
    security_groups: tuple[SecurityGroupSpec, ...]
    ip_sets: tuple[IpSetSpec, ...]
    #: Which security group is attached to each VNet's guest NICs.
    vnet_security_group: dict[str, str] = field(default_factory=dict)
    egress: EgressGatewaySpec | None = None

    def vnet(self, name: str) -> VNetSpec | None:
        for candidate in self.vnets:
            if candidate.name == name:
                return candidate
        return None

    def vnets_for_team(self, team_ref: str) -> tuple[VNetSpec, ...]:
        return tuple(vnet for vnet in self.vnets if vnet.ownership.team_ref == team_ref)

    @property
    def team_refs(self) -> tuple[str, ...]:
        seen = [v.ownership.team_ref for v in self.vnets if v.ownership.team_ref is not None]
        return tuple(sorted(set(seen)))


@dataclass(frozen=True)
class CompiledTopology:
    """A complete, apply-ready desired state for one range generation.

    Everything needed to render a workspace is here and is already resolved. Anything the compiler
    could not resolve produced a :class:`BlockedPlan` instead of this.
    """

    target: ProxmoxTargetIdentity
    ownership: Ownership
    network: SegregatedNetworkPlan
    guests: tuple[GuestSpec, ...]
    #: The IPAM ledger this topology was compiled against, serialized for the manifest.
    allocations: tuple[dict, ...] = ()

    def guests_on_vnet(self, vnet_name: str) -> tuple[GuestSpec, ...]:
        return tuple(
            guest for guest in self.guests if any(nic.vnet_name == vnet_name for nic in guest.nics)
        )

    def guests_for_team(self, team_ref: str) -> tuple[GuestSpec, ...]:
        return tuple(guest for guest in self.guests if guest.ownership.team_ref == team_ref)


def assert_management_plane_untouched(
    topology: CompiledTopology,
    *,
    management_bridges: tuple[str, ...] = (),
) -> None:
    """Refuse a topology that would own, bridge into, or address the management plane.

    The management network is pre-existing infrastructure. A scenario that allocates inside it,
    rides its bridge, or routes to it is not a misconfiguration to warn about — it is the one
    outcome that takes the control plane down with the lab, so this raises.
    """
    management_networks = [
        ipaddress.ip_network(cidr, strict=True) for cidr in topology.target.management_cidrs
    ]
    # The target's own declaration is authoritative; the argument only ever adds to it, so a
    # caller cannot narrow the guard by passing an empty tuple.
    management_bridges = tuple({*management_bridges, *topology.target.management_bridges})

    if management_bridges and topology.network.zone.bridge in management_bridges:
        raise ProxmoxModelError(
            f"SDN zone {topology.network.zone.name!r} rides management bridge "
            f"{topology.network.zone.bridge!r}; the management plane must never be scenario-owned"
        )

    for vnet in topology.network.vnets:
        subnet = vnet.subnet.network
        for management in management_networks:
            if subnet.overlaps(management):
                raise ProxmoxModelError(
                    f"VNet {vnet.name!r} subnet {vnet.subnet.cidr} overlaps the management network "
                    f"{management}; scenario addressing must never intersect the management plane"
                )

    for guest in topology.guests:
        published = ipaddress.ip_address(guest.address.published_address)
        for management in management_networks:
            if published in management:
                raise ProxmoxModelError(
                    f"guest {guest.guest_ref!r} is addressed inside the management network "
                    f"{management}"
                )
