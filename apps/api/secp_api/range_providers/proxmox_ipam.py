"""Deterministic, recorded, conflict-checked allocation for Proxmox ranges.

Every identifier a compiled range needs — VM/CT ids, MACs, subnets, guest and gateway addresses,
VLAN tags, VNet and firewall object names, remote-state keys — is allocated here, recorded here,
and read back from here. Nothing else in the compiler may invent an identifier.

WHY A LEDGER AND NOT A COUNTER
-------------------------------
The obvious implementation hands out "the next free VMID" at render time. That is wrong in three
separate ways this module is built to prevent:

1. **It is not reproducible.** A reset that re-derives "next free" after some other tenant took
   105 renumbers the range under the participants. Allocation is therefore *derived from a stable
   digest of the scope* and then *recorded*; re-running the compiler on the same inputs yields
   byte-identical output.
2. **It is not reviewable.** An identifier invented during apply never appears in the plan a human
   approved. Every allocation here lands in the ledger, the ledger goes into the immutable
   manifest, and the manifest is what gets approved.
3. **It cannot be safely released.** Freeing an id because a destroy "probably worked" is how a
   later range gets an id that still has a live VM on it. :meth:`AllocationLedger.release` demands
   a proof-of-absence observation and refuses anything weaker.

WHERE THE LEDGER IS PERSISTED
------------------------------
Inside ``ProvisioningManifest.content`` (ADR-011), which is already JSON, already written before
apply, already content-hashed, and already immutable after creation via
:mod:`secp_api.immutability`. That gives "persisted before apply, immutable after plan approval"
with no new table and no migration. :meth:`AllocationLedger.to_manifest` produces that payload and
:meth:`AllocationLedger.from_manifest` reads it back for a reset or a destroy.

UNKNOWN AVAILABILITY BLOCKS
----------------------------
Every allocator cross-checks its candidate against what live discovery observed. When the relevant
observation is ``None`` — not collected — the allocator raises :class:`AllocationBlocked` rather
than allocating. "We did not look" is never treated as "nothing is there".
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from enum import Enum

from secp_api.range_providers.proxmox_model import (
    VLAN_MAX,
    VLAN_MIN,
    VMID_MAX,
    VMID_MIN,
    MissingPrerequisite,
    Ownership,
    ProxmoxModelError,
)

#: Locally-administered unicast OUI. Bit 1 of the first octet set = locally administered, bit 0
#: clear = unicast. Using a real vendor OUI would be a (small) lie about hardware provenance and
#: risks colliding with actual NICs on the same L2.
LOCAL_MAC_OUI = (0x02, 0x53, 0x45)  # 02:53:45 — "SE" for SECP.

_STATE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9/_.-]{0,190}$")


class AllocationKind(str, Enum):
    """Every class of identifier the compiler is allowed to need."""

    vmid = "vmid"
    lxc_id = "lxc_id"
    mac = "mac"
    subnet = "subnet"
    guest_address = "guest_address"
    gateway_address = "gateway_address"
    vlan_tag = "vlan_tag"
    vnet_name = "vnet_name"
    zone_name = "zone_name"
    resource_name = "resource_name"
    firewall_object_name = "firewall_object_name"
    remote_state_key = "remote_state_key"


class AllocationError(ProxmoxModelError):
    """An allocation was structurally invalid, duplicated, or attempted on a sealed ledger."""


class AllocationBlocked(Exception):
    """Allocation is impossible without an observation that was never collected.

    Carries a :class:`MissingPrerequisite` so the compiler can aggregate every blocker into one
    closed :class:`~secp_api.range_providers.proxmox_model.BlockedPlan` instead of failing on the
    first one.
    """

    def __init__(self, prerequisite: MissingPrerequisite) -> None:
        super().__init__(f"[{prerequisite.reason_id}] {prerequisite.detail}")
        self.prerequisite = prerequisite


@dataclass(frozen=True)
class Allocation:
    """One recorded identifier.

    ``purpose`` distinguishes multiple allocations of the same kind within one scope (the attacker
    VNet's subnet vs the vulnerable VNet's subnet). ``(scope, kind, purpose)`` is the primary key:
    asking twice for the same triple returns the same value, which is what makes the compiler
    idempotent.
    """

    kind: AllocationKind
    #: ``(organization_id, target_id, range_id, team_ref, generation)``.
    scope: tuple[str, str, str, str, int]
    purpose: str
    value: str

    def key(self) -> tuple[tuple[str, str, str, str, int], AllocationKind, str]:
        return (self.scope, self.kind, self.purpose)

    def as_dict(self) -> dict:
        organization_id, target_id, range_id, team_ref, generation = self.scope
        return {
            "kind": self.kind.value,
            "organization_id": organization_id,
            "target_id": target_id,
            "range_id": range_id,
            "team_ref": team_ref,
            "generation": generation,
            "purpose": self.purpose,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> Allocation:
        try:
            return cls(
                kind=AllocationKind(payload["kind"]),
                scope=(
                    str(payload["organization_id"]),
                    str(payload["target_id"]),
                    str(payload["range_id"]),
                    str(payload["team_ref"]),
                    int(payload["generation"]),
                ),
                purpose=str(payload["purpose"]),
                value=str(payload["value"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AllocationError(f"malformed allocation record: {exc}") from exc


@dataclass(frozen=True)
class IpamPools:
    """The bounds SECP is permitted to allocate within.

    These are policy, not discovery: an operator declares which VMID band and which supernet this
    product may use on their cluster. The allocator never steps outside them, and a pool too small
    for the requested topology is a blocking error rather than a silent overflow.
    """

    vmid_min: int = 9000
    vmid_max: int = 9999
    #: The supernet every scenario subnet is carved from.
    supernet: str = "10.80.0.0/12"
    #: Prefix length of each carved segment subnet.
    segment_prefix: int = 24
    vlan_min: int = 1000
    vlan_max: int = 1999

    def __post_init__(self) -> None:
        if not VMID_MIN <= self.vmid_min <= self.vmid_max <= VMID_MAX:
            raise AllocationError(
                f"vmid pool {self.vmid_min}-{self.vmid_max} is outside the Proxmox range "
                f"{VMID_MIN}-{VMID_MAX} or inverted"
            )
        if not VLAN_MIN <= self.vlan_min <= self.vlan_max <= VLAN_MAX:
            raise AllocationError(
                f"vlan pool {self.vlan_min}-{self.vlan_max} is outside the usable range "
                f"{VLAN_MIN}-{VLAN_MAX} or inverted"
            )
        supernet = ipaddress.ip_network(self.supernet, strict=True)
        if not isinstance(supernet, ipaddress.IPv4Network):
            raise AllocationError("supernet must be IPv4")
        if self.segment_prefix <= supernet.prefixlen:
            raise AllocationError(
                f"segment prefix /{self.segment_prefix} must be longer than the supernet prefix "
                f"/{supernet.prefixlen}, otherwise no segments can be carved"
            )
        if self.segment_prefix > 30:
            raise AllocationError(
                f"segment prefix /{self.segment_prefix} leaves no usable guest addresses"
            )

    @property
    def supernet_network(self) -> ipaddress.IPv4Network:
        network = ipaddress.ip_network(self.supernet, strict=True)
        assert isinstance(network, ipaddress.IPv4Network)
        return network

    def candidate_subnets(self) -> tuple[ipaddress.IPv4Network, ...]:
        return tuple(self.supernet_network.subnets(new_prefix=self.segment_prefix))


def _digest_offset(scope: tuple[str, str, str, str, int], purpose: str, salt: str) -> int:
    """A stable non-negative integer derived from the allocation identity.

    Used as the STARTING OFFSET of a deterministic walk, not as the value itself. Deriving the
    value directly from a hash would make collisions unresolvable; deriving the start point keeps
    determinism while still letting the walk step past anything already taken.
    """
    payload = "\x1f".join([*(str(part) for part in scope), purpose, salt])
    return int.from_bytes(hashlib.sha256(payload.encode("utf-8")).digest()[:8], "big")


class AllocationLedger:
    """The recorded set of allocations for one range, with sealing and proof-gated release.

    A ledger moves through exactly two states. While OPEN it accepts new allocations. Once
    :meth:`seal` is called — which the service does when the plan is approved — it accepts none,
    and any attempt to allocate a value not already recorded raises. That is the mechanism behind
    "a changed allocation requires a new plan and new approval": the compiler cannot quietly widen
    an approved plan, it can only fail and force a new generation.
    """

    def __init__(
        self,
        allocations: tuple[Allocation, ...] = (),
        *,
        sealed: bool = False,
    ) -> None:
        self._by_key: dict[tuple, Allocation] = {}
        for allocation in allocations:
            if allocation.key() in self._by_key:
                raise AllocationError(f"duplicate allocation for {allocation.key()}")
            self._by_key[allocation.key()] = allocation
        self._sealed = sealed

    # -- state -------------------------------------------------------------------------

    @property
    def sealed(self) -> bool:
        return self._sealed

    def seal(self) -> None:
        """Freeze the ledger. Called when the plan is approved; there is no unseal."""
        self._sealed = True

    def __len__(self) -> int:
        return len(self._by_key)

    def all(self) -> tuple[Allocation, ...]:
        """Every allocation in a stable order, so the manifest payload is byte-reproducible."""
        return tuple(
            sorted(
                self._by_key.values(),
                key=lambda a: (a.kind.value, a.scope, a.purpose),
            )
        )

    def values_of(self, kind: AllocationKind) -> tuple[str, ...]:
        return tuple(a.value for a in self.all() if a.kind == kind)

    def get(
        self, scope: tuple[str, str, str, str, int], kind: AllocationKind, purpose: str
    ) -> Allocation | None:
        return self._by_key.get((scope, kind, purpose))

    # -- persistence -------------------------------------------------------------------

    def to_manifest(self) -> dict:
        """The payload embedded in ``ProvisioningManifest.content``.

        ``ledger_hash`` lets a later stage prove the ledger it is reading is the one that was
        approved, without re-deriving anything.
        """
        records = [allocation.as_dict() for allocation in self.all()]
        return {
            "version": 1,
            "sealed": self._sealed,
            "allocations": records,
            "ledger_hash": self.content_hash(),
        }

    @classmethod
    def from_manifest(cls, payload: dict) -> AllocationLedger:
        """Read a ledger back from a manifest, verifying it was not edited in place."""
        if not isinstance(payload, dict):
            raise AllocationError("allocation ledger payload must be an object")
        if payload.get("version") != 1:
            raise AllocationError(f"unsupported allocation ledger version {payload.get('version')}")
        records = payload.get("allocations")
        if not isinstance(records, list):
            raise AllocationError("allocation ledger payload has no allocations list")
        ledger = cls(tuple(Allocation.from_dict(record) for record in records))
        expected = payload.get("ledger_hash")
        if expected is not None and expected != ledger.content_hash():
            raise AllocationError(
                "allocation ledger hash mismatch: the recorded allocations do not match the hash "
                "they were approved under"
            )
        if payload.get("sealed"):
            ledger.seal()
        return ledger

    def content_hash(self) -> str:
        payload = json.dumps(
            [allocation.as_dict() for allocation in self.all()],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # -- allocation --------------------------------------------------------------------

    def _record(self, allocation: Allocation) -> Allocation:
        existing = self._by_key.get(allocation.key())
        if existing is not None:
            return existing
        if self._sealed:
            raise AllocationError(
                f"ledger is sealed: cannot allocate {allocation.kind.value} for "
                f"{allocation.purpose!r}. A changed allocation requires a new plan generation and "
                "a new approval."
            )
        self._by_key[allocation.key()] = allocation
        return allocation

    def _reserved(self, kind: AllocationKind) -> set[str]:
        return {a.value for a in self._by_key.values() if a.kind == kind}

    def allocate_int(
        self,
        *,
        ownership: Ownership,
        kind: AllocationKind,
        purpose: str,
        low: int,
        high: int,
        observed_in_use: tuple[int, ...] | None,
        observation_field: str,
        reason_id: str,
    ) -> int:
        """Deterministically allocate an integer from ``[low, high]``, skipping conflicts."""
        if observed_in_use is None:
            raise AllocationBlocked(
                MissingPrerequisite(
                    reason_id=reason_id,
                    observation=observation_field,
                    detail=(
                        f"cannot allocate {kind.value} for {purpose!r}: the set of values already "
                        "in use on the target was never observed, so availability is unknown"
                    ),
                )
            )
        scope = ownership.scope_key()
        existing = self.get(scope, kind, purpose)
        if existing is not None:
            return int(existing.value)

        span = high - low + 1
        if span <= 0:
            raise AllocationError(f"{kind.value} pool is empty")
        taken = {int(value) for value in self._reserved(kind)} | set(observed_in_use)
        start = _digest_offset(scope, purpose, kind.value) % span
        for step in range(span):
            candidate = low + (start + step) % span
            if candidate not in taken:
                self._record(
                    Allocation(kind=kind, scope=scope, purpose=purpose, value=str(candidate))
                )
                return candidate
        raise AllocationError(
            f"{kind.value} pool {low}-{high} is exhausted: {len(taken)} of {span} values are "
            "already in use or reserved"
        )

    def allocate_vmid(
        self,
        *,
        ownership: Ownership,
        purpose: str,
        pools: IpamPools,
        observed_vmids: tuple[int, ...] | None,
        lxc: bool = False,
    ) -> int:
        """Allocate a guest id. VM and CT ids share one Proxmox namespace, so they share a pool.

        The ``kind`` recorded still distinguishes them, because the ledger is also the audit record
        of what was created, but collision checking deliberately spans both.
        """
        kind = AllocationKind.lxc_id if lxc else AllocationKind.vmid
        if observed_vmids is None:
            raise AllocationBlocked(
                MissingPrerequisite(
                    reason_id="proxmox.vmid_inventory_missing",
                    observation="TargetObservation.vmids_in_use",
                    detail=(
                        f"cannot allocate a guest id for {purpose!r}: the cluster's existing VM/CT "
                        "ids were never observed, so a collision cannot be ruled out"
                    ),
                )
            )
        scope = ownership.scope_key()
        existing = self.get(scope, kind, purpose)
        if existing is not None:
            return int(existing.value)

        # Both id kinds occupy one namespace on Proxmox — reserve across both.
        taken = {int(v) for v in self._reserved(AllocationKind.vmid)}
        taken |= {int(v) for v in self._reserved(AllocationKind.lxc_id)}
        taken |= set(observed_vmids)
        span = pools.vmid_max - pools.vmid_min + 1
        start = _digest_offset(scope, purpose, kind.value) % span
        for step in range(span):
            candidate = pools.vmid_min + (start + step) % span
            if candidate not in taken:
                self._record(
                    Allocation(kind=kind, scope=scope, purpose=purpose, value=str(candidate))
                )
                return candidate
        raise AllocationError(
            f"guest id pool {pools.vmid_min}-{pools.vmid_max} is exhausted "
            f"({len(taken)} of {span} taken)"
        )

    def allocate_subnet(
        self,
        *,
        ownership: Ownership,
        purpose: str,
        pools: IpamPools,
        observed_subnets: tuple[str, ...] | None,
        management_cidrs: tuple[str, ...],
    ) -> ipaddress.IPv4Network:
        """Allocate a segment subnet that overlaps nothing observed and nothing management."""
        if observed_subnets is None:
            raise AllocationBlocked(
                MissingPrerequisite(
                    reason_id="proxmox.subnet_inventory_missing",
                    observation="TargetObservation.subnets_in_use",
                    detail=(
                        f"cannot allocate a subnet for {purpose!r}: the networks already routed on "
                        "the target were never observed, so an overlap cannot be ruled out"
                    ),
                )
            )
        scope = ownership.scope_key()
        existing = self.get(scope, AllocationKind.subnet, purpose)
        if existing is not None:
            return ipaddress.ip_network(existing.value, strict=True)  # type: ignore[return-value]

        blocked = [ipaddress.ip_network(cidr, strict=False) for cidr in observed_subnets]
        blocked += [ipaddress.ip_network(cidr, strict=True) for cidr in management_cidrs]
        blocked += [
            ipaddress.ip_network(value, strict=True)
            for value in self._reserved(AllocationKind.subnet)
        ]
        candidates = pools.candidate_subnets()
        span = len(candidates)
        if span == 0:
            raise AllocationError("subnet pool yields no candidates")
        start = _digest_offset(scope, purpose, AllocationKind.subnet.value) % span
        for step in range(span):
            candidate = candidates[(start + step) % span]
            if not any(candidate.overlaps(other) for other in blocked):
                self._record(
                    Allocation(
                        kind=AllocationKind.subnet,
                        scope=scope,
                        purpose=purpose,
                        value=str(candidate),
                    )
                )
                return candidate
        raise AllocationError(
            f"subnet pool {pools.supernet} has no /{pools.segment_prefix} free of the "
            f"{len(blocked)} networks already in use"
        )

    def allocate_address(
        self,
        *,
        ownership: Ownership,
        purpose: str,
        subnet: ipaddress.IPv4Network,
        kind: AllocationKind = AllocationKind.guest_address,
        offset: int | None = None,
    ) -> ipaddress.IPv4Address:
        """Allocate an address inside an already-allocated subnet.

        No discovery cross-check is needed or possible here: the subnet was just proved to overlap
        nothing, so the only conflicts are ones this ledger itself created.
        """
        scope = ownership.scope_key()
        existing = self.get(scope, kind, purpose)
        if existing is not None:
            return ipaddress.ip_address(existing.value)  # type: ignore[return-value]

        hosts = list(subnet.hosts())
        if not hosts:
            raise AllocationError(f"subnet {subnet} has no usable host addresses")
        taken = {
            str(a.value)
            for a in self._by_key.values()
            if a.kind in (AllocationKind.guest_address, AllocationKind.gateway_address)
        }
        chosen: ipaddress.IPv4Address | None = None
        if offset is not None:
            if offset >= len(hosts):
                raise AllocationError(f"offset {offset} outside subnet {subnet}")
            chosen = hosts[offset]
            if str(chosen) in taken:
                raise AllocationError(f"address {chosen} already allocated in {subnet}")
        else:
            span = len(hosts)
            start = _digest_offset(scope, purpose, kind.value) % span
            for step in range(span):
                candidate = hosts[(start + step) % span]
                if str(candidate) not in taken:
                    chosen = candidate
                    break
        if chosen is None:
            raise AllocationError(f"subnet {subnet} is fully allocated")
        self._record(Allocation(kind=kind, scope=scope, purpose=purpose, value=str(chosen)))
        return chosen

    def allocate_mac(
        self,
        *,
        ownership: Ownership,
        purpose: str,
        observed_macs: tuple[str, ...] | None,
    ) -> str:
        """Allocate a locally-administered MAC that collides with nothing observed."""
        if observed_macs is None:
            raise AllocationBlocked(
                MissingPrerequisite(
                    reason_id="proxmox.mac_inventory_missing",
                    observation="TargetObservation.macs_in_use",
                    detail=(
                        f"cannot allocate a MAC for {purpose!r}: existing guest MACs were never "
                        "observed, so a layer-2 collision cannot be ruled out"
                    ),
                )
            )
        scope = ownership.scope_key()
        existing = self.get(scope, AllocationKind.mac, purpose)
        if existing is not None:
            return existing.value

        taken = {mac.upper() for mac in observed_macs} | self._reserved(AllocationKind.mac)
        base = _digest_offset(scope, purpose, AllocationKind.mac.value)
        for step in range(1 << 20):
            suffix = (base + step) & 0xFFFFFF
            octets = (*LOCAL_MAC_OUI, (suffix >> 16) & 0xFF, (suffix >> 8) & 0xFF, suffix & 0xFF)
            candidate = ":".join(f"{octet:02X}" for octet in octets)
            if candidate not in taken:
                self._record(
                    Allocation(
                        kind=AllocationKind.mac, scope=scope, purpose=purpose, value=candidate
                    )
                )
                return candidate
        raise AllocationError("MAC space exhausted for this scope")

    def allocate_name(
        self,
        *,
        ownership: Ownership,
        purpose: str,
        kind: AllocationKind,
        candidate: str,
        observed_names: tuple[str, ...] | None,
        observation_field: str,
        reason_id: str,
        max_length: int | None = None,
    ) -> str:
        """Record a generated object name after proving nothing already holds it.

        Names are *proposed* by the caller (they carry meaning — ``t1atk`` is readable in a UI)
        rather than derived from a hash, but they are still collision-checked and still recorded.
        A collision appends a deterministic discriminator instead of silently reusing the name of
        an object SECP does not own.
        """
        if observed_names is None:
            raise AllocationBlocked(
                MissingPrerequisite(
                    reason_id=reason_id,
                    observation=observation_field,
                    detail=(
                        f"cannot allocate a name for {purpose!r}: existing object names on the "
                        "target were never observed, so a collision cannot be ruled out"
                    ),
                )
            )
        scope = ownership.scope_key()
        existing = self.get(scope, kind, purpose)
        if existing is not None:
            return existing.value

        taken = {name.lower() for name in observed_names} | {
            value.lower() for value in self._reserved(kind)
        }
        base = candidate
        if max_length is not None and len(base) > max_length:
            base = base[:max_length]
        chosen = base
        if chosen.lower() in taken:
            digest = _digest_offset(scope, purpose, kind.value)
            for step in range(256):
                discriminator = f"{(digest + step) % 256:02x}"
                trimmed = base
                if max_length is not None:
                    trimmed = base[: max(0, max_length - len(discriminator))]
                attempt = f"{trimmed}{discriminator}"
                if attempt.lower() not in taken:
                    chosen = attempt
                    break
            else:
                raise AllocationError(f"could not find a free name near {base!r}")
        self._record(Allocation(kind=kind, scope=scope, purpose=purpose, value=chosen))
        return chosen

    def allocate_remote_state_key(
        self,
        *,
        ownership: Ownership,
        purpose: str = "workspace",
    ) -> str:
        """Allocate the remote-state key this range's OpenTofu state lives under.

        Derived from the scope rather than a hash so a human can find the state for a range they
        are looking at, and recorded so a later generation cannot silently point at another
        range's state.
        """
        scope = ownership.scope_key()
        existing = self.get(scope, AllocationKind.remote_state_key, purpose)
        if existing is not None:
            return existing.value
        organization_id, target_id, range_id, team_ref, generation = scope
        parts = ["secp", organization_id, target_id, range_id]
        if team_ref:
            parts.append(team_ref)
        parts.append(f"g{generation}")
        key = "/".join(part.strip().lower().replace(" ", "-") for part in parts)
        if not _STATE_KEY_RE.match(key):
            raise AllocationError(f"derived remote-state key {key!r} is not a safe key")
        self._record(
            Allocation(
                kind=AllocationKind.remote_state_key, scope=scope, purpose=purpose, value=key
            )
        )
        return key

    # -- release -----------------------------------------------------------------------

    def release(
        self,
        *,
        scope: tuple[str, str, str, str, int],
        kind: AllocationKind,
        purpose: str,
        absence_proved: bool,
        proof_detail: str = "",
    ) -> Allocation:
        """Release one allocation — only when absence was actually PROVED.

        ``absence_proved`` must come from a teardown observation whose probe was itself
        demonstrably working (``TeardownResourceOutcome.removed``), never from
        ``unproven`` and never from "the destroy call exited zero". Releasing an id whose guest may
        still exist is how the next range collides with a live machine.
        """
        allocation = self._by_key.get((scope, kind, purpose))
        if allocation is None:
            raise AllocationError(f"no allocation recorded for {(scope, kind.value, purpose)}")
        if not absence_proved:
            raise AllocationError(
                f"refusing to release {kind.value} {allocation.value!r} for {purpose!r}: absence "
                f"was not proved{f' ({proof_detail})' if proof_detail else ''}. An unproven "
                "teardown keeps its allocations reserved."
            )
        del self._by_key[(scope, kind, purpose)]
        return allocation


@dataclass
class AllocationRequestLog:
    """Collects :class:`AllocationBlocked` prerequisites so the compiler can report them all."""

    blocked: list[MissingPrerequisite] = field(default_factory=list)

    def run(self, thunk):
        """Run an allocating callable, capturing a block instead of propagating it.

        Returns ``None`` when blocked, so the caller can carry on and surface every missing
        prerequisite in one pass rather than one round-trip per field.
        """
        try:
            return thunk()
        except AllocationBlocked as blocked:
            if blocked.prerequisite not in self.blocked:
                self.blocked.append(blocked.prerequisite)
            return None
