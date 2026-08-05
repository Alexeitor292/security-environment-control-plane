"""Serialize a compiled Proxmox desired state into the immutable provisioning manifest.

The compiler in :mod:`secp_api.range_providers.proxmox_network` produces a
:class:`~secp_api.range_providers.proxmox_model.CompiledTopology` of frozen dataclasses. The worker
renders HCL from a plain ``dict`` read out of ``ProvisioningManifest.content``. This module is the
one seam between them.

WHY THE PAYLOAD IS ORDERED, NOT JUST SERIALIZED
------------------------------------------------
The renderer's contract is that identical desired state plus identical discovery produces
byte-identical HCL. Python dict and set iteration order would leak into the rendered files through
this payload, so every collection here is emitted in an explicit sort order and every mapping is
built with sorted keys. Determinism is established HERE, at the boundary, rather than being
re-imposed by each consumer — a consumer that forgets would produce a plan whose hash changes
without the desired state changing, and an operator would be asked to re-approve an identical plan.

The payload carries NO secrets and no endpoint credentials. Provider endpoint and token reach
OpenTofu only as input variables injected just-in-time in the worker (see the bundle renderer);
they are never part of the manifest, its hash, or anything derived from it.
"""

from __future__ import annotations

from dataclasses import replace

from secp_api.range_enums import RangeResourceKind
from secp_api.range_providers.proxmox_ipam import AllocationLedger
from secp_api.range_providers.proxmox_model import (
    CloneStrategy,
    CloudInitSpec,
    CompiledTopology,
    DiskSpec,
    EgressGatewaySpec,
    FirewallDirection,
    FirewallRuleSpec,
    FirewallVerdict,
    GuestAddress,
    GuestKind,
    GuestSpec,
    IpSetSpec,
    NicSpec,
    Ownership,
    ProxmoxModelError,
    ProxmoxTargetIdentity,
    SdnZoneSpec,
    SecurityGroupSpec,
    SegmentRole,
    SegregatedNetworkPlan,
    SubnetSpec,
    VNetSpec,
)

#: Bumped whenever the payload shape changes in a way a renderer must notice. The bundle renderer
#: refuses a version it was not written for rather than rendering a partial workspace from fields
#: it does not understand.
DESIRED_STATE_VERSION = 1

#: The manifest key this payload occupies. Chosen so a manifest WITHOUT it renders through the
#: legacy fixture path unchanged.
MANIFEST_KEY = "proxmox_desired_state"


class DesiredStateSerializationError(ProxmoxModelError):
    """The desired state could not be serialized or read back faithfully."""


def _ownership_payload(ownership: Ownership) -> dict:
    return {
        "organization_id": ownership.organization_id,
        "target_id": ownership.target_id,
        "range_id": ownership.range_id,
        "generation": ownership.generation,
        "operation_generation": ownership.operation_generation,
        "resource_kind": ownership.resource_kind.value,
        "team_ref": ownership.team_ref,
        # The flat tag form the renderer stamps onto objects. Emitted rather than re-derived so
        # the manifest an operator approved and the tags that land on the cluster cannot diverge.
        "tags": ownership.as_tags(),
    }


def _ownership_from(payload: dict) -> Ownership:
    try:
        return Ownership(
            organization_id=str(payload["organization_id"]),
            target_id=str(payload["target_id"]),
            range_id=str(payload["range_id"]),
            generation=int(payload["generation"]),
            operation_generation=int(payload["operation_generation"]),
            resource_kind=RangeResourceKind(payload["resource_kind"]),
            team_ref=payload["team_ref"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DesiredStateSerializationError(f"malformed ownership payload: {exc}") from exc


def _rule_payload(rule: FirewallRuleSpec) -> dict:
    return {
        "position": rule.position,
        "direction": rule.direction.value,
        "verdict": rule.verdict.value,
        "comment": rule.comment,
        "source": rule.source,
        "dest": rule.dest,
        "proto": rule.proto,
        "dport": rule.dport,
        "enabled": rule.enabled,
    }


def _rule_from(payload: dict) -> FirewallRuleSpec:
    return FirewallRuleSpec(
        position=int(payload["position"]),
        direction=FirewallDirection(payload["direction"]),
        verdict=FirewallVerdict(payload["verdict"]),
        comment=str(payload["comment"]),
        source=payload.get("source"),
        dest=payload.get("dest"),
        proto=payload.get("proto"),
        dport=payload.get("dport"),
        enabled=bool(payload.get("enabled", True)),
    )


def _guest_payload(guest: GuestSpec) -> dict:
    return {
        "guest_ref": guest.guest_ref,
        "name": guest.name,
        "kind": guest.kind.value,
        "vmid": guest.vmid,
        "node_name": guest.node_name,
        "template_ref": guest.template_ref,
        "clone_strategy": guest.clone_strategy.value,
        "cpu_cores": guest.cpu_cores,
        "memory_mb": guest.memory_mb,
        "start_on_deploy": guest.start_on_deploy,
        "readiness_timeout_seconds": guest.readiness_timeout_seconds,
        "disks": [
            {
                "slot": disk.slot,
                "size_gb": disk.size_gb,
                "storage_id": disk.storage_id,
                "discard": disk.discard,
                "ssd_emulation": disk.ssd_emulation,
            }
            # Sorted by slot: the rendered disk blocks must not reorder between runs.
            for disk in sorted(guest.disks, key=lambda d: d.slot)
        ],
        "nics": [
            {
                "index": nic.index,
                "vnet_name": nic.vnet_name,
                "mac_address": nic.mac_address,
                "model": nic.model,
                "firewall": nic.firewall,
            }
            for nic in sorted(guest.nics, key=lambda n: n.index)
        ],
        "address": {
            "published_address": guest.address.published_address,
            # Kept distinct with no fallback. A renderer that substituted one for the other would
            # reintroduce the published-vs-probe defect this repo already fixed once.
            "probe_address": guest.address.probe_address,
        },
        "cloud_init": (
            None
            if guest.cloud_init is None
            else {
                "user": guest.cloud_init.user,
                "ssh_authorized_keys": list(guest.cloud_init.ssh_authorized_keys),
                "nameservers": list(guest.cloud_init.nameservers),
                "search_domain": guest.cloud_init.search_domain,
                "gateway": guest.cloud_init.gateway,
            }
        ),
        "ownership": _ownership_payload(guest.ownership),
    }


def _guest_from(payload: dict) -> GuestSpec:
    cloud_init = payload.get("cloud_init")
    return GuestSpec(
        guest_ref=str(payload["guest_ref"]),
        name=str(payload["name"]),
        kind=GuestKind(payload["kind"]),
        vmid=int(payload["vmid"]),
        node_name=str(payload["node_name"]),
        template_ref=str(payload["template_ref"]),
        clone_strategy=CloneStrategy(payload["clone_strategy"]),
        cpu_cores=int(payload["cpu_cores"]),
        memory_mb=int(payload["memory_mb"]),
        disks=tuple(
            DiskSpec(
                slot=str(d["slot"]),
                size_gb=int(d["size_gb"]),
                storage_id=str(d["storage_id"]),
                discard=bool(d.get("discard", True)),
                ssd_emulation=bool(d.get("ssd_emulation", False)),
            )
            for d in payload.get("disks", [])
        ),
        nics=tuple(
            NicSpec(
                index=int(n["index"]),
                vnet_name=str(n["vnet_name"]),
                mac_address=str(n["mac_address"]),
                model=str(n.get("model", "virtio")),
                firewall=bool(n.get("firewall", True)),
            )
            for n in payload.get("nics", [])
        ),
        address=GuestAddress(
            published_address=str(payload["address"]["published_address"]),
            probe_address=payload["address"].get("probe_address"),
        ),
        ownership=_ownership_from(payload["ownership"]),
        cloud_init=(
            None
            if cloud_init is None
            else CloudInitSpec(
                user=str(cloud_init["user"]),
                ssh_authorized_keys=tuple(cloud_init.get("ssh_authorized_keys", [])),
                nameservers=tuple(cloud_init.get("nameservers", [])),
                search_domain=cloud_init.get("search_domain"),
                gateway=cloud_init.get("gateway"),
            )
        ),
        start_on_deploy=bool(payload.get("start_on_deploy", True)),
        readiness_timeout_seconds=int(payload.get("readiness_timeout_seconds", 300)),
    )


def to_manifest_payload(
    topology: CompiledTopology,
    ledger: AllocationLedger | None = None,
) -> dict:
    """Serialize a compiled topology into the manifest payload the worker renders from.

    Every collection is explicitly ordered. The allocation ledger travels with the topology so the
    plan an operator approves contains the exact identifiers that will be created.
    """
    network = topology.network
    payload = {
        "desired_state_version": DESIRED_STATE_VERSION,
        "target": {
            "target_id": topology.target.target_id,
            "cluster_name": topology.target.cluster_name,
            "cluster_fingerprint": topology.target.cluster_fingerprint,
            "management_cidrs": sorted(topology.target.management_cidrs),
            "management_bridges": sorted(topology.target.management_bridges),
        },
        "ownership": _ownership_payload(topology.ownership),
        "network": {
            "zone": {
                "name": network.zone.name,
                "bridge": network.zone.bridge,
                "nodes": sorted(network.zone.nodes),
                "mtu": network.zone.mtu,
                "ownership": _ownership_payload(network.zone.ownership),
            },
            "vnets": [
                {
                    "name": vnet.name,
                    "zone_name": vnet.zone_name,
                    "vlan_tag": vnet.vlan_tag,
                    "role": vnet.role.value,
                    "alias": vnet.alias,
                    "subnet": {
                        "cidr": vnet.subnet.cidr,
                        "gateway": vnet.subnet.gateway,
                        "routed": vnet.subnet.routed,
                    },
                    "ownership": _ownership_payload(vnet.ownership),
                }
                for vnet in sorted(network.vnets, key=lambda v: v.name)
            ],
            "ip_sets": [
                {
                    "name": ip_set.name,
                    "cidrs": sorted(ip_set.cidrs),
                    "comment": ip_set.comment,
                    "ownership": _ownership_payload(ip_set.ownership),
                }
                for ip_set in sorted(network.ip_sets, key=lambda i: i.name)
            ],
            "security_groups": [
                {
                    "name": group.name,
                    "comment": group.comment,
                    "ownership": _ownership_payload(group.ownership),
                    # ordered_rules() is the same order the evaluator and the renderer use, so the
                    # reviewed plan and the enforced policy cannot disagree about precedence.
                    "rules": [_rule_payload(rule) for rule in group.ordered_rules()],
                }
                for group in sorted(network.security_groups, key=lambda g: g.name)
            ],
            "vnet_security_group": dict(sorted(network.vnet_security_group.items())),
            "egress": (
                None
                if network.egress is None
                else {
                    "vnet_name": network.egress.vnet_name,
                    "allowed_destinations": sorted(network.egress.allowed_destinations),
                    "allowed_ports": sorted(network.egress.allowed_ports),
                    "approval_reference": network.egress.approval_reference,
                    "ownership": _ownership_payload(network.egress.ownership),
                }
            ),
        },
        "guests": [
            _guest_payload(guest) for guest in sorted(topology.guests, key=lambda g: g.guest_ref)
        ],
        "allocations": (
            list(topology.allocations)
            if ledger is None
            else [allocation.as_dict() for allocation in ledger.all()]
        ),
    }
    if ledger is not None:
        payload["allocation_ledger"] = ledger.to_manifest()
    return payload


def from_manifest_payload(payload: dict) -> CompiledTopology:
    """Read a compiled topology back out of a manifest payload.

    Used by reset and destroy, which must act on the desired state that was APPROVED rather than
    recompiling — a recompile against drifted discovery would silently produce a different plan
    than the one a human signed off.
    """
    if not isinstance(payload, dict):
        raise DesiredStateSerializationError("desired-state payload must be an object")
    version = payload.get("desired_state_version")
    if version != DESIRED_STATE_VERSION:
        raise DesiredStateSerializationError(
            f"unsupported desired_state_version {version!r}; this reader understands "
            f"{DESIRED_STATE_VERSION}"
        )
    try:
        target_payload = payload["target"]
        network_payload = payload["network"]
        zone_payload = network_payload["zone"]
    except KeyError as exc:
        raise DesiredStateSerializationError(f"desired-state payload is missing {exc}") from exc

    target = ProxmoxTargetIdentity(
        target_id=str(target_payload["target_id"]),
        cluster_name=str(target_payload["cluster_name"]),
        cluster_fingerprint=str(target_payload["cluster_fingerprint"]),
        management_cidrs=tuple(target_payload["management_cidrs"]),
        management_bridges=tuple(target_payload.get("management_bridges", ())),
    )
    zone = SdnZoneSpec(
        name=str(zone_payload["name"]),
        bridge=str(zone_payload["bridge"]),
        nodes=tuple(zone_payload["nodes"]),
        ownership=_ownership_from(zone_payload["ownership"]),
        mtu=zone_payload.get("mtu"),
    )
    vnets = tuple(
        VNetSpec(
            name=str(item["name"]),
            zone_name=str(item["zone_name"]),
            vlan_tag=int(item["vlan_tag"]),
            subnet=SubnetSpec(
                cidr=str(item["subnet"]["cidr"]),
                gateway=str(item["subnet"]["gateway"]),
                routed=bool(item["subnet"].get("routed", False)),
            ),
            role=SegmentRole(item["role"]),
            ownership=_ownership_from(item["ownership"]),
            alias=str(item.get("alias", "")),
        )
        for item in network_payload.get("vnets", [])
    )
    ip_sets = tuple(
        IpSetSpec(
            name=str(item["name"]),
            cidrs=tuple(item["cidrs"]),
            ownership=_ownership_from(item["ownership"]),
            comment=str(item.get("comment", "")),
        )
        for item in network_payload.get("ip_sets", [])
    )
    security_groups = tuple(
        SecurityGroupSpec(
            name=str(item["name"]),
            rules=tuple(_rule_from(rule) for rule in item.get("rules", [])),
            ownership=_ownership_from(item["ownership"]),
            comment=str(item.get("comment", "")),
        )
        for item in network_payload.get("security_groups", [])
    )
    egress_payload = network_payload.get("egress")
    egress = (
        None
        if egress_payload is None
        else EgressGatewaySpec(
            vnet_name=str(egress_payload["vnet_name"]),
            allowed_destinations=tuple(egress_payload["allowed_destinations"]),
            allowed_ports=tuple(egress_payload["allowed_ports"]),
            ownership=_ownership_from(egress_payload["ownership"]),
            approval_reference=str(egress_payload["approval_reference"]),
        )
    )
    network = SegregatedNetworkPlan(
        zone=zone,
        vnets=vnets,
        security_groups=security_groups,
        ip_sets=ip_sets,
        vnet_security_group=dict(network_payload.get("vnet_security_group", {})),
        egress=egress,
    )
    return CompiledTopology(
        target=target,
        ownership=_ownership_from(payload["ownership"]),
        network=network,
        guests=tuple(_guest_from(item) for item in payload.get("guests", [])),
        allocations=tuple(payload.get("allocations", ())),
    )


def attach_to_manifest(
    manifest: dict, topology: CompiledTopology, ledger: AllocationLedger
) -> dict:
    """Return a copy of ``manifest`` carrying the desired state and its allocation ledger.

    Returns a NEW dict rather than mutating: the caller's manifest may already be the immutable
    ADR-011 content, and mutating it in place would change a value whose hash is the binding a
    later stage verifies.
    """
    updated = dict(manifest)
    updated[MANIFEST_KEY] = to_manifest_payload(topology, ledger)
    return updated


def with_operation_generation(topology: CompiledTopology, generation: int) -> CompiledTopology:
    """Re-stamp every ownership tag for a new lifecycle operation.

    The desired-state ``generation`` is untouched — only ``operation_generation`` advances — so the
    IPAM scope key is unchanged and a reset resolves to the allocations the deploy recorded.
    """

    def restamp(ownership: Ownership) -> Ownership:
        return replace(ownership, operation_generation=generation)

    network = topology.network
    return replace(
        topology,
        ownership=restamp(topology.ownership),
        network=replace(
            network,
            zone=replace(network.zone, ownership=restamp(network.zone.ownership)),
            vnets=tuple(replace(v, ownership=restamp(v.ownership)) for v in network.vnets),
            ip_sets=tuple(replace(i, ownership=restamp(i.ownership)) for i in network.ip_sets),
            security_groups=tuple(
                replace(g, ownership=restamp(g.ownership)) for g in network.security_groups
            ),
            egress=(
                None
                if network.egress is None
                else replace(network.egress, ownership=restamp(network.egress.ownership))
            ),
        ),
        guests=tuple(replace(g, ownership=restamp(g.ownership)) for g in topology.guests),
    )
