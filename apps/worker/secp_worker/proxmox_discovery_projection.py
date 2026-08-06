"""Proxmox API payloads to per-field observations. The only place a response becomes a fact.

Every parser here obeys four rules, and each rule exists because breaking it produces a confident
wrong answer rather than a visible failure:

1. **A field is either observed or explained.** There is no default, no empty fallback and no zero.
   ``Observation`` already refuses to carry a value in an unobserved state; the parsers never try.
2. **Recognising nothing in a non-empty payload is malformed, not empty.** If the target answered
   with rows and this code understood none of them, the honest report is "the answer could not be
   parsed" — an empty result would read as "the target has none of these", which is the single most
   dangerous confusion in the whole discovery path.
3. **Per-node and per-storage facts are keyed mappings, never flat values.** One field code names a
   FACT, not a node. Returning node A's capacity as ``node_capacity`` would let a three-node
   cluster's first node stand in for the cluster once the sequencer merged it.
4. **Where two shapes could mean the same thing, normalise before reporting.** ``/nodes/{n}/status``
   reports ``pve-manager/9.1.1/abcdef`` and ``/nodes/{n}/version`` reports ``9.1.1``. Left
   unnormalised, two sources that actually agree would be recorded as contradicting each other.

Safe-direction choices are marked where they occur: where an inference could only be wrong in one
direction, the parsers take the direction that causes SECP to refuse rather than to proceed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from secp_api.discovery_observation import Observation

from secp_worker.proxmox_discovery_operations import (
    GetClusterFirewallGroupsOperation,
    GetClusterFirewallOptionsOperation,
    GetClusterResourcesOperation,
    GetClusterStatusOperation,
    GetNodeAptVersionsOperation,
    GetNodeLxcOperation,
    GetNodeNetworkOperation,
    GetNodeQemuOperation,
    GetNodesOperation,
    GetNodeStatusOperation,
    GetNodeStorageOperation,
    GetNodeVersionOperation,
    GetStorageContentOperation,
    GetVersionOperation,
)
from secp_worker.proxmox_sdn_operations import (
    GetEffectivePermissionsOperation,
    GetNodeSdnBridgesOperation,
    GetNodeSdnZonesOperation,
    GetSdnControllersOperation,
    GetSdnFabricsOperation,
    GetSdnIpamStatusOperation,
    GetSdnRootOperation,
    GetSdnSubnetsOperation,
    GetSdnVnetsOperation,
    GetSdnZonesOperation,
    parse_pending_objects,
)

PROJECTION_IMPLEMENTATION_ID = "secp.proxmox-discovery.projection/v1"


class ProjectionError(Exception):
    """An operation reached the projection with no parser. A programming error, never a target
    condition — and deliberately not survivable, because the alternative is an operation whose
    payload is silently discarded while its evidence record claims it was interpreted."""


class _MalformedPayload(Exception):
    """The payload's overall shape is wrong, so every field of this operation is unobtainable."""


# --- shared helpers -------------------------------------------------------------------------------


def _rows(payload: object, what: str) -> list[dict]:
    if not isinstance(payload, list):
        raise _MalformedPayload(f"{what}_not_a_list")
    out = []
    for row in payload:
        if not isinstance(row, dict):
            raise _MalformedPayload(f"{what}_row_not_an_object")
        out.append(row)
    return out


def _object(payload: object, what: str) -> dict:
    if not isinstance(payload, dict):
        raise _MalformedPayload(f"{what}_not_an_object")
    return payload


def _text(row: dict, key: str) -> str | None:
    value = row.get(key)
    return value if isinstance(value, str) and value else None


def _integer(row: dict, key: str) -> int | None:
    value = row.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None


def _truthy(row: dict, key: str) -> bool:
    """Proxmox reports booleans as 0/1, "0"/"1" or by omitting the key."""
    value = row.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value not in ("", "0", "false")
    return False


#: ``pve-manager/9.1.1/abcdef0123456789`` and ``9.1.1`` are the same fact in two shapes.
_PVE_MANAGER_VERSION = re.compile(r"^pve-manager/(?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)/")


def _normalised_manager_version(raw: str) -> str | None:
    match = _PVE_MANAGER_VERSION.match(raw)
    if match:
        return match.group("version")
    return raw if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", raw) else None


# --- version --------------------------------------------------------------------------------------


def _parse_api_version(operation: object, payload: object) -> dict[str, Observation]:
    """``/version``. A malformed or partial response yields ``observed_malformed`` — never an empty
    or default version, because a version is precisely the field where an invented value silently
    changes which provider SECP believes it may use."""
    from secp_worker.target_discovery.probes import ProbeError, parse_api_version

    body = _object(payload, "version_payload")
    try:
        major, minor, patch = parse_api_version(json.dumps(body).encode("utf-8"))
    except ProbeError as exc:
        raise _MalformedPayload(str(getattr(exc, "args", ["malformed_probe_output"])[0])) from None

    release = body.get("release")
    repoid = body.get("repoid")
    return {
        "pve_version_full": Observation.observed(str(body.get("version", ""))),
        "pve_version_major": Observation.observed(major),
        "pve_version_minor": Observation.observed(minor),
        # ``None`` when the target genuinely reported two parts — never a fabricated 0.
        "pve_version_patch": (
            Observation.observed(patch)
            if patch is not None
            else Observation.malformed("version_reported_without_a_patch_component")
        ),
        "pve_release": (
            Observation.observed(str(release))
            if isinstance(release, str)
            else Observation.malformed("release_absent_or_not_a_string")
        ),
        "pve_repoid": (
            Observation.observed(str(repoid))
            if isinstance(repoid, str)
            else Observation.malformed("repoid_absent_or_not_a_string")
        ),
    }


# --- cluster and nodes ----------------------------------------------------------------------------


def _parse_cluster_status(operation: object, payload: object) -> dict[str, Observation]:
    """``/cluster/status``. Identity comes from the cluster row; a standalone host has none, and
    saying so is different from failing to find one."""
    rows = _rows(payload, "cluster_status")
    if not rows:
        raise _MalformedPayload("cluster_status_empty")

    cluster = [r for r in rows if r.get("type") == "cluster"]
    nodes = [r for r in rows if r.get("type") == "node"]
    node_names = sorted(n for r in nodes if (n := _text(r, "name")))

    if cluster:
        row = cluster[0]
        identity: Observation = Observation.observed(
            {
                "kind": "cluster",
                "cluster_name": _text(row, "name") or "",
                "cluster_id": _text(row, "id") or "",
                "quorate": _truthy(row, "quorate"),
            }
        )
    elif len(nodes) == 1 and node_names:
        identity = Observation.observed({"kind": "standalone", "node": node_names[0]})
    else:
        identity = Observation.malformed("cluster_row_absent_with_multiple_node_rows")

    return {
        "cluster_identity": identity,
        "node_names": (
            Observation.observed(tuple(node_names))
            if node_names
            else Observation.malformed("cluster_status_named_no_nodes")
        ),
    }


def _parse_node_index(operation: object, payload: object) -> dict[str, Observation]:
    rows = _rows(payload, "node_index")
    if not rows:
        raise _MalformedPayload("node_index_empty")

    names = sorted(n for r in rows if (n := _text(r, "node")))
    online = {n: _text(r, "status") or "unknown" for r in rows if (n := _text(r, "node"))}
    if not names:
        raise _MalformedPayload("node_index_rows_named_no_node")
    return {
        "node_names": Observation.observed(tuple(names)),
        "node_online_state": Observation.observed(online),
    }


def _parse_node_status(operation: object, payload: object) -> dict[str, Observation]:
    node = operation.node  # type: ignore[attr-defined]
    body = _object(payload, "node_status")

    def _section(name: str) -> dict:
        value = body.get(name)
        return value if isinstance(value, dict) else {}

    cpuinfo, memory, rootfs = _section("cpuinfo"), _section("memory"), _section("rootfs")
    capacity = {
        "cpus": _integer(cpuinfo, "cpus"),
        "memory_total": _integer(memory, "total"),
        "memory_free": _integer(memory, "free"),
        "rootfs_total": _integer(rootfs, "total"),
        "rootfs_available": _integer(rootfs, "avail"),
    }

    kversion = _text(body, "kversion") or _text(body, "current-kernel")
    raw_manager = _text(body, "pveversion")
    normalised = _normalised_manager_version(raw_manager) if raw_manager else None

    return {
        # Every component must be present: a partial capacity reading that omits memory would let a
        # range be sized against CPU count alone.
        "node_capacity": (
            Observation.observed({node: capacity})
            if all(v is not None for v in capacity.values())
            else Observation.malformed("node_status_capacity_incomplete")
        ),
        "kernel_version": (
            Observation.observed({node: kversion})
            if kversion
            else Observation.malformed("node_status_reported_no_kernel_version")
        ),
        # Normalised so this agrees with /nodes/{node}/version instead of contradicting it.
        "node_versions": (
            Observation.observed({node: normalised})
            if normalised
            else Observation.malformed("node_status_manager_version_unrecognised")
        ),
    }


def _parse_node_version(operation: object, payload: object) -> dict[str, Observation]:
    node = operation.node  # type: ignore[attr-defined]
    body = _object(payload, "node_version")
    version = _text(body, "version")
    normalised = _normalised_manager_version(version) if version else None
    return {
        "node_versions": (
            Observation.observed({node: normalised})
            if normalised
            else Observation.malformed("node_version_unrecognised")
        )
    }


#: Which key of an apt entry names the INSTALLED version is UNVERIFIED against a live target from
#: this repository, so the parser records every version-bearing key rather than choosing one. A
#: wrong choice here would silently misreport the running release.
_APT_VERSION_KEYS = ("Version", "OldVersion", "CurrentState")


def _parse_node_package_inventory(operation: object, payload: object) -> dict[str, Observation]:
    node = operation.node  # type: ignore[attr-defined]
    rows = _rows(payload, "apt_versions")

    inventory: dict[str, dict[str, str]] = {}
    for row in rows:
        package = _text(row, "Package")
        if not package:
            continue
        present = {key: str(row[key]) for key in _APT_VERSION_KEYS if key in row}
        if present:
            inventory[package] = present
    if rows and not inventory:
        raise _MalformedPayload("apt_versions_shape_unrecognised")

    manager = inventory.get("pve-manager", {})
    candidates = {manager[k] for k in ("Version", "OldVersion") if k in manager}
    if len(candidates) == 1:
        build: Observation = Observation.observed({node: candidates.pop()})
    elif not candidates:
        build = Observation.malformed("pve_manager_absent_from_package_inventory")
    else:
        build = Observation.malformed("pve_manager_installed_version_ambiguous")

    return {
        "raw_host_package_version": Observation.observed({node: inventory}),
        "release_build_identifier": build,
    }


# --- network --------------------------------------------------------------------------------------

_BRIDGE_TYPES = frozenset({"bridge", "OVSBridge"})


def _parse_node_network(operation: object, payload: object) -> dict[str, Observation]:
    """``/nodes/{node}/network``.

    Two safe-direction choices are made here, both in the direction of refusing:

    * a bridge without ``bridge_vlan_aware`` is recorded as NOT VLAN-aware. Proxmox omits the key
      when it is unset, so absence really does mean unaware — and if that ever changed, the error
      would make SECP decline to place VLAN tags rather than place tags that are silently dropped
      and put every team on one flat segment;
    * ``management_cidrs`` and ``management_bridges`` are SUPERSETS: every configured CIDR on the
      node, and every bridge carrying one. Naming the one true management interface would need to
      know which address SECP reached the node on; a superset over-refuses a colliding lab subnet,
      which is the failure that does not take the target away with it.
    """
    node = operation.node  # type: ignore[attr-defined]
    rows = _rows(payload, "node_network")

    bridges: list[str] = []
    vlan_aware: dict[str, bool] = {}
    management_bridges: list[str] = []
    cidrs: list[str] = []

    for row in rows:
        iface = _text(row, "iface")
        if not iface:
            continue
        is_bridge = row.get("type") in _BRIDGE_TYPES
        if is_bridge:
            bridges.append(iface)
            vlan_aware[f"{node}/{iface}"] = _truthy(row, "bridge_vlan_aware")
        for key in ("cidr", "cidr6"):
            value = _text(row, key)
            if value:
                cidrs.append(value)
                if is_bridge:
                    management_bridges.append(iface)

    if rows and not bridges and not cidrs:
        raise _MalformedPayload("node_network_shape_unrecognised")

    return {
        "bridges": Observation.observed({node: tuple(sorted(set(bridges)))}),
        "bridge_vlan_awareness": Observation.observed(vlan_aware),
        "management_bridges": Observation.observed({node: tuple(sorted(set(management_bridges)))}),
        "management_cidrs": Observation.observed({node: tuple(sorted(set(cidrs)))}),
    }


# --- storage --------------------------------------------------------------------------------------


def _parse_node_storage(operation: object, payload: object) -> dict[str, Observation]:
    node = operation.node  # type: ignore[attr-defined]
    rows = _rows(payload, "node_storage")

    ids: list[str] = []
    types: dict[str, str] = {}
    content: dict[str, tuple[str, ...]] = {}
    capacity: dict[str, dict] = {}

    for row in rows:
        storage = _text(row, "storage")
        if not storage:
            continue
        key = f"{node}/{storage}"
        ids.append(storage)
        types[key] = _text(row, "type") or "unknown"
        raw_content = _text(row, "content") or ""
        content[key] = tuple(sorted(p for p in raw_content.split(",") if p))
        total, avail = _integer(row, "total"), _integer(row, "avail")
        # An inactive storage reports no numbers. Saying so explicitly beats a null that a consumer
        # could read as zero free space — or as unlimited.
        capacity[key] = (
            {"total": total, "available": avail}
            if total is not None and avail is not None
            else {"unreported": True}
        )

    if rows and not ids:
        raise _MalformedPayload("node_storage_shape_unrecognised")

    return {
        "storage_ids": Observation.observed({node: tuple(sorted(ids))}),
        "storage_types": Observation.observed(types),
        "allowed_storage_content": Observation.observed(content),
        "available_capacity": Observation.observed(capacity),
    }


def _parse_storage_content(operation: object, payload: object) -> dict[str, Observation]:
    node = operation.node  # type: ignore[attr-defined]
    storage = operation.storage  # type: ignore[attr-defined]
    rows = _rows(payload, "storage_content")
    key = f"{node}/{storage}"

    by_kind: dict[str, list[str]] = {"iso": [], "vztmpl": []}
    for row in rows:
        volid = _text(row, "volid")
        kind = _text(row, "content")
        if volid and kind in by_kind:
            by_kind[kind].append(volid)

    return {
        "iso_and_container_template_availability": Observation.observed(
            {key: {kind: tuple(sorted(volids)) for kind, volids in by_kind.items()}}
        )
    }


# --- guests ---------------------------------------------------------------------------------------


def _guest_index(rows: list[dict], *, kinds: frozenset[str], node_override: str | None) -> tuple:
    """Group guest rows into ``{node: (vmid, ...)}`` and ``{node: (template vmid, ...)}``."""
    ids: dict[str, list[int]] = {}
    templates: dict[str, list[int]] = {}
    for row in rows:
        if kinds and row.get("type") not in kinds:
            continue
        node = node_override or _text(row, "node")
        vmid = _integer(row, "vmid")
        if not node or vmid is None:
            continue
        ids.setdefault(node, []).append(vmid)
        if _truthy(row, "template"):
            templates.setdefault(node, []).append(vmid)
    return (
        {n: tuple(sorted(v)) for n, v in ids.items()},
        {n: tuple(sorted(v)) for n, v in templates.items()},
    )


def _parse_cluster_resources(operation: object, payload: object) -> dict[str, Observation]:
    rows = _rows(payload, "cluster_resources")
    ids, templates = _guest_index(rows, kinds=frozenset({"qemu"}), node_override=None)
    if rows and not ids:
        # Rows arrived and none was a recognisable qemu guest. An empty result here would read as
        # "this cluster has no VMs", which is exactly the claim that permits a VMID collision.
        raise _MalformedPayload("cluster_resources_shape_unrecognised")
    return {
        "existing_vm_ids": Observation.observed(ids),
        "templates": Observation.observed(templates),
    }


def _parse_node_qemu(operation: object, payload: object) -> dict[str, Observation]:
    node = operation.node  # type: ignore[attr-defined]
    rows = _rows(payload, "node_qemu")
    ids, templates = _guest_index(rows, kinds=frozenset(), node_override=node)
    if rows and not ids:
        raise _MalformedPayload("node_qemu_shape_unrecognised")
    # An empty index is a real answer for a node with no VMs, so the node key is present either way.
    return {
        "existing_vm_ids": Observation.observed(ids or {node: ()}),
        "templates": Observation.observed(templates or {node: ()}),
    }


def _parse_node_lxc(operation: object, payload: object) -> dict[str, Observation]:
    node = operation.node  # type: ignore[attr-defined]
    rows = _rows(payload, "node_lxc")
    ids, _templates = _guest_index(rows, kinds=frozenset(), node_override=node)
    if rows and not ids:
        raise _MalformedPayload("node_lxc_shape_unrecognised")
    return {"existing_lxc_ids": Observation.observed(ids or {node: ()})}


# --- firewall -------------------------------------------------------------------------------------


def _parse_cluster_firewall_options(operation: object, payload: object) -> dict[str, Observation]:
    body = _object(payload, "cluster_firewall_options")
    return {
        "firewall_capability": Observation.observed(
            {"cluster_options": {"enable": _truthy(body, "enable")}}
        )
    }


def _parse_cluster_firewall_groups(operation: object, payload: object) -> dict[str, Observation]:
    rows = _rows(payload, "cluster_firewall_groups")
    groups = sorted(g for row in rows if (g := _text(row, "group")))
    if rows and not groups:
        raise _MalformedPayload("cluster_firewall_groups_shape_unrecognised")
    return {"firewall_capability": Observation.observed({"security_groups": tuple(groups)})}


# --- SDN ------------------------------------------------------------------------------------------


def _parse_sdn_root(operation: object, payload: object) -> dict[str, Observation]:
    """``/cluster/sdn``. Declared ``check => ['perm','/sdn',['SDN.Audit']]``, so it cannot answer
    200-with-empty for a permission reason. Reaching this parser at all means the target returned a
    success, and that is the ONLY thing that licenses reading an empty SDN index as absence."""
    _rows(payload, "sdn_root")
    return {"sdn_read_authority": Observation.observed({"cluster_sdn_readable": True})}


def _parse_effective_permissions(operation: object, payload: object) -> dict[str, Observation]:
    body = _object(payload, "effective_permissions")
    granted = False
    for path in ("/sdn", "/"):
        entry = body.get(path)
        if isinstance(entry, dict) and _truthy(entry, "SDN.Audit"):
            granted = True
            break
    return {"sdn_read_authority": Observation.observed({"sdn_audit_granted": granted})}


def _pending(family: str, payload: object) -> tuple[dict, ...]:
    try:
        return parse_pending_objects(family, payload)
    except ValueError as exc:
        raise _MalformedPayload(str(exc.args[0])) from None


def _parse_sdn_zones(operation: object, payload: object) -> dict[str, Observation]:
    rows = _rows(payload, "sdn_zones")
    zones = {z: {"cluster_index": row} for row in rows if (z := _text(row, "zone"))}
    if rows and not zones:
        raise _MalformedPayload("sdn_zones_shape_unrecognised")
    # Only some zone types carry a service tag; an empty mapping here means the zones were read and
    # none declared one, which is a real observation rather than a gap.
    vlan_use = {
        f"zone:{z}": tag
        for row in rows
        if (z := _text(row, "zone")) and (tag := _integer(row, "tag")) is not None
    }
    return {
        "existing_sdn_zones": Observation.observed(zones),
        "pending_sdn_state": Observation.observed({"zones": _pending("zones", payload)}),
        "existing_vlan_use": Observation.observed(vlan_use),
    }


def _parse_sdn_vnets(operation: object, payload: object) -> dict[str, Observation]:
    rows = _rows(payload, "sdn_vnets")
    vnets = {v: {"cluster_index": row} for row in rows if (v := _text(row, "vnet"))}
    if rows and not vnets:
        raise _MalformedPayload("sdn_vnets_shape_unrecognised")
    vlan_use = {
        f"vnet:{v}": tag
        for row in rows
        if (v := _text(row, "vnet")) and (tag := _integer(row, "tag")) is not None
    }
    return {
        "existing_vnets": Observation.observed(vnets),
        "pending_sdn_state": Observation.observed({"vnets": _pending("vnets", payload)}),
        "existing_vlan_use": Observation.observed(vlan_use),
    }


def _parse_sdn_subnets(operation: object, payload: object) -> dict[str, Observation]:
    vnet = operation.vnet  # type: ignore[attr-defined]
    rows = _rows(payload, "sdn_subnets")
    subnets = {s: {"cluster_index": row} for row in rows if (s := _text(row, "subnet"))}
    if rows and not subnets:
        raise _MalformedPayload("sdn_subnets_shape_unrecognised")
    return {
        "existing_subnets": Observation.observed(subnets),
        # Keyed per vnet: there is no cluster-wide subnet index, so completeness is a property of
        # having enumerated EVERY vnet, and a single "subnets" key would let one vnet's answer stand
        # in for all of them.
        "pending_sdn_state": Observation.observed(
            {f"subnets@{vnet}": _pending("subnets", payload)}
        ),
    }


def _parse_sdn_controllers(operation: object, payload: object) -> dict[str, Observation]:
    return {
        "pending_sdn_state": Observation.observed({"controllers": _pending("controllers", payload)})
    }


def _parse_sdn_fabrics(operation: object, payload: object) -> dict[str, Observation]:
    return {"pending_sdn_state": Observation.observed({"fabrics": _pending("fabrics", payload)})}


def _parse_sdn_ipam_status(operation: object, payload: object) -> dict[str, Observation]:
    rows = _rows(payload, "sdn_ipam_status")
    allocations: dict[str, dict] = {}
    for row in rows:
        subnet = _text(row, "subnet")
        ip = _text(row, "ip")
        if not subnet or not ip:
            continue
        allocations.setdefault(subnet, {"ipam": {}})["ipam"][ip] = {
            "vnet": _text(row, "vnet") or "",
            "zone": _text(row, "zone") or "",
        }
    if rows and not allocations:
        raise _MalformedPayload("sdn_ipam_status_shape_unrecognised")
    return {"existing_subnets": Observation.observed(allocations)}


def _parse_node_sdn_zones(operation: object, payload: object) -> dict[str, Observation]:
    """The unfiltered side of the partial-visibility differential: this handler documents an
    ``SDN.Audit`` filter it does not implement, so a zone visible here and absent from the cluster
    index proves per-object filtering rather than absence."""
    node = operation.node  # type: ignore[attr-defined]
    rows = _rows(payload, "node_sdn_zones")
    zones = {
        z: {"node_runtime": {node: _text(row, "status") or "unknown"}}
        for row in rows
        if (z := _text(row, "zone"))
    }
    if rows and not zones:
        raise _MalformedPayload("node_sdn_zones_shape_unrecognised")
    return {"existing_sdn_zones": Observation.observed(zones)}


def _parse_node_sdn_bridges(operation: object, payload: object) -> dict[str, Observation]:
    """PVE 9.1+ only, and added days before the 9.1 release. Because the exact row shape is not
    pinned from a live target here, an unrecognised non-empty payload is reported as malformed
    rather than parsed into an empty result that would read as "no VLANs are materialised"."""
    node = operation.node  # type: ignore[attr-defined]
    rows = _rows(payload, "node_sdn_bridges")

    awareness: dict[str, bool] = {}
    vlan_use: dict[str, int] = {}
    for row in rows:
        bridge = _text(row, "bridge") or _text(row, "name")
        if not bridge:
            continue
        tag = _integer(row, "vlan")
        if tag is None:
            tag = _integer(row, "tag")
        if tag is not None:
            # A bridge materialising a VLAN is VLAN-aware by observation, not by inference.
            awareness[f"{node}/{bridge}"] = True
            vlan_use[f"bridge:{node}/{bridge}/{tag}"] = tag
    if rows and not awareness and not vlan_use:
        raise _MalformedPayload("node_sdn_bridges_shape_unrecognised")

    return {
        "bridge_vlan_awareness": Observation.observed(awareness),
        "existing_vlan_use": Observation.observed(vlan_use),
    }


# --- dispatch -------------------------------------------------------------------------------------

_PARSERS: dict[str, Callable[[object, object], dict[str, Observation]]] = {
    GetVersionOperation.operation_code: _parse_api_version,
    GetClusterStatusOperation.operation_code: _parse_cluster_status,
    GetNodesOperation.operation_code: _parse_node_index,
    GetNodeStatusOperation.operation_code: _parse_node_status,
    GetNodeVersionOperation.operation_code: _parse_node_version,
    GetNodeAptVersionsOperation.operation_code: _parse_node_package_inventory,
    GetNodeNetworkOperation.operation_code: _parse_node_network,
    GetNodeStorageOperation.operation_code: _parse_node_storage,
    GetStorageContentOperation.operation_code: _parse_storage_content,
    GetClusterResourcesOperation.operation_code: _parse_cluster_resources,
    GetNodeQemuOperation.operation_code: _parse_node_qemu,
    GetNodeLxcOperation.operation_code: _parse_node_lxc,
    GetClusterFirewallOptionsOperation.operation_code: _parse_cluster_firewall_options,
    GetClusterFirewallGroupsOperation.operation_code: _parse_cluster_firewall_groups,
    GetSdnRootOperation.operation_code: _parse_sdn_root,
    GetEffectivePermissionsOperation.operation_code: _parse_effective_permissions,
    GetSdnZonesOperation.operation_code: _parse_sdn_zones,
    GetSdnVnetsOperation.operation_code: _parse_sdn_vnets,
    GetSdnSubnetsOperation.operation_code: _parse_sdn_subnets,
    GetSdnControllersOperation.operation_code: _parse_sdn_controllers,
    GetSdnIpamStatusOperation.operation_code: _parse_sdn_ipam_status,
    GetSdnFabricsOperation.operation_code: _parse_sdn_fabrics,
    GetNodeSdnZonesOperation.operation_code: _parse_node_sdn_zones,
    GetNodeSdnBridgesOperation.operation_code: _parse_node_sdn_bridges,
}


def observe(operation: object, payload: object) -> dict[str, Observation]:
    """Turn one operation's payload into exactly the fields that operation declares.

    The returned key set is checked against ``observation_field_codes`` rather than trusted. A
    parser that skipped a field would leave it absent from the snapshot entirely — which the
    required-fact evaluator reads as "not observed", but with no state and no reason to show an
    operator. A parser that invented one would put a fact into a signed document that no evidence
    record claims to have produced.
    """
    code = getattr(operation, "operation_code", "")
    parser = _PARSERS.get(code)
    if parser is None:
        raise ProjectionError(f"no_parser_for_operation:{code or 'unknown'}")

    declared = set(operation.observation_field_codes)  # type: ignore[attr-defined]
    try:
        produced = parser(operation, payload)
    except _MalformedPayload as exc:
        return {field: Observation.malformed(str(exc.args[0])) for field in declared}

    if set(produced) != declared:
        raise ProjectionError(
            f"parser_field_mismatch:{code}:"
            f"missing={sorted(declared - set(produced))}:"
            f"unexpected={sorted(set(produced) - declared)}"
        )
    return produced
