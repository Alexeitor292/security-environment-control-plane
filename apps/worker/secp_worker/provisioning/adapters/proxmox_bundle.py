"""The reviewed Proxmox module bundle — deterministic, secret-free HCL. Worker-only.

Renders a compiled desired state (see :mod:`secp_api.range_providers.proxmox_manifest`) into the
workspace the pinned OpenTofu executable plans against. It is a RENDERER only: it opens no socket,
starts no process, imports no provider SDK, and contacts no Proxmox. Execution belongs to the
existing :class:`~secp_worker.provisioning.opentofu.OpenTofuRunner`; this module deliberately adds
no second runner.

THE BUNDLE AND THE PROFILE MUST AGREE ON THE PROVIDER
------------------------------------------------------
This bundle declares the provider it was reviewed against in :data:`PROVIDER_SOURCE` /
:data:`PROVIDER_VERSION`, and the profile pins the same two values plus a checksum. Neither is
redundant, because they are facts about different things: the bundle's constants are what this HCL
was *written and reviewed* for, and the profile's pins are what the control plane *authorized this
operation to install*. :func:`render_bundle` refuses when they disagree.

That refusal is the seam that would otherwise stay open. Rendering against a profile pinning a
different provider version produces HCL requiring one version while the authorized mirror artifact
is another; ``tofu init`` would then either fail late, at the point where the operator has already
approved a change set, or succeed against whichever artifact the mirror happened to hold. Checking
at render time makes the disagreement a refusal before anything is hashed or approved.

The source is written in its registry-less short form. The offline mirror is enforced by the
runner's CLI flags, exactly as the pre-existing renderer documents; embedding a registry hostname
here would put a real endpoint in a generated artifact for no benefit.

DETERMINISM IS THE POINT
-------------------------
Identical desired state plus identical discovery must produce byte-identical HCL, because the
canonical change-set hash derived downstream is what an operator approves. Every collection is
rendered in an explicit sort order, no timestamp or hostname is interpolated, and nothing is
derived from dict iteration order. The manifest payload is already ordered at the boundary; this
module does not rely on that and sorts again, because a renderer that trusts its input's ordering
breaks the moment the input is hand-edited or round-tripped through a store that does not preserve
order.

SECRETS NEVER ENTER
--------------------
The provider endpoint and API token appear ONLY as input variables with no defaults and no values.
They are injected just-in-time in the worker at apply and are never written into HCL, a variable
file persisted as evidence, the plan document, the canonical change set, a database row, an API
response, an audit event, or a log. There is no code path here that can accept a credential.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from secp_worker.provisioning.adapters.base import AdapterError

#: This bundle's reviewed identity. A toolchain profile must pin exactly this, or rendering is
#: refused — the same fail-closed posture the renderer already applies to ``renderer_version``.
BUNDLE_ID = "secp-proxmox-range/bundle/v1"

#: The provider this reviewed bundle targets, pinned to an exact version, in BOTH the forms that
#: exist for it. They are not interchangeable and neither is derived from the other here:
#:
#: * :data:`PROVIDER_SOURCE` is what goes into ``required_providers`` — the registry-less short form
#:   HCL uses. Rendering the fully-qualified address instead would put a registry hostname into a
#:   generated artifact for no benefit, since resolution comes from the pinned offline mirror.
#: * :data:`PROVIDER_ADDRESS` is what OpenTofu expands that to and records in the dependency
#:   lockfile. It is the form the toolchain profile pins and the form every comparison downstream
#:   uses, so that no step in the chain needs a rule for relating one form to the other.
PROVIDER_SOURCE = "bpg/proxmox"
PROVIDER_ADDRESS = "registry.opentofu.org/bpg/proxmox"
PROVIDER_VERSION = "0.66.1"
#: The local name the bundle refers to the provider by.
PROVIDER_LOCAL_NAME = "proxmox"

#: Resource type names for the pinned provider, gathered in ONE table on purpose.
#:
#: These are modelled from the provider's documented schema. This bundle is rendered and hashed
#: without provider access — nothing here has been checked against the provider's real schema,
#: because doing so requires the pinned mirror, and no such verification has run. A reviewer with
#: the mirror available corrects this table in one place, and ``tofu validate`` against the pinned
#: provider is what settles it. Until that has happened the plan document reports the schema as
#: unverified rather than implying a check that never occurred.
RESOURCE_TYPES = {
    "sdn_zone": "proxmox_virtual_environment_sdn_zone_vlan",
    "sdn_vnet": "proxmox_virtual_environment_sdn_vnet",
    "sdn_subnet": "proxmox_virtual_environment_sdn_subnet",
    "security_group": "proxmox_virtual_environment_cluster_firewall_security_group",
    "ipset": "proxmox_virtual_environment_firewall_ipset",
    "qemu_guest": "proxmox_virtual_environment_vm",
    "lxc_guest": "proxmox_virtual_environment_container",
}

_HEADER = "# GENERATED by {bundle} — do not edit. Deterministic and secret-free.\n"
_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9_]")


def _label(value: str) -> str:
    """An HCL resource label. Deterministic, and never empty."""
    cleaned = _LABEL_UNSAFE.sub("_", value)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = f"r_{cleaned}"
    return cleaned


def _s(value: object) -> str:
    """An HCL string literal with the two escapes that matter."""
    text = "" if value is None else str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _list(values: Iterable[object]) -> str:
    return "[" + ", ".join(_s(v) for v in values) + "]"


def _ownership_comment(ownership: dict) -> str:
    """The ownership stamp as a single deterministic line.

    This is what makes a later destroy ownership-bounded: the tag travels onto the object, and
    ``is_owned_by_secp`` reads it back. A name match is never treated as proof, so an object
    missing this stamp is one SECP will refuse to touch.
    """
    tags = ownership.get("tags") or {}
    return " ".join(f"{key}={tags[key]}" for key in sorted(tags))


def _ownership_tag_list(ownership: dict) -> list[str]:
    """Ownership as provider ``tags``. Proxmox tags are lowercase and separator-restricted."""
    tags = ownership.get("tags") or {}
    rendered = [f"{key}={tags[key]}" for key in sorted(tags)]
    return [re.sub(r"[^a-z0-9_.=-]", "-", item.lower()) for item in rendered]


def _prefix_len(cidr: str) -> int:
    return ipaddress.ip_network(cidr, strict=True).prefixlen


def render_bundle(desired_state: dict, profile: dict) -> dict[str, str]:
    """Render the full module bundle. Returns ``{relative_path: content}``.

    Raises :class:`AdapterError` on anything it cannot render faithfully — a partially rendered
    workspace would plan a partially isolated lab, which is worse than not planning at all.
    """
    if not isinstance(desired_state, dict):
        raise AdapterError("desired state payload must be an object")

    declared_bundle = str(profile.get("module_bundle_id", ""))
    if declared_bundle != BUNDLE_ID:
        raise AdapterError(
            f"toolchain profile pins module bundle {declared_bundle!r} but this renderer is "
            f"{BUNDLE_ID!r}; regenerate the plan with a matching profile"
        )

    opentofu_version = str(profile.get("opentofu_version", ""))
    if not opentofu_version:
        raise AdapterError("toolchain profile does not pin an OpenTofu version")

    # The profile's provider pins must be THIS bundle's provider. A missing pin is refused rather
    # than defaulted to the bundle's own constant: defaulting would make the check pass by
    # supplying the very value it was meant to compare against.
    for field, expected in (
        # The profile pins the lockfile form, so it is compared to PROVIDER_ADDRESS rather than to
        # the short form this bundle renders into HCL.
        ("provider_source", PROVIDER_ADDRESS),
        ("provider_version", PROVIDER_VERSION),
    ):
        declared = str(profile.get(field, ""))
        if declared != expected:
            raise AdapterError(
                f"toolchain profile pins {field} {declared!r} but this reviewed bundle "
                f"targets {expected!r}; regenerate the plan with a matching profile"
            )

    network = desired_state.get("network")
    if not isinstance(network, dict):
        raise AdapterError("desired state has no network section")
    zone = network.get("zone")
    if not isinstance(zone, dict):
        raise AdapterError("desired state has no SDN zone")
    vnets = sorted(network.get("vnets", []), key=lambda v: str(v["name"]))
    if not vnets:
        raise AdapterError("desired state declares no network segments")
    guests = sorted(desired_state.get("guests", []), key=lambda g: str(g["guest_ref"]))

    header = _HEADER.format(bundle=BUNDLE_ID)
    files: dict[str, str] = {
        "versions.tf": _render_versions(header, opentofu_version),
        "variables.tf": _render_variables(header),
        "provider.tf": _render_provider(header),
        "network_foundation.tf": _render_zone(header, zone),
        "network_range.tf": _render_vnets(header, vnets),
        "network_segments.tf": _render_segments(header, vnets),
        "firewall.tf": _render_firewall(header, network),
        "outputs.tf": _render_outputs(header, zone, vnets, guests),
    }

    qemu = [g for g in guests if g.get("kind") == "qemu"]
    lxc = [g for g in guests if g.get("kind") == "lxc"]
    if not qemu and not lxc:
        raise AdapterError("desired state declares no guests")
    # QEMU is the required guest kind and always gets a file, even when empty, so the bundle's
    # file set does not change shape based on content.
    files["guests_qemu.tf"] = _render_qemu_guests(header, qemu, vnets)
    if lxc:
        # LXC is optional: the file appears only when the desired state actually contains one.
        files["guests_lxc.tf"] = _render_lxc_guests(header, lxc, vnets)

    return files


def _render_versions(header: str, opentofu_version: str) -> str:
    return (
        header + "terraform {\n"
        f'  required_version = "= {opentofu_version}"\n'
        "  required_providers {\n"
        f"    {PROVIDER_LOCAL_NAME} = {{\n"
        f"      source  = {_s(PROVIDER_SOURCE)}\n"
        f'      version = "= {PROVIDER_VERSION}"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )


def _render_variables(header: str) -> str:
    """Endpoint and token as declared inputs with NO defaults and NO values."""
    return (
        header + "# Injected just-in-time in the worker at apply. Never persisted, never hashed,\n"
        "# never logged, and never written into any rendered file.\n"
        'variable "pm_endpoint" {\n'
        "  type        = string\n"
        '  description = "Proxmox API endpoint; supplied at apply time only."\n'
        "}\n\n"
        'variable "pm_api_token" {\n'
        "  type        = string\n"
        "  sensitive   = true\n"
        '  description = "Proxmox API token; supplied at apply time only."\n'
        "}\n"
    )


def _render_provider(header: str) -> str:
    return (
        header + f'provider "{PROVIDER_LOCAL_NAME}" {{\n'
        "  endpoint = var.pm_endpoint\n"
        "  api_token = var.pm_api_token\n"
        "  insecure = false\n"
        "}\n"
    )


def _render_zone(header: str, zone: dict) -> str:
    """The SDN zone: the network foundation every scenario segment hangs off."""
    label = _label(str(zone["name"]))
    body = [
        header,
        "# The scenario SDN zone. Its bridge is chosen by the compiler from bridges observed on\n"
        "# every online node, EXCLUDING declared management bridges, so the zone can never ride\n"
        "# the management plane.\n",
        f'resource "{RESOURCE_TYPES["sdn_zone"]}" "{label}" {{\n',
        f"  id     = {_s(zone['name'])}\n",
        f"  nodes  = {_list(sorted(zone.get('nodes', [])))}\n",
        f"  bridge = {_s(zone['bridge'])}\n",
    ]
    if zone.get("mtu") is not None:
        body.append(f"  mtu    = {int(zone['mtu'])}\n")
    body.append(f"  # {_ownership_comment(zone.get('ownership', {}))}\n")
    body.append("}\n")
    return "".join(body)


def _render_vnets(header: str, vnets: list[dict]) -> str:
    """Per-range network: one VNet + one subnet per segment."""
    parts = [
        header,
        "# One VNet per segment, each carrying its own VLAN tag, and one subnet per VNet.\n"
        "# Subnets are unrouted by default: SECP provides no gateway off-segment unless an\n"
        "# approved plan explicitly asked for egress.\n\n",
    ]
    for vnet in vnets:
        label = _label(str(vnet["name"]))
        subnet = vnet["subnet"]
        parts.append(f'resource "{RESOURCE_TYPES["sdn_vnet"]}" "{label}" {{\n')
        parts.append(f"  id   = {_s(vnet['name'])}\n")
        parts.append(f"  zone = {_s(vnet['zone_name'])}\n")
        parts.append(f"  tag  = {int(vnet['vlan_tag'])}\n")
        if vnet.get("alias"):
            parts.append(f"  alias = {_s(vnet['alias'])}\n")
        parts.append(f"  # {_ownership_comment(vnet.get('ownership', {}))}\n")
        parts.append("}\n\n")

        parts.append(f'resource "{RESOURCE_TYPES["sdn_subnet"]}" "{label}" {{\n')
        parts.append(f"  vnet = {RESOURCE_TYPES['sdn_vnet']}.{label}.id\n")
        parts.append(f"  cidr = {_s(subnet['cidr'])}\n")
        parts.append(f"  gateway = {_s(subnet['gateway'])}\n")
        # SNAT stays off unless the segment is routed. A NAT'd segment has a path off-net, which
        # is precisely what the default-deny posture exists to prevent.
        parts.append(f"  snat = {'true' if subnet.get('routed') else 'false'}\n")
        parts.append("}\n\n")
    return "".join(parts)


def _render_segments(header: str, vnets: list[dict]) -> str:
    """Per-team segment index, rendered as locals for outputs and review.

    Emitted as data rather than resources: the segments themselves ARE the VNets above. This file
    exists so a reviewer can see the team-to-segment mapping in one place instead of reconstructing
    it from ownership comments scattered across resources.
    """
    by_team: dict[str, list[dict]] = {}
    for vnet in vnets:
        team = vnet.get("ownership", {}).get("team_ref") or "_shared"
        by_team.setdefault(team, []).append(vnet)

    parts = [header, "locals {\n  secp_segments = {\n"]
    for team in sorted(by_team):
        parts.append(f"    {_label(team)} = {{\n")
        for vnet in sorted(by_team[team], key=lambda v: str(v["name"])):
            parts.append(
                f"      {_label(str(vnet['role']))} = {{ "
                f"vnet = {_s(vnet['name'])}, "
                f"vlan = {int(vnet['vlan_tag'])}, "
                f"cidr = {_s(vnet['subnet']['cidr'])} }}\n"
            )
        parts.append("    }\n")
    parts.append("  }\n}\n")
    return "".join(parts)


def _render_firewall(header: str, network: dict) -> str:
    """IPSets and ordered security groups — the isolation itself."""
    parts = [
        header,
        "# Default deny with explicit allows. Rule ORDER is significant and is preserved exactly\n"
        "# as the compiler emitted it: every deny precedes every allow, and the compiled order is\n"
        "# what the isolation verifier evaluated. Reordering them invalidates that proof.\n\n",
    ]

    for ip_set in sorted(network.get("ip_sets", []), key=lambda i: str(i["name"])):
        label = _label(str(ip_set["name"]))
        parts.append(f'resource "{RESOURCE_TYPES["ipset"]}" "{label}" {{\n')
        parts.append(f"  name    = {_s(ip_set['name'])}\n")
        comment = ip_set.get("comment") or ""
        stamp = _ownership_comment(ip_set.get("ownership", {}))
        parts.append(f"  comment = {_s(f'{comment} [{stamp}]'.strip())}\n")
        for cidr in sorted(ip_set.get("cidrs", [])):
            parts.append("  cidr {\n")
            parts.append(f"    name = {_s(cidr)}\n")
            parts.append("  }\n")
        parts.append("}\n\n")

    for group in sorted(network.get("security_groups", []), key=lambda g: str(g["name"])):
        label = _label(str(group["name"]))
        parts.append(f'resource "{RESOURCE_TYPES["security_group"]}" "{label}" {{\n')
        parts.append(f"  name    = {_s(group['name'])}\n")
        comment = group.get("comment") or ""
        stamp = _ownership_comment(group.get("ownership", {}))
        parts.append(f"  comment = {_s(f'{comment} [{stamp}]'.strip())}\n")
        # Sorted by position: the same precedence the compiler verified.
        for rule in sorted(group.get("rules", []), key=lambda r: int(r["position"])):
            parts.append("\n  rule {\n")
            parts.append(f"    type    = {_s(str(rule['direction']).lower())}\n")
            parts.append(f"    action  = {_s(rule['verdict'])}\n")
            parts.append(f"    comment = {_s(rule['comment'])}\n")
            if rule.get("source"):
                parts.append(f"    source  = {_s(rule['source'])}\n")
            if rule.get("dest"):
                parts.append(f"    dest    = {_s(rule['dest'])}\n")
            if rule.get("proto"):
                parts.append(f"    proto   = {_s(rule['proto'])}\n")
            if rule.get("dport"):
                parts.append(f"    dport   = {_s(rule['dport'])}\n")
            parts.append(f"    enabled = {'true' if rule.get('enabled', True) else 'false'}\n")
            parts.append("  }\n")
        parts.append("}\n\n")
    return "".join(parts)


def _vnet_index(vnets: list[dict]) -> dict[str, dict]:
    return {str(vnet["name"]): vnet for vnet in vnets}


def _render_network_devices(guest: dict, index: dict[str, dict]) -> list[str]:
    """NIC blocks. The VNet carries the VLAN tag, so the device must NOT tag again.

    Setting ``vlan_id`` here in addition to the VNet's tag double-tags the frame and silently
    breaks the segment. The tag lives in exactly one place.
    """
    lines: list[str] = []
    for nic in sorted(guest.get("nics", []), key=lambda n: int(n["index"])):
        vnet_name = str(nic["vnet_name"])
        if vnet_name not in index:
            raise AdapterError(
                f"guest {guest.get('guest_ref')!r} attaches to unknown segment {vnet_name!r}"
            )
        lines.append("  network_device {\n")
        lines.append(f"    bridge      = {_s(vnet_name)}\n")
        lines.append(f"    mac_address = {_s(nic['mac_address'])}\n")
        lines.append(f"    model       = {_s(nic.get('model', 'virtio'))}\n")
        lines.append(f"    firewall    = {'true' if nic.get('firewall', True) else 'false'}\n")
        lines.append("  }\n")
    return lines


def _render_qemu_guests(header: str, guests: list[dict], vnets: list[dict]) -> str:
    """QEMU guests, with storage, disks and cloud-init. The required guest kind."""
    index = _vnet_index(vnets)
    parts = [header]
    if not guests:
        parts.append("# No QEMU guests in this desired state.\n")
        return "".join(parts)

    for guest in guests:
        label = _label(str(guest["guest_ref"]))
        parts.append(f'resource "{RESOURCE_TYPES["qemu_guest"]}" "{label}" {{\n')
        parts.append(f"  name      = {_s(guest['name'])}\n")
        parts.append(f"  vm_id     = {int(guest['vmid'])}\n")
        parts.append(f"  node_name = {_s(guest['node_name'])}\n")
        parts.append(f"  started   = {'true' if guest.get('start_on_deploy', True) else 'false'}\n")
        parts.append(f"  tags      = {_list(_ownership_tag_list(guest.get('ownership', {})))}\n")
        parts.append(f"  description = {_s(_ownership_comment(guest.get('ownership', {})))}\n")

        parts.append("\n  clone {\n")
        parts.append(f"    vm_id = {_s(guest['template_ref'])}\n")
        # full = true survives template churn; a linked clone dies with its template.
        parts.append(f"    full  = {'true' if guest['clone_strategy'] == 'full' else 'false'}\n")
        parts.append("  }\n")

        parts.append("\n  cpu {\n")
        parts.append(f"    cores = {int(guest['cpu_cores'])}\n")
        parts.append("  }\n")
        parts.append("\n  memory {\n")
        parts.append(f"    dedicated = {int(guest['memory_mb'])}\n")
        parts.append("  }\n")

        parts.append("\n")
        for disk in sorted(guest.get("disks", []), key=lambda d: str(d["slot"])):
            parts.append("  disk {\n")
            parts.append(f"    interface    = {_s(disk['slot'])}\n")
            parts.append(f"    datastore_id = {_s(disk['storage_id'])}\n")
            parts.append(f"    size         = {int(disk['size_gb'])}\n")
            parts.append(
                f"    discard      = {_s('on' if disk.get('discard', True) else 'ignore')}\n"
            )
            parts.append(f"    ssd          = {'true' if disk.get('ssd_emulation') else 'false'}\n")
            parts.append("  }\n")

        parts.append("\n")
        parts.extend(_render_network_devices(guest, index))

        cloud_init = guest.get("cloud_init")
        if cloud_init:
            parts.append("\n")
            parts.extend(_render_cloud_init(guest, cloud_init, index))

        parts.append("}\n\n")
    return "".join(parts)


def _render_cloud_init(guest: dict, cloud_init: dict, index: dict[str, dict]) -> list[str]:
    """Cloud-init: public keys only, and a gateway only where the segment is actually routed."""
    keys = list(cloud_init.get("ssh_authorized_keys", []))
    for key in keys:
        if "PRIVATE KEY" in key:
            raise AdapterError("cloud-init received private key material")

    first_nic = min(guest.get("nics", []), key=lambda n: int(n["index"]), default=None)
    if first_nic is None:
        raise AdapterError(f"guest {guest.get('guest_ref')!r} has no NIC to address")
    vnet = index[str(first_nic["vnet_name"])]
    subnet = vnet["subnet"]
    address = f"{guest['address']['published_address']}/{_prefix_len(str(subnet['cidr']))}"

    lines = ["  initialization {\n"]
    if cloud_init.get("search_domain"):
        lines.append(f"    dns {{\n      domain = {_s(cloud_init['search_domain'])}\n")
        if cloud_init.get("nameservers"):
            lines.append(f"      servers = {_list(cloud_init['nameservers'])}\n")
        lines.append("    }\n")
    elif cloud_init.get("nameservers"):
        lines.append(f"    dns {{\n      servers = {_list(cloud_init['nameservers'])}\n    }}\n")

    lines.append("    ip_config {\n      ipv4 {\n")
    lines.append(f"        address = {_s(address)}\n")
    # A gateway is written ONLY when the compiler marked the segment routed. Writing one on an
    # unrouted segment would advertise a path that does not exist.
    if subnet.get("routed") and cloud_init.get("gateway"):
        lines.append(f"        gateway = {_s(cloud_init['gateway'])}\n")
    lines.append("      }\n    }\n")

    lines.append("    user_account {\n")
    lines.append(f"      username = {_s(cloud_init['user'])}\n")
    lines.append(f"      keys     = {_list(sorted(keys))}\n")
    lines.append("    }\n")
    lines.append("  }\n")
    return lines


def _render_lxc_guests(header: str, guests: list[dict], vnets: list[dict]) -> str:
    """LXC guests — optional, rendered only when the desired state contains one."""
    index = _vnet_index(vnets)
    parts = [header]
    for guest in guests:
        label = _label(str(guest["guest_ref"]))
        parts.append(f'resource "{RESOURCE_TYPES["lxc_guest"]}" "{label}" {{\n')
        parts.append(f"  vm_id     = {int(guest['vmid'])}\n")
        parts.append(f"  node_name = {_s(guest['node_name'])}\n")
        parts.append(f"  started   = {'true' if guest.get('start_on_deploy', True) else 'false'}\n")
        parts.append(f"  tags      = {_list(_ownership_tag_list(guest.get('ownership', {})))}\n")
        parts.append("\n  clone {\n")
        parts.append(f"    vm_id = {_s(guest['template_ref'])}\n")
        parts.append("  }\n")
        parts.append("\n  cpu {\n")
        parts.append(f"    cores = {int(guest['cpu_cores'])}\n")
        parts.append("  }\n")
        parts.append("\n  memory {\n")
        parts.append(f"    dedicated = {int(guest['memory_mb'])}\n")
        parts.append("  }\n")
        for disk in sorted(guest.get("disks", []), key=lambda d: str(d["slot"])):
            parts.append("\n  disk {\n")
            parts.append(f"    datastore_id = {_s(disk['storage_id'])}\n")
            parts.append(f"    size         = {int(disk['size_gb'])}\n")
            parts.append("  }\n")
        parts.append("\n")
        for nic in sorted(guest.get("nics", []), key=lambda n: int(n["index"])):
            vnet_name = str(nic["vnet_name"])
            if vnet_name not in index:
                raise AdapterError(
                    f"guest {guest.get('guest_ref')!r} attaches to unknown segment {vnet_name!r}"
                )
            parts.append("  network_interface {\n")
            parts.append(f"    name        = {_s('eth' + str(nic['index']))}\n")
            parts.append(f"    bridge      = {_s(vnet_name)}\n")
            parts.append(f"    mac_address = {_s(nic['mac_address'])}\n")
            parts.append(f"    firewall    = {'true' if nic.get('firewall', True) else 'false'}\n")
            parts.append("  }\n")
        parts.append("}\n\n")
    return "".join(parts)


def _render_outputs(header: str, zone: dict, vnets: list[dict], guests: list[dict]) -> str:
    """Outputs and observations.

    ``published_addresses`` and ``probe_addresses`` are SEPARATE outputs with no fallback between
    them. Collapsing them into one would let a readiness check probe the address it published and
    report success without proving reachability.
    """
    parts = [
        header,
        f'output "secp_zone" {{\n  value = {_s(zone["name"])}\n}}\n\n',
        'output "secp_segments" {\n  value = local.secp_segments\n}\n\n',
    ]
    published = {
        str(g["guest_ref"]): str(g["address"]["published_address"])
        for g in guests
        if g.get("address", {}).get("published_address")
    }
    probe = {
        str(g["guest_ref"]): str(g["address"]["probe_address"])
        for g in guests
        if g.get("address", {}).get("probe_address")
    }
    parts.append('output "secp_published_addresses" {\n  value = {\n')
    for ref in sorted(published):
        parts.append(f"    {_label(ref)} = {_s(published[ref])}\n")
    parts.append("  }\n}\n\n")

    parts.append(
        "# Probe addresses are deliberately a separate output. A guest with no probe address\n"
        "# appears in NEITHER map rather than falling back to its published address.\n"
    )
    parts.append('output "secp_probe_addresses" {\n  value = {\n')
    for ref in sorted(probe):
        parts.append(f"    {_label(ref)} = {_s(probe[ref])}\n")
    parts.append("  }\n}\n\n")

    parts.append('output "secp_guest_ids" {\n  value = {\n')
    for guest in sorted(guests, key=lambda g: str(g["guest_ref"])):
        parts.append(f"    {_label(str(guest['guest_ref']))} = {int(guest['vmid'])}\n")
    parts.append("  }\n}\n")
    return "".join(parts)
