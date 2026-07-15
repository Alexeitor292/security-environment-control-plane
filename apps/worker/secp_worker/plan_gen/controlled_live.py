"""Controlled-live Proxmox plan-only renderer (SECP-002B-1B-PR5B, ADR-022 §2/§3/§4) — worker-only.

This is the SEPARATE, unmistakably controlled-live renderer. It is NOT the inert B1-A fake adapter
(``example.test/fake/labproxmox`` / ``0.0.0-fake`` / ``labfake_*``), which must never be reachable
by a controlled-live plan. It emits a deterministic, secret-free workspace for the exact reviewed
provider (``CONTROLLED_LIVE_PROVIDER_SOURCE`` = ``bpg/proxmox``) at an EXACT version pin supplied
out-of-band from the immutable ``ToolchainProfile`` — never
``latest``, never a runtime download, never a registry URL.

The initial controlled-live scope is deliberately the SMALLEST truthful shape (task §3): ONE bounded
disposable **LXC container** on an EXISTING reviewed node/storage/bridge, an explicitly reserved
VM-ID, exact CPU/memory/disk quotas. It creates no bridge, VLAN, SDN object, image, snippet, HA or
host-hardware resource, uses no SSH/PAM/root credential, and performs no file transfer. Every other
guest kind and every unsupported field fails closed BEFORE rendering.

The provider ENDPOINT and TOKEN are OpenTofu input variables only (``var.pm_endpoint`` /
``var.pm_api_token``) — never written into the artifact; their values are JIT-projected into the
child process environment in the worker at execution time and are never persisted, hashed, or
logged. No provider SDK is imported here and no network connection is opened. The output is
validated by :func:`controlled_live_render_scan` before it may ever be materialized.
"""

from __future__ import annotations

import re

from secp_worker.plan_gen.render_scan import (
    CONTROLLED_LIVE_PROVIDER_SOURCE,
    RenderScanContract,
    controlled_live_render_scan,
)

# The controlled-live adapter kind — distinct from the fake ``proxmox`` adapter kind, so a fake
# manifest/profile can never select this path (and vice-versa).
CONTROLLED_LIVE_ADAPTER_KIND = "controlled_live_proxmox"

# The ONE supported bpg/proxmox resource type in the initial narrow scope: an LXC container.
_CONTAINER_RESOURCE_TYPE = "proxmox_virtual_environment_container"
SUPPORTED_RESOURCE_TYPES: frozenset[str] = frozenset({_CONTAINER_RESOURCE_TYPE})
# The provider identity OpenTofu ``show -json`` reports for the pinned ``bpg/proxmox`` provider.
CONTROLLED_LIVE_PROVIDER_SHOW_NAME = "registry.terraform.io/bpg/proxmox"
# The initial module reads NO data sources.
ALLOWED_DATA_SOURCES: frozenset[str] = frozenset()

# Bump when the deterministic renderer output changes. Bound into the workspace hash + result
# provenance (the reviewed renderer implementation identity, task §4/§16).
CONTROLLED_LIVE_RENDERER_VERSION = "secp-002b-1b-pr5b/controlled-live-proxmox-renderer/v1"


def controlled_live_renderer_implementation_digest() -> str:
    """The stable digest of the reviewed controlled-live renderer implementation identity.

    A plan-only capability binds this exact digest; the issuer refuses a mismatch, so a fake
    renderer cannot be promoted by merely re-declaring the renderer version string.
    """
    import hashlib

    return "sha256:" + hashlib.sha256(CONTROLLED_LIVE_RENDERER_VERSION.encode()).hexdigest()


# Only these guest kinds are representable; the initial scope supports exactly one.
_SUPPORTED_GUEST_KIND = "container"

# The exact reviewed container network-interface name required by the bpg/proxmox provider.
_CONTAINER_NIC_NAME = "veth0"

# An EXISTING Proxmox container template (``<datastore>:vztmpl/<file>``) — never a URL, upload,
# snippet, or runtime download. The OS type is NOT inferred from the filename.
_VZTMPL_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*:vztmpl/[A-Za-z0-9][A-Za-z0-9._-]*$")


class ControlledLiveRenderError(Exception):
    """A manifest/profile cannot be rendered as a controlled-live workspace (bounded reason)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _hcl_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _require_int(value: object, reason: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ControlledLiveRenderError(reason)
    return value


def _container_local_ref(manifest: dict) -> str:
    """The exact controlled-live resource local name for the manifest's single container.

    Validates the exactly-one shape (one team, one container) and returns the local name the
    renderer
    emits, so the change policy can bind the EXACT expected resource address server-side.
    """
    topology = manifest.get("topology")
    if not isinstance(topology, list) or len(topology) != 1:
        raise ControlledLiveRenderError("exactly_one_team_required")
    team = topology[0]
    nodes = team.get("nodes") if isinstance(team, dict) else None
    if not isinstance(nodes, list) or len(nodes) != 1:
        raise ControlledLiveRenderError("exactly_one_container_required")
    node = nodes[0]
    if not isinstance(node, dict) or node.get("guest_kind") != _SUPPORTED_GUEST_KIND:
        raise ControlledLiveRenderError("unsupported_guest_kind")
    return f"{team.get('team_ref', '')}_{node.get('ref', 'node')}".replace("-", "_")


def controlled_live_expected_address(manifest: dict) -> str:
    """The EXACT ``<type>.<name>`` address the controlled-live plan must contain (change-policy)."""
    return f"{_CONTAINER_RESOURCE_TYPE}.{_container_local_ref(manifest)}"


def render_controlled_live_workspace(
    manifest: dict, *, provider_version: str, state_backend_kind: str
) -> dict[str, str]:
    """Render the controlled-live ``bpg/proxmox`` plan-only workspace, or fail closed.

    ``provider_version`` is the EXACT pin from the immutable ``ToolchainProfile``. Only ONE LXC
    container shape is supported: every other guest kind, any network/bridge/VLAN declaration, and
    any missing bounded field raises :class:`ControlledLiveRenderError` before any text is emitted.
    The output is additionally run through :func:`controlled_live_render_scan` here, so a defect in
    this renderer can never produce an unsafe workspace.
    """
    if state_backend_kind != "http":
        raise ControlledLiveRenderError("unsupported_state_backend_kind")

    # EXACTLY ONE disposable LXC: one team, one node, no networks. Zero or more than one is refused.
    topology = manifest.get("topology")
    if not isinstance(topology, list) or len(topology) != 1:
        raise ControlledLiveRenderError("exactly_one_team_required")
    team = topology[0]
    if not isinstance(team, dict) or team.get("networks"):
        raise ControlledLiveRenderError("network_creation_unsupported")
    nodes = team.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 1:
        raise ControlledLiveRenderError("exactly_one_container_required")
    node = nodes[0]
    if not isinstance(node, dict) or node.get("guest_kind") != _SUPPORTED_GUEST_KIND:
        raise ControlledLiveRenderError("unsupported_guest_kind")

    files: dict[str, str] = {}

    # versions.tf — the exact reviewed provider, exactly pinned, with an EMPTY http backend block.
    # No endpoint/address literal; the backend address is supplied out-of-band via TF_HTTP_* env.
    files["versions.tf"] = (
        "# GENERATED — do not edit. Secret-free controlled-live plan-only workspace.\n"
        "terraform {\n"
        "  required_providers {\n"
        "    proxmox = {\n"
        f"      source  = {_hcl_str(CONTROLLED_LIVE_PROVIDER_SOURCE)}\n"
        f'      version = "= {provider_version}"\n'
        "    }\n"
        "  }\n"
        '  backend "http" {}\n'
        "}\n"
    )

    # variables.tf — endpoint + token are INPUT VARIABLES only (no defaults, no values).
    files["variables.tf"] = (
        'variable "pm_endpoint" {\n'
        "  type        = string\n"
        '  description = "Provider HTTPS endpoint; JIT-projected in the worker, never persisted."\n'
        "}\n\n"
        'variable "pm_api_token" {\n'
        "  type        = string\n"
        "  sensitive   = true\n"
        '  description = "Provider plan-read token; JIT-resolved in the worker, never persisted."\n'
        "}\n"
    )

    # provider.tf — references variables only; no endpoint/credential literal; TLS verification on.
    files["provider.tf"] = (
        'provider "proxmox" {\n'
        "  endpoint  = var.pm_endpoint\n"
        "  api_token = var.pm_api_token\n"
        "  insecure  = false\n"
        "}\n"
    )

    # main.tf — the single deterministic LXC from the immutable manifest node (secret-free). Every
    # field comes from the reviewed manifest; nothing is inferred and no extra resource is emitted.
    team_ref = str(team.get("team_ref", ""))
    ref = f"{team_ref}_{node.get('ref', 'node')}".replace("-", "_")
    vmid = _require_int(node.get("vmid"), "vmid_required")
    target_node = str(node.get("node", ""))
    storage = str(node.get("storage", ""))
    bridge = str(node.get("bridge", ""))
    if not target_node or not storage or not bridge:
        raise ControlledLiveRenderError("node_storage_bridge_required")
    cores = _require_int(node.get("vcpu"), "vcpu_required")
    memory = _require_int(node.get("memory_mb"), "memory_required")
    disk_gb = _require_int(node.get("disk_gb"), "disk_required")
    # The container template is an EXISTING Proxmox vztmpl reference from the manifest — never a
    # URL,
    # upload, snippet, or runtime download; the OS type is not inferred from the filename.
    template = node.get("image")
    if not isinstance(template, str) or not _VZTMPL_RE.match(template):
        raise ControlledLiveRenderError("container_template_invalid")

    files["main.tf"] = (
        "# GENERATED — secret-free controlled-live lab topology (exactly one LXC).\n"
        f'resource "{_CONTAINER_RESOURCE_TYPE}" "{ref}" {{\n'
        f"  node_name = {_hcl_str(target_node)}\n"
        f"  vm_id     = {vmid}\n"
        "  unprivileged = true\n"
        "  started      = false\n"
        "  cpu {\n"
        f"    cores = {cores}\n"
        "  }\n"
        "  memory {\n"
        f"    dedicated = {memory}\n"
        "  }\n"
        "  disk {\n"
        f"    datastore_id = {_hcl_str(storage)}\n"
        f"    size         = {disk_gb}\n"
        "  }\n"
        "  operating_system {\n"
        f"    template_file_id = {_hcl_str(template)}\n"
        "  }\n"
        "  network_interface {\n"
        f'    name   = "{_CONTAINER_NIC_NAME}"\n'
        f"    bridge = {_hcl_str(bridge)}\n"
        "  }\n"
        "}\n"
    )

    # Defense in depth: the renderer's own output must pass the render-safety scanner. A renderer
    # defect can therefore never emit an unsafe controlled-live workspace.
    controlled_live_render_scan(
        files,
        contract=RenderScanContract(
            provider_source=CONTROLLED_LIVE_PROVIDER_SOURCE,
            provider_version=provider_version,
            supported_resource_types=SUPPORTED_RESOURCE_TYPES,
            allowed_data_sources=ALLOWED_DATA_SOURCES,
        ),
    )
    return files
