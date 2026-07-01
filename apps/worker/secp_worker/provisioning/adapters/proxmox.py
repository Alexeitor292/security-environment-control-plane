"""Proxmox provisioning adapter (SECP-002B-1A, ADR-013) — worker-only.

Renders a deterministic, secret-free OpenTofu workspace from an immutable manifest +
toolchain profile. Everything here is INERT fixture rendering:

* the provider source/version are **clearly-fake placeholders** on a non-routable
  ``.test`` mirror and cannot resolve to a real registry;
* resource *types* are fake (``labfake_*``) so this text can never drive a real Proxmox
  provider even if it were ever fed to a real OpenTofu (it will not be in B1-A);
* the provider **endpoint and token are referenced only as input variables**
  (``var.pm_endpoint`` / ``var.pm_api_token``) — never written into the artifact. Their
  values would be injected just-in-time in the worker at real apply (B1-B), and are
  never persisted, hashed, or logged.

No provider SDK is imported and no network connection is opened.
"""

from __future__ import annotations

from secp_worker.provisioning.adapters.base import AdapterError

# Clearly-fake, non-routable fixture provenance. NOT a real provider or registry.
_FAKE_PROVIDER_SOURCE = "example.test/fake/labproxmox"
_FAKE_PROVIDER_VERSION = "0.0.0-fake"


def _hcl_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ProxmoxAdapter:
    adapter_kind = "proxmox"

    def render(self, manifest: dict, profile: dict) -> dict[str, str]:
        topology = manifest.get("topology")
        if not topology:
            raise AdapterError("manifest topology is empty; nothing to render")

        module_bundle_id = str(profile.get("module_bundle_id", ""))
        opentofu_version = str(profile.get("opentofu_version", ""))

        files: dict[str, str] = {}

        # versions.tf — pinned, fake required_providers; offline mirror is enforced by
        # the runner via CLI flags, not by embedding a registry URL here.
        files["versions.tf"] = (
            "# GENERATED — do not edit. Secret-free. Fake fixture provider (inert).\n"
            "terraform {\n"
            f'  required_version = "= {opentofu_version}"\n'
            "  required_providers {\n"
            "    labproxmox = {\n"
            f"      source  = {_hcl_str(_FAKE_PROVIDER_SOURCE)}\n"
            f'      version = "= {_FAKE_PROVIDER_VERSION}"\n'
            "    }\n"
            "  }\n"
            "}\n"
            f"# module_bundle_id = {module_bundle_id}\n"
        )

        # variables.tf — endpoint + token are INPUT VARIABLES only (no defaults/values).
        files["variables.tf"] = (
            'variable "pm_endpoint" {\n'
            "  type        = string\n"
            '  description = "Provider endpoint; injected just-in-time in the worker at apply."\n'
            "}\n\n"
            'variable "pm_api_token" {\n'
            "  type        = string\n"
            "  sensitive   = true\n"
            '  description = "Provider token; JIT-resolved in the worker, never persisted."\n'
            "}\n"
        )

        # provider.tf — references variables only; no endpoint/credential literal.
        files["provider.tf"] = (
            'provider "labproxmox" {\n'
            "  endpoint  = var.pm_endpoint\n"
            "  api_token = var.pm_api_token\n"
            "  insecure  = false\n"
            "}\n"
        )

        # main.tf — deterministic resources from the manifest topology (secret-free).
        lines: list[str] = ["# GENERATED — secret-free lab topology (fake resource types).\n"]
        for team in topology:
            team_ref = str(team.get("team_ref", ""))
            for net in team.get("networks", []):
                name = f"{team_ref}_{net.get('name', 'net')}".replace("-", "_")
                lines.append(f'resource "labfake_network" "{name}" {{\n')
                lines.append(f"  team    = {_hcl_str(team_ref)}\n")
                lines.append(f"  cidr    = {_hcl_str(str(net.get('cidr', '')))}\n")
                lines.append(f"  bridge  = {_hcl_str(str(net.get('bridge', '')))}\n")
                lines.append("  isolated = true\n")
                lines.append("}\n\n")
            for node in team.get("nodes", []):
                ref = f"{team_ref}_{node.get('ref', 'node')}".replace("-", "_")
                res_type = "labfake_lxc" if node.get("guest_kind") == "container" else "labfake_vm"
                lines.append(f'resource "{res_type}" "{ref}" {{\n')
                lines.append(f"  team    = {_hcl_str(team_ref)}\n")
                lines.append(f"  vmid    = {int(node.get('vmid', 0))}\n")
                lines.append(f"  target_node = {_hcl_str(str(node.get('node', '')))}\n")
                lines.append(f"  template    = {_hcl_str(str(node.get('image', '')))}\n")
                lines.append(f"  storage     = {_hcl_str(str(node.get('storage', '')))}\n")
                lines.append(f"  cores       = {int(node.get('vcpu', 0))}\n")
                lines.append(f"  memory      = {int(node.get('memory_mb', 0))}\n")
                lines.append(f"  disk_gb     = {int(node.get('disk_gb', 0))}\n")
                lines.append("}\n\n")
        files["main.tf"] = "".join(lines)

        return files
