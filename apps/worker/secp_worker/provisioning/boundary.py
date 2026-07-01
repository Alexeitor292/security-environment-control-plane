"""Worker-only effective-boundary enforcement seam (SECP-002B-1B-0 correction pass, ADR-014).

The *effective execution boundary* = declared onboarding boundary ∩ target scope policy is
computed in the control plane and bound (immutably, hash-covered) into the plan and manifest.
This module is the worker-side enforcement of that boundary: BEFORE any rendering, secret
resolution, executor construction, or process call, every provider action the worker would
take must be validated to fall strictly inside the effective boundary.

Provider-neutral and pure: no provider SDK, no network, no subprocess, no OpenTofu. It only
inspects the (already secret-free) manifest topology + totals against the effective boundary.
``apps/api`` never imports this module.

In SECP-002B-1B-0 no real provider operations exist; the enforced "actions" are the manifest's
declared nodes/storage/networks/reservations/VM-IDs/totals. The per-action helpers exist so a
future real provider adapter validates each concrete operation through the same seam.
"""

from __future__ import annotations

from secp_api.onboarding import cidr_within_allowed


class BoundaryViolation(Exception):
    """Raised when a provider action would fall outside the effective execution boundary."""


def node_within_boundary(eb: dict, node: str) -> bool:
    return node in set(eb.get("nodes", []))


def storage_within_boundary(eb: dict, storage: str) -> bool:
    return storage in set(eb.get("storage", []))


def network_within_boundary(eb: dict, segment: str) -> bool:
    return segment in set(eb.get("network_segments", []))


def cidr_within_boundary(eb: dict, cidr: str) -> bool:
    try:
        return cidr_within_allowed(cidr, list(eb.get("cidrs", [])))
    except ValueError:
        return False


def vmid_within_boundary(eb: dict, vmid: int) -> bool:
    vr = eb.get("vmid_range", {}) or {}
    start, end = vr.get("start"), vr.get("end")
    if start is None or end is None or not isinstance(vmid, int):
        return False
    return start <= vmid <= end


def external_connectivity_denied(eb: dict) -> bool:
    return (eb.get("external_connectivity", {}) or {}).get("policy") == "deny"


# Map manifest requested-totals keys to effective-boundary quota keys.
_TOTAL_TO_QUOTA = {
    "teams": "max_teams",
    "vms": "max_vms",
    "containers": "max_containers",
    "total_vcpu": "max_total_vcpu",
    "total_memory_mb": "max_total_memory_mb",
    "total_disk_gb": "max_total_disk_gb",
}


def totals_within_quotas(eb: dict, totals: dict) -> list[str]:
    """Return quota-violation reasons (empty when all requested totals fit)."""
    quotas = eb.get("quotas", {}) or {}
    problems: list[str] = []
    for total_key, quota_key in _TOTAL_TO_QUOTA.items():
        requested = totals.get(total_key, 0)
        cap = quotas.get(quota_key)
        if cap is not None and requested > cap:
            problems.append(f"{total_key}={requested} exceeds effective quota {quota_key}={cap}")
    return problems


def enforce_manifest_within_boundary(content: dict, eb: dict) -> list[str]:
    """Validate the manifest's declared actions against the effective boundary.

    Returns a list of violation reasons (empty when the manifest is entirely in-bound). Every
    node selection, storage selection, network/bridge selection, CIDR reservation, VM-ID, the
    requested totals, and the external-connectivity policy are checked.
    """
    problems: list[str] = []
    if not external_connectivity_denied(eb):
        problems.append("effective boundary external connectivity is not deny")

    for team in content.get("topology", []):
        team_ref = team.get("team_ref", "?")
        for net in team.get("networks", []):
            bridge = net.get("bridge")
            if not network_within_boundary(eb, bridge):
                problems.append(
                    f"{team_ref}: network segment {bridge!r} is outside the effective boundary"
                )
            cidr = net.get("cidr", "")
            if not cidr_within_boundary(eb, cidr):
                problems.append(
                    f"{team_ref}: reservation {cidr!r} is outside the effective boundary CIDRs"
                )
        for node in team.get("nodes", []):
            node_name = node.get("node")
            if not node_within_boundary(eb, node_name):
                problems.append(f"{team_ref}: node {node_name!r} is outside the effective boundary")
            storage = node.get("storage")
            if not storage_within_boundary(eb, storage):
                problems.append(
                    f"{team_ref}: storage {storage!r} is outside the effective boundary"
                )
            vmid = node.get("vmid")
            if not vmid_within_boundary(eb, vmid):
                problems.append(f"{team_ref}: vmid {vmid!r} is outside the effective VM-ID range")

    # External connectivity declared in the manifest scope snapshot must remain deny.
    scope_ext = (content.get("scope_policy", {}) or {}).get("external_connectivity", {}) or {}
    if scope_ext.get("policy") != "deny":
        problems.append("manifest external connectivity policy is not deny")

    problems.extend(totals_within_quotas(eb, content.get("requested_totals", {}) or {}))
    return problems
