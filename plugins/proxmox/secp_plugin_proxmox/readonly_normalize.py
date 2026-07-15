"""Pure, provider-neutral normalizer for read-only Proxmox observations (SECP-002B-1B-3).

Maps canned Proxmox GET responses into an in-memory, provider-neutral ``observed`` structure
shaped like the fields the existing boundary↔evidence comparison consumes (nodes, storage,
network_segments, cidr_reservations, and — only from explicit, dedicated, approved observations
— vmid_range, quotas, isolation).

Guarantees (ADR-015):

* **Pure.** No I/O, no HTTP/socket/subprocess/provider SDK imports. Deterministic.
* **Does not choose** ``evidence_source`` or ``verification_level`` and **does not persist**
  anything. It returns a plain dict; wrapping it into an evidence payload is a test-only concern.
* **Redacts.** Inventory is reduced to identifiers/counts by whitelist extraction; descriptions,
  notes, tags, comments, secrets, credentials, cookies, and tickets are dropped.
* **Never infers.** A category is emitted only when its source data is present. Isolation is
  emitted only from an explicit dedicated observation — never inferred from inventory presence
  or segment names (see the ``fully_segregated`` guardrail).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Keys that must never survive normalization (descriptions / metadata / secret-like material).
_REDACT_KEYS = frozenset(
    {
        "description",
        "desc",
        "notes",
        "note",
        "comment",
        "comments",
        "tags",
        "tag",
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "ticket",
        "csrfpreventiontoken",
        "privatekey",
        "private_key",
    }
)


def _as_list(value: object) -> list[dict]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _strip(obj: Any) -> Any:
    """Recursively drop redacted keys from dicts/lists (defense-in-depth for dedicated obs)."""
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items() if str(k).lower() not in _REDACT_KEYS}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


def normalize_proxmox_observations(
    path_responses: Mapping[str, Any],
    *,
    dedicated: Mapping[str, Any] | None = None,
) -> dict:
    """Return the provider-neutral ``observed`` structure for the given fake responses.

    ``path_responses`` maps concrete allowlisted GET paths to canned Proxmox ``data``. Inventory
    (nodes / storage / network_segments / cidr_reservations) is extracted by whitelist.
    ``dedicated`` optionally supplies pre-formed, approved observations for ``vmid_range`` /
    ``quotas`` / ``isolation`` — the only way those dimensions are ever populated (they are never
    inferred from inventory). Absent categories are omitted, which the comparison treats as
    ``unverifiable`` (fail closed).
    """
    observed: dict[str, Any] = {}

    # A category is emitted only when its source is a WELL-FORMED list. A present-but-malformed
    # (non-list) response is omitted, so the comparison treats it as unverifiable (fail closed).
    raw_nodes = path_responses.get("/nodes")
    if isinstance(raw_nodes, list):
        observed["nodes"] = sorted({str(n["node"]) for n in _as_list(raw_nodes) if n.get("node")})

    storage_ids: set[str] = set()
    saw_storage = False
    for path, value in path_responses.items():
        if path == "/storage" or (path.startswith("/nodes/") and path.endswith("/storage")):
            if isinstance(value, list):
                saw_storage = True
                for row in _as_list(value):
                    if row.get("storage"):
                        storage_ids.add(str(row["storage"]))
    if saw_storage:
        observed["storage"] = sorted(storage_ids)

    segments: set[str] = set()
    cidrs: set[str] = set()
    saw_segments = False
    raw_vnets = path_responses.get("/cluster/sdn/vnets")
    if isinstance(raw_vnets, list):
        saw_segments = True
        for vnet in _as_list(raw_vnets):
            if vnet.get("vnet"):
                segments.add(str(vnet["vnet"]))
            if isinstance(vnet.get("cidr"), str) and vnet["cidr"]:
                cidrs.add(str(vnet["cidr"]))
    for path, value in path_responses.items():
        if path.startswith("/nodes/") and path.endswith("/network") and isinstance(value, list):
            saw_segments = True
            for iface in _as_list(value):
                if iface.get("type") == "bridge" and iface.get("iface"):
                    segments.add(str(iface["iface"]))
    if saw_segments:
        observed["network_segments"] = sorted(segments)
        if cidrs:
            observed["cidr_reservations"] = sorted(cidrs)

    # Explicit, approved dedicated observations only — NEVER inferred from inventory.
    for key in ("vmid_range", "quotas", "isolation"):
        if dedicated is not None and dedicated.get(key) is not None:
            observed[key] = _strip(dedicated[key])

    # A LIVE Path B VM-ID observation (SECP-002B-1B-PR5A §6): the used VM-IDs actually present on
    # the cluster, from the allowlisted ``/cluster/resources`` GET. Redacted to bare integer ids
    # only (no name/node/status/config). Merged into any dedicated ``vmid_range`` window so
    # the policy can derive collision LIVE rather than trusting an asserted boolean. The allocatable
    # WINDOW itself is not inferred here (it is an approved dedicated observation), so the shipped
    # collector alone still cannot make the VM-ID dimension pass — it can only prove collision.
    raw_resources = path_responses.get("/cluster/resources")
    if isinstance(raw_resources, list):
        used_vmids = sorted(
            {
                int(r["vmid"])
                for r in _as_list(raw_resources)
                if isinstance(r.get("vmid"), int)
                and not isinstance(r.get("vmid"), bool)
                and r.get("type") in ("qemu", "lxc")
            }
        )
        window = observed.get("vmid_range")
        observed["vmid_range"] = {
            **(window if isinstance(window, dict) else {}),
            "used_vmids": used_vmids,
        }

    return observed
