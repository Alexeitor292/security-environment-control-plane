"""Manifest-derived resource helpers (SECP-002B-1A, ADR-013).

Deterministic, secret-free helpers used to build the fixture ``show -json`` and to
summarize apply/destroy results. The authoritative change-set canonicalization + hashing
lives in :mod:`secp_worker.provisioning.plan_json` (it consumes the OpenTofu plan JSON and
redacts it). No raw binary plan is ever persisted.
"""

from __future__ import annotations

import hashlib


def planned_resources(manifest: dict) -> list[dict]:
    """Deterministic, secret-free list of resources the manifest would create."""
    resources: list[dict] = []
    for team in manifest.get("topology", []):
        team_ref = team.get("team_ref")
        for net in team.get("networks", []):
            ref = f"{team_ref}/net/{net.get('name')}"
            resources.append(
                {
                    "resource_id": _resource_id(ref),
                    "type": "network",
                    "team_ref": team_ref,
                    "name": net.get("name"),
                    "cidr": net.get("cidr"),
                    "bridge": net.get("bridge"),
                }
            )
        for node in team.get("nodes", []):
            ref = f"{team_ref}/{node.get('guest_kind')}/{node.get('ref')}"
            resources.append(
                {
                    "resource_id": _resource_id(ref),
                    "type": node.get("guest_kind"),
                    "team_ref": team_ref,
                    "ref": node.get("ref"),
                    "image": node.get("image"),
                    "node": node.get("node"),
                    "storage": node.get("storage"),
                    "vmid": node.get("vmid"),
                }
            )
    return resources


def _resource_id(ref: str) -> str:
    return "otf-" + hashlib.sha256(ref.encode("utf-8")).hexdigest()[:16]


def summarize(resources: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    for r in resources:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    return {"create": len(resources), "by_type": by_type}
