"""Canonical, redacted change-set representation + hashing (SECP-002B-1A, ADR-013).

Durable approvals bind to a *canonical, redacted, hashed JSON change-set representation*
— never a raw OpenTofu binary plan (which is not proven secret-free). The change set
combines the deterministic intended resources (from the immutable manifest), the rendered
workspace hash, and a non-secret ``plan_digest`` marker extracted from the runner's
``show -json`` step. Two identical dry runs produce an identical hash; any real-plan drift
changes the ``plan_digest`` and therefore the hash (so apply fails closed, proof #10).
"""

from __future__ import annotations

import hashlib

from secp_scenario_schema import content_hash


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


def canonical_change_set(
    *,
    kind: str,
    workspace_hash: str,
    resources: list[dict],
    plan_digest: str,
) -> dict:
    """Build the canonical, redacted change-set dict (secret-free)."""
    return {
        "change_set_version": "secp-002b-1a/change-set/v1",
        "kind": kind,
        "workspace_hash": workspace_hash,
        "plan_digest": plan_digest,
        "resources": sorted(resources, key=lambda r: r["resource_id"]),
        "summary": summarize(resources),
    }


def change_set_hash(change_set: dict) -> str:
    """Deterministic SHA-256 over a canonical redacted change set."""
    return content_hash(change_set)
