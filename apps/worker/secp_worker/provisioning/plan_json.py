"""Canonical, redacted OpenTofu plan-JSON handling (SECP-002B-1A, ADR-013) — worker-only.

Consumes a ``tofu show -json``-shaped structure and produces a **deterministic, redacted,
canonical change-set** for human review and exact hash binding. Only safe review fields
survive: resource address, mode, type, name, provider identity, action list, and a
replacement indicator, plus the workspace and immutable provenance hashes.

**Never** emitted: before/after values, provider configuration, endpoint values, tokens,
sensitive values, unknown raw fields, state contents, or the raw plan JSON. Malformed or
unsupported plan structures **fail closed**.

``build_fixture_show_json`` produces realistic, safe *fixture* JSON for the
``FakeProcessExecutor`` in B1-A tests/verification (it deliberately includes fake secret
values so tests can prove they never survive canonicalization). It is not used on any real
path.
"""

from __future__ import annotations

from secp_scenario_schema import content_hash

CHANGE_SET_VERSION = "secp-002b-1a/change-set/v2"

# Only these safe review fields are ever surfaced per resource.
_ALLOWED_MODES = {"managed", "data"}


class PlanCanonicalizationError(Exception):
    """The plan JSON was malformed/unsupported. Message is redacted."""


def _is_replace(actions: list[str], change: dict) -> bool:
    if change.get("replace_paths"):
        return True
    return actions in (["delete", "create"], ["create", "delete"])


def canonicalize_plan_json(
    show_json: object,
    *,
    kind: str,
    workspace_hash: str,
    provenance: dict,
) -> dict:
    """Return a deterministic, redacted canonical change set. Fail closed on malformed input."""
    if not isinstance(show_json, dict):
        raise PlanCanonicalizationError("plan JSON is not an object")
    resource_changes = show_json.get("resource_changes")
    if not isinstance(resource_changes, list):
        raise PlanCanonicalizationError("plan JSON has no resource_changes list")

    resources: list[dict] = []
    for item in resource_changes:
        if not isinstance(item, dict):
            raise PlanCanonicalizationError("resource_changes entry is not an object")
        change = item.get("change")
        if not isinstance(change, dict):
            raise PlanCanonicalizationError("resource change is missing")
        actions = change.get("actions")
        if not isinstance(actions, list) or not all(isinstance(a, str) for a in actions):
            raise PlanCanonicalizationError("resource change actions are malformed")
        address = item.get("address")
        rtype = item.get("type")
        name = item.get("name")
        mode = item.get("mode", "managed")
        provider = item.get("provider_name", "")
        if not (isinstance(address, str) and address):
            raise PlanCanonicalizationError("resource address is missing")
        if not (isinstance(rtype, str) and rtype and isinstance(name, str) and name):
            raise PlanCanonicalizationError("resource type/name is missing")
        if mode not in _ALLOWED_MODES:
            raise PlanCanonicalizationError("unsupported resource mode")
        # Only safe review fields; before/after/sensitive/config/state are dropped.
        resources.append(
            {
                "address": address,
                "mode": mode,
                "type": rtype,
                "name": name,
                "provider": provider if isinstance(provider, str) else "",
                "actions": list(actions),
                "replace": _is_replace(list(actions), change),
            }
        )

    resources.sort(key=lambda r: r["address"])
    by_action: dict[str, int] = {}
    for r in resources:
        key = ",".join(r["actions"])
        by_action[key] = by_action.get(key, 0) + 1

    return {
        "change_set_version": CHANGE_SET_VERSION,
        "kind": kind,
        "workspace_hash": workspace_hash,
        "provenance": dict(provenance),
        "resources": resources,
        "summary": {"count": len(resources), "by_action": by_action},
    }


def change_set_hash(change_set: dict) -> str:
    """Deterministic SHA-256 over a canonical redacted change set."""
    return content_hash(change_set)


def build_fixture_show_json(manifest: dict, *, actions: tuple[str, ...] = ("create",)) -> dict:
    """Realistic, SAFE fixture ``tofu show -json`` for B1-A fakes.

    Deliberately embeds fake secret-looking values (``after``, ``after_sensitive``) so
    tests can prove canonicalization drops them. NOT used on any real path.
    """
    from secp_worker.provisioning.change_set import planned_resources

    changes: list[dict] = []
    for r in planned_resources(manifest):
        if r["type"] == "network":
            rtype = "labfake_network"
            local = str(r.get("name"))
        elif r["type"] == "container":
            rtype = "labfake_lxc"
            local = str(r.get("ref"))
        else:
            rtype = "labfake_vm"
            local = str(r.get("ref"))
        local_name = f"{r['team_ref']}_{local}".replace("-", "_")
        changes.append(
            {
                "address": f"{rtype}.{local_name}",
                "mode": "managed",
                "type": rtype,
                "name": local_name,
                "provider_name": "example.test/fake/labproxmox",
                "change": {
                    "actions": list(actions),
                    # These MUST be dropped by canonicalization:
                    "before": None,
                    "after": {
                        "api_token": "SUPER-SECRET-FAKE-TOKEN",
                        "endpoint": "https://proxmox.example.test:8006",
                        "root_password": "hunter2-fake",
                    },
                    "after_sensitive": {"api_token": True, "root_password": True},
                },
            }
        )
    return {"format_version": "1.2", "resource_changes": changes}
