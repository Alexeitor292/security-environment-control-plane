"""FakeOpenTofuRunner — the only runner in SECP-002B-0 (ADR-012).

No subprocess, no network, no provider client, no OpenTofu/Terraform binary. All
operations are pure functions of the manifest content, so operation and resource
IDs and dry-run change sets are deterministic, and apply/destroy are idempotent.
Errors are redacted. Fake state is kept in-process (durable for the worker process)
and the caller persists results to the ProvisioningOperation record.
"""

from __future__ import annotations

import hashlib
import json

from secp_worker.provisioning.runner import (
    RunnerApplyResult,
    RunnerChangeSet,
    RunnerDestroyResult,
    RunnerError,
    RunnerStatus,
    RunnerValidationResult,
)

_REQUIRED_KEYS = ("manifest_version", "topology", "reservations", "resource_limits")


def _fingerprint(manifest: dict) -> str:
    blob = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _resource_id(fingerprint: str, ref: str) -> str:
    return "fake-" + hashlib.sha256(f"{fingerprint}:{ref}".encode()).hexdigest()[:16]


def _planned_resources(manifest: dict) -> list[dict]:
    """Deterministic list of resources this manifest would create (secret-free)."""
    fp = _fingerprint(manifest)
    resources: list[dict] = []
    for team in manifest.get("topology", []):
        team_ref = team.get("team_ref")
        for net in team.get("networks", []):
            ref = f"{team_ref}/net/{net.get('name')}"
            resources.append(
                {
                    "resource_id": _resource_id(fp, ref),
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
                    "resource_id": _resource_id(fp, ref),
                    "type": node.get("guest_kind"),
                    "team_ref": team_ref,
                    "ref": node.get("ref"),
                    "image": node.get("image"),
                    "node": node.get("node"),
                    "storage": node.get("storage"),
                }
            )
    return resources


class FakeOpenTofuRunner:
    name = "fake-opentofu"

    def __init__(self) -> None:
        # operation_id -> {"state": str, "resources": list}
        self._state: dict[str, dict] = {}

    def validate(self, manifest: dict) -> RunnerValidationResult:
        errors = [k for k in _REQUIRED_KEYS if k not in manifest]
        if errors:
            return RunnerValidationResult(
                ok=False, errors=[f"manifest missing '{k}'" for k in errors]
            )
        if not manifest.get("topology"):
            return RunnerValidationResult(ok=False, errors=["manifest topology is empty"])
        return RunnerValidationResult(ok=True)

    def dry_run(self, manifest: dict, *, operation_id: str) -> RunnerChangeSet:
        result = self.validate(manifest)
        if not result.ok:
            raise RunnerError("manifest is not runnable (redacted)")
        creates = _planned_resources(manifest)
        by_type: dict[str, int] = {}
        for r in creates:
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        return RunnerChangeSet(
            operation_id=operation_id,
            creates=creates,
            summary={"create": len(creates), "by_type": by_type, "change": "create-only"},
        )

    def apply(self, manifest: dict, *, operation_id: str) -> RunnerApplyResult:
        existing = self._state.get(operation_id)
        if existing is not None and existing.get("state") == "applied":
            # Idempotent: the same operation was already applied.
            return RunnerApplyResult(
                operation_id=operation_id,
                ok=True,
                resources=existing["resources"],
                summary={"applied": len(existing["resources"])},
                idempotent_noop=True,
            )
        result = self.validate(manifest)
        if not result.ok:
            raise RunnerError("manifest is not runnable (redacted)")
        resources = _planned_resources(manifest)
        self._state[operation_id] = {"state": "applied", "resources": resources}
        return RunnerApplyResult(
            operation_id=operation_id,
            ok=True,
            resources=resources,
            summary={"applied": len(resources)},
            idempotent_noop=False,
        )

    def destroy(self, manifest: dict, *, operation_id: str) -> RunnerDestroyResult:
        existing = self._state.get(operation_id)
        if existing is not None and existing.get("state") == "destroyed":
            return RunnerDestroyResult(
                operation_id=operation_id, ok=True, destroyed=[], idempotent_noop=True
            )
        resources = _planned_resources(manifest)
        destroyed = [r["resource_id"] for r in resources]
        self._state[operation_id] = {"state": "destroyed", "resources": []}
        return RunnerDestroyResult(
            operation_id=operation_id,
            ok=True,
            destroyed=destroyed,
            idempotent_noop=False,
        )

    def status(self, operation_id: str) -> RunnerStatus:
        record = self._state.get(operation_id)
        if record is None:
            return RunnerStatus(operation_id=operation_id, state="unknown", exists=False)
        return RunnerStatus(
            operation_id=operation_id,
            state=record["state"],
            exists=True,
            summary={"resources": len(record.get("resources", []))},
        )
