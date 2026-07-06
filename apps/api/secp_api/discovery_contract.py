"""Shared, content-addressed discovery candidate-plan contract (SECP-B5).

The SINGLE source of truth for how a discovery-derived candidate plan is canonicalized and hashed,
so
the app-side service and the worker-side discovery engine can never disagree. A candidate plan binds
the EXACT discovered node/storage identity, bounded candidate VMIDs, generated ownership-bound
resource names + unique per-resource markers, the resource profile, the capacity-snapshot hash, the
discovery-evidence hash, the worker identity version, the artifact-profile identity, the target
enrollment version, and a clear expiry. It fabricates NO value: every provider identifier is derived
from the exact observed discovery evidence supplied by the read-only probes. It performs no I/O and
stores/derives only safe opaque values — never a secret, endpoint, address, or raw host output.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime

from secp_api.ownership_contract import (
    compute_ownership_fingerprint,
    compute_ownership_tag,
    compute_resource_marker,
    compute_resource_ref,
)

DISCOVERY_PLAN_SCHEMA_VERSION = "secp-b5/discovery-candidate-plan/v1"
DISCOVERY_EVIDENCE_SCHEMA_VERSION = "secp-b5/discovery-evidence/v1"
# The standard Proxmox local realm for the generated scoped service identity (a provider convention,
# not a target-specific value).
_LOCAL_REALM = "pam"

# The closed, ordered candidate resource categories a discovery plan pins (each exactly once).
_CANDIDATE_KINDS: tuple[str, ...] = (
    "proxmox_service_identity",
    "isolated_bridge",
    "host_firewall_boundary",
    "control_plane_vm",
    "nested_target_vm",
)


class DiscoveryPlanError(ValueError):
    """Raised for an out-of-contract candidate-plan input. Never echoes an offending value."""


def _sha(canonical: str) -> str:
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_evidence_hash(evidence: dict) -> str:
    """Deterministic content address of the typed, bounded discovery evidence snapshot."""
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return _sha(f"{DISCOVERY_EVIDENCE_SCHEMA_VERSION}|{encoded}")


def compute_capacity_snapshot_hash(
    *, cpu_total: int, mem_total_mb: int, mem_free_mb: int, storage: str, storage_avail_mb: int
) -> str:
    """Deterministic hash of the discovered capacity snapshot the plan is bound to (drift
    anchor)."""
    canonical = (
        f"{DISCOVERY_PLAN_SCHEMA_VERSION}|cpu={cpu_total}|memt={mem_total_mb}|memf={mem_free_mb}"
        f"|store={storage}|avail={storage_avail_mb}"
    )
    return _sha(canonical)


def candidate_resource_specs(
    *, ownership_label: str, node: str, control_plane_vmid: int, nested_target_vmid: int
) -> list[dict]:
    """Generate the closed candidate resource set: each a safe kind + generated ownership ref +
    unique
    marker + a typed locator dict whose fields are the EXACT discovered/generated identifiers. No
    hardcoded node/VMID/bridge/user — the node/VMIDs are the discovered values passed in."""
    fp8 = compute_ownership_fingerprint(ownership_label)[:8]
    specs: list[dict] = []

    def spec(kind: str, locator: dict) -> dict:
        return {
            "kind": kind,
            "resource_ref": compute_resource_ref(ownership_label, kind, 0),
            "ownership_marker": compute_resource_marker(ownership_label, kind, 0),
            "locator": locator,
        }

    specs.append(
        spec(
            "proxmox_service_identity",
            {"type": "service_identity", "userid": f"secp{fp8}@{_LOCAL_REALM}"},
        )
    )
    specs.append(spec("isolated_bridge", {"type": "bridge", "node": node, "iface": f"secp{fp8}br"}))
    specs.append(
        spec("host_firewall_boundary", {"type": "firewall_group", "group": f"secp{fp8}fw"})
    )
    specs.append(
        spec("control_plane_vm", {"type": "guest", "node": node, "vmid": int(control_plane_vmid)})
    )
    specs.append(
        spec("nested_target_vm", {"type": "guest", "node": node, "vmid": int(nested_target_vmid)})
    )
    return specs


def build_candidate_plan_document(
    *,
    ownership_label: str,
    resource_profile: str,
    node: str,
    storage: str,
    control_plane_vmid: int,
    nested_target_vmid: int,
    capacity_snapshot_hash: str,
    evidence_hash: str,
    worker_identity_version: int,
    artifact_manifest_id: str,
    enrollment_version: int,
    expires_at: datetime,
) -> dict:
    """Build the closed, deterministic candidate-plan document. Live apply remains sealed: the plan
    explicitly declares it is not executable in this PR."""
    return {
        "schema_version": DISCOVERY_PLAN_SCHEMA_VERSION,
        "ownership_tag": compute_ownership_tag(ownership_label),
        "resource_profile": resource_profile,
        "node": node,
        "storage": storage,
        "resources": candidate_resource_specs(
            ownership_label=ownership_label,
            node=node,
            control_plane_vmid=control_plane_vmid,
            nested_target_vmid=nested_target_vmid,
        ),
        "capacity_snapshot_hash": capacity_snapshot_hash,
        "evidence_hash": evidence_hash,
        "worker_identity_version": worker_identity_version,
        "artifact_manifest_id": artifact_manifest_id,
        "enrollment_version": enrollment_version,
        "expires_at": expires_at.isoformat(),
        # Live deployment apply remains sealed pending controlled integration enablement (SECP-B5).
        "executable": False,
    }


def discovery_candidate_plan_hash(plan_document: dict) -> str:
    """Deterministic ``sha256:`` content address of a canonicalized candidate-plan document."""
    encoded = json.dumps(plan_document, sort_keys=True, separators=(",", ":"))
    return _sha(encoded)


def discovery_operation_fingerprint(enrollment_id: uuid.UUID, enrollment_version: int) -> str:
    """Deterministic server key over (enrollment, version) so a retry resolves to the SAME job
    row."""
    return _sha(f"{enrollment_id}|{enrollment_version}")
