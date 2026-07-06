"""Shared, content-addressed deployment-plan contract (SECP-B4).

The SINGLE source of truth for how a deployment plan is canonicalized and hashed, so the app-side
service (which produces and pins the plan) and the worker-side engine (which recomputes the hash to
detect drift before any mutation) can never disagree. A plan document lists ONLY safe planned
resource CATEGORIES + bounded counts + generated ownership-bound references + pinned version labels
and deterministic hashes — never a secret, endpoint, host, IP, real bridge/VMID/storage name,
certificate, or credential. No I/O is performed.
"""

from __future__ import annotations

import hashlib
import json
import uuid

from secp_api.ownership_contract import compute_ownership_tag, compute_resource_ref

DEPLOYMENT_PLAN_SCHEMA_VERSION = "secp-b4/deployment-plan/v1"
# Pinned offline artifact catalog version (see the artifact pipeline). A change re-versions plans.
ARTIFACT_CATALOG_VERSION = "secp-b4/artifact-catalog/v1"

# The closed, ordered set of resource categories a deployment plan provisions (each exactly once).
_PLAN_RESOURCE_KINDS: tuple[str, ...] = (
    "proxmox_service_identity",
    "isolated_bridge",
    "host_firewall_boundary",
    "artifact_stage",
    "control_plane_vm",
    "nested_target_vm",
    "openbao_scoped_credential",
)
# App-owned bounded resource profiles (NOT user infrastructure values).
_PROFILES: frozenset[str] = frozenset({"small_lab", "medium_lab"})


class DeploymentPlanError(ValueError):
    """Raised for an out-of-contract plan input. Never echoes an offending value."""


def compute_capacity_assessment_hash(*, boundary_hash: str, resource_profile: str) -> str:
    """Deterministic hash binding the declared capacity: the target's onboarding boundary hash + the
    app-owned resource profile. A later change to either re-hashes and is detected as drift."""
    canonical = f"{DEPLOYMENT_PLAN_SCHEMA_VERSION}|{boundary_hash}|{resource_profile}"
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_artifact_manifest_id(resource_profile: str) -> str:
    """The pinned offline artifact manifest identity for a resource profile (closed catalog)."""
    if resource_profile not in _PROFILES:
        raise DeploymentPlanError("unknown_resource_profile")
    return f"{ARTIFACT_CATALOG_VERSION}/{resource_profile}"


def build_plan_document(
    *,
    ownership_label: str,
    resource_profile: str,
    capacity_assessment_hash: str,
    artifact_manifest_id: str,
) -> dict:
    """Build the closed, deterministic plan document (safe categories/counts/refs/labels only)."""
    if resource_profile not in _PROFILES:
        raise DeploymentPlanError("unknown_resource_profile")
    ownership_tag = compute_ownership_tag(ownership_label)
    resources = [
        {"kind": kind, "count": 1, "resource_ref": compute_resource_ref(ownership_label, kind, 0)}
        for kind in _PLAN_RESOURCE_KINDS
    ]
    return {
        "schema_version": DEPLOYMENT_PLAN_SCHEMA_VERSION,
        "ownership_tag": ownership_tag,
        "resource_profile": resource_profile,
        "capacity_assessment_hash": capacity_assessment_hash,
        "artifact_manifest_id": artifact_manifest_id,
        "resources": resources,
        # The plan pins ownership-bound resource CATEGORIES + generated refs derived only from
        # persisted enrollment evidence. It fabricates NO node/storage/VMID value; exact provider
        # locators are resolved by worker-only read-only discovery at apply time (a sealed, fail-
        # closed seam until integration), so the plan is not executable while discovery is sealed.
        "locator_binding": "discovered_at_apply",
    }


def deployment_plan_hash(plan_document: dict) -> str:
    """Deterministic ``sha256:`` content address of a canonicalized plan document."""
    encoded = json.dumps(plan_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def deployment_operation_fingerprint(
    deployment_id: uuid.UUID, operation_kind: str, plan_hash: str
) -> str:
    """Deterministic server key over (deployment, kind, plan hash). A retry (even after a worker
    restart) resolves to the SAME operation row, so no work is duplicated."""
    canonical = f"{deployment_id}|{operation_kind}|{plan_hash}"
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
