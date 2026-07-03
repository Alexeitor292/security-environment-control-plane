"""Provider-neutral disposable staging-lab compiler (SECP-002B-1B-9).

Control-plane only and side-effect free. This module transforms an approved, logical
staging-lab specification into an immutable, deterministic logical plan. It contacts nothing,
imports no worker/provider/transport/secret code, and stores no real infrastructure value.

The plan describes *logical intent only*: an isolated host-only network, a self-contained
staging control plane (staging API + database + worker), one disposable nested Proxmox target,
exactly one target-facing read-only connection policy, a known-clean checkpoint + rollback
intent, and a teardown intent — every resource carrying the lab's immutable ownership label.

No infrastructure is created by compiling a plan. A later, separately reviewed adapter PR is
required for any real provisioning; a staging-lab plan approval is NOT a
:class:`LiveReadAuthorization` and never authorizes live read-only collection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secp_api.enums import (
    StagingLabProfile,
    StagingLabPurpose,
    StagingNetworkIntent,
    StagingResourceClass,
    StagingRollbackPolicy,
)

# The plan-shape/contract version. A change here changes every plan hash by construction.
STAGING_LAB_PLAN_CONTRACT_VERSION = "secp-002b-1b-9/plan/v1"

# The three mandatory self-contained control-plane components (SECP-002B-1B-8).
STAGING_CONTROL_PLANE_COMPONENTS = ("staging_api", "staging_database", "staging_worker")

# Logical resource kinds emitted by the compiler (provider-neutral).
RESOURCE_ISOLATED_NETWORK = "isolated_target_facing_network"
RESOURCE_CONTROL_PLANE = "self_contained_staging_control_plane"
RESOURCE_NESTED_TARGET = "disposable_nested_proxmox_target"
RESOURCE_CONNECTION_POLICY = "target_facing_connection_policy"
RESOURCE_CHECKPOINT = "known_clean_checkpoint"
RESOURCE_TEARDOWN = "teardown_intent"

# Bounded logical resource classes (never raw host CPU/RAM/disk values).
_RESOURCE_CLASS_BOUNDS = {
    StagingResourceClass.small_lab: {
        "logical_size": "small",
        "max_nested_guests_class": "minimal",
        "headroom_requirement": "verified_spare_headroom_required",
    },
    StagingResourceClass.medium_lab: {
        "logical_size": "medium",
        "max_nested_guests_class": "modest",
        "headroom_requirement": "verified_spare_headroom_required",
    },
}


class StagingLabPlanError(Exception):
    """Raised when a staging-lab specification cannot be compiled into a safe logical plan.

    Messages are generic and provider-neutral; they never echo real infrastructure values
    (none exist in a spec) and carry a stable ``reason_code`` for auditing.
    """

    def __init__(self, reason_code: str, message: str | None = None) -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class StagingLabSpec:
    """Safe, logical intent for a disposable staging lab. No real infrastructure values.

    Provider-neutral. Every field is either a controlled enum, a boolean intent flag, a small
    bounded count, or an opaque logical label/profile id — never an endpoint, host, IP,
    bridge/VNet name, VMID, storage id, certificate, credential, token, secret ref, or artifact
    URL/checksum.
    """

    ownership_label: str
    purpose: StagingLabPurpose = StagingLabPurpose.disposable_readonly_staging
    profile: StagingLabProfile = StagingLabProfile.nested_proxmox
    network_intent: StagingNetworkIntent = StagingNetworkIntent.host_only_no_uplink
    resource_class: StagingResourceClass = StagingResourceClass.small_lab
    rollback_policy: StagingRollbackPolicy = StagingRollbackPolicy.revert_to_known_clean_checkpoint
    bootstrap_artifact_profile_id: str = ""
    # Blast-radius / self-containment intent flags (SECP-002B-1B-8 constraints).
    self_contained_control_plane: bool = True
    substrate_approved: bool = False
    nested_target_count: int = 1
    target_facing_connection_count: int = 1
    standing_authorization: bool = False
    # Extra guard: any component the caller tries to reuse from production is rejected.
    reuses_production_components: tuple[str, ...] = field(default_factory=tuple)


_LABEL_MAX = 120
_ARTIFACT_PROFILE_MAX = 120


def _validate_spec(spec: StagingLabSpec) -> None:
    """Fail closed unless the spec is a safe, self-contained, single-target staging lab."""
    label = (spec.ownership_label or "").strip()
    if not label:
        raise StagingLabPlanError("ownership_label_missing", "an ownership label is required")
    if len(label) > _LABEL_MAX:
        raise StagingLabPlanError("ownership_label_invalid", "ownership label is too long")

    if spec.purpose != StagingLabPurpose.disposable_readonly_staging:
        raise StagingLabPlanError("unsupported_purpose")
    if spec.profile != StagingLabProfile.nested_proxmox:
        raise StagingLabPlanError("unsupported_profile")

    if not spec.substrate_approved:
        raise StagingLabPlanError(
            "unapproved_substrate", "the substrate target is not approved for staging"
        )
    if spec.network_intent != StagingNetworkIntent.host_only_no_uplink:
        raise StagingLabPlanError(
            "shared_or_production_network_rejected",
            "only a host-only, no-uplink network intent is permitted",
        )
    if not spec.self_contained_control_plane:
        raise StagingLabPlanError(
            "production_control_plane_reuse_rejected",
            "the staging control plane must be self-contained (staging API + database + worker)",
        )
    if spec.reuses_production_components:
        raise StagingLabPlanError(
            "production_control_plane_reuse_rejected",
            "no production API/database/worker component may be reused",
        )
    if spec.nested_target_count != 1:
        raise StagingLabPlanError(
            "nested_target_count_invalid", "exactly one nested target is permitted"
        )
    if spec.target_facing_connection_count != 1:
        raise StagingLabPlanError(
            "target_facing_connection_count_invalid",
            "exactly one target-facing connection is permitted",
        )
    if spec.standing_authorization:
        raise StagingLabPlanError(
            "standing_authorization_rejected",
            "a standing or auto-renewing live-read authorization may not be associated",
        )
    if spec.resource_class not in _RESOURCE_CLASS_BOUNDS:
        raise StagingLabPlanError("resource_class_invalid")
    artifact = (spec.bootstrap_artifact_profile_id or "").strip()
    if not artifact:
        raise StagingLabPlanError(
            "bootstrap_artifact_profile_missing",
            "an approved bootstrap-artifact profile id is required",
        )
    if len(artifact) > _ARTIFACT_PROFILE_MAX or "://" in artifact or "/" in artifact:
        # A profile id is an opaque logical label, never a path/URL.
        raise StagingLabPlanError(
            "bootstrap_artifact_profile_invalid",
            "the bootstrap-artifact profile id must be an opaque logical label, not a path/URL",
        )


def _resource(kind: str, ownership_label: str, **attrs: object) -> dict:
    """A logical plan resource. Every resource carries the immutable lab ownership label."""
    resource: dict[str, object] = {"kind": kind, "owner": ownership_label}
    resource.update(attrs)
    return resource


def compile_staging_plan(spec: StagingLabSpec) -> dict:
    """Compile a validated spec into an immutable, deterministic logical plan.

    Raises :class:`StagingLabPlanError` (fail-closed) for any spec that reuses a production
    control-plane service, attaches to a shared/production network, requests more than one
    target-facing network or nested target, omits the self-contained control plane, associates a
    standing authorization, omits ownership labeling, or uses an unapproved substrate.

    The result is canonical: equivalent specs yield an equivalent plan (and, via
    :func:`staging_plan_hash`, an equivalent hash). No infrastructure is created.
    """
    _validate_spec(spec)
    label = spec.ownership_label.strip()
    artifact = spec.bootstrap_artifact_profile_id.strip()

    resources = [
        _resource(
            RESOURCE_ISOLATED_NETWORK,
            label,
            network_intent=spec.network_intent.value,
            uplink="none",
            default_gateway="none",
            dns="none",
            reachable_networks="none",
        ),
        _resource(
            RESOURCE_CONTROL_PLANE,
            label,
            components=list(STAGING_CONTROL_PLANE_COMPONENTS),
            self_contained=True,
            uses_production_control_plane=False,
            uses_production_database=False,
            local_control_plane_transport="loopback_or_internal_container_network",
        ),
        _resource(
            RESOURCE_NESTED_TARGET,
            label,
            profile=spec.profile.value,
            disposable=True,
            recoverable_from_known_clean=True,
        ),
        _resource(
            RESOURCE_CONNECTION_POLICY,
            label,
            source="staging_worker",
            destination="nested_target_read_only_api",
            direction="worker_to_target",
            access="read_only",
            count=1,
        ),
        _resource(
            RESOURCE_CHECKPOINT,
            label,
            rollback_policy=spec.rollback_policy.value,
            known_clean=True,
        ),
        _resource(
            RESOURCE_TEARDOWN,
            label,
            preserves_audit_trail=True,
        ),
    ]

    plan = {
        "plan_contract_version": STAGING_LAB_PLAN_CONTRACT_VERSION,
        "purpose": spec.purpose.value,
        "profile": spec.profile.value,
        "network_intent": spec.network_intent.value,
        "resource_class": spec.resource_class.value,
        "resource_class_bounds": dict(_RESOURCE_CLASS_BOUNDS[spec.resource_class]),
        "bootstrap_artifact_profile_id": artifact,
        "bootstrap": {
            "source": "operator_approved_prestaged_offline_artifacts",
            "post_isolation_internet_dependency": "forbidden",
        },
        "ownership_label": label,
        "rollback_policy": spec.rollback_policy.value,
        "simulation_only": True,
        "creates_infrastructure": False,
        "resources": resources,
    }
    return canonicalize_plan(plan)


def canonicalize_plan(plan: dict) -> dict:
    """Return a canonical copy of a plan: resources sorted by (kind, owner), keys sorted on dump.

    Sorting the resource list makes the plan order-independent so equivalent inputs hash equal.
    """
    resources = sorted(
        plan.get("resources", []), key=lambda r: (r.get("kind", ""), r.get("owner", ""))
    )
    canonical = dict(plan)
    canonical["resources"] = resources
    return canonical


def staging_plan_hash(plan: dict) -> str:
    """Deterministic ``sha256:`` hash of the canonical plan (ADR-002 canonical serializer)."""
    from secp_scenario_schema import content_hash

    return content_hash(canonicalize_plan(plan))
