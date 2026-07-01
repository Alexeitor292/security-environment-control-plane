"""Provisioning manifest services (ADR-011).

Generate immutable, secret-free provisioning manifests from an approved,
target-bound plan. Every precondition is enforced; generation refuses (audited) on
any failure. This is a pure control-plane operation: NO runner, provider client,
OpenTofu, subprocess, network, or secret resolution is involved.
"""

from __future__ import annotations

import uuid
from datetime import UTC
from typing import NoReturn

from secp_scenario_schema import content_hash, validate_definition
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    Permission,
    PlanStatus,
    ProvisioningOperationKind,
    ReservationStatus,
    TargetStatus,
)
from secp_api.errors import NotFoundError, ValidationFailedError
from secp_api.models import (
    DeploymentPlan,
    EnvironmentVersion,
    NetworkReservation,
    ProvisioningManifest,
)
from secp_api.provisioning_scope import (
    ProvisioningScopePolicy,
    provisioning_scope_policy_hash,
    validate_provisioning_scope,
)
from secp_api.services.targets import get_target

MANIFEST_VERSION = "secp-002b-0/v1"

# Proxmox: qemu guests are VMs; lxc guests are containers.
_CONTAINER_KINDS = {"sensor"}


def _audit_refusal(actor: Principal, plan: DeploymentPlan, reason: str) -> None:
    from secp_api.db import session_scope

    with session_scope() as s:
        audit.record(
            s,
            action=AuditAction.manifest_generation_refused,
            resource_type="deployment_plan",
            resource_id=plan.id,
            organization_id=plan.organization_id,
            actor=str(actor.user_id),
            outcome="denied",
            data={"reason": reason},
        )


def _refuse(actor: Principal, plan: DeploymentPlan, reason: str) -> NoReturn:
    _audit_refusal(actor, plan, reason)
    raise ValidationFailedError(reason)


def _resolve_onboarding_binding(session, actor, plan, target) -> dict:
    """Verify the plan's onboarding bindings match the current single active onboarding.

    Returns the durable binding dict for the manifest. Fails closed on missing/ambiguous
    onboarding, boundary/evidence-hash drift, verification-level change, or a stale/altered
    approved preflight (SECP-002B-1B-0, ADR-014).
    """
    from secp_api.models import TargetPreflight
    from secp_api.services.onboarding import (
        active_onboarding_for_target,
        onboarding_drift,
        recompute_evidence_hash,
    )

    if plan.target_onboarding_id is None:
        _refuse(actor, plan, "target-bound plan has no onboarding binding; regenerate the plan")
    try:
        onboarding = active_onboarding_for_target(session, target.id)
    except Exception:
        _refuse(actor, plan, "ambiguous active onboarding for target; fail closed")
    if onboarding is None:
        _refuse(actor, plan, "target has no active onboarding; onboard the target first")
    if onboarding.id != plan.target_onboarding_id:
        _refuse(actor, plan, "plan onboarding id does not match the active onboarding")
    if onboarding.approved_boundary_hash != plan.onboarding_boundary_hash:
        _refuse(actor, plan, "onboarding boundary hash has drifted since plan approval")
    if str(onboarding.approved_preflight_id) != str(plan.approved_preflight_id):
        _refuse(actor, plan, "approved preflight id has changed since plan approval")
    if onboarding.approved_preflight_evidence_hash != plan.approved_preflight_evidence_hash:
        _refuse(actor, plan, "approved preflight evidence hash has changed since plan approval")
    if onboarding.approved_verification_level != plan.onboarding_verification_level:
        _refuse(actor, plan, "onboarding verification level has changed since plan approval")
    drift = onboarding_drift(onboarding, target)
    if drift is not None:
        _refuse(actor, plan, f"onboarding approval invalidated: {drift}")
    pf = session.get(TargetPreflight, onboarding.approved_preflight_id)
    if pf is None or recompute_evidence_hash(pf) != onboarding.approved_preflight_evidence_hash:
        _refuse(actor, plan, "approved preflight evidence is missing or altered")
    # Toolchain provenance binding (ADR-014 §4): the approved preflight must have been
    # collected against the current active toolchain profile (which the plan also pins).
    from secp_api.services.onboarding import preflight_toolchain_matches_active

    tc_reason = preflight_toolchain_matches_active(session, target, pf)
    if tc_reason is not None:
        _refuse(actor, plan, f"onboarding toolchain provenance drift: {tc_reason}")
    # Effective execution boundary (ADR-014 §2): recompute from the active onboarding +
    # current target scope and require exact agreement with the plan's bound boundary. Fail
    # closed if it is empty, absent on the plan, broadened, or otherwise changed.
    from secp_api.onboarding import (
        OnboardingBoundarySpec,
        effective_boundary_hash,
        effective_boundary_is_empty,
    )
    from secp_api.onboarding import effective_boundary as compute_effective_boundary

    spec = OnboardingBoundarySpec.model_validate(onboarding.declared_boundary)
    eff = compute_effective_boundary(spec, target.scope_policy or {})
    if effective_boundary_is_empty(eff):
        _refuse(actor, plan, "effective execution boundary is empty; re-onboard the target")
    eff_hash = effective_boundary_hash(eff)
    if plan.effective_boundary != eff:
        _refuse(actor, plan, "effective execution boundary has drifted since plan approval")
    if plan.effective_boundary_hash is None:
        _refuse(actor, plan, "approved plan has no effective-boundary binding; regenerate the plan")
    if eff_hash != plan.effective_boundary_hash:
        _refuse(actor, plan, "effective execution boundary has drifted since plan approval")
    return {
        "target_onboarding_id": onboarding.id,
        "onboarding_boundary_hash": onboarding.approved_boundary_hash,
        "approved_preflight_id": onboarding.approved_preflight_id,
        "approved_preflight_evidence_hash": onboarding.approved_preflight_evidence_hash,
        "onboarding_verification_level": onboarding.approved_verification_level,
        "effective_boundary": eff,
        "effective_boundary_hash": eff_hash,
    }


def _finalized_reservations(session: Session, plan: DeploymentPlan) -> list[NetworkReservation]:
    return list(
        session.execute(
            select(NetworkReservation)
            .where(
                NetworkReservation.execution_target_id == plan.execution_target_id,
                NetworkReservation.exercise_id == plan.exercise_id,
                NetworkReservation.status == ReservationStatus.reserved,
            )
            .order_by(NetworkReservation.cidr)
        )
        .scalars()
        .all()
    )


def _cidr_in_policy(cidr: str, policy: ProvisioningScopePolicy) -> bool:
    import ipaddress

    net = ipaddress.ip_network(cidr, strict=True)
    for allowed in policy.allowed_cidr_reservations:
        block = ipaddress.ip_network(allowed, strict=True)
        if net.version == block.version and net.subnet_of(block):  # type: ignore[arg-type]
            return True
    return False


def _build_topology(
    definition, reservations_by_team: dict[str, str], policy: ProvisioningScopePolicy
) -> tuple[list[dict], dict[str, int]]:
    """Build a secret-free desired topology bounded by the scope policy.

    Every node gets a deterministic vmid inside vmid_range and explicit
    vcpu/memory_mb/disk_gb from the approved node_sizing profile.  Missing
    sizing data fails closed rather than applying hidden defaults.
    """
    spec = definition.spec
    nodes_per_team = spec.roles
    distinct_images = {role.image for role in nodes_per_team}
    missing_templates = distinct_images - set(policy.allowed_templates)
    if missing_templates:
        raise ValidationFailedError(
            "desired images are not in the scope policy allowed_templates",
            errors=[f"template(s) not allowed: {sorted(missing_templates)}"],
        )
    # Fail closed: every image used must have an explicit sizing profile.
    missing_sizing = distinct_images - set(policy.node_sizing)
    if missing_sizing:
        raise ValidationFailedError(
            "node_sizing profile missing for image(s); no silent defaults are applied",
            errors=[f"no sizing for image '{img}'" for img in sorted(missing_sizing)],
        )

    topology: list[dict] = []
    total_vms = 0
    total_containers = 0
    total_vcpu = 0
    total_memory_mb = 0
    total_disk_gb = 0
    # Deterministic vmid assignment: start from vmid_range.start, increment per node.
    vmid_counter = policy.vmid_range.start
    node_pool = policy.allowed_nodes
    for team_index in range(spec.teams.count):
        team_ref = f"team{team_index + 1}"
        cidr = reservations_by_team.get(team_ref)
        if cidr is None:
            raise ValidationFailedError(f"no finalized reservation for {team_ref}")
        networks = [
            {
                "name": net.name,
                "cidr": cidr,
                "bridge": policy.allowed_bridges[0],
                "isolated": True,
            }
            for net in spec.networks
        ]
        nodes = []
        for i, role in enumerate(nodes_per_team):
            for c in range(role.count):
                is_container = role.kind.value in _CONTAINER_KINDS
                sizing = policy.node_sizing[role.image]
                if vmid_counter > policy.vmid_range.end:
                    raise ValidationFailedError(
                        f"vmid_range [{policy.vmid_range.start}, {policy.vmid_range.end}] "
                        "is exhausted; reduce the topology or widen the vmid_range",
                    )
                vmid = vmid_counter
                vmid_counter += 1
                if is_container:
                    total_containers += 1
                else:
                    total_vms += 1
                total_vcpu += sizing.vcpu
                total_memory_mb += sizing.memory_mb
                total_disk_gb += sizing.disk_gb
                nodes.append(
                    {
                        "ref": f"{role.name}-{c}" if role.count > 1 else role.name,
                        "role": role.name,
                        "guest_kind": "container" if is_container else "vm",
                        "image": role.image,
                        "node": node_pool[(team_index + i) % len(node_pool)],
                        "storage": policy.allowed_storage[0],
                        "vmid": vmid,
                        "vcpu": sizing.vcpu,
                        "memory_mb": sizing.memory_mb,
                        "disk_gb": sizing.disk_gb,
                    }
                )
        topology.append({"team_ref": team_ref, "networks": networks, "nodes": nodes})

    totals = {
        "teams": spec.teams.count,
        "vms": total_vms,
        "containers": total_containers,
        "total_vcpu": total_vcpu,
        "total_memory_mb": total_memory_mb,
        "total_disk_gb": total_disk_gb,
    }
    return topology, totals


def _enforce_limits(totals: dict[str, int], policy: ProvisioningScopePolicy) -> None:
    problems = []
    if totals["teams"] > policy.max_teams:
        problems.append(f"teams {totals['teams']} exceeds max_teams {policy.max_teams}")
    if totals["vms"] > policy.max_vms:
        problems.append(f"vms {totals['vms']} exceeds max_vms {policy.max_vms}")
    if totals["containers"] > policy.max_containers:
        problems.append(
            f"containers {totals['containers']} exceeds max_containers {policy.max_containers}"
        )
    if totals["total_vcpu"] > policy.max_total_vcpu:
        problems.append(
            f"total_vcpu {totals['total_vcpu']} exceeds max_total_vcpu {policy.max_total_vcpu}"
        )
    if totals["total_memory_mb"] > policy.max_total_memory_mb:
        problems.append(
            f"total_memory_mb {totals['total_memory_mb']} exceeds "
            f"max_total_memory_mb {policy.max_total_memory_mb}"
        )
    if totals["total_disk_gb"] > policy.max_total_disk_gb:
        problems.append(
            f"total_disk_gb {totals['total_disk_gb']} exceeds "
            f"max_total_disk_gb {policy.max_total_disk_gb}"
        )
    if problems:
        raise ValidationFailedError("desired topology exceeds blast-radius limits", errors=problems)


def generate_manifest(
    session: Session, actor: Principal, plan_id: uuid.UUID
) -> ProvisioningManifest:
    """Generate an immutable, secret-free manifest from an approved target-bound plan."""
    actor.require(Permission.provisioning_manage)

    plan = session.get(DeploymentPlan, plan_id)
    if plan is None:
        raise NotFoundError(f"deployment plan {plan_id} not found")
    actor.require_org(plan.organization_id)

    # 1. Plan must be approved (or already applied).
    if plan.status not in (PlanStatus.approved, PlanStatus.applied):
        _refuse(actor, plan, f"plan is '{plan.status.value}', not approved")
    # 2. Manifests are only for target-bound plans (simulator has no manifest).
    if plan.execution_target_id is None:
        _refuse(actor, plan, "plan is not bound to an execution target")

    target = get_target(session, actor, plan.execution_target_id)
    # 3. Target must be active.
    if target.status != TargetStatus.active:
        _refuse(actor, plan, f"execution target is '{target.status.value}', not active")
    # 4. Target config hash must not have drifted from the pinned value.
    if plan.target_config_hash != target.config_hash:
        _refuse(actor, plan, "target configuration hash has drifted from the approved plan")

    # 4b. Plan must carry a scope-policy hash (pre-migration plans are refused: fail closed).
    if plan.target_scope_policy_hash is None:
        _refuse(
            actor,
            plan,
            "approved plan has no scope-policy hash; "
            "regenerate the plan and obtain fresh approval to provision",
        )

    # 5. Strict provisioning scope policy.
    try:
        policy = validate_provisioning_scope(target.scope_policy)
    except ValidationFailedError as exc:
        _refuse(actor, plan, f"invalid provisioning scope policy: {exc.message}")
        raise  # unreachable (keeps type-checkers happy)

    # 5b. Current scope policy must not have changed since plan approval.
    current_scope_hash = provisioning_scope_policy_hash(target.scope_policy)
    if current_scope_hash != plan.target_scope_policy_hash:
        _refuse(
            actor,
            plan,
            "target scope_policy has changed since plan approval "
            "(scope-policy hash mismatch); "
            "regenerate the plan and obtain fresh approval before generating a manifest",
        )

    # 5c. Toolchain-profile binding (SECP-002B-1A). Optional: a plan with no pinned
    #     profile keeps the fake-runner/Simulator behaviour (the real-lab gate fails
    #     closed later). When pinned, the profile must still exist, be active, and its
    #     content hash must match the plan's pinned hash (fail closed on drift).
    from secp_api.enums import ToolchainProfileStatus
    from secp_api.models import ToolchainProfile

    toolchain_profile_id = None
    toolchain_profile_hash = None
    if plan.toolchain_profile_id is not None:
        toolchain = session.get(ToolchainProfile, plan.toolchain_profile_id)
        if toolchain is None or toolchain.status != ToolchainProfileStatus.active:
            _refuse(actor, plan, "pinned toolchain profile is missing or not active")
        if toolchain.content_hash != plan.toolchain_profile_hash:
            _refuse(
                actor,
                plan,
                "toolchain profile has drifted since plan approval "
                "(profile hash mismatch); regenerate the plan and obtain fresh approval",
            )
        toolchain_profile_id = toolchain.id
        toolchain_profile_hash = toolchain.content_hash

    # 5d. Onboarding binding (SECP-002B-1B-0, ADR-014). The plan's onboarding bindings must
    #     exactly match the single active onboarding for the target and its pinned approved
    #     preflight evidence. Fail closed on any mismatch/ambiguity/drift.
    onboarding_binding = _resolve_onboarding_binding(session, actor, plan, target)

    # 6. Valid, finalized, in-policy, same-org reservations.
    version = session.get(EnvironmentVersion, plan.environment_version_id)
    if version is None:
        raise NotFoundError("environment version not found for plan")
    definition = validate_definition(version.spec)
    teams = definition.spec.teams.count

    reservations = _finalized_reservations(session, plan)
    if len(reservations) < teams:
        _refuse(
            actor,
            plan,
            f"missing finalized reservations: need {teams}, found {len(reservations)}",
        )
    reservations_by_team: dict[str, str] = {}
    for res in reservations:
        if res.organization_id != plan.organization_id:
            _refuse(actor, plan, "reservation belongs to a different organization")
        if not _cidr_in_policy(res.cidr, policy):
            _refuse(actor, plan, f"reservation {res.cidr} is outside the scope policy")
        reservations_by_team[res.team_ref] = res.cidr
    missing_team_refs = {f"team{i + 1}" for i in range(teams)} - set(reservations_by_team)
    if missing_team_refs:
        _refuse(actor, plan, f"no finalized reservation for teams {sorted(missing_team_refs)}")

    # 7. Build secret-free desired topology and enforce blast-radius limits.
    topology, totals = _build_topology(definition, reservations_by_team, policy)
    _enforce_limits(totals, policy)

    content = {
        "manifest_version": MANIFEST_VERSION,
        "deployment_plan_id": str(plan.id),
        "execution_target_id": str(target.id),
        "target_config_hash": target.config_hash,
        "target_scope_policy_hash": current_scope_hash,
        "toolchain_profile_id": str(toolchain_profile_id) if toolchain_profile_id else None,
        "toolchain_profile_hash": toolchain_profile_hash,
        "onboarding": {
            "target_onboarding_id": str(onboarding_binding["target_onboarding_id"]),
            "onboarding_boundary_hash": onboarding_binding["onboarding_boundary_hash"],
            "approved_preflight_id": str(onboarding_binding["approved_preflight_id"]),
            "approved_preflight_evidence_hash": onboarding_binding[
                "approved_preflight_evidence_hash"
            ],
            "verification_level": onboarding_binding["onboarding_verification_level"],
            "effective_boundary": onboarding_binding["effective_boundary"],
            "effective_boundary_hash": onboarding_binding["effective_boundary_hash"],
        },
        "plugin_name": target.plugin_name,
        "teams": teams,
        "scope_policy": policy.model_dump(),
        "resource_limits": {
            "max_teams": policy.max_teams,
            "max_vms": policy.max_vms,
            "max_containers": policy.max_containers,
            "max_total_vcpu": policy.max_total_vcpu,
            "max_total_memory_mb": policy.max_total_memory_mb,
            "max_total_disk_gb": policy.max_total_disk_gb,
        },
        "reservations": [
            {"team_ref": t, "cidr": c} for t, c in sorted(reservations_by_team.items())
        ],
        "topology": topology,
        "requested_totals": totals,
        # Automated, declarative deployment contract (SECP-002B-1B-0, ADR-014): SECP
        # creates the scenario resources automatically inside the declared boundary; no
        # manual per-scenario guest/network/address/storage creation is required, and no
        # pre-existing user assets are adopted in standard mode.
        "deployment": {
            "mode": "automated",
            "provisioning_model": "declarative",
            "scenario_resources_created_by_secp": True,
            "manual_pre_creation_required": False,
            "user_provided_preexisting_assets": [],
            "subject_to_approval": True,
            "subject_to_scope_policy": True,
        },
    }

    manifest = ProvisioningManifest(
        organization_id=plan.organization_id,
        deployment_plan_id=plan.id,
        execution_target_id=target.id,
        target_config_hash=target.config_hash,
        target_scope_policy_hash=current_scope_hash,
        toolchain_profile_id=toolchain_profile_id,
        toolchain_profile_hash=toolchain_profile_hash,
        target_onboarding_id=onboarding_binding["target_onboarding_id"],
        onboarding_boundary_hash=onboarding_binding["onboarding_boundary_hash"],
        approved_preflight_id=onboarding_binding["approved_preflight_id"],
        approved_preflight_evidence_hash=onboarding_binding["approved_preflight_evidence_hash"],
        onboarding_verification_level=onboarding_binding["onboarding_verification_level"],
        effective_boundary=onboarding_binding["effective_boundary"],
        effective_boundary_hash=onboarding_binding["effective_boundary_hash"],
        content=content,
        content_hash=content_hash(content),
        validated_at=_now(),
        created_by=actor.user_id,
    )
    session.add(manifest)
    session.flush()

    # Per-kind ProvisioningOperation records are created on first call to
    # run_provisioning (not here).  Each kind (dry_run, apply, destroy) gets
    # its own durable record with an idempotency key that includes the kind.

    audit.record(
        session,
        action=AuditAction.manifest_generated,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=plan.organization_id,
        actor=str(actor.user_id),
        data={"content_hash": manifest.content_hash, "teams": teams, "totals": totals},
    )
    audit.record(
        session,
        action=AuditAction.manifest_validated,
        resource_type="provisioning_manifest",
        resource_id=manifest.id,
        organization_id=plan.organization_id,
        actor=str(actor.user_id),
        data={"content_hash": manifest.content_hash},
    )
    return manifest


def get_manifest(
    session: Session, actor: Principal, manifest_id: uuid.UUID
) -> ProvisioningManifest:
    actor.require(Permission.provisioning_read)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise NotFoundError(f"provisioning manifest {manifest_id} not found")
    actor.require_org(manifest.organization_id)
    return manifest


def manifest_idempotency_key(content_hash_value: str, kind: ProvisioningOperationKind) -> str:
    import hashlib

    digest = hashlib.sha256(f"{content_hash_value}:{kind.value}".encode()).hexdigest()
    return f"prov:{digest}"


def _now():
    from datetime import datetime

    return datetime.now(UTC)
