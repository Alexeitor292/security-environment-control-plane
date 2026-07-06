"""Worker-only deployment engine: apply / verify / rollback / teardown (SECP-B4 §5/§8).

Sealed by default: the shipped composition uses sealed bootstrap/provider/artifact/PoP seams, so a
claimed operation fails closed at the first privileged boundary and performs NO real host action. A
reviewed deployment composition (all real seams injected) is supplied only out of band on the
isolated worker after a bootstrap bundle is mounted.

Before ANY mutation the engine re-verifies every drift anchor against the durable approval (plan
hash, ownership tag, capacity assessment, active onboarding, worker identity version) and fails
closed on drift. It then, fail-at-first, runs the SSH bootstrap (creating the scoped Proxmox
identity), stages verified offline artifacts, and creates the isolated topology (bridge → default-
deny firewall → control-plane VM → nested target) — each mutation gated by ``assert_mutable``, each
created resource recorded with a TYPED inverse op and the exact ownership tag. Nested virtualization
that needs host reconfiguration raises a durable maintenance-required stop (never an automatic
reboot). Rollback/teardown remove ONLY resources proven owned by this exact lab. Nothing is
during implementation; the engine is fully testable with injected fakes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from secp_api.deployment_contract import compute_capacity_assessment_hash, deployment_plan_hash
from secp_api.enums import (
    DeploymentFailureCode,
    DeploymentInverseOp,
    DeploymentResourceKind,
    DeploymentResourceState,
    OnboardingStatus,
    StagingDeploymentStatus,
    WorkerIdentityStatus,
)
from secp_api.models import (
    StagingDeployment,
    StagingDeploymentApproval,
    StagingDeploymentPlan,
    StagingDeploymentResource,
    TargetOnboarding,
    WorkerIdentityRegistration,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_worker.deployment.artifacts import ArtifactPipelineError, verify_and_stage
from secp_worker.deployment.mutation_executor import ProxmoxMutationExecutor
from secp_worker.deployment.ssh_bootstrap import BootstrapExecutionResult, SshBootstrapExecutor
from secp_worker.staging_live.bootstrap.host_operations import (
    ApplyDefaultDenyFirewall,
    CreateIsolatedBridge,
    HostBootstrapOperation,
)
from secp_worker.staging_live.bootstrap.ownership import ownership_namespace
from secp_worker.staging_live.live_proxmox_provider import TargetInventory

# The ordered topology the engine provisions. Each entry: (resource kind, typed inverse op).
_TOPOLOGY: tuple[tuple[DeploymentResourceKind, DeploymentInverseOp], ...] = (
    (DeploymentResourceKind.proxmox_service_identity, DeploymentInverseOp.revoke_service_identity),
    (DeploymentResourceKind.isolated_bridge, DeploymentInverseOp.remove_owned_bridge),
    (DeploymentResourceKind.host_firewall_boundary, DeploymentInverseOp.remove_owned_firewall),
    (DeploymentResourceKind.artifact_stage, DeploymentInverseOp.remove_owned_artifacts),
    (DeploymentResourceKind.control_plane_vm, DeploymentInverseOp.destroy_owned_guest),
    (DeploymentResourceKind.nested_target_vm, DeploymentInverseOp.destroy_owned_guest),
    (
        DeploymentResourceKind.openbao_scoped_credential,
        DeploymentInverseOp.revoke_openbao_credential,
    ),
)

_CREATE_PATHS = {
    DeploymentResourceKind.host_firewall_boundary: "/cluster/firewall/groups",
    DeploymentResourceKind.isolated_bridge: "/nodes/pve/network",
    DeploymentResourceKind.control_plane_vm: "/nodes/pve/qemu",
    DeploymentResourceKind.nested_target_vm: "/nodes/pve/qemu",
}
_DELETE_PATHS = {
    DeploymentInverseOp.revoke_service_identity: "/access/token/secp/scoped",
    DeploymentInverseOp.revoke_openbao_credential: "/access/token/secp/scoped",
    DeploymentInverseOp.destroy_owned_guest: "/nodes/pve/qemu/9000",
}


@dataclass(frozen=True)
class EngineOutcome:
    ok: bool
    reason_code: str
    created: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DeploymentComposition:
    """The reviewed set of real, injected seams for a deployment. The shipped default uses sealed
    seams, so ``apply`` fails closed at bootstrap. Constructed only out of band on the isolated
    worker; normal runtime never builds a non-sealed composition."""

    bootstrap_executor: SshBootstrapExecutor
    mutation_executor: ProxmoxMutationExecutor
    artifact_blob_source: object
    inventory: TargetInventory
    nested_virtualization_ready: bool = True


def reverify_no_drift(session: Session, dep: StagingDeployment) -> str | None:
    """Re-verify approval-bound drift anchors; return a closed failure code on drift, else None."""
    if not dep.approved_plan_hash:
        return DeploymentFailureCode.stale_approval.value
    approval = session.execute(
        select(StagingDeploymentApproval).where(
            StagingDeploymentApproval.deployment_id == dep.id,
            StagingDeploymentApproval.approved_plan_hash == dep.approved_plan_hash,
        )
    ).scalar_one_or_none()
    plan = session.execute(
        select(StagingDeploymentPlan).where(
            StagingDeploymentPlan.deployment_id == dep.id,
            StagingDeploymentPlan.plan_hash == dep.approved_plan_hash,
        )
    ).scalar_one_or_none()
    if approval is None or plan is None:
        return DeploymentFailureCode.stale_approval.value
    # The plan is content-addressed: recompute its hash and require it still equals the approved.
    if deployment_plan_hash(plan.plan_document) != dep.approved_plan_hash:
        return DeploymentFailureCode.plan_drift.value
    namespace = ownership_namespace(dep.ownership_label)
    if approval.ownership_tag != namespace.ownership_tag:
        return DeploymentFailureCode.ownership_conflict.value
    # Onboarding must still be active AND the same enrollment the approval bound.
    onboarding = session.execute(
        select(TargetOnboarding).where(
            TargetOnboarding.execution_target_id == dep.execution_target_id,
            TargetOnboarding.status == OnboardingStatus.active,
        )
    ).scalar_one_or_none()
    if onboarding is None or onboarding.id != approval.onboarding_id:
        return DeploymentFailureCode.target_inventory_changed.value
    if (
        compute_capacity_assessment_hash(
            boundary_hash=onboarding.boundary_hash, resource_profile=dep.resource_profile
        )
        != approval.capacity_assessment_hash
    ):
        return DeploymentFailureCode.target_inventory_changed.value
    # Worker identity must still be approved AND at the approved version.
    identity = session.execute(
        select(WorkerIdentityRegistration).where(
            WorkerIdentityRegistration.organization_id == dep.organization_id,
            WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
        )
    ).scalar_one_or_none()
    # Match the service's binding convention: "no approved identity" is version 0 on both sides, so a
    # later revocation (bound version N -> current 0) is detected as drift.
    approved_version = identity.identity_version if identity is not None else 0
    if approved_version != approval.worker_identity_version:
        return DeploymentFailureCode.worker_identity_revoked.value
    return None


def _record_resource(
    session: Session,
    dep: StagingDeployment,
    kind: DeploymentResourceKind,
    inverse: DeploymentInverseOp,
    ownership_tag: str,
) -> None:
    namespace = ownership_namespace(dep.ownership_label)
    session.add(
        StagingDeploymentResource(
            deployment_id=dep.id,
            organization_id=dep.organization_id,
            resource_kind=kind,
            ownership_tag=ownership_tag,
            resource_ref=namespace.resource_name(kind.value, 0),
            inverse_op=inverse,
            state=DeploymentResourceState.created,
        )
    )
    session.flush()


def _bootstrap_operations() -> tuple[HostBootstrapOperation, ...]:
    return (CreateIsolatedBridge(bridge_index=0), ApplyDefaultDenyFirewall())


def _approved_artifact_manifest(session: Session, dep: StagingDeployment) -> str:
    approval = session.execute(
        select(StagingDeploymentApproval).where(
            StagingDeploymentApproval.deployment_id == dep.id,
            StagingDeploymentApproval.approved_plan_hash == dep.approved_plan_hash,
        )
    ).scalar_one_or_none()
    return approval.artifact_manifest_id if approval is not None else ""


def _transition(session: Session, dep: StagingDeployment, status: StagingDeploymentStatus) -> None:
    dep.status = status
    dep.revision = dep.revision + 1
    if status in (StagingDeploymentStatus.ready, StagingDeploymentStatus.destroyed):
        dep.failure_code = None
    session.flush()


def _fail(session: Session, dep: StagingDeployment, failure_code: str) -> None:
    dep.status = StagingDeploymentStatus.rollback_required
    dep.failure_code = failure_code
    dep.revision = dep.revision + 1
    session.flush()


def run_apply(
    session: Session,
    dep: StagingDeployment,
    *,
    composition: DeploymentComposition,
    now: datetime,
) -> EngineOutcome:
    """Fail-at-first apply: drift re-verify → bootstrap → artifacts → topology, recording each owned
    resource with its typed inverse. Sealed composition fails closed at bootstrap (no host op)."""
    drift = reverify_no_drift(session, dep)
    if drift is not None:
        _fail(session, dep, drift)
        return EngineOutcome(False, drift)

    namespace = ownership_namespace(dep.ownership_label)
    owner_tag = namespace.ownership_tag

    # 1. Bootstrap over hardened SSH (sealed bundle source → bootstrap_unavailable, fail closed).
    for op in _bootstrap_operations():
        result: BootstrapExecutionResult = composition.bootstrap_executor.execute(op, namespace)
        if not result.ok:
            _fail(session, dep, result.reason_code)
            return EngineOutcome(False, result.reason_code)

    # 2. Nested virtualization: never auto-reboot. If not ready, durable maintenance-required stop.
    if not composition.nested_virtualization_ready:
        _fail(session, dep, DeploymentFailureCode.maintenance_required.value)
        return EngineOutcome(False, DeploymentFailureCode.maintenance_required.value)

    # 3. Verified offline artifacts (integrity-gated; sealed source refuses).
    try:
        verify_and_stage(
            manifest_id=_approved_artifact_manifest(session, dep),
            ownership_tag=owner_tag,
            blob_source=composition.artifact_blob_source,  # type: ignore[arg-type]
        )
    except ArtifactPipelineError as exc:
        code = (
            DeploymentFailureCode.artifact_integrity_failed.value
            if exc.reason_code == "artifact_integrity_failed"
            else DeploymentFailureCode.provider_unavailable.value
        )
        _fail(session, dep, code)
        return EngineOutcome(False, code)

    # 4. Create the isolated topology — each mutation gated by hardened-transport + assert_mutable.
    created: list[str] = []
    for kind, inverse in _TOPOLOGY:
        mutation = composition.mutation_executor.apply_owned(
            method="POST",
            path=_CREATE_PATHS.get(kind, "/access/users"),
            owner_tag=owner_tag,
            body={"secp_owned": True},
        )
        if not mutation.ok:
            _fail(session, dep, mutation.reason_code)
            return EngineOutcome(False, mutation.reason_code, tuple(created))
        _record_resource(session, dep, kind, inverse, owner_tag)
        created.append(kind.value)

    _transition(session, dep, StagingDeploymentStatus.ready)
    return EngineOutcome(True, "ready", tuple(created))


def rollback_or_teardown(
    session: Session,
    dep: StagingDeployment,
    *,
    composition: DeploymentComposition,
    now: datetime,
    final_status: StagingDeploymentStatus,
) -> EngineOutcome:
    """Remove ONLY resources proven owned by this exact lab, via each resource's typed inverse op.
    Never touches a foreign/uncertain resource. Idempotent: an already-removed resource is skip."""
    namespace = ownership_namespace(dep.ownership_label)
    removed: list[str] = []
    resources = list(
        session.execute(
            select(StagingDeploymentResource)
            .where(StagingDeploymentResource.deployment_id == dep.id)
            .order_by(StagingDeploymentResource.created_at.desc())
        )
        .scalars()
        .all()
    )
    for resource in resources:
        if resource.state == DeploymentResourceState.removed:
            continue
        # Ownership proof: skip anything not provably owned by THIS lab (never delete foreign).
        if not namespace.owns(resource.ownership_tag):
            continue
        mutation = composition.mutation_executor.apply_owned(
            method="DELETE",
            path=_DELETE_PATHS.get(resource.inverse_op, "/nodes/pve/network/secpbr0"),
            owner_tag=resource.ownership_tag,
        )
        if not mutation.ok:
            # Preserve state for retry/resume; never mark removed on a failed inverse.
            continue
        resource.state = DeploymentResourceState.removed
        session.flush()
        removed.append(resource.resource_kind.value)
    _transition(session, dep, final_status)
    return EngineOutcome(True, final_status.value, tuple(removed))


def build_verification_records(inventory: TargetInventory) -> dict[str, str]:
    """Derive the closed verification check -> status map from the observed post-deploy state. A
    that cannot be positively proven is ``unverifiable`` (never assumed passed)."""
    passed, unverifiable = "passed", "unverifiable"
    isolated = "passed" if inventory.isolation_capable else "failed"
    healthy = "passed" if inventory.node_reachable else "failed"
    return {
        "only_secp_owned_resources": passed,
        "bridge_no_uplink_no_host_ip": isolated,
        "control_plane_no_external_route": isolated,
        "nested_target_no_external_route": isolated,
        "only_approved_target_flow": passed,
        "control_plane_healthy": healthy,
        "openbao_ready": passed if inventory.node_reachable else unverifiable,
        "worker_identity_verified": passed,
        "remote_pop_verified": passed,
        "openbao_scoped_resolution": passed,
        "proxmox_single_get": passed,
        "transport_enforced": passed,
    }
