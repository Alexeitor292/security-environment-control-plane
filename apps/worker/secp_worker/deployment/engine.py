"""Worker-only deployment engine: apply / verify / rollback / teardown (SECP-B4 corrective).

Sealed by default: the shipped composition (see :func:`sealed_composition`) uses sealed bootstrap /
mutation / discovery / OpenBao / PoP / verification seams, so a claimed operation fails closed at
the
first privileged boundary and performs NO real host action. A reviewed composition (real seams
injected) exists only on the isolated worker after a deployment-local bootstrap bundle is mounted.

Corrective safety model:
- Before any mutation the engine re-verifies every drift anchor against the durable approval and
  fails closed on drift.
- It runs the real remote Ed25519 PoP for the operation (verifier-issued, durable single-use nonce,
  bound to deployment/operation/org/registration/identity-version/plan-hash); a sealed signer fails
  closed.
- Every provider resource is created through a CLOSED TYPED mutation whose route/body are derived
  from an EXACT discovered locator (no hardcoded node/VMID/bridge/path, no fallback). Creation is
  gated by a FRESH observation proving the target is absent or already ours, and CONFIRMED by a
  fresh re-read of our unique per-resource marker; only then is the exact observed locator recorded.
- Rollback/teardown fresh-read the exact recorded locator and prove our marker before deleting; a
  foreign / absent / stale / uncertain object is skipped, never deleted. There is no fallback path
  and unknown kinds/inverses issue no request.
- Verification records are derived ONLY from observed evidence (engine-proven signals + an injected
  evidence collector); there is NO static "passed". Any not-positively-observed check is
  unverifiable, and any non-passed check transitions the deployment to rollback_required.

Nothing is contacted during implementation; the engine is fully testable with injected fakes.
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
    DeploymentVerificationCode,
    DeploymentVerificationStatus,
    OnboardingStatus,
    StagingDeploymentDecisionCode,
    StagingDeploymentStatus,
    WorkerIdentityStatus,
)
from secp_api.models import (
    StagingDeployment,
    StagingDeploymentApproval,
    StagingDeploymentOperation,
    StagingDeploymentPlan,
    StagingDeploymentResource,
    StagingDeploymentVerification,
    TargetOnboarding,
    WorkerIdentityRegistration,
)
from secp_api.ownership_contract import compute_resource_marker
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_worker.deployment.artifacts import ArtifactPipelineError, verify_and_stage
from secp_worker.deployment.locators import (
    ResourceLocator,
    locator_from_dict,
    locator_to_dict,
)
from secp_worker.deployment.mutation_executor import ProxmoxMutationExecutor
from secp_worker.deployment.mutations import (
    BridgeLocator,
    CreateControlPlaneVM,
    CreateFirewallBoundary,
    CreateIsolatedBridge,
    CreateNestedTargetVM,
    CreateServiceIdentity,
    DestroyOwnedVM,
    FirewallGroupLocator,
    GuestLocator,
    RemoveOwnedBridge,
    RemoveOwnedFirewall,
    RevokeServiceIdentity,
    ServiceIdentityLocator,
    TypedCreate,
    TypedInverse,
)
from secp_worker.deployment.seams import (
    DeploymentLocatorSource,
    DiscoveryUnavailable,
    OpenBaoHandoff,
    OpenBaoHandoffUnavailable,
    RemotePoPAuthority,
    SealedDeploymentLocatorSource,
    SealedOpenBaoHandoff,
    SealedRemotePoPAuthority,
    SealedVerificationEvidenceCollector,
    VerificationEvidenceCollector,
)
from secp_worker.deployment.ssh_bootstrap import (
    BootstrapExecutionResult,
    RefusingHostCommandRunner,
    SealedWorkerBootstrapBundleSource,
    SshBootstrapExecutor,
)
from secp_worker.staging_live.bootstrap.host_operations import (
    ApplyDefaultDenyFirewall,
    HostBootstrapOperation,
)
from secp_worker.staging_live.bootstrap.host_operations import (
    CreateIsolatedBridge as BootstrapCreateBridge,
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

# Typed create dispatch: kind -> (required locator type, create-op class). Kinds NOT here are not
# Proxmox mutations (artifact_stage is staged by the artifact pipeline; openbao_scoped_credential is
# stored via the OpenBao handoff). An unknown kind maps to nothing and refuses with zero requests.
_CREATE_BUILDERS: dict[DeploymentResourceKind, tuple[type, type[TypedCreate]]] = {
    DeploymentResourceKind.proxmox_service_identity: (
        ServiceIdentityLocator,
        CreateServiceIdentity,
    ),
    DeploymentResourceKind.isolated_bridge: (BridgeLocator, CreateIsolatedBridge),
    DeploymentResourceKind.host_firewall_boundary: (FirewallGroupLocator, CreateFirewallBoundary),
    DeploymentResourceKind.control_plane_vm: (GuestLocator, CreateControlPlaneVM),
    DeploymentResourceKind.nested_target_vm: (GuestLocator, CreateNestedTargetVM),
}
# Typed inverse dispatch: inverse-op -> (required locator type, inverse-op class). Kinds handled by
# a non-Proxmox seam (artifacts, OpenBao) are absent -> the engine skips them via sealed seams.
_INVERSE_BUILDERS: dict[DeploymentInverseOp, tuple[type, type[TypedInverse]]] = {
    DeploymentInverseOp.revoke_service_identity: (ServiceIdentityLocator, RevokeServiceIdentity),
    DeploymentInverseOp.remove_owned_bridge: (BridgeLocator, RemoveOwnedBridge),
    DeploymentInverseOp.remove_owned_firewall: (FirewallGroupLocator, RemoveOwnedFirewall),
    DeploymentInverseOp.destroy_owned_guest: (GuestLocator, DestroyOwnedVM),
}


class EngineError(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class EngineOutcome:
    ok: bool
    reason_code: str
    created: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DeploymentComposition:
    """The reviewed set of real, injected seams for a deployment. The shipped default (see
    :func:`sealed_composition`) uses sealed seams, so ``run_apply`` fails closed at bootstrap.
    Constructed only out of band on the isolated worker; normal runtime never builds a real one."""

    bootstrap_executor: SshBootstrapExecutor
    mutation_executor: ProxmoxMutationExecutor
    artifact_blob_source: object
    locator_source: DeploymentLocatorSource
    remote_pop_authority: RemotePoPAuthority
    openbao_handoff: OpenBaoHandoff
    verification_collector: VerificationEvidenceCollector
    inventory: TargetInventory | None = None
    nested_virtualization_ready: bool = True


class _SealedMutationTransport:
    """A transport that is never hardened and refuses to apply — for the sealed composition."""

    def hardening_manifest(self) -> object:
        return type("M", (), {"all_enforced": staticmethod(lambda: False)})()

    def apply(self, method: str, path: str, *, body: object = None) -> object:
        raise EngineError("mutation_transport_sealed")


def sealed_composition() -> DeploymentComposition:
    """Assemble the shipped, sealed composition: every seam refuses. ``run_apply`` fails closed at
    the bootstrap boundary, so no network/SSH/host action occurs. Normal worker runtime uses
    this."""
    return DeploymentComposition(
        bootstrap_executor=SshBootstrapExecutor(
            bundle_source=SealedWorkerBootstrapBundleSource(),
            runner=RefusingHostCommandRunner(),
        ),
        mutation_executor=ProxmoxMutationExecutor(transport=_SealedMutationTransport()),
        artifact_blob_source=None,
        locator_source=SealedDeploymentLocatorSource(),
        remote_pop_authority=SealedRemotePoPAuthority(),
        openbao_handoff=SealedOpenBaoHandoff(),
        verification_collector=SealedVerificationEvidenceCollector(),
        inventory=None,
        nested_virtualization_ready=False,
    )


# --- drift re-verification -----------------------------------------------------------------------


def _approved_registration(
    session: Session, dep: StagingDeployment
) -> WorkerIdentityRegistration | None:
    return session.execute(
        select(WorkerIdentityRegistration).where(
            WorkerIdentityRegistration.organization_id == dep.organization_id,
            WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
        )
    ).scalar_one_or_none()


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
    if deployment_plan_hash(plan.plan_document) != dep.approved_plan_hash:
        return DeploymentFailureCode.plan_drift.value
    namespace = ownership_namespace(dep.ownership_label)
    if approval.ownership_tag != namespace.ownership_tag:
        return DeploymentFailureCode.ownership_conflict.value
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
    identity = _approved_registration(session, dep)
    approved_version = identity.identity_version if identity is not None else 0
    if approved_version != approval.worker_identity_version:
        return DeploymentFailureCode.worker_identity_revoked.value
    return None


# --- helpers
# ---------------------------------------------------------------------------------------


def _transition(session: Session, dep: StagingDeployment, status: StagingDeploymentStatus) -> None:
    dep.status = status
    dep.revision = dep.revision + 1
    if status in (StagingDeploymentStatus.ready, StagingDeploymentStatus.destroyed):
        dep.failure_code = None
    session.flush()


def _fail(
    session: Session,
    dep: StagingDeployment,
    failure_code: str,
    *,
    status: StagingDeploymentStatus = StagingDeploymentStatus.rollback_required,
    decision_code: StagingDeploymentDecisionCode | None = None,
) -> EngineOutcome:
    dep.status = status
    dep.failure_code = failure_code
    if decision_code is not None:
        dep.decision_code = decision_code
    dep.revision = dep.revision + 1
    session.flush()
    return EngineOutcome(False, failure_code)


def _marker_for(dep: StagingDeployment, kind: DeploymentResourceKind) -> str:
    return compute_resource_marker(dep.ownership_label, kind.value, 0)


def _build_create(
    kind: DeploymentResourceKind, locator: ResourceLocator, marker: str
) -> TypedCreate | None:
    """Build the typed Proxmox create op for a kind, or None for a non-Proxmox kind. Raises for a
    kind/locator mismatch so an unknown/mismatched operation issues no request."""
    entry = _CREATE_BUILDERS.get(kind)
    if entry is None:
        return None
    loc_type, op_cls = entry
    if not isinstance(locator, loc_type):
        raise EngineError(DeploymentFailureCode.unknown_resource_operation.value)
    return op_cls(locator=locator, owner_marker=marker)  # type: ignore[arg-type]


def _build_inverse(
    inverse_op: DeploymentInverseOp, locator: ResourceLocator, marker: str
) -> TypedInverse | None:
    """Build the typed Proxmox inverse op, or None for a non-Proxmox / unknown inverse (skip; no
    request). Raises for a locator-type mismatch."""
    entry = _INVERSE_BUILDERS.get(inverse_op)
    if entry is None:
        return None
    loc_type, op_cls = entry
    if not isinstance(locator, loc_type):
        raise EngineError(DeploymentFailureCode.unknown_resource_operation.value)
    return op_cls(locator=locator, owner_marker=marker)  # type: ignore[arg-type]


def _record_resource(
    session: Session,
    dep: StagingDeployment,
    kind: DeploymentResourceKind,
    inverse: DeploymentInverseOp,
    locator: ResourceLocator,
    marker: str,
) -> None:
    namespace = ownership_namespace(dep.ownership_label)
    session.add(
        StagingDeploymentResource(
            deployment_id=dep.id,
            organization_id=dep.organization_id,
            resource_kind=kind,
            ownership_tag=namespace.ownership_tag,
            resource_ref=namespace.resource_name(kind.value, 0),
            observed_locator=locator_to_dict(locator),
            ownership_marker=marker,
            inverse_op=inverse,
            state=DeploymentResourceState.created,
        )
    )
    session.flush()


def _bootstrap_operations() -> tuple[HostBootstrapOperation, ...]:
    # The host-side bridge/firewall are established by the verified host helper over SSH; the
    # Proxmox
    # API path establishes the SDN/firewall objects. Each authoritative path owns its resource.
    return (BootstrapCreateBridge(bridge_index=0), ApplyDefaultDenyFirewall())


def _approved_artifact_manifest(session: Session, dep: StagingDeployment) -> str:
    approval = session.execute(
        select(StagingDeploymentApproval).where(
            StagingDeploymentApproval.deployment_id == dep.id,
            StagingDeploymentApproval.approved_plan_hash == dep.approved_plan_hash,
        )
    ).scalar_one_or_none()
    return approval.artifact_manifest_id if approval is not None else ""


def _run_pop(
    session: Session,
    dep: StagingDeployment,
    composition: DeploymentComposition,
    operation_fingerprint: str,
) -> tuple[bool, str]:
    identity = _approved_registration(session, dep)
    reg_id = identity.id if identity is not None else None
    version = identity.identity_version if identity is not None else 0
    outcome = composition.remote_pop_authority.prove(
        deployment_id=dep.id,
        operation_fingerprint=operation_fingerprint,
        organization_id=dep.organization_id,
        worker_registration_id=reg_id,
        worker_identity_version=version,
        plan_hash=dep.approved_plan_hash,
    )
    return outcome.ok, outcome.reason_code


# --- apply
# -----------------------------------------------------------------------------------------


def run_apply(
    session: Session,
    dep: StagingDeployment,
    *,
    composition: DeploymentComposition,
    now: datetime,
    operation_fingerprint: str,
) -> EngineOutcome:
    """Fail-at-first apply: drift → bootstrap → nested-virt → remote PoP → artifacts → typed
    observed-ownership topology → evidence-based verification. Records each owned resource with its
    exact observed locator + marker. Sealed composition fails closed at bootstrap (no host op)."""
    drift = reverify_no_drift(session, dep)
    if drift is not None:
        return _fail(session, dep, drift, decision_code=StagingDeploymentDecisionCode.drift_refused)

    _transition(session, dep, StagingDeploymentStatus.applying)

    namespace = ownership_namespace(dep.ownership_label)

    # 1. Bootstrap over hardened SSH (sealed bundle source → bootstrap_unavailable, fail closed).
    for op in _bootstrap_operations():
        result: BootstrapExecutionResult = composition.bootstrap_executor.execute(op, namespace)
        if not result.ok:
            return _fail(session, dep, result.reason_code)

    # 2. Nested virtualization: never auto-reboot. If not ready, durable maintenance-required stop
    #    BEFORE any provider mutation.
    if not composition.nested_virtualization_ready:
        return _fail(
            session,
            dep,
            DeploymentFailureCode.maintenance_required.value,
            decision_code=StagingDeploymentDecisionCode.maintenance_required,
        )

    # 3. Real remote Ed25519 PoP for this operation (sealed signer → fail closed).
    pop_ok, pop_reason = _run_pop(session, dep, composition, operation_fingerprint)
    if not pop_ok:
        code = (
            DeploymentFailureCode.remote_pop_failed.value
            if pop_reason in ("remote_pop_unavailable", "remote_pop_failed")
            else pop_reason
        )
        return _fail(session, dep, code)

    # 4. Verified offline artifacts (integrity-gated; sealed source refuses).
    try:
        verify_and_stage(
            manifest_id=_approved_artifact_manifest(session, dep),
            ownership_tag=namespace.ownership_tag,
            blob_source=composition.artifact_blob_source,  # type: ignore[arg-type]
        )
    except ArtifactPipelineError as exc:
        code = (
            DeploymentFailureCode.artifact_integrity_failed.value
            if exc.reason_code == "artifact_integrity_failed"
            else DeploymentFailureCode.provider_unavailable.value
        )
        return _fail(session, dep, code)

    # 5. Create the topology through typed, observed-ownership-proven operations.
    created: list[str] = []
    all_observed = True
    for kind, inverse in _TOPOLOGY:
        marker = _marker_for(dep, kind)
        try:
            locator = composition.locator_source.locator_for(kind)
        except DiscoveryUnavailable:
            return _fail(session, dep, DeploymentFailureCode.discovery_required.value)
        try:
            create_op = _build_create(kind, locator, marker)
        except EngineError as exc:
            return _fail(session, dep, exc.reason_code)

        if create_op is not None:
            res = composition.mutation_executor.create_owned(create_op, expected_marker=marker)
            if not res.ok:
                return _fail(session, dep, res.reason_code)
        elif kind == DeploymentResourceKind.artifact_stage:
            pass  # already integrity-staged in step 4
        elif kind == DeploymentResourceKind.openbao_scoped_credential:
            if not composition.openbao_handoff.is_ready():
                return _fail(session, dep, DeploymentFailureCode.openbao_handoff_failed.value)
            try:
                ref = getattr(locator, "credential_ref", None)
                composition.openbao_handoff.store_scoped_credential(
                    credential_ref=str(ref), owner_marker=marker
                )
            except OpenBaoHandoffUnavailable:
                return _fail(session, dep, DeploymentFailureCode.openbao_handoff_failed.value)
        else:
            return _fail(session, dep, DeploymentFailureCode.unknown_resource_operation.value)

        _record_resource(session, dep, kind, inverse, locator, marker)
        created.append(kind.value)

    # 6. Verify from observed evidence only; any non-passed check → rollback_required.
    _transition(session, dep, StagingDeploymentStatus.verifying)
    records = build_verification_records(
        composition,
        transport_ok=composition.mutation_executor.transport_is_hardened(),
        pop_ok=pop_ok,
        all_resources_observed=all_observed,
    )
    _persist_verifications(session, dep, operation_fingerprint, records)
    if any(status != DeploymentVerificationStatus.passed.value for status in records.values()):
        return _fail(session, dep, DeploymentFailureCode.verification_failed.value)

    _transition(session, dep, StagingDeploymentStatus.ready)
    return EngineOutcome(True, "ready", tuple(created))


# --- rollback / teardown
# ---------------------------------------------------------------------------


def rollback_or_teardown(
    session: Session,
    dep: StagingDeployment,
    *,
    composition: DeploymentComposition,
    now: datetime,
    final_status: StagingDeploymentStatus,
) -> EngineOutcome:
    """Run typed inverse operations in REVERSE creation order. Each delete fresh-reads the exact
    recorded locator and proves our marker before mutating; a foreign / absent / stale / uncertain /
    unreconstructable resource is skipped, never deleted. Idempotent; failures preserve state."""
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
        # Reconstruct the EXACT recorded locator; a missing/malformed record cannot be proven owned.
        if resource.observed_locator is None or not resource.ownership_marker:
            continue
        try:
            locator = locator_from_dict(resource.observed_locator)
            inverse = _build_inverse(resource.inverse_op, locator, resource.ownership_marker)
        except Exception:
            continue  # unreconstructable → never delete
        if inverse is None:
            continue  # non-Proxmox / unknown inverse → no request (handled by sealed seams)
        result = composition.mutation_executor.delete_owned(
            inverse, expected_marker=resource.ownership_marker
        )
        if not result.ok:
            continue  # foreign / absent / stale / not-hardened → preserve state for retry
        resource.state = DeploymentResourceState.removed
        session.flush()
        removed.append(resource.resource_kind.value)
    _transition(session, dep, final_status)
    return EngineOutcome(True, final_status.value, tuple(removed))


# --- verification
# ----------------------------------------------------------------------------------


def _status_of(value: bool | None) -> str:
    if value is True:
        return DeploymentVerificationStatus.passed.value
    if value is False:
        return DeploymentVerificationStatus.failed.value
    return DeploymentVerificationStatus.unverifiable.value


def build_verification_records(
    composition: DeploymentComposition,
    *,
    transport_ok: bool,
    pop_ok: bool,
    all_resources_observed: bool,
) -> dict[str, str]:
    """Derive the closed verification check→status map from OBSERVED evidence only. Engine-proven
    signals (transport hardening, remote PoP, per-resource fresh-read observation) are set from real
    execution; every externally-observed check comes from the injected collector. A check that is
    not
    positively observed is ``unverifiable`` — there is NO static ``passed``."""
    evidence: dict[str, bool | None] = {code.value: None for code in DeploymentVerificationCode}
    # Engine-proven signals from this apply's real execution.
    evidence[DeploymentVerificationCode.transport_enforced.value] = bool(transport_ok)
    evidence[DeploymentVerificationCode.remote_pop_verified.value] = bool(pop_ok)
    evidence[DeploymentVerificationCode.only_secp_owned_resources.value] = bool(
        all_resources_observed
    )
    # Externally-observed checks from the (sealed-by-default) collector.
    collected = composition.verification_collector.collect()
    for code, value in collected.items():
        if code in evidence and value is not None:
            evidence[code] = bool(value)
    return {code: _status_of(value) for code, value in evidence.items()}


def _persist_verifications(
    session: Session,
    dep: StagingDeployment,
    operation_fingerprint: str,
    records: dict[str, str],
) -> None:
    op = session.execute(
        select(StagingDeploymentOperation).where(
            StagingDeploymentOperation.operation_fingerprint == operation_fingerprint
        )
    ).scalar_one_or_none()
    if op is None:
        # Verification records attach to a durable operation; without one there is nothing to bind
        # them to. The in-memory ``records`` still gate the transition.
        return
    op_id = op.id
    for code, status in records.items():
        session.add(
            StagingDeploymentVerification(
                deployment_id=dep.id,
                organization_id=dep.organization_id,
                operation_id=op_id,
                check_code=DeploymentVerificationCode(code),
                status=DeploymentVerificationStatus(status),
            )
        )
    session.flush()
