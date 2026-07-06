"""SECP-B4 §5/§6/§8 — deployment engine (corrective): observed-ownership, discovery-gated, wired.

Fake-backed; no real host/ssh/http is contacted. Proves the dangerous cases the review demanded:
the sealed composition fails closed at bootstrap; a fully-injected composition drift-re-verifies,
bootstraps, runs remote PoP, stages integrity-checked offline artifacts, and creates the topology
only
through typed, fresh-read observed-ownership creates (recording the EXACT observed locator) to reach
`ready`; drift / sealed discovery / sealed observer / sealed PoP / nested-virt all fail closed
BEFORE
or WITHOUT unsafe mutation; rollback removes ONLY resources whose exact locator fresh-reads as ours
(foreign untouched); an unknown inverse issues no request; and verification is derived from observed
evidence with NO static `passed` (any non-passed check → rollback_required).
"""

from __future__ import annotations

from datetime import UTC, datetime

from secp_api.deployment_contract import ARTIFACT_CATALOG_VERSION
from secp_api.enums import (
    DeploymentInverseOp,
    DeploymentResourceKind,
    DeploymentResourceState,
    DeploymentVerificationStatus,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    StagingDeploymentStatus,
    TargetStatus,
)
from secp_api.models import (
    ExecutionTarget,
    StagingDeploymentOperation,
    StagingDeploymentResource,
    StagingDeploymentVerification,
    TargetOnboarding,
)
from secp_api.ownership_contract import compute_resource_marker
from secp_api.services import staging_deployment as svc
from secp_plugin_proxmox.mutation_transport import HardeningManifest
from secp_worker.deployment.engine import (
    DeploymentComposition,
    build_verification_records,
    reverify_no_drift,
    rollback_or_teardown,
    run_apply,
    sealed_composition,
)
from secp_worker.deployment.locators import (
    ArtifactStageLocator,
    BridgeLocator,
    FirewallGroupLocator,
    GuestLocator,
    OpenBaoCredentialLocator,
    ServiceIdentityLocator,
)
from secp_worker.deployment.mutation_executor import ProxmoxMutationExecutor
from secp_worker.deployment.ownership_evidence import ObservedOwnership, SealedOwnershipObserver
from secp_worker.deployment.seams import (
    RemotePoPOutcome,
    SealedDeploymentLocatorSource,
    SealedRemotePoPAuthority,
)
from secp_worker.deployment.ssh_bootstrap import (
    CommandResult,
    SshBootstrapExecutor,
)

_OP_FP = "op-apply-1"

# Fake discovered locators, one per resource kind (never hardcoded in the engine).
_LOCATORS = {
    DeploymentResourceKind.proxmox_service_identity: ServiceIdentityLocator("secp-svc@pve"),
    DeploymentResourceKind.isolated_bridge: BridgeLocator("pve-a", "secpbr0"),
    DeploymentResourceKind.host_firewall_boundary: FirewallGroupLocator("secpfw0"),
    DeploymentResourceKind.artifact_stage: ArtifactStageLocator("pve-a", "local"),
    DeploymentResourceKind.control_plane_vm: GuestLocator("pve-a", 9101),
    DeploymentResourceKind.nested_target_vm: GuestLocator("pve-a", 9102),
    DeploymentResourceKind.openbao_scoped_credential: OpenBaoCredentialLocator("secp-cred"),
}
_PROXMOX_KINDS = (
    DeploymentResourceKind.proxmox_service_identity,
    DeploymentResourceKind.isolated_bridge,
    DeploymentResourceKind.host_firewall_boundary,
    DeploymentResourceKind.control_plane_vm,
    DeploymentResourceKind.nested_target_vm,
)


# --- fakes ---------------------------------------------------------------------------------------


class _FakeRunner:
    def run(self, argv, *, timeout):
        return CommandResult(exit_code=0)


class _FakeBundleSource:
    def acquire(self):
        from secp_worker.deployment.ssh_bootstrap import SshBootstrapBundle

        return SshBootstrapBundle("h", 22, "u", "/k", "/kh", "fp")

    def dispose(self):
        return None


class _PassHostKeyVerifier:
    def verify(self, bundle):
        return True


class _FakeTransport:
    def __init__(self, *, hardened=True):
        self._h = hardened
        self.calls: list[tuple] = []

    def hardening_manifest(self):
        v = self._h
        return HardeningManifest(v, v, v, v, v, v, v)

    def apply(self, method, path, *, body=None):
        self.calls.append((method, path, body))
        return {"ok": True}


class _FlipObserver:
    def __init__(self):
        self._markers: dict[str, str] = {}
        self._seen: set[str] = set()

    def seed_create(self, locator, marker):
        self._markers[locator.observe_key()] = marker

    def seed_present(self, locator, marker):
        self._markers[locator.observe_key()] = marker
        self._seen.add(locator.observe_key())

    def observe(self, locator):
        k = locator.observe_key()
        if k not in self._markers:
            return ObservedOwnership(False, None)
        if k not in self._seen:
            self._seen.add(k)
            return ObservedOwnership(False, None)
        return ObservedOwnership(True, self._markers[k])


class _FakeLocatorSource:
    def __init__(self, mapping=None):
        self._map = mapping if mapping is not None else _LOCATORS

    def locator_for(self, kind):
        return self._map[kind]


class _OkPoP:
    def prove(self, **_kwargs):
        return RemotePoPOutcome(True, "verified")


class _FakeOpenBao:
    def __init__(self):
        self.stored = []

    def is_ready(self):
        return True

    def store_scoped_credential(self, *, credential_ref, owner_marker):
        self.stored.append((credential_ref, owner_marker))


class _AllTrueCollector:
    def collect(self):
        # Every externally-observed check positively observed (real integration supplies these).
        from secp_api.enums import DeploymentVerificationCode

        return {c.value: True for c in DeploymentVerificationCode}


class _MatchingArtifactSource:
    def fetch(self, artifact_id: str) -> bytes:
        return f"{ARTIFACT_CATALOG_VERSION}|{artifact_id}".encode()


def _seed_observer_for_creates(dep) -> _FlipObserver:
    obs = _FlipObserver()
    for kind in _PROXMOX_KINDS:
        marker = compute_resource_marker(dep.ownership_label, kind.value, 0)
        obs.seed_create(_LOCATORS[kind], marker)
    return obs


def _composition(
    dep,
    *,
    nested_ready=True,
    bundle_source=None,
    observer=None,
    locator_source=None,
    pop=None,
    openbao=None,
    collector=None,
    artifact_source=None,
):
    return DeploymentComposition(
        bootstrap_executor=SshBootstrapExecutor(
            bundle_source=bundle_source or _FakeBundleSource(),
            runner=_FakeRunner(),
            host_key_verifier=_PassHostKeyVerifier(),
        ),
        mutation_executor=ProxmoxMutationExecutor(
            transport=_FakeTransport(),
            observer=observer if observer is not None else _seed_observer_for_creates(dep),
        ),
        artifact_blob_source=artifact_source or _MatchingArtifactSource(),
        locator_source=locator_source or _FakeLocatorSource(),
        remote_pop_authority=pop or _OkPoP(),
        openbao_handoff=openbao or _FakeOpenBao(),
        verification_collector=collector or _AllTrueCollector(),
        nested_virtualization_ready=nested_ready,
    )


# --- durable substrate + approved deployment -----------------------------------------------------


def _target_with_active_onboarding(session, principal) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:secp/proxmox/target-1",
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    return target


def _approved(session, principal):
    target = _target_with_active_onboarding(session, principal)
    dep = svc.create_deployment(session, principal, execution_target_id=target.id)
    svc.generate_plan(session, principal, dep.id)
    svc.submit_for_approval(session, principal, dep.id)
    svc.approve_deployment(session, principal, dep.id, expected_plan_hash=dep.plan_hash)
    svc.submit_deployment(session, principal, dep.id)  # -> bootstrap_pending
    return dep


def _apply(session, dep, composition):
    op = (
        session.query(StagingDeploymentOperation)
        .filter(StagingDeploymentOperation.deployment_id == dep.id)
        .first()
    )
    fingerprint = op.operation_fingerprint if op is not None else _OP_FP
    return run_apply(
        session,
        dep,
        composition=composition,
        now=datetime.now(UTC),
        operation_fingerprint=fingerprint,
    )


# --- tests ---------------------------------------------------------------------------------------


def test_sealed_composition_fails_closed_at_bootstrap(session, principal):
    dep = _approved(session, principal)
    outcome = _apply(session, dep, sealed_composition())
    assert outcome.ok is False and outcome.reason_code == "bootstrap_unavailable"
    assert dep.status == StagingDeploymentStatus.rollback_required
    assert session.query(StagingDeploymentResource).count() == 0


def test_full_apply_creates_owned_topology_and_reaches_ready(session, principal):
    dep = _approved(session, principal)
    outcome = _apply(session, dep, _composition(dep))
    assert outcome.ok is True and outcome.reason_code == "ready"
    assert dep.status == StagingDeploymentStatus.ready
    resources = session.query(StagingDeploymentResource).all()
    assert len(resources) == 7
    # Every resource records the EXACT observed locator + a per-resource marker (never a bare
    # label).
    for r in resources:
        assert r.observed_locator is not None and "type" in r.observed_locator
        assert r.ownership_marker and r.ownership_marker.startswith("secp-owned:")
    # Verification persisted and all passed (from observed evidence, not static).
    verifs = session.query(StagingDeploymentVerification).all()
    assert verifs and all(v.status == DeploymentVerificationStatus.passed for v in verifs)


def test_apply_fails_closed_on_onboarding_drift(session, principal):
    dep = _approved(session, principal)
    onboarding = session.get(TargetOnboarding, dep.onboarding_id)
    onboarding.status = OnboardingStatus.retired
    session.flush()
    outcome = _apply(session, dep, _composition(dep))
    assert outcome.ok is False and outcome.reason_code == "target_inventory_changed"
    assert session.query(StagingDeploymentResource).count() == 0


def test_nested_virtualization_required_stops_before_mutation(session, principal):
    dep = _approved(session, principal)
    outcome = _apply(session, dep, _composition(dep, nested_ready=False))
    assert outcome.ok is False and outcome.reason_code == "maintenance_required"
    assert dep.decision_code.value == "maintenance_required"
    assert session.query(StagingDeploymentResource).count() == 0


def test_apply_refuses_when_discovery_sealed(session, principal):
    dep = _approved(session, principal)
    comp = _composition(dep, locator_source=SealedDeploymentLocatorSource())
    outcome = _apply(session, dep, comp)
    assert outcome.ok is False and outcome.reason_code == "discovery_required"
    assert session.query(StagingDeploymentResource).count() == 0


def test_apply_fails_closed_on_sealed_observer(session, principal):
    dep = _approved(session, principal)
    outcome = _apply(session, dep, _composition(dep, observer=SealedOwnershipObserver()))
    assert outcome.ok is False and outcome.reason_code == "ownership_observation_unavailable"
    assert session.query(StagingDeploymentResource).count() == 0


def test_remote_pop_required_on_apply_path(session, principal):
    dep = _approved(session, principal)
    outcome = _apply(session, dep, _composition(dep, pop=SealedRemotePoPAuthority()))
    assert outcome.ok is False and outcome.reason_code == "remote_pop_failed"
    assert session.query(StagingDeploymentResource).count() == 0  # PoP is BEFORE any mutation


def test_apply_fails_closed_on_artifact_integrity(session, principal):
    dep = _approved(session, principal)

    class _Corrupt:
        def fetch(self, artifact_id: str) -> bytes:
            return b"corrupt"

    outcome = _apply(session, dep, _composition(dep, artifact_source=_Corrupt()))
    assert outcome.ok is False and outcome.reason_code == "artifact_integrity_failed"


def test_rollback_removes_only_owned_and_foreign_untouched(session, principal):
    dep = _approved(session, principal)
    # Use one shared observer so the same seeded keys read as owned during both create and delete.
    observer = _seed_observer_for_creates(dep)
    for kind in _PROXMOX_KINDS:
        marker = compute_resource_marker(dep.ownership_label, kind.value, 0)
        observer.seed_present(_LOCATORS[kind], marker)  # owned + present for delete fresh-read
    _apply(session, dep, _composition(dep, observer=observer))
    assert dep.status == StagingDeploymentStatus.ready

    # Inject a FOREIGN resource whose observed locator fresh-reads as NOT ours.
    foreign = StagingDeploymentResource(
        deployment_id=dep.id,
        organization_id=dep.organization_id,
        resource_kind=DeploymentResourceKind.isolated_bridge,
        ownership_tag="secp-owned:deadbeefdeadbeef",
        resource_ref="foreign-ref",
        observed_locator={"type": "bridge", "node": "pve-a", "iface": "foreignbr"},
        ownership_marker="secp-owned:deadbeef#foreign",
        inverse_op=DeploymentInverseOp.remove_owned_bridge,
        state=DeploymentResourceState.created,
    )
    session.add(foreign)
    session.flush()

    rollback_or_teardown(
        session,
        dep,
        composition=_composition(dep, observer=observer),
        now=datetime.now(UTC),
        final_status=StagingDeploymentStatus.rolled_back,
    )
    session.refresh(foreign)
    assert foreign.state == DeploymentResourceState.created  # foreign never touched
    # The owned Proxmox-typed resources were removed (bridge/firewall/identity/2 guests = 5).
    removed = (
        session.query(StagingDeploymentResource)
        .filter(StagingDeploymentResource.state == DeploymentResourceState.removed)
        .count()
    )
    assert removed == 5
    assert dep.status == StagingDeploymentStatus.rolled_back


def test_unknown_inverse_and_missing_locator_send_no_request(session, principal):
    dep = _approved(session, principal)
    transport = _FakeTransport()
    executor = ProxmoxMutationExecutor(transport=transport, observer=_FlipObserver())
    composition = _composition(dep)
    object.__setattr__(composition, "mutation_executor", executor)
    # A resource with a non-Proxmox inverse (artifacts) and one with no observed_locator: neither
    # may issue a delete request.
    session.add(
        StagingDeploymentResource(
            deployment_id=dep.id,
            organization_id=dep.organization_id,
            resource_kind=DeploymentResourceKind.artifact_stage,
            ownership_tag="secp-owned:x",
            resource_ref="r1",
            observed_locator={"type": "artifact_stage", "node": "n", "storage": "s"},
            ownership_marker="secp-owned:x#a",
            inverse_op=DeploymentInverseOp.remove_owned_artifacts,
            state=DeploymentResourceState.created,
        )
    )
    session.add(
        StagingDeploymentResource(
            deployment_id=dep.id,
            organization_id=dep.organization_id,
            resource_kind=DeploymentResourceKind.isolated_bridge,
            ownership_tag="secp-owned:x",
            resource_ref="r2",
            observed_locator=None,
            ownership_marker=None,
            inverse_op=DeploymentInverseOp.remove_owned_bridge,
            state=DeploymentResourceState.created,
        )
    )
    session.flush()
    rollback_or_teardown(
        session,
        dep,
        composition=composition,
        now=datetime.now(UTC),
        final_status=StagingDeploymentStatus.rolled_back,
    )
    # No delete request issued for the unknown-inverse / no-locator records.
    assert transport.calls == []


def test_verification_has_no_static_passed_and_failure_rolls_back(session, principal):
    dep = _approved(session, principal)

    class _EmptyCollector:
        def collect(self):
            return {}

    outcome = _apply(session, dep, _composition(dep, collector=_EmptyCollector()))
    # With no external evidence, the isolation/route/health checks are unverifiable -> not all
    # passed
    # -> rollback_required. There is no static "passed".
    assert outcome.ok is False and outcome.reason_code == "verification_failed"
    assert dep.status == StagingDeploymentStatus.rollback_required
    statuses = {v.status for v in session.query(StagingDeploymentVerification).all()}
    assert DeploymentVerificationStatus.unverifiable in statuses


def test_build_verification_records_never_static_passed():
    # A composition whose collector observes nothing, with engine signals off, yields NO passed.
    class _Empty:
        def collect(self):
            return {}

    comp = DeploymentComposition(
        bootstrap_executor=None,  # type: ignore[arg-type]
        mutation_executor=None,  # type: ignore[arg-type]
        artifact_blob_source=None,
        locator_source=None,  # type: ignore[arg-type]
        remote_pop_authority=None,  # type: ignore[arg-type]
        openbao_handoff=None,  # type: ignore[arg-type]
        verification_collector=_Empty(),  # type: ignore[arg-type]
    )
    records = build_verification_records(
        comp, transport_ok=False, pop_ok=False, all_resources_observed=False
    )
    assert DeploymentVerificationStatus.passed.value not in records.values()


def test_reverify_no_drift_on_fresh_approval(session, principal):
    dep = _approved(session, principal)
    assert reverify_no_drift(session, dep) is None
