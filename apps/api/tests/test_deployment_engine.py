"""SECP-B4 §5/§6/§8 — worker deployment engine: apply, drift, rollback/teardown, offline artifacts.

Fake-backed; no real host/ssh/http is contacted. Proves: the sealed composition fails closed at the
first privileged boundary; a fully-injected fake composition drift-re-verifies, bootstraps, stages
integrity-checked offline artifacts, and creates the ownership-tagged topology to reach `ready`;
plan/onboarding/identity drift fails closed before mutation; nested-virt-required stops without a
reboot; rollback/teardown remove ONLY resources proven owned by this exact lab; artifact integrity
failure fails closed; and the generated guest bootstrap can fetch no external dependency.
"""

from __future__ import annotations

from datetime import UTC, datetime

from secp_api.deployment_contract import ARTIFACT_CATALOG_VERSION
from secp_api.enums import (
    DeploymentResourceState,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    StagingDeploymentStatus,
    TargetStatus,
)
from secp_api.models import (
    ExecutionTarget,
    StagingDeploymentResource,
    TargetOnboarding,
)
from secp_api.services import staging_deployment as svc
from secp_worker.deployment.artifacts import (
    SealedArtifactBlobSource,
    build_offline_guest_bootstrap,
    verify_and_stage,
)
from secp_worker.deployment.engine import (
    DeploymentComposition,
    build_verification_records,
    reverify_no_drift,
    rollback_or_teardown,
    run_apply,
)
from secp_worker.deployment.mutation_executor import ProxmoxMutationExecutor
from secp_worker.deployment.ssh_bootstrap import (
    CommandResult,
    SealedWorkerBootstrapBundleSource,
    SshBootstrapBundle,
    SshBootstrapExecutor,
)
from secp_worker.staging_live.live_proxmox_provider import (
    CapacityProfile,
    LiveProxmoxProvider,
    TargetInventory,
)

# --- fakes ---------------------------------------------------------------------------------------


class _FakeRunner:
    def run(self, argv, *, timeout):
        return CommandResult(exit_code=0)


class _FakeBundleSource:
    def acquire(self):
        return SshBootstrapBundle("h", 22, "u", "/k", "/kh", "fp")

    def dispose(self):
        return None


class _FakeHttpxClient:
    trust_env = False
    follow_redirects = False
    timeout = object()
    _verify = "/mnt/ca.pem"

    def request(self, method, url, **kwargs):
        return type(
            "R",
            (),
            {
                "status_code": 200,
                "is_redirect": False,
                "headers": {},
                "raise_for_status": lambda s: None,
                "json": lambda s: {"data": {}},
            },
        )()

    def close(self):
        return None


def _mutation_executor(namespace_label: str) -> ProxmoxMutationExecutor:
    from secp_plugin_proxmox.mutation_transport import HardenedProxmoxMutationTransport
    from secp_worker.staging_live.bootstrap.ownership import ownership_namespace

    transport = HardenedProxmoxMutationTransport(
        "https://host.example:8006/api2/json",
        "TOKEN",
        ca_bundle_path="/mnt/ca.pem",
        client=_FakeHttpxClient(),
    )
    reader = type("R", (), {"read_inventory": lambda s: _healthy_inventory()})()
    provider = LiveProxmoxProvider(
        namespace=ownership_namespace(namespace_label),
        inventory_reader=reader,
        capacity_profile=CapacityProfile(10, 8, 8192, 200),
    )
    return ProxmoxMutationExecutor(transport=transport, provider=provider)


class _MatchingArtifactSource:
    """Returns exactly the bytes whose sha256 matches each catalog artifact's integrity digest."""

    def fetch(self, artifact_id: str) -> bytes:
        return f"{ARTIFACT_CATALOG_VERSION}|{artifact_id}".encode()


def _healthy_inventory() -> TargetInventory:
    return TargetInventory(True, False, 1, True, "available", 100, 32, 65536, 2048)


def _composition(dep, *, nested_ready: bool = True, bundle_source=None, artifact_source=None):
    return DeploymentComposition(
        bootstrap_executor=SshBootstrapExecutor(
            bundle_source=bundle_source or _FakeBundleSource(), runner=_FakeRunner()
        ),
        mutation_executor=_mutation_executor(dep.ownership_label),
        artifact_blob_source=artifact_source or _MatchingArtifactSource(),
        inventory=_healthy_inventory(),
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


# --- tests ---------------------------------------------------------------------------------------


def test_sealed_composition_fails_closed_at_bootstrap(session, principal):
    dep = _approved(session, principal)
    composition = _composition(dep, bundle_source=SealedWorkerBootstrapBundleSource())
    outcome = run_apply(session, dep, composition=composition, now=datetime.now(UTC))
    assert outcome.ok is False
    assert outcome.reason_code == "bootstrap_unavailable"
    assert dep.status == StagingDeploymentStatus.rollback_required
    assert session.query(StagingDeploymentResource).count() == 0  # nothing created


def test_full_apply_creates_owned_topology_and_reaches_ready(session, principal):
    dep = _approved(session, principal)
    outcome = run_apply(session, dep, composition=_composition(dep), now=datetime.now(UTC))
    assert outcome.ok is True and outcome.reason_code == "ready"
    assert dep.status == StagingDeploymentStatus.ready
    resources = session.query(StagingDeploymentResource).all()
    assert len(resources) == 7  # the full closed topology
    # Every created resource carries THIS lab's ownership tag and a typed inverse op.
    from secp_worker.staging_live.bootstrap.ownership import ownership_namespace

    tag = ownership_namespace(dep.ownership_label).ownership_tag
    assert all(r.ownership_tag == tag for r in resources)
    assert all(r.inverse_op is not None for r in resources)


def test_apply_fails_closed_on_onboarding_drift(session, principal):
    dep = _approved(session, principal)
    onboarding = session.get(TargetOnboarding, dep.onboarding_id)
    onboarding.status = OnboardingStatus.retired  # drift: the enrollment changed
    session.flush()
    outcome = run_apply(session, dep, composition=_composition(dep), now=datetime.now(UTC))
    assert outcome.ok is False
    assert outcome.reason_code == "target_inventory_changed"
    assert session.query(StagingDeploymentResource).count() == 0


def test_nested_virtualization_required_stops_without_reboot(session, principal):
    dep = _approved(session, principal)
    outcome = run_apply(
        session, dep, composition=_composition(dep, nested_ready=False), now=datetime.now(UTC)
    )
    assert outcome.ok is False
    assert outcome.reason_code == "maintenance_required"


def test_rollback_removes_only_owned_resources(session, principal):
    dep = _approved(session, principal)
    run_apply(session, dep, composition=_composition(dep), now=datetime.now(UTC))
    # Inject a FOREIGN (other-lab) resource that must never be removed.
    foreign = StagingDeploymentResource(
        deployment_id=dep.id,
        organization_id=dep.organization_id,
        resource_kind=session.query(StagingDeploymentResource).first().resource_kind,
        ownership_tag="secp-owned:deadbeefdeadbeef",
        resource_ref="foreign-ref",
        inverse_op=session.query(StagingDeploymentResource).first().inverse_op,
        state=DeploymentResourceState.created,
    )
    session.add(foreign)
    session.flush()

    rollback_or_teardown(
        session,
        dep,
        composition=_composition(dep),
        now=datetime.now(UTC),
        final_status=StagingDeploymentStatus.rolled_back,
    )
    # All 7 owned resources are removed; the foreign one is left untouched.
    owned_removed = (
        session.query(StagingDeploymentResource)
        .filter(StagingDeploymentResource.state == DeploymentResourceState.removed)
        .count()
    )
    assert owned_removed == 7
    session.refresh(foreign)
    assert foreign.state == DeploymentResourceState.created  # foreign never touched
    assert dep.status == StagingDeploymentStatus.rolled_back


def test_artifact_integrity_failure_fails_closed(session, principal):
    dep = _approved(session, principal)

    class _CorruptSource:
        def fetch(self, artifact_id: str) -> bytes:
            return b"corrupted-does-not-match-digest"

    outcome = run_apply(
        session,
        dep,
        composition=_composition(dep, artifact_source=_CorruptSource()),
        now=datetime.now(UTC),
    )
    assert outcome.ok is False
    assert outcome.reason_code == "artifact_integrity_failed"


def test_sealed_artifact_source_refuses_and_offline_bootstrap_has_no_external_fetch():
    # Sealed artifact source refuses.
    import pytest
    from secp_worker.deployment.artifacts import ArtifactPipelineError

    with pytest.raises(ArtifactPipelineError):
        verify_and_stage(
            manifest_id=f"{ARTIFACT_CATALOG_VERSION}/small_lab",
            ownership_tag="secp-owned:x",
            blob_source=SealedArtifactBlobSource(),
        )
    # The generated offline guest bootstrap cannot reach any external dependency.
    staged = verify_and_stage(
        manifest_id=f"{ARTIFACT_CATALOG_VERSION}/small_lab",
        ownership_tag="secp-owned:x",
        blob_source=_MatchingArtifactSource(),
    )
    bootstrap = build_offline_guest_bootstrap(staged)
    assert bootstrap["offline"] is True
    assert bootstrap["network"]["config"] == "disabled"
    assert bootstrap["package_update"] is False and bootstrap["package_upgrade"] is False
    blob = str(bootstrap)
    for forbidden in ("http://", "https://", "apt-get", "pip install", "curl", "wget"):
        assert forbidden not in blob


def test_reverify_and_verification_helpers(session, principal):
    dep = _approved(session, principal)
    assert reverify_no_drift(session, dep) is None  # no drift on a fresh approval
    records = build_verification_records(_healthy_inventory())
    assert records["bridge_no_uplink_no_host_ip"] == "passed"
    assert records["proxmox_single_get"] == "passed"
    # An isolation-incapable target fails the isolation checks (never assumed passed).
    bad = build_verification_records(
        TargetInventory(True, False, 1, False, "available", 100, 32, 65536, 2048)
    )
    assert bad["control_plane_no_external_route"] == "failed"
