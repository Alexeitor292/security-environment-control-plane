"""Shared pytest fixtures.

Tests are hermetic: a fresh file-backed SQLite database per test, the inline
dispatcher, and the bootstrapped dev admin principal. No external services.
"""

from __future__ import annotations

import os

os.environ.setdefault("SECP_APP_ENV", "test")
os.environ.setdefault("SECP_WORKFLOW_DISPATCH_MODE", "inline")

import uuid  # noqa: E402

import pytest  # noqa: E402
import secp_api.immutability  # noqa: E402,F401  (registers ORM immutability guards)
from secp_api.auth import Principal  # noqa: E402
from secp_api.db import (  # noqa: E402
    get_sessionmaker,
    reset_engine_for_tests,
)
from secp_api.models import Base  # noqa: E402
from secp_api.seed import bootstrap_dev  # noqa: E402

VALID_DEFINITION: dict = {
    "apiVersion": "controlplane.security/v1alpha1",
    "kind": "Environment",
    "metadata": {"name": "test-env", "displayName": "Test Env"},
    "spec": {
        "teams": {"count": 2, "isolationPolicy": "strict"},
        "networks": [
            {"name": "team-network", "cidrStrategy": "per-team", "baseCidr": "10.20.0.0/16"}
        ],
        "roles": [
            {
                "name": "attacker",
                "kind": "attacker",
                "image": "kali-linux",
                "network": "team-network",
            },
            {
                "name": "web-server",
                "kind": "target",
                "image": "ubuntu-server-22.04",
                "network": "team-network",
            },
            {
                "name": "wazuh-sensor",
                "kind": "sensor",
                "image": "wazuh-agent",
                "network": "team-network",
            },
        ],
        "telemetry": {"providers": ["wazuh"]},
        "validation": {
            "provider": "ctfd",
            "objectives": [
                {"id": "gain-initial-access", "description": "Get a shell", "points": 100}
            ],
        },
        "requiredPlugins": ["simulator"],
    },
}


@pytest.fixture
def engine(tmp_path):
    url = f"sqlite+pysqlite:///{(tmp_path / 'test.db').as_posix()}"
    eng = reset_engine_for_tests(url)
    Base.metadata.create_all(eng)
    yield eng
    # ``environment_version`` and ``topology_authoring_document`` reference each other
    # (ADR-016: a version can cite its source topology document, and a topology document
    # can cite its source version), so metadata forms an FK cycle that ``drop_all`` cannot
    # topologically sort. Disable SQLite FK enforcement on the raw DBAPI connection (so the
    # PRAGMA runs outside any transaction and is not a no-op) and drop on that same
    # connection. Production ordering is handled explicitly by Alembic migrations.
    with eng.connect() as conn:
        if conn.dialect.name == "sqlite":
            conn.connection.dbapi_connection.execute("PRAGMA foreign_keys=OFF")
        Base.metadata.drop_all(bind=conn)
        conn.commit()


@pytest.fixture
def session(engine):
    factory = get_sessionmaker()
    s = factory()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture
def principal(session) -> Principal:
    p = bootstrap_dev(session)
    session.commit()
    return p


@pytest.fixture
def other_org_principal(session, principal) -> Principal:
    """A principal in a *different* organization (for org-scoping tests)."""
    from secp_api.enums import Permission
    from secp_api.models import (
        Organization,
        Role,
        User,
        UserRoleAssignment,
    )

    org = Organization(name="Other Org", slug="other-org")
    session.add(org)
    session.flush()
    role = session.query(Role).filter_by(name="platform-admin").one()
    user = User(
        organization_id=org.id,
        email="other-admin@local.test",
        display_name="Other Admin",
        subject="other-admin",
    )
    session.add(user)
    session.flush()
    session.add(UserRoleAssignment(organization_id=org.id, user_id=user.id, role_id=role.id))
    session.commit()
    return Principal(
        user_id=user.id,
        organization_id=org.id,
        email=user.email,
        permissions=frozenset(Permission),
    )


# SECP-B2-4.4 — a test-only, load-bearing durable worker-identity verifier. It creates a REAL,
# approved ``WorkerIdentityRegistration`` in the principal's organization + a test-only attestation
# claim source, and returns a ``RegisteredWorkerIdentityVerifier``. A preflight in that org will
# verify against this durable registration (never a simplistic hand-built identity). It is never
# selectable by production runtime (the shipped default is ``DenyingWorkerIdentityVerifier``).
_WI_LABEL = "staging-worker-a"
_WI_ANCHOR = "test-public-anchor-v1"
_WI_BINDING = "deploy-01"


@pytest.fixture
def worker_identity_verifier(session, principal):
    def _make(*, label: str = _WI_LABEL, anchor: str = _WI_ANCHOR, binding: str = _WI_BINDING):
        from secp_api.enums import (
            WorkerIdentityEvidenceKind,
            WorkerIdentityEvidenceStatus,
            WorkerIdentityMechanism,
        )
        from secp_api.services import worker_identity as wi
        from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
        from secp_worker.preflight.worker_identity_attestation import (
            RegisteredWorkerIdentityVerifier,
            WorkerIdentityClaim,
        )

        mechanism = WorkerIdentityMechanism.mtls_workload_identity
        row = wi.register_worker_identity(
            session,
            principal,
            mechanism=mechanism,
            identity_label=label,
            deployment_binding=binding,
            verification_anchor_fingerprint=compute_verification_anchor_fingerprint(anchor),
        )
        for kind in WorkerIdentityEvidenceKind:
            wi.record_evidence(
                session,
                principal,
                row.id,
                kind=kind,
                status=WorkerIdentityEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        wi.approve_worker_identity(session, principal, row.id)

        class _FakeAttestationSource:
            def attest(self, *, preflight, now):
                return WorkerIdentityClaim(
                    organization_id=preflight.organization_id,
                    mechanism=mechanism.value,
                    identity_label=label,
                    deployment_binding=binding,
                    identity_version=row.identity_version,
                    public_anchor=anchor,
                )

        return RegisteredWorkerIdentityVerifier(_FakeAttestationSource())

    return _make


@pytest.fixture
def valid_definition() -> dict:
    import copy

    return copy.deepcopy(VALID_DEFINITION)


@pytest.fixture
def template_and_version(session, principal):
    """Create a template + immutable version from the valid definition."""
    from secp_api.services import catalog

    template = catalog.create_template(
        session, principal, name="Test Template", slug="test-template"
    )
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=VALID_DEFINITION
    )
    session.commit()
    return template, version


def _make_running_exercise(session, principal, *, name: str = "ex"):
    """Drive an exercise to 'running' through the full approval-gated flow."""
    from secp_api.services import catalog, exercises, planning

    template = catalog.create_template(
        session, principal, name=name, slug=f"{name}-{uuid.uuid4().hex[:8]}"
    )
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=VALID_DEFINITION
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name=name
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "approved for test")
    exercises.start_exercise(session, principal, exercise.id)
    session.commit()
    return exercise


@pytest.fixture
def running_exercise(session, principal):
    """A factory fixture: call to create a fresh exercise driven to 'running'."""

    def _factory(name: str = "ex"):
        return _make_running_exercise(session, principal, name=name)

    return _factory


# --- SECP-002B-0 provisioning fixtures ---------------------------------------

VALID_PROVISIONING_SCOPE: dict = {
    "allowed_nodes": ["pve-node-1", "pve-node-2"],
    "allowed_storage": ["local-lvm"],
    "allowed_bridges": ["vmbr0"],
    "allowed_templates": ["kali-linux", "ubuntu-server-22.04", "wazuh-agent"],
    "vmid_range": {"start": 9000, "end": 9100},
    "max_teams": 4,
    "max_vms": 20,
    "max_containers": 10,
    "max_total_vcpu": 64,
    "max_total_memory_mb": 131072,
    "max_total_disk_gb": 2048,
    "allowed_cidr_reservations": ["10.60.0.0/16"],
    "external_connectivity": {"policy": "deny"},
    "node_sizing": {
        "kali-linux": {"vcpu": 2, "memory_mb": 4096, "disk_gb": 40},
        "ubuntu-server-22.04": {"vcpu": 1, "memory_mb": 2048, "disk_gb": 20},
        "wazuh-agent": {"vcpu": 1, "memory_mb": 1024, "disk_gb": 10},
    },
}


class ProvisioningEnv:
    def __init__(self, target, exercise, plan):
        self.target = target
        self.exercise = exercise
        self.plan = plan


def build_provisioning_env(
    session, principal, *, scope=None, address_spaces=None, approve=True
) -> ProvisioningEnv:
    """Set up an approved, target-bound plan + finalized reservations for 2 teams."""
    import copy

    from secp_api.services import catalog, exercises, planning, reservations, targets

    target = targets.register_target(
        session,
        principal,
        display_name="Lab (placeholder)",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__LAB",
        scope_policy={"provisioning": copy.deepcopy(scope or VALID_PROVISIONING_SCOPE)},
        address_spaces=address_spaces or [{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    )
    # A target-bound plan requires an approved & active onboarding (SECP-002B-1B-0).
    onboard_and_activate(session, principal, target)
    template = catalog.create_template(
        session, principal, name="Prov", slug=f"prov-{uuid.uuid4().hex[:8]}"
    )
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=VALID_DEFINITION
    )
    exercise = exercises.create_exercise(
        session,
        principal,
        template_id=template.id,
        version_id=version.id,
        name="prov",
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    if approve:
        planning.approve_plan(session, principal, plan.id, "approved for provisioning test")
    # Finalized reservations for both teams.
    for team in ("team1", "team2"):
        reservations.reserve_network(
            session, principal, target_id=target.id, team_ref=team, exercise_id=exercise.id
        )
    session.commit()
    return ProvisioningEnv(target, exercise, plan)


@pytest.fixture
def provisioning_env(session, principal):
    def _factory(**kwargs):
        return build_provisioning_env(session, principal, **kwargs)

    return _factory


# --- SECP-002B-1A sealed-OpenTofu / lab fixtures -----------------------------

# Clearly-fake, non-routable, well-formed placeholder toolchain profile. The version
# is not a real OpenTofu release; digests are repeated-byte placeholders; the state
# backend and provider mirror reference fake, offline, non-routable identities.
VALID_TOOLCHAIN_PROFILE: dict = {
    "runner_kind": "opentofu",
    "executable": "tofu",
    "opentofu_version": "9.9.9",
    "binary_integrity": "sha256:" + "de" * 32,
    "adapter_kind": "proxmox",
    "module_bundle_id": "secp-fake-lab-bundle",
    "module_bundle_hash": "sha256:" + "ab" * 32,
    "provider_lockfile_hash": "sha256:" + "cd" * 32,
    "renderer_version": "secp-002b-1a/renderer/v1",
    "state_backend": {"kind": "http", "reference": "secp-fake-remote-state/lab"},
    "provider_mirror": {
        "identity": "secp-fake-offline-mirror",
        "network_access": "offline",
        "allow_runtime_download": False,
    },
    "activation_class": "isolated_lab",
}


# Clearly-fake, non-routable declared onboarding boundary (SECP-002B-1B-0). Provider-
# neutral; consistent with VALID_PROVISIONING_SCOPE.
VALID_ONBOARDING_BOUNDARY: dict = {
    "nodes": ["pve-node-1", "pve-node-2"],
    "storage": ["local-lvm"],
    "network_segments": ["vmbr0"],
    "cidrs": ["10.60.0.0/16"],
    "vmid_range": {"start": 9000, "end": 9100},
    "quotas": {
        "max_teams": 4,
        "max_vms": 20,
        "max_containers": 10,
        "max_total_vcpu": 64,
        "max_total_memory_mb": 131072,
        "max_total_disk_gb": 2048,
    },
    "external_connectivity": {"policy": "deny"},
    "credential_scope": "least_privilege",
}


def onboard_and_activate(session, principal, target, *, isolation_model=None, boundary=None):
    """Drive a target onboarding to 'active' (create → preflight → submit → approve → activate).

    The declared boundary defaults to one derived from the target scope policy (always
    within scope). Uses the API-style simulated preflight (no arbitrary caller checks).
    """
    import copy

    from secp_api.enums import IsolationModel, OnboardingMode
    from secp_api.onboarding import boundary_from_scope
    from secp_api.services import onboarding as onb

    isolation_model = isolation_model or IsolationModel.logical
    b = (
        copy.deepcopy(boundary)
        if boundary is not None
        else boundary_from_scope(target.scope_policy)
    )
    ob = onb.create_onboarding(
        session,
        principal,
        target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=isolation_model,
        declared_boundary=b,
    )
    onb.record_simulated_preflight(session, principal, ob.id)
    onb.submit_for_review(session, principal, ob.id)
    onb.approve_onboarding(session, principal, ob.id, "approved for test")
    onb.activate_onboarding(session, principal, ob.id)
    return ob


class LabEnv:
    def __init__(self, target, exercise, plan, manifest, toolchain, onboarding=None):
        self.target = target
        self.exercise = exercise
        self.plan = plan
        self.manifest = manifest
        self.toolchain = toolchain
        self.onboarding = onboarding


def build_lab_env(
    session,
    principal,
    *,
    toolchain=None,
    scope=None,
    approve=True,
    secret_ref="env:SECP_PROVIDER_SECRET__LAB",
) -> LabEnv:
    """Approved target-bound plan + reservations + toolchain profile + manifest.

    The toolchain profile is registered BEFORE plan generation so the plan pins it,
    and the manifest copies the binding — the full real-lab chain (ADR-013).

    ``secret_ref`` is an OPAQUE placeholder pointer (never a secret). B1B-PR4 readiness
    suites pass a ``vault:`` placeholder because a plan-read provisioning credential may
    only use the ``vault`` reference scheme.
    """
    import copy

    from secp_api.services import (
        catalog,
        exercises,
        manifests,
        planning,
        reservations,
        targets,
    )
    from secp_api.services import (
        toolchain as toolchain_svc,
    )

    target = targets.register_target(
        session,
        principal,
        display_name="Disposable Lab (placeholder)",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref=secret_ref,
        scope_policy={"provisioning": copy.deepcopy(scope or VALID_PROVISIONING_SCOPE)},
        address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
    )
    tp = toolchain_svc.register_toolchain_profile(
        session,
        principal,
        target_id=target.id,
        name="lab-opentofu",
        profile=copy.deepcopy(toolchain or VALID_TOOLCHAIN_PROFILE),
    )
    # Approve + activate a target onboarding so the real-provisioning gate is satisfied.
    ob = onboard_and_activate(session, principal, target)
    template = catalog.create_template(
        session, principal, name="Lab", slug=f"lab-{uuid.uuid4().hex[:8]}"
    )
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=VALID_DEFINITION
    )
    exercise = exercises.create_exercise(
        session,
        principal,
        template_id=template.id,
        version_id=version.id,
        name="lab",
        execution_target_id=target.id,
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    if approve:
        planning.approve_plan(session, principal, plan.id, "approved for lab test")
    for team in ("team1", "team2"):
        reservations.reserve_network(
            session, principal, target_id=target.id, team_ref=team, exercise_id=exercise.id
        )
    session.commit()
    manifest = manifests.generate_manifest(session, principal, plan.id)
    session.commit()
    return LabEnv(target, exercise, plan, manifest, tp, onboarding=ob)


@pytest.fixture
def lab_env(session, principal):
    def _factory(**kwargs):
        return build_lab_env(session, principal, **kwargs)

    return _factory
