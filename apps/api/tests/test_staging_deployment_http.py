"""SECP-B4 §2 — HTTP + boundary tests for the real deployment lifecycle routes.

Drives the real ASGI app end-to-end through the control-plane lifecycle (create -> plan -> submit ->
approve -> deploy) and proves: the API enqueues durable work only (never contacts infrastructure);
validation errors never echo a token-shaped input; the bootstrap-availability endpoint returns only
a safe boolean + closed reason (never a path/contents); and the router/schema modules import no
privileged (worker/ssh/proxmox/openbao/subprocess/crypto/provider) code and accept no unsafe field.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    StagingDeploymentStatus,
    TargetStatus,
)
from secp_api.models import ExecutionTarget, TargetOnboarding

MARKER = "s3cr3t-hunter2"
MALICIOUS_LOGICAL_NAME = f"PVEAPIToken=user@pam!tok={MARKER}"


@pytest.fixture
def client(engine):
    from secp_api.db import session_scope
    from secp_api.main import create_app
    from secp_api.seed import bootstrap_dev

    with session_scope() as s:
        bootstrap_dev(s)
    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


def _seed_target_with_active_onboarding(engine) -> str:
    """Create a substrate + active onboarding in the dev org (visible to the TestClient session).

    Returns the target id as a string — the ORM instance is detached once the session closes.
    """
    from secp_api.db import get_sessionmaker
    from secp_api.models import Organization, User

    factory = get_sessionmaker()
    with factory() as s:
        org = s.query(Organization).order_by(Organization.created_at.asc()).first()
        user = s.query(User).filter(User.organization_id == org.id).first()
        target = ExecutionTarget(
            organization_id=org.id,
            display_name="substrate",
            plugin_name="proxmox",
            config={"base_url": "placeholder", "verify_tls": True},
            config_hash="sha256:" + "ab" * 32,
            secret_ref="vault:secp/proxmox/target-1",
            status=TargetStatus.active,
            scope_policy={},
            created_by=user.id,
        )
        s.add(target)
        s.flush()
        target_id = str(target.id)
        s.add(
            TargetOnboarding(
                organization_id=org.id,
                execution_target_id=target.id,
                onboarding_mode=OnboardingMode.existing_environment,
                isolation_model=IsolationModel.logical,
                status=OnboardingStatus.active,
                declared_boundary={},
                boundary_hash="sha256:" + "cd" * 32,
                created_by=user.id,
            )
        )
        s.commit()
        return target_id


def test_validation_422_never_echoes_input(client, engine):
    resp = client.post(
        "/api/v1/staging-deployments",
        json={
            "execution_target_id": "00000000-0000-0000-0000-000000000001",
            "logical_name": MALICIOUS_LOGICAL_NAME,
        },
    )
    assert resp.status_code == 422
    body = resp.text
    assert MALICIOUS_LOGICAL_NAME not in body
    assert MARKER not in body and "@pam" not in body
    assert resp.json() == {"error": {"code": "invalid_staging_deployment_input"}}

    from secp_api.db import get_sessionmaker
    from secp_api.models import AuditEvent, StagingDeployment

    with get_sessionmaker()() as s:
        assert s.query(StagingDeployment).count() == 0
        blob = " ".join(str(e.data) for e in s.query(AuditEvent).all())
        assert MARKER not in blob and MALICIOUS_LOGICAL_NAME not in blob


def test_full_control_plane_lifecycle_over_http(client, engine):
    target_id = _seed_target_with_active_onboarding(engine)

    # create -> draft
    r = client.post(
        "/api/v1/staging-deployments",
        json={"execution_target_id": target_id, "resource_profile": "small_lab"},
    )
    assert r.status_code == 201, r.text
    dep = r.json()
    dep_id = dep["id"]
    assert dep["status"] == StagingDeploymentStatus.draft.value
    assert dep["ownership_label"].startswith("secp-deploy-")
    # The response carries only safe fields — no host/endpoint/token/secret leak.
    for unsafe in ("secret", "token", "endpoint", "base_url", "ssh", "private", "vmid"):
        assert unsafe not in {k.lower() for k in dep}

    # plan -> planned (content-addressed)
    r = client.post(f"/api/v1/staging-deployments/{dep_id}/plan")
    assert r.status_code == 200, r.text
    plan_hash = r.json()["plan_hash"]
    assert plan_hash.startswith("sha256:")

    # GET plan shows safe resource categories only
    r = client.get(f"/api/v1/staging-deployments/{dep_id}/plan")
    assert r.status_code == 200
    plan = r.json()
    kinds = {res["kind"] for res in plan["resources"]}
    assert "isolated_bridge" in kinds and "control_plane_vm" in kinds
    assert plan["ownership_tag"].startswith("secp-owned:")

    # submit -> awaiting_approval
    r = client.post(f"/api/v1/staging-deployments/{dep_id}/submit")
    assert r.json()["status"] == StagingDeploymentStatus.awaiting_approval.value

    # approve with the EXACT plan hash -> approved
    r = client.post(
        f"/api/v1/staging-deployments/{dep_id}/approve",
        json={"expected_plan_hash": plan_hash},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == StagingDeploymentStatus.approved.value

    # deploy -> bootstrap_pending (enqueues durable apply; the API contacts nothing)
    r = client.post(f"/api/v1/staging-deployments/{dep_id}/deploy")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == StagingDeploymentStatus.bootstrap_pending.value

    # No resource is ever created by the API path — the deployment stays sealed until a worker runs.
    r = client.get(f"/api/v1/staging-deployments/{dep_id}/resources")
    assert r.status_code == 200 and r.json() == []

    # bootstrap availability is a SAFE boolean + closed reason (never a path/contents)
    r = client.get(f"/api/v1/staging-deployments/{dep_id}/bootstrap-availability")
    assert r.status_code == 200
    avail = r.json()
    assert avail == {"available": False, "reason_code": "deployment_local_bootstrap_not_mounted"}
    assert "/" not in avail["reason_code"]  # no filesystem location leaks


def test_approve_wrong_hash_and_deploy_before_approve_fail_closed(client, engine):
    target_id = _seed_target_with_active_onboarding(engine)
    dep_id = client.post(
        "/api/v1/staging-deployments", json={"execution_target_id": target_id}
    ).json()["id"]
    client.post(f"/api/v1/staging-deployments/{dep_id}/plan")
    client.post(f"/api/v1/staging-deployments/{dep_id}/submit")

    # Wrong plan hash is refused (stale approval).
    r = client.post(
        f"/api/v1/staging-deployments/{dep_id}/approve",
        json={"expected_plan_hash": "sha256:" + "00" * 32},
    )
    assert r.status_code == 400

    # Deploy before approval is refused.
    r = client.post(f"/api/v1/staging-deployments/{dep_id}/deploy")
    assert r.status_code == 400


def test_router_and_schema_import_no_privileged_code():
    """The router/schema modules must import NO worker/ssh/proxmox/openbao/subprocess/crypto code.

    Checked structurally over the actual import statements (not prose)."""
    import ast
    import inspect

    import secp_api.routers.staging_deployments as router_mod
    import secp_api.schemas_staging_deployment as schema_mod

    forbidden_roots = {
        "secp_worker",
        "secp_plugin_proxmox",
        "secp_plugin",
        "paramiko",
        "httpx",
        "subprocess",
        "cryptography",
        "socket",
        "ssl",
    }
    for mod in (router_mod, schema_mod):
        tree = ast.parse(inspect.getsource(mod))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        bad = imported & forbidden_roots
        assert not bad, f"{mod.__name__} imports forbidden modules: {bad}"


def test_create_schema_rejects_unsafe_fields():
    from secp_api.schemas_staging_deployment import DeploymentCreate

    allowed = set(DeploymentCreate.model_fields)
    assert allowed == {"execution_target_id", "resource_profile", "logical_name"}
    # Unknown / unsafe fields are ignored or rejected — never persisted as provider options.
    unsafe = {
        "execution_target_id": "00000000-0000-0000-0000-000000000001",
        "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
        "api_token": "PVEAPIToken=root@pam!x=secret",
        "host": "10.0.0.5",
        "bridge": "vmbr9",
        "vmid": 9001,
        "command": "rm -rf /",
    }
    model = DeploymentCreate(**unsafe)
    dumped = model.model_dump()
    for leaked in ("ssh_private_key", "api_token", "host", "bridge", "vmid", "command"):
        assert leaked not in dumped
