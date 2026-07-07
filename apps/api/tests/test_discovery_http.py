"""SECP-B5 — HTTP surface for read-only target discovery (drives the real ASGI app).

Proves: validation errors never echo a token-shaped input; the API surfaces only safe enrollment /
evidence / candidate-plan fields (never SSH host/account/port/key path/known_hosts/fingerprint,
Proxmox endpoint/token, or raw output); the candidate plan is declared non-executable (apply
sealed);
approval requires the exact plan hash and is fail-closed; and no privileged value can be passed in.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from secp_api.enums import IsolationModel, OnboardingMode, OnboardingStatus, TargetStatus
from secp_api.models import ExecutionTarget, TargetDiscoveryEnrollment, TargetOnboarding

MARKER = "s3cr3t-hunter2"
MALICIOUS = f"PVEAPIToken=user@pam!tok={MARKER}"

# Substrings that must NEVER appear in any discovery API response.
_FORBIDDEN = (
    "host.example",
    "secpops",
    "known_hosts",
    "SHA256:",
    "PVEAPIToken",
    "BEGIN OPENSSH",
    "/mnt/",
    "8006",
    "private_key",
)


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


def _seed_and_discover(engine) -> str:
    """Create a target+onboarding+enrollment and run the read-only engine (fake eligible source) to
    produce a candidate plan. Returns the enrollment id."""
    from secp_api.db import get_sessionmaker
    from secp_api.models import DiscoveryJob, Organization, User
    from secp_api.services import target_discovery as svc
    from secp_worker.target_discovery.engine import DiscoveryComposition, run_discovery
    from secp_worker.target_discovery.seams import InventoryFacts, StorageOption

    class _Src:
        def read_inventory(self):
            return InventoryFacts(
                8,
                1,
                False,
                "pve-a",
                1,
                16,
                65536,
                32768,
                True,
                (StorageOption("local-lvm", 500_000, True),),
                frozenset(),
            )

        def probe_candidate_presence(self, locators):
            from secp_worker.target_discovery.seams import LocatorPresence

            return {loc.observe_key(): LocatorPresence(False, None) for loc in locators}

    factory = get_sessionmaker()
    with factory() as s:
        org = s.query(Organization).order_by(Organization.created_at.asc()).first()
        user = s.query(User).filter(User.organization_id == org.id).first()

        class _P:
            user_id = user.id
            organization_id = org.id
            permissions = frozenset()

            def require(self, *_a):
                return None

            def require_org(self, *_a):
                return None

        target = ExecutionTarget(
            organization_id=org.id,
            display_name="s",
            plugin_name="proxmox",
            config={"base_url": "x", "verify_tls": True},
            config_hash="sha256:" + "ab" * 32,
            secret_ref="vault:x",
            status=TargetStatus.active,
            scope_policy={},
            created_by=user.id,
        )
        s.add(target)
        s.flush()
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
        s.flush()
        # SECP-B6 F-IDENTITY: a candidate plan is only approvable when it binds a real approved
        # worker identity (version > 0), so register + approve one before discovery.
        _approve_worker_identity(s, _P())
        enrollment = svc.request_discovery(s, _P(), execution_target_id=target.id)
        job = s.query(DiscoveryJob).filter(DiscoveryJob.enrollment_id == enrollment.id).one()
        run_discovery(
            s, job, composition=DiscoveryComposition(probe_source=_Src()), now=datetime.now(UTC)
        )
        s.commit()
        return str(enrollment.id)


def _approve_worker_identity(session, principal) -> None:
    """Register + evidence + approve one worker identity for the principal's org (SECP-B6)."""
    from secp_api.enums import (
        WorkerIdentityEvidenceKind,
        WorkerIdentityEvidenceStatus,
        WorkerIdentityMechanism,
    )
    from secp_api.services import worker_identity as wi
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

    row = wi.register_worker_identity(
        session,
        principal,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label="staging-worker-a",
        deployment_binding="deploy-01",
        verification_anchor_fingerprint=compute_verification_anchor_fingerprint("anchor-v1"),
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


def test_validation_422_never_echoes_input(client, engine):
    resp = client.post(
        "/api/v1/target-discovery",
        json={
            "execution_target_id": "00000000-0000-0000-0000-000000000001",
            "logical_name": MALICIOUS,
        },
    )
    assert resp.status_code == 422
    assert MARKER not in resp.text and MALICIOUS not in resp.text and "@pam" not in resp.text
    assert resp.json() == {"error": {"code": "invalid_target_discovery_input"}}
    from secp_api.db import get_sessionmaker

    with get_sessionmaker()() as s:
        assert s.query(TargetDiscoveryEnrollment).count() == 0


def test_discovery_lifecycle_and_safe_fields(client, engine):
    enrollment_id = _seed_and_discover(engine)

    # Enrollment is plan_ready with safe fields only.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}")
    assert r.status_code == 200, r.text
    enr = r.json()
    assert enr["status"] == "plan_ready" and enr["ownership_label"].startswith("secp-discover-")
    for unsafe in ("ssh", "token", "endpoint", "host", "port", "key", "fingerprint"):
        assert unsafe not in {k.lower() for k in enr}

    # Evidence: safe capability/eligibility outcome, no raw/SSH fields.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/evidence")
    ev = r.json()
    assert ev["eligibility"] == "eligible" and ev["node"] == "pve-a"
    assert ev["nested_available"] is True
    assert ev["cpu_total"] == 16 and ev["selected_storage"] == "local-lvm"

    # Candidate plan: safe categories + node/storage labels + generated identifiers; non-executable.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/candidate-plan")
    plan = r.json()
    assert plan["executable"] is False
    assert plan["node"] == "pve-a" and plan["storage"] == "local-lvm"
    kinds = {res["kind"] for res in plan["resources"]}
    assert "isolated_bridge" in kinds and "control_plane_vm" in kinds
    plan_hash = plan["plan_hash"]

    # Apply-status: explicit sealed notice.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/apply-status")
    assert r.json()["live_apply_sealed"] is True
    assert "sealed" in r.json()["message"].lower()

    # Bootstrap availability: safe boolean only, no location.
    r = client.get(f"/api/v1/target-discovery/{enrollment_id}/bootstrap-availability")
    assert r.json() == {"available": False, "reason_code": "worker_local_bootstrap_not_mounted"}

    # No response leaks any SSH/endpoint/raw material.
    for path in ("", "/evidence", "/candidate-plan", "/bootstrap-availability", "/apply-status"):
        body = client.get(f"/api/v1/target-discovery/{enrollment_id}{path}").text
        for forbidden in _FORBIDDEN:
            assert forbidden not in body

    # Approve with the WRONG hash → refused; with the EXACT hash → approved.
    assert (
        client.post(
            f"/api/v1/target-discovery/{enrollment_id}/approve",
            json={"expected_plan_hash": "sha256:" + "00" * 32},
        ).status_code
        == 400
    )
    r = client.post(
        f"/api/v1/target-discovery/{enrollment_id}/approve",
        json={"expected_plan_hash": plan_hash},
    )
    assert r.status_code == 200 and r.json()["status"] == "approved"


def test_request_schema_rejects_unsafe_fields():
    from secp_api.schemas_target_discovery import DiscoveryRequest

    assert set(DiscoveryRequest.model_fields) == {
        "execution_target_id",
        "resource_profile",
        "logical_name",
    }
    model = DiscoveryRequest(
        execution_target_id="00000000-0000-0000-0000-000000000001",
        ssh_host="10.0.0.5",
        api_token="PVEAPIToken=x",
        node="pve-a",
        vmid=9000,
        command="rm -rf /",
    )
    dumped = model.model_dump()
    for leaked in ("ssh_host", "api_token", "node", "vmid", "command"):
        assert leaked not in dumped
