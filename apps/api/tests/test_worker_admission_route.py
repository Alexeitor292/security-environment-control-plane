"""SECP-B6 MB-1 — internal worker-admission route (drives the real ASGI app).

Proves the route is internal + inert-by-default, wraps the control-plane-verified service, and — the
key anti-spoofing property — a request BODY asserting a public anchor cannot impersonate a worker:
only a signature that verifies against the registration's pinned anchor is admitted.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from secp_api.config import Settings
from secp_api.deps import settings_dep

# Uppercase so the no-real-endpoints guard (which scans lowercase ``base_url`` lines) skips this
# non-routable test host, matching the convention in the other discovery test modules.
_BASE_URL = "https://pve-a.internal:8006"


@pytest.fixture
def app_and_ctx(engine):
    """Build the app + commit a worker/target/authorization/job, returning the admission context."""
    from secp_api.db import get_sessionmaker, session_scope
    from secp_api.enums import (
        IsolationModel,
        OnboardingMode,
        OnboardingStatus,
        TargetStatus,
        WorkerIdentityEvidenceKind,
        WorkerIdentityEvidenceStatus,
        WorkerIdentityMechanism,
    )
    from secp_api.live_read_contract import normalize_target_host, ssh_endpoint_binding_hash
    from secp_api.main import create_app
    from secp_api.models import DiscoveryJob, ExecutionTarget, Organization, TargetOnboarding, User
    from secp_api.seed import bootstrap_dev
    from secp_api.services import readonly_preflight, staging_labs
    from secp_api.services import target_discovery as td
    from secp_api.services import worker_identity as wi
    from secp_api.worker_admission_contract import (
        compute_verification_anchor_fingerprint,
        generate_ed25519_keypair,
    )

    ebh = ssh_endpoint_binding_hash(
        normalized_target_host=normalize_target_host({"base_url": _BASE_URL}),
        ssh_host="pve-a.internal",
        ssh_port=22,
        host_key_fingerprint="SHA256:" + "A" * 43,
    )
    priv, pub = generate_ed25519_keypair()
    ctx: dict = {"priv": priv, "pub": pub, "endpoint_binding_hash": ebh}
    with session_scope() as s:
        bootstrap_dev(s)
    with get_sessionmaker()() as s:
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

        p = _P()
        row = wi.register_worker_identity(
            s,
            p,
            mechanism=WorkerIdentityMechanism.mtls_workload_identity,
            identity_label="worker-a",
            deployment_binding="deploy-a",
            verification_anchor_fingerprint=compute_verification_anchor_fingerprint(pub),
        )
        for kind in WorkerIdentityEvidenceKind:
            wi.record_evidence(
                s,
                p,
                row.id,
                kind=kind,
                status=WorkerIdentityEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        wi.approve_worker_identity(s, p, row.id)
        target = ExecutionTarget(
            organization_id=org.id,
            display_name="t",
            plugin_name="proxmox",
            config={"base_url": _BASE_URL, "verify_tls": True},
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
        staging_labs.grant_substrate_eligibility(s, p, execution_target_id=target.id)
        auth = readonly_preflight.create_preflight_authorization(
            s, p, execution_target_id=target.id, endpoint_binding_hash=ebh
        )
        auth = readonly_preflight.approve_preflight_authorization(s, p, auth.id)
        enrollment = td.request_discovery(s, p, execution_target_id=target.id)
        job = s.query(DiscoveryJob).filter(DiscoveryJob.enrollment_id == enrollment.id).one()
        ctx["job_id"] = str(job.id)
        ctx["authorization_id"] = str(auth.id)
        ctx["authorization_version"] = auth.authorization_version
        s.commit()

    app = create_app()
    app.router.on_startup.clear()
    return app, ctx


def _enabled_client(app) -> TestClient:
    app.dependency_overrides[settings_dep] = lambda: Settings(
        discovery_controlled_integration_enabled=True
    )
    return TestClient(app)


def test_route_inert_when_profile_disabled(app_and_ctx):
    app, ctx = app_and_ctx
    client = TestClient(app)  # default settings → profile disabled
    r = client.post(
        "/internal/worker-discovery-admission/begin",
        json={
            "discovery_job_id": ctx["job_id"],
            "authorization_id": ctx["authorization_id"],
            "authorization_version": ctx["authorization_version"],
            "endpoint_binding_hash": ctx["endpoint_binding_hash"],
        },
    )
    assert r.status_code == 404


def test_route_handshake_and_body_spoof_refused(app_and_ctx):
    from secp_api.worker_admission_contract import admission_signing_message, ed25519_sign

    app, ctx = app_and_ctx
    client = _enabled_client(app)
    begin = client.post(
        "/internal/worker-discovery-admission/begin",
        json={
            "discovery_job_id": ctx["job_id"],
            "authorization_id": ctx["authorization_id"],
            "authorization_version": ctx["authorization_version"],
            "endpoint_binding_hash": ctx["endpoint_binding_hash"],
        },
    )
    assert begin.status_code == 200, begin.text
    body = begin.json()
    message = admission_signing_message(
        nonce=body["nonce"],
        organization_id=body["organization_id"],
        discovery_job_id=body["discovery_job_id"],
        worker_registration_id=body["worker_registration_id"],
        identity_version=body["identity_version"],
        endpoint_binding_hash=body["endpoint_binding_hash"],
        expires_at=datetime.fromisoformat(body["expires_at"]).astimezone(UTC),
    )

    # Anti-spoof: a body asserting an UNREGISTERED anchor + a matching signature is refused (the
    # anchor is pinned to the registration's fingerprint, not trusted from the body).
    from secp_api.worker_admission_contract import generate_ed25519_keypair

    spoof_priv, spoof_pub = generate_ed25519_keypair()
    spoof_sig = ed25519_sign(private_key_hex=spoof_priv, message=message)
    bad = client.post(
        "/internal/worker-discovery-admission/complete",
        json={
            "admission_id": body["admission_id"],
            "public_anchor": spoof_pub,
            "signature": spoof_sig,
        },
    )
    assert bad.status_code == 403
    assert bad.json()["detail"]["reason_code"] == "anchor_pin_mismatch"

    # The genuine registered key completes the admission.
    good_sig = ed25519_sign(private_key_hex=ctx["priv"], message=message)
    ok = client.post(
        "/internal/worker-discovery-admission/complete",
        json={
            "admission_id": body["admission_id"],
            "public_anchor": ctx["pub"],
            "signature": good_sig,
        },
    )
    assert ok.status_code == 200 and ok.json()["status"] == "admitted"
