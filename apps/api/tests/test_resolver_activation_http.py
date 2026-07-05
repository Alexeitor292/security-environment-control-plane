"""SECP-B2-4.1 — HTTP-level: redacted validation + closed error codes for resolver-activation.

Drives the real ASGI app (in-process, no network). Proves request-validation failures on
``/api/v1/resolver-activation[...]`` return only the safe generic code (never the rejected value),
and that service refusals serialize as closed codes with no free-form message.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

MARKER = "vault:secp/leak/hunter2"


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


SAFE = {"error": {"code": "invalid_resolver_activation_input"}}


def test_create_malformed_body_is_redacted(client):
    resp = client.post("/api/v1/resolver-activation/authorizations", json={"preflight_id": MARKER})
    assert resp.status_code == 422
    assert resp.json() == SAFE
    assert MARKER not in resp.text and "vault" not in resp.text


def test_evidence_malformed_proof_is_redacted(client):
    resp = client.post(
        f"/api/v1/resolver-activation/authorizations/{uuid.uuid4()}/evidence",
        json={
            "kind": "isolated_staging_identity",
            "status": "verified",
            "proof_id": MARKER,
            "issuer": "rev",
        },
    )
    assert resp.status_code == 422
    assert resp.json() == SAFE
    assert MARKER not in resp.text


def test_not_found_serializes_closed_code_only(client):
    resp = client.get(f"/api/v1/resolver-activation/authorizations/{uuid.uuid4()}")
    assert resp.status_code == 404
    assert resp.json() == {"error": {"code": "resolver_activation_not_found"}}
    assert "message" not in resp.text and "detail" not in resp.text


def test_unrelated_route_validation_unchanged(client):
    resp = client.post("/api/v1/targets", json={"display_name": 123})
    assert resp.status_code == 422
    assert "detail" in resp.json()  # FastAPI default shape preserved for unrelated routes


def test_prefix_lookalike_route_is_not_redacted(client):
    resp = client.post("/api/v1/resolver-activationX", json={})
    assert resp.status_code == 404
    assert resp.json() != SAFE


# --- FIX 3: approve-on-expired must COMMIT the expiry transition while returning a closed 409 ---


def _seed_expired_draft() -> uuid.UUID:
    """Seed a work item + a DRAFT resolver-activation authorization in the dev org, then back-date
    its expiry (raw Core update: SQLite has no immutability trigger and Core bypasses the ORM guard,
    so this stands in for wall-clock expiry). Returns the authorization id."""
    from datetime import UTC, datetime, timedelta

    from secp_api.auth import Principal, dev_principal
    from secp_api.db import session_scope
    from secp_api.enums import (
        IsolationModel,
        LiveReadAuthorizationStatus,
        OnboardingMode,
        OnboardingStatus,
        Permission,
        ReadonlyPreflightStatus,
        TargetStatus,
    )
    from secp_api.live_read_contract import (
        LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        LIVE_READ_EVIDENCE_SOURCE,
        LIVE_VERIFIED_LEVEL,
        PROXMOX_READONLY_POLICY_VERSION,
    )
    from secp_api.models import (
        ExecutionTarget,
        LiveReadAuthorization,
        ReadonlyStagingPreflight,
        ResolverActivationAuthorization,
        TargetOnboarding,
    )
    from secp_api.services import resolver_activation as ra
    from sqlalchemy import update

    now = datetime.now(UTC)
    with session_scope() as s:
        org_id = dev_principal(s).organization_id
        target = ExecutionTarget(
            organization_id=org_id,
            display_name="t",
            plugin_name="proxmox",
            config={"base_url": "x"},
            config_hash="sha256:" + "ab" * 32,
            secret_ref="vault:secp/x",
            status=TargetStatus.active,
            scope_policy={},
        )
        s.add(target)
        s.flush()
        ob = TargetOnboarding(
            organization_id=org_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
        )
        s.add(ob)
        s.flush()
        auth = LiveReadAuthorization(
            organization_id=org_id,
            execution_target_id=target.id,
            onboarding_id=ob.id,
            connection_hash="sha256:" + "ab" * 32,
            boundary_hash="sha256:" + "cd" * 32,
            authorization_version=1,
            authorization_expiry=now + timedelta(hours=2),
            collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
            endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
            evidence_source=LIVE_READ_EVIDENCE_SOURCE,
            verification_level=LIVE_VERIFIED_LEVEL,
            status=LiveReadAuthorizationStatus.approved,
        )
        s.add(auth)
        s.flush()
        pf = ReadonlyStagingPreflight(
            organization_id=org_id,
            execution_target_id=target.id,
            onboarding_id=ob.id,
            live_read_authorization_id=auth.id,
            authorization_version=1,
            collector_contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
            endpoint_allowlist_version=PROXMOX_READONLY_POLICY_VERSION,
            operation_fingerprint="sha256:" + uuid.uuid4().hex + uuid.uuid4().hex,
            status=ReadonlyPreflightStatus.running,
            revision=0,
        )
        s.add(pf)
        s.flush()
        actor = Principal(
            user_id=uuid.uuid4(),
            organization_id=org_id,
            email="a@b",
            permissions=frozenset(Permission),
        )
        draft = ra.create_activation_authorization(s, actor, preflight_id=pf.id)
        s.flush()
        s.execute(
            update(ResolverActivationAuthorization)
            .where(ResolverActivationAuthorization.id == draft.id)
            .values(authorization_expiry=now - timedelta(seconds=1))
        )
        auth_id = draft.id
        s.commit()
    return auth_id


def _count_expiration_audits(auth_id: uuid.UUID) -> int:
    from secp_api.db import session_scope
    from secp_api.models import AuditEvent

    with session_scope() as s:
        return (
            s.query(AuditEvent)
            .filter_by(action="resolver_activation.expired", resource_id=str(auth_id))
            .count()
        )


def _status_of(auth_id: uuid.UUID) -> str:
    from secp_api.db import session_scope
    from secp_api.models import ResolverActivationAuthorization

    with session_scope() as s:
        row = s.get(ResolverActivationAuthorization, auth_id)
        return row.status.value


def test_expired_approve_returns_closed_409_and_persists_expiry_and_one_audit(client):
    auth_id = _seed_expired_draft()

    resp = client.post(f"/api/v1/resolver-activation/authorizations/{auth_id}/approve")
    assert resp.status_code == 409
    assert resp.json() == {"error": {"code": "resolver_activation_invalid_state"}}
    assert "message" not in resp.text and "detail" not in resp.text

    # The terminal expired transition + its single expiration audit COMMITTED despite the 409.
    assert _status_of(auth_id) == "expired"
    assert _count_expiration_audits(auth_id) == 1


def test_no_approval_succeeds_after_expiration_and_no_duplicate_audit(client):
    auth_id = _seed_expired_draft()
    first = client.post(f"/api/v1/resolver-activation/authorizations/{auth_id}/approve")
    assert first.status_code == 409

    # A second approve on the now-expired (terminal) row stays a closed 409 and emits NO new audit.
    second = client.post(f"/api/v1/resolver-activation/authorizations/{auth_id}/approve")
    assert second.status_code == 409
    assert second.json() == {"error": {"code": "resolver_activation_invalid_state"}}
    assert _status_of(auth_id) == "expired"
    assert _count_expiration_audits(auth_id) == 1
