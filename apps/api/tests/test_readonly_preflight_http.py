"""SECP-B2-0 — HTTP-level regression: read-only preflight never echoes input, closed codes only.

Drives the real ASGI app (in-process, no network). Proves (1) request-validation failures on
`/api/v1/readonly-preflight[...]` return only the safe generic code and never echo the submitted
value/body/detail, and (2) service DomainError paths serialize as closed codes with no free-form
message. Also confirms unrelated routes keep their default behavior.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

MARKER = "s3cr3t-hunter2"
CRED_SHAPED = f"PVEAPIToken=user@pam!tok={MARKER}"


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


def _eligible_with_draft_auth():
    """Create an eligible substrate + a DRAFT (unapproved) authorization; return (target, auth)."""
    from secp_api.db import get_sessionmaker
    from secp_api.enums import (
        IsolationModel,
        OnboardingMode,
        OnboardingStatus,
        TargetStatus,
    )
    from secp_api.models import ExecutionTarget, TargetOnboarding
    from secp_api.seed import bootstrap_dev
    from secp_api.services import readonly_preflight, staging_labs

    with get_sessionmaker()() as s:
        p = bootstrap_dev(s)
        target = ExecutionTarget(
            organization_id=p.organization_id,
            display_name="substrate",
            plugin_name="proxmox",
            config={"base_url": "placeholder", "verify_tls": True},
            config_hash="sha256:" + "ab" * 32,
            secret_ref="env:SECP_PROVIDER_SECRET__PF",
            status=TargetStatus.active,
            scope_policy={},
            created_by=p.user_id,
        )
        s.add(target)
        s.flush()
        s.add(
            TargetOnboarding(
                organization_id=p.organization_id,
                execution_target_id=target.id,
                onboarding_mode=OnboardingMode.existing_environment,
                isolation_model=IsolationModel.logical,
                status=OnboardingStatus.active,
                declared_boundary={},
                boundary_hash="sha256:" + "cd" * 32,
                created_by=p.user_id,
            )
        )
        s.flush()
        staging_labs.grant_substrate_eligibility(s, p, execution_target_id=target.id)
        auth = readonly_preflight.create_preflight_authorization(
            s, p, execution_target_id=target.id
        )  # draft (not approved)
        s.commit()
        return target.id, auth.id


SAFE_VALIDATION_BODY = {"error": {"code": "invalid_readonly_preflight_input"}}


def test_create_authorization_bad_uuid_is_redacted(client):
    resp = client.post(
        "/api/v1/readonly-preflight/authorizations",
        json={"execution_target_id": CRED_SHAPED},
    )
    assert resp.status_code == 422
    # Exact-body equality fully pins the response (no pydantic input/ctx/url/detail keys).
    assert resp.json() == SAFE_VALIDATION_BODY
    assert MARKER not in resp.text and "@pam" not in resp.text


def test_queue_malformed_body_is_redacted(client):
    resp = client.post(
        "/api/v1/readonly-preflight", json={"live_read_authorization_id": CRED_SHAPED}
    )
    assert resp.status_code == 422
    assert resp.json() == SAFE_VALIDATION_BODY
    assert MARKER not in resp.text


def test_nested_action_route_malformed_uuid_is_redacted(client):
    # A nested readonly-preflight action route with a malformed path UUID must also be redacted.
    resp = client.post(f"/api/v1/readonly-preflight/authorizations/{CRED_SHAPED}/approve")
    assert resp.status_code == 422
    assert resp.json() == SAFE_VALIDATION_BODY
    assert MARKER not in resp.text


def test_not_found_serializes_closed_code_only(client):
    # A well-formed but unknown authorization id -> closed code, no free-form message/detail.
    resp = client.post(
        "/api/v1/readonly-preflight", json={"live_read_authorization_id": str(uuid.uuid4())}
    )
    assert resp.status_code == 404
    assert resp.json() == {"error": {"code": "readonly_preflight_not_found"}}
    assert "message" not in resp.text and "detail" not in resp.text


def test_authorization_invalid_serializes_closed_code_only(client, engine):
    _target_id, auth_id = _eligible_with_draft_auth()
    # Queueing a DRAFT (unapproved) authorization -> closed authorization_invalid, no message.
    resp = client.post(
        "/api/v1/readonly-preflight", json={"live_read_authorization_id": str(auth_id)}
    )
    assert resp.status_code == 409
    assert resp.json() == {"error": {"code": "readonly_preflight_authorization_invalid"}}
    body = resp.text.lower()
    for forbidden in ("message", "not approved", "draft", "authorization is not"):
        assert forbidden not in body


def test_no_persistence_or_audit_leak_on_validation_failure(client, engine):
    resp = client.post(
        "/api/v1/readonly-preflight/authorizations",
        json={"execution_target_id": CRED_SHAPED, "ttl_seconds": 900},
    )
    assert resp.status_code == 422
    from secp_api.db import get_sessionmaker
    from secp_api.models import AuditEvent, ReadonlyStagingPreflight

    with get_sessionmaker()() as s:
        assert s.query(ReadonlyStagingPreflight).count() == 0
        blob = " ".join(str(e.data) for e in s.query(AuditEvent).all())
        assert MARKER not in blob and CRED_SHAPED not in blob


def test_unrelated_route_validation_unchanged(client):
    resp = client.post("/api/v1/targets", json={"display_name": 123})
    assert resp.status_code == 422
    assert "detail" in resp.json()  # FastAPI default shape preserved


def test_staging_lab_validation_still_redacted(client):
    resp = client.post(
        "/api/v1/staging-labs",
        json={
            "execution_target_id": "00000000-0000-0000-0000-000000000001",
            "logical_name": "BAD NAME",
        },
    )
    assert resp.status_code == 422
    assert resp.json() == {"error": {"code": "invalid_staging_lab_input"}}


def test_prefix_lookalike_route_is_not_redacted(client):
    # Segment-aware gate: a lookalike path that merely shares a prefix must NOT get the redacted
    # readonly-preflight code (it is a 404 route, not a validation redaction).
    resp = client.post("/api/v1/readonly-preflightX", json={})
    assert resp.status_code == 404
    assert resp.json() != SAFE_VALIDATION_BODY
