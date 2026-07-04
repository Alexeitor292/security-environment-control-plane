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
