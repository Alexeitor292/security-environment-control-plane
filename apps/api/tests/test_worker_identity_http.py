"""SECP-B2-4.3 — HTTP-level: redacted validation + closed error codes for worker-identity.

Drives the real ASGI app (in-process, no network). Proves request-validation failures on
``/api/v1/worker-identity[...]`` return only the safe generic code (never the rejected value), and
that service refusals serialize as closed codes with no free-form message.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

# A value shaped like a leaked secret/anchor/endpoint — it must never appear in any response body.
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


SAFE = {"error": {"code": "invalid_worker_identity_input"}}


def test_register_malformed_label_is_redacted(client):
    resp = client.post(
        "/api/v1/worker-identity/registrations",
        json={
            "mechanism": "mtls_workload_identity",
            "identity_label": MARKER,
            "deployment_binding": "deploy-01",
            "verification_anchor_fingerprint": "sha256:" + "ab" * 32,
        },
    )
    assert resp.status_code == 422
    assert resp.json() == SAFE
    assert MARKER not in resp.text and "vault" not in resp.text


def test_register_malformed_anchor_fingerprint_is_redacted(client):
    resp = client.post(
        "/api/v1/worker-identity/registrations",
        json={
            "mechanism": "mtls_workload_identity",
            "identity_label": "staging-worker-a",
            "deployment_binding": "deploy-01",
            "verification_anchor_fingerprint": MARKER,
        },
    )
    assert resp.status_code == 422
    assert resp.json() == SAFE
    assert MARKER not in resp.text


def test_evidence_malformed_proof_is_redacted(client):
    resp = client.post(
        f"/api/v1/worker-identity/registrations/{uuid.uuid4()}/evidence",
        json={
            "kind": "deployment_binding_review",
            "status": "verified",
            "proof_id": MARKER,
            "issuer": "rev",
        },
    )
    assert resp.status_code == 422
    assert resp.json() == SAFE
    assert MARKER not in resp.text


def test_not_found_serializes_closed_code_only(client):
    resp = client.get(f"/api/v1/worker-identity/registrations/{uuid.uuid4()}")
    assert resp.status_code == 404
    assert resp.json() == {"error": {"code": "worker_identity_not_found"}}
    assert "message" not in resp.text and "detail" not in resp.text


def test_unrelated_route_validation_unchanged(client):
    resp = client.post("/api/v1/targets", json={"display_name": 123})
    assert resp.status_code == 422
    assert "detail" in resp.json()  # FastAPI default shape preserved for unrelated routes


def test_prefix_lookalike_route_is_not_redacted(client):
    resp = client.post("/api/v1/worker-identityX", json={})
    assert resp.status_code == 404
    assert resp.json() != SAFE


def test_full_lifecycle_over_http_is_secret_free(client):
    # Register -> record all evidence -> approve, all over HTTP; the response is closed-shape and
    # carries only ids/enums/safe hashes/timestamps — never an anchor value or secret.
    reg = client.post(
        "/api/v1/worker-identity/registrations",
        json={
            "mechanism": "mtls_workload_identity",
            "identity_label": "staging-worker-a",
            "deployment_binding": "deploy-01",
            "verification_anchor_fingerprint": "sha256:" + "cd" * 32,
        },
    )
    assert reg.status_code == 201, reg.text
    rid = reg.json()["id"]
    assert reg.json()["status"] == "draft"
    assert reg.json()["evidence_fingerprint"] == ""

    for kind in (
        "deployment_binding_review",
        "verification_anchor_review",
        "rotation_revocation_review",
    ):
        ev = client.post(
            f"/api/v1/worker-identity/registrations/{rid}/evidence",
            json={"kind": kind, "status": "verified", "proof_id": "TKT-1", "issuer": "rev"},
        )
        assert ev.status_code == 200, ev.text

    approved = client.post(f"/api/v1/worker-identity/registrations/{rid}/approve")
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["status"] == "approved"
    assert body["evidence_fingerprint"].startswith("sha256:")
    # No secret/backend/certificate field anywhere in the response.
    for banned in ("certificate", "private", "secret", "token", "endpoint", "://", "public_key"):
        assert banned not in approved.text.lower()
