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


# --- expired approval over HTTP: closed 409 + durable expiry transition + audit-once ------------


def _seed_expired_draft_registration() -> uuid.UUID:
    """Seed a fully-evidenced DRAFT worker-identity registration in the dev org, then back-date its
    expiry via a raw Core update (SQLite has no immutability trigger and Core bypasses the ORM
    guard, standing in for wall-clock expiry). Returns the registration id."""
    from datetime import UTC, datetime, timedelta

    from secp_api.auth import Principal, dev_principal
    from secp_api.db import session_scope
    from secp_api.enums import (
        Permission,
        WorkerIdentityEvidenceKind,
        WorkerIdentityEvidenceStatus,
        WorkerIdentityMechanism,
    )
    from secp_api.models import WorkerIdentityRegistration
    from secp_api.services import worker_identity as wi
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
    from sqlalchemy import update

    now = datetime.now(UTC)
    with session_scope() as s:
        org_id = dev_principal(s).organization_id
        actor = Principal(
            user_id=uuid.uuid4(),
            organization_id=org_id,
            email="a@b",
            permissions=frozenset(Permission),
        )
        row = wi.register_worker_identity(
            s,
            actor,
            mechanism=WorkerIdentityMechanism.mtls_workload_identity,
            identity_label="staging-worker-a",
            deployment_binding="deploy-01",
            verification_anchor_fingerprint=compute_verification_anchor_fingerprint("anchor-v1"),
        )
        for kind in WorkerIdentityEvidenceKind:
            wi.record_evidence(
                s,
                actor,
                row.id,
                kind=kind,
                status=WorkerIdentityEvidenceStatus.verified,
                proof_id="TKT-1",
                issuer="rev",
            )
        s.flush()
        s.execute(
            update(WorkerIdentityRegistration)
            .where(WorkerIdentityRegistration.id == row.id)
            .values(expiry=now - timedelta(seconds=1))
        )
        reg_id = row.id
        s.commit()
    return reg_id


def _count_expiration_audits(reg_id: uuid.UUID) -> int:
    from secp_api.db import session_scope
    from secp_api.models import AuditEvent

    with session_scope() as s:
        return (
            s.query(AuditEvent)
            .filter_by(action="worker_identity.expired", resource_id=str(reg_id))
            .count()
        )


def _status_of(reg_id: uuid.UUID) -> str:
    from secp_api.db import session_scope
    from secp_api.models import WorkerIdentityRegistration

    with session_scope() as s:
        return s.get(WorkerIdentityRegistration, reg_id).status.value


def test_expired_approve_returns_closed_409_and_persists_expiry_and_one_audit(client):
    reg_id = _seed_expired_draft_registration()

    resp = client.post(f"/api/v1/worker-identity/registrations/{reg_id}/approve")
    assert resp.status_code == 409
    assert resp.json() == {"error": {"code": "worker_identity_invalid_state"}}
    assert "message" not in resp.text and "detail" not in resp.text

    # The terminal ``expired`` transition + its single expiration audit COMMITTED despite the 409 —
    # the router commits the durable transition before re-raising, so ``db_session``'s rollback
    # (which normally undoes an errored request) does NOT undo it.
    assert _status_of(reg_id) == "expired"
    assert _count_expiration_audits(reg_id) == 1


def test_no_approval_succeeds_after_expiration_and_no_duplicate_audit(client):
    reg_id = _seed_expired_draft_registration()
    first = client.post(f"/api/v1/worker-identity/registrations/{reg_id}/approve")
    assert first.status_code == 409

    # A second approve on the now-expired (terminal) row stays a closed 409 and emits NO new audit.
    second = client.post(f"/api/v1/worker-identity/registrations/{reg_id}/approve")
    assert second.status_code == 409
    assert second.json() == {"error": {"code": "worker_identity_invalid_state"}}
    assert _status_of(reg_id) == "expired"
    assert _count_expiration_audits(reg_id) == 1
