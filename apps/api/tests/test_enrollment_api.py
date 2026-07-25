"""Supported worker-enrollment controller API — first vertical slice (SECP-PR5H-B1).

Drives the controller invitation lifecycle through the real ASGI app on a per-test engine: create a
single-use invitation (opening its durable enrollment at revision 0) and read the bounded status
projection. Proves the org-boundary authorization and the secret-free projection end to end over
HTTP, wired to the PR5H-A durable service — no direct service calls for the happy path.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from secp_api.worker_enrollment_contract import create_invitation, sha256_digest_of_hex

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = sha256_digest_of_hex(CTRL_HEX)
RELEASE = "sha256:" + "a" * 64
ORIGIN = "https://ctrl.example.com"
SITE = "rack-01.eu_a"


@pytest.fixture
def client(engine, principal):
    from secp_api.main import create_app
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD

    # the durable enrollment service refuses unless the live schema head is the required one; the
    # ORM ``create_all`` does not manage ``alembic_version``, so stamp it here (as production
    # migrations would). ``b6e2f4a9c1d7`` is the sole PR5H-A head.
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )

    app = create_app()
    app.router.on_startup.clear()  # the per-test engine is already seeded via fixtures
    return TestClient(app)


def _create_body(**over: object) -> dict:
    body: dict = dict(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        deployment_site_label=SITE,
        ttl_seconds=3600,
    )
    body.update(over)
    return body


def test_create_invitation_opens_enrollment_and_is_readable(client):
    r = client.post("/api/v1/enrollment/invitations", json=_create_body())
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["state"] == "invited" and out["revision"] == 0
    assert out["invitation_id"].startswith("sha256:")
    assert out["enrollment_id"].startswith("sha256:")
    assert out["controller_origin"] == ORIGIN
    assert out["deployment_site_label"] == SITE

    # the enrollment is readable at INVITED via the bounded status projection
    s = client.get(f"/api/v1/enrollment/{out['enrollment_id']}")
    assert s.status_code == 200, s.text
    status = s.json()
    assert status["state"] == "invited" and status["revision"] == 0
    assert status["worker_installation_id"] == ""  # not yet bound
    # the projection is secret-free: no trust anchor / raw key material rides through
    assert "controller_trust_anchor_hex" not in status
    assert "worker_key_fingerprint" in status


def test_status_of_unknown_enrollment_is_not_found(client):
    r = client.get("/api/v1/enrollment/sha256:" + "0" * 64)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "enrollment_not_found"


def test_cross_org_status_is_forbidden(client, session, other_org_principal):
    # seed an enrollment in a DIFFERENT organization directly through the durable service...
    from secp_api.services import worker_enrollment as svc

    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-cross",
        nonce="sha256:" + "b" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    seeded = svc.create_invitation_and_open(
        session,
        other_org_principal,
        invitation=invitation,
        deployment_site_label=SITE,
        now="2026-07-21T00:10:00Z",
    )
    session.commit()
    # ...and the authenticated dev principal (a different org) must NOT be able to read it
    r = client.get(f"/api/v1/enrollment/{seeded.state.enrollment_id}")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "enrollment_forbidden"


def test_malformed_invitation_request_is_rejected(client):
    # a non-HTTPS origin is refused by the pure contract, surfaced as a bounded 422 (no echo)
    r = client.post(
        "/api/v1/enrollment/invitations", json=_create_body(controller_origin="http://x")
    )
    assert r.status_code == 422
