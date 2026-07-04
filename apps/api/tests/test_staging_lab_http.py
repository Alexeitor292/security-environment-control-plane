"""SECP-002B-1B-9 — HTTP-level regression: staging-lab validation errors never echo input.

FastAPI's default RequestValidationError body includes Pydantic's rejected ``input`` value. For
staging-lab routes that could reflect a token-shaped ``logical_name`` back to the caller. This
test drives the real ASGI app and proves the 422 body carries only a safe generic code — no
submitted value — and that nothing is persisted or audited. In-process only; no network.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

# Token-shaped, credential-like value with a distinctive marker to search for anywhere in output.
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


def test_staging_lab_validation_422_never_echoes_input(client, engine):
    resp = client.post(
        "/api/v1/staging-labs",
        json={
            "execution_target_id": "00000000-0000-0000-0000-000000000001",
            "logical_name": MALICIOUS_LOGICAL_NAME,
        },
    )
    assert resp.status_code == 422

    body = resp.text
    # The exact submitted value (and its distinctive marker) must not appear anywhere in the body.
    assert MALICIOUS_LOGICAL_NAME not in body
    assert MARKER not in body
    assert "@pam" not in body
    # The body is EXACTLY the safe generic code — no raw pydantic details/ctx/input keys, no
    # rejected value. (Exact equality fully pins the response shape.)
    assert resp.json() == {"error": {"code": "invalid_staging_lab_input"}}

    # The value was never persisted and never entered the audit trail.
    from secp_api.db import get_sessionmaker
    from secp_api.models import AuditEvent, StagingLab

    with get_sessionmaker()() as s:
        assert s.query(StagingLab).count() == 0
        blob = " ".join(str(e.data) for e in s.query(AuditEvent).all())
        assert MARKER not in blob and MALICIOUS_LOGICAL_NAME not in blob


def test_non_staging_routes_keep_default_validation_body(client):
    # Backward compatibility: unrelated routes still use FastAPI's default validation response
    # shape (a ``detail`` list), which the staging override must not affect.
    resp = client.post("/api/v1/targets", json={"display_name": 123})
    assert resp.status_code == 422
    assert "detail" in resp.json()
