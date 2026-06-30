"""AC7 — the full controlled flow over HTTP via the FastAPI TestClient.

Create Template -> Create Immutable Version -> Validate -> Generate Plan ->
Approve Plan -> Start Simulated Exercise -> Per-Team Topologies ->
Reset One Team -> Destroy Exercise -> View Audit Log.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(engine):
    # engine fixture rebinds the DB to a fresh temp SQLite and creates tables.
    from secp_api.db import session_scope
    from secp_api.main import create_app
    from secp_api.seed import bootstrap_dev

    with session_scope() as s:
        bootstrap_dev(s)

    app = create_app()
    # Avoid re-running startup bootstrap against a different engine.
    app.router.on_startup.clear()
    return TestClient(app)


def test_full_controlled_flow(client, valid_definition):
    # 1. Create template
    r = client.post(
        "/api/v1/templates",
        json={"name": "Web Breach", "slug": "web-breach-e2e"},
    )
    assert r.status_code == 201, r.text
    template_id = r.json()["id"]

    # 2. Create immutable version
    r = client.post(
        f"/api/v1/templates/{template_id}/versions",
        json={"definition": valid_definition},
    )
    assert r.status_code == 201, r.text
    version = r.json()
    version_id = version["id"]
    assert version["content_hash"].startswith("sha256:")

    # 3. Create + validate exercise
    r = client.post(
        "/api/v1/exercises",
        json={"template_id": template_id, "version_id": version_id, "name": "e2e"},
    )
    assert r.status_code == 201, r.text
    exercise_id = r.json()["id"]
    r = client.post(f"/api/v1/exercises/{exercise_id}/validate")
    assert r.json()["lifecycle_state"] == "validated"

    # 4. Generate plan
    r = client.post(f"/api/v1/exercises/{exercise_id}/plan")
    assert r.status_code == 201, r.text
    plan = r.json()
    plan_id = plan["id"]
    assert plan["summary"]["teams"] == 2

    # Deploy must be refused before approval.
    refused = client.post(f"/api/v1/exercises/{exercise_id}/deploy")
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "approval_required"

    # 5. Submit + approve plan
    client.post(f"/api/v1/plans/{plan_id}/submit")
    r = client.post(f"/api/v1/plans/{plan_id}/approve", json={"reason": "looks good"})
    assert r.json()["status"] == "approved"

    # 6. Start simulated exercise
    r = client.post(f"/api/v1/exercises/{exercise_id}/deploy")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "completed"
    r = client.get(f"/api/v1/exercises/{exercise_id}")
    assert r.json()["lifecycle_state"] == "running"

    # 7. Per-team topologies
    r = client.get(f"/api/v1/exercises/{exercise_id}/topology")
    topos = r.json()
    assert len(topos) == 2
    team_cidrs = []
    for t in topos:
        cidrs = sorted(n["data"]["cidr"] for n in t["nodes"] if n["type"] == "network")
        team_cidrs.append(cidrs)
        assert t["nodes"] and t["edges"]
    assert team_cidrs[0] != team_cidrs[1]  # isolation

    # 8. Reset one team
    instances = client.get(f"/api/v1/exercises/{exercise_id}/instances").json()
    first_instance = instances[0]["id"]
    r = client.post(f"/api/v1/exercises/{exercise_id}/instances/{first_instance}/reset")
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "reset"

    # 9. Destroy exercise (and idempotent retry)
    r = client.post(f"/api/v1/exercises/{exercise_id}/destroy")
    assert r.status_code == 200, r.text
    r2 = client.post(f"/api/v1/exercises/{exercise_id}/destroy")
    assert r2.status_code == 200
    r = client.get(f"/api/v1/exercises/{exercise_id}")
    assert r.json()["lifecycle_state"] == "destroyed"

    # 10. Audit log
    r = client.get(f"/api/v1/audit?exercise_id={exercise_id}")
    actions = {e["action"] for e in r.json()}
    for expected in (
        "exercise.created",
        "plan.approved",
        "deploy.completed",
        "reset.completed",
        "destroy.completed",
        "apply.refused",
    ):
        assert expected in actions, f"missing audit action {expected}"


def test_health_and_plugins(client):
    assert client.get("/health").json() == {"status": "ok"}
    plugins = client.get("/api/v1/plugins").json()
    assert any(p["name"] == "simulator" and p["simulated"] for p in plugins)
