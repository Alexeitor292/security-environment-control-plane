"""Slice 9 — Provider Targets API over HTTP (register, list, discover-refused)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


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


GOOD = {
    "display_name": "Lab Proxmox (placeholder)",
    "plugin_name": "proxmox",
    "config": {"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
    "secret_ref": "env:SECP_PROVIDER_SECRET__LAB",
    "scope_policy": {"resource_types": ["node", "vm"]},
    "address_spaces": [{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
}


def test_register_list_get_target(client):
    r = client.post("/api/v1/targets", json=GOOD)
    assert r.status_code == 201, r.text
    target = r.json()
    assert target["config_hash"].startswith("sha256:")
    assert target["secret_ref"] == GOOD["secret_ref"]  # a reference, not a secret

    assert any(t["id"] == target["id"] for t in client.get("/api/v1/targets").json())
    detail = client.get(f"/api/v1/targets/{target['id']}").json()
    assert detail["plugin_name"] == "proxmox"
    spaces = client.get(f"/api/v1/targets/{target['id']}/address-spaces").json()
    assert spaces[0]["cidr_block"] == "10.60.0.0/16"


def test_register_rejects_plaintext_secret(client):
    bad = {**GOOD, "config": {**GOOD["config"], "password": "hunter2"}}
    r = client.post("/api/v1/targets", json=bad)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_failed"


def test_discovery_refused_in_inline_mode(client):
    target_id = client.post("/api/v1/targets", json=GOOD).json()["id"]
    # Default dev dispatch mode is inline -> discovery refused (requires Temporal).
    r = client.post(f"/api/v1/targets/{target_id}/discover")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "inline_execution_forbidden"

    # The refusal is audited.
    audit = client.get("/api/v1/audit").json()
    assert any(e["action"] == "provider.operation_refused" for e in audit)


def test_capabilities_shows_provisioning_disabled(client):
    caps = client.get("/api/v1/providers/capabilities").json()
    assert caps["provisioning_enabled"] is False
    assert caps["discovery"] == "read-only"
