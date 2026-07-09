"""SECP-B7 — Proxmox read-only discovery bootstrap HTTP-surface + flow tests.

Drives the real ASGI app end to end: create session (public key only) → script → complete (computes
the endpoint digest) → bind (creates + approves a live-read authorization) → binding descriptor. It
proves the security invariants: a private key is rejected at the API; responses never leak a private
key / raw host / command; the request body accepts no host/port/account/known_hosts/key/command; and
binding fails closed on a target/onboarding/enrollment mismatch.
"""

from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient

# Values that must NEVER appear in any bootstrap API response body.
_FORBIDDEN = ("PRIVATE KEY", "BEGIN OPENSSH", "proxmox.example.test", "secret", "credential")


def _pubkey(comment: str = "worker@secp") -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    line = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return f"{line} {comment}"


@pytest.fixture
def client_ctx(engine):
    """Commit a proxmox target + active onboarding + substrate eligibility, return (client, ctx)."""
    from conftest import VALID_PROVISIONING_SCOPE, onboard_and_activate
    from secp_api.db import get_sessionmaker, session_scope
    from secp_api.main import create_app
    from secp_api.seed import bootstrap_dev
    from secp_api.services import staging_labs, targets

    with session_scope() as s:
        p = bootstrap_dev(s)
        target = targets.register_target(
            s,
            p,
            display_name="Lab",
            plugin_name="proxmox",
            config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
            secret_ref="env:SECP_PROVIDER_SECRET__LAB",
            scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
            address_spaces=[{"cidr_block": "10.60.0.0/16", "subnet_prefix": 24}],
        )
        onboard_and_activate(s, p, target)
        staging_labs.grant_substrate_eligibility(s, p, execution_target_id=target.id)
        # A second proxmox target WITHOUT onboarding (for the fail-closed cases).
        bare = targets.register_target(
            s,
            p,
            display_name="Bare",
            plugin_name="proxmox",
            config={"base_url": "https://proxmox2.example.test:8006/api2/json", "verify_tls": True},
            secret_ref="env:SECP_PROVIDER_SECRET__BARE",
            scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
            address_spaces=[{"cidr_block": "10.61.0.0/16", "subnet_prefix": 24}],
        )
        ctx = {"target_id": str(target.id), "bare_target_id": str(bare.id)}

    app = create_app()
    app.router.on_startup.clear()
    _ = get_sessionmaker()
    return TestClient(app), ctx


_BASE = "/api/v1/target-discovery/read-only-bootstrap"


def _no_leak(resp) -> None:
    blob = resp.text
    for forbidden in _FORBIDDEN:
        assert forbidden not in blob, f"response leaked {forbidden!r}"


def test_full_bootstrap_flow(client_ctx):
    client, ctx = client_ctx
    # 1. create
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    assert r.status_code == 201, r.text
    sess = r.json()
    assert sess["status"] == "pending" and sess["worker_ssh_public_key_fingerprint"].startswith(
        "SHA256:"
    )
    _no_leak(r)
    sid = sess["id"]

    # 2. script — contains the forced command + carries no private key
    r = client.get(f"{_BASE}/sessions/{sid}/script")
    assert r.status_code == 200
    body = r.json()
    assert 'command="/usr/local/sbin/secpdisc-force-command"' in body["script"]
    assert "PRIVATE KEY" not in body["script"]
    assert "no-pty" in body["script"]

    # 3. complete — computes the endpoint binding digest
    r = client.post(
        f"{_BASE}/sessions/{sid}/complete",
        json={"host_key_fingerprint": "SHA256:" + "A" * 43, "proof_text": "selftest_ok=1"},
    )
    assert r.status_code == 200, r.text
    sess = r.json()
    assert sess["status"] == "completed"
    assert sess["endpoint_binding_hash"].startswith("sha256:")
    _no_leak(r)

    # 4. bind — creates + approves a live-read authorization
    r = client.post(f"{_BASE}/sessions/{sid}/bind")
    assert r.status_code == 200, r.text
    sess = r.json()
    assert sess["status"] == "bound"
    assert sess["live_read_authorization_id"] and sess["authorization_version"] >= 1

    # 5. enrollment + binding descriptor (secret-free binding.json)
    r = client.post("/api/v1/target-discovery", json={"execution_target_id": ctx["target_id"]})
    assert r.status_code == 201, r.text
    enrollment_id = r.json()["id"]
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/binding-descriptor")
    assert r.status_code == 200, r.text
    desc = r.json()
    assert set(desc.keys()) == {
        "organization_id",
        "execution_target_id",
        "onboarding_id",
        "enrollment_id",
        "authorization_id",
        "authorization_version",
        "endpoint_binding_hash",
    }
    assert desc["endpoint_binding_hash"] == sess["endpoint_binding_hash"]
    _no_leak(r)


def test_create_rejects_private_key(client_ctx):
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={
            "execution_target_id": ctx["target_id"],
            "worker_ssh_public_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"
            "-----END OPENSSH PRIVATE KEY-----",
        },
    )
    assert r.status_code == 422
    # The rejection must not echo the submitted key material.
    assert "PRIVATE KEY" not in r.text


def test_create_rejects_malformed_key(client_ctx):
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={
            "execution_target_id": ctx["target_id"],
            "worker_ssh_public_key": "not a key at all!!",
        },
    )
    assert r.status_code == 422


def test_create_requires_active_onboarding(client_ctx):
    client, ctx = client_ctx
    # The bare target has no active onboarding → fail closed.
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["bare_target_id"], "worker_ssh_public_key": _pubkey()},
    )
    assert r.status_code == 422
    assert "onboarding" in r.json()["error"]["message"]


def test_request_body_accepts_no_host_port_or_command(client_ctx):
    # The bootstrap create body ignores any injected host/port/account/known_hosts/command fields —
    # pydantic drops unknown fields; only the public key + port are accepted.
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={
            "execution_target_id": ctx["target_id"],
            "worker_ssh_public_key": _pubkey(),
            "ssh_host": "10.0.0.9",
            "known_hosts": "evil",
            "private_key_path": "/etc/x",
            "command": "rm -rf /",
        },
    )
    assert r.status_code == 201  # extra fields ignored
    sess = r.json()
    # None of the injected fields are reflected/stored.
    for forbidden in ("10.0.0.9", "evil", "/etc/x", "rm -rf"):
        assert forbidden not in r.text
    assert "ssh_host" not in sess and "command" not in sess


def test_bind_before_complete_fails_closed(client_ctx):
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    sid = r.json()["id"]
    r = client.post(f"{_BASE}/sessions/{sid}/bind")  # still pending
    assert r.status_code == 422
    assert "completed" in r.json()["error"]["message"]


def test_binding_descriptor_requires_bound_session(client_ctx):
    client, ctx = client_ctx
    # Create + complete but do NOT bind; the binding descriptor must fail closed.
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    sid = r.json()["id"]
    client.post(
        f"{_BASE}/sessions/{sid}/complete", json={"host_key_fingerprint": "SHA256:" + "A" * 43}
    )
    r = client.post("/api/v1/target-discovery", json={"execution_target_id": ctx["target_id"]})
    enrollment_id = r.json()["id"]
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/binding-descriptor")
    assert r.status_code == 422
    assert "no bound bootstrap session" in r.json()["error"]["message"]


def test_complete_rejects_bad_fingerprint(client_ctx):
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    sid = r.json()["id"]
    r = client.post(f"{_BASE}/sessions/{sid}/complete", json={"host_key_fingerprint": "MD5:zz"})
    assert r.status_code == 422


def test_complete_rejects_proof_with_private_key(client_ctx):
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    sid = r.json()["id"]
    priv = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----"
    r = client.post(
        f"{_BASE}/sessions/{sid}/complete",
        json={"host_key_fingerprint": "SHA256:" + "A" * 43, "proof_text": priv},
    )
    assert r.status_code == 422
    assert "PRIVATE KEY" not in r.text


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
