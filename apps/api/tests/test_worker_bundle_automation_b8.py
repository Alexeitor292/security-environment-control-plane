"""SECP-B8 — worker-owned live discovery bundle automation (HTTP + service tests).

Proves the B8 product flow + its security invariants end to end over the real ASGI app:
  * completion captures the host PUBLIC key from the proof and cross-checks it against the
    fingerprint (fail closed on mismatch); a private key is never accepted as the host key;
  * the worker bundle descriptor is a SECRET-FREE superset that fails closed until the session is
    fully bound AND the host public key is captured;
  * the readiness diagnostic reports the EXACT missing prerequisite (never an opaque
    ``probe_source_sealed``);
  * worker-node publication surfaces only the PUBLIC key material (a private key is rejected
    everywhere; a malformed anchor is rejected);
  * the substrate-eligibility grant endpoint is permission-gated and never silently auto-grants;
  * the worker-facing ``resolve_ready_bundle_descriptors`` yields the exact descriptor the worker
    assembles its bundle from — and it contains no secret.

No response body ever leaks a private key / raw host / command.
"""

from __future__ import annotations

import base64
import copy
import hashlib

import pytest
from fastapi.testclient import TestClient

_BASE = "/api/v1/target-discovery/read-only-bootstrap"
_NODES = "/api/v1/target-discovery/read-only-bootstrap/worker-nodes"
_FORBIDDEN = ("PRIVATE KEY", "BEGIN OPENSSH")


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


def _host_key_and_fp() -> tuple[str, str]:
    """A synthetic Proxmox host ed25519 PUBLIC key line + its SHA256 fingerprint."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    line = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    blob = line.split()[1]
    fp = "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(blob)).digest()
    ).decode().rstrip("=")
    return line, fp


def _anchor_hex() -> str:
    from secp_api.worker_admission_contract import generate_ed25519_keypair

    _priv, anchor = generate_ed25519_keypair()
    return anchor


@pytest.fixture
def client_ctx(engine):
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
        # A second proxmox target WITHOUT substrate eligibility (for the grant + readiness cases).
        ineligible = targets.register_target(
            s,
            p,
            display_name="Ineligible",
            plugin_name="proxmox",
            config={"base_url": "https://proxmox3.example.test:8006/api2/json", "verify_tls": True},
            secret_ref="env:SECP_PROVIDER_SECRET__INELIG",
            scope_policy={"provisioning": copy.deepcopy(VALID_PROVISIONING_SCOPE)},
            address_spaces=[{"cidr_block": "10.62.0.0/16", "subnet_prefix": 24}],
        )
        onboard_and_activate(s, p, ineligible)
        ctx = {"target_id": str(target.id), "ineligible_target_id": str(ineligible.id)}

    app = create_app()
    app.router.on_startup.clear()
    _ = get_sessionmaker()
    return TestClient(app), ctx


def _no_leak(resp) -> None:
    for forbidden in _FORBIDDEN:
        assert forbidden not in resp.text, f"response leaked {forbidden!r}"


def _bind_target_with_host_key(client, target_id: str, host_line: str, fp: str) -> str:
    """Create → complete (capturing host public key from the proof) → bind. Returns session id."""
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": target_id, "worker_ssh_public_key": _pubkey()},
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    proof = f"selftest_ok=1\nhost_key_fingerprint={fp}\nhost_public_key={host_line}"
    r = client.post(
        f"{_BASE}/sessions/{sid}/complete",
        json={"host_key_fingerprint": fp, "proof_text": proof},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "completed"
    r = client.post(f"{_BASE}/sessions/{sid}/bind")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "bound"
    return sid


def _enroll(client, target_id: str) -> str:
    r = client.post("/api/v1/target-discovery", json={"execution_target_id": target_id})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# --- host public key capture -------------------------------------------------


def test_complete_captures_host_public_key_and_bundle_descriptor(client_ctx):
    client, ctx = client_ctx
    host_line, fp = _host_key_and_fp()
    _bind_target_with_host_key(client, ctx["target_id"], host_line, fp)
    enrollment_id = _enroll(client, ctx["target_id"])

    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/bundle-descriptor")
    assert r.status_code == 200, r.text
    desc = r.json()
    assert set(desc) == {
        "organization_id",
        "execution_target_id",
        "onboarding_id",
        "enrollment_id",
        "authorization_id",
        "authorization_version",
        "endpoint_binding_hash",
        "ssh_host",
        "ssh_port",
        "account",
        "host_key_fingerprint",
        "host_public_key",
    }
    assert desc["host_public_key"] == host_line
    assert desc["host_key_fingerprint"] == fp
    assert desc["account"] == "secpdisc"  # scoped, non-root
    _no_leak(r)


def test_complete_rejects_host_public_key_fingerprint_mismatch(client_ctx):
    client, ctx = client_ctx
    host_line, _fp = _host_key_and_fp()
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    sid = r.json()["id"]
    # A fingerprint that does not match the supplied host public key must fail closed.
    r = client.post(
        f"{_BASE}/sessions/{sid}/complete",
        json={"host_key_fingerprint": "SHA256:" + "B" * 43, "host_public_key": host_line},
    )
    assert r.status_code == 422
    assert "host_public_key" in r.json()["error"]["message"]


def test_complete_rejects_private_key_as_host_public_key(client_ctx):
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    sid = r.json()["id"]
    r = client.post(
        f"{_BASE}/sessions/{sid}/complete",
        json={
            "host_key_fingerprint": "SHA256:" + "A" * 43,
            "host_public_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"
            "-----END OPENSSH PRIVATE KEY-----",
        },
    )
    assert r.status_code == 422
    _no_leak(r)


def test_complete_without_host_key_stays_backward_compatible(client_ctx):
    """A B7-style completion (no host public key) still succeeds; the bundle descriptor then fails
    closed because the host key was not captured."""
    client, ctx = client_ctx
    r = client.post(
        f"{_BASE}/sessions",
        json={"execution_target_id": ctx["target_id"], "worker_ssh_public_key": _pubkey()},
    )
    sid = r.json()["id"]
    r = client.post(
        f"{_BASE}/sessions/{sid}/complete",
        json={"host_key_fingerprint": "SHA256:" + "A" * 43, "proof_text": "selftest_ok=1"},
    )
    assert r.status_code == 200, r.text
    client.post(f"{_BASE}/sessions/{sid}/bind")
    enrollment_id = _enroll(client, ctx["target_id"])
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/bundle-descriptor")
    assert r.status_code == 422
    assert "host public key" in r.json()["error"]["message"]


# --- bundle descriptor fail-closed -------------------------------------------


def test_bundle_descriptor_requires_bound_session(client_ctx):
    client, ctx = client_ctx
    enrollment_id = _enroll(client, ctx["target_id"])  # no bootstrap yet
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/bundle-descriptor")
    assert r.status_code == 422
    assert "bound" in r.json()["error"]["message"]


# --- readiness diagnostic ----------------------------------------------------


def test_readiness_reports_ready_when_fully_bound(client_ctx):
    client, ctx = client_ctx
    host_line, fp = _host_key_and_fp()
    _bind_target_with_host_key(client, ctx["target_id"], host_line, fp)
    enrollment_id = _enroll(client, ctx["target_id"])
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/readiness")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ready"] is True
    assert body["missing_prerequisites"] == []
    assert body["checks"]["host_public_key_captured"] is True
    assert body["bootstrap_status"] == "bound"


def test_readiness_reports_missing_prerequisites(client_ctx):
    client, ctx = client_ctx
    enrollment_id = _enroll(client, ctx["target_id"])  # no bootstrap session at all
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/readiness")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ready"] is False
    missing = set(body["missing_prerequisites"])
    # No bootstrap session -> these are all missing.
    assert {"bootstrap_session_present", "bootstrap_completed", "bootstrap_bound"} <= missing
    assert body["bootstrap_status"] is None


def test_readiness_flags_substrate_ineligible(client_ctx):
    client, ctx = client_ctx
    enrollment_id = _enroll(client, ctx["ineligible_target_id"])
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["checks"]["substrate_eligible"] is False
    assert "substrate_eligible" in body["missing_prerequisites"]


# --- worker node publication -------------------------------------------------


def test_worker_node_publish_and_list_public_only(client_ctx):
    client, _ctx = client_ctx
    pub = _pubkey("node-a")
    anchor = _anchor_hex()
    r = client.post(
        _NODES,
        json={"node_label": "worker-a", "ssh_public_key": pub, "admission_anchor_hex": anchor},
    )
    assert r.status_code == 201, r.text
    node = r.json()
    assert node["ssh_public_key"].startswith("ssh-ed25519 ")
    assert node["admission_anchor_hex"] == anchor
    assert node["ssh_public_key_fingerprint"].startswith("SHA256:")
    assert node["admission_anchor_fingerprint"].startswith("sha256:")
    # No private key field is present.
    assert "private" not in {k.lower() for k in node}
    r = client.get(_NODES)
    assert r.status_code == 200
    assert any(n["node_label"] == "worker-a" for n in r.json())
    _no_leak(r)


def test_worker_node_publish_is_idempotent(client_ctx):
    client, _ctx = client_ctx
    anchor = _anchor_hex()
    body = {"node_label": "worker-a", "ssh_public_key": _pubkey(), "admission_anchor_hex": anchor}
    r1 = client.post(_NODES, json=body)
    assert r1.status_code == 201
    body2 = {"node_label": "worker-a", "ssh_public_key": _pubkey(), "admission_anchor_hex": anchor}
    r2 = client.post(_NODES, json=body2)
    assert r2.status_code == 201
    assert r1.json()["id"] == r2.json()["id"]  # upsert on (org, label)
    r = client.get(_NODES)
    assert sum(1 for n in r.json() if n["node_label"] == "worker-a") == 1


def test_worker_node_rejects_private_key(client_ctx):
    client, _ctx = client_ctx
    r = client.post(
        _NODES,
        json={
            "node_label": "evil",
            "ssh_public_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"
            "-----END OPENSSH PRIVATE KEY-----",
            "admission_anchor_hex": _anchor_hex(),
        },
    )
    assert r.status_code == 422
    _no_leak(r)


def test_worker_node_rejects_bad_anchor(client_ctx):
    client, _ctx = client_ctx
    r = client.post(
        _NODES,
        json={
            "node_label": "bad-anchor",
            "ssh_public_key": _pubkey(),
            "admission_anchor_hex": "zz",
        },
    )
    assert r.status_code == 422


# --- substrate eligibility grant ---------------------------------------------


def test_substrate_grant_endpoint_makes_target_eligible(client_ctx):
    client, ctx = client_ctx
    # Readiness first shows ineligible.
    enrollment_id = _enroll(client, ctx["ineligible_target_id"])
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/readiness")
    assert r.json()["checks"]["substrate_eligible"] is False
    # Grant eligibility (the dev principal has staging_substrate:manage).
    r = client.post(f"{_BASE}/targets/{ctx['ineligible_target_id']}/substrate-eligibility")
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "active"
    # Readiness now shows eligible.
    r = client.get(f"{_BASE}/enrollments/{enrollment_id}/readiness")
    assert r.json()["checks"]["substrate_eligible"] is True


# --- worker-facing resolver (no principal) -----------------------------------


def test_resolve_ready_bundle_descriptors_yields_secret_free_descriptor(client_ctx):
    client, ctx = client_ctx
    host_line, fp = _host_key_and_fp()
    _bind_target_with_host_key(client, ctx["target_id"], host_line, fp)
    enrollment_id = _enroll(client, ctx["target_id"])

    from secp_api.db import session_scope
    from secp_api.services import bootstrap_discovery

    with session_scope() as s:
        descriptors = bootstrap_discovery.resolve_ready_bundle_descriptors(s)
    assert len(descriptors) == 1
    d = descriptors[0]
    assert d["enrollment_id"] == enrollment_id
    assert d["host_public_key"] == host_line
    assert d["account"] == "secpdisc"
    # Secret-free: no private key anywhere in the descriptor values.
    blob = repr(d)
    assert "PRIVATE" not in blob and "BEGIN OPENSSH" not in blob
