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
import uuid
from datetime import UTC, datetime, timedelta

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


def _identity_review(node: dict, **overrides) -> dict:
    body = {
        "expected_node_revision": node["revision"],
        "expected_ssh_public_key_fingerprint": node["ssh_public_key_fingerprint"],
        "expected_admission_anchor_fingerprint": node["admission_anchor_fingerprint"],
        "deployment_binding": "production-worker",
        "proof_id": "pr5f.operator-review",
        "issuer": "secp.operator",
        "deployment_binding_review_confirmed": True,
        "verification_anchor_review_confirmed": True,
        "rotation_revocation_review_confirmed": True,
    }
    body.update(overrides)
    return body


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
        ctx = {
            "organization_id": str(p.organization_id),
            "target_id": str(target.id),
            "ineligible_target_id": str(ineligible.id),
        }

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
    assert node["revision"] == 1
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
    r2 = client.post(_NODES, json=body)
    assert r2.status_code == 201
    assert r1.json()["id"] == r2.json()["id"]  # upsert on (org, label)
    assert r1.json()["revision"] == r2.json()["revision"] == 1
    r = client.get(_NODES)
    assert sum(1 for n in r.json() if n["node_label"] == "worker-a") == 1


def test_worker_node_key_rotation_advances_revision_and_clears_stale_link(client_ctx):
    client, _ctx = client_ctx
    first = {
        "node_label": "worker-rotate",
        "ssh_public_key": _pubkey("old"),
        "admission_anchor_hex": _anchor_hex(),
    }
    r1 = client.post(_NODES, json=first)
    assert r1.status_code == 201
    second = {
        "node_label": "worker-rotate",
        "ssh_public_key": _pubkey("new"),
        "admission_anchor_hex": _anchor_hex(),
    }
    r2 = client.post(_NODES, json=second)
    assert r2.status_code == 201
    assert r2.json()["id"] == r1.json()["id"]
    assert r2.json()["revision"] == 2
    assert r2.json()["worker_identity_registration_id"] is None


def test_stale_identity_link_cas_cannot_survive_intervening_key_rotation(engine):
    from secp_api.db import session_scope
    from secp_api.models import WorkerDiscoveryNode
    from secp_api.seed import bootstrap_dev
    from secp_api.services import worker_nodes
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint
    from sqlalchemy import update

    with session_scope() as session:
        principal = bootstrap_dev(session)
        node = worker_nodes.publish_worker_node(
            session,
            organization_id=principal.organization_id,
            node_label="worker-cas",
            ssh_public_key=_pubkey("cas-old"),
            admission_anchor_hex=_anchor_hex(),
        )
        stale_anchor = node.admission_anchor_fingerprint
        stale_revision = node.revision
        new_anchor = _anchor_hex()
        session.execute(
            update(WorkerDiscoveryNode)
            .where(WorkerDiscoveryNode.id == node.id)
            .values(
                admission_anchor_hex=new_anchor,
                admission_anchor_fingerprint=compute_verification_anchor_fingerprint(new_anchor),
                revision=stale_revision + 1,
                worker_identity_registration_id=None,
            )
            .execution_options(synchronize_session=False)
        )

        linked = worker_nodes._link_identity_if_current(
            session,
            node_id=node.id,
            organization_id=principal.organization_id,
            expected_anchor_fingerprint=stale_anchor,
            expected_revision=stale_revision,
            registration_id=uuid.uuid4(),
        )
        session.expire_all()
        current = session.get(WorkerDiscoveryNode, node.id)

        assert linked is False
        assert current is not None
        assert current.revision == stale_revision + 1
        assert current.worker_identity_registration_id is None


def test_legacy_direct_identity_link_route_is_not_exposed(client_ctx):
    client, _ctx = client_ctx
    anchor = _anchor_hex()
    node = client.post(
        _NODES,
        json={
            "node_label": "worker-linked",
            "ssh_public_key": _pubkey(),
            "admission_anchor_hex": anchor,
        },
    ).json()
    reg = client.post(
        "/api/v1/worker-identity/registrations",
        json={
            "mechanism": "ed25519_signed_nonce",
            "identity_label": "worker-linked",
            "deployment_binding": "pr5f-installation",
            "verification_anchor_fingerprint": node["admission_anchor_fingerprint"],
            "ttl_seconds": 3600,
        },
    )
    assert reg.status_code == 201, reg.text
    registration_id = reg.json()["id"]
    for kind in (
        "deployment_binding_review",
        "verification_anchor_review",
        "rotation_revocation_review",
    ):
        recorded = client.post(
            f"/api/v1/worker-identity/registrations/{registration_id}/evidence",
            json={
                "kind": kind,
                "status": "verified",
                "proof_id": f"pr5f.{kind}",
                "issuer": "operator.review",
            },
        )
        assert recorded.status_code == 200, recorded.text
    approved = client.post(f"/api/v1/worker-identity/registrations/{registration_id}/approve")
    assert approved.status_code == 200, approved.text
    linked = client.post(
        f"{_NODES}/{node['id']}/identity-link",
        json={"worker_identity_registration_id": registration_id},
    )
    assert linked.status_code == 404
    current = client.get(f"{_NODES}/{node['id']}")
    assert current.status_code == 200
    assert current.json()["worker_identity_registration_id"] is None


def test_identity_review_never_revokes_same_label_non_ed_identity(client_ctx):
    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": "worker-mechanism-collision",
            "ssh_public_key": _pubkey("mechanism-collision"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    registration = client.post(
        "/api/v1/worker-identity/registrations",
        json={
            "mechanism": "mtls_workload_identity",
            "identity_label": node["node_label"],
            "deployment_binding": "ordinary-worker-identity",
            "verification_anchor_fingerprint": "sha256:" + "9" * 64,
            "ttl_seconds": 3600,
        },
    )
    assert registration.status_code == 201, registration.text
    registration_id = registration.json()["id"]
    for kind in (
        "deployment_binding_review",
        "verification_anchor_review",
        "rotation_revocation_review",
    ):
        recorded = client.post(
            f"/api/v1/worker-identity/registrations/{registration_id}/evidence",
            json={
                "kind": kind,
                "status": "verified",
                "proof_id": "existing.mtls.review",
                "issuer": "operator.review",
            },
        )
        assert recorded.status_code == 200, recorded.text
    approved = client.post(f"/api/v1/worker-identity/registrations/{registration_id}/approve")
    assert approved.status_code == 200, approved.text

    refused = client.post(
        f"{_NODES}/{node['id']}/identity-approval-link",
        json=_identity_review(node),
    )
    assert refused.status_code == 422

    from secp_api.db import get_sessionmaker
    from secp_api.enums import WorkerIdentityMechanism, WorkerIdentityStatus
    from secp_api.models import WorkerDiscoveryNode, WorkerIdentityRegistration
    from sqlalchemy import select

    with get_sessionmaker()() as session:
        legacy = session.get(WorkerIdentityRegistration, uuid.UUID(registration_id))
        current_node = session.get(WorkerDiscoveryNode, uuid.UUID(node["id"]))
        ed_rows = list(
            session.execute(
                select(WorkerIdentityRegistration).where(
                    WorkerIdentityRegistration.identity_label == node["node_label"],
                    WorkerIdentityRegistration.mechanism
                    == WorkerIdentityMechanism.ed25519_signed_nonce,
                )
            ).scalars()
        )
        assert legacy is not None and legacy.status == WorkerIdentityStatus.approved
        assert current_node is not None and current_node.worker_identity_registration_id is None
        assert ed_rows == []


@pytest.mark.parametrize(
    "override",
    [
        {"deployment_binding_review_confirmed": 1},
        {"verification_anchor_review_confirmed": "true"},
        {"rotation_revocation_review_confirmed": 1},
        {"expected_node_revision": True},
        {"private_key": "must-never-be-accepted"},
    ],
)
def test_identity_review_schema_rejects_coercion_and_unknown_material(client_ctx, override):
    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": f"worker-strict-{uuid.uuid4().hex[:8]}",
            "ssh_public_key": _pubkey("strict-review"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    refused = client.post(
        f"{_NODES}/{node['id']}/identity-approval-link",
        json=_identity_review(node, **override),
    )
    assert refused.status_code == 422
    current = client.get(f"{_NODES}/{node['id']}")
    assert current.status_code == 200
    assert current.json()["worker_identity_registration_id"] is None


def test_worker_node_register_schema_rejects_unknown_private_material(client_ctx):
    client, _ctx = client_ctx
    refused = client.post(
        _NODES,
        json={
            "node_label": "worker-unknown-private-material",
            "ssh_public_key": _pubkey("unknown-field"),
            "admission_anchor_hex": _anchor_hex(),
            "private_key": "must-never-be-accepted",
        },
    )
    assert refused.status_code == 422
    _no_leak(refused)


def test_explicit_identity_review_atomically_approves_links_and_retries_exactly(client_ctx):
    from secp_api.db import get_sessionmaker
    from secp_api.enums import (
        WorkerIdentityEvidenceStatus,
        WorkerIdentityMechanism,
        WorkerIdentityStatus,
    )
    from secp_api.models import WorkerIdentityEvidence, WorkerIdentityRegistration
    from sqlalchemy import select

    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": "worker-reviewed",
            "ssh_public_key": _pubkey("reviewed"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    body = _identity_review(node)
    reviewed = client.post(f"{_NODES}/{node['id']}/identity-approval-link", json=body)
    assert reviewed.status_code == 200, reviewed.text
    registration_id = reviewed.json()["worker_identity_registration_id"]
    assert registration_id

    # The exact same reviewed request is an idempotent retry, not a second identity version.
    retried = client.post(f"{_NODES}/{node['id']}/identity-approval-link", json=body)
    assert retried.status_code == 200, retried.text
    assert retried.json()["worker_identity_registration_id"] == registration_id
    mismatched_retry = client.post(
        f"{_NODES}/{node['id']}/identity-approval-link",
        json=_identity_review(node, proof_id="different-review"),
    )
    assert mismatched_retry.status_code == 422

    with get_sessionmaker()() as session:
        registrations = list(
            session.execute(
                select(WorkerIdentityRegistration).where(
                    WorkerIdentityRegistration.identity_label == "worker-reviewed"
                )
            ).scalars()
        )
        assert len(registrations) == 1
        registration = registrations[0]
        assert str(registration.id) == registration_id
        assert registration.status == WorkerIdentityStatus.approved
        assert registration.mechanism == WorkerIdentityMechanism.ed25519_signed_nonce
        assert registration.deployment_binding == body["deployment_binding"]
        evidence = list(
            session.execute(
                select(WorkerIdentityEvidence).where(
                    WorkerIdentityEvidence.registration_id == registration.id
                )
            ).scalars()
        )
        assert len(evidence) == 3
        assert all(row.status == WorkerIdentityEvidenceStatus.verified for row in evidence)
        assert {row.proof_id for row in evidence} == {body["proof_id"]}
        assert {row.issuer for row in evidence} == {body["issuer"]}


@pytest.mark.parametrize("terminal_state", ["expired", "revoked"])
def test_identity_review_renews_same_key_after_terminal_registration(
    client_ctx, terminal_state: str
) -> None:
    from secp_api.db import get_sessionmaker
    from secp_api.enums import WorkerIdentityStatus
    from secp_api.models import (
        WorkerDiscoveryNode,
        WorkerIdentityEvidence,
        WorkerIdentityRegistration,
    )
    from sqlalchemy import select, update

    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": f"worker-renew-{terminal_state}",
            "ssh_public_key": _pubkey(f"renew-{terminal_state}"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    body = _identity_review(node)
    first = client.post(f"{_NODES}/{node['id']}/identity-approval-link", json=body)
    assert first.status_code == 200, first.text
    old_id = first.json()["worker_identity_registration_id"]

    if terminal_state == "revoked":
        revoked = client.post(f"/api/v1/worker-identity/registrations/{old_id}/revoke")
        assert revoked.status_code == 200, revoked.text
    else:
        with get_sessionmaker()() as session:
            session.execute(
                update(WorkerIdentityRegistration)
                .where(WorkerIdentityRegistration.id == uuid.UUID(old_id))
                .values(expiry=datetime.now(UTC) - timedelta(seconds=1))
            )
            session.commit()

    old_link = client.get(f"{_NODES}/{node['id']}")
    assert old_link.status_code == 200
    assert old_link.json()["worker_identity_registration_id"] == old_id

    renewed = client.post(f"{_NODES}/{node['id']}/identity-approval-link", json=body)
    assert renewed.status_code == 200, renewed.text
    new_id = renewed.json()["worker_identity_registration_id"]
    assert new_id != old_id
    assert renewed.json()["revision"] == node["revision"]

    historical = client.get(f"/api/v1/worker-identity/registrations/{old_id}")
    replacement = client.get(f"/api/v1/worker-identity/registrations/{new_id}")
    current_node = client.get(f"{_NODES}/{node['id']}")
    assert historical.status_code == replacement.status_code == current_node.status_code == 200
    assert historical.json()["status"] == terminal_state
    assert replacement.json()["status"] == "approved"
    assert replacement.json()["identity_version"] == historical.json()["identity_version"] + 1
    assert current_node.json()["worker_identity_registration_id"] == new_id

    with get_sessionmaker()() as session:
        old = session.get(WorkerIdentityRegistration, uuid.UUID(old_id))
        new = session.get(WorkerIdentityRegistration, uuid.UUID(new_id))
        current_node = session.get(WorkerDiscoveryNode, uuid.UUID(node["id"]))
        assert old is not None and old.status == WorkerIdentityStatus(terminal_state)
        assert new is not None and new.status == WorkerIdentityStatus.approved
        assert new.identity_version == old.identity_version + 1
        assert new.verification_anchor_fingerprint == old.verification_anchor_fingerprint
        assert current_node is not None and current_node.worker_identity_registration_id == new.id
        evidence_counts = {
            registration_id: len(
                list(
                    session.execute(
                        select(WorkerIdentityEvidence).where(
                            WorkerIdentityEvidence.registration_id == registration_id
                        )
                    ).scalars()
                )
            )
            for registration_id in (old.id, new.id)
        }
        assert evidence_counts == {old.id: 3, new.id: 3}


def test_identity_renewal_cas_refusal_keeps_old_link_and_creates_nothing(
    client_ctx, monkeypatch
) -> None:
    from secp_api.db import get_sessionmaker
    from secp_api.models import WorkerDiscoveryNode, WorkerIdentityRegistration
    from secp_api.services import worker_nodes
    from sqlalchemy import select, update

    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": "worker-renew-cas",
            "ssh_public_key": _pubkey("renew-cas"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    body = _identity_review(node)
    first = client.post(f"{_NODES}/{node['id']}/identity-approval-link", json=body)
    assert first.status_code == 200, first.text
    old_id = first.json()["worker_identity_registration_id"]
    with get_sessionmaker()() as session:
        session.execute(
            update(WorkerIdentityRegistration)
            .where(WorkerIdentityRegistration.id == uuid.UUID(old_id))
            .values(expiry=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()

    monkeypatch.setattr(
        worker_nodes,
        "_unlink_terminal_identity_if_current",
        lambda *_a, **_k: False,
    )
    refused = client.post(f"{_NODES}/{node['id']}/identity-approval-link", json=body)
    assert refused.status_code == 422

    with get_sessionmaker()() as session:
        current_node = session.get(WorkerDiscoveryNode, uuid.UUID(node["id"]))
        rows = list(
            session.execute(
                select(WorkerIdentityRegistration).where(
                    WorkerIdentityRegistration.identity_label == node["node_label"]
                )
            ).scalars()
        )
        assert current_node is not None
        assert str(current_node.worker_identity_registration_id) == old_id
        assert len(rows) == 1 and str(rows[0].id) == old_id


@pytest.mark.parametrize(
    "confirmation",
    (
        "deployment_binding_review_confirmed",
        "verification_anchor_review_confirmed",
        "rotation_revocation_review_confirmed",
    ),
)
def test_identity_review_requires_every_explicit_confirmation(client_ctx, confirmation):
    from secp_api.db import get_sessionmaker
    from secp_api.models import WorkerIdentityRegistration

    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": f"worker-confirm-{confirmation[:8]}",
            "ssh_public_key": _pubkey(confirmation),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    refused = client.post(
        f"{_NODES}/{node['id']}/identity-approval-link",
        json=_identity_review(node, **{confirmation: False}),
    )
    assert refused.status_code == 422
    with get_sessionmaker()() as session:
        assert (
            session.query(WorkerIdentityRegistration)
            .filter_by(identity_label=node["node_label"])
            .count()
            == 0
        )


def test_identity_review_refuses_stale_node_and_existing_draft(client_ctx):
    from secp_api.db import get_sessionmaker
    from secp_api.models import WorkerDiscoveryNode, WorkerIdentityRegistration

    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": "worker-stale-review",
            "ssh_public_key": _pubkey("stale-old"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    stale_body = _identity_review(node)
    rotated = client.post(
        _NODES,
        json={
            "node_label": node["node_label"],
            "ssh_public_key": _pubkey("stale-new"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    refused = client.post(f"{_NODES}/{node['id']}/identity-approval-link", json=stale_body)
    assert refused.status_code == 422

    draft = client.post(
        "/api/v1/worker-identity/registrations",
        json={
            "mechanism": "ed25519_signed_nonce",
            "identity_label": rotated["node_label"],
            "deployment_binding": "production-worker",
            "verification_anchor_fingerprint": rotated["admission_anchor_fingerprint"],
            "ttl_seconds": 3600,
        },
    )
    assert draft.status_code == 201, draft.text
    refused = client.post(
        f"{_NODES}/{node['id']}/identity-approval-link",
        json=_identity_review(rotated),
    )
    assert refused.status_code == 422

    with get_sessionmaker()() as session:
        current_node = session.get(WorkerDiscoveryNode, uuid.UUID(node["id"]))
        current_draft = session.get(WorkerIdentityRegistration, uuid.UUID(draft.json()["id"]))
        assert current_node is not None and current_node.worker_identity_registration_id is None
        assert current_draft is not None and current_draft.status.value == "draft"


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("deployment_binding", "env:DO_NOT_ACCEPT"),
        ("proof_id", "https://review.invalid/ticket"),
        ("issuer", "operator@example.invalid"),
    ),
)
def test_identity_review_rejects_unsafe_metadata_without_echo(client_ctx, field, unsafe_value):
    from secp_api.db import get_sessionmaker
    from secp_api.models import WorkerIdentityRegistration

    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": f"worker-unsafe-{field.replace('_', '-')}",
            "ssh_public_key": _pubkey(field),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    refused = client.post(
        f"{_NODES}/{node['id']}/identity-approval-link",
        json=_identity_review(node, **{field: unsafe_value}),
    )
    assert refused.status_code == 422
    assert unsafe_value not in refused.text
    with get_sessionmaker()() as session:
        assert session.query(WorkerIdentityRegistration).count() == 0


def test_identity_rotation_requires_review_then_revokes_old_anchor_and_links_new(
    client_ctx, monkeypatch
):
    from secp_api.db import get_sessionmaker
    from secp_api.enums import WorkerIdentityStatus
    from secp_api.models import WorkerIdentityRegistration

    client, _ctx = client_ctx
    first = client.post(
        _NODES,
        json={
            "node_label": "worker-reviewed-rotation",
            "ssh_public_key": _pubkey("rotation-old"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    first_link = client.post(
        f"{_NODES}/{first['id']}/identity-approval-link", json=_identity_review(first)
    )
    assert first_link.status_code == 200, first_link.text
    old_registration_id = first_link.json()["worker_identity_registration_id"]

    second = client.post(
        _NODES,
        json={
            "node_label": first["node_label"],
            "ssh_public_key": _pubkey("rotation-new"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()
    assert second["worker_identity_registration_id"] is None
    refused = client.post(
        f"{_NODES}/{second['id']}/identity-approval-link",
        json=_identity_review(second, rotation_revocation_review_confirmed=False),
    )
    assert refused.status_code == 422
    with get_sessionmaker()() as session:
        old = session.get(WorkerIdentityRegistration, uuid.UUID(old_registration_id))
        assert old is not None and old.status == WorkerIdentityStatus.approved

    # The old identity revocation and every new lifecycle row are in the same request transaction:
    # a final-link refusal restores the old approval rather than leaving a half-rotated identity.
    from secp_api.services import worker_nodes

    original_link = worker_nodes._link_worker_node_identity

    def refuse_link(*_args, **_kwargs):
        raise worker_nodes._fail("synthetic rotation link refusal")

    monkeypatch.setattr(worker_nodes, "_link_worker_node_identity", refuse_link)
    failed_rotation = client.post(
        f"{_NODES}/{second['id']}/identity-approval-link", json=_identity_review(second)
    )
    assert failed_rotation.status_code == 422
    with get_sessionmaker()() as session:
        old = session.get(WorkerIdentityRegistration, uuid.UUID(old_registration_id))
        assert old is not None and old.status == WorkerIdentityStatus.approved
        assert session.query(WorkerIdentityRegistration).count() == 1
    monkeypatch.setattr(worker_nodes, "_link_worker_node_identity", original_link)

    second_link = client.post(
        f"{_NODES}/{second['id']}/identity-approval-link", json=_identity_review(second)
    )
    assert second_link.status_code == 200, second_link.text
    new_registration_id = second_link.json()["worker_identity_registration_id"]
    assert new_registration_id != old_registration_id
    with get_sessionmaker()() as session:
        old = session.get(WorkerIdentityRegistration, uuid.UUID(old_registration_id))
        new = session.get(WorkerIdentityRegistration, uuid.UUID(new_registration_id))
        assert old is not None and old.status == WorkerIdentityStatus.revoked
        assert old.revocation_reason_code == "worker_anchor_rotated"
        assert new is not None and new.status == WorkerIdentityStatus.approved


def test_identity_review_transaction_rolls_back_if_final_link_refuses(client_ctx, monkeypatch):
    from secp_api.db import get_sessionmaker
    from secp_api.models import (
        WorkerDiscoveryNode,
        WorkerIdentityEvidence,
        WorkerIdentityRegistration,
    )
    from secp_api.services import worker_nodes

    client, _ctx = client_ctx
    node = client.post(
        _NODES,
        json={
            "node_label": "worker-link-rollback",
            "ssh_public_key": _pubkey("rollback"),
            "admission_anchor_hex": _anchor_hex(),
        },
    ).json()

    def refuse_link(*_args, **_kwargs):
        raise worker_nodes._fail("synthetic final link refusal")

    monkeypatch.setattr(worker_nodes, "_link_worker_node_identity", refuse_link)
    refused = client.post(
        f"{_NODES}/{node['id']}/identity-approval-link", json=_identity_review(node)
    )
    assert refused.status_code == 422
    with get_sessionmaker()() as session:
        current_node = session.get(WorkerDiscoveryNode, uuid.UUID(node["id"]))
        assert current_node is not None and current_node.worker_identity_registration_id is None
        assert session.query(WorkerIdentityRegistration).count() == 0
        assert session.query(WorkerIdentityEvidence).count() == 0


def test_identity_review_service_requires_separate_approval_permission_and_exact_org(engine):
    from secp_api.auth import Principal
    from secp_api.db import session_scope
    from secp_api.enums import Permission
    from secp_api.errors import AuthorizationError
    from secp_api.models import Organization, WorkerIdentityRegistration
    from secp_api.seed import bootstrap_dev
    from secp_api.services import worker_nodes

    with session_scope() as session:
        principal = bootstrap_dev(session)
        node = worker_nodes.publish_worker_node(
            session,
            organization_id=principal.organization_id,
            node_label="worker-rbac-review",
            ssh_public_key=_pubkey("rbac"),
            admission_anchor_hex=_anchor_hex(),
        )
        limited = Principal(
            user_id=principal.user_id,
            organization_id=principal.organization_id,
            email=principal.email,
            permissions=frozenset(
                {Permission.target_discovery_manage, Permission.worker_identity_manage}
            ),
        )
        kwargs = {
            "node_id": node.id,
            "expected_node_revision": node.revision,
            "expected_ssh_public_key_fingerprint": node.ssh_public_key_fingerprint,
            "expected_admission_anchor_fingerprint": node.admission_anchor_fingerprint,
            "deployment_binding": "production-worker",
            "proof_id": "pr5f.operator-review",
            "issuer": "secp.operator",
            "deployment_binding_review_confirmed": True,
            "verification_anchor_review_confirmed": True,
            "rotation_revocation_review_confirmed": True,
        }
        with pytest.raises(AuthorizationError):
            worker_nodes.approve_and_link_worker_node_identity(session, limited, **kwargs)
        assert session.query(WorkerIdentityRegistration).count() == 0

        foreign_org = Organization(name="Foreign", slug=f"foreign-{uuid.uuid4().hex[:8]}")
        session.add(foreign_org)
        session.flush()
        foreign_node = worker_nodes.publish_worker_node(
            session,
            organization_id=foreign_org.id,
            node_label="worker-foreign-review",
            ssh_public_key=_pubkey("foreign"),
            admission_anchor_hex=_anchor_hex(),
        )
        with pytest.raises(AuthorizationError):
            worker_nodes.approve_and_link_worker_node_identity(
                session,
                principal,
                **{
                    **kwargs,
                    "node_id": foreign_node.id,
                    "expected_node_revision": foreign_node.revision,
                    "expected_ssh_public_key_fingerprint": (
                        foreign_node.ssh_public_key_fingerprint
                    ),
                    "expected_admission_anchor_fingerprint": (
                        foreign_node.admission_anchor_fingerprint
                    ),
                },
            )
        assert session.query(WorkerIdentityRegistration).count() == 0


def test_new_bootstrap_key_binding_refuses_old_binding_compatibly(client_ctx):
    client, ctx = client_ctx
    host_line, fp = _host_key_and_fp()
    first_id = _bind_target_with_host_key(client, ctx["target_id"], host_line, fp)
    second_id = _bind_target_with_host_key(client, ctx["target_id"], host_line, fp)
    assert second_id != first_id
    first = client.get(f"{_BASE}/sessions/{first_id}")
    second = client.get(f"{_BASE}/sessions/{second_id}")
    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == "refused"
    assert second.json()["status"] == "bound"


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
        descriptors = bootstrap_discovery.resolve_ready_bundle_descriptors(
            s, uuid.UUID(ctx["organization_id"])
        )
    assert len(descriptors) == 1
    d = descriptors[0]
    assert d["enrollment_id"] == enrollment_id
    assert d["host_public_key"] == host_line
    assert d["account"] == "secpdisc"
    assert d["worker_ssh_public_key_fingerprint"].startswith("SHA256:")
    # Secret-free: no private key anywhere in the descriptor values.
    blob = repr(d)
    assert "PRIVATE" not in blob and "BEGIN OPENSSH" not in blob


def test_ready_bundle_resolver_is_strictly_scoped_to_worker_organization(client_ctx):
    client, ctx = client_ctx
    host_line, fingerprint = _host_key_and_fp()
    _bind_target_with_host_key(client, ctx["target_id"], host_line, fingerprint)
    local_enrollment_id = _enroll(client, ctx["target_id"])

    from secp_api.bootstrap_models import ProxmoxReadOnlyBootstrapSession
    from secp_api.db import session_scope
    from secp_api.discovery_models import TargetDiscoveryEnrollment
    from secp_api.enums import ProxmoxBootstrapStatus
    from secp_api.models import ExecutionTarget, Organization, TargetOnboarding
    from secp_api.services import bootstrap_discovery
    from sqlalchemy import select

    with session_scope() as session:
        local_org_id = uuid.UUID(ctx["organization_id"])
        local_session = session.execute(
            select(ProxmoxReadOnlyBootstrapSession).where(
                ProxmoxReadOnlyBootstrapSession.organization_id == local_org_id,
                ProxmoxReadOnlyBootstrapSession.status == ProxmoxBootstrapStatus.bound,
            )
        ).scalar_one()
        local_target = session.get(ExecutionTarget, local_session.execution_target_id)
        local_onboarding = session.get(TargetOnboarding, local_session.onboarding_id)
        assert local_target is not None and local_onboarding is not None

        foreign_org = Organization(name="Foreign tenant", slug="foreign-tenant-b8")
        empty_org = Organization(name="Empty tenant", slug="empty-tenant-b8")
        session.add_all((foreign_org, empty_org))
        session.flush()
        foreign_target = ExecutionTarget(
            organization_id=foreign_org.id,
            display_name="Foreign Proxmox",
            plugin_name=local_target.plugin_name,
            config=copy.deepcopy(local_target.config),
            config_hash="sha256:" + "e" * 64,
            secret_ref="env:SECP_PROVIDER_SECRET__FOREIGN",
            status=local_target.status,
            scope_policy=copy.deepcopy(local_target.scope_policy),
        )
        session.add(foreign_target)
        session.flush()
        foreign_onboarding = TargetOnboarding(
            organization_id=foreign_org.id,
            execution_target_id=foreign_target.id,
            onboarding_mode=local_onboarding.onboarding_mode,
            isolation_model=local_onboarding.isolation_model,
            status=local_onboarding.status,
            declared_boundary=copy.deepcopy(local_onboarding.declared_boundary),
            boundary_hash="sha256:" + "d" * 64,
        )
        session.add(foreign_onboarding)
        session.flush()
        foreign_enrollment = TargetDiscoveryEnrollment(
            organization_id=foreign_org.id,
            execution_target_id=foreign_target.id,
            onboarding_id=foreign_onboarding.id,
            display_name="Foreign discovery",
            ownership_label="secp.discovery/foreign",
        )
        foreign_session = ProxmoxReadOnlyBootstrapSession(
            organization_id=foreign_org.id,
            execution_target_id=foreign_target.id,
            onboarding_id=foreign_onboarding.id,
            account=local_session.account,
            pve_role=local_session.pve_role,
            worker_ssh_public_key=local_session.worker_ssh_public_key,
            worker_ssh_public_key_fingerprint=local_session.worker_ssh_public_key_fingerprint,
            status=local_session.status,
            ssh_port=local_session.ssh_port,
            host_key_fingerprint=local_session.host_key_fingerprint,
            host_public_key=local_session.host_public_key,
            endpoint_binding_hash=local_session.endpoint_binding_hash,
            live_read_authorization_id=uuid.uuid4(),
            authorization_version=1,
            expires_at=local_session.expires_at,
        )
        session.add_all((foreign_enrollment, foreign_session))
        session.flush()
        foreign_enrollment_id = str(foreign_enrollment.id)

        local = bootstrap_discovery.resolve_ready_bundle_descriptors(session, local_org_id)
        foreign = bootstrap_discovery.resolve_ready_bundle_descriptors(session, foreign_org.id)
        empty = bootstrap_discovery.resolve_ready_bundle_descriptors(session, empty_org.id)

    assert [row["enrollment_id"] for row in local] == [local_enrollment_id]
    assert [row["enrollment_id"] for row in foreign] == [foreign_enrollment_id]
    assert empty == []  # both ready descriptors are foreign to this worker binding
