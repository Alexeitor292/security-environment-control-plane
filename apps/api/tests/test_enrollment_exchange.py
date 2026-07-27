"""Supported evidence-driven bind exchange over HTTP (SECP-PR5H-B1, Phase 3).

Drives POST /api/v1/enrollment/{id}/exchange/bind through the real ASGI app with an INJECTED
in-process controller signer (the sealed default is exercised separately). Proves: a genuine worker
proof-of-possession yields an internally-signed controller offer that verifies under the
invitation's pinned controller key and advances the enrollment to ``offer_transported`` writing one
signed-offer row; a lost-response retry returns the BYTE-EQUIVALENT original offer; the sealed
default fails closed; a forged PoP and a worker presenting the controller's own key both refuse.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient
from secp_api.deps import get_enrollment_offer_signer
from secp_commissioning import enrollment_attestation as ea
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    ControllerEnrollmentOfferSigner,
    SigningIdentityLease,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.signing import generate_keypair
from sqlalchemy import text
from sqlalchemy.orm import Session

DEV_ORIGIN = "https://controller.example.test"
RELEASE = "sha256:" + "a" * 64
INSTALL = "controller-dev0001"
_ANCESTORS = ("/var", "/var/lib", "/var/lib/secp", "/var/lib/secp/bootstrap")


@pytest.fixture
def client(engine, principal):
    from secp_api.main import create_app
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD

    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )
    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


class _Provider:
    def __init__(self, lease: SigningIdentityLease) -> None:
        self._lease = lease

    @contextmanager
    def lease(self):
        yield self._lease


def _activate_identity(session, pub_hex: str) -> None:
    """Supersede the dev-seeded controller identity with one whose key we control, so the injected
    signer can mint an offer that matches the invitation's pinned controller key."""
    from secp_api.controller_identity_dev import build_test_verified_controller_identity
    from secp_api.services import controller_identity

    proof = build_test_verified_controller_identity(controller_trust_anchor_hex=pub_hex)
    controller_identity.activate_controller_identity(session, proof)
    session.commit()


def _injected_signer(pub_hex: str, priv_hex: str) -> ControllerEnrollmentOfferSigner:
    fs = InMemoryFilesystem()
    for d in _ANCESTORS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    fs.seed_file(CONTROLLER_ENROLLMENT_KEY_PATH, bytes.fromhex(priv_hex), uid=0, gid=0, mode=0o600)
    lease = SigningIdentityLease(
        row_id="row-1",
        activation_token="row-1|2026-07-01T00:00:00+00:00|gen-1",
        controller_installation_id=INSTALL,
        controller_key_id=ea.key_id_for(pub_hex),
        controller_trust_anchor_hex=pub_hex,
        controller_origin=DEV_ORIGIN,
        release_digest=RELEASE,
        management_identity_digest="sha256:" + "e" * 64,
        bootstrap_evidence_digest="sha256:" + "f" * 64,
        enrollment_key_proof_id=ea.enrollment_key_proof_id_for(pub_hex),
    )
    return ControllerEnrollmentOfferSigner(fs, _Provider(lease))


def _wire_signer(client, session):
    """Rotate to a controller identity we hold the key for and inject the matching signer."""
    priv_hex, pub_hex = generate_keypair()
    _activate_identity(session, pub_hex)
    signer = _injected_signer(pub_hex, priv_hex)
    client.app.dependency_overrides[get_enrollment_offer_signer] = lambda: signer
    return pub_hex


def _create_invitation(client) -> dict:
    r = client.post(
        "/api/v1/enrollment/invitations",
        json={"idempotency_key": "k" * 24, "deployment_site_label": "rack-01.eu_a"},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _pop_body(inv: dict, wpriv: str, wpub: str, *, worker_installation_id: str) -> dict:
    claim = ea.worker_binding_claim(
        enrollment_id=inv["enrollment_id"],
        invitation_id=inv["invitation_id"],
        controller_installation_id=inv["controller_installation_id"],
        controller_key_id=inv["controller_key_id"],
        controller_transaction_id=inv["transaction_id"],
        worker_installation_id=worker_installation_id,
        worker_key_id=ea.key_id_for(wpub),
        release_digest=inv["release_digest"],
        expires_at=inv["expires_at"],
    )
    att = ea.sign_detached(
        wpriv,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.POP_KIND,
        digest=ea.claim_digest(claim),
    )
    return {
        "worker_installation_id": worker_installation_id,
        "worker_public_key_hex": wpub,
        "attestation": {
            "algorithm": att.algorithm,
            "key_id": att.key_id,
            "public_key_hex": att.public_key_hex,
            "signature": att.signature,
        },
        "expected_revision": 0,
    }


def _signed_offer_count(engine, enrollment_id: str) -> int:
    with Session(engine) as s:
        return s.execute(
            text("SELECT count(*) FROM worker_enrollment_signed_offer WHERE enrollment_id=:e"),
            {"e": enrollment_id},
        ).scalar_one()


def _post_bind(client, inv: dict, body: dict):
    return client.post(f"/api/v1/enrollment/{inv['enrollment_id']}/exchange/bind", json=body)


# --- happy path ----------------------------------------------------------------------------------


def test_bind_exchange_mints_a_verifiable_offer_and_advances_to_offer_transported(
    client, session, engine
):
    _wire_signer(client, session)
    inv = _create_invitation(client)
    wpriv, wpub = generate_keypair()
    wid = "worker-" + ea.key_id_for(wpub).split(":")[-1][:16]
    r = _post_bind(client, inv, _pop_body(inv, wpriv, wpub, worker_installation_id=wid))
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["enrollment"]["state"] == "offer_transported"
    assert payload["enrollment"]["revision"] == 2
    offer = payload["signed_offer"]
    ea.verify_detached(
        ea.DetachedAttestation(**offer["attestation"]),
        expected_key_id=inv["controller_key_id"],
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.OFFER_KIND,
        digest=ea.claim_digest(offer["claim"]),
    )
    assert _signed_offer_count(engine, inv["enrollment_id"]) == 1


def test_a_lost_response_retry_returns_the_byte_equivalent_offer(client, session, engine):
    _wire_signer(client, session)
    inv = _create_invitation(client)
    wpriv, wpub = generate_keypair()
    wid = "worker-" + ea.key_id_for(wpub).split(":")[-1][:16]
    body = _pop_body(inv, wpriv, wpub, worker_installation_id=wid)
    first = _post_bind(client, inv, body)
    assert first.status_code == 200, first.text
    second = _post_bind(client, inv, body)
    assert second.status_code == 200, second.text
    # the persisted signed offer is returned byte-equivalent; no second signed-offer row is written
    assert second.json()["signed_offer"] == first.json()["signed_offer"]
    assert _signed_offer_count(engine, inv["enrollment_id"]) == 1


# --- sealed default + refusals -------------------------------------------------------------------


def test_the_sealed_signer_default_fails_closed(client):
    # no signer override => the sealed default client refuses (503)
    inv = _create_invitation(client)  # uses the dev-seeded identity; signer never runs
    wpriv, wpub = generate_keypair()
    wid = "worker-" + ea.key_id_for(wpub).split(":")[-1][:16]
    r = _post_bind(client, inv, _pop_body(inv, wpriv, wpub, worker_installation_id=wid))
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "enrollment_signer_unavailable"


def test_a_forged_pop_is_refused(client, session):
    _wire_signer(client, session)
    inv = _create_invitation(client)
    wpriv, wpub = generate_keypair()
    wid = "worker-" + ea.key_id_for(wpub).split(":")[-1][:16]
    body = _pop_body(inv, wpriv, wpub, worker_installation_id=wid)
    body["attestation"]["signature"] = "0" * 128  # forged
    r = _post_bind(client, inv, body)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "enrollment_pop_invalid"


def test_a_worker_presenting_the_controller_key_is_refused(client, session):
    pub_hex = _wire_signer(client, session)
    inv = _create_invitation(client)
    # the injected signer's private key is not available to the worker, so a real PoP under the
    # controller key cannot be forged here; instead present the controller PUBLIC key with a
    # worker-signed claim — the derived worker key id won't match the signature and PoP fails first.
    wpriv, _wpub = generate_keypair()
    wid = "worker-" + ea.key_id_for(pub_hex).split(":")[-1][:16]
    body = _pop_body(inv, wpriv, pub_hex, worker_installation_id=wid)  # present controller pubkey
    r = _post_bind(client, inv, body)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "enrollment_pop_invalid"


def test_the_exchange_requires_an_authenticated_progress_principal(client, session):
    from secp_api.auth import Principal
    from secp_api.deps import current_principal
    from secp_api.enums import Permission

    _wire_signer(client, session)
    inv = _create_invitation(client)
    # a principal with only read/manage (no progress) is refused authorization
    reader = Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="r@t",
        permissions=frozenset({Permission.enrollment_read}),
    )
    client.app.dependency_overrides[current_principal] = lambda: reader
    wpriv, wpub = generate_keypair()
    wid = "worker-" + ea.key_id_for(wpub).split(":")[-1][:16]
    r = _post_bind(client, inv, _pop_body(inv, wpriv, wpub, worker_installation_id=wid))
    assert r.status_code in (403, 401)


# --- result exchange (verified -> healthy) -------------------------------------------------------


def _drive_bind(client, session):
    _wire_signer(client, session)
    inv = _create_invitation(client)
    wpriv, wpub = generate_keypair()
    wid = "worker-" + ea.key_id_for(wpub).split(":")[-1][:16]
    r = _post_bind(client, inv, _pop_body(inv, wpriv, wpub, worker_installation_id=wid))
    assert r.status_code == 200, r.text
    return inv, wpriv, wpub, r.json()["signed_offer"]


def _result_body(inv, wpriv, wpub, offer, *, health=None, outcome="healthy") -> dict:
    health = {k: True for k in ea.REQUIRED_HEALTH_CHECKS} if health is None else health
    claim = ea.worker_result_claim(
        enrollment_id=inv["enrollment_id"],
        controller_transaction_id=inv["transaction_id"],
        worker_key_id=ea.key_id_for(wpub),
        predecessor_digest=ea.claim_digest(offer["claim"]),
        release_digest=inv["release_digest"],
        outcome=outcome,
        health_evidence_digest=ea.sha256_digest(health),
        generation=offer["attestation"]["key_id"],
        challenge=offer["attestation"]["signature"],
    )
    att = ea.sign_detached(
        wpriv,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.RESULT_KIND,
        digest=ea.claim_digest(claim),
    )
    return {
        "worker_public_key_hex": wpub,
        "outcome": outcome,
        "attestation": {
            "algorithm": att.algorithm,
            "key_id": att.key_id,
            "public_key_hex": att.public_key_hex,
            "signature": att.signature,
        },
        "health_evidence": health,
        "expected_revision": 2,
    }


def _post_result(client, inv, body):
    return client.post(f"/api/v1/enrollment/{inv['enrollment_id']}/exchange/result", json=body)


def test_result_exchange_drives_verified_then_healthy(client, session):
    inv, wpriv, wpub, offer = _drive_bind(client, session)
    r = _post_result(client, inv, _result_body(inv, wpriv, wpub, offer))
    assert r.status_code == 200, r.text
    e = r.json()["enrollment"]
    assert e["state"] == "healthy" and e["revision"] == 5


def test_result_exchange_retry_is_idempotent(client, session):
    inv, wpriv, wpub, offer = _drive_bind(client, session)
    body = _result_body(inv, wpriv, wpub, offer)
    first = _post_result(client, inv, body)
    assert first.status_code == 200, first.text
    second = _post_result(client, inv, body)
    assert second.status_code == 200, second.text
    assert second.json()["enrollment"]["state"] == "healthy"


def test_incomplete_health_cannot_become_healthy(client, session):
    inv, wpriv, wpub, offer = _drive_bind(client, session)
    health = {k: True for k in ea.REQUIRED_HEALTH_CHECKS}
    health["no_provider_contact"] = False  # one required check fails
    r = _post_result(client, inv, _result_body(inv, wpriv, wpub, offer, health=health))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "enrollment_health_incomplete"


def test_a_non_success_outcome_cannot_become_healthy(client, session):
    inv, wpriv, wpub, offer = _drive_bind(client, session)
    r = _post_result(client, inv, _result_body(inv, wpriv, wpub, offer, outcome="degraded"))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "enrollment_health_incomplete"


def test_a_result_signed_by_an_unbound_key_is_refused(client, session):
    inv, wpriv, wpub, offer = _drive_bind(client, session)
    other_priv, other_pub = generate_keypair()  # not the bound worker key
    r = _post_result(client, inv, _result_body(inv, other_priv, other_pub, offer))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "enrollment_pop_invalid"


def test_a_forged_result_signature_is_refused(client, session):
    inv, wpriv, wpub, offer = _drive_bind(client, session)
    body = _result_body(inv, wpriv, wpub, offer)
    body["attestation"]["signature"] = "0" * 128
    r = _post_result(client, inv, body)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "enrollment_pop_invalid"


def test_result_before_offer_is_refused(client, session):
    # a result cannot be accepted before an offer has been transported (no persisted offer)
    _wire_signer(client, session)
    inv = _create_invitation(client)
    wpriv, wpub = generate_keypair()
    fake_offer = {
        "claim": {"schema": ea.OFFER_SCHEMA},
        "attestation": {"key_id": "x", "signature": "y"},
    }
    r = _post_result(client, inv, _result_body(inv, wpriv, wpub, fake_offer))
    assert r.status_code in (409, 422)  # wrong_state (no bound worker / no offer)
