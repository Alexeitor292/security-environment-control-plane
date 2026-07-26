"""Supported worker-enrollment controller API — first vertical slice (SECP-PR5H-B1).

Drives the controller invitation lifecycle through the real ASGI app on a per-test engine: create a
single-use invitation (opening its durable enrollment at revision 0) and read the bounded status
projection. Proves the org-boundary authorization and the secret-free projection end to end over
HTTP, wired to the PR5H-A durable service — no direct service calls for the happy path.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.auth import Principal
from secp_api.deps import current_principal
from secp_api.enums import Permission
from secp_api.errors import WorkerEnrollmentError
from secp_api.worker_enrollment_contract import create_invitation, sha256_digest_of_hex

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = sha256_digest_of_hex(CTRL_HEX)
RELEASE = "sha256:" + "a" * 64
ORIGIN = "https://ctrl.example.com"
SITE = "rack-01.eu_a"
# the dev seed activates this controller identity; the API sources it authoritatively (F3)
DEV_ORIGIN = "https://controller.example.test"
DEV_ANCHOR_HEX = "11" * 32
DEV_KEY = sha256_digest_of_hex(DEV_ANCHOR_HEX)


def _principal(org_id: uuid.UUID, perms) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=org_id,
        email="rbac@test",
        permissions=frozenset(perms),
    )


def _as(client: TestClient, principal: Principal) -> TestClient:
    """Override the resolved principal on the running app (router-independent auth injection)."""
    client.app.dependency_overrides[current_principal] = lambda: principal
    return client


@pytest.fixture
def client(engine, principal):
    from secp_api.main import create_app
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD

    # the durable enrollment service refuses unless the live schema head is the required one; the
    # ORM ``create_all`` does not manage ``alembic_version``, so stamp it here (as production
    # migrations would). ``c2f8e1a4b6d9`` is the sole PR5H-B1 head.
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
    # a fresh high-entropy idempotency key per call (distinct logical creation) unless overridden
    body: dict = dict(
        idempotency_key=secrets.token_urlsafe(24),
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
    assert out["deployment_site_label"] == SITE
    # F3: the response reflects the authoritative ACTIVE controller identity, not a caller value
    assert out["controller_origin"] == DEV_ORIGIN
    assert out["controller_key_id"] == DEV_KEY
    assert out["controller_trust_anchor_hex"] == DEV_ANCHOR_HEX

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


def test_caller_supplied_controller_identity_field_is_rejected(client):
    # F3: the request schema forbids extra fields, so a caller cannot substitute the controller
    # identity/origin/trust-anchor/release — an attempt is a bounded 422, never silently used
    for field in (
        "controller_installation_id",
        "controller_key_id",
        "controller_trust_anchor_hex",
        "controller_origin",
        "release_digest",
    ):
        r = client.post("/api/v1/enrollment/invitations", json=_create_body(**{field: "x"}))
        assert r.status_code == 422, field


def test_malformed_idempotency_key_is_rejected(client):
    r = client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key="short"))
    assert r.status_code == 422


# --- F1: dedicated RBAC (enrollment:read vs enrollment:manage), enforced in the service ----------


def test_rbac_split_read_vs_manage_is_pinned(client, principal):
    # create as the full-permission admin (the default dev principal has both perms)
    eid = client.post("/api/v1/enrollment/invitations", json=_create_body()).json()["enrollment_id"]
    org = principal.organization_id

    # read-only: may read status, may NOT create
    _as(client, _principal(org, [Permission.enrollment_read]))
    assert client.get(f"/api/v1/enrollment/{eid}").status_code == 200
    assert client.post("/api/v1/enrollment/invitations", json=_create_body()).status_code == 403

    # manage-only: PINNED decision — manage does NOT imply read (strict separation)
    _as(client, _principal(org, [Permission.enrollment_manage]))
    assert client.post("/api/v1/enrollment/invitations", json=_create_body()).status_code == 201
    assert client.get(f"/api/v1/enrollment/{eid}").status_code == 403

    # zero permissions: both forbidden
    _as(client, _principal(org, []))
    assert client.post("/api/v1/enrollment/invitations", json=_create_body()).status_code == 403
    assert client.get(f"/api/v1/enrollment/{eid}").status_code == 403


def test_unauthenticated_request_is_401(client):
    from secp_api.errors import AuthenticationError

    def _raise() -> Principal:
        raise AuthenticationError("no credential")

    client.app.dependency_overrides[current_principal] = _raise
    assert client.post("/api/v1/enrollment/invitations", json=_create_body()).status_code == 401
    assert client.get("/api/v1/enrollment/sha256:" + "0" * 64).status_code == 401


def test_service_layer_enforces_rbac_so_a_router_bypass_cannot_evade_it(session, principal):
    from secp_api.errors import AuthorizationError
    from secp_api.services import worker_enrollment as svc

    zero = _principal(principal.organization_id, [])
    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-rbac",
        nonce="sha256:" + "f" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    # RBAC is enforced inside the service, before any schema/DB access — a direct call still refuses
    with pytest.raises(AuthorizationError):
        svc.create_invitation_and_open(
            session,
            zero,
            invitation=invitation,
            deployment_site_label=SITE,
            now="2026-07-21T00:10:00Z",
        )
    with pytest.raises(AuthorizationError):
        svc.load_public_view(session, zero, enrollment_id="sha256:" + "0" * 64)


# --- F2: atomic, secret-free invitation-created audit --------------------------------------------


def _audit_rows(session):
    from sqlalchemy import text

    return session.execute(
        text(
            "SELECT resource_id, organization_id, data FROM audit_event"
            " WHERE action='enrollment.invitation_created'"
        )
    ).all()


def _enrollment_row_count(session) -> int:
    from sqlalchemy import text

    return session.execute(text("SELECT count(*) FROM worker_enrollment_state")).scalar_one()


def test_successful_creation_records_exactly_one_secret_free_audit(client, session):
    out = client.post("/api/v1/enrollment/invitations", json=_create_body()).json()
    rows = _audit_rows(session)
    assert len(rows) == 1
    rid, _org, data = rows[0]
    assert rid == out["enrollment_id"]
    import json as _json

    blob = _json.dumps(data if isinstance(data, dict) else _json.loads(data))
    d = data if isinstance(data, dict) else _json.loads(data)
    assert d["state"] == "invited" and d["revision"] == 0 and d["deployment_site_label"] == SITE
    # never audit the nonce, trust-anchor bytes, origin, transaction id or a full digest
    for secret in (out["invitation_id"], CTRL_HEX, ORIGIN, out["transaction_id"], RELEASE):
        assert secret not in blob


def test_authorization_failure_produces_no_success_audit(client, principal, session):
    _as(client, _principal(principal.organization_id, []))
    assert client.post("/api/v1/enrollment/invitations", json=_create_body()).status_code == 403
    assert _audit_rows(session) == []


def test_contract_failure_leaves_no_state_and_no_success_audit(client, session):
    assert (
        client.post(
            "/api/v1/enrollment/invitations", json=_create_body(controller_origin="http://x")
        ).status_code
        == 422
    )
    assert _enrollment_row_count(session) == 0
    assert _audit_rows(session) == []


def test_failure_after_state_creation_before_commit_rolls_back_state_and_audit(
    client, session, monkeypatch
):
    # inject a failure at the audit step (after the durable rows are added, before commit): the
    # whole transaction must roll back — zero enrollment rows AND zero audit rows survive.
    from secp_api.services import worker_enrollment as svc

    def _boom(*a, **k):
        raise RuntimeError("injected post-state failure")

    monkeypatch.setattr(svc.audit, "record", _boom)
    # the failure unwinds through get_db, which rolls the whole request transaction back (the
    # TestClient re-raises the server exception; production would surface it as a 500)
    with pytest.raises(RuntimeError):
        client.post("/api/v1/enrollment/invitations", json=_create_body())
    assert _enrollment_row_count(session) == 0  # durable state rolled back
    assert _audit_rows(session) == []  # ...and no audit survived


# --- F4: one clock sample per creation -----------------------------------------------------------


def test_creation_samples_the_clock_once_and_ttl_is_exact(client, monkeypatch):
    import datetime as dt

    from secp_api.routers import enrollment as router_mod

    calls = {"n": 0}
    fixed = dt.datetime(2026, 7, 25, 12, 0, 0, 999999, tzinfo=dt.UTC)  # near a boundary

    def fake_now() -> dt.datetime:
        calls["n"] += 1
        return fixed

    monkeypatch.setattr(router_mod, "_utc_now", fake_now)
    out = client.post("/api/v1/enrollment/invitations", json=_create_body(ttl_seconds=86400)).json()
    assert calls["n"] == 1  # exactly one sample per creation
    created = dt.datetime.fromisoformat(out["created_at"])
    expires = dt.datetime.fromisoformat(out["expires_at"])
    # created and expires derive from the same instant: the difference is exactly the requested TTL
    assert (expires - created).total_seconds() == 86400


# --- F3: authoritative controller-identity sourcing ----------------------------------------------


def test_creation_refused_when_no_active_controller_identity(client, session):
    from sqlalchemy import text

    session.execute(text("DELETE FROM controller_enrollment_identity"))
    session.commit()
    r = client.post("/api/v1/enrollment/invitations", json=_create_body())
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "enrollment_controller_identity_unavailable"
    # refused before any write: no enrollment row, no audit
    assert _enrollment_row_count(session) == 0
    assert _audit_rows(session) == []


def test_creation_refused_when_active_identity_binding_is_inconsistent(client, session):
    from sqlalchemy import text

    # a persisted key id that no longer derives from the anchor (the DB CHECKs cannot compute
    # sha256, so sourcing re-validates it and refuses) — the anchor stays a valid 64-hex string
    session.execute(
        text(
            "UPDATE controller_enrollment_identity SET controller_trust_anchor_hex = :h"
            " WHERE status='active'"
        ),
        {"h": "99" * 32},
    )
    session.commit()
    r = client.post("/api/v1/enrollment/invitations", json=_create_body())
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "enrollment_controller_identity_unavailable"


def _rotate(session, **over):
    from secp_api.controller_identity_dev import build_test_verified_controller_identity
    from secp_api.services import controller_identity

    proof = build_test_verified_controller_identity(**over)
    controller_identity.activate_controller_identity(session, proof)
    session.commit()
    return proof


def test_response_tracks_the_active_identity_after_rotation(client, session):
    proof = _rotate(
        session,
        controller_installation_id="controller-rot0002",
        controller_trust_anchor_hex="22" * 32,
        controller_origin="https://controller2.example.test",
        release_digest="sha256:" + "b" * 64,
    )
    out = client.post("/api/v1/enrollment/invitations", json=_create_body()).json()
    # new invitations bind ONLY the current active identity
    assert out["controller_key_id"] == proof.controller_key_id
    assert out["controller_origin"] == "https://controller2.example.test"


# --- R2: idempotency is bound to the exact active controller identity/release --------------------


def test_replay_after_controller_rotation_conflicts(client, session):
    key = secrets.token_urlsafe(24)
    assert (
        client.post(
            "/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key)
        ).status_code
        == 201
    )
    _rotate(
        session,
        controller_installation_id="controller-rot0007",
        controller_trust_anchor_hex="77" * 32,
    )
    r = client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    assert r.status_code == 409 and r.json()["error"]["code"] == "enrollment_idempotency_conflict"


def test_replay_after_release_change_conflicts(client, session):
    key = secrets.token_urlsafe(24)
    assert (
        client.post(
            "/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key)
        ).status_code
        == 201
    )
    _rotate(session, release_digest="sha256:" + "d" * 64)  # same key/anchor/origin, new release
    r = client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    assert r.status_code == 409 and r.json()["error"]["code"] == "enrollment_idempotency_conflict"


def test_replay_after_origin_change_conflicts(client, session):
    key = secrets.token_urlsafe(24)
    assert (
        client.post(
            "/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key)
        ).status_code
        == 201
    )
    _rotate(session, controller_origin="https://controller-moved.example.test")
    r = client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    assert r.status_code == 409 and r.json()["error"]["code"] == "enrollment_idempotency_conflict"


# --- R3: the service must not roll back the caller's outer transaction ---------------------------


def test_replay_preserves_the_callers_outer_transaction(client, session, principal):
    from secp_api import audit
    from secp_api.enums import AuditAction
    from secp_api.services import worker_enrollment as svc
    from sqlalchemy import text

    key = secrets.token_urlsafe(24)
    # a committed original so the next attempt collides
    client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    # stage an unrelated audit row in the caller's tx, THEN trigger a replay via the service
    audit.record(
        session,
        action=AuditAction.authorization_denied,
        resource_type="unrelated",
        resource_id="keep-me",
        actor="t",
        organization_id=principal.organization_id,
    )
    result = svc.create_supported_invitation(
        session,
        principal,
        idempotency_key=key,
        deployment_site_label=SITE,
        ttl_seconds=3600,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    session.commit()
    assert result.deduplicated is True  # exact replay
    # the unrelated staged row survived (only the speculative insert's savepoint was rolled back)
    n = session.execute(
        text("SELECT count(*) FROM audit_event WHERE resource_id='keep-me'")
    ).scalar_one()
    assert n == 1


def test_conflict_preserves_the_callers_outer_transaction(client, session, principal):
    from secp_api import audit
    from secp_api.enums import AuditAction
    from secp_api.services import worker_enrollment as svc
    from sqlalchemy import text

    key = secrets.token_urlsafe(24)
    client.post(
        "/api/v1/enrollment/invitations",
        json=_create_body(idempotency_key=key, deployment_site_label="rack-01.eu_a"),
    )
    audit.record(
        session,
        action=AuditAction.authorization_denied,
        resource_type="unrelated",
        resource_id="survivor",
        actor="t",
        organization_id=principal.organization_id,
    )
    with pytest.raises(WorkerEnrollmentError) as ei:
        svc.create_supported_invitation(
            session,
            principal,
            idempotency_key=key,
            deployment_site_label="rack-99.elsewhere",  # different bound input -> conflict
            ttl_seconds=3600,
            created_at="2026-07-21T00:00:00Z",
            expires_at="2026-07-21T01:00:00Z",
        )
    assert ei.value.code == "enrollment_idempotency_conflict"
    session.commit()
    n = session.execute(
        text("SELECT count(*) FROM audit_event WHERE resource_id='survivor'")
    ).scalar_one()
    assert n == 1


# --- R4: a delayed replay returns the IMMUTABLE original create response -------------------------


def test_replay_after_progression_returns_the_original_invited_response(client):
    key = secrets.token_urlsafe(24)
    r1 = client.post(
        "/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key)
    ).json()
    # advance the enrollment past invited (revoke -> refused/revision 1)
    assert (
        client.post(
            f"/api/v1/enrollment/{r1['enrollment_id']}/revoke", json={"expected_revision": 0}
        ).status_code
        == 200
    )
    # a delayed replay STILL returns the byte-equivalent original invited/revision-0 response
    r2 = client.post(
        "/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key)
    ).json()
    assert r2 == r1
    assert r2["state"] == "invited" and r2["revision"] == 0


# --- F5: idempotent creation across lost responses -----------------------------------------------


def test_exact_replay_returns_the_original_invitation(client):
    key = secrets.token_urlsafe(24)
    r1 = client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    assert r1.status_code == 201
    # a retry (lost-response) with the SAME key returns the ORIGINAL invitation, byte-equivalent
    r2 = client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    assert r2.status_code == 201
    assert r1.json() == r2.json()


def test_replay_creates_no_second_state_or_audit(client, session):
    key = secrets.token_urlsafe(24)
    client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    client.post("/api/v1/enrollment/invitations", json=_create_body(idempotency_key=key))
    assert _enrollment_row_count(session) == 1  # exactly one durable enrollment
    assert len(_audit_rows(session)) == 1  # ...and exactly one creation audit


def test_same_key_different_site_refuses_conflict(client):
    key = secrets.token_urlsafe(24)
    assert (
        client.post(
            "/api/v1/enrollment/invitations",
            json=_create_body(idempotency_key=key, deployment_site_label="rack-01.eu_a"),
        ).status_code
        == 201
    )
    r = client.post(
        "/api/v1/enrollment/invitations",
        json=_create_body(idempotency_key=key, deployment_site_label="rack-99.elsewhere"),
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "enrollment_idempotency_conflict"


# --- worker submission/progression slice: bind / offer / result / verify / healthy over HTTP ------
#
# Each endpoint is a thin adapter over the PR5H-A durable CAS service: service-layer
# ``enrollment:progress`` authorization, the organization boundary, and exact-retry through the
# existing step receipts. Endpoints consume ONLY already-bound facts (a digest + transaction +
# signer key id) — never raw handoff bytes or a private key — and open no outbound transport.

WORKER_HEX = (b"\x22" * 32).hex()
WORKER_KEY = sha256_digest_of_hex(WORKER_HEX)
OFFER_D = "sha256:" + "c" * 64
RESULT_D = "sha256:" + "d" * 64
WORKER_INSTALL = "worker-bbbbbbbb"


def _fresh(engine):
    from sqlalchemy.orm import Session

    return Session(engine)


def _create(client, **over) -> tuple[str, str]:
    # returns (enrollment_id, transaction_id): the worker echoes the invitation's server-issued
    # transaction id on every progression step — it is not a value the worker invents
    out = client.post("/api/v1/enrollment/invitations", json=_create_body(**over)).json()
    return out["enrollment_id"], out["transaction_id"]


def _token(engine, enrollment_id: str) -> dict:
    # the caller's observed CAS coordinates, read from a fresh session so it always reflects the
    # latest committed head (the secret-free status projection deliberately omits these)
    from secp_api import worker_enrollment_repository as repo

    with _fresh(engine) as s:
        loaded = repo.load_read_only(s, enrollment_id)
        assert loaded is not None, enrollment_id
        st = loaded.state
        return {
            "revision": st.revision,
            "state_digest": st.digest(),
            "sequence": st.sequence,
            "predecessor_digest": st.predecessor_digest,
        }


def _bind_body(engine, eid: str, txn: str) -> dict:
    return {
        "worker_installation_id": WORKER_INSTALL,
        "worker_key_id": WORKER_KEY,
        "transaction_id": txn,
        "expected": _token(engine, eid),
    }


def _drive_to_healthy(client, engine, eid: str, txn: str) -> None:
    assert (
        client.post(f"/api/v1/enrollment/{eid}/bind", json=_bind_body(engine, eid, txn)).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/enrollment/{eid}/offer",
            json={
                "digest": OFFER_D,
                "transaction_id": txn,
                "signer_key_id": CTRL_KEY,
                "expected": _token(engine, eid),
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/enrollment/{eid}/result",
            json={
                "digest": RESULT_D,
                "transaction_id": txn,
                "signer_key_id": WORKER_KEY,
                "expected": _token(engine, eid),
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/enrollment/{eid}/verify",
            json={"release_digest": RELEASE, "expected": _token(engine, eid)},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/enrollment/{eid}/healthy",
            json={"expected": _token(engine, eid)},
        ).status_code
        == 200
    )


def test_progression_bind_offer_result_verify_healthy_over_http(client, engine):
    eid, txn = _create(client)

    b = client.post(f"/api/v1/enrollment/{eid}/bind", json=_bind_body(engine, eid, txn))
    assert b.status_code == 200, b.text
    assert b.json()["state"] == "worker_bound" and b.json()["revision"] == 1
    assert b.json()["worker_installation_id"] == WORKER_INSTALL
    assert b.json()["worker_key_fingerprint"]  # a fingerprint, not the full key
    assert "controller_trust_anchor_hex" not in b.json()  # projection stays secret-free

    o = client.post(
        f"/api/v1/enrollment/{eid}/offer",
        json={
            "digest": OFFER_D,
            "transaction_id": txn,
            "signer_key_id": CTRL_KEY,
            "expected": _token(engine, eid),
        },
    )
    assert (
        o.status_code == 200
        and o.json()["state"] == "offer_transported"
        and o.json()["revision"] == 2
    )

    r = client.post(
        f"/api/v1/enrollment/{eid}/result",
        json={
            "digest": RESULT_D,
            "transaction_id": txn,
            "signer_key_id": WORKER_KEY,
            "expected": _token(engine, eid),
        },
    )
    assert (
        r.status_code == 200
        and r.json()["state"] == "result_transported"
        and r.json()["revision"] == 3
    )

    v = client.post(
        f"/api/v1/enrollment/{eid}/verify",
        json={"release_digest": RELEASE, "expected": _token(engine, eid)},
    )
    assert v.status_code == 200 and v.json()["state"] == "verified" and v.json()["revision"] == 4

    h = client.post(f"/api/v1/enrollment/{eid}/healthy", json={"expected": _token(engine, eid)})
    assert h.status_code == 200 and h.json()["state"] == "healthy" and h.json()["revision"] == 5


def test_progression_requires_the_enrollment_progress_permission(client, engine, principal):
    eid, txn = _create(client)
    org = principal.organization_id
    body = _bind_body(engine, eid, txn)

    # read + manage but NOT progress: strictly separated, so progression is forbidden
    _as(client, _principal(org, [Permission.enrollment_read, Permission.enrollment_manage]))
    assert client.post(f"/api/v1/enrollment/{eid}/bind", json=body).status_code == 403

    # the dedicated progress permission authorizes it (same org, still revision 0)
    _as(client, _principal(org, [Permission.enrollment_progress]))
    ok = client.post(f"/api/v1/enrollment/{eid}/bind", json=body)
    assert ok.status_code == 200, ok.text
    assert ok.json()["revision"] == 1


def test_progression_is_organization_scoped(client, session, engine, other_org_principal):
    from secp_api.services import worker_enrollment as svc

    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-prog-cross",
        nonce="sha256:" + "e" * 64,
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
    eid = seeded.state.enrollment_id
    # the authenticated dev principal (a DIFFERENT org) cannot progress it — refused on the org
    # boundary before the invitation/CAS logic is reached
    r = client.post(
        f"/api/v1/enrollment/{eid}/bind", json=_bind_body(engine, eid, "txn-prog-cross")
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "enrollment_forbidden"


def test_progression_exact_retry_is_idempotent_through_receipts(client, engine):
    from sqlalchemy import text

    eid, txn = _create(client)
    body = _bind_body(engine, eid, txn)  # a rev-0 token
    a = client.post(f"/api/v1/enrollment/{eid}/bind", json=body)
    assert a.status_code == 200 and a.json()["revision"] == 1

    # replay the SAME request (the retry legitimately carries the now-stale rev-0 token): the step
    # receipt short-circuits it to the identical result — never a second advance or a conflict
    b = client.post(f"/api/v1/enrollment/{eid}/bind", json=body)
    assert b.status_code == 200
    assert b.json() == a.json()

    with _fresh(engine) as s:
        n = s.execute(
            text(
                "SELECT count(*) FROM audit_event"
                " WHERE action='enrollment.worker_bound' AND resource_id=:e"
            ),
            {"e": eid},
        ).scalar_one()
    assert n == 1  # exactly one winning-transition audit; the dedup path records none


def test_progression_audit_is_bounded_and_secret_free(client, engine):
    import json as _json

    from sqlalchemy import text

    eid, txn = _create(client)
    _drive_to_healthy(client, engine, eid, txn)

    with _fresh(engine) as s:
        rows = s.execute(
            text(
                "SELECT action, data FROM audit_event WHERE resource_id=:e"
                " AND action LIKE 'enrollment.%' AND action <> 'enrollment.invitation_created'"
            ),
            {"e": eid},
        ).all()

    # exactly one bounded audit per winning transition (audit ids are uuids, so order is by content)
    assert sorted(r[0] for r in rows) == sorted(
        [
            "enrollment.worker_bound",
            "enrollment.offer_recorded",
            "enrollment.result_recorded",
            "enrollment.verified",
            "enrollment.healthy",
        ]
    )
    for _action, data in rows:
        d = data if isinstance(data, dict) else _json.loads(data)
        assert set(d) == {"state", "revision"}  # bounded: only the resulting state + revision
        blob = _json.dumps(d)
        for secret in (WORKER_KEY, WORKER_HEX, OFFER_D, RESULT_D, RELEASE, CTRL_HEX, txn):
            assert secret not in blob  # never a key, digest, anchor or transaction id


def test_progression_rejects_raw_key_or_handoff_bytes(client, engine):
    eid, txn = _create(client)
    tok = _token(engine, eid)

    # extra="forbid": a caller cannot smuggle a private key or a raw handoff record through any step
    for extra in (
        {"private_key": "x"},
        {"handoff_record": "..."},
        {"worker_private_key_pem": "..."},
    ):
        body = {
            "worker_installation_id": WORKER_INSTALL,
            "worker_key_id": WORKER_KEY,
            "transaction_id": txn,
            "expected": tok,
            **extra,
        }
        assert client.post(f"/api/v1/enrollment/{eid}/bind", json=body).status_code == 422

    # a handoff step accepts ONLY an already-bound sha256 digest, never raw bytes / a bad value
    bad_offer = {
        "digest": "not-a-bound-digest",
        "transaction_id": txn,
        "signer_key_id": CTRL_KEY,
        "expected": tok,
    }
    assert client.post(f"/api/v1/enrollment/{eid}/offer", json=bad_offer).status_code == 422


def test_progression_stale_expected_token_conflicts(client, engine):
    eid, txn = _create(client)
    rev0 = _token(engine, eid)
    assert (
        client.post(f"/api/v1/enrollment/{eid}/bind", json=_bind_body(engine, eid, txn)).status_code
        == 200
    )

    # a FRESH step (no receipt) carrying the stale rev-0 token is a lost-update: bounded conflict
    r = client.post(
        f"/api/v1/enrollment/{eid}/offer",
        json={
            "digest": OFFER_D,
            "transaction_id": txn,
            "signer_key_id": CTRL_KEY,
            "expected": rev0,
        },
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "enrollment_revision_conflict"


def test_same_key_different_ttl_refuses_conflict(client):
    key = secrets.token_urlsafe(24)
    assert (
        client.post(
            "/api/v1/enrollment/invitations",
            json=_create_body(idempotency_key=key, ttl_seconds=3600),
        ).status_code
        == 201
    )
    r = client.post(
        "/api/v1/enrollment/invitations",
        json=_create_body(idempotency_key=key, ttl_seconds=7200),
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "enrollment_idempotency_conflict"


# --- revoke slice: POST /{enrollment_id}/revoke --------------------------------------------------


def _revoked_audits(session) -> int:
    from sqlalchemy import text

    return session.execute(
        text("SELECT count(*) FROM audit_event WHERE action='enrollment.revoked'")
    ).scalar_one()


def test_revoke_transitions_to_refused_and_audits_once(client, session):
    from sqlalchemy import text

    eid = client.post("/api/v1/enrollment/invitations", json=_create_body()).json()["enrollment_id"]
    r = client.post(f"/api/v1/enrollment/{eid}/revoke", json={"expected_revision": 0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "refused"
    # secret-free projection: fingerprints only, never the trust anchor / raw key material
    assert "controller_trust_anchor_hex" not in body and "invitation_id" not in body
    rows = session.execute(
        text("SELECT resource_id FROM audit_event WHERE action='enrollment.revoked'")
    ).all()
    assert len(rows) == 1 and rows[0][0] == eid


def test_revoke_is_idempotent_and_records_no_second_audit(client, session):
    eid = client.post("/api/v1/enrollment/invitations", json=_create_body()).json()["enrollment_id"]
    assert (
        client.post(f"/api/v1/enrollment/{eid}/revoke", json={"expected_revision": 0}).status_code
        == 200
    )
    # an exact retry stays refused and appends no second audit
    r2 = client.post(f"/api/v1/enrollment/{eid}/revoke", json={"expected_revision": 0})
    assert r2.status_code == 200 and r2.json()["state"] == "refused"
    assert _revoked_audits(session) == 1


def test_revoke_with_stale_revision_conflicts(client):
    eid = client.post("/api/v1/enrollment/invitations", json=_create_body()).json()["enrollment_id"]
    r = client.post(f"/api/v1/enrollment/{eid}/revoke", json={"expected_revision": 7})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "enrollment_revision_conflict"


def test_revoke_requires_manage_permission(client, principal):
    eid = client.post("/api/v1/enrollment/invitations", json=_create_body()).json()["enrollment_id"]
    _as(client, _principal(principal.organization_id, [Permission.enrollment_read]))
    r = client.post(f"/api/v1/enrollment/{eid}/revoke", json={"expected_revision": 0})
    assert r.status_code == 403


def test_revoke_cross_org_is_forbidden(client, session, other_org_principal):
    from secp_api.services import worker_enrollment as svc

    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-rev-cross",
        nonce="sha256:" + "d" * 64,
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
    r = client.post(
        f"/api/v1/enrollment/{seeded.state.enrollment_id}/revoke", json={"expected_revision": 0}
    )
    assert r.status_code == 403
