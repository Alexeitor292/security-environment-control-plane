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
    # migrations would). ``e3b7a9c25f41`` is the current sole head (SECP-M1).
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


# --- SEALED claim-only progression steps: bind / offer / result / verify / healthy over HTTP ------
#
# T1: the public boundary carries ONLY ``expected_revision`` (the small integer every response
# already returns) — the durable CAS state_digest / sequence / predecessor are derived server-side.
# A real worker/CLI/UI therefore drives the whole lifecycle from supported HTTP responses alone; NO
# test helper below reads the database to CONSTRUCT a request (only verification reads do). The
# routes are SEALED by default and enabled here via a deployment-local dev/test settings profile.

WORKER_HEX = (b"\x22" * 32).hex()
WORKER_KEY = sha256_digest_of_hex(WORKER_HEX)
OFFER_D = "sha256:" + "c" * 64
RESULT_D = "sha256:" + "d" * 64
WORKER_INSTALL = "worker-bbbbbbbb"


def _enable_progression(client: TestClient) -> TestClient:
    """Enable the sealed progression routes via the deployment-local dev/test profile."""
    from secp_api.config import Settings
    from secp_api.deps import settings_dep

    client.app.dependency_overrides[settings_dep] = lambda: Settings(
        app_env="dev", enable_enrollment_progression=True
    )
    return client


@pytest.fixture
def pclient(client):
    """A client with the sealed progression profile enabled (default ``client`` keeps it sealed)."""
    return _enable_progression(client)


def _db(engine):
    # VERIFICATION-only fresh session (never used to build a request) — asserts durable invariants
    from sqlalchemy.orm import Session

    return Session(engine)


def _create(client, **over) -> tuple[str, str, int]:
    # (enrollment_id, transaction_id, revision) from the create RESPONSE — the worker echoes the
    # invitation's server-issued transaction id and drives from the response revision, not the DB
    out = client.post("/api/v1/enrollment/invitations", json=_create_body(**over)).json()
    return out["enrollment_id"], out["transaction_id"], out["revision"]


def _bind(client, eid, txn, expected_revision, **over):
    body = {
        "worker_installation_id": WORKER_INSTALL,
        "worker_key_id": WORKER_KEY,
        "transaction_id": txn,
        "expected_revision": expected_revision,
    }
    body.update(over)
    return client.post(f"/api/v1/enrollment/{eid}/bind", json=body)


def _offer(client, eid, txn, expected_revision, *, digest=OFFER_D, signer=CTRL_KEY):
    return client.post(
        f"/api/v1/enrollment/{eid}/offer",
        json={
            "digest": digest,
            "transaction_id": txn,
            "signer_key_id": signer,
            "expected_revision": expected_revision,
        },
    )


def _result(client, eid, txn, expected_revision):
    return client.post(
        f"/api/v1/enrollment/{eid}/result",
        json={
            "digest": RESULT_D,
            "transaction_id": txn,
            "signer_key_id": WORKER_KEY,
            "expected_revision": expected_revision,
        },
    )


def _verify(client, eid, expected_revision):
    return client.post(
        f"/api/v1/enrollment/{eid}/verify",
        json={"release_digest": RELEASE, "expected_revision": expected_revision},
    )


def _healthy(client, eid, expected_revision):
    return client.post(
        f"/api/v1/enrollment/{eid}/healthy", json={"expected_revision": expected_revision}
    )


def _drive_to_healthy(client, eid, txn) -> None:
    # each next expected_revision comes from the PRIOR response — never the database
    r = _bind(client, eid, txn, 0)
    assert r.status_code == 200, r.text
    r = _offer(client, eid, txn, r.json()["revision"])
    assert r.status_code == 200, r.text
    r = _result(client, eid, txn, r.json()["revision"])
    assert r.status_code == 200, r.text
    r = _verify(client, eid, r.json()["revision"])
    assert r.status_code == 200, r.text
    r = _healthy(client, eid, r.json()["revision"])
    assert r.status_code == 200, r.text


# --- seal ----------------------------------------------------------------------------------------


def test_progression_is_sealed_by_default(client):
    # default profile: the claim-only routes are NOT a supported trusted exchange
    eid, txn, rev = _create(client)
    r = _bind(client, eid, txn, rev)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "enrollment_progression_sealed"


def test_production_refuses_the_progression_flag():
    import pytest as _pytest
    from secp_api.config import Settings

    with _pytest.raises(ValueError, match="ENABLE_ENROLLMENT_PROGRESSION"):
        Settings(
            app_env="production",
            auth_dev_mode=False,
            workflow_dispatch_mode="temporal",
            enable_enrollment_progression=True,
            oidc_issuer="https://issuer.example.com",
            oidc_audience="secp",
            public_origin="https://app.example.com",
        )


# --- T1: public contract carries only expected_revision ------------------------------------------


def test_public_progression_schemas_expose_no_internal_cas_fields():
    # a customer/worker/UI must never compute/store/manage the durable CAS coordinates
    from secp_api import schemas_enrollment as s

    forbidden = {"state_digest", "sequence", "predecessor_digest"}
    for model in (
        s.BindWorkerRequest,
        s.RecordHandoffRequest,
        s.VerifyReleaseRequest,
        s.MarkHealthyRequest,
    ):
        fields = set(model.model_fields)
        assert not (fields & forbidden), (model.__name__, fields)
        assert "expected_revision" in fields, model.__name__
    assert not hasattr(s, "ExpectedToken")  # the internal-coordinate request type is gone


def test_progression_full_lifecycle_over_http_without_database_reads(pclient):
    # drives bind->healthy using ONLY supported HTTP responses (this test imports no repository)
    eid, txn, rev = _create(pclient)
    assert rev == 0

    b = _bind(pclient, eid, txn, rev)
    assert b.status_code == 200, b.text
    assert b.json()["state"] == "worker_bound" and b.json()["revision"] == 1
    assert b.json()["worker_installation_id"] == WORKER_INSTALL
    assert "controller_trust_anchor_hex" not in b.json()  # projection stays secret-free

    o = _offer(pclient, eid, txn, b.json()["revision"])
    assert o.status_code == 200 and o.json()["state"] == "offer_transported"
    assert o.json()["revision"] == 2

    r = _result(pclient, eid, txn, o.json()["revision"])
    assert r.status_code == 200 and r.json()["state"] == "result_transported"
    assert r.json()["revision"] == 3

    v = _verify(pclient, eid, r.json()["revision"])
    assert v.status_code == 200 and v.json()["state"] == "verified" and v.json()["revision"] == 4

    h = _healthy(pclient, eid, v.json()["revision"])
    assert h.status_code == 200 and h.json()["state"] == "healthy" and h.json()["revision"] == 5


def test_progression_stale_expected_revision_conflicts(pclient):
    eid, txn, rev = _create(pclient)
    assert _bind(pclient, eid, txn, rev).status_code == 200  # head advances to revision 1
    # a FRESH step (no receipt) with the stale rev-0 value is a lost update: bounded conflict
    r = _offer(pclient, eid, txn, 0)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "enrollment_revision_conflict"


def test_internal_repository_cas_still_uses_revision_and_state_digest(pclient, engine):
    # T1 removed the CAS coordinates from the PUBLIC boundary, not from persistence: the durable
    # step receipt still records (resulting_revision, resulting_state_digest), and the head/history
    # rows carry the state_digest the repository compare-and-swaps on.
    from sqlalchemy import text

    eid, txn, rev = _create(pclient)
    assert _bind(pclient, eid, txn, rev).status_code == 200
    with _db(engine) as s:
        receipt = s.execute(
            text(
                "SELECT resulting_revision, resulting_state_digest FROM"
                " worker_enrollment_step_receipt"
                " WHERE enrollment_id=:e AND step='bind_worker_identity'"
            ),
            {"e": eid},
        ).one()
        head_digest = s.execute(
            text("SELECT state_digest FROM worker_enrollment_state WHERE enrollment_id=:e"),
            {"e": eid},
        ).scalar_one()
        hist_digest = s.execute(
            text(
                "SELECT state_digest FROM worker_enrollment_revision"
                " WHERE enrollment_id=:e AND revision=1"
            ),
            {"e": eid},
        ).scalar_one()
    assert receipt.resulting_revision == 1
    assert receipt.resulting_state_digest.startswith("sha256:")
    assert receipt.resulting_state_digest == head_digest == hist_digest


# --- RBAC + organization boundary ----------------------------------------------------------------


def test_progression_requires_the_enrollment_progress_permission(pclient, principal):
    eid, txn, rev = _create(pclient)
    org = principal.organization_id

    # read + manage but NOT progress: strictly separated, so progression is forbidden
    _as(pclient, _principal(org, [Permission.enrollment_read, Permission.enrollment_manage]))
    assert _bind(pclient, eid, txn, rev).status_code == 403

    # the dedicated progress permission authorizes it (same org, still revision 0)
    _as(pclient, _principal(org, [Permission.enrollment_progress]))
    ok = _bind(pclient, eid, txn, rev)
    assert ok.status_code == 200, ok.text
    assert ok.json()["revision"] == 1


def test_progression_is_organization_scoped(pclient, session, other_org_principal):
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
    # the dev principal (a DIFFERENT org) is refused on the org boundary before any CAS logic
    r = _bind(pclient, eid, "txn-prog-cross", 0)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "enrollment_forbidden"


# --- receipt-first exact retry + T3 delayed-retry returns the ORIGINAL step result ----------------


def test_exact_retry_with_the_original_expected_revision_succeeds(pclient, engine):
    from sqlalchemy import text

    eid, txn, rev = _create(pclient)
    a = _bind(pclient, eid, txn, rev)
    assert a.status_code == 200 and a.json()["revision"] == 1
    # replay the SAME request carrying the ORIGINAL (now-stale) expected_revision: the step receipt
    # short-circuits it to the identical result — never a second advance or a conflict
    b = _bind(pclient, eid, txn, rev)
    assert b.status_code == 200
    assert b.json() == a.json()
    with _db(engine) as s:
        audits = s.execute(
            text(
                "SELECT count(*) FROM audit_event"
                " WHERE action='enrollment.worker_bound' AND resource_id=:e"
            ),
            {"e": eid},
        ).scalar_one()
        revs = s.execute(
            text("SELECT count(*) FROM worker_enrollment_revision WHERE enrollment_id=:e"),
            {"e": eid},
        ).scalar_one()
        receipts = s.execute(
            text("SELECT count(*) FROM worker_enrollment_step_receipt WHERE enrollment_id=:e"),
            {"e": eid},
        ).scalar_one()
    assert audits == 1  # exactly one winning-transition audit; the dedup path records none
    assert revs == 2  # rev 0 (invited) + rev 1 (worker_bound); no second history row
    assert receipts == 1  # one bind receipt


def test_bind_retry_after_healthy_returns_the_original_worker_bound_result(pclient):
    eid, txn, rev = _create(pclient)
    original = _bind(pclient, eid, txn, rev).json()
    assert original["state"] == "worker_bound" and original["revision"] == 1
    # advance the enrollment all the way to healthy...
    o = _offer(pclient, eid, txn, 1)
    _result(pclient, eid, txn, o.json()["revision"])
    v = _verify(pclient, eid, 3)
    _healthy(pclient, eid, v.json()["revision"])
    # ...a delayed bind retry STILL returns the ORIGINAL worker_bound result, not the healthy head
    replay = _bind(pclient, eid, txn, rev)
    assert replay.status_code == 200
    assert replay.json() == original
    assert replay.json()["state"] == "worker_bound" and replay.json()["revision"] == 1


def test_offer_retry_after_healthy_returns_the_original_offer_transported_result(pclient):
    eid, txn, _ = _create(pclient)
    _bind(pclient, eid, txn, 0)
    original = _offer(pclient, eid, txn, 1).json()
    assert original["state"] == "offer_transported" and original["revision"] == 2
    _result(pclient, eid, txn, 2)
    _verify(pclient, eid, 3)
    _healthy(pclient, eid, 4)
    replay = _offer(pclient, eid, txn, 1)
    assert replay.status_code == 200 and replay.json() == original


def test_result_retry_after_verification_returns_the_original_result_transported_result(pclient):
    eid, txn, _ = _create(pclient)
    _bind(pclient, eid, txn, 0)
    _offer(pclient, eid, txn, 1)
    original = _result(pclient, eid, txn, 2).json()
    assert original["state"] == "result_transported" and original["revision"] == 3
    _verify(pclient, eid, 3)
    _healthy(pclient, eid, 4)
    replay = _result(pclient, eid, txn, 2)
    assert replay.status_code == 200 and replay.json() == original


def test_retry_after_revocation_returns_the_original_step_result(pclient):
    eid, txn, _ = _create(pclient)
    original = _bind(pclient, eid, txn, 0).json()
    # revoke the enrollment (drives it to the refused terminal at a later revision)
    assert (
        pclient.post(f"/api/v1/enrollment/{eid}/revoke", json={"expected_revision": 1}).status_code
        == 200
    )
    replay = _bind(pclient, eid, txn, 0)
    assert replay.status_code == 200
    assert replay.json() == original
    assert replay.json()["state"] == "worker_bound"


def test_retry_after_restart_returns_the_same_original_result(pclient, engine, principal):
    eid, txn, _ = _create(pclient)
    original = _bind(pclient, eid, txn, 0).json()
    _drive_to_healthy_from(pclient, eid, txn, start_rev=1)
    # simulate a full process restart: a brand-new app + client over the SAME persisted database
    from secp_api.deps import current_principal
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    restarted = TestClient(app)
    restarted.app.dependency_overrides[current_principal] = lambda: principal
    _enable_progression(restarted)
    replay = _bind(restarted, eid, txn, 0)
    assert replay.status_code == 200
    assert replay.json() == original


def _drive_to_healthy_from(client, eid, txn, *, start_rev):
    # offer..healthy after a bind already committed at start_rev
    o = _offer(client, eid, txn, start_rev)
    assert o.status_code == 200, o.text
    r = _result(client, eid, txn, o.json()["revision"])
    assert r.status_code == 200, r.text
    v = _verify(client, eid, r.json()["revision"])
    assert v.status_code == 200, v.text
    assert _healthy(client, eid, v.json()["revision"]).status_code == 200


def test_corrupt_historical_snapshot_refuses_closed(pclient, engine):
    from sqlalchemy import text

    eid, txn, _ = _create(pclient)
    _bind(pclient, eid, txn, 0)
    _offer(pclient, eid, txn, 1)  # advance so the bind retry cannot be an at-target no-op
    # tamper the immutable revision-1 snapshot so its rehydrated digest no longer matches
    with _db(engine) as s:
        s.execute(
            text(
                "UPDATE worker_enrollment_revision SET state_snapshot='{\"tampered\": true}'"
                " WHERE enrollment_id=:e AND revision=1"
            ),
            {"e": eid},
        )
        s.commit()
    replay = _bind(pclient, eid, txn, 0)
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "enrollment_state_corrupt"


# --- bounded secret-free audit + no raw key/handoff bytes -----------------------------------------


def test_progression_audit_is_bounded_and_secret_free(pclient, engine):
    import json as _json

    from sqlalchemy import text

    eid, txn, _ = _create(pclient)
    _drive_to_healthy(pclient, eid, txn)

    with _db(engine) as s:
        rows = s.execute(
            text(
                "SELECT action, data FROM audit_event WHERE resource_id=:e"
                " AND action LIKE 'enrollment.%' AND action <> 'enrollment.invitation_created'"
            ),
            {"e": eid},
        ).all()

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


def test_progression_rejects_raw_key_or_handoff_bytes(pclient):
    eid, txn, rev = _create(pclient)

    # extra="forbid": a caller cannot smuggle a private key or a raw handoff record through any step
    for extra in (
        {"private_key": "x"},
        {"handoff_record": "..."},
        {"worker_private_key_pem": "..."},
    ):
        assert _bind(pclient, eid, txn, rev, **extra).status_code == 422

    # a handoff step accepts ONLY an already-bound sha256 digest, never raw bytes / a bad value
    assert _offer(pclient, eid, txn, rev, digest="not-a-bound-digest").status_code == 422


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
