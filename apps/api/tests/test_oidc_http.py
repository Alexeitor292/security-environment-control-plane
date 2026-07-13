"""OIDC bearer HTTP integration tests (ADR-017 / OIDC-A).

Exercises REAL FastAPI routes + dependencies with only the verifier's network/time seam overridden
(never ``current_principal`` itself). Proves end-to-end: subject → DB identity, DB-owned
authorization, closed/redacted 401 + 503, WWW-Authenticate, dev-fallback precedence, no
domain mutation/audit on authentication, and that raw tokens never reach logs.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.config import Settings
from secp_api.deps import settings_dep
from secp_api.enums import Permission
from secp_api.models import AuditEvent, Role, User, UserRoleAssignment
from secp_api.oidc import get_oidc_verifier
from tests.oidc_helpers import (  # type: ignore
    FakeIdp,
    build_verifier,
    claims,
    gen_rsa,
    public_jwk,
    sign,
)

KID = "k1"


@pytest.fixture(scope="module")
def rsa_key():
    return gen_rsa()


@pytest.fixture
def idp(rsa_key):
    provider = FakeIdp()
    provider.set_keys(public_jwk(rsa_key, kid=KID))
    return provider


@pytest.fixture
def client(engine, principal, idp):
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    verifier = build_verifier(idp)
    app.dependency_overrides[get_oidc_verifier] = lambda: verifier
    return TestClient(app)


def _provision(session, *, org_id, subject, email, permissions):
    role = Role(name=f"role-{subject}", permissions=[p.value for p in permissions])
    session.add(role)
    session.flush()
    user = User(organization_id=org_id, email=email, display_name=subject, subject=subject)
    session.add(user)
    session.flush()
    session.add(UserRoleAssignment(organization_id=org_id, user_id=user.id, role_id=role.id))
    session.commit()
    return user


def _bearer(rsa_key, sub, **claim_kwargs):
    return {"Authorization": f"Bearer {sign(rsa_key, claims(sub=sub, **claim_kwargs), kid=KID)}"}


# --- valid token reaches a real route; identity/permissions come from the DB -------------------


def test_valid_token_reaches_me_with_db_identity(session, principal, rsa_key, client):
    alice = _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-alice",
        email="alice@dev.test",
        permissions={Permission.audit_read},
    )
    r = client.get("/api/v1/me", headers=_bearer(rsa_key, "oidc-alice"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == str(alice.id)
    assert body["organization_id"] == str(principal.organization_id)
    assert body["email"] == "alice@dev.test"
    assert body["permissions"] == ["audit:read"]
    assert body["is_dev_fallback"] is False


def test_token_roles_groups_email_org_claims_grant_nothing(session, principal, rsa_key, client):
    _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-bob",
        email="bob@dev.test",
        permissions={Permission.audit_read},
    )
    # A token stuffed with realm/client roles, groups, and a foreign organization claim.
    forged = {
        "realm_access": {"roles": ["platform-admin"]},
        "resource_access": {"secp-api": {"roles": ["approver"]}},
        "groups": ["/admins"],
        "organization_id": str(uuid.uuid4()),
        "org": "evil-corp",
        "preferred_username": "root",
        "email": "attacker@evil.test",
    }
    r = client.get("/api/v1/me", headers=_bearer(rsa_key, "oidc-bob", extra=forged))
    assert r.status_code == 200
    body = r.json()
    # organization + permissions + email are the DB values, never the token's.
    assert body["organization_id"] == str(principal.organization_id)
    assert body["permissions"] == ["audit:read"]
    assert body["email"] == "bob@dev.test"


def test_db_role_grants_permission_gated_route(session, principal, rsa_key, client):
    _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-auditor",
        email="auditor@dev.test",
        permissions={Permission.audit_read},
    )
    r = client.get("/api/v1/audit", headers=_bearer(rsa_key, "oidc-auditor"))
    assert r.status_code == 200


def test_authenticated_but_missing_permission_is_403(session, principal, rsa_key, client):
    # Zero-role user: authenticated, but no permissions -> normal 403 (NOT a 401).
    _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-noperm",
        email="noperm@dev.test",
        permissions=set(),
    )
    me = client.get("/api/v1/me", headers=_bearer(rsa_key, "oidc-noperm"))
    assert me.status_code == 200
    assert me.json()["permissions"] == []  # authenticated with NO permissions
    denied = client.get("/api/v1/audit", headers=_bearer(rsa_key, "oidc-noperm"))
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden"


def test_valid_token_cannot_access_foreign_organization(
    session, principal, rsa_key, client, running_exercise
):
    exercise = running_exercise()  # in the dev org
    # a fully-permissioned user in a DIFFERENT organization
    other_org = __import__("secp_api.models", fromlist=["Organization"]).Organization(
        name="Other OIDC Org", slug="other-oidc-org"
    )
    session.add(other_org)
    session.flush()
    _provision(
        session,
        org_id=other_org.id,
        subject="oidc-outsider",
        email="outsider@other.test",
        permissions=set(Permission),
    )
    session.commit()
    r = client.get(
        f"/api/v1/exercises/{exercise.id}/topology", headers=_bearer(rsa_key, "oidc-outsider")
    )
    assert r.status_code == 403  # cross-org denied by the normal org check, not authentication


# --- identity mapping is by exact subject only -------------------------------------------------


def test_email_only_and_username_only_matches_fail(session, principal, rsa_key, client):
    _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-exact",
        email="exact@dev.test",
        permissions={Permission.audit_read},
    )
    # sub == the user's EMAIL (not their subject) -> unauthenticated (no email linking).
    by_email = client.get("/api/v1/me", headers=_bearer(rsa_key, "exact@dev.test"))
    assert by_email.status_code == 401
    # sub == a username-ish value that is not the subject -> unauthenticated.
    by_username = client.get("/api/v1/me", headers=_bearer(rsa_key, "exact"))
    assert by_username.status_code == 401


def test_unknown_subject_is_unauthenticated_not_provisioned(rsa_key, client, session):
    before = session.query(User).count()
    r = client.get("/api/v1/me", headers=_bearer(rsa_key, "never-provisioned-subject"))
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthenticated"}}
    session.expire_all()
    assert session.query(User).count() == before  # a valid token for an unknown sub creates NO user


def test_duplicate_non_null_subjects_are_prevented_by_db(session, principal):
    from sqlalchemy.exc import IntegrityError

    session.add(
        User(
            organization_id=principal.organization_id,
            email="d1@dev.test",
            display_name="d1",
            subject="dup-subject",
        )
    )
    session.add(
        User(
            organization_id=principal.organization_id,
            email="d2@dev.test",
            display_name="d2",
            subject="dup-subject",
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


# --- closed / redacted 401 + 503 with WWW-Authenticate -----------------------------------------


def _assert_closed_401(r):
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthenticated"}}
    assert r.headers.get("WWW-Authenticate") == "Bearer"


def test_expired_token_is_closed_401(rsa_key, client):
    _assert_closed_401(
        client.get("/api/v1/me", headers=_bearer(rsa_key, "x", exp_delta=-100, iat_delta=-200))
    )


def test_forged_token_is_closed_401(rsa_key, client):
    attacker = gen_rsa()
    token = sign(attacker, claims(sub="x"), kid=KID)
    _assert_closed_401(client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}))


def test_wrong_audience_is_closed_401(rsa_key, client):
    _assert_closed_401(client.get("/api/v1/me", headers=_bearer(rsa_key, "x", aud="other-api")))


def test_provider_outage_is_closed_503(rsa_key, client, idp):
    idp.fail = True
    r = client.get("/api/v1/me", headers=_bearer(rsa_key, "oidc-alice"))
    assert r.status_code == 503
    assert r.json() == {"error": {"code": "authentication_unavailable"}}
    assert r.headers.get("WWW-Authenticate") == "Bearer"


def test_401_body_reveals_no_reason_token_or_claim(session, principal, rsa_key, client):
    _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-secretful",
        email="s@dev.test",
        permissions=set(),
    )
    secret_sub = "SENSITIVE-SUBJECT-XYZ"
    token = sign(rsa_key, claims(sub=secret_sub, aud="wrong-aud"), kid=KID)
    r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert r.json() == {"error": {"code": "unauthenticated"}}
    text = r.text
    for leaked in (secret_sub, token, "wrong-aud", "audience", "signature", "expired", "Traceback"):
        assert leaked not in text


# --- header parsing + dev-fallback precedence --------------------------------------------------


def test_no_header_uses_dev_fallback_when_enabled(client):
    r = client.get("/api/v1/me")
    assert r.status_code == 200
    assert r.json()["is_dev_fallback"] is True


def test_no_header_is_401_when_dev_fallback_disabled(client):
    client.app.dependency_overrides[settings_dep] = lambda: Settings(
        app_env="dev", auth_dev_mode=False
    )
    try:
        r = client.get("/api/v1/me")
        _assert_closed_401(r)
    finally:
        client.app.dependency_overrides.pop(settings_dep, None)


def test_invalid_bearer_never_falls_back_to_dev(rsa_key, client):
    # dev fallback IS enabled, but a malformed/invalid token must 401 — never dev-admin.
    r = client.get("/api/v1/me", headers={"Authorization": "Bearer not.a.jwt"})
    _assert_closed_401(r)


def test_basic_scheme_is_not_treated_as_absent(client):
    r = client.get("/api/v1/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    _assert_closed_401(r)  # a non-Bearer header is refused, NOT fallen back


def test_comma_combined_credentials_refused(rsa_key, client):
    token = sign(rsa_key, claims(sub="x"), kid=KID)
    r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}, Basic abc"})
    _assert_closed_401(r)


def test_empty_bearer_token_refused(client):
    _assert_closed_401(client.get("/api/v1/me", headers={"Authorization": "Bearer "}))


def test_bearer_scheme_is_case_insensitive(session, principal, rsa_key, client):
    _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-case",
        email="case@dev.test",
        permissions={Permission.audit_read},
    )
    token = sign(rsa_key, claims(sub="oidc-case"), kid=KID)
    r = client.get("/api/v1/me", headers={"Authorization": f"bearer {token}"})
    assert r.status_code == 200


# --- authentication is side-effect free; logs never contain the token --------------------------


def test_authentication_performs_no_mutation_or_audit(session, principal, rsa_key, client):
    _provision(
        session,
        org_id=principal.organization_id,
        subject="oidc-quiet",
        email="quiet@dev.test",
        permissions={Permission.audit_read},
    )
    session.expire_all()
    audits_before = session.query(AuditEvent).count()
    users_before = session.query(User).count()
    for _ in range(3):
        assert client.get("/api/v1/me", headers=_bearer(rsa_key, "oidc-quiet")).status_code == 200
    session.expire_all()
    assert session.query(AuditEvent).count() == audits_before
    assert session.query(User).count() == users_before


def test_raw_token_never_appears_in_logs(rsa_key, client):
    # Attach a dedicated handler to the auth logger (robust to alembic's fileConfig, which disables
    # existing loggers when a migration test runs earlier in the session).
    import io

    logger = logging.getLogger("secp.api")
    logger.disabled = False
    old_level = logger.level
    logger.setLevel(logging.INFO)
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    token = sign(rsa_key, claims(sub="never-provisioned"), kid=KID)
    try:
        client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
    log_text = buffer.getvalue()
    assert token not in log_text
    assert "never-provisioned" not in log_text
    assert "authentication refused" in log_text  # a bounded category IS logged


# --- OpenAPI security scheme -------------------------------------------------------------------


def test_openapi_advertises_bearer_and_keeps_health_public(client):
    schema = client.app.openapi()
    schemes = schema["components"]["securitySchemes"]
    assert schemes == {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer",
            "description": "OIDC access token (ADR-017)",
        }
    }
    paths = schema["paths"]
    assert paths["/health"]["get"].get("security") is None  # health stays public
    assert paths["/api/v1/me"]["get"]["security"] == [{"HTTPBearer": []}]
    # no password/implicit/token-endpoint flow and no client secret leak anywhere in the schema.
    blob = str(schema).lower()
    for forbidden in (
        "password",
        "implicit",
        "clientsecret",
        "client_secret",
        "tokenurl",
        "oauth2",
    ):
        assert forbidden not in blob
