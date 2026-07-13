"""Public browser auth-config endpoint tests (ADR-018 / OIDC-B).

``GET /api/v1/auth/config`` is public, secret-free, network-free, and side-effect-free; ``mode`` is
server-derived (production can never silently become dev-fallback); and it exposes exactly the
non-secret values the public browser client needs. The endpoint never weakens the OIDC-A boundary:
every other protected route stays protected and health stays public.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from secp_api.config import Settings
from secp_api.deps import settings_dep
from secp_api.models import AuditEvent

_SECRET_TOKENS = ("secret", "password", "token", "private", "certificate", "credential")
_FIXED_SCOPE = "openid profile email"


@pytest.fixture
def client(engine, principal):
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    return TestClient(app)


def _override(client, settings: Settings) -> None:
    client.app.dependency_overrides[settings_dep] = lambda: settings


_OIDC_PROD = dict(
    app_env="production",
    auth_dev_mode=False,
    workflow_dispatch_mode="temporal",
    oidc_issuer="https://idp.example.test/realms/secp",
    oidc_audience="secp-api",
    oidc_web_client_id="secp-web",
    # OIDC-C (ADR-019): safe same-origin production config.
    public_origin="https://secp.example.test",
    cors_allow_origins=[],
)


# --- public, no auth required ------------------------------------------------------------------


def test_auth_config_is_public_no_authorization_needed(client):
    r = client.get("/api/v1/auth/config")
    assert r.status_code == 200, r.text
    # no Authorization header was sent, and none is demanded.
    assert "WWW-Authenticate" not in r.headers


def test_auth_config_shape_and_fixed_values(client):
    body = client.get("/api/v1/auth/config").json()
    assert set(body) == {
        "mode",
        "issuer",
        "client_id",
        "audience",
        "scope",
        "redirect_path",
        "post_logout_redirect_path",
    }
    assert body["scope"] == _FIXED_SCOPE
    assert "offline_access" not in body["scope"]
    assert body["redirect_path"] == "/auth/callback"
    assert body["post_logout_redirect_path"] == "/login"


# --- mode is server-derived --------------------------------------------------------------------


def test_dev_fallback_mode_when_dev_auth_enabled(client):
    _override(client, Settings(app_env="dev", auth_dev_mode=True, workflow_dispatch_mode="inline"))
    body = client.get("/api/v1/auth/config").json()
    assert body["mode"] == "dev_fallback"


def test_oidc_mode_when_dev_auth_disabled(client):
    _override(
        client,
        Settings(
            app_env="dev",
            auth_dev_mode=False,
            oidc_issuer="https://idp.example.test/realms/secp",
            oidc_audience="secp-api",
            oidc_web_client_id="secp-web",
        ),
    )
    body = client.get("/api/v1/auth/config").json()
    assert body["mode"] == "oidc"
    assert body["issuer"] == "https://idp.example.test/realms/secp"
    assert body["audience"] == "secp-api"
    assert body["client_id"] == "secp-web"


def test_production_always_reports_oidc_mode(client):
    _override(client, Settings(**_OIDC_PROD))
    body = client.get("/api/v1/auth/config").json()
    assert body["mode"] == "oidc"  # production can never be dev_fallback


# --- no secret / credential in the response ----------------------------------------------------


def test_response_contains_no_secret_or_credential(client):
    text = client.get("/api/v1/auth/config").text.lower()
    for token in _SECRET_TOKENS:
        assert token not in text


# --- no network, no mutation, no audit ---------------------------------------------------------


def test_endpoint_makes_no_network_request(client, monkeypatch):
    import httpx

    def _boom(*a, **k):
        raise AssertionError("auth/config must not open an HTTP client (no discovery/JWKS)")

    monkeypatch.setattr(httpx.Client, "__init__", _boom)
    assert client.get("/api/v1/auth/config").status_code == 200


def test_endpoint_performs_no_mutation_or_audit(client, session):
    session.expire_all()
    before = session.query(AuditEvent).count()
    for _ in range(3):
        assert client.get("/api/v1/auth/config").status_code == 200
    session.expire_all()
    assert session.query(AuditEvent).count() == before


# --- the endpoint does not weaken the rest of the API ------------------------------------------


def test_health_stays_public(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_protected_route_still_requires_auth_when_no_fallback(client):
    _override(client, Settings(app_env="dev", auth_dev_mode=False))
    r = client.get("/api/v1/me")
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthenticated"}}


def test_openapi_marks_auth_config_public(client):
    schema = client.app.openapi()
    assert schema["paths"]["/api/v1/auth/config"]["get"].get("security") is None
    assert schema["paths"]["/api/v1/me"]["get"]["security"] == [{"HTTPBearer": []}]
    assert "client_secret" not in str(schema).lower()


# --- Settings: bounded, non-secret public web client id ----------------------------------------


def test_web_client_id_default_is_secp_web():
    assert Settings(app_env="dev").oidc_web_client_id == "secp-web"


def test_production_requires_non_empty_web_client_id():
    with pytest.raises(ValidationError):
        Settings(**{**_OIDC_PROD, "oidc_web_client_id": "   "})


def test_web_client_id_is_length_bounded():
    with pytest.raises(ValidationError):
        Settings(app_env="dev", oidc_web_client_id="x" * 500)


def test_web_client_id_is_not_a_secret_field():
    # It carries no "secret"/"password" naming and has a non-empty public default.
    field = Settings.model_fields["oidc_web_client_id"]
    assert "secret" not in "oidc_web_client_id"
    assert field.default == "secp-web"
