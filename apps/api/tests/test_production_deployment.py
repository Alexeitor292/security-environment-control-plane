"""Production deployment guardrails: public origin, CORS, and Host validation (ADR-019 / OIDC-C).

These prove the same-origin production model: the canonical public origin is a validated exact HTTPS
origin; CORS is disabled in production and, in development, allows only the exact configured origin
without credentials or wildcards; and the production Host allowlist accepts only the canonical (and
optional internal health) host, failing closed on anything else — with no ``/health`` bypass.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from secp_api.config import Settings

_PROD = dict(
    app_env="production",
    auth_dev_mode=False,
    workflow_dispatch_mode="temporal",
    oidc_issuer="https://idp.example.test/realms/secp",
    oidc_audience="secp-api",
    oidc_web_client_id="secp-web",
    public_origin="https://secp.example.test",
    cors_allow_origins=[],
)


def _prod(**overrides) -> Settings:
    return Settings(**{**_PROD, **overrides})


def _app(monkeypatch, settings: Settings):
    import secp_api.main as main_mod

    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)
    app = main_mod.create_app()
    app.router.on_startup.clear()  # no dev seed / DB in these middleware tests
    return app


# --- public origin validation -------------------------------------------------------------------


def test_valid_production_public_origin_is_accepted():
    s = _prod()
    assert s.public_origin_canonical == "https://secp.example.test"
    assert s.public_origin_host == "secp.example.test"
    assert s.oidc_callback_url == "https://secp.example.test/auth/callback"
    assert s.oidc_logout_url == "https://secp.example.test/login"


def test_public_origin_with_explicit_port_is_canonicalized():
    s = _prod(public_origin="https://secp.example.test:8443/")
    assert s.public_origin_canonical == "https://secp.example.test:8443"
    assert s.public_origin_host == "secp.example.test"  # host allowlist drops the port


@pytest.mark.parametrize(
    "origin",
    [
        "http://secp.example.test",  # not https
        "https://user:pass@secp.example.test",  # userinfo
        "https://secp.example.test/app",  # path
        "https://secp.example.test/?x=1",  # query
        "https://secp.example.test/#f",  # fragment
        "https://*.secp.example.test",  # wildcard
        "//secp.example.test",  # protocol-relative
        "",  # empty
        "https://",  # no host
    ],
)
def test_production_rejects_unsafe_public_origin(origin):
    with pytest.raises(ValidationError):
        _prod(public_origin=origin)


@pytest.mark.parametrize(
    "origin",
    [
        "https://localhost",
        "https://LOCALHOST",  # case-insensitive
        "https://app.localhost",  # any *.localhost
        "https://127.0.0.1",  # IPv4 loopback
        "https://127.10.20.30",  # anywhere in 127.0.0.0/8
        "https://[::1]",  # compressed IPv6 loopback
        "https://[0:0:0:0:0:0:0:1]",  # expanded IPv6 loopback
        "https://[::ffff:127.0.0.1]",  # IPv4-mapped IPv6 loopback
        "https://secp.example.com.",  # trailing-dot host (never silently canonicalized)
        "https://[::g]",  # malformed bracketed IPv6
    ],
)
def test_production_rejects_loopback_and_ambiguous_public_origin(origin):
    with pytest.raises(ValidationError):
        _prod(public_origin=origin)


def test_production_accepts_normal_dns_origin():
    # A normal canonical HTTPS DNS origin — including an ordinary private-enterprise DNS name that
    # might resolve internally — still passes (no DNS resolution is performed).
    assert (
        _prod(public_origin="https://secp.example.test").public_origin_host == "secp.example.test"
    )
    assert (
        _prod(public_origin="https://secp.internal.corp").public_origin_host == "secp.internal.corp"
    )


def test_production_requires_empty_cors():
    with pytest.raises(ValidationError):
        _prod(cors_allow_origins=["https://secp.example.test"])


def test_cors_wildcard_is_rejected_in_every_environment():
    with pytest.raises(ValidationError):
        Settings(app_env="dev", cors_allow_origins=["*"])


@pytest.mark.parametrize(
    "origin",
    [
        "//evil.test",
        "https://evil.test/path",
        "ftp://evil.test",
        "https://user:p@evil.test",
        "https://*.evil.test",  # wildcard anywhere in an origin is refused
    ],
)
def test_malformed_cors_origin_is_rejected(origin):
    with pytest.raises(ValidationError):
        Settings(app_env="dev", cors_allow_origins=[origin])


def test_internal_health_host_must_be_bare_hostname():
    with pytest.raises(ValidationError):
        _prod(internal_health_host="https://health.internal")
    with pytest.raises(ValidationError):
        _prod(internal_health_host="*")


# --- CORS behavior (development) -----------------------------------------------------------------


def test_dev_cors_allows_exact_origin_without_credentials(monkeypatch):
    app = _app(monkeypatch, Settings(app_env="dev", cors_allow_origins=["http://localhost:5173"]))
    client = TestClient(app)
    r = client.options(
        "/api/v1/me",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
    # No credentials, no wildcard methods/headers, explicit Authorization + Content-Type allowed.
    assert "access-control-allow-credentials" not in {k.lower() for k in r.headers}
    methods = r.headers.get("access-control-allow-methods", "")
    assert "*" not in methods and "GET" in methods and "POST" in methods
    allow_headers = r.headers.get("access-control-allow-headers", "").lower()
    assert "*" not in allow_headers
    assert "authorization" in allow_headers and "content-type" in allow_headers


def test_dev_cors_denies_untrusted_origin(monkeypatch):
    app = _app(monkeypatch, Settings(app_env="dev", cors_allow_origins=["http://localhost:5173"]))
    client = TestClient(app)
    r = client.get("/health", headers={"Origin": "http://evil.test"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


# --- CORS behavior (production: same-origin, no CORS) --------------------------------------------


def test_production_has_no_cors_and_ignores_untrusted_origin(monkeypatch):
    app = _app(monkeypatch, _prod())
    client = TestClient(app)
    # A same-origin request works; no CORS authorization is granted to any cross origin.
    r = client.get(
        "/health",
        headers={"host": "secp.example.test", "Origin": "https://evil.test"},
    )
    assert r.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


# --- Host validation (production) ---------------------------------------------------------------


def test_production_accepts_canonical_host(monkeypatch):
    app = _app(monkeypatch, _prod())
    client = TestClient(app)
    r = client.get("/health", headers={"host": "secp.example.test"})
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_production_refuses_unknown_host(monkeypatch):
    app = _app(monkeypatch, _prod())
    client = TestClient(app)
    r = client.get("/health", headers={"host": "attacker.example"})
    assert r.status_code == 400  # fails closed


def test_health_does_not_bypass_host_validation(monkeypatch):
    """/health is subject to the SAME Host allowlist — it is not a special-cased exception."""
    app = _app(monkeypatch, _prod())
    client = TestClient(app)
    assert client.get("/health", headers={"host": "secp.example.test"}).status_code == 200
    assert client.get("/health", headers={"host": "spoofed.test"}).status_code == 400


def test_production_accepts_optional_internal_health_host(monkeypatch):
    app = _app(monkeypatch, _prod(internal_health_host="secp-api.internal"))
    client = TestClient(app)
    assert client.get("/health", headers={"host": "secp.example.test"}).status_code == 200
    assert client.get("/health", headers={"host": "secp-api.internal"}).status_code == 200
    assert client.get("/health", headers={"host": "other.internal"}).status_code == 400


def test_development_has_no_host_restriction(monkeypatch):
    app = _app(monkeypatch, Settings(app_env="dev", cors_allow_origins=["http://localhost:5173"]))
    client = TestClient(app)
    # Any Host is accepted in development (convenient + deterministic); trusted_hosts() is None.
    assert client.get("/health", headers={"host": "anything.local"}).status_code == 200


def test_trusted_hosts_never_contains_wildcard():
    assert "*" not in _prod().trusted_hosts()
    assert Settings(app_env="dev").trusted_hosts() is None


# --- the backend never builds callback URLs from the Host header --------------------------------


def test_auth_config_returns_relative_paths_regardless_of_host(monkeypatch):
    app = _app(monkeypatch, _prod())
    client = TestClient(app)
    body = client.get("/api/v1/auth/config", headers={"host": "secp.example.test"}).json()
    # The browser derives callback/logout URLs from its OWN origin; the backend returns only fixed
    # relative paths and never an absolute URL built from the (attacker-controllable) Host header.
    assert body["redirect_path"] == "/auth/callback"
    assert body["post_logout_redirect_path"] == "/login"
    # The callback/logout paths are RELATIVE (no scheme/host) so the browser derives absolute URLs
    # from its own origin, never from a backend Host header.
    assert "http" not in body["redirect_path"]
    assert "http" not in body["post_logout_redirect_path"]
    # The (attacker-controllable) Host header never leaks into any returned value.
    for value in body.values():
        assert "secp.example.test" not in str(value)
