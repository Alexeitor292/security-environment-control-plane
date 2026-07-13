"""Token-free OIDC deployment preflight tests (ADR-019 / OIDC-C).

Everything runs against generated ephemeral RSA keys and an injected ``httpx.MockTransport`` fake
IdP (``oidc_helpers``) — no public internet. The preflight must never obtain a token, never touch
the database or audit log, and never print a discovery body, JWK material, or a token-shaped value.
"""

from __future__ import annotations

import json

import httpx
from secp_api.config import Settings
from secp_api.oidc_preflight import (
    EXIT_CONFIG_INVALID,
    EXIT_OK,
    EXIT_PROVIDER_METADATA_INVALID,
    EXIT_PROVIDER_UNAVAILABLE,
    PreflightReport,
    run_preflight,
)
from tests.oidc_helpers import ISSUER, JWKS_URI, FakeIdp, gen_rsa, public_jwk  # type: ignore

_AUTH_EP = "https://issuer.test/realms/secp/protocol/openid-connect/auth"
_TOKEN_EP = "https://issuer.test/realms/secp/protocol/openid-connect/token"
_LOGOUT_EP = "https://issuer.test/realms/secp/protocol/openid-connect/logout"


def _full_discovery(**overrides) -> dict:
    doc = {
        "issuer": ISSUER,
        "jwks_uri": JWKS_URI,
        "authorization_endpoint": _AUTH_EP,
        "token_endpoint": _TOKEN_EP,
        "end_session_endpoint": _LOGOUT_EP,
        "code_challenge_methods_supported": ["S256"],
    }
    doc.update(overrides)
    return doc


def _idp(*, keys: list[dict] | None = None, **discovery_overrides) -> FakeIdp:
    idp = FakeIdp()
    idp.discovery = _full_discovery(**discovery_overrides)
    if keys is None:
        keys = [public_jwk(gen_rsa(), kid="k1")]
    idp.set_keys(*keys)
    return idp


def _factory(idp: FakeIdp):
    transport = idp.transport()

    def make() -> httpx.Client:
        # Mirror the production posture: no redirects, no ambient proxy/env.
        return httpx.Client(
            transport=transport, follow_redirects=False, trust_env=False, timeout=5.0
        )

    return make


def _prod_settings(**overrides) -> Settings:
    base = dict(
        app_env="production",
        auth_dev_mode=False,
        workflow_dispatch_mode="temporal",
        oidc_issuer=ISSUER,
        oidc_audience="secp-api",
        public_origin="https://secp.example.test",
        cors_allow_origins=[],
    )
    base.update(overrides)
    return Settings(**base)


def _run(idp: FakeIdp, settings: Settings | None = None) -> PreflightReport:
    return run_preflight(settings or _prod_settings(), client_factory=_factory(idp))


# --- happy path ---------------------------------------------------------------------------------


def test_valid_production_configuration_passes():
    report = _run(_idp())
    assert report.category == "ok"
    assert report.exit_code == EXIT_OK
    assert report.usable_rsa_keys == 1
    assert report.s256_advertised is True
    assert report.issuer_host == "issuer.test"
    # callback/logout URLs are derived from OUR public origin (never from the provider).
    assert report.callback_url == "https://secp.example.test/auth/callback"
    assert report.logout_url == "https://secp.example.test/login"


def test_exact_issuer_agreement_is_required():
    report = _run(_idp(issuer="https://evil.test/realms/secp"))
    assert report.category == "provider_metadata_invalid"
    assert report.exit_code == EXIT_PROVIDER_METADATA_INVALID


def test_https_endpoint_validation_in_production():
    report = _run(_idp(token_endpoint="http://issuer.test/realms/secp/token"))
    assert report.category == "provider_metadata_invalid"


def test_userinfo_in_endpoint_is_refused():
    report = _run(_idp(authorization_endpoint="https://user:pass@issuer.test/auth"))
    assert report.category == "provider_metadata_invalid"


def test_missing_signing_key_is_metadata_invalid():
    report = _run(_idp(keys=[]))
    assert report.category == "provider_metadata_invalid"
    assert report.usable_rsa_keys is None  # never reached a usable-key count


def test_malformed_key_material_is_metadata_invalid():
    bad = {"kid": "k1", "kty": "RSA", "use": "sig", "n": "!!!not-base64!!!", "e": "AQAB"}
    report = _run(_idp(keys=[bad]))
    assert report.category == "provider_metadata_invalid"


def test_key_without_kid_is_not_usable():
    key = public_jwk(gen_rsa(), kid="k1")
    key.pop("kid")
    report = _run(_idp(keys=[key]))
    assert report.category == "provider_metadata_invalid"  # zero usable -> invalid


def test_duplicate_kid_is_metadata_invalid():
    k = gen_rsa()
    report = _run(_idp(keys=[public_jwk(k, kid="dup"), public_jwk(gen_rsa(), kid="dup")]))
    assert report.category == "provider_metadata_invalid"


def test_provider_unavailable_maps_to_exit_2():
    idp = _idp()
    idp.fail = True
    report = _run(idp)
    assert report.category == "provider_unavailable"
    assert report.exit_code == EXIT_PROVIDER_UNAVAILABLE


def test_discovery_redirect_is_refused_as_unavailable():
    idp = _idp()
    idp.redirect = True
    report = _run(idp)
    assert report.category == "provider_unavailable"


def test_oversized_jwks_is_unavailable():
    idp = _idp()
    idp.oversized = True  # ~2 MiB body exceeds the (small) document cap below
    report = _run(idp, _prod_settings(oidc_max_document_bytes=4096))
    assert report.category == "provider_unavailable"


def test_oversized_discovery_is_unavailable():
    idp = _idp()
    idp.discovery_raw = b'{"issuer":"x"}' + b" " * 8192
    report = _run(idp, _prod_settings(oidc_max_document_bytes=4096))
    assert report.category == "provider_unavailable"


def test_malformed_discovery_json_is_metadata_invalid():
    idp = _idp()
    idp.discovery_raw = b"{not valid json"
    report = _run(idp)
    assert report.category == "provider_metadata_invalid"


def test_config_invalid_when_public_origin_is_malformed():
    # A dev dry-run with an unusable public origin fails at config stage (exit 1) before any fetch.
    settings = Settings(app_env="dev", public_origin="http://")
    report = run_preflight(settings, client_factory=_factory(_idp()))
    assert report.category == "config_invalid"
    assert report.exit_code == EXIT_CONFIG_INVALID


def test_http_issuer_refused_in_production_dry_run():
    # Production Settings can't be constructed with an http issuer, so simulate a would-be-prod dry
    # run by forcing an http issuer past construction and asserting the preflight catches it.
    settings = _prod_settings()
    object.__setattr__(settings, "oidc_issuer", "http://issuer.test/realms/secp")
    report = run_preflight(settings, client_factory=_factory(_idp()))
    assert report.category == "config_invalid"


# --- S256 advertisement (reported, never falsely claimed as proof) ------------------------------


def test_s256_not_advertised_is_a_warning_not_a_failure():
    idp = _idp()
    idp.discovery.pop("code_challenge_methods_supported")
    report = _run(idp)
    assert report.category == "ok"  # advisory only — ADR-019
    assert report.exit_code == EXIT_OK
    assert report.s256_advertised is False


# --- no token acquisition -----------------------------------------------------------------------


def test_preflight_never_contacts_the_token_endpoint():
    idp = _idp()
    _run(idp)
    # Only discovery + JWKS are ever fetched; the token endpoint is never called.
    assert any(u.endswith("/openid-configuration") for u in idp.calls)
    assert JWKS_URI in idp.calls
    assert not any("/token" in u for u in idp.calls), idp.calls


# --- exit-code mapping is stable ----------------------------------------------------------------


def test_exit_code_mapping_is_stable():
    assert PreflightReport("ok").exit_code == 0
    assert PreflightReport("config_invalid").exit_code == 1
    assert PreflightReport("provider_unavailable").exit_code == 2
    assert PreflightReport("provider_metadata_invalid").exit_code == 3


# --- no provider body / JWK material in any output ----------------------------------------------


def test_no_jwk_material_or_provider_body_in_rendered_or_json_output():
    key = public_jwk(gen_rsa(), kid="k1")
    idp = _idp(keys=[key])
    report = _run(idp)
    modulus = key["n"]  # the base64url RSA modulus — must never appear in output
    text = report.render()
    blob = json.dumps(report.to_json())
    for out in (text, blob):
        assert modulus not in out
        assert "authorization_endpoint" not in out  # no raw discovery body echoed
        assert _AUTH_EP not in out
        assert JWKS_URI not in out
    # the safe, non-secret issuer host + our own URLs ARE allowed:
    assert "issuer.test" in text
    assert "secp.example.test" in text


def test_safe_json_output_contains_only_categories_and_booleans():
    report = _run(_idp())
    payload = report.to_json()
    assert set(payload) == {
        "category",
        "exit_code",
        "issuer_host",
        "callback_url",
        "logout_url",
        "s256_advertised",
        "usable_rsa_keys",
        "checks",
    }
    for check in payload["checks"]:
        assert set(check) == {"name", "passed", "fatal", "detail"}
        assert isinstance(check["passed"], bool)
    # no key/JWKS collection is present
    assert "keys" not in payload
    assert "jwks" not in payload


# --- no database / audit access -----------------------------------------------------------------


def test_preflight_does_not_open_a_database_session(monkeypatch):
    import secp_api.db as db

    def _boom(*a, **k):
        raise AssertionError("preflight must not open a database session")

    monkeypatch.setattr(db, "get_engine", _boom)
    monkeypatch.setattr(db, "get_sessionmaker", _boom)
    report = _run(_idp())
    assert report.category == "ok"


def test_preflight_makes_no_network_call_at_module_import():
    # Importing the module must not perform any network I/O (functions only).
    import importlib

    import secp_api.oidc_preflight as mod

    def _boom(*a, **k):
        raise AssertionError("no network at import time")

    orig = httpx.Client.__init__
    httpx.Client.__init__ = _boom  # type: ignore[method-assign]
    try:
        importlib.reload(mod)
    finally:
        httpx.Client.__init__ = orig  # type: ignore[method-assign]
