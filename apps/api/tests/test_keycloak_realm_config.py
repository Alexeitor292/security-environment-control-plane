"""Keycloak dev-realm configuration tests (ADR-017 + ADR-018) — hermetic (no running Keycloak).

Proves the committed dev realm gives the backend verifier what it needs: the ``secp-web`` access
token carries the ``secp-api`` audience via an explicit mapper, the API audience matches the
backend's configured audience, the deterministic dev subject equals the seeded ``User.subject``, and
NO client secret is exposed to the browser (the public client has none; only the bearer-only server
client does). It also pins the OIDC-B browser-client hardening: PKCE S256 required, exact
redirect/post-logout URIs, and implicit/direct-access/service-account flows disabled.
"""

from __future__ import annotations

import json
from pathlib import Path

from secp_api.auth import DEV_PRINCIPAL_SUBJECT
from secp_api.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
REALM_PATH = REPO_ROOT / "infra" / "dev" / "keycloak" / "realm-secp.json"
_EXPECTED_AUDIENCE = Settings.model_fields["oidc_audience"].default  # source default == "secp-api"


def _realm() -> dict:
    return json.loads(REALM_PATH.read_text(encoding="utf-8"))


def _client(realm: dict, client_id: str) -> dict:
    return next(c for c in realm["clients"] if c["clientId"] == client_id)


def test_realm_is_valid_json_with_expected_clients():
    realm = _realm()
    ids = {c["clientId"] for c in realm["clients"]}
    assert {"secp-web", "secp-api"} <= ids


def test_secp_web_is_public_with_no_browser_secret():
    web = _client(_realm(), "secp-web")
    assert web.get("publicClient") is True
    assert "secret" not in web  # a public browser client must carry NO client secret


def test_audience_mapper_targets_the_api_audience():
    web = _client(_realm(), "secp-web")
    audience_mappers = [
        m
        for m in web.get("protocolMappers", [])
        if m.get("protocolMapper") == "oidc-audience-mapper"
    ]
    assert len(audience_mappers) == 1, "exactly one explicit audience mapper is expected"
    config = audience_mappers[0]["config"]
    assert config["included.custom.audience"] == _EXPECTED_AUDIENCE == "secp-api"
    assert config["access.token.claim"] == "true"  # the AUDIENCE lands in the access token


def test_dev_admin_subject_matches_seeded_subject():
    user = next(u for u in _realm()["users"] if u["username"] == "dev-admin")
    # Keycloak's access-token ``sub`` is the user id; it must equal the seeded User.subject so the
    # same user resolves on both the dev-fallback and the real bearer path.
    assert user["id"] == DEV_PRINCIPAL_SUBJECT


def test_only_the_bearer_only_server_client_has_a_secret():
    for client in _realm()["clients"]:
        if "secret" in client:
            assert client.get("bearerOnly") is True and client.get("publicClient") is False


def test_no_self_registration_enabled():
    assert _realm().get("registrationAllowed") is False


# --- ADR-018: browser client (secp-web) hardening for Authorization Code + PKCE ----------------


def test_secp_web_requires_pkce_s256():
    web = _client(_realm(), "secp-web")
    assert web.get("attributes", {}).get("pkce.code.challenge.method") == "S256"


def test_secp_web_disables_implicit_direct_and_service_account_flows():
    web = _client(_realm(), "secp-web")
    assert web.get("standardFlowEnabled") is True  # Authorization Code stays on
    assert web.get("implicitFlowEnabled") is False
    assert web.get("directAccessGrantsEnabled") is False  # no password grant
    assert web.get("serviceAccountsEnabled") is False


def test_secp_web_uses_exact_callback_redirect_uri_no_wildcard():
    web = _client(_realm(), "secp-web")
    assert web.get("redirectUris") == ["http://localhost:5173/auth/callback"]
    for uri in web.get("redirectUris", []):
        assert "*" not in uri  # no wildcard redirect URIs
    assert web.get("webOrigins") == ["http://localhost:5173"]


def test_secp_web_has_exact_post_logout_redirect_uri():
    web = _client(_realm(), "secp-web")
    assert web.get("attributes", {}).get("post.logout.redirect.uris") == (
        "http://localhost:5173/login"
    )


def test_secp_web_disables_refresh_token_issuance():
    # ADR-018: the browser client issues NO refresh token. Keycloak 25 honors the client attribute
    # ``use.refresh.tokens`` (string "false") for the standard Authorization Code flow, so the token
    # endpoint omits the refresh_token grant entirely. The frontend still strips one defensively.
    web = _client(_realm(), "secp-web")
    assert web.get("attributes", {}).get("use.refresh.tokens") == "false"


def test_dev_realm_has_no_production_origins():
    # The dev realm must never carry a production (https) origin in redirect/web-origin config.
    assert "https://" not in json.dumps(_realm())
