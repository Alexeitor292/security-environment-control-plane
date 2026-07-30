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


# --- ADR-028 §3: operator CLI client (secp-cli) for the device authorization grant --------------


def test_secp_cli_client_exists_and_is_public_with_no_secret():
    cli = _client(_realm(), "secp-cli")
    assert cli.get("publicClient") is True
    # A public client has no secret. `test_only_the_bearer_only_server_client_has_a_secret` already
    # scans every client; this pins the intent at the CLI client itself.
    assert "secret" not in cli


def test_secp_cli_enables_only_the_device_authorization_grant():
    cli = _client(_realm(), "secp-cli")
    assert cli.get("attributes", {}).get("oauth2.device.authorization.grant.enabled") == "true"
    # Every browser/password/service flow stays off: the CLI has exactly one way in.
    assert cli.get("standardFlowEnabled") is False
    assert cli.get("implicitFlowEnabled") is False
    assert cli.get("directAccessGrantsEnabled") is False  # no password grant, ever
    assert cli.get("serviceAccountsEnabled") is False


def test_secp_cli_issues_no_refresh_token():
    # ADR-018 eliminated the refresh token for the browser, but `use.refresh.tokens` is a PER-CLIENT
    # attribute, so secp-cli does not inherit secp-web's setting and must pin it explicitly. The CLI
    # requests no `offline_access` scope either (see test_operator_device_auth).
    cli = _client(_realm(), "secp-cli")
    assert cli.get("attributes", {}).get("use.refresh.tokens") == "false"


def test_secp_cli_carries_the_api_audience_mapper():
    # The device-grant access token must carry the `secp-api` audience or the backend verifier
    # refuses it. secp-cli needs its OWN mapper; it does not inherit secp-web's.
    cli = _client(_realm(), "secp-cli")
    mappers = [
        m
        for m in cli.get("protocolMappers", [])
        if m.get("protocolMapper") == "oidc-audience-mapper"
    ]
    assert len(mappers) == 1
    config = mappers[0]["config"]
    assert config["included.custom.audience"] == _EXPECTED_AUDIENCE == "secp-api"
    assert config["access.token.claim"] == "true"


def test_secp_cli_declares_no_redirect_uri():
    # The device grant has no browser redirect. A redirect URI on the CLI client would be an unused
    # attack surface, and a wildcard one would be a redirect-forgery hazard.
    cli = _client(_realm(), "secp-cli")
    assert not cli.get("redirectUris")
    assert not cli.get("webOrigins")


def test_only_the_browser_client_enables_the_standard_flow():
    # Defence in depth against a future client being added with browser flows switched on by habit.
    for client in _realm()["clients"]:
        if client.get("standardFlowEnabled") is True:
            assert client["clientId"] == "secp-web"
