"""Hardened device-authorization transport (SECP-PR5H-B2, Workstream C).

Exercised entirely through the injected client seams — no socket is opened. These pin the discovery
contract (the device endpoint is READ, never constructed), the exact provider-limitation refusal
when the device grant is not advertised, the public-client request shape, and the closed refusal
behaviour that keeps an origin, CA path, token or provider body out of every error.
"""

from __future__ import annotations

import json

import pytest
from secp_management import ManagementError
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.device_grant import DEVICE_CODE_GRANT_TYPE, DeviceCode
from secp_management.operator_device_auth import (
    OPERATOR_CLI_CLIENT_ID,
    OPERATOR_CLI_SCOPE,
    DeviceAuthorizationClient,
    DeviceEndpoints,
)

ORIGIN = "https://controller.invalid"
ISSUER = "https://idp.invalid/realms/secp"
LOCATOR = ControllerApiLocator(
    canonical_origin=ORIGIN, ca_bundle_path="/etc/secp/controller/ca.pem"
)

AUTH_CONFIG = {
    "mode": "oidc",
    "issuer": ISSUER,
    "client_id": "secp-web",
    "audience": "secp-api",
    "scope": "openid profile email",
    "redirect_path": "/auth/callback",
    "post_logout_redirect_path": "/login",
}

DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
    "device_authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth/device",
    "grant_types_supported": ["authorization_code", DEVICE_CODE_GRANT_TYPE],
}

DEVICE_RESPONSE = {
    "device_code": "ZGV2aWNlLWNvZGUtdmFsdWUtMDAwMDAwMDAwMDAx",
    "user_code": "WDJL-MBQK",
    "verification_uri": "https://idp.invalid/device",
    "expires_in": 600,
    "interval": 5,
}

ENDPOINTS = DeviceEndpoints(
    device_authorization_endpoint=DISCOVERY["device_authorization_endpoint"],
    token_endpoint=DISCOVERY["token_endpoint"],
    jwks_uri=DISCOVERY["jwks_uri"],
)

#: RFC 8414 §2 names the member ``revocation_endpoint`` and makes it OPTIONAL, so both a provider
#: that advertises one and a provider that does not are conforming. `DISCOVERY` above deliberately
#: omits it; this pair is the advertising case.
REVOCATION_URL = f"{ISSUER}/protocol/openid-connect/revoke"
REVOCABLE_DISCOVERY = {**DISCOVERY, "revocation_endpoint": REVOCATION_URL}
REVOCABLE_ENDPOINTS = DeviceEndpoints(
    device_authorization_endpoint=DISCOVERY["device_authorization_endpoint"],
    token_endpoint=DISCOVERY["token_endpoint"],
    jwks_uri=DISCOVERY["jwks_uri"],
    revocation_endpoint=REVOCATION_URL,
)


class _Headers:
    def __init__(self, encodings):
        self._encodings = encodings

    def get_list(self, _name):
        return self._encodings


class _Response:
    def __init__(self, *, status=200, body=b"", encodings=(), redirect=False):
        self.status_code = status
        self.content = body
        self.headers = _Headers(list(encodings))
        self.is_redirect = redirect

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_bytes(self):
        yield self.content


class _FakeClient:
    """Records every request so the transport contract is assertable without a socket."""

    def __init__(self, *, stream=None, post=None):
        self._stream = stream or (lambda url: _Response())
        self._post = post or (lambda url, data, headers: _Response())
        self.streamed: list[str] = []
        self.posted: list[tuple[str, dict, dict]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def stream(self, _method, url):
        self.streamed.append(url)
        return self._stream(url)

    def post(self, url, data=None, headers=None):
        self.posted.append((url, dict(data or {}), dict(headers or {})))
        return self._post(url, data, headers)


def _json_response(payload, **kwargs):
    return _Response(body=json.dumps(payload).encode("utf-8"), **kwargs)


def _client(*, issuer_docs=None, post=None, pinned=None, require_https=True):
    docs = issuer_docs or {}
    issuer_client = _FakeClient(stream=lambda url: _json_response(docs.get(url, {})), post=post)
    pinned_client = (
        pinned
        if pinned is not None
        else _FakeClient(stream=lambda url: _json_response(AUTH_CONFIG))
    )
    client = DeviceAuthorizationClient(
        locator=LOCATOR,
        require_https=require_https,
        client_factory=lambda: issuer_client,
        pinned_client_factory=lambda: pinned_client,
    )
    return client, issuer_client, pinned_client


def _reason(excinfo) -> str:
    return excinfo.value.reason_code


# --- code-owned client identity -------------------------------------------------------------------


def test_client_id_and_scope_are_code_owned_and_exclude_offline_access():
    assert OPERATOR_CLI_CLIENT_ID == "secp-cli"
    assert OPERATOR_CLI_SCOPE == "openid profile email"
    assert "offline_access" not in OPERATOR_CLI_SCOPE


# --- reviewed authority (reads the EXISTING public route, unmodified) -----------------------------


def test_reviewed_authority_reads_the_existing_public_auth_config_route():
    client, _issuer, pinned = _client()
    authority = client.reviewed_authority()
    assert authority.issuer == ISSUER
    assert authority.audience == "secp-api"
    assert pinned.streamed == [f"{ORIGIN}/api/v1/auth/config"]


def test_reviewed_authority_uses_the_ca_pinned_transport_not_the_issuer_transport():
    client, issuer, pinned = _client()
    client.reviewed_authority()
    assert pinned.streamed and not issuer.streamed


def test_authority_repr_never_reveals_the_issuer_or_audience():
    client, _issuer, _pinned = _client()
    assert repr(client.reviewed_authority()) == "ReviewedAuthority(<redacted>)"


def test_a_dev_fallback_controller_refuses_rather_than_pretending():
    pinned = _FakeClient(stream=lambda url: _json_response({**AUTH_CONFIG, "mode": "dev_fallback"}))
    client, _issuer, _pinned = _client(pinned=pinned)
    with pytest.raises(ManagementError) as ei:
        client.reviewed_authority()
    assert _reason(ei) == "secpctl_device_authority_not_oidc"


@pytest.mark.parametrize(
    "issuer",
    ["http://idp.invalid/realms/secp", "https://u:p@idp.invalid", "not-a-url", "", None],
)
def test_an_unsafe_issuer_from_the_controller_is_refused(issuer):
    pinned = _FakeClient(stream=lambda url: _json_response({**AUTH_CONFIG, "issuer": issuer}))
    client, _issuer, _pinned = _client(pinned=pinned)
    with pytest.raises(ManagementError) as ei:
        client.reviewed_authority()
    assert _reason(ei) == "secpctl_device_authority_invalid"


def test_a_controller_error_status_is_a_bounded_refusal():
    pinned = _FakeClient(stream=lambda url: _Response(status=503))
    client, _issuer, _pinned = _client(pinned=pinned)
    with pytest.raises(ManagementError) as ei:
        client.reviewed_authority()
    assert _reason(ei) == "secpctl_controller_unavailable"


def test_a_compressed_controller_response_is_refused():
    pinned = _FakeClient(stream=lambda url: _json_response(AUTH_CONFIG, encodings=["gzip"]))
    client, _issuer, _pinned = _client(pinned=pinned)
    with pytest.raises(ManagementError) as ei:
        client.reviewed_authority()
    assert _reason(ei) == "secpctl_controller_response_invalid"


# --- discovery ------------------------------------------------------------------------------------


def _discovery_docs(document=None):
    return {f"{ISSUER}/.well-known/openid-configuration": document or DISCOVERY}


def test_discovery_reads_the_device_endpoint_and_never_constructs_it():
    client, issuer, _pinned = _client(issuer_docs=_discovery_docs())
    endpoints = client.discover(client.reviewed_authority())
    assert endpoints.device_authorization_endpoint == DISCOVERY["device_authorization_endpoint"]
    assert issuer.streamed == [f"{ISSUER}/.well-known/openid-configuration"]


def test_discovery_endpoint_is_not_built_by_string_concatenation():
    """A provider on a different path (or a different host entirely) must still be honoured."""
    moved = {**DISCOVERY, "device_authorization_endpoint": "https://idp.invalid/custom/dev-auth"}
    client, _issuer, _pinned = _client(issuer_docs=_discovery_docs(moved))
    endpoints = client.discover(client.reviewed_authority())
    assert endpoints.device_authorization_endpoint == "https://idp.invalid/custom/dev-auth"


def test_a_provider_without_the_device_endpoint_reports_the_exact_limitation():
    """ADR-028 §3: report the provider limitation; never fall back to another grant."""
    without = {k: v for k, v in DISCOVERY.items() if k != "device_authorization_endpoint"}
    client, _issuer, _pinned = _client(issuer_docs=_discovery_docs(without))
    with pytest.raises(ManagementError) as ei:
        client.discover(client.reviewed_authority())
    assert _reason(ei) == "secpctl_device_grant_unsupported"


def test_a_provider_not_advertising_the_device_grant_type_is_refused():
    narrowed = {**DISCOVERY, "grant_types_supported": ["authorization_code", "refresh_token"]}
    client, _issuer, _pinned = _client(issuer_docs=_discovery_docs(narrowed))
    with pytest.raises(ManagementError) as ei:
        client.discover(client.reviewed_authority())
    assert _reason(ei) == "secpctl_device_grant_unsupported"


def test_a_discovery_issuer_mismatch_is_refused():
    """The discovery document's issuer must EXACTLY equal the reviewed issuer — no substitution."""
    swapped = {**DISCOVERY, "issuer": "https://evil.invalid/realms/secp"}
    client, _issuer, _pinned = _client(issuer_docs=_discovery_docs(swapped))
    with pytest.raises(ManagementError) as ei:
        client.discover(client.reviewed_authority())
    assert _reason(ei) == "secpctl_device_discovery_invalid"


@pytest.mark.parametrize("field", ["token_endpoint", "jwks_uri"])
def test_an_unsafe_discovered_endpoint_is_refused(field):
    hostile = {**DISCOVERY, field: "http://idp.invalid/plaintext"}
    client, _issuer, _pinned = _client(issuer_docs=_discovery_docs(hostile))
    with pytest.raises(ManagementError) as ei:
        client.discover(client.reviewed_authority())
    assert _reason(ei) == "secpctl_device_discovery_invalid"


def test_endpoints_repr_never_reveals_the_urls():
    assert repr(ENDPOINTS) == "DeviceEndpoints(<redacted>)"


# --- device authorization request (RFC 8628 §3.1) -------------------------------------------------


def test_device_authorization_sends_only_client_id_and_scope_with_no_secret():
    posts = []

    def post(url, data, headers):
        posts.append((url, data))
        return _json_response(DEVICE_RESPONSE)

    client, _issuer, _pinned = _client(post=post)
    authorization = client.request_device_authorization(ENDPOINTS)
    url, form = posts[0]
    assert url == DISCOVERY["device_authorization_endpoint"]
    assert form == {"client_id": "secp-cli", "scope": "openid profile email"}
    assert "client_secret" not in form
    assert authorization.user_code == "WDJL-MBQK"


def test_a_redirect_on_the_device_authorization_request_is_refused():
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _Response(status=302, redirect=True)
    )
    with pytest.raises(ManagementError) as ei:
        client.request_device_authorization(ENDPOINTS)
    assert _reason(ei) == "secpctl_device_authorization_invalid"


def test_an_oversized_device_authorization_body_is_refused():
    huge = _Response(body=b"{" + b"x" * 70_000)
    client, _issuer, _pinned = _client(post=lambda url, data, headers: huge)
    with pytest.raises(ManagementError) as ei:
        client.request_device_authorization(ENDPOINTS)
    assert _reason(ei) == "secpctl_device_authorization_invalid"


# --- token request (RFC 8628 §3.4) ----------------------------------------------------------------


def _device_code():
    return DeviceCode(DEVICE_RESPONSE["device_code"])


def test_token_request_uses_the_device_grant_type_and_the_public_client_id():
    posts = []

    def post(url, data, headers):
        posts.append((url, data))
        return _json_response({"access_token": "header.payload.sig", "token_type": "Bearer"})

    client, _issuer, _pinned = _client(post=post)
    token, error = client.request_token(ENDPOINTS, _device_code())
    url, form = posts[0]
    assert url == DISCOVERY["token_endpoint"]
    assert form["grant_type"] == DEVICE_CODE_GRANT_TYPE
    assert form["client_id"] == "secp-cli"
    assert form["device_code"] == DEVICE_RESPONSE["device_code"]
    assert "client_secret" not in form
    assert (token, error) == ("header.payload.sig", "")


@pytest.mark.parametrize("error", ["authorization_pending", "slow_down", "access_denied"])
def test_a_provider_error_is_returned_for_the_pure_scheduler_to_decide(error):
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _json_response({"error": error}, status=400)
    )
    token, returned = client.request_token(ENDPOINTS, _device_code())
    assert (token, returned) == ("", error)


def test_a_non_bearer_token_type_is_refused():
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _json_response(
            {"access_token": "a.b.c", "token_type": "mac"}
        )
    )
    with pytest.raises(ManagementError) as ei:
        client.request_token(ENDPOINTS, _device_code())
    assert _reason(ei) == "secpctl_device_token_refused"


def test_a_success_without_an_access_token_is_refused():
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _json_response({"token_type": "Bearer"})
    )
    with pytest.raises(ManagementError) as ei:
        client.request_token(ENDPOINTS, _device_code())
    assert _reason(ei) == "secpctl_device_token_refused"


def test_a_redirect_on_the_token_request_is_refused():
    """A redirect would forward the device code to another host."""
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _Response(status=302, redirect=True)
    )
    with pytest.raises(ManagementError) as ei:
        client.request_token(ENDPOINTS, _device_code())
    assert _reason(ei) == "secpctl_device_token_refused"


def test_a_transport_failure_never_leaks_the_endpoint_or_exception():
    def explode(url, data, headers):
        raise RuntimeError(f"connect to {url} failed: secret-internal-detail")

    client, _issuer, _pinned = _client(post=explode)
    with pytest.raises(ManagementError) as ei:
        client.request_token(ENDPOINTS, _device_code())
    rendered = f"{ei.value!r} {ei.value}"
    assert _reason(ei) == "secpctl_device_provider_unavailable"
    assert "secret-internal-detail" not in rendered
    assert ISSUER not in rendered


# --- revocation endpoint discovery (RFC 8414 §2 — OPTIONAL) ---------------------------------------


def test_the_revocation_endpoint_is_read_from_discovery_when_advertised():
    client, _issuer, _pinned = _client(
        issuer_docs={f"{ISSUER}/.well-known/openid-configuration": REVOCABLE_DISCOVERY}
    )
    endpoints = client.discover(client.reviewed_authority())
    assert endpoints.revocation_endpoint == REVOCATION_URL


def test_an_absent_revocation_endpoint_is_none_and_not_a_refusal():
    """RFC 8414 §2 makes ``revocation_endpoint`` OPTIONAL, so a conforming provider may omit it.
    Discovery must still succeed — the operator simply cannot revoke, which ``auth logout``
    reports."""
    client, _issuer, _pinned = _client(
        issuer_docs={f"{ISSUER}/.well-known/openid-configuration": DISCOVERY}
    )
    assert client.discover(client.reviewed_authority()).revocation_endpoint is None


@pytest.mark.parametrize(
    "value",
    [
        "http://idp.invalid/revoke",  # RFC 7009 §2: revocation URLs MUST be HTTPS
        "https://user:pw@idp.invalid/revoke",
        "not-a-url",
        "https://idp.invalid/rev oke",
        "",
        123,
    ],
)
def test_a_present_but_malformed_revocation_endpoint_is_refused_never_downgraded(value):
    """A broken discovery document must not silently become 'no revocation available' — that would
    turn a provider defect into a logout that quietly leaves the token live."""
    client, _issuer, _pinned = _client(
        issuer_docs={
            f"{ISSUER}/.well-known/openid-configuration": {
                **DISCOVERY,
                "revocation_endpoint": value,
            }
        }
    )
    with pytest.raises(ManagementError) as ei:
        client.discover(client.reviewed_authority())
    assert _reason(ei) == "secpctl_device_discovery_invalid"


# --- revocation requests (RFC 7009) ---------------------------------------------------------------


def test_revocation_posts_the_token_in_the_body_with_the_hint_and_public_client_id():
    posted = []

    def post(url, data, headers):
        posted.append((url, dict(data)))
        return _Response(status=200)

    client, issuer, _pinned = _client(post=post)
    outcome = client.revoke_token(REVOCABLE_ENDPOINTS, "the-access-token")

    assert outcome.revoked is True
    assert posted == [
        (
            REVOCATION_URL,
            {
                "token": "the-access-token",
                "token_type_hint": "access_token",
                "client_id": OPERATOR_CLI_CLIENT_ID,
            },
        )
    ]
    # the token travels in the BODY, never in the URL — a revocation endpoint's access log is
    # exactly where a bearer credential must not land
    assert "the-access-token" not in issuer.posted[0][0]
    assert "client_secret" not in posted[0][1]


def test_revocation_without_an_advertised_endpoint_makes_no_request():
    client, issuer, _pinned = _client()
    outcome = client.revoke_token(ENDPOINTS, "the-access-token")
    assert outcome.outcome == "unsupported"
    assert outcome.token_still_live is True
    assert issuer.posted == []


def test_a_200_with_an_empty_body_is_a_successful_revocation():
    """RFC 7009 §2.2 defines no success body, so a 200 is authoritative on its own."""
    client, _issuer, _pinned = _client(post=lambda url, data, headers: _Response(status=200))
    assert client.revoke_token(REVOCABLE_ENDPOINTS, "t").revoked is True


def test_a_503_reports_the_token_as_still_live():
    client, _issuer, _pinned = _client(post=lambda url, data, headers: _Response(status=503))
    outcome = client.revoke_token(REVOCABLE_ENDPOINTS, "t")
    assert outcome.outcome == "unavailable"
    assert outcome.token_still_live is True


def test_an_unsupported_token_type_error_body_is_parsed_into_the_outcome():
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _json_response(
            {"error": "unsupported_token_type"}, status=400
        )
    )
    outcome = client.revoke_token(REVOCABLE_ENDPOINTS, "t")
    assert outcome.outcome == "unsupported"
    assert outcome.reason_code == "secpctl_revocation_unsupported_token_type"


def test_a_transport_failure_never_raises_and_reports_the_token_as_still_live():
    """``auth logout`` must reach its LOCAL deletion whatever the provider does, so this method
    never raises. An unreachable issuer can never strand a credential on the workstation."""

    def explode(url, data, headers):
        raise RuntimeError("secret-internal-detail")

    client, _issuer, _pinned = _client(post=explode)
    outcome = client.revoke_token(REVOCABLE_ENDPOINTS, "t")
    assert outcome.outcome == "unavailable"
    assert outcome.token_still_live is True
    assert "secret-internal-detail" not in f"{outcome!r}"


def test_a_redirected_revocation_is_refused_and_never_followed():
    """Following it would forward the token to an unreviewed host."""
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _Response(status=302, redirect=True)
    )
    outcome = client.revoke_token(REVOCABLE_ENDPOINTS, "t")
    assert outcome.outcome == "refused"
    assert outcome.token_still_live is True


def test_an_unparseable_error_body_still_yields_a_bounded_refusal():
    client, _issuer, _pinned = _client(
        post=lambda url, data, headers: _Response(status=400, body=b"<html>nope</html>")
    )
    assert client.revoke_token(REVOCABLE_ENDPOINTS, "t").outcome == "refused"


# --- granted scope on the token response (RFC 6749 §5.1) ------------------------------------------


def _token_response(payload, status=200):
    return lambda url, data, headers: _json_response(payload, status=status)


def test_a_token_response_that_grants_offline_access_is_refused():
    """The CLI never requests ``offline_access``; a provider that grants it anyway would hand the
    workstation a long-lived renewal credential, which is exactly the posture ADR-018 excludes."""
    client, _issuer, _pinned = _client(
        post=_token_response(
            {
                "access_token": "t",
                "token_type": "Bearer",
                "scope": "openid profile email offline_access",
            }
        )
    )
    with pytest.raises(ManagementError) as ei:
        client.request_token(ENDPOINTS, _device_code())
    assert _reason(ei) == "secpctl_device_scope_refused"


def test_a_token_response_missing_the_required_scope_is_refused():
    client, _issuer, _pinned = _client(
        post=_token_response({"access_token": "t", "token_type": "Bearer", "scope": "profile"})
    )
    with pytest.raises(ManagementError) as ei:
        client.request_token(ENDPOINTS, _device_code())
    assert _reason(ei) == "secpctl_device_scope_insufficient"


def test_an_absent_scope_member_means_exactly_what_was_requested():
    """RFC 6749 §5.1 — ``scope`` is OPTIONAL when identical to the request."""
    client, _issuer, _pinned = _client(
        post=_token_response({"access_token": "t", "token_type": "Bearer"})
    )
    assert client.request_token(ENDPOINTS, _device_code()) == ("t", "")


def test_a_provider_default_scope_beyond_the_request_is_accepted():
    """Identity providers routinely attach their own default client scopes (Keycloak's ``roles``
    and ``basic`` among them). Refusing on width alone would break real logins for a reason that is
    not a security property; the REFUSED set is the security property, and it still applies."""
    client, _issuer, _pinned = _client(
        post=_token_response(
            {"access_token": "t", "token_type": "Bearer", "scope": "openid profile email roles"}
        )
    )
    assert client.request_token(ENDPOINTS, _device_code()) == ("t", "")


def test_an_unrequested_refresh_token_is_refused():
    """A public client with ``use.refresh.tokens`` off is issued none. One arriving unasked means
    the grant is not the posture this CLI is built on, and nothing here manages its lifetime."""
    client, _issuer, _pinned = _client(
        post=_token_response(
            {"access_token": "t", "token_type": "Bearer", "refresh_token": "r", "scope": "openid"}
        )
    )
    with pytest.raises(ManagementError) as ei:
        client.request_token(ENDPOINTS, _device_code())
    assert _reason(ei) == "secpctl_device_refresh_token_unexpected"


def test_the_client_repr_is_constant_and_reveals_no_locator():
    client, _issuer, _pinned = _client()
    assert repr(client) == "DeviceAuthorizationClient(<redacted>)"
    assert ORIGIN not in repr(client)


def test_the_client_cannot_be_pickled():
    import pickle

    client, _issuer, _pinned = _client()
    with pytest.raises(ManagementError) as ei:
        pickle.dumps(client)
    assert _reason(ei) == "secpctl_device_client_not_serializable"


def test_https_is_required_by_default_and_relaxed_only_explicitly():
    """The shipped composition refuses a plaintext issuer; only a test may relax it."""
    import inspect

    signature = inspect.signature(DeviceAuthorizationClient.__init__)
    assert signature.parameters["require_https"].default is True
