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
