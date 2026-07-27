"""Hardened management-plane controller enrollment client (SECP-PR5H-B1, Phase 4).

Offline (fake httpx.Client, no real network/TLS). Proves the CA-pinned/no-proxy/no-redirect posture,
the Bearer token attached only to the pinned origin, correct paths/methods, bounded error mapping,
redirect/compressed/oversized refusal, the sealed default, redaction + non-serializability, and that
the management value objects are field-for-field parity with the API response schemas.
"""

from __future__ import annotations

import json
import pickle
import ssl

import httpx
import pytest
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.enrollment_controller_client import (
    ControllerEnrollmentStatus,
    ControllerInvitation,
    EnrollmentControllerClientError,
    HttpsEnrollmentControllerClient,
    SealedEnrollmentControllerClient,
)
from secp_management.operator_auth import OperatorAccessToken

ORIGIN = "https://controller.example.test"
CA = "/etc/secp/controller/ca.pem"
TOKEN = "x" * 40
EID = "sha256:" + "a" * 64

_INVITATION = {
    "enrollment_id": EID,
    "invitation_id": "sha256:" + "b" * 64,
    "controller_installation_id": "controller-dev0001",
    "controller_key_id": "sha256:" + "c" * 64,
    "controller_trust_anchor_hex": "11" * 32,
    "controller_origin": ORIGIN,
    "release_digest": "sha256:" + "d" * 64,
    "transaction_id": "txn-0001",
    "deployment_site_label": "rack-01.eu_a",
    "created_at": "2026-07-27T00:00:00+00:00",
    "expires_at": "2026-07-27T01:00:00+00:00",
    "state": "invited",
    "revision": 0,
}
_STATUS = {
    "enrollment_id": EID,
    "state": "healthy",
    "revision": 5,
    "controller_installation_id": "controller-dev0001",
    "controller_key_fingerprint": "sha256:c…",
    "worker_installation_id": "worker-bbbbbbbb",
    "worker_key_fingerprint": "sha256:9…",
    "release_fingerprint": "sha256:d…",
    "offer_fingerprint": "sha256:e…",
    "result_fingerprint": "sha256:f…",
    "expires_at": "2026-07-27T01:00:00+00:00",
    "updated_at": "2026-07-27T00:30:00+00:00",
    "refusal_reason": "",
}


class _Locator:
    def locate(self) -> ControllerApiLocator:
        return ControllerApiLocator(canonical_origin=ORIGIN, ca_bundle_path=CA)


class _Token:
    def access_token(self) -> OperatorAccessToken:
        return OperatorAccessToken(TOKEN)


class _FakeResp:
    def __init__(self, status, body=None, *, is_redirect=False, encoding=None, raw=None):
        self.status_code = status
        self._raw = raw if raw is not None else json.dumps(body or {}).encode("utf-8")
        self.is_redirect = is_redirect
        self.headers = httpx.Headers({"content-encoding": encoding} if encoding else {})

    @property
    def content(self):
        return self._raw


class _FakeClient:
    captured: dict = {}
    resp = _FakeResp(200, {})

    def __init__(self, **kw):
        _FakeClient.captured = {"init": kw}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, method, url, *, content, headers):
        _FakeClient.captured.update(method=method, url=url, content=content, headers=headers)
        return _FakeClient.resp


@pytest.fixture
def patched(monkeypatch):
    monkeypatch.setattr(
        ssl, "create_default_context", lambda *, cafile: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    )
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    _FakeClient.resp = _FakeResp(200, {})
    return _FakeClient


def _client() -> HttpsEnrollmentControllerClient:
    return HttpsEnrollmentControllerClient(locator_provider=_Locator(), token_provider=_Token())


# --- happy paths + transport posture -------------------------------------------------------------


def test_create_invitation_posts_ca_pinned_with_bearer(patched):
    patched.resp = _FakeResp(201, _INVITATION)
    inv = _client().create_invitation(
        deployment_site_label="rack-01.eu_a", ttl_seconds=3600, idempotency_key="k" * 24
    )
    assert isinstance(inv, ControllerInvitation) and inv.enrollment_id == EID
    cap = patched.captured
    assert cap["method"] == "POST"
    assert (
        cap["url"] == ORIGIN + "/api/v1/enrollment/invitations"
    )  # token only on the pinned origin
    assert cap["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert cap["headers"]["Accept-Encoding"] == "identity"
    assert isinstance(cap["init"]["verify"], ssl.SSLContext)  # never True/False/system trust
    assert cap["init"]["trust_env"] is False
    assert cap["init"]["follow_redirects"] is False


def test_get_status_is_a_get_on_the_enrollment_path(patched):
    patched.resp = _FakeResp(200, _STATUS)
    status = _client().get_enrollment_status(enrollment_id=EID)
    assert isinstance(status, ControllerEnrollmentStatus) and status.state == "healthy"
    assert patched.captured["method"] == "GET"
    assert patched.captured["url"] == ORIGIN + f"/api/v1/enrollment/{EID}"
    assert patched.captured["content"] is None


def test_revoke_posts_expected_revision(patched):
    patched.resp = _FakeResp(200, {**_STATUS, "state": "refused", "revision": 1})
    status = _client().revoke_enrollment(enrollment_id=EID, expected_revision=0)
    assert status.state == "refused"
    assert patched.captured["url"] == ORIGIN + f"/api/v1/enrollment/{EID}/revoke"
    assert json.loads(patched.captured["content"]) == {"expected_revision": 0}


# --- bounded error mapping -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (401, {}, "secpctl_operator_auth_expired"),
        (403, {}, "secpctl_controller_forbidden"),
        (404, {}, "secpctl_controller_not_found"),
        (
            409,
            {"error": {"code": "enrollment_revision_conflict"}},
            "secpctl_controller_revision_conflict",
        ),
        (409, {"error": {"code": "enrollment_scope_mismatch"}}, "secpctl_controller_conflict"),
        (422, {}, "secpctl_controller_request_invalid"),
        (503, {}, "secpctl_controller_unavailable"),
    ],
)
def test_http_status_maps_to_bounded_reason(patched, status, body, expected):
    patched.resp = _FakeResp(status, body)
    with pytest.raises(EnrollmentControllerClientError) as ei:
        _client().get_enrollment_status(enrollment_id=EID)
    assert ei.value.reason_code == expected


def test_redirect_is_refused(patched):
    patched.resp = _FakeResp(302, {}, is_redirect=True)
    with pytest.raises(EnrollmentControllerClientError) as ei:
        _client().get_enrollment_status(enrollment_id=EID)
    assert ei.value.reason_code == "secpctl_controller_response_invalid"


def test_compressed_response_is_refused(patched):
    patched.resp = _FakeResp(200, _STATUS, encoding="gzip")
    with pytest.raises(EnrollmentControllerClientError) as ei:
        _client().get_enrollment_status(enrollment_id=EID)
    assert ei.value.reason_code == "secpctl_controller_response_invalid"


def test_oversized_response_is_refused(patched):
    patched.resp = _FakeResp(200, raw=b"x" * (65536 + 1))
    with pytest.raises(EnrollmentControllerClientError) as ei:
        _client().get_enrollment_status(enrollment_id=EID)
    assert ei.value.reason_code == "secpctl_controller_response_invalid"


def test_a_response_with_unexpected_fields_is_refused(patched):
    patched.resp = _FakeResp(200, {**_STATUS, "surprise": "x"})
    with pytest.raises(EnrollmentControllerClientError) as ei:
        _client().get_enrollment_status(enrollment_id=EID)
    assert ei.value.reason_code == "secpctl_controller_response_invalid"


def test_an_invalid_enrollment_id_is_refused_before_any_request(patched):
    with pytest.raises(EnrollmentControllerClientError) as ei:
        _client().get_enrollment_status(enrollment_id="../secrets")
    assert ei.value.reason_code == "secpctl_enrollment_id_invalid"


# --- sealed default + redaction ------------------------------------------------------------------


def test_sealed_default_fails_closed():
    for call in (
        lambda: SealedEnrollmentControllerClient().create_invitation(
            deployment_site_label="s", ttl_seconds=1, idempotency_key="k" * 24
        ),
        lambda: SealedEnrollmentControllerClient().get_enrollment_status(enrollment_id=EID),
        lambda: SealedEnrollmentControllerClient().revoke_enrollment(
            enrollment_id=EID, expected_revision=0
        ),
    ):
        with pytest.raises(EnrollmentControllerClientError) as ei:
            call()
        assert ei.value.reason_code == "secpctl_controller_client_unavailable"


def test_client_is_redacted_and_non_serializable():
    c = _client()
    assert ORIGIN not in repr(c) and CA not in repr(c) and TOKEN not in repr(c)
    assert "redacted" in repr(c)
    with pytest.raises(EnrollmentControllerClientError):
        pickle.dumps(c)


# --- plane-safe field parity with the API schemas (test layer may import both planes) -------------


def test_management_value_objects_match_the_api_response_schemas():
    import dataclasses

    from secp_api.schemas_enrollment import EnrollmentInvitationOut, EnrollmentStatusOut

    inv_fields = {f.name for f in dataclasses.fields(ControllerInvitation)}
    status_fields = {f.name for f in dataclasses.fields(ControllerEnrollmentStatus)}
    assert inv_fields == set(EnrollmentInvitationOut.model_fields)
    assert status_fields == set(EnrollmentStatusOut.model_fields)
