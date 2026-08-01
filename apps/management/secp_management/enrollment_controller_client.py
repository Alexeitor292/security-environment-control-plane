"""Hardened management-plane client for the controller enrollment HTTPS API (SECP-PR5H-B1, Phase 4).

secpctl's controller commands (invite/status/revoke) operate the controller API EXCLUSIVELY over its
supported HTTPS surface, as an operator-authenticated OIDC client — never by importing ``secp_api``,
its ORM, services, or database. This is that narrow client:

* :class:`EnrollmentControllerClient` — the protocol with only ``create_invitation`` /
  ``get_enrollment_status`` / ``revoke_enrollment``;
* :class:`SealedEnrollmentControllerClient` — the shipped default (fails closed);
* :class:`HttpsEnrollmentControllerClient` — the concrete client. The origin + CA come ONLY from the
  bootstrap-recorded :class:`ControllerApiLocator`; the bearer token ONLY from the protected
  operator token provider. There is NO ``--url``/``--ca``/``--token`` input.

Transport posture (mirrors the reviewed worker/admission transports): HTTPS only; ``verify`` is an
``ssl.SSLContext`` pinned to the reviewed CA (never ``True``/``False``/system trust); ``trust_env=
False``; ``follow_redirects=False``; no cookies; strict ``application/json``; ``Accept-Encoding:
identity`` (compressed responses refused); bounded request/response bytes; bounded connect/read/
overall deadlines; the token attaches only as ``Authorization: Bearer`` on the pinned origin and is
never forwarded (redirects are forbidden). Every failure is a bounded reason code; the origin, CA
path, token, and raw HTTP/exception chain never enter a repr, error, log, or JSON output. The client
is non-serializable with a constant redacted repr and carries no provider/IaC/operator behavior.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import NoReturn, Protocol

from secp_management import ManagementError
from secp_management.controller_api_locator import (
    ControllerApiLocatorProvider,
)
from secp_management.operator_auth import OperatorAccessTokenProvider

_API_PREFIX = "/api/v1/enrollment"
_MAX_REQUEST_BYTES = 8192
_MAX_RESPONSE_BYTES = 65536
_DEFAULT_TIMEOUT = 15.0


class EnrollmentControllerClientError(ManagementError):
    """A bounded, closed controller-client refusal — carries ONLY a reason code, never the origin,
    CA path, bearer token, response body, or raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise EnrollmentControllerClientError(reason_code)


# --- management-plane response value objects (byte/field parity with the API schemas) -------------


@dataclass(frozen=True)
class ControllerInvitation:
    """The non-secret invitation the controller returns. Field-for-field parity with the API's
    ``EnrollmentInvitationOut`` (enforced by a parity test); management defines its OWN value object
    rather than importing the API schema across the plane boundary."""

    enrollment_id: str
    invitation_id: str
    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    transaction_id: str
    deployment_site_label: str
    created_at: str
    expires_at: str
    state: str
    revision: int


@dataclass(frozen=True)
class ControllerEnrollmentStatus:
    """The bounded, secret-free status projection. Field-for-field parity with the API's
    ``EnrollmentStatusOut``."""

    enrollment_id: str
    state: str
    revision: int
    controller_installation_id: str
    controller_key_fingerprint: str
    worker_installation_id: str
    worker_key_fingerprint: str
    release_fingerprint: str
    offer_fingerprint: str
    result_fingerprint: str
    #: The opaque deployment-site grouping label (WS-B R2). Outside the canonical enrollment
    #: contract, so it never affects a digest or the CAS chain; carried here only to keep this
    #: projection field-for-field with the API's ``EnrollmentStatusOut``, which the parity test
    #: pins.
    deployment_site_label: str
    expires_at: str
    updated_at: str
    refusal_reason: str


def _fields(cls: type) -> tuple[str, ...]:
    return tuple(f.name for f in dataclasses.fields(cls))


def _project(cls: type, body: object):
    """Reconstruct a value object from a response dict, requiring EXACTLY its field set (extra or
    missing fields refuse). A malformed body is a bounded closed refusal — never surfaced raw."""
    if not isinstance(body, dict):
        _reject("secpctl_controller_response_invalid")
    names = _fields(cls)
    if set(body) != set(names):
        _reject("secpctl_controller_response_invalid")
    try:
        return cls(**{name: body[name] for name in names})
    except (TypeError, ValueError):
        _reject("secpctl_controller_response_invalid")


# --- the client -----------------------------------------------------------------------------------


class EnrollmentControllerClient(Protocol):
    def create_invitation(
        self, *, deployment_site_label: str, ttl_seconds: int, idempotency_key: str
    ) -> ControllerInvitation: ...
    def get_enrollment_status(self, *, enrollment_id: str) -> ControllerEnrollmentStatus: ...
    def revoke_enrollment(
        self, *, enrollment_id: str, expected_revision: int
    ) -> ControllerEnrollmentStatus: ...


class _NonSerializable:
    def __reduce__(self) -> NoReturn:
        _reject("secpctl_controller_client_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("secpctl_controller_client_not_serializable")


class SealedEnrollmentControllerClient(_NonSerializable):
    """The shipped default: no controller client is activated; every attempt fails closed."""

    def __repr__(self) -> str:
        return "SealedEnrollmentControllerClient(<sealed>)"

    def create_invitation(
        self, *, deployment_site_label: str, ttl_seconds: int, idempotency_key: str
    ) -> ControllerInvitation:
        _reject("secpctl_controller_client_unavailable")

    def get_enrollment_status(self, *, enrollment_id: str) -> ControllerEnrollmentStatus:
        _reject("secpctl_controller_client_unavailable")

    def revoke_enrollment(
        self, *, enrollment_id: str, expected_revision: int
    ) -> ControllerEnrollmentStatus:
        _reject("secpctl_controller_client_unavailable")


def _valid_enrollment_id(value: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[7:])
    )


class HttpsEnrollmentControllerClient(_NonSerializable):
    """CA-pinned, operator-authenticated HTTPS client for the three enrollment operations."""

    __slots__ = ("_locator_provider", "_token_provider", "_timeout")

    def __init__(
        self,
        *,
        locator_provider: ControllerApiLocatorProvider,
        token_provider: OperatorAccessTokenProvider,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._locator_provider = locator_provider
        self._token_provider = token_provider
        self._timeout = timeout

    def __repr__(self) -> str:  # never the origin / CA / token
        return "HttpsEnrollmentControllerClient(<redacted>)"

    def create_invitation(
        self, *, deployment_site_label: str, ttl_seconds: int, idempotency_key: str
    ) -> ControllerInvitation:
        body = {
            "idempotency_key": idempotency_key,
            "deployment_site_label": deployment_site_label,
            "ttl_seconds": ttl_seconds,
        }
        result = self._request("POST", "/invitations", body=body, expect=201)
        return _project(ControllerInvitation, result)

    def get_enrollment_status(self, *, enrollment_id: str) -> ControllerEnrollmentStatus:
        if not _valid_enrollment_id(enrollment_id):
            _reject("secpctl_enrollment_id_invalid")
        result = self._request("GET", f"/{enrollment_id}", body=None, expect=200)
        return _project(ControllerEnrollmentStatus, result)

    def revoke_enrollment(
        self, *, enrollment_id: str, expected_revision: int
    ) -> ControllerEnrollmentStatus:
        if not _valid_enrollment_id(enrollment_id):
            _reject("secpctl_enrollment_id_invalid")
        result = self._request(
            "POST",
            f"/{enrollment_id}/revoke",
            body={"expected_revision": expected_revision},
            expect=200,
        )
        return _project(ControllerEnrollmentStatus, result)

    # --- hardened request -------------------------------------------------------------------------

    def _request(self, method: str, path: str, *, body: dict | None, expect: int) -> object:
        locator = self._locator_provider.locate()  # bootstrap-recorded origin + CA (validated)
        token = self._token_provider.access_token()  # protected operator token (redacted)
        status, raw = self._send(locator, method, _API_PREFIX + path, body, token)
        return self._interpret(status, raw, expect)

    def _send(self, locator, method, path, body, token):
        request_body = b""
        if body is not None:
            request_body = json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
            if len(request_body) > _MAX_REQUEST_BYTES:
                _reject("secpctl_controller_request_invalid")
        import ssl

        import httpx

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Authorization": token.authorization_header(),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            ssl_context = ssl.create_default_context(cafile=locator.ca_bundle_path)
            with httpx.Client(
                verify=ssl_context,  # pinned CA; never system trust / True / False
                trust_env=False,  # no ambient proxy / SSL_CERT_* / env
                follow_redirects=False,  # a redirect is never valid; token never forwarded
                timeout=self._timeout,
            ) as client:
                resp = client.request(
                    method,
                    locator.canonical_origin + path,
                    content=request_body or None,
                    headers=headers,
                )
                if resp.is_redirect:
                    _reject("secpctl_controller_response_invalid")
                encodings = resp.headers.get_list("content-encoding")
                if any(v.strip().lower() != "identity" for v in encodings):
                    _reject("secpctl_controller_response_invalid")
                content = resp.content
                if len(content) > _MAX_RESPONSE_BYTES:
                    _reject("secpctl_controller_response_invalid")
                return resp.status_code, content
        except EnrollmentControllerClientError:
            raise
        except Exception:  # noqa: BLE001 - connect/TLS/timeout fail closed WITHOUT leaking origin/CA
            _reject("secpctl_controller_transport_failed")

    def _interpret(self, status: int, raw: bytes, expect: int) -> object:
        if status == expect:
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001
                _reject("secpctl_controller_response_invalid")
        _reject(_status_reason(status, raw))


def _status_reason(status: int, raw: bytes) -> str:
    """Map an HTTP status (+ the controller's bounded ``error.code`` when present) to a bounded
    client reason code. The raw body is never surfaced."""
    code = _error_code(raw)
    if status == 401:
        return "secpctl_operator_auth_expired"
    if status == 403:
        return "secpctl_controller_forbidden"
    if status == 404:
        return "secpctl_controller_not_found"
    if status == 409:
        if code == "enrollment_revision_conflict":
            return "secpctl_controller_revision_conflict"
        return "secpctl_controller_conflict"
    if status == 422:
        return "secpctl_controller_request_invalid"
    if 500 <= status < 600:
        return "secpctl_controller_unavailable"
    return "secpctl_controller_response_invalid"


def _error_code(raw: bytes) -> str | None:
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        code = body["error"].get("code")
        if isinstance(code, str) and code.startswith("enrollment_"):
            return code
    return None


__all__ = [
    "ControllerEnrollmentStatus",
    "ControllerInvitation",
    "EnrollmentControllerClient",
    "EnrollmentControllerClientError",
    "HttpsEnrollmentControllerClient",
    "SealedEnrollmentControllerClient",
]
