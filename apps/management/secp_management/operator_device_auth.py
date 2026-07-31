"""Hardened OAuth 2.0 Device Authorization Grant client — SECP-PR5H-B2, Workstream C.

The ONLY module in the ``secpctl auth`` surface that performs network I/O. The protocol decisions
live in :mod:`secp_management.device_grant` (pure), token verification in
:mod:`secp_management.operator_token_verify` (pure), and RFC 7009 revocation semantics in
:mod:`secp_management.operator_token_revoke` (pure); this module only retrieves bytes and hands them
over, so the security-relevant logic stays testable without a socket.

Two DIFFERENT transport postures, each matching its counterpart — the distinction is deliberate:

* **Controller** (``GET /api/v1/auth/config``): CA-PINNED to the bootstrap-recorded controller trust
  bundle, exactly as :mod:`secp_management.enrollment_controller_client` does. The controller is
  SECP's own deployment-local service; system trust would defeat the pin.
* **Identity provider** (discovery, JWKS, device authorization, token): the reviewed OIDC issuer is
  an external provider with a normal public/enterprise chain, so it is verified against SYSTEM trust
  with ``trust_env=False``. This mirrors the control plane's own reviewed IdP posture in
  ``secp_api/oidc.py`` (``build_client_factory``), which is the established precedent for talking to
  the issuer in this repository.

Both postures share: bounded connect/read/overall timeouts, ``follow_redirects=False`` (a redirect
is never valid here and would forward a credential), ``trust_env=False`` (no ambient proxy or
``SSL_CERT_*``), ``Accept-Encoding: identity``, and a response-size cap enforced WHILE reading.

The issuer is discovered from the controller's existing public auth-config route — that route is
read UNCHANGED and is not widened for the CLI. The device-authorization endpoint is then taken from
the issuer's ``.well-known`` document and is never constructed by string concatenation. There is no
``--issuer`` / ``--client-id`` / ``--endpoint`` argument anywhere: no identity, endpoint or trust
input is selectable by a CLI flag or an environment variable.

Nothing here logs or returns a token, a device code, a JWK, a provider response body, or an
exception chain; every failure is one bounded reason code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, NoReturn
from urllib.parse import urlsplit

from secp_management import ManagementError
from secp_management.controller_api_locator import ControllerApiLocator
from secp_management.device_grant import (
    DEVICE_CODE_GRANT_TYPE,
    DeviceAuthorization,
    DeviceCode,
    parse_device_authorization,
    validate_granted_scope,
)
from secp_management.operator_token_revoke import (
    OUTCOME_REFUSED,
    OUTCOME_UNAVAILABLE,
    RevocationOutcome,
    interpret_revocation_response,
    revocation_form,
    revocation_unsupported,
)

#: The code-owned PUBLIC client id secpctl presents to the reviewed issuer. It is not a secret (a
#: public client has none) and is never selectable by a CLI flag or environment variable, matching
#: how every other identity/trust input in this plane is fixed and code-owned. Making it
#: deployment-configurable belongs with the slice that ships a credential backend and can be judged
#: end to end; see the PR description.
OPERATOR_CLI_CLIENT_ID = "secp-cli"

#: The requested scope. It EXCLUDES ``offline_access`` deliberately: no refresh token is requested,
#: mirroring the browser posture ADR-018 established (``routers/auth_config.py`` pins the same set).
OPERATOR_CLI_SCOPE = "openid profile email"

_AUTH_CONFIG_PATH = "/api/v1/auth/config"
_DISCOVERY_PATH = "/.well-known/openid-configuration"

_MAX_DOCUMENT_BYTES = 1_048_576
_MAX_TOKEN_RESPONSE_BYTES = 65_536
_DEFAULT_TIMEOUT = 15.0


class OperatorDeviceAuthError(ManagementError):
    """A bounded, closed device-auth transport refusal — carries ONLY a reason code, never the
    issuer, endpoint, CA path, token, device code, response body, or raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise OperatorDeviceAuthError(reason_code)


def _require_safe_url(url: object, *, require_https: bool, reason: str) -> str:
    """Reject anything that is not a bare HTTP(S) URL with a host and no userinfo."""
    if not isinstance(url, str) or not (1 <= len(url) <= 1024):
        _reject(reason)
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        _reject(reason)
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        _reject(reason)
    if require_https and parsed.scheme != "https":
        _reject(reason)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        _reject(reason)
    if not parsed.hostname:
        _reject(reason)
    return url


def _read_bounded(response: Any, *, max_bytes: int, reason: str) -> bytes:
    """Accumulate a streamed body, enforcing the cap WHILE reading (never after)."""
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            _reject(reason)
    return bytes(body)


def _decode_json_object(raw: bytes, *, reason: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - a malformed document is a bounded refusal
        _reject(reason)
    if not isinstance(parsed, dict):
        _reject(reason)
    return parsed


def _refuse_encoded(response: Any, *, reason: str) -> None:
    encodings = response.headers.get_list("content-encoding")
    if any(value.strip().lower() != "identity" for value in encodings):
        _reject(reason)


@dataclass(frozen=True)
class ReviewedAuthority:
    """The reviewed OIDC facts the CLI needs, read from the controller's own public config route.

    Public, non-secret values only. Its repr is redacted so neither value reaches a log.
    """

    issuer: str
    audience: str

    def __repr__(self) -> str:  # never the issuer / audience
        return "ReviewedAuthority(<redacted>)"


@dataclass(frozen=True)
class DeviceEndpoints:
    """The discovered, safety-checked issuer endpoints. Redacted repr.

    ``revocation_endpoint`` is ``None`` when the issuer does not advertise one: RFC 8414 §2 makes it
    OPTIONAL, so a conforming provider may simply not offer revocation. It is the only endpoint here
    that is allowed to be absent, and ``auth logout`` reports that absence rather than treating it
    as a successful revocation.
    """

    device_authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    revocation_endpoint: str | None = None

    def __repr__(self) -> str:
        return "DeviceEndpoints(<redacted>)"


class DeviceAuthorizationClient:
    """Retrieves the reviewed authority, discovers the issuer's device endpoints, starts the grant,
    and polls the token endpoint. Non-serializable with a constant redacted repr."""

    __slots__ = ("_locator", "_require_https", "_timeout", "_client_factory", "_pinned_factory")

    def __init__(
        self,
        *,
        locator: ControllerApiLocator,
        require_https: bool = True,
        timeout: float = _DEFAULT_TIMEOUT,
        client_factory: Any = None,
        pinned_client_factory: Any = None,
    ) -> None:
        """``require_https`` defaults to ``True``: the shipped composition refuses a plaintext
        issuer. Tests (and only tests) relax it explicitly. ``client_factory`` /
        ``pinned_client_factory`` are seams so the transports are exercisable without a socket; the
        shipped defaults build the hardened clients described in the module docstring."""
        self._locator = locator
        self._require_https = require_https
        self._timeout = timeout
        self._client_factory = client_factory
        self._pinned_factory = pinned_client_factory

    def __reduce__(self) -> NoReturn:
        _reject("secpctl_device_client_not_serializable")

    def __getstate__(self) -> NoReturn:
        _reject("secpctl_device_client_not_serializable")

    def __repr__(self) -> str:  # never the locator / issuer / CA path
        return "DeviceAuthorizationClient(<redacted>)"

    # --- transports ------------------------------------------------------------------------------

    def _issuer_client(self) -> Any:
        """Bounded, redirect-disabled, env-disabled client verified against SYSTEM trust — the
        reviewed posture for talking to an external OIDC issuer (mirrors ``secp_api/oidc.py``)."""
        if self._client_factory is not None:
            return self._client_factory()
        import httpx

        timeout = httpx.Timeout(
            self._timeout,
            connect=self._timeout,
            read=self._timeout,
            write=self._timeout,
            pool=self._timeout,
        )
        return httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False)

    def _controller_client(self) -> Any:
        """Bounded client PINNED to the bootstrap-recorded controller CA — never system trust,
        never ``True``/``False``."""
        if self._pinned_factory is not None:
            return self._pinned_factory()
        import ssl

        import httpx

        context = ssl.create_default_context(cafile=self._locator.ca_bundle_path)
        return httpx.Client(
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=self._timeout,
        )

    # --- steps -----------------------------------------------------------------------------------

    def reviewed_authority(self) -> ReviewedAuthority:
        """Read the issuer + audience from the controller's EXISTING public auth-config route.

        The route is consumed unchanged; nothing CLI-specific was added to it. A ``dev_fallback``
        controller has no real issuer to authenticate against, so it refuses rather than pretending.
        """
        url = self._locator.canonical_origin + _AUTH_CONFIG_PATH
        try:
            with self._controller_client() as client, client.stream("GET", url) as response:
                if response.status_code // 100 != 2:
                    _reject("secpctl_controller_unavailable")
                _refuse_encoded(response, reason="secpctl_controller_response_invalid")
                raw = _read_bounded(
                    response,
                    max_bytes=_MAX_DOCUMENT_BYTES,
                    reason="secpctl_controller_response_invalid",
                )
        except ManagementError:
            raise
        except Exception:  # noqa: BLE001 - transport failure never leaks origin / CA / exception
            _reject("secpctl_controller_transport_failed")

        body = _decode_json_object(raw, reason="secpctl_controller_response_invalid")
        if body.get("mode") != "oidc":
            _reject("secpctl_device_authority_not_oidc")
        issuer = _require_safe_url(
            body.get("issuer"),
            require_https=self._require_https,
            reason="secpctl_device_authority_invalid",
        )
        audience = body.get("audience")
        if not isinstance(audience, str) or not audience or len(audience) > 255:
            _reject("secpctl_device_authority_invalid")
        return ReviewedAuthority(issuer=issuer.rstrip("/"), audience=audience)

    def _issuer_document(self, url: str, *, reason: str) -> dict[str, Any]:
        try:
            with self._issuer_client() as client, client.stream("GET", url) as response:
                if response.status_code // 100 != 2:
                    _reject("secpctl_device_provider_unavailable")
                _refuse_encoded(response, reason=reason)
                raw = _read_bounded(response, max_bytes=_MAX_DOCUMENT_BYTES, reason=reason)
        except ManagementError:
            raise
        except Exception:  # noqa: BLE001
            _reject("secpctl_device_provider_unavailable")
        return _decode_json_object(raw, reason=reason)

    def discover(self, authority: ReviewedAuthority) -> DeviceEndpoints:
        """Discover the issuer's endpoints. The device-authorization endpoint is READ from the
        ``.well-known`` document, never constructed; a provider that does not advertise the device
        grant is reported as exactly that limitation and never downgraded to another grant."""
        document = self._issuer_document(
            authority.issuer + _DISCOVERY_PATH, reason="secpctl_device_discovery_invalid"
        )
        # The discovery issuer must EXACTLY equal the reviewed issuer (no substitution).
        if document.get("issuer") != authority.issuer:
            _reject("secpctl_device_discovery_invalid")

        endpoint = document.get("device_authorization_endpoint")
        if endpoint is None:
            _reject("secpctl_device_grant_unsupported")
        grant_types = document.get("grant_types_supported")
        if isinstance(grant_types, list) and DEVICE_CODE_GRANT_TYPE not in grant_types:
            _reject("secpctl_device_grant_unsupported")

        # RFC 8414 §2 — `revocation_endpoint` is OPTIONAL. An ABSENT member is a provider that does
        # not offer revocation and is reported as such; a PRESENT but malformed one is a refusal,
        # never a silent downgrade to "no revocation", because that would turn a broken discovery
        # document into a logout that quietly leaves the token live.
        revocation_raw = document.get("revocation_endpoint")
        revocation_endpoint: str | None = None
        if revocation_raw is not None:
            revocation_endpoint = _require_safe_url(
                revocation_raw,
                # RFC 7009 §2: "URLs for token revocation endpoints MUST be HTTPS URLs." The
                # `require_https` seam still applies so the test transport can drive plain HTTP,
                # exactly as it does for every other endpoint here.
                require_https=self._require_https,
                reason="secpctl_device_discovery_invalid",
            )

        return DeviceEndpoints(
            device_authorization_endpoint=_require_safe_url(
                endpoint,
                require_https=self._require_https,
                reason="secpctl_device_discovery_invalid",
            ),
            token_endpoint=_require_safe_url(
                document.get("token_endpoint"),
                require_https=self._require_https,
                reason="secpctl_device_discovery_invalid",
            ),
            jwks_uri=_require_safe_url(
                document.get("jwks_uri"),
                require_https=self._require_https,
                reason="secpctl_device_discovery_invalid",
            ),
            revocation_endpoint=revocation_endpoint,
        )

    def fetch_jwks(self, endpoints: DeviceEndpoints) -> dict[str, Any]:
        """Retrieve the issuer's JWKS document (projected to ``kid`` -> JWK by the verifier)."""
        return self._issuer_document(
            endpoints.jwks_uri, reason="secpctl_operator_token_jwks_invalid"
        )

    def request_device_authorization(self, endpoints: DeviceEndpoints) -> DeviceAuthorization:
        """RFC 8628 §3.1 — start the grant. A public client presents only ``client_id``; there is no
        client secret and none is ever sent."""
        form = {"client_id": OPERATOR_CLI_CLIENT_ID, "scope": OPERATOR_CLI_SCOPE}
        try:
            with self._issuer_client() as client:
                response = client.post(
                    endpoints.device_authorization_endpoint,
                    data=form,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                )
                if response.is_redirect:
                    _reject("secpctl_device_authorization_invalid")
                if response.status_code // 100 != 2:
                    _reject("secpctl_device_authorization_refused")
                raw = response.content
                if len(raw) > _MAX_TOKEN_RESPONSE_BYTES:
                    _reject("secpctl_device_authorization_invalid")
        except ManagementError:
            raise
        except Exception:  # noqa: BLE001
            _reject("secpctl_device_provider_unavailable")
        body = _decode_json_object(raw, reason="secpctl_device_authorization_invalid")
        return parse_device_authorization(body, require_https=self._require_https)

    def request_token(self, endpoints: DeviceEndpoints, device_code: DeviceCode) -> tuple[str, str]:
        """One RFC 8628 §3.4 token attempt.

        Returns ``(access_token, "")`` on success or ``("", error_code)`` on a provider-reported
        error, so the PURE scheduler decides whether to keep polling. The raw token is returned to
        the immediate caller for wrapping and is never logged, cached, or written anywhere here.
        """
        form = {
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "device_code": device_code.token_request_value(),
            "client_id": OPERATOR_CLI_CLIENT_ID,
        }
        try:
            with self._issuer_client() as client:
                response = client.post(
                    endpoints.token_endpoint,
                    data=form,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                )
                if response.is_redirect:
                    _reject("secpctl_device_token_refused")
                raw = response.content
                if len(raw) > _MAX_TOKEN_RESPONSE_BYTES:
                    _reject("secpctl_device_token_refused")
                status = response.status_code
        except ManagementError:
            raise
        except Exception:  # noqa: BLE001
            _reject("secpctl_device_provider_unavailable")

        body = _decode_json_object(raw, reason="secpctl_device_token_refused")
        if status // 100 == 2:
            access_token = body.get("access_token")
            if not isinstance(access_token, str) or not access_token:
                _reject("secpctl_device_token_refused")
            token_type = body.get("token_type")
            if not isinstance(token_type, str) or token_type.lower() != "bearer":
                _reject("secpctl_device_token_refused")
            # RFC 6749 §5.1 — `scope` is OPTIONAL when identical to the request and REQUIRED when it
            # differs, so an absent member means "what we asked for". A present one is checked
            # against the scope policy BEFORE the token is handed back, so a grant the provider
            # widened to `offline_access` is refused at the point of issue rather than discovered
            # later in a claim.
            validate_granted_scope(body.get("scope"))
            # A public client is issued no refresh token, and one arriving unasked means the grant
            # is not the posture this CLI is built on. Refuse rather than hold a credential whose
            # lifetime nothing here manages.
            if body.get("refresh_token") is not None:
                _reject("secpctl_device_refresh_token_unexpected")
            return access_token, ""
        error = body.get("error")
        if not isinstance(error, str) or not error or len(error) > 64:
            _reject("secpctl_device_token_refused")
        return "", error

    def revoke_token(self, endpoints: DeviceEndpoints, token: str) -> RevocationOutcome:
        """RFC 7009 §2.1 — ask the issuer to revoke this access token.

        Returns a bounded :class:`~secp_management.operator_token_revoke.RevocationOutcome` and
        NEVER raises on a provider answer or a transport failure. That is deliberate and is the
        whole contract of this method: ``auth logout`` must reach its LOCAL deletion whatever the
        provider does, so an unreachable issuer can never strand a credential on the workstation.
        The outcome still records that the token must be assumed live, so nothing is hidden.

        The token travels in the request BODY, never in a query string or a header — a revocation
        endpoint's access log is exactly where a bearer credential must not land.
        """
        if not endpoints.revocation_endpoint:
            return revocation_unsupported()

        form = revocation_form(token=token, client_id=OPERATOR_CLI_CLIENT_ID)
        try:
            with self._issuer_client() as client:
                response = client.post(
                    endpoints.revocation_endpoint,
                    data=form,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                )
                if response.is_redirect:
                    # A redirect would forward the token to an unreviewed host. Never follow it, and
                    # never treat it as a revocation.
                    return RevocationOutcome(
                        OUTCOME_REFUSED, reason_code="secpctl_revocation_refused"
                    )
                raw = response.content
                status = response.status_code
        except ManagementError:
            raise
        except Exception:  # noqa: BLE001 - transport failure never leaks endpoint / token / chain
            return RevocationOutcome(
                OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
            )

        # A 200 is authoritative on its own (RFC 7009 §2.2 defines no success body), so a provider
        # that answers 200 with an empty or non-JSON body is still a successful revocation. Only an
        # ERROR body needs parsing, and a body that will not parse simply yields no error code.
        error: object = None
        if raw and status // 100 != 2 and len(raw) <= _MAX_TOKEN_RESPONSE_BYTES:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:  # noqa: BLE001 - an unparseable error body is simply no error code
                parsed = None
            if isinstance(parsed, dict):
                error = parsed.get("error")
        return interpret_revocation_response(status, error=error)


__all__ = [
    "OPERATOR_CLI_CLIENT_ID",
    "OPERATOR_CLI_SCOPE",
    "DeviceAuthorizationClient",
    "DeviceEndpoints",
    "OperatorDeviceAuthError",
    "ReviewedAuthority",
]
