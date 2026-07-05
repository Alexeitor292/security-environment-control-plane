"""Concrete, narrowly-scoped OpenBao client for the staging-live composition (SECP-B2-5-pre).

All external behaviour is INJECTED through a mockable transport, so the client is fully testable
offline. The client uses ONLY the authoritative ``vault:`` reference already re-verified by the
existing resolver (validated against the repository's existing opaque vault-locator grammar), maps
every backend outcome to a CLOSED, secret-free reason code, and never logs/persists/renders a secret
reference, response body, token, endpoint, certificate, or raw backend error. A backend
authentication self-test proves authentication WITHOUT resolving or returning a secret. No concrete
client/transport is constructed in normal runtime, and none contacts a network at construction.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from secp_api.secret_refs import InvalidSecretRefError, parse_secret_ref

from secp_worker.preflight.backends.openbao_resolver import ResolverSelfTestResult


class OpenBaoClientError(Exception):
    """Fail-closed error. Carries ONLY a closed reason code (never a value or response)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"openbao client refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class OpenBaoSelfTestResult:
    """Closed, redacted result of a backend authentication self-test (never a secret)."""

    ok: bool
    reason_code: str


@runtime_checkable
class OpenBaoBackendTransport(Protocol):
    """Injected, mockable OpenBao transport. A real implementation (deployment-only) enforces
    HTTPS/TLS verification, no redirects, ``trust_env=False``, and a bounded timeout; tests inject a
    fake. ``authenticate`` proves auth returning NO secret; ``read`` returns the backend payload."""

    def authenticate(self, *, now: datetime) -> None: ...
    def read(self, *, locator: str, now: datetime) -> Mapping[str, Any]: ...


class SealedOpenBaoBackendTransport:
    """The shipped default: NO transport. Auth/read refuse — no network, no endpoint."""

    def authenticate(self, *, now: datetime) -> None:
        raise OpenBaoClientError("openbao_transport_sealed")

    def read(self, *, locator: str, now: datetime) -> Mapping[str, Any]:
        raise OpenBaoClientError("openbao_transport_sealed")


def validate_openbao_base_url(base_url: str) -> None:
    """A base URL (used only by a REAL transport, out of band) must be HTTPS with no userinfo/query/
    fragment/escape. Validated so a malformed endpoint can never be accepted; the value is never
    logged or returned."""
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise OpenBaoClientError("base_url_not_https")
    if not parts.hostname:
        raise OpenBaoClientError("base_url_missing_host")
    if parts.username or parts.password or "@" in parts.netloc:
        raise OpenBaoClientError("base_url_has_userinfo")
    if parts.query or parts.fragment:
        raise OpenBaoClientError("base_url_has_query_or_fragment")
    if (
        "\\" in parts.path
        or "%" in parts.path
        or any(seg in (".", "..") for seg in parts.path.split("/"))
    ):
        raise OpenBaoClientError("base_url_unsafe_path")


def _valid_vault_locator(reference: str) -> str:
    """Return the opaque locator of a syntactically valid ``vault:`` reference, else fail closed.

    No endpoint substitution, dynamic host, or uncontrolled path construction: the caller reads ONLY
    the exact re-verified reference's opaque locator (validated by the existing grammar).
    """
    if not (isinstance(reference, str) and reference.strip()):
        raise OpenBaoClientError("blank_reference")
    try:
        scheme, locator = parse_secret_ref(reference)
    except InvalidSecretRefError as exc:
        raise OpenBaoClientError("malformed_reference") from exc
    if scheme != "vault":
        raise OpenBaoClientError("unsupported_reference_scheme")
    return locator


class ConcreteOpenBaoClient:
    """Implements the ``OpenBaoHttpClient`` seam (``read_secret``) over an injected transport.

    NOT a shipped default — supplied only to the staging-live composition. It resolves ONLY the
    authoritative re-verified reference, maps errors to closed codes, and returns opaque secret text
    to the resolver (which wraps it as short-lived ``SecretMaterial``); it logs/persists nothing.
    """

    def __init__(self, *, transport: OpenBaoBackendTransport) -> None:
        self._transport = transport

    def self_test(self, *, now: datetime) -> OpenBaoSelfTestResult:
        """Authentication canary: prove the client can authenticate WITHOUT resolving any secret."""
        try:
            self._transport.authenticate(now=now)
        except OpenBaoClientError as exc:
            return OpenBaoSelfTestResult(ok=False, reason_code=exc.reason_code)
        except Exception:  # never surface a raw backend error
            return OpenBaoSelfTestResult(ok=False, reason_code="authentication_failed")
        return OpenBaoSelfTestResult(ok=True, reason_code="authenticated")

    def read_secret(self, *, reference: str, now: datetime) -> str:
        locator = _valid_vault_locator(reference)
        try:
            response = self._transport.read(locator=locator, now=now)
        except OpenBaoClientError:
            raise
        except Exception as exc:  # closed mapping — never the raw backend error
            raise OpenBaoClientError("backend_unreachable") from exc
        secret = _extract_secret(response)
        if not secret:
            raise OpenBaoClientError("reference_unknown")
        return secret


def _extract_secret(response: Mapping[str, Any]) -> str:
    """Extract the secret string from a closed backend response shape. Never logs the value or
    any other field; a missing/unknown shape yields no secret (fail closed upstream)."""
    if not isinstance(response, Mapping):
        return ""
    value = response.get("value")
    return value if isinstance(value, str) and value else ""


class OpenBaoResolverSelfTest:
    """Adapts the client's authentication self-test to the resolver ``ResolverSelfTest`` seam
    (``run``). This lets the OpenBao readiness canary prove backend authentication through the SAME
    client the resolver would use to read a secret, without resolving one. Returns a closed,
    secret-free result."""

    def __init__(self, *, client: ConcreteOpenBaoClient) -> None:
        self._client = client

    def run(self, *, now: datetime) -> ResolverSelfTestResult:
        result = self._client.self_test(now=now)
        return ResolverSelfTestResult(ok=result.ok, reason_code=result.reason_code)
