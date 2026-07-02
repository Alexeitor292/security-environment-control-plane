"""Read-only HTTP transport for the Proxmox plugin.

The transport allows **GET only**. Any other method is rejected with
``MutatingRequestRefused`` BEFORE a request is sent — this is enforced in code, not
by convention (assignment §5, proof #3). The only public verb is ``get``.

SECP-002B-1B-4 hardening: any future use is bound to the PR #10 closed canonical request
policy. Before a client is constructed or a request is sent, the transport calls
``assert_request_allowed`` (GET-only + canonical path + closed allowlist + cross-host refusal).
It constructs its own client with TLS verification forced on, ambient proxy env ignored
(``trust_env=False``), and redirects disabled + explicitly refused. TLS verification cannot be
disabled. The base URL must be HTTPS with no userinfo/query/fragment/escape. An ``httpx.Client``
may still be injected for offline tests. **No real endpoint is contacted anywhere in this
milestone** — the transport remains dormant behind the default-disabled live gate.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

ALLOWED_METHODS = frozenset({"GET"})


class MutatingRequestRefused(Exception):
    """Raised when any non-GET HTTP method is attempted on a read-only transport."""

    def __init__(self, method: str):
        self.method = method
        super().__init__(
            f"refused non-GET HTTP method '{method}': the Proxmox transport is "
            "read-only (GET only) in SECP-002A"
        )


@runtime_checkable
class ReadOnlyHttpTransport(Protocol):
    def get(self, path: str, params: dict | None = None) -> Any: ...


def _validate_base_url(base_url: str) -> None:
    """A base URL must be HTTPS with no userinfo, query, fragment, or unsafe path escape."""
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise ValueError("base_url must use https://")
    if not parts.hostname:
        raise ValueError("base_url must include a host")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ValueError("base_url must not contain userinfo")
    if parts.query:
        raise ValueError("base_url must not contain a query string")
    if parts.fragment:
        raise ValueError("base_url must not contain a fragment")
    if (
        "\\" in parts.path
        or "%" in parts.path
        or any(seg in (".", "..") for seg in parts.path.split("/"))
    ):
        raise ValueError("base_url path must not contain escapes or dot-segment traversal")
    # The Proxmox API root must normalize exactly to /api2/json (with or without a trailing
    # slash). An empty root or any other path is refused.
    if parts.path not in ("/api2/json", "/api2/json/"):
        raise ValueError("base_url path must be the Proxmox API root '/api2/json'")


class HttpxReadOnlyTransport:
    """httpx-backed transport that can only issue GET requests, bound to the closed policy.

    The token is used only to build the Authorization header at request time and is never
    logged. TLS verification cannot be disabled. An ``httpx.Client`` may be injected for tests
    (so no real network access occurs). No real endpoint is contacted in this milestone.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify_tls: bool = True,
        client: Any | None = None,
        timeout: float = 10.0,
    ) -> None:
        if verify_tls is not True:
            # TLS verification is mandatory; it cannot be disabled on this transport.
            raise ValueError("verify_tls cannot be disabled on the read-only Proxmox transport")
        _validate_base_url(base_url)
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._client = client
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        # Proxmox API-token auth header. Never logged.
        return {"Authorization": f"PVEAPIToken={self._token}"}

    def request(self, method: str, path: str, params: dict | None = None) -> Any:
        # Enforce the closed canonical request policy BEFORE constructing a client or sending:
        # GET-only, canonical path, closed allowlist, cross-host refusal, and NO query params
        # (this milestone allowlists none) (PR #10 / SECP-002B-1B-4).
        from secp_plugin_proxmox.readonly_policy import (
            RedirectRefused,
            assert_no_params,
            assert_request_allowed,
        )

        assert_request_allowed(method, path)
        assert_no_params(params)
        import httpx  # local import: provider HTTP client stays out of apps/api

        url = f"{self._base_url}/{path.lstrip('/')}"
        # Own client: verify TLS, ignore ambient proxy env, never follow redirects.
        client = self._client or httpx.Client(
            verify=True, trust_env=False, follow_redirects=False, timeout=self._timeout
        )
        try:
            resp = client.get(url, params=params, headers=self._headers())
            # Never follow a redirect; refuse it explicitly.
            if getattr(resp, "is_redirect", False) or 300 <= int(resp.status_code) < 400:
                raise RedirectRefused(resp.headers.get("location", ""))
            resp.raise_for_status()
            payload = resp.json()
        finally:
            if self._client is None:
                client.close()
        # Proxmox wraps results in {"data": ...}.
        return payload.get("data") if isinstance(payload, dict) else payload

    def get(self, path: str, params: dict | None = None) -> Any:
        return self.request("GET", path, params)
