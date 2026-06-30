"""Read-only HTTP transport for the Proxmox plugin.

The transport allows **GET only**. Any other method is rejected with
``MutatingRequestRefused`` BEFORE a request is sent — this is enforced in code, not
by convention (assignment §5, proof #3). The only public verb is ``get``.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

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


class HttpxReadOnlyTransport:
    """httpx-backed transport that can only issue GET requests.

    The token is used only to build the Authorization header at request time and
    is never logged. An ``httpx.Client`` may be injected for tests (so no real
    network access occurs). No real endpoint is contacted in SECP-002A.
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
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._verify_tls = verify_tls
        self._client = client
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        # Proxmox API-token auth header. Never logged.
        return {"Authorization": f"PVEAPIToken={self._token}"}

    def request(self, method: str, path: str, params: dict | None = None) -> Any:
        if method.upper() not in ALLOWED_METHODS:
            # Refuse BEFORE constructing or sending any request.
            raise MutatingRequestRefused(method)
        import httpx  # local import: provider HTTP client stays out of apps/api

        url = f"{self._base_url}/{path.lstrip('/')}"
        client = self._client or httpx.Client(verify=self._verify_tls, timeout=self._timeout)
        try:
            resp = client.get(url, params=params, headers=self._headers())
            resp.raise_for_status()
            payload = resp.json()
        finally:
            if self._client is None:
                client.close()
        # Proxmox wraps results in {"data": ...}.
        return payload.get("data") if isinstance(payload, dict) else payload

    def get(self, path: str, params: dict | None = None) -> Any:
        return self.request("GET", path, params)
