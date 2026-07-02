"""Offline, canned fake read-only transport for the Proxmox plugin (SECP-002B-1B-3).

``FakeProxmoxReadOnlyTransport`` conforms to the existing ``ReadOnlyHttpTransport`` protocol and
returns **canned in-memory responses only**. It is structurally incapable of network I/O: this
module imports no HTTP client, socket, subprocess, or provider SDK — only stdlib typing. It is
injected through the existing ``ProxmoxPlugin(transport_factory=...)`` seam in **tests only**;
it is never wired into any runtime collection path and never persists evidence.

Every request is checked against the closed read-only policy (:mod:`readonly_policy`) BEFORE any
response lookup: GET-only, closed path allowlist, and cross-host/absolute-URL refusal. A canned
response may be a :class:`RedirectResponse`, which the transport refuses (redirects are never
followed).
"""

from __future__ import annotations

from typing import Any

from secp_plugin_proxmox.readonly_policy import (
    RedirectRefused,
    assert_no_params,
    assert_request_allowed,
    is_absolute_or_cross_host,
)
from secp_plugin_proxmox.transport import ReadOnlyHttpTransport


class RedirectResponse:
    """A canned marker standing in for an HTTP redirect the server might return."""

    def __init__(self, location: str) -> None:
        self.location = location


class FakeProxmoxReadOnlyTransport:
    """GET-only, allowlist-enforcing, offline transport backed by a canned response map.

    ``responses`` maps concrete Proxmox GET paths (e.g. ``/nodes/node-a/storage``) to canned
    ``data`` payloads (already unwrapped from Proxmox's ``{"data": ...}`` envelope), or to a
    :class:`RedirectResponse`. Missing allowlisted paths return ``[]``. Non-GET methods,
    non-allowlisted paths, and cross-host/absolute URLs are refused before lookup.
    """

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self._responses: dict[str, Any] = dict(responses or {})
        # Recorded (method, path) tuples so tests can assert GET-only behaviour.
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, params: dict | None = None) -> Any:
        # Refuse mutating methods / cross-host / unknown paths / query params BEFORE any lookup.
        assert_request_allowed(method, path)
        assert_no_params(params)
        self.calls.append((method.upper(), path))
        value = self._responses.get(path, [])
        if isinstance(value, RedirectResponse):
            raise RedirectRefused(value.location)
        return value

    def get(self, path: str, params: dict | None = None) -> Any:
        return self.request("GET", path, params)

    def follow(self, location: str) -> Any:
        """A redirect target is always cross-host/absolute here and is refused."""
        if is_absolute_or_cross_host(location):
            raise RedirectRefused(location)
        # Even a relative redirect is not followed by a read-only transport.
        raise RedirectRefused(location)


# Structural conformance guard (evaluated at import; costs nothing at runtime).
_: ReadOnlyHttpTransport = FakeProxmoxReadOnlyTransport()


def fake_transport_factory(responses: dict[str, Any] | None = None):
    """Build a ``transport_factory`` for ``ProxmoxPlugin`` that yields a fake transport.

    Test-only helper. The returned factory ignores the (config, token) arguments — the fake
    transport neither resolves secrets nor contacts anything.
    """

    def factory(config: dict, token: str) -> FakeProxmoxReadOnlyTransport:
        return FakeProxmoxReadOnlyTransport(responses)

    return factory
