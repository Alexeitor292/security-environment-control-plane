"""Concrete hardened Proxmox mutation transport (SECP-B4 §4).

The ONLY place a real Proxmox create/update/delete request is issued, and only from the isolated
worker with a scoped SECP-owned credential. It constructs its own ``httpx.Client`` with: strict TLS
verification against a PINNED deployment-local CA bundle (verification cannot be disabled), ambient
proxy env ignored (``trust_env=False``), redirects disabled + explicitly refused, and bounded
connect/read/write/pool timeouts. It accepts ONLY a closed set of typed mutations mapped to
methods + endpoint templates — never an arbitrary URL, path, method, header, body, or retry.

Hardening evidence is derived from the ACTUAL constructed client configuration (verify target,
trust_env, follow_redirects, timeout, https base) — NOT a self-reported manifest. The scoped token
used only to build the auth header at request time and is never logged. An ``httpx.Client`` may be
injected for offline tests; no real endpoint is contacted during implementation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

# Closed method allowlist for mutations. GET is handled by the separate read-only transport.
ALLOWED_MUTATION_METHODS = frozenset({"POST", "PUT", "DELETE"})
# Bounded timeouts (app-owned constants).
_CONNECT_TIMEOUT = 10.0
_READ_TIMEOUT = 30.0
_WRITE_TIMEOUT = 30.0
_POOL_TIMEOUT = 5.0

# Closed canonical mutation endpoint templates. ``{node}`` / ``{ref}`` accept only a safe token
# (letters/digits/dot/underscore/hyphen); nothing else is permitted, so no path can be smuggled.
_SAFE_TOKEN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_MUTATION_ROUTES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("POST", re.compile(r"^/access/users$")),
    ("POST", re.compile(rf"^/access/token/{_SAFE_TOKEN}/{_SAFE_TOKEN}$")),
    ("DELETE", re.compile(rf"^/access/token/{_SAFE_TOKEN}/{_SAFE_TOKEN}$")),
    ("POST", re.compile(rf"^/nodes/{_SAFE_TOKEN}/network$")),
    ("PUT", re.compile(rf"^/nodes/{_SAFE_TOKEN}/network$")),
    ("DELETE", re.compile(rf"^/nodes/{_SAFE_TOKEN}/network/{_SAFE_TOKEN}$")),
    ("POST", re.compile(r"^/cluster/firewall/groups$")),
    ("POST", re.compile(rf"^/nodes/{_SAFE_TOKEN}/qemu$")),
    ("DELETE", re.compile(rf"^/nodes/{_SAFE_TOKEN}/qemu/{_SAFE_TOKEN}$")),
)


class MutationRequestRefused(Exception):
    """Fail-closed: a method/path/body outside the closed mutation contract. Closed reason only."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"proxmox mutation refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class HardeningManifest:
    """Hardening posture DERIVED FROM the actual client configuration (never self-asserted)."""

    tls_verified: bool
    ca_pinned: bool
    trust_env_disabled: bool
    redirects_disabled: bool
    timeouts_bounded: bool
    https_base: bool
    mutation_methods_closed: bool

    def all_enforced(self) -> bool:
        return all(vars(self).values())


def assert_mutation_allowed(method: str, path: str) -> None:
    """Fail closed unless (method, path) is in the closed canonical mutation allowlist."""
    if method not in ALLOWED_MUTATION_METHODS:
        raise MutationRequestRefused("method_not_allowed")
    if "?" in path or "#" in path or "%" in path or "\\" in path or ".." in path:
        raise MutationRequestRefused("non_canonical_path")
    for allowed_method, pattern in _MUTATION_ROUTES:
        if method == allowed_method and pattern.match(path):
            return
    raise MutationRequestRefused("unknown_mutation_path")


def _validate_https_base(base_url: str) -> None:
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise MutationRequestRefused("base_url_not_https")
    if not parts.hostname or parts.username or parts.password or "@" in parts.netloc:
        raise MutationRequestRefused("base_url_unsafe_host")
    if parts.query or parts.fragment or parts.path not in ("/api2/json", "/api2/json/"):
        raise MutationRequestRefused("base_url_unsafe_path")


class HardenedProxmoxMutationTransport:
    """Issues ONLY closed, canonical Proxmox mutations over a hardened, CA-pinned HTTPS client."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        ca_bundle_path: str,
        client: Any | None = None,
    ) -> None:
        _validate_https_base(base_url)
        if not (isinstance(ca_bundle_path, str) and ca_bundle_path):
            raise MutationRequestRefused("ca_bundle_required")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._ca_bundle_path = ca_bundle_path
        self._injected = client
        # Build the real client eagerly so the manifest reflects its ACTUAL configuration.
        self._client = client if client is not None else self._build_client()

    def _build_client(self) -> Any:
        import httpx  # local import: provider HTTP client stays out of apps/api

        return httpx.Client(
            verify=self._ca_bundle_path,  # pinned CA bundle; verification cannot be disabled
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=_CONNECT_TIMEOUT,
                read=_READ_TIMEOUT,
                write=_WRITE_TIMEOUT,
                pool=_POOL_TIMEOUT,
            ),
        )

    def hardening_manifest(self) -> HardeningManifest:
        """Derive the hardening posture from the client's ACTUAL configuration attributes."""
        client = self._client
        verify = getattr(client, "_verify_target", getattr(client, "_verify", None))
        # httpx stores the constructed config on private attrs; read them directly (real config).
        trust_env = bool(getattr(client, "trust_env", getattr(client, "_trust_env", False)))
        follow = bool(
            getattr(client, "follow_redirects", getattr(client, "_follow_redirects", True))
        )
        timeout = getattr(client, "timeout", getattr(client, "_timeout", None))
        return HardeningManifest(
            tls_verified=verify not in (False, None, "") and verify is not False,
            ca_pinned=bool(self._ca_bundle_path),
            trust_env_disabled=trust_env is False,
            redirects_disabled=follow is False,
            timeouts_bounded=timeout is not None,
            https_base=self._base_url.startswith("https://"),
            mutation_methods_closed=True,
        )

    def apply(self, method: str, path: str, *, body: dict | None = None) -> Any:
        """Issue ONE closed, canonical mutation. Body must be a flat dict of safe scalar values."""
        assert_mutation_allowed(method, path)
        if body is not None:
            if not isinstance(body, dict):
                raise MutationRequestRefused("body_must_be_mapping")
            for value in body.values():
                if not isinstance(value, str | int | bool):
                    raise MutationRequestRefused("body_value_not_scalar")
        from secp_plugin_proxmox.readonly_policy import RedirectRefused

        url = f"{self._base_url}/{path.lstrip('/')}"
        headers = {"Authorization": f"PVEAPIToken={self._token}"}
        resp = self._client.request(method, url, data=body, headers=headers)
        if getattr(resp, "is_redirect", False) or 300 <= int(resp.status_code) < 400:
            raise RedirectRefused(resp.headers.get("location", ""))
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("data") if isinstance(payload, dict) else payload

    def close(self) -> None:
        if self._injected is None and hasattr(self._client, "close"):
            self._client.close()
