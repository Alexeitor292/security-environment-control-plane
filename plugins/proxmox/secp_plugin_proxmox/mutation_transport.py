"""Concrete hardened Proxmox mutation transport (SECP-B4 §4, corrective).

The ONLY place a real Proxmox create/update/delete request is issued, and only from the isolated
worker with a scoped SECP-owned credential. It ALWAYS constructs its OWN ``httpx.Client`` (there is
no injectable client to trust in production) with: strict TLS verification against a PINNED
deployment-local CA bundle loaded eagerly at construction (a missing/invalid CA fails closed
immediately, and verification cannot be disabled), ambient proxy env ignored (``trust_env=False``),
redirects disabled + explicitly refused, and bounded connect/read/write/pool timeouts. It accepts
ONLY a closed set of canonical mutation routes (method + path template) — never an arbitrary URL,
path, method, header, body, or retry.

Hardening evidence is derived from the ACTUAL constructed client (its real ``trust_env`` /
``follow_redirects`` / ``timeout`` attributes) plus the fact that the client was built by this
transport with a pinned CA that loaded successfully — not a self-reported flag and not an injected
client's claims. Because httpx consumes ``verify`` into the transport SSL context (it is not a
readable client attribute), TLS/CA evidence is taken from this transport having built the client
with
a pinned CA that eagerly loaded. The scoped token builds the auth header at request time and is
never
logged. No real endpoint is contacted during implementation (routes are only issued from a real
worker against the disposable staging target during the controlled integration phase).
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

# Closed canonical mutation route templates. ``{token}`` accepts only a safe token
# (letters/digits/dot/underscore/hyphen); ``{userid}`` additionally allows a single ``@realm``.
# Nothing else is permitted, so no path can be smuggled. These mirror the typed mutation ops.
_SAFE = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_USERID = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9._-]{0,31}"
_MUTATION_ROUTES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("POST", re.compile(r"^/access/users$")),
    ("DELETE", re.compile(rf"^/access/users/{_USERID}$")),
    ("POST", re.compile(rf"^/access/users/{_USERID}/token/{_SAFE}$")),
    ("DELETE", re.compile(rf"^/access/users/{_USERID}/token/{_SAFE}$")),
    ("POST", re.compile(rf"^/nodes/{_SAFE}/network$")),
    ("PUT", re.compile(rf"^/nodes/{_SAFE}/network$")),
    ("DELETE", re.compile(rf"^/nodes/{_SAFE}/network/{_SAFE}$")),
    ("POST", re.compile(r"^/cluster/firewall/groups$")),
    ("DELETE", re.compile(rf"^/cluster/firewall/groups/{_SAFE}$")),
    ("POST", re.compile(rf"^/nodes/{_SAFE}/qemu$")),
    ("DELETE", re.compile(rf"^/nodes/{_SAFE}/qemu/{_SAFE}$")),
)


class MutationRequestRefused(Exception):
    """Fail-closed: a method/path/body outside the closed mutation contract. Closed reason only."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"proxmox mutation refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class HardeningManifest:
    """Hardening posture DERIVED FROM the actual constructed client + pinned-CA construction."""

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


def _timeout_bounded(timeout: object) -> bool:
    """A bounded httpx.Timeout has all four phases set to finite positive numbers."""
    phases = [getattr(timeout, p, None) for p in ("connect", "read", "write", "pool")]
    return all(isinstance(v, (int, float)) and v and v > 0 for v in phases)


class HardenedProxmoxMutationTransport:
    """Issues ONLY closed, canonical Proxmox mutations over a hardened, CA-pinned HTTPS client it
    constructs itself. There is no injectable client — production trusts only the client it
    builds."""

    def __init__(self, base_url: str, token: str, *, ca_bundle_path: str) -> None:
        _validate_https_base(base_url)
        if not (isinstance(ca_bundle_path, str) and ca_bundle_path):
            raise MutationRequestRefused("ca_bundle_required")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._ca_bundle_path = ca_bundle_path
        # Build the real client eagerly: verify=<ca> is loaded now, so a missing/invalid CA fails
        # closed at construction, and the manifest reflects the ACTUAL constructed client.
        self._client = self._build_client()

    def _build_client(self) -> Any:
        import httpx  # local import: provider HTTP client stays out of apps/api

        return httpx.Client(
            verify=self._ca_bundle_path,  # pinned CA bundle; eagerly loaded; cannot be disabled
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
        """Derive hardening from the ACTUAL constructed client + pinned-CA construction."""
        client = self._client
        trust_env = bool(getattr(client, "trust_env", True))
        follow = bool(getattr(client, "follow_redirects", True))
        timeout = getattr(client, "timeout", None)
        # TLS/CA: this transport built the client with verify=<ca_bundle_path>, which httpx loads
        # eagerly at construction — reaching this point means the pinned CA loaded successfully.
        ca_pinned = bool(self._ca_bundle_path)
        return HardeningManifest(
            tls_verified=ca_pinned,
            ca_pinned=ca_pinned,
            trust_env_disabled=trust_env is False,
            redirects_disabled=follow is False,
            timeouts_bounded=_timeout_bounded(timeout),
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
        if hasattr(self._client, "close"):
            self._client.close()
