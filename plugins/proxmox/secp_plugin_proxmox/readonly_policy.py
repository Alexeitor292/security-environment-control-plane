"""Closed, deterministic read-only request-safety policy for the Proxmox plugin (SECP-002B-1B-3).

This is a **pure**, offline policy component used by ``FakeProxmoxReadOnlyTransport`` only in
this PR. It encodes the ADR-015 non-mutation contract as data + deterministic rules:

* ``GET`` is the sole permitted method (refused before any response lookup).
* Only a **closed allowlist** of public Proxmox GET path templates is permitted — the exact
  read endpoints needed for the future evidence categories (nodes, storage, network segments,
  VM-ID / resource inventory, capacity / quotas, and approved isolation observations).
* Unknown paths are refused before lookup.
* Absolute URLs / cross-host destinations are refused.

It performs no I/O, imports no HTTP/socket/subprocess/provider SDK, and contacts nothing. It
does not enable, construct, or invoke any real collector. Task/console/guest-agent/backup/
upload/download/create/config/delete/firewall/network-mutation/ACL/token endpoints are simply
**absent** from the allowlist and therefore refused.
"""

from __future__ import annotations

from collections.abc import Iterable

from secp_plugin_proxmox.transport import ALLOWED_METHODS, MutatingRequestRefused

# Bump when the allowlist changes. Surfaced as the "endpoint-allowlist version" that a future
# collector would fold into its job-binding fingerprint (ADR-015 §4/§5).
PROXMOX_READONLY_POLICY_VERSION = "secp-002b-1b-3/proxmox-readonly-allowlist/v1"

# Closed allowlist of public Proxmox GET path templates. ``{param}`` matches exactly one
# non-empty path segment (no slashes). Nothing outside this set is permitted.
ALLOWED_PATH_TEMPLATES: tuple[str, ...] = (
    # nodes + node status / capacity
    "/nodes",
    "/nodes/{node}",
    "/nodes/{node}/status",
    # storage inventory
    "/nodes/{node}/storage",
    "/storage",
    # VM-ID / resource inventory
    "/nodes/{node}/qemu",
    "/nodes/{node}/lxc",
    "/cluster/resources",
    # network segments + approved isolation observations (read-only)
    "/nodes/{node}/network",
    "/cluster/sdn/vnets",
    "/cluster/sdn/zones",
)


class UnknownPathRefused(Exception):
    """Raised when a path is not on the closed read-only allowlist."""

    def __init__(self, path: str):
        self.path = path
        super().__init__(f"refused non-allowlisted read-only path {path!r}")


class RedirectRefused(Exception):
    """Raised when a canned response models an HTTP redirect (never followed)."""

    def __init__(self, location: str):
        self.location = location
        super().__init__("refused redirect: the read-only transport never follows redirects")


class CrossHostRequestRefused(Exception):
    """Raised when a request path is absolute / targets a host other than the approved one."""

    def __init__(self, path: str):
        self.path = path
        super().__init__(f"refused cross-host / absolute destination {path!r}")


def _segments(path: str) -> list[str]:
    # Strip any query string; split into non-empty segments.
    base = path.split("?", 1)[0]
    return [s for s in base.split("/") if s != ""]


def _matches(template: str, segments: list[str]) -> bool:
    tmpl = _segments(template)
    if len(tmpl) != len(segments):
        return False
    for t, s in zip(tmpl, segments, strict=True):
        if t.startswith("{") and t.endswith("}"):
            # placeholder: any single non-empty segment, but never a traversal token
            if s in ("", ".", ".."):
                return False
            continue
        if t != s:
            return False
    return True


def is_absolute_or_cross_host(path: str) -> bool:
    """True when the path is an absolute URL or otherwise escapes the approved host."""
    lowered = path.strip().lower()
    return "://" in lowered or lowered.startswith("//") or lowered.startswith("\\\\")


def path_is_allowed(path: str) -> bool:
    """Deterministic: True iff ``path`` matches exactly one allowlisted GET template."""
    if is_absolute_or_cross_host(path):
        return False
    segments = _segments(path)
    if not segments or any(seg == ".." for seg in segments):
        return False
    return any(_matches(t, segments) for t in ALLOWED_PATH_TEMPLATES)


def assert_request_allowed(method: str, path: str) -> None:
    """Enforce the closed policy BEFORE any response lookup. Raises on any violation.

    Order matters: method is checked first, then absolute/cross-host, then the allowlist.
    """
    if method.upper() not in ALLOWED_METHODS:
        raise MutatingRequestRefused(method)
    if is_absolute_or_cross_host(path):
        raise CrossHostRequestRefused(path)
    if not path_is_allowed(path):
        raise UnknownPathRefused(path)


def allowlisted_templates() -> Iterable[str]:
    return ALLOWED_PATH_TEMPLATES
