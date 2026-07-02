"""Closed, deterministic read-only request-safety policy for the Proxmox plugin (SECP-002B-1B-3).

This is a **pure**, offline policy component used by ``FakeProxmoxReadOnlyTransport`` only in
this PR. It encodes the ADR-015 non-mutation contract as data + deterministic rules:

* ``GET`` is the sole permitted method (refused before any response lookup).
* Only a **closed allowlist** of public Proxmox GET path templates is permitted — the exact
  read endpoints needed for the future evidence categories (nodes, storage, network segments,
  VM-ID / resource inventory, capacity / quotas, and approved isolation observations).
* Unknown paths are refused before lookup.
* Absolute URLs / cross-host destinations are refused.
* Only **canonical absolute paths** are accepted: exactly one leading ``/`` and no query,
  fragment, matrix parameter, raw whitespace/control character, encoded delimiter, repeated
  slash, or dot-segment traversal (see :func:`canonical_path_violation`).

It performs no I/O, imports no HTTP/socket/subprocess/provider SDK, and contacts nothing. It
does not enable, construct, or invoke any real collector. Task/console/guest-agent/backup/
upload/download/create/config/delete/firewall/network-mutation/ACL/token endpoints are simply
**absent** from the allowlist and therefore refused.
"""

from __future__ import annotations

import re
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


class NonCanonicalPathRefused(Exception):
    """Raised when a path is non-canonical: its decoded/canonical form could differ from the
    literal path evaluated (encoded delimiters, backslashes, repeated slashes, traversal, or
    malformed percent-encoding). Refused BEFORE template matching or any response lookup."""

    def __init__(self, path: str, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f"refused non-canonical path {path!r}: {reason}")


# A well-formed percent triplet.
_PERCENT_TRIPLET_RE = re.compile(r"%[0-9A-Fa-f]{2}")
# Characters that, if produced by percent-decoding, would change path segmentation or endpoint
# semantics: path/segment delimiters, dot (traversal), reserved delimiters, whitespace, and any
# C0/C1 control byte (incl. NUL, CR, LF).
_DANGEROUS_DECODED: frozenset[str] = frozenset(
    set("/\\.")
    | {"?", "#", ";", "%", " "}
    | {chr(c) for c in range(0x00, 0x20)}  # C0 controls
    | {chr(0x7F)}  # DEL
    | {chr(c) for c in range(0x80, 0xA0)}  # C1 controls (0x80–0x9F)
)


def canonical_path_violation(path: str) -> str | None:
    """Return a reason if ``path`` is not a canonical absolute request path, else ``None``.

    The **entire** string is evaluated (not just the part before ``?``): the closed allowlist
    accepts only a canonical absolute path with no query, fragment, matrix parameter, raw
    whitespace, or raw control characters. Deterministic and pure. Rejects, in order:

    * a path that is not exactly one leading ``/`` (relative paths; ``//`` prefixes);
    * any raw ``?`` (query — none are allowlisted in this milestone), ``#`` (fragment), or
      ``;`` (matrix parameter);
    * any raw whitespace or C0/C1 control character;
    * raw backslashes;
    * malformed percent-encoding (a ``%`` not beginning a valid ``%XX`` triplet);
    * any percent-escape that decodes to a delimiter/control character (``%2f``/``%2F``->'/',
      ``%5c``->'\\', ``%2e``->'.', ``%00`` …) — this also catches encoded traversal;
    * ambiguous repeated internal slashes (``//``);
    * raw dot-segment traversal (``.`` / ``..``).
    """
    if not path.startswith("/"):
        return "path must be absolute (exactly one leading slash)"
    if path.startswith("//"):
        return "ambiguous repeated slash"
    # No query, fragment, or matrix parameters are permitted in this milestone.
    for ch, label in (("?", "query string"), ("#", "fragment"), (";", "matrix parameter")):
        if ch in path:
            return f"{label} not permitted"
    # No raw whitespace or C0/C1 control characters.
    for ch in path:
        codepoint = ord(ch)
        if ch.isspace() or codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            return "raw whitespace or control character"
    if "\\" in path:
        return "raw backslash"
    # Every '%' must begin a well-formed %XX triplet.
    pos = path.find("%")
    while pos != -1:
        if not _PERCENT_TRIPLET_RE.match(path, pos):
            return "malformed percent-encoding"
        pos = path.find("%", pos + 3)
    # No percent-escape may decode to a delimiter or control character.
    for m in _PERCENT_TRIPLET_RE.finditer(path):
        if bytes.fromhex(m.group(0)[1:]).decode("latin-1") in _DANGEROUS_DECODED:
            return "percent-encoded delimiter or control character"
    # Ambiguous repeated internal slashes (a single leading slash is fine).
    if "//" in path[1:]:
        return "ambiguous repeated slash"
    # Raw dot-segment traversal.
    if any(seg in (".", "..") for seg in path.split("/")):
        return "dot-segment traversal"
    return None


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
    """Deterministic: True iff ``path`` matches exactly one allowlisted GET template.

    A non-canonical path (see :func:`canonical_path_violation`) is never allowed, so encoded
    delimiters cannot smuggle a different endpoint past the matcher.
    """
    if is_absolute_or_cross_host(path):
        return False
    if canonical_path_violation(path) is not None:
        return False
    segments = _segments(path)
    if not segments or any(seg == ".." for seg in segments):
        return False
    return any(_matches(t, segments) for t in ALLOWED_PATH_TEMPLATES)


def assert_request_allowed(method: str, path: str) -> None:
    """Enforce the closed policy BEFORE any response lookup. Raises on any violation.

    Order matters: method first, then absolute/cross-host, then canonical-form validation, then
    the allowlist — so a path whose canonical form could differ is rejected before matching.
    """
    if method.upper() not in ALLOWED_METHODS:
        raise MutatingRequestRefused(method)
    if is_absolute_or_cross_host(path):
        raise CrossHostRequestRefused(path)
    reason = canonical_path_violation(path)
    if reason is not None:
        raise NonCanonicalPathRefused(path, reason)
    if not path_is_allowed(path):
        raise UnknownPathRefused(path)


def allowlisted_templates() -> Iterable[str]:
    return ALLOWED_PATH_TEMPLATES
