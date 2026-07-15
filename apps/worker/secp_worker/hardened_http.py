"""Shared hardened-HTTPS primitives for the reviewed worker backend transports (B1B-PR5B).

The concrete production transports for the plan-execution OpenBao read
(:mod:`secp_worker.openbao_plan_http_transport`) and the remote-state control-metadata probe
(:mod:`secp_worker.state_control_http_transport`) build on these primitives. They live at the worker
top level — NEVER inside ``secp_worker/plan_gen`` or ``secp_worker/readiness`` — because those
packages are forbidden by the architecture boundary from importing ``httpx``/``socket``; the
reviewed composition constructs a transport here and injects it into the (transport-free) resolver /
probe seams.

Every primitive fails closed and secret-free. A backend URL, token, CA path, response body, or raw
backend exception NEVER reaches a ``repr``/``str``, a log, an audit, a Temporal argument, durable
state, or an exception message — only bounded, closed reason codes surface. ``httpx`` is imported
lazily inside the request path so importing this module performs no network work, and CONSTRUCTION
of any transport contacts nothing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, NoReturn, Protocol, SupportsIndex, runtime_checkable
from urllib.parse import urlsplit

# --- bounded transport limits (defence against a hostile or runaway backend) ---------------------

CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 10.0
WRITE_TIMEOUT_SECONDS = 10.0
POOL_TIMEOUT_SECONDS = 5.0

MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 16 * 1024
MAX_JSON_DEPTH = 24
MAX_JSON_CONTAINERS = 512
MAX_JSON_STRING = 8 * 1024

# A conservative hostname / IPv4 literal (no userinfo/ports/whitespace/path/scheme chars).
_SAFE_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-.]*[A-Za-z0-9])?$")

# A reviewed, exact relative control path: leading slash, safe segments only, no traversal, no
# scheme/host/userinfo/query/fragment/whitespace/percent-encoding. Used for the fixed
# control-metadata
# endpoints — there is NO arbitrary URL or path joining anywhere in a transport.
_SAFE_RELATIVE_PATH_RE = re.compile(r"^(?:/[A-Za-z0-9._~-]+)+$")
_DOT_SEGMENTS = frozenset({".", ".."})


class HardenedTransportError(Exception):
    """Fail-closed transport error carrying ONLY a closed reason code.

    Never carries a URL, host, port, token, CA path, response body, or raw backend error, so a
    caller
    that logs / audits / surfaces it cannot leak the backend location or a secret.
    """

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class WorkerAuthMaterialUnavailable(HardenedTransportError):
    """No worker authentication material is configured (the sealed default). Fail closed."""


# --- typed, non-serializable worker authentication-material provider ------------------------------


class _NonSerializable:
    """A worker-auth provider (and the secret material it yields) is never pickled/serialized."""

    def __getstate__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")


@runtime_checkable
class WorkerAuthMaterialProvider(Protocol):
    """Injected, typed, non-serializable provider of per-request authentication HEADERS.

    ``auth_headers`` returns the exact header(s) the transport must send (e.g. an OpenBao token
    header
    or a state-backend authorization header). The material is secret: it is NEVER logged, persisted,
    placed in a Temporal argument, or echoed. There is NO environment-token fallback — a transport
    obtains authentication ONLY from this provider. The shipped default fails closed.
    """

    def auth_headers(self, *, now: datetime) -> Mapping[str, str]: ...


class SealedWorkerAuthMaterialProvider(_NonSerializable):
    """The shipped default: NO auth material. Every request fails closed before contact."""

    def auth_headers(self, *, now: datetime) -> Mapping[str, str]:
        raise WorkerAuthMaterialUnavailable("auth_material_sealed")


def coerce_auth_headers(provider: WorkerAuthMaterialProvider, *, now: datetime) -> dict[str, str]:
    """Return the provider's header map as a plain ``dict[str, str]``, or fail closed.

    A provider that yields a non-mapping, a non-string key/value, or an empty map is refused. The
    values are secret and are never logged; only a closed reason code surfaces on failure.
    """
    material = provider.auth_headers(now=now)
    if not isinstance(material, Mapping) or not material:
        raise WorkerAuthMaterialUnavailable("auth_material_invalid")
    headers: dict[str, str] = {}
    for key, value in material.items():
        if not (isinstance(key, str) and key and isinstance(value, str) and value):
            raise WorkerAuthMaterialUnavailable("auth_material_invalid")
        headers[key] = value
    return headers


# --- origin + relative-path validation ------------------------------------------------------------


def validate_https_origin(origin: str) -> str:
    """Validate + normalize a reviewed backend origin to ``https://host[:port]``, or fail closed.

    Requires ``https``; a syntactically valid host (hostname or IPv4); and REJECTS userinfo, query,
    fragment, any non-root path, and a malformed/out-of-range port — closing off ``http://`` /
    ``file://`` / unix-socket / ``user@`` redirect-style tricks. The raw value never surfaces.
    """
    if not isinstance(origin, str) or not origin.strip():
        raise HardenedTransportError("origin_empty")
    try:
        parts = urlsplit(origin.strip())
    except ValueError as exc:
        raise HardenedTransportError("origin_unparsable") from exc
    if parts.scheme != "https":
        raise HardenedTransportError("origin_scheme_not_https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise HardenedTransportError("origin_userinfo_forbidden")
    if parts.query:
        raise HardenedTransportError("origin_query_forbidden")
    if parts.fragment:
        raise HardenedTransportError("origin_fragment_forbidden")
    if parts.path not in ("", "/"):
        raise HardenedTransportError("origin_path_forbidden")
    host = parts.hostname
    if not host or not _SAFE_HOST_RE.match(host):
        raise HardenedTransportError("origin_host_invalid")
    try:
        port = parts.port  # ValueError if malformed / out of 1..65535
    except ValueError as exc:
        raise HardenedTransportError("origin_port_invalid") from exc
    netloc = host if port is None else f"{host}:{port}"
    return f"https://{netloc}"


def validate_relative_control_path(path: str) -> str:
    """Validate a reviewed, exact relative control-metadata path (leading slash, safe segments).

    Rejects an absolute URL, a scheme/host/userinfo, a query/fragment, whitespace, percent-encoding,
    and any ``.``/``..`` traversal segment. This is how a transport binds a FIXED endpoint — there
    is
    never any arbitrary URL or path joining.
    """
    if not (isinstance(path, str) and path):
        raise HardenedTransportError("control_path_empty")
    if not _SAFE_RELATIVE_PATH_RE.match(path):
        raise HardenedTransportError("control_path_invalid")
    if any(segment in _DOT_SEGMENTS for segment in path.split("/")):
        raise HardenedTransportError("control_path_traversal")
    return path


# --- hardened client + bounded response reading ---------------------------------------------------


def build_ssl_context(ca_path: str):  # noqa: ANN201 - ssl.SSLContext (ssl imported lazily)
    """Build a TLS verifier from the EXACT deployment-local CA bundle (never system trust/disabled).

    A CA path that is missing, unreadable, or malformed fails closed with a closed reason code — the
    path itself never surfaces.
    """
    import ssl

    if not (isinstance(ca_path, str) and ca_path.strip()):
        raise HardenedTransportError("ca_required")
    try:
        return ssl.create_default_context(cafile=ca_path)
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise HardenedTransportError("ca_invalid") from exc


def open_hardened_client(*, ssl_context):  # noqa: ANN201 - httpx.Client (httpx imported lazily)
    """Open a hardened ``httpx.Client``: EXACT-CA TLS verification, no ambient env networking, no
    redirects, bounded connect/read/write/pool timeouts. Construction opens no connection."""
    import httpx

    timeout = httpx.Timeout(
        connect=CONNECT_TIMEOUT_SECONDS,
        read=READ_TIMEOUT_SECONDS,
        write=WRITE_TIMEOUT_SECONDS,
        pool=POOL_TIMEOUT_SECONDS,
    )
    return httpx.Client(
        verify=ssl_context,  # EXACT deployment-local CA; never system trust, never disabled
        trust_env=False,  # ignore *_PROXY / SSL_CERT_* / ambient env networking
        follow_redirects=False,  # a redirect is never a valid backend response
        timeout=timeout,
    )


def read_capped_body(response, *, max_bytes: int = MAX_RESPONSE_BYTES) -> bytes:  # noqa: ANN001
    """Stream a response body, refusing once it exceeds ``max_bytes`` (before it is all read)."""
    total = bytearray()
    for chunk in response.iter_bytes():
        total.extend(chunk)
        if len(total) > max_bytes:
            raise HardenedTransportError("response_too_large")
    return bytes(total)


def parse_bounded_json(
    raw: bytes,
    *,
    max_bytes: int = MAX_RESPONSE_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
    max_containers: int = MAX_JSON_CONTAINERS,
    max_string: int = MAX_JSON_STRING,
) -> Any:
    """Parse JSON under strict size / depth / container / string bounds; fail closed otherwise.

    The byte cap refuses an oversized payload before parsing; a walk of the parsed structure
    (iterative
    — never recursive) then refuses excessive depth, container count, or string length. A malformed
    or
    over-deep payload (including one that would exhaust the parser's own recursion) maps to a closed
    reason code — the payload is never echoed.
    """
    if len(raw) > max_bytes:
        raise HardenedTransportError("response_too_large")
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise HardenedTransportError("response_malformed") from exc

    containers = 0
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise HardenedTransportError("response_too_deep")
        if isinstance(node, dict):
            containers += 1
            if containers > max_containers:
                raise HardenedTransportError("response_too_many_containers")
            for key, value in node.items():
                if isinstance(key, str) and len(key) > max_string:
                    raise HardenedTransportError("response_string_too_long")
                stack.append((value, depth + 1))
        elif isinstance(node, list):
            containers += 1
            if containers > max_containers:
                raise HardenedTransportError("response_too_many_containers")
            for value in node:
                stack.append((value, depth + 1))
        elif isinstance(node, str) and len(node) > max_string:
            raise HardenedTransportError("response_string_too_long")
    return obj
