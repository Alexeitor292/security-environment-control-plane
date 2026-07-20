"""Hardened HTTPS transport for the worker discovery-admission client (SECP-B6 MB-1 item-1).

The shipped production realization of the ``AdmissionTransport`` seam
(`secp_worker.target_discovery.admission_client.AdmissionTransport`). It reaches the internal
control-plane admission endpoint over TLS that is verified against an EXPLICIT, deployment-local CA
bundle (a worker-local trust anchor for the control plane — never the public/system trust store and
never disabled), with ambient environment networking (proxies, ``*_PROXY``, ``SSL_CERT_*``) turned
off and redirects refused. The endpoint URL is strictly validated at construction: ``https`` only, a
plain host[:port], no userinfo/query/fragment/non-root path/malformed port. Any of these fail closed
BEFORE any request, key-material read, or SSH.

It lives OUTSIDE ``secp_worker/target_discovery`` on purpose — the read-only discovery package must
stay transport-free (its only permitted transport is the reviewed SSH channel; the SECP-B5
architecture guard forbids ``httpx`` there). The composition wiring constructs this transport and
injects it into the discovery client. ``httpx`` is imported lazily inside ``post`` so importing this
module has no network dependency. The raw endpoint / CA path is NEVER placed in ``repr``,
exceptions, audit data, events, plans, or logs — only closed reason codes surface.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from urllib.parse import urlsplit

from secp_worker.hardened_http import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    HardenedTransportError,
    parse_bounded_json,
)

# A conservative hostname / IPv4 literal (no userinfo/ports/whitespace/path/scheme chars).
_SAFE_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-.]*[A-Za-z0-9])?$")

# Bounded default request timeout (seconds).
_DEFAULT_TIMEOUT = 10.0
_MAX_TIMEOUT = 30.0
_ALLOWED_PATHS = frozenset(
    {
        "/internal/worker-discovery-admission/begin",
        "/internal/worker-discovery-admission/complete",
        "/internal/worker-discovery-admission/assert",
        "/internal/worker-discovery-admission/consume",
    }
)


class AdmissionTransportError(Exception):
    """Fail-closed transport/endpoint error carrying ONLY a closed reason code.

    Never carries the raw admission endpoint, CA path, or any host/port value — so a caller that
    logs/audits it cannot leak the internal control-plane location."""

    def __init__(self, reason_code: str = "admission_transport_failed") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _validate_admission_endpoint(base_url: str) -> str:
    """Validate + normalize the admission endpoint to ``https://host[:port]``, or fail closed.

    Requires ``https`` scheme, a syntactically valid host (hostname or IPv4), and REJECTS userinfo,
    query strings, fragments, non-root path components, and malformed/empty ports — closing off
    ``http://`` / ``file://`` / unix-socket / ``user@`` redirect-style tricks. Raises
    :class:`AdmissionTransportError` (closed reason, no raw URL) on any problem."""
    if not isinstance(base_url, str) or not base_url.strip():
        raise AdmissionTransportError("admission_endpoint_empty")
    raw = base_url.strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        raise AdmissionTransportError("admission_endpoint_unparsable") from None
    if parts.scheme != "https":
        raise AdmissionTransportError("admission_endpoint_scheme_not_https")
    if parts.username is not None or parts.password is not None:
        raise AdmissionTransportError("admission_endpoint_userinfo_forbidden")
    if parts.query:
        raise AdmissionTransportError("admission_endpoint_query_forbidden")
    if parts.fragment:
        raise AdmissionTransportError("admission_endpoint_fragment_forbidden")
    if parts.path not in ("", "/"):
        raise AdmissionTransportError("admission_endpoint_path_forbidden")
    host = parts.hostname
    if not host or not _SAFE_HOST_RE.match(host):
        raise AdmissionTransportError("admission_endpoint_host_invalid")
    try:
        port = parts.port  # ValueError if malformed / out of 1..65535
    except ValueError:
        raise AdmissionTransportError("admission_endpoint_port_invalid") from None
    netloc = host if port is None else f"{host}:{port}"
    return f"https://{netloc}"


class HttpxAdmissionTransport:
    """CA-pinned HTTPS transport to the internal admission endpoint.

    Server TLS is verified against the EXACT deployment-local CA bundle (``verify`` is provably
    never ``True``/``False`` — always the configured CA path). Ambient environment networking is
    disabled (``trust_env=False``) and redirects are refused (``follow_redirects=False``). The
    endpoint URL is strictly validated at construction. Worker auth is the Ed25519 signed-nonce in
    the request bodies, NOT an X.509 client certificate (this is not mTLS)."""

    def __init__(self, *, base_url: str, ca_path: str, timeout: float = _DEFAULT_TIMEOUT) -> None:
        # Validate the endpoint first (fails closed before anything else touches it).
        self._base_url = _validate_admission_endpoint(base_url)
        if not (isinstance(ca_path, str) and ca_path.strip()):
            raise AdmissionTransportError("admission_ca_required")
        self._ca_path = ca_path
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or timeout <= 0
            or timeout > _MAX_TIMEOUT
            or not math.isfinite(float(timeout))
        ):
            raise AdmissionTransportError("admission_timeout_invalid")
        self._timeout = float(timeout)

    def __repr__(self) -> str:  # never expose the raw endpoint / CA path
        return "HttpxAdmissionTransport(<redacted>)"

    @property
    def base_url(self) -> str:
        """The normalized ``https://host[:port]`` origin (internal accessor for wiring checks)."""
        return self._base_url

    async def _post_async(self, path: str, request_body: bytes) -> tuple[int, bytes]:
        import ssl

        import httpx

        # Build the verifier from the EXACT deployment-local CA bundle (an SSLContext -- provably
        # never True/False, and no reliance on httpx's deprecated ``verify=<str>`` path). A CA that
        # became unreadable or malformed since construction fails closed here.
        ssl_context = ssl.create_default_context(cafile=self._ca_path)
        async with asyncio.timeout(self._timeout):
            async with httpx.AsyncClient(
                verify=ssl_context,  # EXACT deployment-local CA; never system trust, never disabled
                trust_env=False,  # ignore *_PROXY / SSL_CERT_* / ambient env networking
                follow_redirects=False,  # a redirect is never a valid admission response
                timeout=self._timeout,
            ) as client:
                async with client.stream(
                    "POST",
                    self._base_url + path,
                    content=request_body,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Content-Type": "application/json",
                    },
                ) as resp:
                    if resp.is_redirect:
                        raise AdmissionTransportError("admission_redirect_forbidden")
                    encodings = resp.headers.get_list("content-encoding")
                    if len(encodings) > 1 or any(
                        value.strip().lower() != "identity" for value in encodings
                    ):
                        raise AdmissionTransportError("admission_response_invalid")
                    status = resp.status_code
                    response_body = bytearray()
                    async for chunk in resp.aiter_raw():
                        if len(chunk) > MAX_RESPONSE_BYTES - len(response_body):
                            raise HardenedTransportError("response_too_large")
                        response_body.extend(chunk)
                    return status, bytes(response_body)

    def post(self, path: str, payload: dict) -> tuple[int, dict]:
        if path not in _ALLOWED_PATHS:
            raise AdmissionTransportError("admission_path_forbidden")
        try:
            request_body = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise AdmissionTransportError("admission_request_invalid") from None
        if len(request_body) > MAX_REQUEST_BYTES:
            raise AdmissionTransportError("admission_request_too_large")

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            # The public protocol is synchronous. Refuse explicitly instead of constructing an
            # un-awaited coroutine or attempting a nested event loop.
            raise AdmissionTransportError("admission_async_context_forbidden")
        try:
            status, raw = asyncio.run(self._post_async(path, request_body))
        except AdmissionTransportError:
            raise
        except HardenedTransportError as exc:
            reason = (
                "admission_response_too_large"
                if exc.reason_code == "response_too_large"
                else "admission_response_invalid"
            )
            raise AdmissionTransportError(reason) from None
        except Exception:
            # A connect/TLS/timeout failure fails closed WITHOUT leaking the endpoint or CA path
            # (``from None`` drops the httpx exception chain, which can contain the host).
            raise AdmissionTransportError("admission_transport_failed") from None
        try:
            body = parse_bounded_json(raw, max_bytes=MAX_RESPONSE_BYTES)
        except HardenedTransportError:
            raise AdmissionTransportError("admission_response_invalid") from None
        # Unwrap FastAPI's error envelope so callers see the closed reason code directly.
        if isinstance(body, dict) and isinstance(body.get("detail"), dict):
            body = body["detail"]
        if not isinstance(body, dict):
            body = {}
        return status, body
