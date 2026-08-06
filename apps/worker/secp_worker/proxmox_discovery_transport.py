"""The hardened read-only Proxmox HTTPS transport for discovery.

This composes two things that already exist and re-derives neither:

* ``secp_worker.hardened_http`` — the CA-pinned client factory, the capped body reader and the
  bounded JSON parser that five other worker transports already use;
* ``secp_plugin_proxmox.readonly_policy`` — the closed GET allowlist, canonical-path checks,
  no-query-parameter rule and cross-host refusal.

**Why it lives on the worker side and not in the plugin.** The plugin imports nothing from
``secp_worker``; ``secp_worker`` imports the plugin in four places. The dependency is one-way, and
having the plugin reach back for ``hardened_http`` would invert it and create a package cycle. The
plugin keeps the *policy*, which is pure; the worker owns the *client*, which does I/O — which is
also where every other hardened transport lives.

It implements the same ``ReadOnlyHttpTransport`` shape ``LiveReadOnlyProxmoxCollector`` already
consumes, so nothing downstream changes.

What this fixes in the existing ``HttpxReadOnlyTransport``, each of which is a real exposure rather
than a tidy-up:

``verify=True`` is ambient system trust
    Any CA in the host trust store could impersonate the target. Discovery now pins the exact
    deployment-local CA bundle. "TLS verification cannot be disabled" was true and is not the same
    property as "TLS identity is pinned".
The exception chain carried the token
    ``resp.raise_for_status()`` raises ``httpx.HTTPStatusError``, which holds ``.request``, whose
    ``.headers`` contain ``Authorization: PVEAPIToken=…``. Any traceback, log line or error report
    that captured that exception captured the credential. Every failure here is re-raised
    ``from None`` as a closed reason code.
An injectable client defeated the posture
    ``self._client or httpx.Client(...)`` meant a caller-supplied client — whose ``trust_env``
    defaults to ``True`` — silently replaced the hardened one. There is no injection seam here.
The body was unbounded
    ``resp.json()`` buffers whatever arrives. Reads are streamed and capped.
A non-GET was representable on the call surface
    ``request(method, path)`` accepted any method and refused it later. Here there is no method
    parameter at all.
"""

from __future__ import annotations

from typing import Any, NoReturn, SupportsIndex

from secp_worker.hardened_http import (
    MAX_RESPONSE_BYTES,
    HardenedTransportError,
    build_ssl_context,
    open_hardened_client,
    parse_bounded_json,
    read_capped_body,
)

#: Bumped whenever the hardening posture changes, so a composition reviewed against an older
#: posture cannot silently accept this one.
PROXMOX_DISCOVERY_TRANSPORT_VERSION = "secp.proxmox-discovery-transport/v1"

#: Proxmox wraps every successful result in ``{"data": ...}``.
_DATA_KEY = "data"


class ProxmoxDiscoveryTransportError(HardenedTransportError):
    """Fail-closed transport failure carrying ONLY a closed reason code.

    Inherits the parent's contract deliberately: never a URL, host, port, token, CA path, response
    body or raw backend error. That is the property that keeps the credential out of a traceback.
    """


class HardenedProxmoxDiscoveryTransport:
    """Read-only Proxmox HTTPS transport. GET is the only representable operation.

    Construction opens no connection and contacts nothing.
    """

    __slots__ = ("__base_url", "__ca_path", "__token")

    def __init__(self, *, base_url: str, ca_path: str, token: str) -> None:
        # Validated by the plugin's own policy so the base-URL grammar has ONE owner. A second
        # scheme/host check here would be a second thing to keep in step.
        from secp_plugin_proxmox.transport import _validate_base_url

        if not ca_path or not str(ca_path).strip():
            # Fail closed at CONSTRUCTION, not at first request. A transport that would fall back
            # to system trust must not be constructible at all.
            raise ProxmoxDiscoveryTransportError("proxmox_discovery_ca_not_pinned")
        if not token or not str(token).strip():
            raise ProxmoxDiscoveryTransportError("proxmox_discovery_token_absent")
        _validate_base_url(base_url)
        # Name-mangled slots: a generic "log this object's fields" helper finds nothing useful, and
        # there is no `.token` or `._token` to stumble into. The load-bearing protection is the
        # repr/serialization refusal below — this is the cheap second layer.
        self.__base_url = base_url.rstrip("/")
        self.__ca_path = ca_path
        self.__token = token

    # --- the credential never leaves this object in any renderable form --------------------------

    def __repr__(self) -> str:
        return "HardenedProxmoxDiscoveryTransport(<redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __getstate__(self) -> NoReturn:
        raise ProxmoxDiscoveryTransportError("proxmox_discovery_transport_not_serializable")

    def __reduce__(self) -> NoReturn:
        raise ProxmoxDiscoveryTransportError("proxmox_discovery_transport_not_serializable")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise ProxmoxDiscoveryTransportError("proxmox_discovery_transport_not_serializable")

    # --- the only operation ----------------------------------------------------------------------

    def get(self, path: str, params: dict | None = None) -> Any:
        """Issue one allowlisted GET and return the unwrapped ``data`` payload.

        There is no ``method`` parameter. A non-GET is not expressible on this surface at all,
        rather than expressible and refused — which is the difference between a type that cannot
        represent a mutation and a check somebody can later move.
        """
        from secp_plugin_proxmox.readonly_policy import (
            RedirectRefused,
            assert_no_params,
            assert_request_allowed,
        )

        # The policy still runs, as defence in depth: the closed allowlist, canonical-path and
        # cross-host rules live in ONE place and this transport is not exempt from them.
        assert_request_allowed("GET", path)
        assert_no_params(params)

        ssl_context = build_ssl_context(self.__ca_path)
        url = f"{self.__base_url}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"PVEAPIToken={self.__token}",
            # Asked for explicitly so a non-JSON body is a server contract violation rather than
            # something the parser has to guess at.
            "Accept": "application/json",
            # No transparent decompression: a compressed body defeats a byte cap measured on the
            # wire, which is where the cap has to hold.
            "Accept-Encoding": "identity",
        }

        try:
            with open_hardened_client(ssl_context=ssl_context) as client:
                with client.stream("GET", url, headers=headers) as response:
                    # Checked before the body is read: a redirect is refused rather than followed,
                    # and its destination is never fetched.
                    if 300 <= int(response.status_code) < 400:
                        raise RedirectRefused("")
                    if int(response.status_code) >= 400:
                        # Deliberately NOT raise_for_status(): that exception carries .request,
                        # whose headers hold the token.
                        raise ProxmoxDiscoveryTransportError(
                            _status_reason(int(response.status_code))
                        )
                    raw = read_capped_body(response, max_bytes=MAX_RESPONSE_BYTES)
        except RedirectRefused:
            raise
        except ProxmoxDiscoveryTransportError:
            raise
        except Exception as exc:
            # `from None` severs the backend exception chain. httpx exceptions carry the request —
            # URL and Authorization header included — so re-raising with context would put the
            # credential into every traceback that touches this call. The CLASS is still read
            # first, because "the certificate did not verify", "the target did not answer in time"
            # and "the body exceeded the cap" are three different operator actions and collapsing
            # them into one code is how a TLS substitution reads as a flaky network.
            raise ProxmoxDiscoveryTransportError(_failure_reason(exc)) from None

        payload = parse_bounded_json(raw)
        if isinstance(payload, dict):
            return payload.get(_DATA_KEY)
        # A Proxmox success is always a `{"data": ...}` object. Anything else is not a response
        # this transport understands, and guessing at it is how a malformed body becomes a fact.
        raise ProxmoxDiscoveryTransportError("proxmox_discovery_response_not_an_object")


#: Closed reason codes this transport may raise. Nothing outside this set reaches an observation,
#: and a test asserts the projection has a rule for every one of them.
TRANSPORT_REASONS: tuple[str, ...] = (
    "proxmox_discovery_unauthenticated",
    "proxmox_discovery_permission_denied",
    "proxmox_discovery_endpoint_absent",
    "proxmox_discovery_endpoint_unsupported",
    "proxmox_discovery_request_refused",
    "proxmox_discovery_tls_identity_unverified",
    "proxmox_discovery_timeout",
    "proxmox_discovery_response_exceeded_bound",
    "proxmox_discovery_response_not_an_object",
    "proxmox_discovery_transport_failed",
)


def _failure_reason(exc: BaseException) -> str:
    """Classify a backend failure WITHOUT reusing its text.

    Only the exception's type and, for the one helper that raises closed codes of its own, its
    first argument are consulted. Nothing from a backend message is propagated: httpx and ssl
    messages routinely carry the URL.
    """
    import ssl

    if isinstance(exc, ssl.SSLError):
        return "proxmox_discovery_tls_identity_unverified"

    first = ""
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], str):
        first = args[0]
    if first == "response_too_large":
        return "proxmox_discovery_response_exceeded_bound"

    # httpx is imported lazily elsewhere; match on the type name so this module keeps no import.
    name = type(exc).__name__
    if "Timeout" in name or "Timedout" in name:
        return "proxmox_discovery_timeout"
    if "CertificateError" in name or "SSL" in name:
        return "proxmox_discovery_tls_identity_unverified"
    return "proxmox_discovery_transport_failed"


def _status_reason(status: int) -> str:
    """Map an HTTP status to a closed reason code.

    ``401``/``403`` are kept DISTINCT from a generic failure because they are the states an
    operator resolves with a grant, and because a 403 is the one unambiguous denial signal on a
    surface where a denied index read otherwise returns ``200`` with an empty list.
    """
    if status == 401:
        return "proxmox_discovery_unauthenticated"
    if status == 403:
        return "proxmox_discovery_permission_denied"
    if status == 404:
        return "proxmox_discovery_endpoint_absent"
    if status == 501:
        return "proxmox_discovery_endpoint_unsupported"
    return "proxmox_discovery_request_refused"
