"""The hardened read-only Proxmox HTTPS transport for discovery.

It composes what already exists and re-derives neither half:

* ``secp_worker.hardened_http`` — the CA-pinned client factory, the capped body reader and the
  bounded JSON parser that five other worker transports already use;
* ``secp_worker.proxmox_discovery_operations`` — the typed operations, and the request grammar
  DERIVED from them. The base-URL grammar and the redirect refusal still come from
  ``secp_plugin_proxmox``, which owns both.

**Why the allowlist is derived rather than declared here.** It used to be the plugin's
``readonly_policy``: a hand-maintained twelve-template list plus a blanket no-query-parameter rule.
That list drifted from the twenty-four reviewed operations, so eighteen were refused at the wire —
including ``GET /cluster/sdn``, the SDN authority preflight, and every operation carrying
``?pending=1``. Both lists looked right in review; the defect was that there were two. The grammar
is now computed from the operation types, so a reviewed operation and an authorised request are the
same fact rather than two facts that must be kept in step.

**Why it lives on the worker side and not in the plugin.** The plugin imports nothing from
``secp_worker``; ``secp_worker`` imports the plugin in four places. The dependency is one-way, and
having the plugin reach back for ``hardened_http`` would invert it and create a package cycle. The
worker owns the *client*, which does I/O — which is also where every other hardened transport lives.

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

import re
from typing import Any, NoReturn, SupportsIndex
from urllib.parse import urlencode

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

    def _assert_grammatical(self, operation: object) -> tuple[str, tuple[tuple[str, str], ...]]:
        """Refuse anything the typed operation grammar does not describe, exactly.

        Four separate checks, because each closes a different way a request could differ from the
        one that was reviewed: the operation TYPE must be one of the closed set; the rendered path
        must match its own declared template segment for segment; every interpolated segment must
        satisfy the identifier grammar; and the query must be byte-identical to the pairs its type
        declares — not a subset, not a superset, not merely "no parameters".
        """
        from secp_worker.proxmox_discovery_operations import (
            discovery_operation_types,
            discovery_request_grammar,
        )

        if type(operation) not in discovery_operation_types():
            raise ProxmoxDiscoveryTransportError("proxmox_discovery_operation_not_reviewed")

        grammar = discovery_request_grammar()
        code = getattr(operation, "operation_code", "")
        if code not in grammar:
            raise ProxmoxDiscoveryTransportError("proxmox_discovery_operation_not_reviewed")

        template, declared_query = grammar[code]
        path = operation.rendered_path()  # type: ignore[attr-defined]
        if not _path_matches_template(path, template):
            raise ProxmoxDiscoveryTransportError("proxmox_discovery_path_outside_its_template")

        query = tuple(operation.query_parameters())  # type: ignore[attr-defined]
        if query != declared_query:
            raise ProxmoxDiscoveryTransportError("proxmox_discovery_query_outside_the_grammar")

        return path, query

    def execute(self, operation: object) -> Any:
        """Issue ONE typed operation and return the unwrapped ``data`` payload.

        The parameter is an OPERATION, not a path. There is no ``get(path)`` on this surface, no
        method parameter, no raw query string and no caller-supplied mapping: a request that is not
        one of the reviewed typed reads is not expressible here, rather than expressible and
        checked. The path and the query are rendered by the operation from its own template, and
        both are then verified against :func:`discovery_request_grammar`, which is DERIVED from the
        operation types rather than maintained beside them.

        That derivation is the fix for a specific defect. The transport previously enforced a
        hand-maintained twelve-template allowlist that had drifted from the twenty-four reviewed
        operations: eighteen were refused, including ``GET /cluster/sdn`` — the SDN authority
        preflight every SDN honesty claim in this system rests on — and every operation carrying a
        query parameter, because the old policy refused parameters universally. Two lists, one of
        them wrong, and nothing compared them.
        """
        from secp_plugin_proxmox.readonly_policy import RedirectRefused

        path, query = self._assert_grammatical(operation)

        ssl_context = build_ssl_context(self.__ca_path)
        url = f"{self.__base_url}/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urlencode(query)}"
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


class HardenedDiscoveryTransportFactory:
    """The production ``TransportFactory``. Builds the hardened transport and nothing else.

    This exists because the hardened class was reached by no production code path: every caller was
    a test fake, so the composition's transport seam had a protocol, a bounded fake and no
    implementation behind it. That is the "correct code reached by nothing" shape — the class would
    have passed every test it has while a real run had no way to get one.

    It takes no arguments of its own. Base URL, CA path and token all arrive at ``build`` from the
    composition, which resolves the token, uses it and drops it inside one function body; a factory
    holding any of them would extend the credential's lifetime past that.

    Building contacts nothing: construction validates the base URL, refuses an unpinned CA and an
    absent token, and opens no socket. The CA file is read at request time.
    """

    __slots__ = ()

    def build(
        self, *, base_url: str, ca_path: str, token: str
    ) -> HardenedProxmoxDiscoveryTransport:
        return HardenedProxmoxDiscoveryTransport(base_url=base_url, ca_path=ca_path, token=token)


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


#: A rendered dynamic segment must still satisfy the operation grammar. Checked HERE as well as at
#: construction, because the transport is the last thing before the wire and a segment that reached
#: it by some other route must not be sent on the strength of having been checked earlier.
_TRANSPORT_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def _path_matches_template(path: str, template: str) -> bool:
    """Whether a rendered path is exactly its template with safe segments interpolated."""
    rendered = [p for p in path.split("/") if p != ""]
    expected = [p for p in template.split("/") if p != ""]
    if len(rendered) != len(expected):
        return False
    for actual, declared in zip(rendered, expected, strict=True):
        if declared.startswith("{") and declared.endswith("}"):
            if not _TRANSPORT_SAFE_SEGMENT.match(actual):
                return False
        elif actual != declared:
            return False
    return True
