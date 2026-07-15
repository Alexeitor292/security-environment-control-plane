"""Concrete production OpenBao HTTPS transport for plan-execution reads (B1B-PR5B, ADR-022 §10).

This is the reviewed, repository-controlled implementation that actually performs the OpenBao read.
It lives at the worker top level ON PURPOSE — ``secp_worker/plan_gen`` is forbidden by the
architecture boundary from importing ``httpx``/``socket`` — and it implements the transport-free
:class:`~secp_worker.plan_gen.openbao_plan_resolver.PlanSecretBackendTransport` seam that
``ConcreteOpenBaoPlanSecretClient`` reads through.

Hardening (all enforced; none configurable to a weaker value):

* HTTPS only, an EXACT reviewed origin (no userinfo/query/fragment/non-root path), validated at
  construction;
* TLS verified against an EXPLICIT deployment-local CA bundle (an ``ssl.SSLContext`` — never system
  trust, never disabled);
* ``trust_env=False`` (no ``*_PROXY`` / ``SSL_CERT_*`` inheritance) and ``follow_redirects=False``;
* bounded connect/read/write/pool timeouts and a bounded, streamed response size + bounded JSON
  depth/container/string counts;
* the ONLY method is ``GET`` and the ONLY path is the exact OpenBao KV-v2
``/v1/<mount>/data/<path>``
  grammar built from the already-re-verified opaque locator — no arbitrary method, URL, or path
  joining;
* authentication material comes ONLY from a typed, non-serializable
  :class:`~secp_worker.hardened_http.WorkerAuthMaterialProvider` (no environment-token fallback);
* a secret read is NEVER retried;
* no origin, token, reference, CA path, response body, or raw backend exception appears in ``repr``
/
  ``str`` / logs / audits / errors / Temporal / durable state — only closed reason codes.

CONSTRUCTION performs no contact: it validates the origin string and stores config; the CA bundle,
the TLS handshake, and the request happen only when ``read`` is called.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, NoReturn, SupportsIndex

from secp_worker.hardened_http import (
    HardenedTransportError,
    WorkerAuthMaterialProvider,
    build_ssl_context,
    coerce_auth_headers,
    open_hardened_client,
    parse_bounded_json,
    read_capped_body,
    validate_https_origin,
    validate_relative_control_path,
)
from secp_worker.reviewed_identity import declaration_digest

# The reviewed implementation registration for this exact concrete transport. A controlled-live
# composition is bound to it (and to this class's actual ``module.qualname``), so a fake/foreign
# transport that merely satisfies the Protocol is refused.
OPENBAO_PLAN_HTTP_TRANSPORT_REGISTRATION = "secp-002b-1b-pr5b/openbao-plan-http-transport/v1"


def openbao_plan_http_transport_digest() -> str:
    """The stable digest of the reviewed OpenBao plan HTTPS transport implementation identity."""
    return declaration_digest(OPENBAO_PLAN_HTTP_TRANSPORT_REGISTRATION)


# A minimum OpenBao KV-v2 locator is ``<mount>/<name>`` (at least two safe segments).
_MIN_LOCATOR_SEGMENTS = 2
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


class OpenBaoHttpTransport:
    """The concrete, hardened OpenBao KV-v2 read transport. Constructed only by a reviewed
    deployment-local composition; construction contacts nothing."""

    IMPLEMENTATION_ID = OPENBAO_PLAN_HTTP_TRANSPORT_REGISTRATION

    __slots__ = ("__origin", "__ca_path", "__auth_provider")

    def __init__(
        self,
        *,
        origin: str,
        ca_path: str,
        auth_provider: WorkerAuthMaterialProvider,
    ) -> None:
        # Validate the origin FIRST (fails closed before anything else is stored or touched).
        self.__origin = validate_https_origin(origin)
        if not (isinstance(ca_path, str) and ca_path.strip()):
            raise HardenedTransportError("ca_required")
        self.__ca_path = ca_path
        if auth_provider is None:
            raise HardenedTransportError("auth_provider_required")
        self.__auth_provider = auth_provider

    @property
    def implementation_registration(self) -> str:
        return OPENBAO_PLAN_HTTP_TRANSPORT_REGISTRATION

    @property
    def implementation_digest(self) -> str:
        return openbao_plan_http_transport_digest()

    def read(self, *, locator: str, now: datetime) -> Mapping[str, Any]:
        """Perform the single hardened GET of the exact KV-v2 path and return ``{"value": secret}``.

        Every failure maps to a closed, secret-free reason code; the origin/token/path/body/raw
        error
        never surface.
        """
        # Auth material is obtained BEFORE any contact (a sealed/invalid provider fails closed
        # here).
        headers = self._request_headers(now=now)
        url = self._build_kv_url(locator)
        ssl_context = build_ssl_context(self.__ca_path)
        try:
            with open_hardened_client(ssl_context=ssl_context) as client:
                with client.stream("GET", url, headers=headers) as response:
                    if response.status_code in _REDIRECT_STATUS or response.is_redirect:
                        raise HardenedTransportError("redirect_forbidden")
                    status = response.status_code
                    if status == 404:
                        raise HardenedTransportError("reference_unknown")
                    if status in (401, 403):
                        raise HardenedTransportError("authentication_failed")
                    if status != 200:
                        raise HardenedTransportError("backend_status_error")
                    body = read_capped_body(response)
        except HardenedTransportError:
            raise
        except Exception:
            # Drop the httpx exception chain (it can carry the host) — never leak the backend.
            raise HardenedTransportError("backend_unreachable") from None
        payload = parse_bounded_json(body)
        return self._extract_value(payload)

    # --- internals -------------------------------------------------------------------------------

    def _request_headers(self, *, now: datetime) -> dict[str, str]:
        headers = coerce_auth_headers(self.__auth_provider, now=now)
        headers.setdefault("Accept", "application/json")
        return headers

    def _build_kv_url(self, locator: str) -> str:
        if not (isinstance(locator, str) and locator.strip()):
            raise HardenedTransportError("reference_invalid")
        segments = locator.split("/")
        if len(segments) < _MIN_LOCATOR_SEGMENTS or any(not s for s in segments):
            raise HardenedTransportError("reference_invalid")
        mount = segments[0]
        subpath = "/".join(segments[1:])
        # Build the EXACT KV-v2 data path; re-validate the assembled path (defence in depth).
        path = validate_relative_control_path(f"/v1/{mount}/data/{subpath}")
        return self.__origin + path

    @staticmethod
    def _extract_value(payload: Any) -> Mapping[str, Any]:
        """Extract the single ``value`` field from a KV-v2 ``data.data`` map; else return ``{}``.

        Only the secret value crosses the seam — never the metadata, versions, or other fields. A
        missing/non-string value yields ``{}`` (→ ``reference_unknown`` upstream). Nothing is
        logged.
        """
        data = payload.get("data") if isinstance(payload, Mapping) else None
        inner = data.get("data") if isinstance(data, Mapping) else None
        value = inner.get("value") if isinstance(inner, Mapping) else None
        return {"value": value} if isinstance(value, str) and value else {}

    def __repr__(self) -> str:  # never expose the raw origin / CA path
        return "OpenBaoHttpTransport(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("OpenBaoHttpTransport cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("OpenBaoHttpTransport cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("OpenBaoHttpTransport cannot be pickled")
