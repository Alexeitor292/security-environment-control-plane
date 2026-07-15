"""Concrete production HTTP state-control transport for remote-state readiness (B1B-PR5B).

The reviewed, repository-controlled implementation that actually performs the bounded
control-metadata
requests behind :class:`~secp_worker.readiness.http_state_probe.ConcreteHttpStateControlProbe`. It
lives at the worker top level ON PURPOSE — ``secp_worker/readiness`` is forbidden by the
architecture
boundary from importing ``httpx``/``socket`` — and it subclasses the nominal
:class:`~secp_worker.readiness.http_state_probe.ApprovedStateBackendControlTransport`.

**Structurally incapable of touching a state body.** Its ONLY operations are the eight
control-metadata
methods the probe needs; there is no ``get_state`` / ``read`` / ``download`` / ``upload`` /
``delete``
/ ``restore`` / force-unlock method and no generic request method on the public surface. Every
method
obeys the EXACT method-to-endpoint policy (HEAD→metadata, GET→capabilities, LOCK/UNLOCK→a DEDICATED
readiness-lock path — never the deployment state address), so the probe/adapter cannot ask this
transport to fetch a state payload — there is no interface through which one could.

The control origin is DERIVED from the AUTHORITATIVE deployment state address (§6): at construction
the state address + plan lock/unlock addresses must share one origin, and the three control paths
are
refused if any collides with the deployment state object (so a mis-set capabilities/metadata path
can
never read state, and the readiness lock is a dedicated readiness-only namespace). The probe further
requires ``control_origin`` to equal the origin of the toolchain profile's
``state_backend.reference``
before any contact — readiness can never validate a different backend than the one it is bound to.

Hardening (all enforced): HTTPS only; the origin derived + re-validated; TLS verified against an
EXPLICIT CA bundle (``ssl.SSLContext``); ``trust_env=False``; ``follow_redirects=False`` (a redirect
fails the metadata closed); bounded timeouts + streamed response size + bounded JSON; the exact
method-to-endpoint policy (no generic method, no generic URL); a typed, non-serializable
auth-material
provider (no environment-token fallback); and closed reason codes with no raw origin/response/error
leakage. CONSTRUCTION contacts nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, SupportsIndex

from secp_worker.hardened_http import (
    MAX_REQUEST_BYTES,
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
from secp_worker.readiness.http_state_probe import (
    ApprovedStateBackendControlTransport,
    ReadinessLockHandle,
    TransportSecurityPosture,
)
from secp_worker.reviewed_identity import declaration_digest

STATE_CONTROL_HTTP_TRANSPORT_REGISTRATION = "secp-002b-1b-pr5b/state-control-http-transport/v1"


def state_control_http_transport_digest() -> str:
    """The stable digest of the reviewed HTTP state-control transport implementation identity."""
    return declaration_digest(STATE_CONTROL_HTTP_TRANSPORT_REGISTRATION)


# The EXACT method-to-endpoint policy (ADR-021 §E). A method is valid ONLY with its one endpoint:
# HEAD → metadata; GET → capabilities; LOCK/UNLOCK → the DEDICATED readiness-lock. There is no
# ``GET``/``HEAD`` of the state object, no generic method, and no generic URL — so the probe/adapter
# cannot request a state body through this transport. Every other (method, endpoint) pair refuses.
_METADATA = "metadata"
_CAPABILITIES = "capabilities"
_READINESS_LOCK = "readiness_lock"
_METHOD_ENDPOINT_POLICY = frozenset(
    {
        ("HEAD", _METADATA),
        ("GET", _CAPABILITIES),
        ("LOCK", _READINESS_LOCK),
        ("UNLOCK", _READINESS_LOCK),
    }
)
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_LOCK_CONFLICT_STATUS = frozenset({409, 423})


def _assert_control_paths_disjoint(
    state_path: str, lock_path: str, unlock_path: str, endpoints: StateBackendControlEndpoints
) -> None:
    """Refuse any control-path collision that could read/lock the deployment state (ADR-021 §E).

    The three deployment-state paths (state object + plan lock + plan unlock) collapse to the state
    object's path. No control path may equal it — otherwise a GET of the capabilities endpoint, a
    HEAD of the metadata endpoint, or a LOCK of the readiness endpoint would touch the real state.
    The readiness lock must be a DEDICATED readiness-only namespace, and the three control paths
    must
    be pairwise distinct. Raises before any auth material or network contact.
    """
    meta = endpoints.namespace_metadata_path
    caps = endpoints.capabilities_path
    rlock = endpoints.readiness_lock_path
    state_object = {state_path, lock_path, unlock_path}
    if caps in state_object:
        raise HardenedTransportError("capabilities_path_is_state_object")
    if meta in state_object:
        raise HardenedTransportError("metadata_path_is_state_object")
    if rlock in state_object:
        raise HardenedTransportError("readiness_lock_is_state_object")
    if len({meta, caps, rlock}) != 3:
        raise HardenedTransportError("control_path_collision")


@dataclass(frozen=True)
class StateBackendControlEndpoints:
    """The reviewed, EXACT relative control-metadata endpoints (never the deployment state address).

    * ``namespace_metadata_path`` — a HEAD-only existence probe (returns no state body);
    * ``capabilities_path`` — a GET returning the token's allowed backend actions;
    * ``readiness_lock_path`` — a DEDICATED readiness-namespace lock path (LOCK/UNLOCK), separate
    from
      the deployment state so the probe can never lock or read real state.

    Each is validated as a safe leading-slash relative path (no scheme/host/userinfo/query/fragment/
    traversal). They are supplied by the reviewed composition; nothing is inferred or joined at
    runtime.
    """

    namespace_metadata_path: str
    capabilities_path: str
    readiness_lock_path: str

    def __post_init__(self) -> None:
        validate_relative_control_path(self.namespace_metadata_path)
        validate_relative_control_path(self.capabilities_path)
        validate_relative_control_path(self.readiness_lock_path)


class HttpStateControlTransport(ApprovedStateBackendControlTransport):
    """The concrete, hardened control-metadata transport. Constructed only by a reviewed
    deployment-local composition; construction contacts nothing and reads NO state body."""

    IMPLEMENTATION_ID = STATE_CONTROL_HTTP_TRANSPORT_REGISTRATION

    def __init__(
        self,
        *,
        state_address: str,
        plan_lock_address: str,
        plan_unlock_address: str,
        ca_path: str,
        auth_provider: WorkerAuthMaterialProvider,
        endpoints: StateBackendControlEndpoints,
        readiness_lock_id: str,
    ) -> None:
        # The control origin is DERIVED from the authoritative deployment state address (§6) — never
        # a
        # second, independently-supplied origin. The plan lock/unlock addresses (also authoritative)
        # must share that exact origin, and the control endpoints are checked for state-object
        # collisions, ALL before anything is stored or contacted.
        from secp_worker.plan_gen.destination_binding import (
            DestinationBindingError,
            canonicalize_https,
        )

        try:
            _sc, origin, state_path = canonicalize_https(
                state_address, allow_query=False, reason="state_address"
            )
            _lc, lock_origin, lock_path = canonicalize_https(
                plan_lock_address, allow_query=True, reason="state_lock"
            )
            _uc, unlock_origin, unlock_path = canonicalize_https(
                plan_unlock_address, allow_query=True, reason="state_unlock"
            )
        except DestinationBindingError as exc:
            raise HardenedTransportError(exc.reason_code) from None
        if not (origin == lock_origin == unlock_origin):
            raise HardenedTransportError("state_origin_mismatch")
        if not isinstance(endpoints, StateBackendControlEndpoints):
            raise HardenedTransportError("endpoints_invalid")
        _assert_control_paths_disjoint(state_path, lock_path, unlock_path, endpoints)
        if not (isinstance(ca_path, str) and ca_path.strip()):
            raise HardenedTransportError("ca_required")
        self.__ca_path = ca_path
        if auth_provider is None:
            raise HardenedTransportError("auth_provider_required")
        self.__auth_provider = auth_provider
        if not (isinstance(readiness_lock_id, str) and readiness_lock_id.strip()):
            raise HardenedTransportError("readiness_lock_id_required")
        self.__readiness_lock_id = readiness_lock_id
        self.__control_origin = origin
        # The EXACT URL for each of the three reviewed endpoint keys; there is no other URL and no
        # arbitrary path joining. ``validate_https_origin`` re-confirms the derived origin's shape.
        base = validate_https_origin(origin)
        self.__urls = {
            _METADATA: base + endpoints.namespace_metadata_path,
            _CAPABILITIES: base + endpoints.capabilities_path,
            _READINESS_LOCK: base + endpoints.readiness_lock_path,
        }

    @property
    def control_origin(self) -> str:
        return self.__control_origin

    @property
    def implementation_registration(self) -> str:
        return STATE_CONTROL_HTTP_TRANSPORT_REGISTRATION

    @property
    def implementation_digest(self) -> str:
        return state_control_http_transport_digest()

    # --- the eight control-metadata operations (fixed verb + fixed path each) ---------------------

    def security_posture(self, *, now: datetime) -> TransportSecurityPosture:
        # The transport is CONFIGURED hardened: EXACT-CA TLS verification, no proxy inheritance, no
        # redirect following, a fixed validated origin. This reflects the construction, not a probe.
        return TransportSecurityPosture(
            tls_verified=True,
            certificate_validation_enabled=True,
            trusted_identity_policy="pinned_ca_bundle",
            proxy_inheritance_enabled=False,
            redirect_observed=False,
            destination_stable=True,
        )

    def namespace_occupied(self, *, now: datetime) -> bool | None:
        try:
            status, _ = self._send("HEAD", _METADATA, now=now, read_body=False)
        except HardenedTransportError:
            return None  # a redirect / transport failure → undeterminable → unverifiable
        if status == 200:
            return True
        if status == 404:
            return False
        return None  # any other status → undeterminable WITHOUT reading a body → unverifiable

    def granted_actions(self, *, now: datetime) -> tuple[str, ...] | None:
        try:
            status, body = self._send("GET", _CAPABILITIES, now=now, read_body=True)
        except HardenedTransportError:
            return None
        if status != 200 or body is None:
            return None
        try:
            payload = parse_bounded_json(body)
        except HardenedTransportError:
            return None
        actions = payload.get("actions") if isinstance(payload, dict) else None
        if not isinstance(actions, list):
            return None
        cleaned = tuple(a.strip().lower() for a in actions if isinstance(a, str) and a.strip())
        return cleaned or None

    def local_fallback_reachable(self, *, now: datetime) -> bool:
        # A remote-only HTTPS transport exposes no local/disk state fallback.
        return False

    def force_unlock_available(self, *, now: datetime) -> bool:
        # This transport exposes NO force-unlock operation; force-unlock is never available through
        # it.
        return False

    def acquire_readiness_lock(self, *, now: datetime) -> ReadinessLockHandle | None:
        try:
            status, _ = self._send(
                "LOCK", _READINESS_LOCK, now=now, read_body=False, content=self._lock_body()
            )
        except HardenedTransportError:
            return None
        if status == 200:
            # The owner is server-derived from OUR readiness lock id — never a caller-supplied
            # owner.
            return ReadinessLockHandle(caller_supplied_owner=False)
        return None

    def probe_contention(self, *, now: datetime) -> bool:
        try:
            status, _ = self._send(
                "LOCK", _READINESS_LOCK, now=now, read_body=False, content=self._lock_body()
            )
        except HardenedTransportError:
            return False
        if status in _LOCK_CONFLICT_STATUS:
            return True  # the backend correctly refused a second lock → contention proven
        if status == 200:
            # The backend WRONGLY granted a second lock: release it immediately and report unproven.
            try:
                self._send(
                    "UNLOCK", _READINESS_LOCK, now=now, read_body=False, content=self._lock_body()
                )
            except HardenedTransportError:
                pass
            return False
        return False

    def release_readiness_lock(self, handle: ReadinessLockHandle, *, now: datetime) -> bool:
        try:
            status, _ = self._send(
                "UNLOCK", _READINESS_LOCK, now=now, read_body=False, content=self._lock_body()
            )
        except HardenedTransportError:
            return False
        return status == 200

    # --- internals -------------------------------------------------------------------------------

    def _lock_body(self) -> bytes:
        body = json.dumps(
            {"ID": self.__readiness_lock_id, "Operation": "readiness-probe", "Who": "secp-worker"}
        ).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise HardenedTransportError("request_too_large")
        return body

    def _send(
        self,
        method: str,
        endpoint: str,
        *,
        now: datetime,
        read_body: bool,
        content: bytes | None = None,
    ) -> tuple[int, bytes | None]:
        """Issue ONE hardened request under the EXACT method-to-endpoint policy; return (status,
        body?).

        ``(method, endpoint)`` must be one of the four reviewed pairs (HEAD→metadata, GET→
        capabilities, LOCK/UNLOCK→readiness-lock) — every other pair refuses BEFORE any auth
        material
        or network contact, so no valid method can reach the wrong endpoint and no generic
        method/URL exists. A redirect fails closed. Failures map to closed reason codes; the raw
        endpoint/response/error never surfaces.
        """
        if (method, endpoint) not in _METHOD_ENDPOINT_POLICY:
            raise HardenedTransportError("method_endpoint_forbidden")
        url = self.__urls[endpoint]
        headers = coerce_auth_headers(self.__auth_provider, now=now)
        if content is not None:
            headers.setdefault("Content-Type", "application/json")
        ssl_context = build_ssl_context(self.__ca_path)
        try:
            with open_hardened_client(ssl_context=ssl_context) as client:
                with client.stream(method, url, headers=headers, content=content) as response:
                    if response.status_code in _REDIRECT_STATUS or response.is_redirect:
                        raise HardenedTransportError("redirect_forbidden")
                    status = response.status_code
                    body = read_capped_body(response) if read_body else None
        except HardenedTransportError:
            raise
        except Exception:
            raise HardenedTransportError("backend_unreachable") from None
        return status, body

    def __repr__(self) -> str:  # never expose the raw origin / CA path / endpoints
        return "HttpStateControlTransport(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("HttpStateControlTransport cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("HttpStateControlTransport cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("HttpStateControlTransport cannot be pickled")
