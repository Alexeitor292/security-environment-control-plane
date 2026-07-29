"""Strict READ-ONLY live controller-finalization state observer (SECP-PR5H-B2, 2b-3c-c / R3).

The engine's exact same-release REPLAY (``_controller_install_replay``) and its managed-upgrade
eligibility classification (``_classify_upgrade_eligibility``) authenticate the five on-disk
documents, the finalization extension and the enablement-marker BINDING — all of which are static
artefacts. None of that observes the LIVE system, so a dead broker, a sealed or unhealthy API, a
stale socket, an old image, a drifted DB role, an unauthenticatable credential or a DB active
identity that disagrees with the documents could still qualify a host for replay/upgrade.

This module closes that gap with ONE closed, typed, fail-closed observation. It INDEPENDENTLY
proves, each as an explicit typed field/boolean on :class:`ControllerFinalizationState`:

* exactly ONE verified ACTIVE controller identity (leased under the fixed identity advisory lock
  through the dedicated least-privilege role — never a cached snapshot);
* that identity's row id + per-activation token;
* its installation id, release digest and controller key id;
* its management-identity digest, bootstrap binding digest and enrollment-key proof id;
* the current durable finalization generation;
* the EXACT enablement-marker binding (posture + schema + all twelve fields, agreeing with BOTH the
  live identity and the authenticated expectation);
* the EXACT dedicated signer role plus credential authentication;
* a LIVE API signer-runtime observation (the same authoritative proof the finalizer requires after
  writing the marker);
* broker transport readiness (unit active, the fixed path is EXACTLY an AF_UNIX socket in reviewed
  posture, and a bounded no-sign connect probe succeeds).

:meth:`ControllerFinalizationState.refusal_reason` returns a bounded, specific code from the closed
:data:`CONTROLLER_STATE_REASONS` set, or ``None`` when every fact is genuinely proven.

Discipline (identical to the finalization adapter it complements):

* the observation is MUTATION-FREE — only ``lstat``/``safe_read`` through the hardened filesystem,
  three fixed read-only pinned-runner queries (``systemctl is-active``, ``docker ps`` by compose
  label, ``docker inspect --format {{.Image}}``), two fixed SQL statements as the dedicated role, a
  connect/close socket probe, and the injected runtime observer. Replay stays mutation-free;
* NO ``secp_api`` import (the management plane may not reach the API plane), no generic SQL, no
  shell, and no caller-selected path / endpoint / module / argv;
* every read is bounded (size + timeout) and every probe fault FAILS CLOSED — an unprovable fact is
  never a proven fact, and no boolean is ever defaulted True;
* every live seam is injected, so production wires the real leaves (the dedicated-role lease
  provider, the real API signer runtime observer, the pinned ``RealAdapterContext``) and tests
  inject hermetic fakes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from secp_commissioning.controller_enrollment_signer import (
    ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY,
    ENROLLMENT_SIGNER_SOCKET_PATH,
)

from secp_management import ManagementError
from secp_management.controller_finalization import ApiSignerRuntimeObservation
from secp_management.enrollment_signer_db import ENROLLMENT_SIGNER_DB_ROLE, build_signer_role_engine
from secp_management.enrollment_signer_identity import DbActiveControllerSigningIdentityProvider
from secp_management.finalization import ApiSignerMarker
from secp_management.real_adapters import RealAdapterContext
from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID

# --------------------------------------------------------------------------- closed reason codes

#: Broker unit not active, or the bounded no-sign transport probe could not reach the accept loop.
CONTROLLER_STATE_BROKER_UNREACHABLE = "controller_state_broker_unreachable"
#: The ordinary API is absent / not running / running as root / not healthy.
CONTROLLER_STATE_API_UNHEALTHY = "controller_state_api_unhealthy"
#: The API is running but NOT signer-enabled with exactly this marker (sealed / mis-sealed).
CONTROLLER_STATE_API_SEALED = "controller_state_api_sealed"
#: No single verified ACTIVE identity, or the live identity disagrees with the authenticated docs.
CONTROLLER_STATE_ACTIVE_IDENTITY_MISMATCH = "controller_state_active_identity_mismatch"
#: The on-disk enablement marker is absent / unsafe / malformed / no longer binds the live identity.
CONTROLLER_STATE_MARKER_STALE = "controller_state_marker_stale"
#: The signer credential is absent / unsafe / malformed, or it does not authenticate to the DB.
CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED = "controller_state_credential_unauthenticated"
#: The credential authenticates but the session is not the reviewed dedicated least-privilege role.
CONTROLLER_STATE_ROLE_DRIFTED = "controller_state_role_drifted"
#: The fixed broker socket path is absent or is not EXACTLY an AF_UNIX socket in reviewed posture.
CONTROLLER_STATE_SOCKET_STALE = "controller_state_socket_stale"
#: The resolved API container is running an image other than the expected release image.
CONTROLLER_STATE_IMAGE_UNEXPECTED = "controller_state_image_unexpected"
#: A generation fact could not be proven or disagrees (durable generation / mixed API generation).
CONTROLLER_STATE_GENERATION_DISAGREEMENT = "controller_state_generation_disagreement"

#: The CLOSED set of refusal codes this observer may ever produce.
CONTROLLER_STATE_REASONS: tuple[str, ...] = (
    CONTROLLER_STATE_BROKER_UNREACHABLE,
    CONTROLLER_STATE_API_UNHEALTHY,
    CONTROLLER_STATE_API_SEALED,
    CONTROLLER_STATE_ACTIVE_IDENTITY_MISMATCH,
    CONTROLLER_STATE_MARKER_STALE,
    CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED,
    CONTROLLER_STATE_ROLE_DRIFTED,
    CONTROLLER_STATE_SOCKET_STALE,
    CONTROLLER_STATE_IMAGE_UNEXPECTED,
    CONTROLLER_STATE_GENERATION_DISAGREEMENT,
)

# --------------------------------------------------------------------------- constants

_ROOT_UID = 0
_ROOT_GID = 0
_MARKER_MODE = 0o644
_CREDENTIAL_MODE = 0o600
_SOCKET_MODE = 0o660
_MAX_READ = 64 * 1024
_SERVICE_TIMEOUT = 30
_PROBE_TIMEOUT = 20
_CONNECT_TIMEOUT_SECONDS = 5.0
_UNPROVEN_GENERATION = -1

_MARKER_SCHEMA = "secp.enrollment-signer-enablement/v1"
_PASSWORD_GRAMMAR = re.compile(r"[0-9a-f]{32,128}")
_FULL_CID = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")

_COMPOSE_API_SERVICE = "api"
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_COMPOSE_SERVICE_LABEL = "com.docker.compose.service"

#: The ten string + two integer binding fields the marker file must carry verbatim.
_MARKER_STR_FIELDS: tuple[str, ...] = (
    "installation_id",
    "release_digest",
    "active_identity_row_id",
    "activation_token",
    "controller_key_id",
    "uds_contract_identity",
    "signer_role_name",
    "locator_ca_digest",
    "management_identity_digest",
    "bootstrap_evidence_digest",
)
_MARKER_INT_FIELDS: tuple[str, ...] = ("api_uid", "api_gid")


# --------------------------------------------------------------------------- expected input


@dataclass(frozen=True)
class ExpectedControllerState:
    """The closed, NONSECRET expectation the engine derives from already-authenticated artefacts —
    the verified :class:`~secp_management.evidence.FinalizationEvidence` extension, the
    authenticated management identity, and the signed release. Every field is a public identity or
    digest; nothing here is a credential, path, DSN or endpoint.

    The last four fields are code-owned constants carried explicitly so the observation binds them
    (an installation that drifted off the reviewed role/UDS/peer contract refuses)."""

    generation: int
    installation_id: str
    release_digest: str
    controller_key_id: str
    active_identity_row_id: str
    management_identity_digest: str
    bootstrap_binding_digest: str
    enrollment_key_proof_id: str
    locator_ca_digest: str
    api_image_digest: str
    signer_role_name: str = ENROLLMENT_SIGNER_DB_ROLE
    uds_contract_identity: str = ENROLLMENT_SIGNER_SOCKET_PATH
    api_uid: int = API_RUNTIME_UID
    api_gid: int = API_RUNTIME_GID


# --------------------------------------------------------------------------- observed state


@dataclass(frozen=True)
class ControllerFinalizationState:
    """One closed, typed, PUBLIC snapshot of the LIVE controller-finalization state. Every boolean
    is True only when the corresponding fact was genuinely PROVEN by a live observation; a fault,
    ambiguity, parse failure or absence leaves it False. Carries no secret, path content, DSN or
    raw exception."""

    # ---- the independently reobserved ACTIVE controller identity ----
    single_active_identity: bool
    active_identity_row_id: str
    activation_token: str
    installation_id: str
    release_digest: str
    controller_key_id: str
    management_identity_digest: str
    bootstrap_binding_digest: str
    enrollment_key_proof_id: str
    active_identity_matches_expected: bool
    # ---- durable generation ----
    durable_generation: int  # -1 when unprovable
    generation_agrees: bool
    # ---- the enablement marker ----
    marker_binding_exact: bool
    marker_activation_token: str
    # ---- dedicated signer role + credential ----
    credential_authenticated: bool
    signer_role_exact: bool
    # ---- live API signer runtime ----
    runtime_observed: bool
    api_live: bool
    api_unsealed: bool
    api_image_observed: str
    api_image_expected: bool
    # ---- broker transport ----
    broker_service_active: bool
    broker_socket_exact: bool
    broker_transport_ready: bool

    def refusal_reason(self, expected: ExpectedControllerState) -> str | None:
        """The bounded refusal code for this state against ``expected``, or ``None`` when every
        fact is proven. Deterministic, most-specific-first order; the identity/image/generation
        equalities are RE-checked here, so a state observed against a different expectation can
        never silently pass."""
        if not self.broker_service_active:
            return CONTROLLER_STATE_BROKER_UNREACHABLE
        if not self.broker_socket_exact:
            return CONTROLLER_STATE_SOCKET_STALE
        if not self.broker_transport_ready:
            return CONTROLLER_STATE_BROKER_UNREACHABLE
        if not self.credential_authenticated:
            return CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED
        if not self.signer_role_exact:
            return CONTROLLER_STATE_ROLE_DRIFTED
        if not (
            self.single_active_identity
            and self.active_identity_matches_expected
            and self._identity_equals(expected)
        ):
            return CONTROLLER_STATE_ACTIVE_IDENTITY_MISMATCH
        if not self.marker_binding_exact:
            return CONTROLLER_STATE_MARKER_STALE
        if not (self.runtime_observed and self.api_live):
            return CONTROLLER_STATE_API_UNHEALTHY
        if not (
            self.api_image_expected
            and self.api_image_observed != ""
            and self.api_image_observed == expected.api_image_digest
        ):
            return CONTROLLER_STATE_IMAGE_UNEXPECTED
        if not self.api_unsealed:
            return CONTROLLER_STATE_API_SEALED
        if not (
            self.generation_agrees
            and self.durable_generation >= 0
            and self.durable_generation == expected.generation
        ):
            return CONTROLLER_STATE_GENERATION_DISAGREEMENT
        return None

    def ok_for(self, expected: ExpectedControllerState) -> bool:
        """True iff no fact refuses against ``expected`` (the positive form of
        :meth:`refusal_reason`)."""
        return self.refusal_reason(expected) is None

    def _identity_equals(self, expected: ExpectedControllerState) -> bool:
        return (
            self.active_identity_row_id == expected.active_identity_row_id
            and self.installation_id == expected.installation_id
            and self.release_digest == expected.release_digest
            and self.controller_key_id == expected.controller_key_id
            and self.management_identity_digest == expected.management_identity_digest
            and self.bootstrap_binding_digest == expected.bootstrap_binding_digest
            and self.enrollment_key_proof_id == expected.enrollment_key_proof_id
            and self.activation_token != ""
        )


def _unproven_state() -> ControllerFinalizationState:
    """The fully fail-closed state: NOTHING proven. Returned when the observation itself faults."""
    return ControllerFinalizationState(
        single_active_identity=False,
        active_identity_row_id="",
        activation_token="",
        installation_id="",
        release_digest="",
        controller_key_id="",
        management_identity_digest="",
        bootstrap_binding_digest="",
        enrollment_key_proof_id="",
        active_identity_matches_expected=False,
        durable_generation=_UNPROVEN_GENERATION,
        generation_agrees=False,
        marker_binding_exact=False,
        marker_activation_token="",
        credential_authenticated=False,
        signer_role_exact=False,
        runtime_observed=False,
        api_live=False,
        api_unsealed=False,
        api_image_observed="",
        api_image_expected=False,
        broker_service_active=False,
        broker_socket_exact=False,
        broker_transport_ready=False,
    )


# --------------------------------------------------------------------------- injected context


def _default_role_prober(engine: Any) -> str | None:
    """Prove the dedicated least-privilege role with exactly TWO fixed statements: the session
    identity, then the fixed transaction-level advisory lock (PostgreSQL only — it does not exist on
    SQLite and is unnecessary there). A connect/authenticate fault is a CREDENTIAL refusal; a wrong
    session identity or an unavailable advisory lock is a ROLE-posture refusal. Never generic SQL,
    never a leaked DBAPI exception."""
    from sqlalchemy import text

    try:
        with engine.begin() as conn:
            who = conn.execute(text("SELECT current_user")).scalar()
    except Exception:  # noqa: BLE001 - connect / auth / transport fault -> credential refusal
        return CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED
    if who != ENROLLMENT_SIGNER_DB_ROLE:
        return CONTROLLER_STATE_ROLE_DRIFTED
    if str(getattr(getattr(engine, "dialect", None), "name", "")) != "postgresql":
        return None
    try:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT pg_advisory_xact_lock(:k)"),
                {"k": ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY},
            )
    except Exception:  # noqa: BLE001 - the reviewed serialization lock is unavailable -> drifted
        return CONTROLLER_STATE_ROLE_DRIFTED
    return None


def _default_socket_prober(socket_path: str, *, expected_peer: tuple[int, int]) -> None:
    """A bounded no-sign transport probe: connect/close only, never a signing request. Raises
    :class:`~secp_management.ManagementError` when the accept loop is unreachable."""
    import socket as _socket  # pragma: no cover - production probe (root fence exercises it)

    af_unix = getattr(_socket, "AF_UNIX", None)
    if af_unix is None:
        raise ManagementError(CONTROLLER_STATE_BROKER_UNREACHABLE)
    sock = _socket.socket(af_unix, _socket.SOCK_STREAM)
    try:
        sock.settimeout(_CONNECT_TIMEOUT_SECONDS)
        sock.connect(socket_path)
    except OSError:
        raise ManagementError(CONTROLLER_STATE_BROKER_UNREACHABLE) from None
    finally:
        sock.close()


@dataclass(frozen=True)
class ControllerStateContext:
    """The fixed production composition context for the observer.

    ``host`` is the hardened filesystem + pinned runner shared with the bootstrap/finalization
    adapters; ``runtime_observer`` is the boundary-safe live API observer (exactly what
    ``build_api_signer_runtime_observer`` returns); ``generation_probe`` is the bounded read-only
    durable-generation reader (returning ``None`` when the generation cannot be proven).

    The remaining fields are seams: ``api_uid``/``api_gid`` are the reviewed non-root API peer pair,
    ``db_base_url`` is the dedicated-role Engine coordinate, ``lease_provider_factory`` builds the
    ACTIVE-identity reobservation provider, and ``engine_factory``/``role_prober``/``socket_prober``
    default to the real leaves (tests inject fakes)."""

    host: RealAdapterContext
    runtime_observer: Callable[[ApiSignerMarker], ApiSignerRuntimeObservation]
    generation_probe: Callable[[], int | None]
    api_uid: int = API_RUNTIME_UID
    api_gid: int = API_RUNTIME_GID
    db_base_url: str | None = None
    lease_provider_factory: Any = DbActiveControllerSigningIdentityProvider
    engine_factory: Callable[[str], Any] | None = None
    role_prober: Callable[[Any], str | None] | None = None
    socket_prober: Any = None

    def dedicated_role_engine(self, password: str) -> Any:
        if self.engine_factory is not None:
            return self.engine_factory(password)
        return build_signer_role_engine(password, base_url=self.db_base_url)


# --------------------------------------------------------------------------- the observer


class ControllerFinalizationStateObserver:
    """The strict, root-composed, READ-ONLY live-state observer the engine consults BEFORE it
    accepts an exact same-release replay or a managed upgrade. It performs NO mutation: only
    bounded hardened-filesystem reads, three fixed read-only pinned-runner queries, two fixed SQL
    statements as the dedicated role, a connect/close socket probe, and the injected runtime
    observation. It NEVER raises into the engine — any fault yields a fail-closed state."""

    __slots__ = ("_ctx",)

    def __init__(self, ctx: ControllerStateContext) -> None:
        self._ctx = ctx

    def __repr__(self) -> str:  # never a path, credential, engine URL or identity value
        return "ControllerFinalizationStateObserver(<redacted>)"

    # ---- public entry point ----
    def observe(self, *, expected: ExpectedControllerState) -> ControllerFinalizationState:
        """Observe the live state ONCE and bind it to ``expected``. Never raises; an unprovable
        fact is left False / empty / ``-1`` so :meth:`ControllerFinalizationState.refusal_reason`
        refuses."""
        try:
            return self._observe(expected)
        except Exception:  # noqa: BLE001 - the observer must never raise into the engine
            return _unproven_state()

    # ---- composition ----
    def _observe(self, expected: ExpectedControllerState) -> ControllerFinalizationState:
        ctx = self._ctx
        loc = ctx.host.locations

        # 1. broker: unit active -> socket is EXACTLY an AF_UNIX socket -> bounded connect probe.
        broker_active = self._broker_service_active()
        socket_exact = self._broker_socket_exact()
        transport_ready = socket_exact and self._broker_transport_ready()

        # 2. credential + dedicated role (the credential is read through the hardened fs from the
        #    FIXED path; a malformed/unsafe credential can never reach the engine factory).
        password = self._read_credential(loc.enrollment_signer_credential_path())
        credential_ok, role_ok, lease = self._prove_role_and_reobserve(password)

        # 3. the enablement marker: posture + schema + all twelve binding fields.
        marker = self._read_marker(loc.api_signer_marker_path())
        marker_exact = marker is not None and self._marker_binds(marker, lease, expected)

        # 4. the LIVE API signer runtime observation (only meaningful against a parsed marker).
        obs, runtime_observed = self._observe_runtime(marker)
        api_live = bool(obs.api_present and obs.api_non_root and obs.api_healthy)
        api_unsealed = bool(
            obs.marker_mounted_readonly
            and obs.binding_equals_marker
            and obs.effective_signer_is_fixed_uds
            and obs.no_env_enablement
            and obs.handoffs_absent
            and obs.enrollment_key_not_mounted
            and obs.signer_credential_not_mounted
        )

        # 5. the running API image (resolved THROUGH the compose project labels, never by name).
        image = self._observe_api_image()

        # 6. the durable generation + the runtime's no-mixed-generation proof.
        generation = self._durable_generation()
        generation_agrees = bool(
            generation >= 0 and generation == expected.generation and obs.no_mixed_generation
        )

        # The runtime observer independently re-proves the broker socket type + that the broker unit
        # bytes equal the reviewed rendering. That extra proof counts ONLY when an observation was
        # genuinely TAKEN: with no readable marker (or a faulted observer) the observation is fully
        # fail-closed, and the honest refusal is a stale marker / unhealthy API — never a phantom
        # broker fault.
        runtime_broker_ok = obs.broker_reachable if runtime_observed else True

        identity_matches = bool(lease is not None and self._identity_matches(lease, expected))
        return ControllerFinalizationState(
            single_active_identity=lease is not None,
            active_identity_row_id=_field(lease, "row_id"),
            activation_token=_field(lease, "activation_token"),
            installation_id=_field(lease, "controller_installation_id"),
            release_digest=_field(lease, "release_digest"),
            controller_key_id=_field(lease, "controller_key_id"),
            management_identity_digest=_field(lease, "management_identity_digest"),
            bootstrap_binding_digest=_field(lease, "bootstrap_evidence_digest"),
            enrollment_key_proof_id=_field(lease, "enrollment_key_proof_id"),
            active_identity_matches_expected=identity_matches,
            durable_generation=generation,
            generation_agrees=generation_agrees,
            marker_binding_exact=marker_exact,
            marker_activation_token=marker.activation_token if marker is not None else "",
            credential_authenticated=credential_ok,
            signer_role_exact=role_ok,
            runtime_observed=runtime_observed,
            api_live=api_live,
            api_unsealed=api_unsealed,
            api_image_observed=image,
            api_image_expected=bool(image != "" and image == expected.api_image_digest),
            broker_service_active=broker_active,
            broker_socket_exact=socket_exact,
            broker_transport_ready=bool(transport_ready and runtime_broker_ok),
        )

    # ---- broker ----
    def _broker_service_active(self) -> bool:
        ctx = self._ctx
        unit = ctx.host.locations.broker_unit_path().rsplit("/", 1)[-1]
        try:
            out = ctx.host.run(
                ctx.host.executables.service_manager,
                ("is-active", unit),
                timeout=_SERVICE_TIMEOUT,
                reason=CONTROLLER_STATE_BROKER_UNREACHABLE,
            )
        except ManagementError:
            return False  # inactive / failed / unqueryable -> the broker is not proven running
        return out.strip() == "active"

    def _broker_socket_exact(self) -> bool:
        """EXACTLY an AF_UNIX socket at the fixed path, root:api-group 0660, single-link, not a
        symlink — the same posture the finalizer proves. Anything else is a STALE socket object."""
        ctx = self._ctx
        try:
            st = ctx.host.fs.lstat(ctx.host.locations.broker_socket_path())
        except Exception:  # noqa: BLE001 - a probe fault cannot prove the posture -> fail closed
            return False
        return bool(
            st is not None
            and st.is_socket
            and not st.is_symlink
            and st.uid == _ROOT_UID
            and st.gid == ctx.api_gid
            and st.mode == _SOCKET_MODE
            and st.nlink == 1
        )

    def _broker_transport_ready(self) -> bool:
        ctx = self._ctx
        prober = ctx.socket_prober if ctx.socket_prober is not None else _default_socket_prober
        try:
            prober(
                ctx.host.locations.broker_socket_path(),
                expected_peer=(ctx.api_uid, ctx.api_gid),
            )
        except Exception:  # noqa: BLE001 - unreachable / refused / faulted -> not proven ready
            return False
        return True

    # ---- credential + dedicated role + ACTIVE identity ----
    def _read_credential(self, path: str) -> str | None:
        """Read the signer credential through the hardened filesystem from the FIXED path after
        proving root:root 0600 single-link regular posture. Returns ``None`` (fail closed) on any
        posture, read or grammar failure; the value never appears in a repr, log or refusal."""
        ctx = self._ctx
        try:
            st = ctx.host.fs.lstat(path)
            if not (
                st is not None
                and st.is_regular
                and not st.is_symlink
                and st.uid == _ROOT_UID
                and st.gid == _ROOT_GID
                and st.mode == _CREDENTIAL_MODE
                and st.nlink == 1
            ):
                return None
            raw = ctx.host.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=_ROOT_UID)
        except Exception:  # noqa: BLE001 - unreadable / unsafe / absent -> no credential
            return None
        value = raw.decode("ascii", "ignore").strip()
        return value if _PASSWORD_GRAMMAR.fullmatch(value) else None

    def _prove_role_and_reobserve(self, password: str | None) -> tuple[bool, bool, Any]:
        """Authenticate as the dedicated role, prove its exact posture, and — only then — lease the
        single verified ACTIVE identity. Returns ``(credential_ok, role_ok, lease_or_None)``."""
        if password is None:
            return False, False, None
        ctx = self._ctx
        try:
            engine = ctx.dedicated_role_engine(password)
        except Exception:  # noqa: BLE001 - a malformed credential never reaches the DB
            return False, False, None
        try:
            prober = ctx.role_prober if ctx.role_prober is not None else _default_role_prober
            try:
                reason = prober(engine)
            except Exception:  # noqa: BLE001 - any prober fault is a closed credential refusal
                return False, False, None
            if reason == CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED:
                return False, False, None
            if reason is not None:
                return True, False, None  # authenticated, but the role posture drifted
            return True, True, self._lease(engine)
        finally:
            _dispose(engine)

    def _lease(self, engine: Any) -> Any:
        """Reobserve the single verified ACTIVE identity under the fixed advisory lock. Absent /
        ambiguous / unverified / malformed / unreachable all yield ``None`` (fail closed)."""
        try:
            with self._ctx.lease_provider_factory(engine).lease() as lease:
                return lease
        except Exception:  # noqa: BLE001 - a bounded closed refusal is not a proven identity
            return None

    @staticmethod
    def _identity_matches(lease: Any, expected: ExpectedControllerState) -> bool:
        return bool(
            str(lease.row_id) == expected.active_identity_row_id
            and str(lease.controller_installation_id) == expected.installation_id
            and str(lease.release_digest) == expected.release_digest
            and str(lease.controller_key_id) == expected.controller_key_id
            and str(lease.management_identity_digest) == expected.management_identity_digest
            and str(lease.bootstrap_evidence_digest) == expected.bootstrap_binding_digest
            and str(lease.enrollment_key_proof_id) == expected.enrollment_key_proof_id
            and str(lease.activation_token) != ""
        )

    # ---- marker ----
    def _read_marker(self, path: str) -> ApiSignerMarker | None:
        """Parse the on-disk enablement marker after proving root:root 0644 single-link regular
        posture, the exact schema, and that every one of the twelve binding fields is present with
        the right type. Any defect yields ``None`` (a marker that cannot be read is STALE)."""
        ctx = self._ctx
        try:
            st = ctx.host.fs.lstat(path)
            if not (
                st is not None
                and st.is_regular
                and not st.is_symlink
                and st.uid == _ROOT_UID
                and st.gid == _ROOT_GID
                and st.mode == _MARKER_MODE
                and st.nlink == 1
            ):
                return None
            raw = ctx.host.fs.safe_read(path, max_bytes=_MAX_READ, expected_uid=_ROOT_UID)
            obj = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001 - unreadable / malformed marker -> not a proven marker
            return None
        if not isinstance(obj, dict) or obj.get("schema") != _MARKER_SCHEMA:
            return None
        values: dict[str, Any] = {}
        for field_name in _MARKER_STR_FIELDS:
            value = obj.get(field_name)
            if not isinstance(value, str) or not value:
                return None
            values[field_name] = value
        for field_name in _MARKER_INT_FIELDS:
            value = obj.get(field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None
            values[field_name] = value
        return ApiSignerMarker(marker_path=path, **values)

    def _marker_binds(
        self, marker: ApiSignerMarker, lease: Any, expected: ExpectedControllerState
    ) -> bool:
        """The marker must agree EXACTLY with BOTH the live leased identity (so a rotated identity
        makes the marker stale) and the authenticated expectation (so a drifted document set can
        never be replayed), including the reviewed role / UDS / peer contract."""
        if lease is None:
            return False
        live_ok = (
            marker.installation_id == str(lease.controller_installation_id)
            and marker.release_digest == str(lease.release_digest)
            and marker.active_identity_row_id == str(lease.row_id)
            and marker.activation_token == str(lease.activation_token)
            and marker.controller_key_id == str(lease.controller_key_id)
            and marker.management_identity_digest == str(lease.management_identity_digest)
            and marker.bootstrap_evidence_digest == str(lease.bootstrap_evidence_digest)
        )
        expected_ok = (
            marker.marker_path == self._ctx.host.locations.api_signer_marker_path()
            and marker.installation_id == expected.installation_id
            and marker.release_digest == expected.release_digest
            and marker.active_identity_row_id == expected.active_identity_row_id
            and marker.controller_key_id == expected.controller_key_id
            and marker.management_identity_digest == expected.management_identity_digest
            and marker.bootstrap_evidence_digest == expected.bootstrap_binding_digest
            and marker.locator_ca_digest == expected.locator_ca_digest
            and marker.signer_role_name == expected.signer_role_name
            and marker.uds_contract_identity == expected.uds_contract_identity
            and marker.api_uid == expected.api_uid
            and marker.api_gid == expected.api_gid
        )
        return bool(live_ok and expected_ok)

    # ---- live runtime ----
    def _observe_runtime(
        self, marker: ApiSignerMarker | None
    ) -> tuple[ApiSignerRuntimeObservation, bool]:
        """Take the one authoritative live runtime observation against the on-disk marker. Returns
        ``(observation, taken)``; ``taken`` is False when there was no readable marker to bind, the
        observer faulted, or it returned a foreign type — in which case a fully fail-closed
        observation stands in and NO runtime-derived fact is credited."""
        if marker is None:
            return _fail_closed_observation(), False
        try:
            obs = self._ctx.runtime_observer(marker)
        except Exception:  # noqa: BLE001 - an observer fault proves nothing -> fail closed
            return _fail_closed_observation(), False
        if not isinstance(obs, ApiSignerRuntimeObservation):
            return _fail_closed_observation(), False
        return obs, True

    def _observe_api_image(self) -> str:
        """The image id of the SINGLE API container resolved through the compose project/service
        labels via the pinned container runtime. Zero, several, malformed or unqueryable -> ``""``
        (fail closed): an unresolvable image is never an expected image."""
        ctx = self._ctx
        try:
            listing = ctx.host.run(
                ctx.host.executables.container_runtime,
                (
                    "ps",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    f"label={_COMPOSE_PROJECT_LABEL}={ctx.host.controller_project}",
                    "--filter",
                    f"label={_COMPOSE_SERVICE_LABEL}={_COMPOSE_API_SERVICE}",
                    "--format",
                    "{{.ID}}",
                ),
                timeout=_PROBE_TIMEOUT,
                reason="controller_state_api_container_list_failed",
            )
        except ManagementError:
            return ""
        ids = [line.strip() for line in listing.splitlines() if line.strip()]
        if len(ids) != 1 or _FULL_CID.fullmatch(ids[0]) is None:
            return ""
        try:
            out = ctx.host.run(
                ctx.host.executables.container_runtime,
                ("inspect", "--format", "{{.Image}}", ids[0]),
                timeout=_PROBE_TIMEOUT,
                reason="controller_state_api_inspect_failed",
            )
        except ManagementError:
            return ""
        image = out.strip()
        return image if _IMAGE_ID.fullmatch(image) else ""

    def _durable_generation(self) -> int:
        try:
            value = self._ctx.generation_probe()
        except Exception:  # noqa: BLE001 - an unprovable generation is not a proven generation
            return _UNPROVEN_GENERATION
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return _UNPROVEN_GENERATION
        return value


def build_controller_finalization_state_observer(
    ctx: ControllerStateContext,
) -> Callable[..., ControllerFinalizationState]:
    """Build the read-only live-state observation callable the engine calls from
    ``_controller_install_replay`` and ``_classify_upgrade_eligibility``.

    Returns ``observe(*, expected: ExpectedControllerState) -> ControllerFinalizationState``. The
    callable never raises and never mutates."""
    return ControllerFinalizationStateObserver(ctx).observe


# --------------------------------------------------------------------------- module helpers


def _fail_closed_observation() -> ApiSignerRuntimeObservation:
    return ApiSignerRuntimeObservation(
        api_present=False,
        api_non_root=False,
        api_healthy=False,
        marker_mounted_readonly=False,
        handoffs_absent=False,
        enrollment_key_not_mounted=False,
        signer_credential_not_mounted=False,
        effective_signer_is_fixed_uds=False,
        binding_equals_marker=False,
        no_env_enablement=False,
        broker_reachable=False,
        no_mixed_generation=False,
    )


def _field(lease: Any, name: str) -> str:
    if lease is None:
        return ""
    try:
        return str(getattr(lease, name))
    except Exception:  # noqa: BLE001 - an unreadable field is not a proven field
        return ""


def _dispose(engine: Any) -> None:
    try:
        engine.dispose()
    except Exception:  # noqa: BLE001 - disposal is best effort and never a refusal
        pass


__all__ = [
    "CONTROLLER_STATE_ACTIVE_IDENTITY_MISMATCH",
    "CONTROLLER_STATE_API_SEALED",
    "CONTROLLER_STATE_API_UNHEALTHY",
    "CONTROLLER_STATE_BROKER_UNREACHABLE",
    "CONTROLLER_STATE_CREDENTIAL_UNAUTHENTICATED",
    "CONTROLLER_STATE_GENERATION_DISAGREEMENT",
    "CONTROLLER_STATE_IMAGE_UNEXPECTED",
    "CONTROLLER_STATE_MARKER_STALE",
    "CONTROLLER_STATE_REASONS",
    "CONTROLLER_STATE_ROLE_DRIFTED",
    "CONTROLLER_STATE_SOCKET_STALE",
    "ControllerFinalizationState",
    "ControllerFinalizationStateObserver",
    "ControllerStateContext",
    "ExpectedControllerState",
    "build_controller_finalization_state_observer",
]
