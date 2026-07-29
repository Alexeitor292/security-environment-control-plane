"""READ-ONLY pre-mutation inventory of the controller-enrollment FINALIZATION installation
(SECP-PR5H-B2, 2b-3c-c — clean-room review 4803080223 finding R1).

The engine's controller-install classification used to decide FRESH from the five management
bootstrap documents plus a single ``lstat`` of the signer-enablement marker. Every OTHER
installer-owned finalization object — the controller TLS set, the API locator, the signer database
credential, the controller enrollment private key, the broker unit / service / AF_UNIX socket, the
two one-shot handoffs, the recovery journal, the transaction staging area, the dedicated
``secp_enrollment_signer`` database role, and the authoritative ACTIVE controller identity — was
unclassified, so a host carrying ORPHANED finalization state could be classified FRESH and that
state silently ADOPTED by the following install. This module closes that hole.

It is a pure OBSERVER:

* it performs **no mutation whatsoever** — only ``lstat``/``list_dir`` through the hardened
  filesystem, ONE bounded read-only service-state query through the pinned service manager (the
  same reviewed ``is-active`` idiom the finalization adapter already uses — the management plane
  gains no second systemd output parser), and (optionally) one read-only database probe through an
  INJECTED seam;
* every fixed object is classified BEFORE any mutation into a CLOSED presence/posture state; the
  three TLS objects are classified as ONE INDIVISIBLE SET (absent / complete / partial / foreign);
* every probe fault FAILS CLOSED — an unprovable absence is NOT an absence. A fault yields
  ``UNKNOWN``, which is never "clean", so a fresh install REFUSES rather than adopting silently;
* there is no generic SQL, shell, argv, or caller-selected path: every path is a code constant
  derived from :class:`~secp_management.layout.ManagementLocations`, the service query is one fixed
  two-token argv, and the optional database one-shot is a fixed, code-owned argv driven through the
  pinned compose runner. The management plane NEVER imports ``secp_api``.

The engine consumes two closed helpers:

* :attr:`ControllerFinalizationInventory.is_fresh` / :attr:`~.orphan_reason` — True only when EVERY
  installer-owned finalization object is proven absent (no broker unit/service/socket, no recovery
  journal or staging object, no dedicated signer role, no active controller enrollment identity);
  otherwise a bounded, OBJECT-SPECIFIC ``finalization_orphan_*`` reason code in a deterministic
  precedence order;
* :attr:`~.is_complete` / :attr:`~.complete_reason` / :attr:`~.has_transient_state` — the
  same-release and managed-upgrade side: every finalization object present and coherent, versus a
  partial install or an INTERRUPTED transaction (any handoff / recovery journal / staging object
  present is TRANSIENT state, never a complete install).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from secp_commissioning.canonical import canonical_json
from secp_commissioning.controller_enrollment_signer import CONTROLLER_ENROLLMENT_KEY_PATH
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE
from secp_commissioning.runtime import FileStat

from secp_management.layout import ManagementLocations
from secp_management.real_adapters import RealAdapterContext
from secp_management.topology import API_RUNTIME_GID

# --------------------------------------------------------------------------- fixed posture

_ROOT_UID = 0
_ROOT_GID = 0
_CA_BUNDLE_MODE = 0o644
_SERVER_KEY_MODE = 0o600
_CREDENTIAL_MODE = 0o600
_ENROLLMENT_KEY_MODE = 0o600
_HANDOFF_MODE = 0o640
_MARKER_MODE = 0o644
_LOCATOR_MODE = 0o644
_UNIT_MODE = 0o644
_JOURNAL_MODE = 0o600
_STAGING_DIR_MODE = 0o700
_SOCKET_MODE = 0o660

# The two fixed finalization-transaction paths. They MUST byte-match the paths
# ``controller_finalization._Journal`` / ``._Staging`` build from the same ``bootstrap_state`` root;
# a drift guard in the test suite proves the equality (this module may not reach into those
# privates at runtime).
_JOURNAL_NAME = "controller-finalization-journal.json"
_STAGING_DIR_NAME = "finalization-staging"
#: the fixed, code-owned staging backup handles (never a caller-selected name).
_STAGING_BACKUP_HANDLES: tuple[str, ...] = ("broker-unit.prior", "marker.prior", "locator.prior")
#: bounded staging enumeration — never an unbounded directory walk.
_MAX_STAGING_ENTRIES = 64

# --------------------------------------------------------------------------- fixed service query

_SERVICE_TIMEOUT = 30
_MAX_SERVICE_OUTPUT = 4 * 1024  # a single state word — never an unbounded read
#: the exact ``is-active`` words that mean the broker is RUNNING in some form (never "clean").
_IS_ACTIVE_RUNNING = frozenset({"active", "activating", "reloading", "deactivating"})
#: the exact words that PROVE the broker is not running (systemd prints these for an inactive unit
#: and for a unit it does not know at all). Anything else — "failed", empty, garbage — is UNKNOWN.
_IS_ACTIVE_STOPPED = frozenset({"inactive", "unknown"})

# --------------------------------------------------------------------------- fixed DB one-shot

_DB_STATE_SCHEMA = "secp.controller-finalization-db-state/v1"
#: the FIXED, code-owned read-only API-plane one-shot (a string constant — never an import; the
#: management plane may not import ``secp_api``).
_DB_STATE_ARGV: tuple[str, ...] = ("python", "-m", "secp_api.observe_controller_finalization_once")
_DB_STATE_TIMEOUT = 300
_DB_STATE_FIELDS = frozenset(
    {"schema", "role_name", "role_present", "active_identity_present", "activation_generation"}
)
_MAX_GENERATION = 1_000_000


# --------------------------------------------------------------------------- closed classifications


class ObjectState(str, Enum):
    """The closed presence/posture classification of ONE fixed finalization object.

    ``ABSENT`` is the only state that PROVES the object is not installed; ``UNKNOWN`` is the
    fail-closed state for any probe fault (an unprovable absence is NOT an absence)."""

    ABSENT = "absent"  # proven absent
    PRESENT = "present"  # present with the exact reviewed root-owned posture
    FOREIGN = "foreign"  # present but NOT the reviewed posture (owner/mode/type/link/nlink)
    UNKNOWN = "unknown"  # unprovable — fail closed (never treated as absent OR as installed)


class TlsSetState(str, Enum):
    """The closed classification of the three controller TLS objects as ONE INDIVISIBLE SET."""

    ABSENT = "absent"  # all three proven absent
    COMPLETE = "complete"  # all three present with the reviewed posture
    PARTIAL = "partial"  # a mixed set — never adoptable, never fresh
    FOREIGN = "foreign"  # all three present but at least one has a non-reviewed posture
    UNKNOWN = "unknown"  # unprovable — fail closed


class ServiceState(str, Enum):
    """The closed classification of the broker systemd unit's running state. The reviewed broker
    unit carries no ``[Install]`` section, so "enabled" is not a reachable posture — the unit FILE
    is classified separately as ``broker_unit``."""

    STOPPED = "stopped"  # proven not running (systemd reports inactive / unknown)
    RUNNING = "running"  # active / activating / reloading / deactivating
    UNKNOWN = "unknown"  # unprovable — fail closed (a fault, "failed", or an unrecognised word)


@dataclass(frozen=True)
class FinalizationDbState:
    """The closed result of ONE read-only database-plane probe: the dedicated signer role, the
    authoritative ACTIVE controller enrollment identity, and that identity's activation GENERATION.

    ``activation_generation`` is the public nonnegative generation of the active identity (``None``
    when there is no active identity or the probe could not prove one)."""

    signer_role: ObjectState
    active_identity: ObjectState
    activation_generation: int | None = None


#: The shipped FAIL-CLOSED default: with NO injected probe nothing about the database plane is
#: provable, so neither object can be classified absent and a fresh install refuses. Production
#: MUST inject a probe (see :func:`build_oneshot_finalization_db_probe`).
SEALED_FINALIZATION_DB_STATE = FinalizationDbState(
    signer_role=ObjectState.UNKNOWN,
    active_identity=ObjectState.UNKNOWN,
    activation_generation=None,
)

#: The injected read-only database probe seam: a zero-argument callable returning one
#: :class:`FinalizationDbState`. It must never mutate and never raise into the observer (the
#: observer defends anyway: any raise or malformed return degrades to the sealed state).
FinalizationDbProbe = Callable[[], FinalizationDbState]


# --------------------------------------------------------------------------- reason codes

#: The bounded, OBJECT-SPECIFIC orphan reason codes in their DETERMINISTIC precedence order (the
#: reviewed finalization creation order): the first non-clean object names the refusal.
ORPHAN_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("tls", "finalization_orphan_tls"),
    ("api_locator", "finalization_orphan_locator"),
    ("signer_credential", "finalization_orphan_signer_credential"),
    ("enrollment_key", "finalization_orphan_enrollment_key"),
    ("broker_unit", "finalization_orphan_broker_unit"),
    ("broker_socket", "finalization_orphan_broker_socket"),
    ("broker_service", "finalization_orphan_broker_service"),
    ("provisioning_handoff", "finalization_orphan_provisioning_handoff"),
    ("activation_handoff", "finalization_orphan_activation_handoff"),
    ("signer_marker", "finalization_orphan_marker"),
    ("recovery_journal", "finalization_orphan_recovery_journal"),
    ("staging", "finalization_orphan_staging"),
    ("signer_db_role", "finalization_orphan_signer_role"),
    ("active_identity", "finalization_orphan_active_identity"),
)

#: TRANSIENT state — an INTERRUPTED finalization transaction, never part of a complete install.
TRANSIENT_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("provisioning_handoff", "finalization_transient_provisioning_handoff"),
    ("activation_handoff", "finalization_transient_activation_handoff"),
    ("recovery_journal", "finalization_transient_recovery_journal"),
    ("staging", "finalization_transient_staging"),
)

#: Every object a COMPLETE, coherent finalization installation must carry, in precedence order.
REQUIRED_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("tls", "finalization_incomplete_tls"),
    ("api_locator", "finalization_incomplete_locator"),
    ("signer_credential", "finalization_incomplete_signer_credential"),
    ("enrollment_key", "finalization_incomplete_enrollment_key"),
    ("broker_unit", "finalization_incomplete_broker_unit"),
    ("broker_socket", "finalization_incomplete_broker_socket"),
    ("broker_service", "finalization_incomplete_broker_service"),
    ("signer_marker", "finalization_incomplete_marker"),
    ("signer_db_role", "finalization_incomplete_signer_role"),
    ("active_identity", "finalization_incomplete_active_identity"),
)

ORPHAN_REASONS: tuple[str, ...] = tuple(code for _f, code in ORPHAN_PRECEDENCE)
TRANSIENT_REASONS: tuple[str, ...] = tuple(code for _f, code in TRANSIENT_PRECEDENCE)
INCOMPLETE_REASONS: tuple[str, ...] = tuple(code for _f, code in REQUIRED_PRECEDENCE)


def _is_clean(state: object) -> bool:
    """True ONLY for a PROVEN absence — every other state (including ``UNKNOWN``) is not clean."""
    if isinstance(state, TlsSetState):
        return state is TlsSetState.ABSENT
    if isinstance(state, ServiceState):
        return state is ServiceState.STOPPED
    return state is ObjectState.ABSENT


def _is_installed(state: object) -> bool:
    """True ONLY for a PROVEN, reviewed-posture installation — never ``FOREIGN``/``UNKNOWN``."""
    if isinstance(state, TlsSetState):
        return state is TlsSetState.COMPLETE
    if isinstance(state, ServiceState):
        return state is ServiceState.RUNNING
    return state is ObjectState.PRESENT


# --------------------------------------------------------------------------- the inventory


@dataclass(frozen=True)
class ControllerFinalizationInventory:
    """One READ-ONLY, pre-mutation classification of the ENTIRE controller-enrollment finalization
    installation. Every field is a closed presence/posture classification (plus the two bounded
    public scalars ``activation_generation`` and ``staged_backup_objects``); nothing here is a
    secret, a path, a byte, or a raw exception."""

    tls: TlsSetState
    api_locator: ObjectState
    signer_credential: ObjectState
    enrollment_key: ObjectState
    broker_unit: ObjectState
    broker_socket: ObjectState
    broker_service: ServiceState
    provisioning_handoff: ObjectState
    activation_handoff: ObjectState
    signer_marker: ObjectState
    recovery_journal: ObjectState
    staging: ObjectState
    signer_db_role: ObjectState
    active_identity: ObjectState
    activation_generation: int | None = None
    staged_backup_objects: int = 0

    # ---- freshness -------------------------------------------------------------------------
    @property
    def orphan_reason(self) -> str | None:
        """The bounded, OBJECT-SPECIFIC reason the host is NOT fresh, or ``None`` when it is.

        Deterministic precedence: the reviewed finalization creation order (:data:`ORPHAN_
        PRECEDENCE`). A fail-closed ``UNKNOWN`` is reported exactly like a present object — an
        unprovable absence is not an absence."""
        for name, code in ORPHAN_PRECEDENCE:
            if not _is_clean(getattr(self, name)):
                return code
        if self.activation_generation is not None:
            # an activation generation with no active identity is incoherent -> not fresh
            return "finalization_orphan_active_identity"
        return None

    @property
    def is_fresh(self) -> bool:
        """True ONLY when EVERY installer-owned finalization object is PROVEN absent: no TLS
        material, locator, signer credential, enrollment key, broker unit/service/socket, handoff,
        marker, recovery journal or staging object, no dedicated signer database role, and no
        active controller enrollment identity or activation generation."""
        return self.orphan_reason is None

    # ---- completeness (the same-release / managed-upgrade side) -----------------------------
    @property
    def transient_reason(self) -> str | None:
        """The first TRANSIENT object present — a handoff, the recovery journal, or a staging
        object — i.e. the fingerprint of an INTERRUPTED finalization transaction."""
        for name, code in TRANSIENT_PRECEDENCE:
            if not _is_clean(getattr(self, name)):
                return code
        return None

    @property
    def has_transient_state(self) -> bool:
        return self.transient_reason is not None

    @property
    def complete_reason(self) -> str | None:
        """``None`` when every finalization object is present with its reviewed posture AND no
        transient object exists; otherwise the bounded object-specific reason it is partial
        (``finalization_incomplete_*``) or transient (``finalization_transient_*``)."""
        transient = self.transient_reason
        if transient is not None:
            return transient
        for name, code in REQUIRED_PRECEDENCE:
            if not _is_installed(getattr(self, name)):
                return code
        return None

    @property
    def is_complete(self) -> bool:
        """True only for a coherent, fully installed, non-transient finalization installation."""
        return self.complete_reason is None

    # ---- public evidence -------------------------------------------------------------------
    def public_facts(self) -> dict[str, str]:
        """The whole classification as a flat public dict (for a refusal receipt / evidence).
        Never a path, byte, secret, or exception."""
        facts: dict[str, str] = {}
        for name, _code in ORPHAN_PRECEDENCE:
            value = getattr(self, name)
            facts[name] = str(value.value)
        facts["activation_generation"] = (
            "" if self.activation_generation is None else str(self.activation_generation)
        )
        facts["staged_backup_objects"] = str(self.staged_backup_objects)
        return facts


# --------------------------------------------------------------------------- filesystem probes


def _lstat(ctx: RealAdapterContext, path: str) -> tuple[FileStat | None, bool]:
    """``(stat, proven)`` — ``proven`` is False when the probe FAULTED, so an absent result can
    never be mistaken for a proven absence."""
    try:
        return ctx.fs.lstat(path), True
    except Exception:  # noqa: BLE001 - any fs fault is unprovable -> fail closed
        return None, False


def _regular_object(ctx: RealAdapterContext, path: str, *, gid: int, mode: int) -> ObjectState:
    """Classify one fixed root-owned regular finalization file (mirrors the adapter's
    ``_root_regular_posture``: regular, not a symlink, root uid, exact gid + mode, single link)."""
    st, proven = _lstat(ctx, path)
    if not proven:
        return ObjectState.UNKNOWN
    if st is None:
        return ObjectState.ABSENT
    exact = (
        st.is_regular
        and not st.is_symlink
        and st.uid == _ROOT_UID
        and st.gid == gid
        and st.mode == mode
        and st.nlink == 1
    )
    return ObjectState.PRESENT if exact else ObjectState.FOREIGN


def _directory_object(ctx: RealAdapterContext, path: str, *, mode: int) -> ObjectState:
    st, proven = _lstat(ctx, path)
    if not proven:
        return ObjectState.UNKNOWN
    if st is None:
        return ObjectState.ABSENT
    exact = (
        st.is_dir
        and not st.is_symlink
        and st.uid == _ROOT_UID
        and st.gid == _ROOT_GID
        and st.mode == mode
    )
    return ObjectState.PRESENT if exact else ObjectState.FOREIGN


def _socket_object(ctx: RealAdapterContext, path: str, *, gid: int) -> ObjectState:
    """Classify the broker socket. PRESENT requires EXACTLY an AF_UNIX socket (``FileStat.
    is_socket`` — POSIX ``S_ISSOCK``) at root:api-group 0660, single-link, not a symlink; any other
    node at the fixed path is a FOREIGN object, never an absence."""
    st, proven = _lstat(ctx, path)
    if not proven:
        return ObjectState.UNKNOWN
    if st is None:
        return ObjectState.ABSENT
    exact = (
        st.is_socket
        and not st.is_symlink
        and st.uid == _ROOT_UID
        and st.gid == gid
        and st.mode == _SOCKET_MODE
        and st.nlink == 1
    )
    return ObjectState.PRESENT if exact else ObjectState.FOREIGN


def _tls_set(ctx: RealAdapterContext, loc: ManagementLocations) -> TlsSetState:
    """Classify the three controller TLS objects as ONE INDIVISIBLE SET — a partial set is never
    adoptable and never fresh (mirrors the adapter's ``finalization_tls_partial_set`` refusal)."""
    states = (
        _regular_object(ctx, loc.controller_ca_bundle_path(), gid=_ROOT_GID, mode=_CA_BUNDLE_MODE),
        _regular_object(
            ctx, loc.controller_server_cert_path(), gid=_ROOT_GID, mode=_CA_BUNDLE_MODE
        ),
        _regular_object(
            ctx, loc.controller_server_key_path(), gid=_ROOT_GID, mode=_SERVER_KEY_MODE
        ),
    )
    if any(s is ObjectState.UNKNOWN for s in states):
        return TlsSetState.UNKNOWN
    if all(s is ObjectState.ABSENT for s in states):
        return TlsSetState.ABSENT
    if any(s is ObjectState.ABSENT for s in states):
        return TlsSetState.PARTIAL
    if all(s is ObjectState.PRESENT for s in states):
        return TlsSetState.COMPLETE
    return TlsSetState.FOREIGN


def finalization_recovery_journal_path(locations: ManagementLocations) -> str:
    """The fixed durable finalization recovery-journal path (code constant, never selected)."""
    return f"{locations.bootstrap_state}/{_JOURNAL_NAME}"


def finalization_staging_root(locations: ManagementLocations) -> str:
    """The fixed root of the finalization transaction staging area (code constant)."""
    return f"{locations.bootstrap_state}/{_STAGING_DIR_NAME}"


def _staged_backup_objects(ctx: RealAdapterContext, root: str) -> int:
    """A BOUNDED count of staged backup objects: at most :data:`_MAX_STAGING_ENTRIES` transaction
    directories, each probed for exactly the three fixed code-owned handles. Never an unbounded
    walk, never a caller-selected name. A fault yields 0 (the staging root is already classified
    non-absent, so freshness has failed closed regardless)."""
    try:
        entries = ctx.fs.list_dir(root)
    except Exception:  # noqa: BLE001 - an enumeration fault is informational only
        return 0
    if not entries:
        return 0
    count = 0
    for entry in entries[:_MAX_STAGING_ENTRIES]:
        for handle in _STAGING_BACKUP_HANDLES:
            st, proven = _lstat(ctx, f"{root}/{entry}/{handle}")
            if proven and st is not None:
                count += 1
    return count


# --------------------------------------------------------------------------- service probe


def _broker_service_state(ctx: RealAdapterContext, unit: str) -> ServiceState:
    """ONE bounded, READ-ONLY ``is-active`` query of the fixed broker unit through the pinned
    service manager — deliberately the SAME reviewed idiom the finalization adapter already uses, so
    the management plane gains NO second systemd output parser (the coherent ``show`` observation
    belongs to the reviewed PR5D deployment adapter and is never duplicated here).

    The EXIT CODE is deliberately ignored: systemd returns nonzero for a merely INACTIVE unit, which
    the pinned runner cannot distinguish from a genuine fault, so a clean host would fail closed
    forever. systemd prints the state word on stdout in every case, so the classification is that
    single bounded word; an unrecognised word, empty output, or a runner fault is ``UNKNOWN``.

    "Enabled" is not a reachable posture for this unit: the reviewed broker unit is rendered WITHOUT
    an ``[Install]`` section (present-but-disabled, started explicitly), so the unit FILE's presence
    — classified independently as ``broker_unit`` — plus this runtime state cover it completely."""
    try:
        result = ctx.runner.run(
            ctx.executables.service_manager,
            ("is-active", unit),
            timeout_seconds=_SERVICE_TIMEOUT,
            max_output_bytes=_MAX_SERVICE_OUTPUT,
        )
        word = str(result.stdout).strip()
    except Exception:  # noqa: BLE001 - any runner fault is unprovable -> fail closed
        return ServiceState.UNKNOWN
    if word in _IS_ACTIVE_RUNNING:
        return ServiceState.RUNNING
    if word in _IS_ACTIVE_STOPPED:
        return ServiceState.STOPPED
    return ServiceState.UNKNOWN


# --------------------------------------------------------------------------- database probe seam


def _observe_db(role_probe: FinalizationDbProbe | None) -> FinalizationDbState:
    """Drive the INJECTED read-only database probe, defending the observer completely: no probe, a
    raising probe, a wrong-type return, or an out-of-grammar generation all degrade to the SEALED
    (fully UNKNOWN) state — never to a proven absence."""
    if role_probe is None:
        return SEALED_FINALIZATION_DB_STATE
    try:
        observed = role_probe()
    except Exception:  # noqa: BLE001 - a probe fault can never prove an absence
        return SEALED_FINALIZATION_DB_STATE
    if type(observed) is not FinalizationDbState:
        return SEALED_FINALIZATION_DB_STATE
    if not isinstance(observed.signer_role, ObjectState) or not isinstance(
        observed.active_identity, ObjectState
    ):
        return SEALED_FINALIZATION_DB_STATE
    generation = observed.activation_generation
    if generation is not None and (
        type(generation) is not int or generation < 0 or generation > _MAX_GENERATION
    ):
        return SEALED_FINALIZATION_DB_STATE
    return observed


def _parse_db_receipt(raw: str) -> FinalizationDbState:
    """Strictly parse the fixed read-only one-shot's canonical receipt. ANY deviation (non-canonical
    output, missing/extra field, wrong schema or role name, non-bool flag, out-of-grammar
    generation) degrades to the sealed state — the one-shot can never rubber-stamp an absence."""
    body = raw.strip()
    if not body:
        return SEALED_FINALIZATION_DB_STATE
    line = body.splitlines()[-1]
    try:
        parsed = json.loads(line)
    except ValueError:
        return SEALED_FINALIZATION_DB_STATE
    if not isinstance(parsed, dict) or set(parsed) != _DB_STATE_FIELDS:
        return SEALED_FINALIZATION_DB_STATE
    if canonical_json(parsed).encode("utf-8") != line.encode("utf-8"):
        return SEALED_FINALIZATION_DB_STATE
    if parsed["schema"] != _DB_STATE_SCHEMA or parsed["role_name"] != ENROLLMENT_SIGNER_DB_ROLE:
        return SEALED_FINALIZATION_DB_STATE
    role = parsed["role_present"]
    identity = parsed["active_identity_present"]
    generation = parsed["activation_generation"]
    if not isinstance(role, bool) or not isinstance(identity, bool):
        return SEALED_FINALIZATION_DB_STATE
    if generation is not None and (
        type(generation) is not int or generation < 0 or generation > _MAX_GENERATION
    ):
        return SEALED_FINALIZATION_DB_STATE
    if not identity and generation is not None:
        return SEALED_FINALIZATION_DB_STATE  # incoherent: a generation with no active identity
    return FinalizationDbState(
        signer_role=ObjectState.PRESENT if role else ObjectState.ABSENT,
        active_identity=ObjectState.PRESENT if identity else ObjectState.ABSENT,
        activation_generation=generation,
    )


def build_oneshot_finalization_db_probe(ctx: RealAdapterContext) -> FinalizationDbProbe:
    """Build the PRODUCTION database probe: ONE fixed, code-owned, READ-ONLY API-plane one-shot run
    through the pinned compose runner (``run --rm --no-deps`` with NO volume, NO handoff, and no
    caller-selectable argv), whose canonical receipt reports only three public facts — whether the
    dedicated ``secp_enrollment_signer`` role exists, whether an ACTIVE controller enrollment
    identity exists, and that identity's nonnegative activation generation.

    The management plane never imports ``secp_api``: the module name is a fixed STRING constant
    executed inside the API container, exactly like the reviewed provisioning/activation one-shots.
    The returned closure NEVER raises and NEVER mutates; every fault yields the sealed state, so a
    fresh install refuses rather than adopting an unprovable absence."""

    def probe() -> FinalizationDbState:
        try:
            out = ctx.run(
                ctx.executables.compose_runtime,
                (
                    "--project-name",
                    ctx.controller_project,
                    "--file",
                    ctx.locations.controller_compose_path(),
                    "run",
                    "--rm",
                    "--no-deps",
                    "api",
                    *_DB_STATE_ARGV,
                ),
                timeout=_DB_STATE_TIMEOUT,
                reason="finalization_db_state_oneshot_failed",
            )
        except Exception:  # noqa: BLE001 - the probe must never raise into the observer
            return SEALED_FINALIZATION_DB_STATE
        try:
            return _parse_db_receipt(out)
        except Exception:  # noqa: BLE001 - a malformed receipt can never prove an absence
            return SEALED_FINALIZATION_DB_STATE

    return probe


# --------------------------------------------------------------------------- the observation


def observe_finalization_inventory(
    ctx: RealAdapterContext,
    *,
    role_probe: FinalizationDbProbe | None = None,
    api_gid: int = API_RUNTIME_GID,
) -> ControllerFinalizationInventory:
    """Classify EVERY fixed controller-enrollment finalization object BEFORE any mutation.

    Performs no mutation whatsoever: hardened-filesystem ``lstat``/``list_dir`` of fixed code-owned
    paths, ONE bounded read-only service-state query through the pinned service manager, and the
    INJECTED read-only database probe (``role_probe``). With NO probe injected the database plane is
    unprovable, so :attr:`ControllerFinalizationInventory.is_fresh` is False — production MUST wire
    :func:`build_oneshot_finalization_db_probe` (or another reviewed read-only boundary)."""
    loc = ctx.locations
    staging_root = finalization_staging_root(loc)
    staging = _directory_object(ctx, staging_root, mode=_STAGING_DIR_MODE)
    staged = 0 if staging is ObjectState.ABSENT else _staged_backup_objects(ctx, staging_root)
    db = _observe_db(role_probe)
    return ControllerFinalizationInventory(
        tls=_tls_set(ctx, loc),
        api_locator=_regular_object(
            ctx, loc.controller_api_locator_path(), gid=_ROOT_GID, mode=_LOCATOR_MODE
        ),
        signer_credential=_regular_object(
            ctx, loc.enrollment_signer_credential_path(), gid=_ROOT_GID, mode=_CREDENTIAL_MODE
        ),
        enrollment_key=_regular_object(
            ctx, CONTROLLER_ENROLLMENT_KEY_PATH, gid=_ROOT_GID, mode=_ENROLLMENT_KEY_MODE
        ),
        broker_unit=_regular_object(ctx, loc.broker_unit_path(), gid=_ROOT_GID, mode=_UNIT_MODE),
        broker_socket=_socket_object(ctx, loc.broker_socket_path(), gid=api_gid),
        broker_service=_broker_service_state(ctx, loc.broker_unit_path().rsplit("/", 1)[-1]),
        provisioning_handoff=_regular_object(
            ctx, loc.provisioning_handoff_host_path(), gid=api_gid, mode=_HANDOFF_MODE
        ),
        activation_handoff=_regular_object(
            ctx, loc.activation_handoff_host_path(), gid=api_gid, mode=_HANDOFF_MODE
        ),
        signer_marker=_regular_object(
            ctx, loc.api_signer_marker_path(), gid=_ROOT_GID, mode=_MARKER_MODE
        ),
        recovery_journal=_regular_object(
            ctx, finalization_recovery_journal_path(loc), gid=_ROOT_GID, mode=_JOURNAL_MODE
        ),
        staging=staging,
        signer_db_role=db.signer_role,
        active_identity=db.active_identity,
        activation_generation=db.activation_generation,
        staged_backup_objects=staged,
    )


__all__ = [
    "INCOMPLETE_REASONS",
    "ORPHAN_PRECEDENCE",
    "ORPHAN_REASONS",
    "REQUIRED_PRECEDENCE",
    "SEALED_FINALIZATION_DB_STATE",
    "TRANSIENT_PRECEDENCE",
    "TRANSIENT_REASONS",
    "ControllerFinalizationInventory",
    "FinalizationDbProbe",
    "FinalizationDbState",
    "ObjectState",
    "ServiceState",
    "TlsSetState",
    "build_oneshot_finalization_db_probe",
    "finalization_recovery_journal_path",
    "finalization_staging_root",
    "observe_finalization_inventory",
]
