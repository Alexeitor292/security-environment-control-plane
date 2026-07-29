"""Hermetic proofs for the READ-ONLY controller-finalization inventory (SECP-PR5H-B2, 2b-3c-c).

Clean-room review 4803080223 finding R1: fresh classification looked only at the five management
documents plus the signer marker, so a host carrying ORPHANED finalization objects could be
classified FRESH and those objects later adopted. ``controller_finalization_inventory`` closes that
by classifying EVERY fixed finalization object before any mutation.

The suite runs entirely on the hardened ``InMemoryFilesystem`` (``seed_file``/``seed_dir``/
``seed_socket``), a fake pinned runner, and a fake read-only database probe — no host, container
runtime, systemd, or database. It proves a genuinely clean host is FRESH, that EACH orphan ALONE
flips ``.is_fresh`` to False with its exact object-specific reason code, that every probe fault
fails CLOSED (an unprovable absence is never an absence), that the module mutates nothing, and that
it never imports ``secp_api``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from secp_commissioning.canonical import canonical_json
from secp_commissioning.controller_enrollment_signer import CONTROLLER_ENROLLMENT_KEY_PATH
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE
from secp_commissioning.runtime import FileStat, InMemoryFilesystem
from secp_management import controller_finalization as cf
from secp_management import controller_finalization_inventory as inv_mod
from secp_management.controller_finalization_inventory import (
    INCOMPLETE_REASONS,
    ORPHAN_PRECEDENCE,
    ORPHAN_REASONS,
    SEALED_FINALIZATION_DB_STATE,
    TRANSIENT_REASONS,
    ControllerFinalizationInventory,
    FinalizationDbState,
    ObjectState,
    ServiceState,
    TlsSetState,
    build_oneshot_finalization_db_probe,
    finalization_recovery_journal_path,
    finalization_staging_root,
    observe_finalization_inventory,
)
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_management.topology import API_RUNTIME_GID
from secp_operator_deployment.host_process import CommandResult
from secp_operator_deployment.pinned_exec import ExecutablePin

_LOC = ManagementLocations()
_PIN = ExecutablePin(path="/usr/bin/systemctl", digest="sha256:" + "1" * 64)

_CA = _LOC.controller_ca_bundle_path()
_CERT = _LOC.controller_server_cert_path()
_KEY = _LOC.controller_server_key_path()
_LOCATOR = _LOC.controller_api_locator_path()
_CRED = _LOC.enrollment_signer_credential_path()
_UNIT = _LOC.broker_unit_path()
_UNIT_NAME = _UNIT.rsplit("/", 1)[-1]
_SOCKET = _LOC.broker_socket_path()
_PROV = _LOC.provisioning_handoff_host_path()
_ACT = _LOC.activation_handoff_host_path()
_MARKER = _LOC.api_signer_marker_path()
_GATE = _LOC.api_signer_readiness_gate_path()
#: a conformant readiness-gate file body: 256 bits of lowercase hex plus exactly one LF.
_GATE_BYTES = b"a" * 64 + b"\n"
_JOURNAL = finalization_recovery_journal_path(_LOC)
_STAGING = finalization_staging_root(_LOC)
_BOOTSTRAP_STATE = _LOC.bootstrap_state

# systemd prints the state word on stdout and mirrors it in the exit code; the observer classifies
# the WORD (a nonzero exit for a merely inactive unit is not a fault).
_INACTIVE = ("inactive\n", 3)
_RUNNING = ("active\n", 0)
_UNIT_UNKNOWN = ("unknown\n", 4)


# --------------------------------------------------------------------------- fakes


class _FakeRunner:
    """Records every argv; answers the fixed read-only ``is-active`` query and the fixed read-only
    compose one-shot. Never mutates anything."""

    def __init__(
        self,
        *,
        service: tuple[str, int] = _INACTIVE,
        raise_on_service: bool = False,
        oneshot: str = "",
        oneshot_exit: int = 0,
    ) -> None:
        self._service = service
        self._raise_on_service = raise_on_service
        self._oneshot = oneshot
        self._oneshot_exit = oneshot_exit
        self.calls: list[tuple[str, ...]] = []

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001,ANN201
        argv = tuple(argv_tail)
        self.calls.append(argv)
        if argv and argv[0] == "is-active":
            if self._raise_on_service:
                raise RuntimeError("injected runner fault")
            stdout, exit_code = self._service
            return CommandResult(exit_code, stdout)
        return CommandResult(self._oneshot_exit, self._oneshot)


class _FaultyLstat:
    """Wraps the in-memory filesystem and raises on ``lstat`` of ONE fixed path, so an unprovable
    absence can be distinguished from a proven one."""

    def __init__(self, fs: InMemoryFilesystem, fault_path: str) -> None:
        self._fs = fs
        self._fault = fault_path

    def lstat(self, path: str) -> FileStat | None:
        if path == self._fault:
            raise RuntimeError("injected lstat fault")
        return self._fs.lstat(path)

    def __getattr__(self, name: str):  # noqa: ANN204 - delegate the rest of the protocol
        return getattr(self._fs, name)


def _clean_db() -> FinalizationDbState:
    return FinalizationDbState(signer_role=ObjectState.ABSENT, active_identity=ObjectState.ABSENT)


def _probe(state: FinalizationDbState):  # noqa: ANN202
    return lambda: state


def _ctx(fs, runner: _FakeRunner) -> RealAdapterContext:  # noqa: ANN001
    return RealAdapterContext(
        locations=_LOC,
        fs=fs,  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        executables=PinnedExecutables(
            container_runtime=_PIN, compose_runtime=_PIN, service_manager=_PIN
        ),
        controller_project="secp-controller",
    )


def _observe(
    fs=None,  # noqa: ANN001
    runner: _FakeRunner | None = None,
    db: FinalizationDbState | None = None,
) -> ControllerFinalizationInventory:
    return observe_finalization_inventory(
        _ctx(InMemoryFilesystem() if fs is None else fs, runner or _FakeRunner()),
        role_probe=_probe(_clean_db() if db is None else db),
    )


# --------------------------------------------------------------------------- seeding helpers


def _fs() -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for directory in (
        "/etc/secp/controller",
        "/etc/secp/controller/tls",
        "/etc/secp/controller/credentials",
        "/etc/systemd",
        "/etc/systemd/system",
        "/run",
        "/run/secp",  # systemd's RuntimeDirectory (root-owned; the installer never writes here)
        _BOOTSTRAP_STATE,
        f"{_BOOTSTRAP_STATE}/handoff",
    ):
        fs.seed_dir(directory)
    return fs


def _seed_tls(fs: InMemoryFilesystem, *, ca: bool = True, cert: bool = True, key: bool = True):
    if ca:
        fs.seed_file(_CA, b"CA", mode=0o644)
    if cert:
        fs.seed_file(_CERT, b"CERT", mode=0o644)
    if key:
        fs.seed_file(_KEY, b"KEY", mode=0o600)


def _seed_staging(fs: InMemoryFilesystem, *, handles: tuple[str, ...] = ("marker.prior",)) -> None:
    fs.seed_dir(_STAGING, mode=0o700)
    fs.seed_dir(f"{_STAGING}/tx-abc", mode=0o700)
    for handle in handles:
        fs.seed_file(f"{_STAGING}/tx-abc/{handle}", b"PRIOR", mode=0o600)


def _seed_complete(fs: InMemoryFilesystem, *, gate: bool = True) -> None:
    """Every installer-owned object present with its exact reviewed posture (no transient state).

    ``gate=False`` omits ONLY the readiness-origin gate, so an otherwise complete installation
    can be proven incomplete on that one object alone."""
    _seed_tls(fs)
    fs.seed_file(_LOCATOR, b"{}", mode=0o644)
    fs.seed_file(_CRED, b"secret\n", mode=0o600)
    fs.seed_file(CONTROLLER_ENROLLMENT_KEY_PATH, b"K" * 32, mode=0o600)
    fs.seed_file(_UNIT, b"[Unit]\n", mode=0o644)
    fs.seed_socket(_SOCKET, gid=API_RUNTIME_GID, mode=0o660)
    if gate:
        fs.seed_file(_GATE, _GATE_BYTES, gid=API_RUNTIME_GID, mode=0o640)
    fs.seed_file(_MARKER, b"{}", mode=0o644)


def _complete_db() -> FinalizationDbState:
    return FinalizationDbState(
        signer_role=ObjectState.PRESENT,
        active_identity=ObjectState.PRESENT,
        activation_generation=3,
    )


# --------------------------------------------------------------------------- a truly clean host


def test_a_truly_clean_host_is_fresh() -> None:
    inventory = _observe()
    assert inventory.is_fresh is True
    assert inventory.orphan_reason is None


def test_a_clean_host_classifies_every_object_as_a_PROVEN_absence() -> None:
    inventory = _observe(_fs())
    assert inventory.tls is TlsSetState.ABSENT
    assert inventory.broker_service is ServiceState.STOPPED
    for name in (
        "api_locator",
        "signer_credential",
        "enrollment_key",
        "broker_unit",
        "broker_socket",
        "provisioning_handoff",
        "activation_handoff",
        "signer_marker",
        "recovery_journal",
        "staging",
        "signer_db_role",
        "active_identity",
    ):
        assert getattr(inventory, name) is ObjectState.ABSENT, name
    assert inventory.activation_generation is None
    assert inventory.staged_backup_objects == 0
    assert inventory.is_fresh is True


# ------------------------------------------------------- EACH orphan alone refuses freshness


def test_orphan_tls_complete_set() -> None:
    fs = _fs()
    _seed_tls(fs)
    inventory = _observe(fs)
    assert inventory.tls is TlsSetState.COMPLETE
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_tls"


def test_orphan_tls_partial_set() -> None:
    fs = _fs()
    _seed_tls(fs, key=False)  # ca + cert, no server key -> an indivisible set is PARTIAL
    inventory = _observe(fs)
    assert inventory.tls is TlsSetState.PARTIAL
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_tls"


def test_orphan_tls_single_object_is_still_partial() -> None:
    fs = _fs()
    _seed_tls(fs, ca=False, cert=False)  # only the private key survives
    inventory = _observe(fs)
    assert inventory.tls is TlsSetState.PARTIAL
    assert inventory.orphan_reason == "finalization_orphan_tls"


def test_orphan_locator() -> None:
    fs = _fs()
    fs.seed_file(_LOCATOR, b"{}", mode=0o644)
    inventory = _observe(fs)
    assert inventory.api_locator is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_locator"


def test_orphan_signer_credential() -> None:
    fs = _fs()
    fs.seed_file(_CRED, b"secret\n", mode=0o600)
    inventory = _observe(fs)
    assert inventory.signer_credential is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_signer_credential"


def test_orphan_enrollment_key() -> None:
    fs = _fs()
    fs.seed_file(CONTROLLER_ENROLLMENT_KEY_PATH, b"K" * 32, mode=0o600)
    inventory = _observe(fs)
    assert inventory.enrollment_key is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_enrollment_key"


def test_orphan_broker_unit() -> None:
    fs = _fs()
    fs.seed_file(_UNIT, b"[Unit]\n", mode=0o644)
    inventory = _observe(fs)
    assert inventory.broker_unit is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_broker_unit"


def test_orphan_broker_socket() -> None:
    fs = _fs()
    fs.seed_socket(_SOCKET, gid=API_RUNTIME_GID, mode=0o660)
    inventory = _observe(fs)
    assert inventory.broker_socket is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_broker_socket"


@pytest.mark.parametrize("word", ["active\n", "activating\n", "reloading\n", "deactivating\n"])
def test_orphan_broker_service_running(word: str) -> None:
    inventory = _observe(_fs(), _FakeRunner(service=(word, 0)))
    assert inventory.broker_service is ServiceState.RUNNING
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_broker_service"


@pytest.mark.parametrize("service", [_INACTIVE, _UNIT_UNKNOWN])
def test_a_nonzero_is_active_exit_is_a_PROVEN_stop_not_a_fault(service: tuple[str, int]) -> None:
    # systemd exits 3/4 for an inactive/unknown unit; conflating that with a runner fault would make
    # every genuinely clean host fail closed forever, so the STATE WORD is authoritative.
    inventory = _observe(_fs(), _FakeRunner(service=service))
    assert inventory.broker_service is ServiceState.STOPPED
    assert inventory.is_fresh is True


def test_orphan_provisioning_handoff() -> None:
    fs = _fs()
    fs.seed_file(_PROV, b"{}", gid=API_RUNTIME_GID, mode=0o640)
    inventory = _observe(fs)
    assert inventory.provisioning_handoff is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_provisioning_handoff"


def test_orphan_activation_handoff() -> None:
    fs = _fs()
    fs.seed_file(_ACT, b"{}", gid=API_RUNTIME_GID, mode=0o640)
    inventory = _observe(fs)
    assert inventory.activation_handoff is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_activation_handoff"


def test_orphan_marker() -> None:
    fs = _fs()
    fs.seed_file(_MARKER, b"{}", mode=0o644)
    inventory = _observe(fs)
    assert inventory.signer_marker is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_marker"


def test_orphan_recovery_journal() -> None:
    fs = _fs()
    fs.seed_file(_JOURNAL, b"{}", mode=0o600)
    inventory = _observe(fs)
    assert inventory.recovery_journal is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_recovery_journal"


def test_orphan_staging_object() -> None:
    fs = _fs()
    _seed_staging(fs, handles=("marker.prior", "locator.prior"))
    inventory = _observe(fs)
    assert inventory.staging is ObjectState.PRESENT
    assert inventory.staged_backup_objects == 2  # the bounded, fixed-handle backup scan
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_staging"


def test_orphan_empty_staging_directory_is_still_not_fresh() -> None:
    fs = _fs()
    _seed_staging(fs, handles=())
    inventory = _observe(fs)
    assert inventory.staging is ObjectState.PRESENT
    assert inventory.staged_backup_objects == 0
    assert inventory.orphan_reason == "finalization_orphan_staging"


def test_orphan_signer_db_role() -> None:
    db = FinalizationDbState(signer_role=ObjectState.PRESENT, active_identity=ObjectState.ABSENT)
    inventory = _observe(_fs(), db=db)
    assert inventory.signer_db_role is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_signer_role"


def test_orphan_active_controller_identity() -> None:
    db = FinalizationDbState(signer_role=ObjectState.ABSENT, active_identity=ObjectState.PRESENT)
    inventory = _observe(_fs(), db=db)
    assert inventory.active_identity is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_active_identity"


def test_orphan_activation_generation_without_an_active_identity() -> None:
    db = FinalizationDbState(
        signer_role=ObjectState.ABSENT, active_identity=ObjectState.ABSENT, activation_generation=0
    )
    inventory = _observe(_fs(), db=db)
    assert inventory.activation_generation == 0
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_active_identity"


def test_every_orphan_reason_code_is_reachable_from_a_single_seeded_object() -> None:
    # a structural completeness check over the whole precedence table: exactly the codes the engine
    # may ever see, each bounded and object-specific.
    assert len(set(ORPHAN_REASONS)) == len(ORPHAN_REASONS) == len(ORPHAN_PRECEDENCE) == 15
    assert all(
        code.startswith("finalization_orphan_") and len(code) <= 60 for code in ORPHAN_REASONS
    )


# ------------------------------------------------------- foreign posture is never an absence


def test_a_wrong_posture_marker_is_foreign_not_absent() -> None:
    fs = _fs()
    fs.seed_file(_MARKER, b"{}", uid=1000, mode=0o644)  # not root-owned
    inventory = _observe(fs)
    assert inventory.signer_marker is ObjectState.FOREIGN
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_marker"
    assert inventory.is_complete is False


# ------------------------------------------------- the readiness-origin gate (2b-3c-c, section C)


def test_an_orphan_readiness_gate_refuses_freshness_before_any_mutation() -> None:
    fs = _fs()
    fs.seed_file(_GATE, _GATE_BYTES, gid=API_RUNTIME_GID, mode=0o640)
    inventory = _observe(fs)
    assert inventory.readiness_gate is ObjectState.PRESENT
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_readiness_gate"


def test_a_world_readable_readiness_gate_is_foreign_not_installed() -> None:
    # the gate is a 256-bit machine SECRET: a world bit means some other party may already hold it,
    # so it is never adoptable as an installed object.
    fs = _fs()
    fs.seed_file(_GATE, _GATE_BYTES, gid=API_RUNTIME_GID, mode=0o644)
    inventory = _observe(fs)
    assert inventory.readiness_gate is ObjectState.FOREIGN
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_readiness_gate"


def test_a_non_root_owned_readiness_gate_is_foreign() -> None:
    fs = _fs()
    fs.seed_file(_GATE, _GATE_BYTES, uid=1000, gid=API_RUNTIME_GID, mode=0o640)
    inventory = _observe(fs)
    assert inventory.readiness_gate is ObjectState.FOREIGN
    assert inventory.orphan_reason == "finalization_orphan_readiness_gate"


def test_a_readiness_gate_group_the_api_cannot_read_is_foreign() -> None:
    fs = _fs()
    fs.seed_file(_GATE, _GATE_BYTES, gid=API_RUNTIME_GID + 1, mode=0o640)
    inventory = _observe(fs)
    assert inventory.readiness_gate is ObjectState.FOREIGN


def test_a_complete_installation_missing_only_the_readiness_gate_is_incomplete() -> None:
    fs = _fs()
    _seed_complete(fs, gate=False)  # every OTHER object exactly as a complete install leaves it
    inventory = _observe(fs, _FakeRunner(service=_RUNNING), db=_complete_db())
    assert inventory.is_complete is False
    assert inventory.complete_reason == "finalization_incomplete_readiness_gate"


def test_a_non_socket_node_at_the_broker_socket_path_is_foreign() -> None:
    fs = _fs()
    fs.seed_file(_SOCKET, b"", gid=API_RUNTIME_GID, mode=0o660)  # a regular file, not AF_UNIX
    inventory = _observe(fs)
    assert inventory.broker_socket is ObjectState.FOREIGN
    assert inventory.orphan_reason == "finalization_orphan_broker_socket"


def test_a_special_but_non_socket_node_at_the_socket_path_is_foreign() -> None:
    fs = _fs()
    fs.seed_special(_SOCKET)  # a FIFO/device: is_special but NOT is_socket
    inventory = _observe(fs)
    assert inventory.broker_socket is ObjectState.FOREIGN
    assert inventory.orphan_reason == "finalization_orphan_broker_socket"


def test_a_hardlinked_credential_is_foreign() -> None:
    fs = _fs()
    fs.seed_file(_CRED, b"secret\n", mode=0o600, nlink=2)
    inventory = _observe(fs)
    assert inventory.signer_credential is ObjectState.FOREIGN
    assert inventory.orphan_reason == "finalization_orphan_signer_credential"


def test_a_foreign_posture_tls_set_is_classified_foreign_not_complete() -> None:
    fs = _fs()
    _seed_tls(fs)
    fs.seed_file(_KEY, b"KEY", mode=0o644)  # world-readable private key
    inventory = _observe(fs)
    assert inventory.tls is TlsSetState.FOREIGN
    assert inventory.orphan_reason == "finalization_orphan_tls"
    assert inventory.complete_reason == "finalization_incomplete_tls"


# ------------------------------------------------------- every probe fault fails CLOSED


def test_no_injected_role_probe_fails_closed() -> None:
    inventory = observe_finalization_inventory(_ctx(_fs(), _FakeRunner()))
    assert inventory.signer_db_role is ObjectState.UNKNOWN
    assert inventory.active_identity is ObjectState.UNKNOWN
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_signer_role"


def test_a_raising_role_probe_fails_closed() -> None:
    def boom() -> FinalizationDbState:
        raise RuntimeError("injected probe fault")

    inventory = observe_finalization_inventory(_ctx(_fs(), _FakeRunner()), role_probe=boom)
    assert inventory.signer_db_role is ObjectState.UNKNOWN
    assert inventory.active_identity is ObjectState.UNKNOWN
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_signer_role"


@pytest.mark.parametrize(
    "returned",
    [
        "not-a-state",
        None,
        FinalizationDbState(
            signer_role="absent",  # type: ignore[arg-type]
            active_identity=ObjectState.ABSENT,
        ),
        FinalizationDbState(
            signer_role=ObjectState.ABSENT,
            active_identity=ObjectState.ABSENT,
            activation_generation=-1,
        ),
        FinalizationDbState(
            signer_role=ObjectState.ABSENT,
            active_identity=ObjectState.ABSENT,
            activation_generation=True,  # a bool is never a generation
        ),
    ],
)
def test_a_malformed_role_probe_return_fails_closed(returned: object) -> None:
    inventory = observe_finalization_inventory(
        _ctx(_fs(), _FakeRunner()),
        role_probe=lambda: returned,  # type: ignore[arg-type,return-value]
    )
    assert inventory.signer_db_role is ObjectState.UNKNOWN
    assert inventory.is_fresh is False


def test_a_filesystem_probe_fault_fails_closed() -> None:
    inventory = _observe(_FaultyLstat(_fs(), _MARKER))
    assert inventory.signer_marker is ObjectState.UNKNOWN
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_marker"
    assert inventory.is_complete is False  # UNKNOWN is never "installed" either


def test_a_tls_probe_fault_fails_the_whole_indivisible_set_closed() -> None:
    inventory = _observe(_FaultyLstat(_fs(), _CERT))
    assert inventory.tls is TlsSetState.UNKNOWN
    assert inventory.orphan_reason == "finalization_orphan_tls"


def test_a_service_query_fault_fails_closed() -> None:
    inventory = _observe(_fs(), _FakeRunner(raise_on_service=True))
    assert inventory.broker_service is ServiceState.UNKNOWN
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_broker_service"


@pytest.mark.parametrize(
    "stdout",
    [
        "",  # no output at all (a swallowed/garbled query proves nothing)
        "failed\n",  # a FAILED broker unit is residue, never a proven clean stop
        "activating (auto-restart)\n",
        "garbage\n",
        "inactive\nactive\n",  # ambiguous multi-line output
    ],
)
def test_a_malformed_or_unrecognised_service_observation_fails_closed(stdout: str) -> None:
    inventory = _observe(_fs(), _FakeRunner(service=(stdout, 0)))
    assert inventory.broker_service is ServiceState.UNKNOWN
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_broker_service"


# ------------------------------------------------------- completeness / transient state


def test_a_complete_coherent_installation_is_complete_and_not_fresh() -> None:
    fs = _fs()
    _seed_complete(fs)
    inventory = _observe(fs, _FakeRunner(service=_RUNNING), db=_complete_db())
    assert inventory.is_complete is True
    assert inventory.complete_reason is None
    assert inventory.has_transient_state is False
    assert inventory.is_fresh is False
    assert inventory.activation_generation == 3


@pytest.mark.parametrize(
    ("path", "gid", "mode", "reason"),
    [
        (_PROV, API_RUNTIME_GID, 0o640, "finalization_transient_provisioning_handoff"),
        (_ACT, API_RUNTIME_GID, 0o640, "finalization_transient_activation_handoff"),
        (_JOURNAL, 0, 0o600, "finalization_transient_recovery_journal"),
    ],
)
def test_a_transient_object_defeats_completeness(
    path: str, gid: int, mode: int, reason: str
) -> None:
    fs = _fs()
    _seed_complete(fs)
    fs.seed_file(path, b"{}", gid=gid, mode=mode)
    inventory = _observe(fs, _FakeRunner(service=_RUNNING), db=_complete_db())
    assert inventory.has_transient_state is True
    assert inventory.transient_reason == reason
    assert inventory.complete_reason == reason
    assert inventory.is_complete is False


def test_a_staging_residual_defeats_completeness() -> None:
    fs = _fs()
    _seed_complete(fs)
    _seed_staging(fs)
    inventory = _observe(fs, _FakeRunner(service=_RUNNING), db=_complete_db())
    assert inventory.transient_reason == "finalization_transient_staging"
    assert inventory.is_complete is False


@pytest.mark.parametrize(
    ("drop", "reason"),
    [
        (_LOCATOR, "finalization_incomplete_locator"),
        (_CRED, "finalization_incomplete_signer_credential"),
        (CONTROLLER_ENROLLMENT_KEY_PATH, "finalization_incomplete_enrollment_key"),
        (_UNIT, "finalization_incomplete_broker_unit"),
        (_SOCKET, "finalization_incomplete_broker_socket"),
        (_MARKER, "finalization_incomplete_marker"),
    ],
)
def test_a_missing_object_makes_the_installation_incomplete(drop: str, reason: str) -> None:
    fs = _fs()
    _seed_complete(fs)
    fs.remove_file(drop)
    inventory = _observe(fs, _FakeRunner(service=_RUNNING), db=_complete_db())
    assert inventory.is_complete is False
    assert inventory.complete_reason == reason


def test_a_stopped_broker_service_makes_the_installation_incomplete() -> None:
    fs = _fs()
    _seed_complete(fs)
    inventory = _observe(fs, _FakeRunner(service=_INACTIVE), db=_complete_db())
    assert inventory.complete_reason == "finalization_incomplete_broker_service"


def test_an_absent_db_role_or_identity_makes_the_installation_incomplete() -> None:
    fs = _fs()
    _seed_complete(fs)
    inventory = _observe(fs, _FakeRunner(service=_RUNNING), db=_clean_db())
    assert inventory.complete_reason == "finalization_incomplete_signer_role"


def test_the_reason_vocabularies_are_disjoint_and_bounded() -> None:
    codes = set(ORPHAN_REASONS) | set(TRANSIENT_REASONS) | set(INCOMPLETE_REASONS)
    assert len(codes) == len(ORPHAN_REASONS) + len(TRANSIENT_REASONS) + len(INCOMPLETE_REASONS)
    assert all(c.startswith("finalization_") and len(c) <= 60 for c in codes)


def test_public_facts_are_a_flat_bounded_nonsecret_projection() -> None:
    fs = _fs()
    _seed_complete(fs)
    facts = _observe(fs, _FakeRunner(service=_RUNNING), db=_complete_db()).public_facts()
    assert facts["tls"] == "complete"
    assert facts["broker_service"] == "running"
    assert facts["activation_generation"] == "3"
    assert set(facts) == {name for name, _c in ORPHAN_PRECEDENCE} | {
        "activation_generation",
        "staged_backup_objects",
    }
    assert all(isinstance(v, str) for v in facts.values())
    blob = " ".join(facts.values())
    assert "/" not in blob and "secret" not in blob  # never a path or a byte


# ------------------------------------------------------- the module mutates NOTHING


def test_the_observation_mutates_nothing_on_disk() -> None:
    fs = _fs()
    _seed_complete(fs)
    _seed_staging(fs)
    fs.seed_file(_JOURNAL, b"{}", mode=0o600)
    before = fs.paths()
    _observe(fs, _FakeRunner(service=_RUNNING), db=_complete_db())
    assert fs.paths() == before


def test_the_module_contains_no_mutating_filesystem_or_service_call() -> None:
    mutators = {
        "atomic_install",
        "exclusive_install",
        "makedir",
        "remove_file",
        "remove_dir",
        "remove_created_file",
        "seed_file",
        "seed_dir",
    }
    tree = ast.parse(Path(inv_mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in mutators, node.func.attr


def test_only_read_only_host_commands_are_ever_issued() -> None:
    runner = _FakeRunner()
    _observe(_fs(), runner)
    assert len(runner.calls) == 1  # exactly ONE bounded service observation, no other host op
    argv = runner.calls[0]
    assert argv == ("is-active", _UNIT_NAME)
    for mutating in ("start", "stop", "enable", "daemon-reload", "up", "restart"):
        assert mutating not in argv


def test_the_module_adds_no_second_systemd_or_container_output_parser() -> None:
    # mirrors test_real_adapters.test_secp_management_has_no_second_docker_or_systemd_parser: the
    # coherent `systemctl show` observation belongs to the reviewed PR5D adapter, never to a second
    # management-plane parser; this observer reuses the finalization adapter's `is-active` idiom.
    src = Path(inv_mod.__file__).read_text(encoding="utf-8")
    assert "systemctl show" not in src
    assert "{{." not in src  # no container inspect Go-template grammar either


# ------------------------------------------------------- the production DB probe seam


def _receipt(**overrides: object) -> str:
    doc: dict[str, object] = {
        "schema": "secp.controller-finalization-db-state/v1",
        "role_name": ENROLLMENT_SIGNER_DB_ROLE,
        "role_present": False,
        "active_identity_present": False,
        "activation_generation": None,
    }
    doc.update(overrides)
    return canonical_json(doc)


def test_the_oneshot_probe_parses_a_canonical_read_only_receipt() -> None:
    runner = _FakeRunner(
        oneshot=_receipt(role_present=True, active_identity_present=True, activation_generation=7)
    )
    state = build_oneshot_finalization_db_probe(_ctx(_fs(), runner))()
    assert state == FinalizationDbState(
        signer_role=ObjectState.PRESENT,
        active_identity=ObjectState.PRESENT,
        activation_generation=7,
    )


def test_the_oneshot_probe_reports_a_proven_absence() -> None:
    runner = _FakeRunner(oneshot=_receipt())
    state = build_oneshot_finalization_db_probe(_ctx(_fs(), runner))()
    assert state.signer_role is ObjectState.ABSENT
    assert state.active_identity is ObjectState.ABSENT
    assert state.activation_generation is None


def test_the_oneshot_probe_argv_is_the_fixed_read_only_compose_run() -> None:
    runner = _FakeRunner(oneshot=_receipt())
    build_oneshot_finalization_db_probe(_ctx(_fs(), runner))()
    argv = runner.calls[0]
    assert argv[:4] == (
        "--project-name",
        "secp-controller",
        "--file",
        _LOC.controller_compose_path(),
    )
    assert "run" in argv and "--rm" in argv and "--no-deps" in argv
    assert "--volume" not in argv  # a read-only probe hands NOTHING in
    assert argv[-3:] == ("python", "-m", "secp_api.observe_controller_finalization_once")


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "not json",
        '{"schema": "wrong", "role_name": "secp_enrollment_signer", "role_present": false, '
        '"active_identity_present": false, "activation_generation": null}',
        _receipt(role_name="postgres"),
        _receipt(role_present="yes"),
        _receipt(activation_generation=-4),
        _receipt(activation_generation=5),  # a generation with no active identity is incoherent
        '{"activation_generation": null, "active_identity_present": false, "role_present": false, '
        '"role_name": "secp_enrollment_signer", "schema": '
        '"secp.controller-finalization-db-state/v1", "extra": 1}',
        '{"schema":"secp.controller-finalization-db-state/v1"}',
    ],
)
def test_the_oneshot_probe_fails_closed_on_any_receipt_drift(stdout: str) -> None:
    runner = _FakeRunner(oneshot=stdout)
    assert build_oneshot_finalization_db_probe(_ctx(_fs(), runner))() is (
        SEALED_FINALIZATION_DB_STATE
    )


def test_the_oneshot_probe_fails_closed_on_a_noncanonical_receipt() -> None:
    # semantically correct but NOT canonical bytes (spaces / key order) -> sealed, never adopted
    runner = _FakeRunner(
        oneshot='{"schema": "secp.controller-finalization-db-state/v1", "role_name": '
        '"secp_enrollment_signer", "role_present": false, "active_identity_present": false, '
        '"activation_generation": null}'
    )
    assert build_oneshot_finalization_db_probe(_ctx(_fs(), runner))() is (
        SEALED_FINALIZATION_DB_STATE
    )


def test_the_oneshot_probe_fails_closed_on_a_runner_fault() -> None:
    runner = _FakeRunner(oneshot=_receipt(), oneshot_exit=1)
    assert build_oneshot_finalization_db_probe(_ctx(_fs(), runner))() is (
        SEALED_FINALIZATION_DB_STATE
    )


def test_a_sealed_db_state_never_lets_a_host_classify_fresh() -> None:
    runner = _FakeRunner(oneshot_exit=1)
    ctx = _ctx(_fs(), runner)
    inventory = observe_finalization_inventory(
        ctx, role_probe=build_oneshot_finalization_db_probe(ctx)
    )
    assert inventory.is_fresh is False
    assert inventory.orphan_reason == "finalization_orphan_signer_role"


# ------------------------------------------------------- boundary + drift guards


def test_module_never_imports_secp_api() -> None:
    # mirrors test_enrollment_signer_runtime_observer / test_controller_finalization_wiring: no
    # import of secp_api and no secp_api identifier referenced (the one-shot module name is a FIXED
    # STRING constant executed inside the API container, exactly like the reviewed one-shots).
    tree = ast.parse(Path(inv_mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("secp_api") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("secp_api")
        elif isinstance(node, ast.Name):
            assert not node.id.startswith("secp_api")
        elif isinstance(node, ast.Attribute):
            assert not node.attr.startswith("secp_api")


def test_module_has_no_generic_sql_shell_or_dynamic_import_capability() -> None:
    tree = ast.parse(Path(inv_mod.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "__import__", "text", "compile"}
    assert not (imported & {"subprocess", "os", "shutil", "sqlalchemy", "socket", "ctypes"})


def test_the_journal_and_staging_paths_match_the_finalization_adapter() -> None:
    # a DRIFT GUARD: this module must name EXACTLY the paths the adapter writes; nothing else in the
    # package exports them, so byte-compare against the adapter's own construction.
    class _Host:
        locations = _LOC

    class _Ctx:
        host = _Host()

    stub = _Ctx()
    assert cf._Journal(stub, "tx-abc", 0)._path == finalization_recovery_journal_path(_LOC)
    assert cf._Staging(stub, "tx-abc")._dir == f"{finalization_staging_root(_LOC)}/tx-abc"
    assert cf._Staging._HANDLES == inv_mod._STAGING_BACKUP_HANDLES


def test_the_classified_paths_are_exactly_the_fixed_code_owned_locations() -> None:
    assert _JOURNAL == "/var/lib/secp/bootstrap/controller-finalization-journal.json"
    assert _STAGING == "/var/lib/secp/bootstrap/finalization-staging"
    assert _SOCKET == "/run/secp/enrollment-signer.sock"
    assert _MARKER == "/etc/secp/controller/enrollment-signer.enabled"
    assert CONTROLLER_ENROLLMENT_KEY_PATH.startswith("/var/lib/secp/bootstrap/")
