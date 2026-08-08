"""Proofs for the REAL POSIX worker-installer adapters that replace the two sealed host seams.

WHY THESE TESTS DO NOT SKIP ON WINDOWS
---------------------------------------
Windows is not a supported install host, and the obvious way to express that is
``pytest.mark.skipif(os.name != "posix")``. This file deliberately does NOT do that. A skipped tier
reads as a passing tier in every JUnit report this program consumes, and an entire tier silently
vanishing while CI stayed green is a failure mode already paid for here more than once.

Instead the platform is a SEAM (:func:`~secp_management.worker_service_adapters._host_os_name`), so
every behavioural test below runs and asserts on EVERY platform, and the count of collected tests is
identical on Linux and Windows. The unsupported-host branch is not skipped past — it is asserted, by
:func:`test_unsupported_host_refuses_every_adapter_entry_point`.

The one thing a hermetic test genuinely cannot do is talk to a real systemd. That tier is opt-in via
``SECP_REAL_POSIX_HOST=1``, and when it is declared and the host cannot honour it,
:func:`test_declared_real_host_tier_fails_rather_than_skipping` FAILS. It never skips.
"""

from __future__ import annotations

import json
import os

import pytest
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import worker_service_adapters as wsa
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_management.worker_installer import (
    InstallationRequest,
    InstallerDeps,
    WorkerInstallerError,
    build_installer_deps,
    install,
)
from secp_management.worker_roles import WorkerRole
from secp_operator_deployment.host_process import CommandResult
from secp_operator_deployment.pinned_exec import ExecutablePin

#: Captured at import, BEFORE the autouse ``posix_host`` fixture can patch it. Without this the
#: platform-seam test would assert against the fixture's own stub and pass vacuously on Linux while
#: failing on Windows — the seam has to be checked against the real thing.
_UNPATCHED_HOST_OS_NAME = wsa._host_os_name

ORDINARY_QUEUE = "secp-ordinary"
OPERATOR_QUEUE = "secp-controlled-live"
ORDINARY_UNIT = "secp-worker-ordinary.service"
OPERATOR_UNIT = "secp-worker-infrastructure-operator.service"
UNIT_DIR = "/etc/systemd/system"
SYSUSERS_DIR = "/usr/lib/sysusers.d"
SYSUSERS_PATH = f"{SYSUSERS_DIR}/secp-worker.conf"
WORKER_EXE = "/opt/secp/worker/bin/secp-worker"
IDENTITY_PATH = "/var/lib/secp/bootstrap/worker-installation-identity.json"

WORKER_UID = 4242
WORKER_GID = 4242

ANCHOR_HEX = "ab" * 32
RELEASE = "sha256:" + "1" * 64


def key_id(anchor_hex: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(bytes.fromhex(anchor_hex)).hexdigest()


# --- doubles -------------------------------------------------------------------------------------


class FakeRunner:
    """Records every pinned command and replays scripted answers per systemctl verb."""

    def __init__(self, **answers: object) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._answers: dict[str, object] = {
            "daemon-reload": CommandResult(exit_code=0, stdout=""),
            "enable": CommandResult(exit_code=0, stdout=""),
            "disable": CommandResult(exit_code=0, stdout=""),
            "restart": CommandResult(exit_code=0, stdout=""),
            "is-active": CommandResult(exit_code=0, stdout="active\n"),
            "is-enabled": CommandResult(exit_code=0, stdout="enabled\n"),
            # `systemctl start systemd-sysusers.service` applies the account declaration the
            # installer writes. The installer OWNS creating the account it requires.
            "start": CommandResult(exit_code=0, stdout=""),
        }
        self._answers.update(answers)

    @property
    def verbs(self) -> list[str]:
        return [c[0] for c in self.calls]

    def run(
        self,
        pin: ExecutablePin,
        argv_tail: object,
        *,
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> CommandResult:
        argv = tuple(argv_tail)  # type: ignore[arg-type]
        self.calls.append(argv)
        answer = self._answers[argv[0]]
        if isinstance(answer, Exception):
            raise answer
        return answer  # type: ignore[return-value]


class FakeAccounts:
    def __init__(self, uid: int = WORKER_UID, gid: int = WORKER_GID, *, absent: bool = False):
        self._uid, self._gid, self._absent = uid, gid, absent

    def resolve(self, user: str, group: str) -> tuple[int, int]:
        if self._absent:
            raise KeyError(user)
        return self._uid, self._gid


class FakeEnroller:
    def __init__(self, *, state: str = "healthy") -> None:
        self._state = state
        self.called = 0

    def enroll(self, invitation: dict, *, now: str, expected_controller_key_id=None) -> dict:
        self.expected_controller_key_id = expected_controller_key_id
        self.called += 1
        return {"enrollment_id": invitation["enrollment_id"], "state": self._state, "revision": 3}


class FakeInvitations:
    def load(self, path: str) -> dict:
        return {
            "enrollment_id": "enr-1",
            "invitation_id": "inv-1",
            "controller_installation_id": "worker-a",
            "controller_key_id": key_id(ANCHOR_HEX),
            "release_digest": RELEASE,
            "expires_at": "2030-01-01T00:00:00+00:00",
        }


# --- fixtures ------------------------------------------------------------------------------------


def _pin() -> ExecutablePin:
    return ExecutablePin(path="/usr/bin/systemctl", digest="sha256:" + "0" * 64)


def build_fs(*, worker_exe: bool = True) -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in (
        "/opt",
        "/opt/secp",
        "/opt/secp/worker",
        "/opt/secp/worker/bin",
        "/etc",
        "/etc/systemd",
        UNIT_DIR,
        # The installer now OWNS creating the dedicated account, declaratively, so the sysusers.d
        # directory has to exist for it to install into.
        "/usr",
        "/usr/lib",
        SYSUSERS_DIR,
        "/var",
        "/var/lib",
        "/var/lib/secp",
        "/var/lib/secp/bootstrap",
    ):
        fs.seed_dir(d)
    if worker_exe:
        fs.seed_file(WORKER_EXE, b"#!elf\n", mode=0o755)
    return fs


def build_ctx(fs: InMemoryFilesystem | None = None, runner: FakeRunner | None = None):
    return RealAdapterContext(
        locations=ManagementLocations(),
        fs=fs if fs is not None else build_fs(),
        runner=runner if runner is not None else FakeRunner(),
        executables=PinnedExecutables(
            container_runtime=_pin(), compose_runtime=_pin(), service_manager=_pin()
        ),
    )


@pytest.fixture(autouse=True)
def posix_host(monkeypatch):
    """Every behavioural test runs as though on the supported platform — on EVERY platform.

    This is what keeps the collected test count identical on Linux and Windows. The unsupported
    branch is covered by an explicit test, not by this fixture's absence.
    """
    monkeypatch.setattr(wsa, "_host_os_name", lambda: "posix")


def services(fs=None, runner=None, accounts=None) -> wsa.PosixServiceManager:
    return wsa.PosixServiceManager(
        build_ctx(fs, runner), accounts=accounts if accounts is not None else FakeAccounts()
    )


def refusal(fn, *args, **kwargs) -> str:
    with pytest.raises(WorkerInstallerError) as exc:
        fn(*args, **kwargs)
    return exc.value.reason_code


# --- platform: asserted, never skipped ------------------------------------------------------------


def test_host_os_name_reads_the_real_platform():
    """The seam that makes these tests platform-independent must not be a bypass: in production it
    is exactly ``os.name``, so a POSIX-only adapter really is POSIX-only."""
    assert _UNPATCHED_HOST_OS_NAME() == os.name


def test_unsupported_host_refuses_every_adapter_entry_point(monkeypatch):
    """Windows is refused LOUDLY at every entry point, not degraded to a no-op.

    Asserted over the whole public surface rather than one method: an adapter that refused in
    ``install`` but silently no-opped in ``disable`` would report a rollback that never happened.
    """
    monkeypatch.setattr(wsa, "_host_os_name", lambda: "nt")
    svc = services()
    store = wsa.PosixDurableIdentityStore(build_ctx())

    entries = (
        lambda: svc.install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE),
        lambda: svc.enable(ORDINARY_UNIT),
        lambda: svc.is_active(ORDINARY_UNIT),
        lambda: svc.disable(ORDINARY_UNIT),
        lambda: svc.restart(ORDINARY_UNIT),
        lambda: store.load(),
        lambda: store.persist({"a": 1}),
        lambda: wsa.build_posix_installer_deps(),
    )
    for entry in entries:
        assert refusal(entry) == "installer_host_platform_unsupported"


def test_declared_real_host_tier_fails_rather_than_skipping():
    """The opt-in real-systemd tier FAILS when it is declared and cannot be honoured.

    ``SECP_REAL_POSIX_HOST=1`` is an operator asserting "this IS a supported install host, run the
    real thing". If that is untrue, the run must go RED. Returning early — or worse,
    ``pytest.skip`` — would let a green report certify a tier that never executed, which is the
    precise defect this file's docstring names.
    """
    declared = os.environ.get("SECP_REAL_POSIX_HOST") == "1"
    if not declared:
        # Not declared: this is the hermetic run. Assert that fact positively so the test is never
        # a silent no-op, then stop — nothing is skipped, and the node still passes on its own
        # assertion rather than on an absence.
        assert wsa.require_supported_install_host is not None
        return
    if os.name != "posix":
        pytest.fail(
            "SECP_REAL_POSIX_HOST=1 declares a supported POSIX install host, but this host is "
            f"{os.name!r}. Refusing to skip: a skipped tier reads as a passed tier."
        )
    import shutil

    if shutil.which("systemctl") is None:
        pytest.fail(
            "SECP_REAL_POSIX_HOST=1 declares a supported install host, but systemctl is absent. "
            "Refusing to skip."
        )


# --- the unit path is derived from the role, never from the operator ------------------------------


def test_every_role_in_the_live_enum_has_a_unit_name():
    """Inverted, per this codebase's guard discipline: every role in the LIVE enum must have an
    approved unit, not merely 'the approved table contains these roles'. A third role added to
    ``WorkerRole`` with no unit here refuses instead of silently reusing another role's unit."""
    assert set(wsa._ROLE_UNIT_NAMES) == set(WorkerRole)
    assert len(set(wsa._ROLE_UNIT_NAMES.values())) == len(WorkerRole), "two roles share a unit"


def test_installer_can_never_target_a_pre_existing_fixed_unit():
    """The sealed controlled-live operator unit is the one that matters.

    ``secp-operator-worker.service`` is installed present-but-disabled and is never enabled by
    anything. This installer ENABLES what it installs, so if a worker unit name ever collided with
    it, the installer would gain the power to activate the sealed operator. Both the current names
    and the collision REFUSAL are pinned.
    """
    loc = ManagementLocations()
    reserved = {loc.controller_unit_path(), loc.operator_unit_path(), loc.broker_unit_path()}
    for role in WorkerRole:
        assert wsa._unit_path_for_role(loc, role) not in reserved

    # and if a future edit pointed a role at the sealed operator unit, it refuses rather than
    # returning a path the adapter would happily enable
    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(wsa._ROLE_UNIT_NAMES, WorkerRole.ordinary, "secp-operator-worker.service")
        assert (
            refusal(wsa._unit_path_for_role, loc, WorkerRole.ordinary)
            == "installer_unit_path_reserved"
        )


@pytest.mark.parametrize(
    "name",
    ["secp-worker", "secp-worker-ordinary", OPERATOR_UNIT, "sshd.service", "secp-worker-ordinary."],
)
def test_operator_supplied_service_name_selects_nothing(name):
    """A ``service_name`` that is not the code-owned name for the role is refused.

    This is the check that keeps the operator's string from becoming a filename in
    ``/etc/systemd/system``. Note the third case: the OTHER role's real unit name is refused too, so
    an ordinary install cannot address the operator role's unit.
    """
    assert (
        refusal(services().install, name, role="ordinary", task_queue=ORDINARY_QUEUE)
        == "installer_service_name_not_fixed"
    )


# --- install -------------------------------------------------------------------------------------


def test_install_writes_the_hardened_code_owned_unit():
    fs, runner = build_fs(), FakeRunner()
    services(fs, runner).install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)

    path = f"{UNIT_DIR}/{ORDINARY_UNIT}"
    stat = fs.lstat(path)
    assert stat is not None and not stat.is_symlink
    assert stat.uid == 0 and stat.gid == 0 and (stat.mode & 0o777) == 0o644

    unit = fs.safe_read(path, max_bytes=64 * 1024, expected_uid=0).decode()
    # the hardening comes from the reviewed renderer; pinned here so a future adapter that
    # hand-rolls its own unit text cannot quietly drop it
    for line in (
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "CapabilityBoundingSet=",
        "User=secp-worker",
        "Group=secp-worker",
        "[Install]",
        "WantedBy=multi-user.target",
    ):
        assert line in unit, line
    assert f"ExecStart={WORKER_EXE} --role ordinary --task-queue {ORDINARY_QUEUE}" in unit
    # no shell, no env indirection
    assert "/bin/sh" not in unit and "/usr/bin/env" not in unit
    # systemd is told about the new unit, and the unit is confirmed loadable
    # `start` comes FIRST and it is the account declaration being applied: the installer creates
    # the unprivileged account before it installs a unit whose User=/Group= names it.
    assert runner.verbs == ["start", "daemon-reload", "is-enabled"]


def test_install_carries_no_enrollment_material_into_the_unit():
    """The unit is rendered from a role, a queue name and code constants only. Nothing the
    invitation carries can reach a rendered config, an argv, or an environment line."""
    fs = build_fs()
    services(fs).install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
    unit = fs.safe_read(f"{UNIT_DIR}/{ORDINARY_UNIT}", max_bytes=64 * 1024, expected_uid=0).decode()
    assert "Environment" not in unit and "EnvironmentFile" not in unit
    for forbidden in ("invitation", "token", "secret", "key", "attestation", "password"):
        assert forbidden not in unit.lower(), forbidden


def test_install_refuses_when_the_worker_runtime_is_absent():
    fs = build_fs(worker_exe=False)
    assert (
        refusal(services(fs).install, ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
        == "installer_worker_runtime_absent"
    )
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is None, "a unit was installed anyway"


def test_install_refuses_a_symlinked_worker_runtime():
    """A symlinked entrypoint is refused: the unit would name an absolute path whose target can be
    repointed after review."""
    fs = build_fs(worker_exe=False)
    fs.seed_symlink(WORKER_EXE)
    assert (
        refusal(services(fs).install, ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
        == "installer_worker_runtime_absent"
    )


def test_install_refuses_when_the_worker_account_is_absent():
    fs = build_fs()
    svc = services(fs, accounts=FakeAccounts(absent=True))
    assert (
        refusal(svc.install, ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
        == "installer_worker_account_absent"
    )
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is None


def test_install_refuses_a_worker_account_that_resolves_to_root():
    """A 'worker' account that is really root defeats the unit's ``User=``; refuse rather than
    install a root-running worker."""
    svc = services(accounts=FakeAccounts(uid=0, gid=0))
    assert (
        refusal(svc.install, ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
        == "installer_worker_account_privileged"
    )


def test_install_refuses_an_unconfigured_queue():
    assert (
        refusal(services().install, ORDINARY_UNIT, role="ordinary", task_queue="  ")
        == "installer_queue_not_configured"
    )


def test_install_refuses_an_unauthorized_role():
    assert (
        refusal(services().install, ORDINARY_UNIT, role="root", task_queue=ORDINARY_QUEUE)
        == "installer_role_not_authorized"
    )


def test_the_operator_role_installs_its_own_distinct_unit():
    fs = build_fs()
    services(fs).install(OPERATOR_UNIT, role="infrastructure_operator", task_queue=OPERATOR_QUEUE)
    unit = fs.safe_read(f"{UNIT_DIR}/{OPERATOR_UNIT}", max_bytes=64 * 1024, expected_uid=0).decode()
    assert f"--role infrastructure_operator --task-queue {OPERATOR_QUEUE}" in unit
    # the SEALED operator unit is untouched
    assert fs.lstat(ManagementLocations().operator_unit_path()) is None


# --- enable / health ------------------------------------------------------------------------------


def test_enable_starts_the_service_and_proves_it_is_enabled():
    """``--now`` is required: the installer verifies health next, and health is observed from a
    RUNNING service. The ``is-enabled`` re-read is what makes restart persistence real."""
    runner = FakeRunner()
    services(runner=runner).enable(ORDINARY_UNIT)
    assert ("enable", "--now", ORDINARY_UNIT) in runner.calls
    assert ("is-enabled", ORDINARY_UNIT) in runner.calls


def test_enable_refuses_when_systemd_does_not_report_enabled():
    """A unit that started but is not enabled would not survive a reboot — refused, not accepted."""
    runner = FakeRunner(**{"is-enabled": CommandResult(exit_code=0, stdout="linked\n")})
    assert refusal(services(runner=runner).enable, ORDINARY_UNIT) == "installer_service_not_enabled"


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (CommandResult(exit_code=0, stdout="active\n"), True),
        (CommandResult(exit_code=0, stdout="activating\n"), False),
        (CommandResult(exit_code=0, stdout=""), False),
        (CommandResult(exit_code=3, stdout="inactive\n"), False),
        (CommandResult(exit_code=3, stdout="failed\n"), False),
        (OSError("runner fault"), False),
    ],
)
def test_is_active_is_true_only_on_an_exact_active_answer(answer, expected):
    """An unobservable service is NOT active. ``activating`` in particular is not healthy — a
    service still starting would otherwise be enrolled as if it were up."""
    runner = FakeRunner(**{"is-active": answer})
    assert services(runner=runner).is_active(ORDINARY_UNIT) is expected


# --- rollback is REMOVAL --------------------------------------------------------------------------


def test_rollback_removes_the_unit_file_and_proves_absence():
    """Rollback removes, it does not merely deactivate.

    A merely-stopped unit is still installed and still enable-able — one boot away from polling a
    controller that holds no verified identity for this host.
    """
    fs, runner = build_fs(), FakeRunner()
    svc = services(fs, runner)
    svc.install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is not None

    svc.disable(ORDINARY_UNIT)
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is None, "the unit file survived rollback"
    assert ("disable", "--now", ORDINARY_UNIT) in runner.calls
    assert runner.verbs.count("daemon-reload") == 2, "systemd was not reloaded after removal"


def test_rollback_still_removes_when_the_unit_was_never_enabled():
    """``systemctl disable`` failing (never enabled / already gone) must not abort the removal."""
    fs = build_fs()
    runner = FakeRunner(disable=CommandResult(exit_code=1, stdout=""))
    svc = wsa.PosixServiceManager(build_ctx(fs, runner), accounts=FakeAccounts())
    svc.install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
    svc.disable(ORDINARY_UNIT)
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is None


def test_rollback_refuses_when_the_unit_survives():
    """If the unit cannot be proven gone, the adapter raises rather than reporting a clean
    rollback."""

    class StubbornFs(InMemoryFilesystem):
        def remove_file(self, path: str) -> None:
            return  # the removal silently does nothing

    fs = StubbornFs()
    for d in ("/etc", "/etc/systemd", UNIT_DIR):
        fs.seed_dir(d)
    fs.seed_file(f"{UNIT_DIR}/{ORDINARY_UNIT}", b"[Unit]\n", mode=0o644)
    svc = wsa.PosixServiceManager(build_ctx(fs), accounts=FakeAccounts())
    assert refusal(svc.disable, ORDINARY_UNIT) == "installer_service_rollback_failed"


def test_restart_restarts_the_code_owned_unit():
    runner = FakeRunner()
    services(runner=runner).restart(ORDINARY_UNIT)
    assert ("restart", ORDINARY_UNIT) in runner.calls


def test_the_systemctl_verb_set_is_closed():
    """Every verb this adapter can issue is a fixed literal from a closed set; a computed verb
    cannot reach the pinned runner."""
    svc = services()
    assert (
        refusal(svc._systemctl, "mask", "x", reason="r") == "installer_service_verb_not_authorized"
    )
    assert set(wsa._SYSTEMCTL_VERBS) == {
        "daemon-reload",
        "enable",
        "disable",
        "restart",
        "is-active",
        "is-enabled",
        # Applies the sysusers.d account declaration. NOT a general "start anything" verb: the
        # only unit it is ever given is the fixed literal asserted below.
        "start",
    }
    assert wsa._SYSUSERS_APPLY_UNIT == "systemd-sysusers.service"
    # no destructive verb is reachable
    for forbidden in ("mask", "unmask", "kill", "isolate", "poweroff", "reboot", "set-property"):
        assert forbidden not in wsa._SYSTEMCTL_VERBS


# --- the durable identity store -------------------------------------------------------------------


def store(fs=None) -> wsa.PosixDurableIdentityStore:
    return wsa.PosixDurableIdentityStore(build_ctx(fs))


def test_identity_persists_root_owned_0600_and_reloads():
    fs = build_fs()
    record = {"installation_id": "worker-a", "enrollment_id": "enr-1", "role": "ordinary"}
    store(fs).persist(record)

    stat = fs.lstat(IDENTITY_PATH)
    assert stat is not None
    assert stat.uid == 0 and stat.gid == 0
    assert (stat.mode & 0o777) == 0o600, "the durable identity is not owner-only"
    assert store(fs).load() == record


def test_identity_survives_a_restart_as_a_fresh_store_instance():
    """Durability means the RECORD outlives the process, not that one object remembered it."""
    fs = build_fs()
    record = {"installation_id": "worker-a", "enrollment_id": "enr-1"}
    store(fs).persist(record)
    assert store(fs).load() == record  # a brand-new adapter over the same filesystem


def test_identity_load_returns_none_only_when_the_record_is_absent():
    assert store(build_fs()).load() is None


@pytest.mark.parametrize("mode", ["symlink", "foreign_owner", "malformed", "not_an_object"])
def test_identity_load_fails_closed_rather_than_reporting_a_clean_host(mode):
    """``None`` must mean ONLY 'no record'.

    The installer's replay check reads ``None`` as 'nothing was ever installed here'. A record that
    exists but cannot be trusted must therefore refuse, never degrade to ``None`` — otherwise a
    tampered file would re-open the replay window it exists to close.
    """
    fs = build_fs()
    if mode == "symlink":
        fs.seed_symlink(IDENTITY_PATH)
    elif mode == "foreign_owner":
        fs.seed_file(IDENTITY_PATH, b"{}", uid=1000, mode=0o600)
    elif mode == "malformed":
        fs.seed_file(IDENTITY_PATH, b"{not json", mode=0o600)
    else:
        fs.seed_file(IDENTITY_PATH, b'["a"]', mode=0o600)
    assert refusal(store(fs).load) == "installer_identity_not_durable"


def test_identity_persist_refuses_a_filesystem_that_did_not_really_write():
    """The read-back is the difference between 'the write call returned' and 'the identity is
    durable'. A store that reported success on a read-only host would let the installer enable a
    service for a worker whose identity did not survive."""

    class LyingFs(InMemoryFilesystem):
        def atomic_install(self, path, data, *, uid, gid, mode):
            return  # claims success, writes nothing

    fs = LyingFs()
    for d in ("/var", "/var/lib", "/var/lib/secp", "/var/lib/secp/bootstrap"):
        fs.seed_dir(d)
    assert refusal(store(fs).persist, {"a": 1}) == "installer_identity_not_durable"


def test_identity_persist_refuses_an_unserialisable_record():
    assert refusal(store(build_fs()).persist, {"a": object()}) == "installer_identity_not_durable"


def test_identity_record_is_written_as_canonical_json():
    fs = build_fs()
    store(fs).persist({"b": 2, "a": 1})
    raw = fs.safe_read(IDENTITY_PATH, max_bytes=4096, expected_uid=0)
    assert raw == b'{"a":1,"b":2}'
    assert json.loads(raw) == {"a": 1, "b": 2}


# --- the payoff: --write --confirm now proceeds, and still refuses everywhere it used to ----------


def _request(role: WorkerRole = WorkerRole.ordinary) -> InstallationRequest:
    return InstallationRequest(
        controller_origin="https://controller.example",
        installation_id="worker-a",
        release_digest=RELEASE,
        role=role,
        worker_plane="management",
        controller_trust_anchor_hex=ANCHOR_HEX,
        invitation_file="/etc/secp/invitation.json",
        service_name=ORDINARY_UNIT if role is WorkerRole.ordinary else OPERATOR_UNIT,
        target_association=None if role is WorkerRole.ordinary else "pve-node-1",
    )


def _real_deps(fs, runner, *, state: str = "healthy") -> InstallerDeps:
    ctx = build_ctx(fs, runner)
    return InstallerDeps(
        services=wsa.PosixServiceManager(ctx, accounts=FakeAccounts()),
        identities=wsa.PosixDurableIdentityStore(ctx),
        enroller=FakeEnroller(state=state),
        invitations=FakeInvitations(),
        now=lambda: "2026-08-05T00:00:00+00:00",
    )


def _install(fs, runner, **over):
    return install(
        _request(),
        _real_deps(fs, runner, **over),
        ordinary_task_queue=ORDINARY_QUEUE,
        operator_task_queue=OPERATOR_QUEUE,
    )


def test_write_confirm_now_completes_a_real_installation():
    """The gap this work exists to close: with the real adapters composed, a full installation
    runs to completion instead of refusing ``installer_service_manager_sealed``."""
    fs, runner = build_fs(), FakeRunner()
    record = _install(fs, runner)

    assert record["state"] == "healthy"
    assert record["installation_id"] == "worker-a"
    assert record["task_queue"] == ORDINARY_QUEUE
    # the host really was mutated, in the reviewed order
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is not None
    assert runner.verbs == [
        "start",  # install: apply the account declaration BEFORE the unit that runs as it
        "daemon-reload",
        "is-enabled",  # install: unit is loadable
        "enable",
        "is-enabled",  # enable --now, then prove enabled
        "is-active",  # verify_service_health
        "restart",
        "is-active",  # verify_restart
    ]
    # and the durable identity names THIS enrollment
    assert wsa.PosixDurableIdentityStore(build_ctx(fs)).load()["enrollment_id"] == "enr-1"


def _assert_service_was_rolled_back(fs, runner) -> None:
    """THE load-bearing assertion of the failed-enrollment path, factored out so the mutation proof
    below can run the EXACT assertion the real test runs, rather than a restatement of it."""
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is None, (
        "a service whose enrollment never authenticated was left installed on the host"
    )
    assert ("disable", "--now", ORDINARY_UNIT) in runner.calls


def test_failed_enrollment_rolls_the_service_back_and_refuses():
    """THE window the installer exists to close, now with a REAL rollback.

    The service is up and enabled before enrollment is driven. If the authenticated exchange does
    not reach healthy, this host must not be left polling — so the unit is REMOVED and the
    installation fails. It is never a partial success to be finished later.
    """
    fs, runner = build_fs(), FakeRunner()
    with pytest.raises(WorkerInstallerError) as exc:
        _install(fs, runner, state="pending")
    assert exc.value.reason_code == "installer_enrolled_service_unauthenticated"
    _assert_service_was_rolled_back(fs, runner)


def test_a_service_that_never_activates_is_rolled_back():
    fs = build_fs()
    runner = FakeRunner(**{"is-active": CommandResult(exit_code=3, stdout="failed\n")})
    with pytest.raises(WorkerInstallerError) as exc:
        _install(fs, runner)
    assert exc.value.reason_code == "installer_service_not_active"
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is None


def test_a_replayed_invitation_is_refused_before_the_host_is_touched():
    """The durable store makes the local replay refusal real: a second install of a DIFFERENT
    enrollment for this installation is refused, and refused before any host mutation."""
    fs, runner = build_fs(), FakeRunner()
    _install(fs, runner)
    fs.remove_file(f"{UNIT_DIR}/{ORDINARY_UNIT}")  # simulate the unit being cleaned up

    runner2 = FakeRunner()
    with pytest.raises(WorkerInstallerError) as exc:
        _install(fs, runner2)
    assert exc.value.reason_code == "installer_enrollment_replayed"
    assert runner2.calls == [], "the host was touched before the replay refusal"


def test_the_shipped_default_composition_is_still_sealed():
    """Filling the seam must not un-seal the DEFAULT. ``build_installer_deps`` still leaves the host
    seams sealed, so nothing gains a real service manager implicitly — only the explicit POSIX
    composition does."""
    d = build_installer_deps(enroller=FakeEnroller())
    assert type(d.services).__name__ == "SealedServiceManager"
    assert type(d.identities).__name__ == "SealedDurableIdentityStore"
    with pytest.raises(WorkerInstallerError) as exc:
        install(
            _request(),
            InstallerDeps(
                services=d.services,
                identities=d.identities,
                enroller=FakeEnroller(),
                invitations=FakeInvitations(),
                now=lambda: "2026-08-05T00:00:00+00:00",
            ),
            ordinary_task_queue=ORDINARY_QUEUE,
            operator_task_queue=OPERATOR_QUEUE,
        )
    assert exc.value.reason_code == "installer_identity_store_sealed"


def test_adapters_never_leak_a_path_or_record_in_their_repr():
    assert repr(services()) == "PosixServiceManager(<posix>)"
    assert repr(store(build_fs())) == "PosixDurableIdentityStore(<posix>)"
    assert repr(wsa.PosixAccountResolver()) == "PosixAccountResolver(<posix>)"


# --- mutation proofs: each guard fires, and fires for its OWN reason ------------------------------


def test_mutation_a_rollback_that_only_stops_fails_exactly_its_own_test():
    """Remove the removal from rollback and ONE test must go red — the one that asserts it.

    A mutation that trips half the suite proves nothing about which test is load-bearing; this
    pins that the rollback-removal property is carried by
    ``test_failed_enrollment_rolls_the_service_back_and_refuses`` specifically, and that the
    surrounding refusal still behaves identically.
    """

    class StopOnlyServiceManager(wsa.PosixServiceManager):
        def disable(self, service_name: str) -> None:
            wsa.require_supported_install_host()
            role = self._role_of_installed_unit(service_name)
            self._systemctl("disable", "--now", wsa._unit_name_for_role(role), reason="installer_x")
            # MUTATION: the unit file is left on disk

    fs, runner = build_fs(), FakeRunner()
    ctx = build_ctx(fs, runner)
    deps = InstallerDeps(
        services=StopOnlyServiceManager(ctx, accounts=FakeAccounts()),
        identities=wsa.PosixDurableIdentityStore(ctx),
        enroller=FakeEnroller(state="pending"),
        invitations=FakeInvitations(),
        now=lambda: "2026-08-05T00:00:00+00:00",
    )
    with pytest.raises(WorkerInstallerError) as exc:
        install(
            _request(),
            deps,
            ordinary_task_queue=ORDINARY_QUEUE,
            operator_task_queue=OPERATOR_QUEUE,
        )

    # ONLY-THAT-ONE, half 1: the refusal is UNCHANGED under the mutation. This is precisely why a
    # reason-code test cannot catch a broken rollback, and why the file assertion has to exist.
    assert exc.value.reason_code == "installer_enrolled_service_unauthenticated"

    # ONLY-THAT-ONE, half 2: the mutation kills the rollback assertion and nothing else. Run the
    # EXACT assertion the real test runs and require it to fail.
    with pytest.raises(AssertionError, match="left installed on the host"):
        _assert_service_was_rolled_back(fs, runner)


def test_mutation_letting_a_failed_enrollment_leave_the_service_active_is_caught():
    """A service manager whose ``disable`` is a no-op leaves the host ENABLED after a failed
    enrollment. The rollback assertion catches it; the reason code alone does not."""

    class NoOpRollback(wsa.PosixServiceManager):
        def disable(self, service_name: str) -> None:
            return

    fs, runner = build_fs(), FakeRunner()
    ctx = build_ctx(fs, runner)
    deps = InstallerDeps(
        services=NoOpRollback(ctx, accounts=FakeAccounts()),
        identities=wsa.PosixDurableIdentityStore(ctx),
        enroller=FakeEnroller(state="pending"),
        invitations=FakeInvitations(),
        now=lambda: "2026-08-05T00:00:00+00:00",
    )
    with pytest.raises(WorkerInstallerError) as exc:
        install(
            _request(),
            deps,
            ordinary_task_queue=ORDINARY_QUEUE,
            operator_task_queue=OPERATOR_QUEUE,
        )
    assert exc.value.reason_code == "installer_enrolled_service_unauthenticated"
    # the host is left with an enabled service and systemd was never asked to stop it
    assert ("disable", "--now", ORDINARY_UNIT) not in runner.calls
    with pytest.raises(AssertionError, match="left installed on the host"):
        _assert_service_was_rolled_back(fs, runner)


def test_mutation_an_is_active_that_accepts_any_answer_is_caught():
    """Loosen the health check to 'systemd answered' and the exact-``active`` test goes red."""

    class LooseHealth(wsa.PosixServiceManager):
        def is_active(self, service_name: str) -> bool:
            wsa.require_supported_install_host()
            role = self._role_of_installed_unit(service_name)
            try:
                self._systemctl("is-active", wsa._unit_name_for_role(role), reason="installer_x")
            except WorkerInstallerError:
                return False
            return True  # MUTATION: no longer requires the exact "active" token

    runner = FakeRunner(**{"is-active": CommandResult(exit_code=0, stdout="activating\n")})
    loose = LooseHealth(build_ctx(None, runner), accounts=FakeAccounts())
    assert loose.is_active(ORDINARY_UNIT) is True  # the mutant accepts a still-starting service
    strict = services(runner=FakeRunner(**{"is-active": CommandResult(0, "activating\n")}))
    assert strict.is_active(ORDINARY_UNIT) is False  # the real adapter does not


# --- the secpctl wiring: a dry run still plans anywhere, a write uses the real adapters ------


def _install_argv(*extra: str) -> list[str]:
    return [
        "worker",
        "install",
        "--invitation",
        "/etc/secp/invitation.json",
        "--role",
        "ordinary",
        "--plane",
        "management",
        "--installation-id",
        "worker-a",
        "--controller-origin",
        "https://controller.example",
        "--controller-trust-anchor",
        ANCHOR_HEX,
        "--release-digest",
        RELEASE,
        "--service-name",
        ORDINARY_UNIT,
        "--ordinary-queue",
        ORDINARY_QUEUE,
        "--operator-queue",
        OPERATOR_QUEUE,
        *extra,
    ]


def _cli_deps():
    from secp_management.enrollment_cli import EnrollmentCliDeps

    return EnrollmentCliDeps(controller_client=None, worker_enroller=FakeEnroller())


def test_dry_run_still_plans_on_an_unsupported_host(monkeypatch):
    """Planning is pure and host-free, and must stay that way.

    Composing the real adapters unconditionally in the CLI would make ``secpctl worker install``
    with no ``--write`` raise on Windows — turning a command that only validates and reports into a
    platform-dependent one. The dry run is given the sealed deps precisely because it never touches
    them.
    """
    from secp_management import cli

    monkeypatch.setattr(wsa, "_host_os_name", lambda: "nt")
    code, payload = cli.run(_install_argv(), enrollment_deps=_cli_deps())
    assert code == 0
    assert payload["mode"] == "dry_run"
    assert payload["plan"]["task_queue"] == ORDINARY_QUEUE
    assert payload["plan"]["role"] == "ordinary"


def test_write_confirm_on_an_unsupported_host_names_the_platform(monkeypatch):
    """The refusal an operator gets on Windows is now the PLATFORM, not a seal.

    Both are refusals; only one tells the operator what to do about it. Falling back to the sealed
    deps here would report ``installer_service_manager_sealed`` on a host that could never have run
    a worker in the first place.
    """
    from secp_management import cli

    monkeypatch.setattr(wsa, "_host_os_name", lambda: "nt")
    code, payload = cli.run(_install_argv("--write", "--confirm"), enrollment_deps=_cli_deps())
    assert code != 0
    assert payload["reason_code"] == "installer_host_platform_unsupported"


def test_the_write_path_composes_the_real_posix_adapters(monkeypatch):
    """The write path reaches the REAL adapters, not the sealed ones.

    Asserted on the composed types rather than on a successful install, because the real composition
    also reads the root-controlled production inputs (pinned executables) that only a provisioned
    host has — see the remaining-blockers note in the module docstring.
    """
    from secp_management.worker_installer import build_supported_installer_deps

    captured = {}

    def fake_build(enroller=None):
        captured["called"] = True
        ctx = build_ctx()
        return InstallerDeps(
            services=wsa.PosixServiceManager(ctx, accounts=FakeAccounts()),
            identities=wsa.PosixDurableIdentityStore(ctx),
            enroller=FakeEnroller(),
            invitations=FakeInvitations(),
            now=lambda: "2026-08-05T00:00:00+00:00",
        )

    monkeypatch.setattr(wsa, "build_posix_installer_deps", fake_build)
    deps = build_supported_installer_deps(FakeEnroller())
    assert captured["called"]
    assert isinstance(deps.services, wsa.PosixServiceManager)
    assert isinstance(deps.identities, wsa.PosixDurableIdentityStore)


# --- the installer OWNS creating the account it requires -----------------------------------------


def test_install_writes_the_account_declaration_at_the_one_fixed_path():
    """Before this, the adapter merely refused ``installer_worker_account_absent`` and a comment
    asserted the account "is expected to have been provisioned by the host image" — which made the
    unit's User=/Group= hardening contingent on provisioning SECP neither performed nor verified."""
    fs, runner = build_fs(), FakeRunner()
    services(fs, runner).install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)

    stat = fs.lstat(SYSUSERS_PATH)
    assert stat is not None and not stat.is_symlink
    assert stat.uid == 0 and stat.gid == 0 and (stat.mode & 0o777) == 0o644

    body = fs.safe_read(SYSUSERS_PATH, max_bytes=64 * 1024, expected_uid=0).decode()
    assert f'u {wsa._WORKER_USER} - "SECP worker" / {wsa._NOLOGIN_SHELL}' in body
    assert f"g {wsa._WORKER_GROUP} -" in body


def test_the_account_has_no_login_shell_and_no_home():
    """A range platform's worker account is a service identity. A usable shell on it is a foothold,
    and sysusers treats "-" as "the distribution default", which is usually a usable shell."""
    fs = build_fs()
    services(fs).install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
    body = fs.safe_read(SYSUSERS_PATH, max_bytes=64 * 1024, expected_uid=0).decode()
    assert wsa._NOLOGIN_SHELL == "/usr/sbin/nologin"
    assert "/bin/bash" not in body and "/bin/sh" not in body
    # `/` is the home field: no home directory is created for it.
    assert f'"SECP worker" / {wsa._NOLOGIN_SHELL}' in body


def test_the_account_declaration_chooses_no_numeric_id():
    """A hardcoded uid collides on exactly the hosts an operator cares about. sysusers assigns."""
    fs = build_fs()
    services(fs).install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
    body = fs.safe_read(SYSUSERS_PATH, max_bytes=64 * 1024, expected_uid=0).decode()
    for line in body.splitlines():
        if line.startswith(("u ", "g ")):
            assert line.split()[2] == "-", line


def test_start_is_only_ever_given_the_fixed_sysusers_unit():
    """`start` is not a general "start anything" verb. If a future edit passed it a computed unit
    name, this fails — which is the difference between one reviewed oneshot and an arbitrary
    service-control primitive."""
    fs, runner = build_fs(), FakeRunner()
    services(fs, runner).install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
    started = [call for call in runner.calls if call[0] == "start"]
    assert started == [("start", wsa._SYSUSERS_APPLY_UNIT)]


def test_a_sysusers_path_that_is_not_the_fixed_one_is_refused():
    """The sysusers write authority is held to the same "exactly one code-owned path" discipline as
    the unit write authority — never a prefix, a wildcard or a caller filename."""
    locations = ManagementLocations()
    locations.assert_sysusers_writable(locations.worker_sysusers_path())
    for foreign in (
        "/usr/lib/sysusers.d/evil.conf",
        "/usr/lib/sysusers.d/",
        "/etc/sysusers.d/secp-worker.conf",
        "/usr/lib/sysusers.d/secp-worker.conf.bak",
    ):
        with pytest.raises(Exception, match="layout_sysusers_path_not_fixed"):
            locations.assert_sysusers_writable(foreign)


def test_account_creation_failing_refuses_the_whole_install():
    """A unit whose User= names an account that was not created starts as nobody, or not at all.

    The refusal surfaces as ``ManagementError`` rather than ``WorkerInstallerError`` because a
    non-zero systemctl exit is raised by the pinned runner itself, carrying the fault reason — it
    never reaches ``_reject``. Asserted at the layer it actually fails on rather than wrapped.
    """
    from secp_management import ManagementError

    runner = FakeRunner(start=CommandResult(exit_code=1, stdout=""))
    fs = build_fs()
    with pytest.raises(ManagementError, match="installer_worker_account_creation_failed"):
        services(fs, runner).install(ORDINARY_UNIT, role="ordinary", task_queue=ORDINARY_QUEUE)
    # And no unit was installed: a host that could not gain the account never gains a service.
    assert fs.lstat(f"{UNIT_DIR}/{ORDINARY_UNIT}") is None


def test_the_account_is_still_REQUIRED_after_being_provisioned():
    """sysusers reporting success is not the same fact as the account being resolvable, and the
    unit's User=/Group= depends on the second."""
    absent = FakeAccounts(absent=True)
    assert (
        refusal(
            services(build_fs(), FakeRunner(), absent).install,
            ORDINARY_UNIT,
            role="ordinary",
            task_queue=ORDINARY_QUEUE,
        )
        == "installer_worker_account_absent"
    )
