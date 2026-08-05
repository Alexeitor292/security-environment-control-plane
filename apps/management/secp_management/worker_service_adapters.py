"""The REAL POSIX host adapters for the two sealed worker-installer seams.

:mod:`~secp_management.worker_installer` ships with :class:`ServiceManager` and
:class:`DurableIdentityStore` sealed, so ``secpctl worker install --write --confirm`` refuses with
``installer_service_manager_sealed`` and no worker can be installed on a real host. That seal was
correct: a half-real installer that no-ops its host steps reports a successful installation on a
host where nothing happened. This module fills the seam with adapters that really do the work, and
really fail when the work does not happen.

WHAT THIS MODULE COMPOSES RATHER THAN REIMPLEMENTS
---------------------------------------------------
Nothing security-sensitive is written fresh here. Every host effect goes through a primitive that is
already reviewed elsewhere:

* the unit CONTENT comes from :func:`~secp_management.systemd.render_service_unit` — the hardened,
  code-owned template (``NoNewPrivileges``, ``ProtectSystem=strict``, empty capability bounding set,
  absolute non-shell ``ExecStart``). No unit text is assembled in this module;
* every ``systemctl`` invocation goes through :meth:`RealAdapterContext.run`, i.e. the ONE reviewed
  pinned-subprocess seam (absolute, root-owned, digest-pinned executable, ``shell=False``, fixed
  env, bounded output and timeout). There is no generic argv verb — every argv below is a fixed
  literal tuple plus a unit name this module itself derived;
* every write goes through the hardened :class:`~secp_commissioning.runtime.RealFilesystem`
  (directory-fd-relative, trusted-ancestor walk, symlink/owner/mode fail-closed, atomic install).

THE UNIT NAME IS DERIVED FROM THE ROLE, NEVER FROM THE OPERATOR
---------------------------------------------------------------
``InstallationRequest.service_name`` is operator-supplied. Writing ``/etc/systemd/system/<that>``
would be precisely the caller-filename-in-the-systemd-directory injection that
:meth:`~secp_management.layout.ManagementLocations.assert_unit_writable` exists to make structurally
impossible. So the operator's ``service_name`` SELECTS NOTHING: the unit path is derived from the
validated ROLE through :data:`_ROLE_UNIT_NAMES`, and a ``service_name`` that does not equal the
code-owned name for that role is refused (``installer_service_name_not_fixed``). The operator's
value is a declaration this adapter checks, never a path it follows.

THE THREE PRE-EXISTING FIXED UNIT PATHS ARE OFF LIMITS
-------------------------------------------------------
The controller wrapper, the enrollment-signer broker, and above all the SEALED controlled-live
operator unit (``secp-operator-worker.service``, installed present-but-disabled and never enabled by
anything) keep their own authority. The two unit names here are NEW and distinct from all three, and
:func:`_unit_path_for_role` refuses to return any of them — so nothing in this installer can write
to, enable, or remove the sealed operator unit. See
``test_worker_service_adapters.py::test_installer_can_never_target_a_pre_existing_fixed_unit``.

ROLLBACK IS REMOVAL, NOT DEACTIVATION
--------------------------------------
The installer treats "service activated, authenticated enrollment did not reach healthy" as a FAILED
installation and calls :meth:`PosixServiceManager.disable`. That is implemented here as a full
removal — stop, disable, delete the unit file, reload, and then PROVE the unit is gone — because a
merely-stopped-but-still-installed unit is one ``systemctl start`` (or one buggy generator) away
from polling a controller that has no verified identity for it.

NO ENROLLMENT MATERIAL PASSES THROUGH HERE
-------------------------------------------
This module never sees the invitation. It receives a role, a queue name and a service name — all
non-secret, all already present in the plan and the evidence record. Nothing here is written to an
environment variable, a rendered unit, a log line, or a process argument that is not one of those.

PLATFORM
--------
POSIX only, and it says so LOUDLY. :func:`require_supported_install_host` refuses on any non-POSIX
host with ``installer_host_platform_unsupported`` rather than degrading to a no-op, and the tests
assert that refusal rather than skipping themselves off Windows.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import NoReturn, Protocol

from secp_commissioning.runtime import FilesystemError

from secp_management import ManagementError
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import RealAdapterContext
from secp_management.systemd import render_service_unit
from secp_management.worker_installer import InstallerDeps, WorkerEnroller, WorkerInstallerError
from secp_management.worker_roles import WorkerRole

# --- code-owned constants (never descriptor-selected, never a CLI argument) ---------------------

#: The role -> unit-name table. NEW names, deliberately distinct from the three pre-existing fixed
#: unit paths (controller wrapper, prepared operator, enrollment-signer broker) so this installer
#: cannot touch any of them. Keyed by the LIVE enum member, so a third role added to
#: :class:`~secp_management.worker_roles.WorkerRole` has no unit here and refuses rather than
#: silently reusing another role's unit.
_ROLE_UNIT_NAMES: dict[WorkerRole, str] = {
    WorkerRole.ordinary: "secp-worker-ordinary.service",
    WorkerRole.infrastructure_operator: "secp-worker-infrastructure-operator.service",
}

#: The dedicated unprivileged POSIX account the worker unit runs as. The worker is NEVER root; the
#: account is expected to have been provisioned by the host image, and its absence is a refusal
#: rather than a silent fallback to a more privileged identity.
_WORKER_USER = "secp-worker"
_WORKER_GROUP = "secp-worker"

_ROOT_UID = 0
_ROOT_GID = 0
_IDENTITY_MODE = 0o600  # owner-only: the durable identity is root-readable and nothing else
_UNIT_MODE = 0o644
_STATE_MODE = 0o700
_MAX_IDENTITY_BYTES = 64 * 1024
_SYSTEMCTL_TIMEOUT = 30
_MAX_UNIT_BYTES = 64 * 1024

#: ``systemctl`` verbs this adapter is permitted to issue, as fixed literals. Listed so the
#: mutation surface of the whole module is readable in one place and testable as a closed set.
_SYSTEMCTL_VERBS = (
    "daemon-reload",
    "enable",
    "disable",
    "restart",
    "is-active",
    "is-enabled",
)


def _reject(reason_code: str) -> NoReturn:
    raise WorkerInstallerError(reason_code)


def _host_os_name() -> str:
    """The live platform. A function, not a captured constant, so it is read at every call and a
    test can exercise the unsupported branch WITHOUT patching ``os.name`` globally (which would
    perturb pathlib and tempfile for the whole process). ``test_host_os_name_reads_the_real_
    platform`` pins that this really is ``os.name`` and not a bypass."""
    return os.name


def require_supported_install_host() -> None:
    """Refuse LOUDLY on a host this installer does not support.

    Windows is not a supported install host. This raises rather than returning a degraded adapter,
    and the tests assert the refusal instead of skipping — a skip that reads as a pass is the exact
    defect this program has repeatedly paid for.
    """
    if _host_os_name() != "posix":
        _reject("installer_host_platform_unsupported")


def _unit_name_for_role(role: WorkerRole) -> str:
    name = _ROLE_UNIT_NAMES.get(role)
    if name is None:
        _reject("installer_role_not_authorized")
    return name


def _unit_path_for_role(locations: ManagementLocations, role: WorkerRole) -> str:
    """The EXACT unit path for ``role``, refusing any collision with a pre-existing fixed unit.

    The collision check is not decoration. :data:`_ROLE_UNIT_NAMES` is a literal table, and a future
    edit that renamed a worker unit onto ``secp-operator-worker.service`` would hand this installer
    the power to enable the sealed controlled-live operator. Refusing here makes that a failure at
    the first call rather than a quiet capability grant.
    """
    path = f"{locations.systemd_dir}/{_unit_name_for_role(role)}"
    if path in (
        locations.controller_unit_path(),
        locations.operator_unit_path(),
        locations.broker_unit_path(),
    ):
        _reject("installer_unit_path_reserved")
    return path


def _parse_role(role: object) -> WorkerRole:
    """Re-parse the role token the installer passes as a plain string across the seam."""
    from secp_management.worker_roles import parse_worker_role

    try:
        return parse_worker_role(role)
    except ManagementError:
        _reject("installer_role_not_authorized")


# --- the unprivileged worker account seam --------------------------------------------------------


class AccountResolver(Protocol):
    """Resolves the dedicated worker account to a (uid, gid). Host-local; reads no file the
    hardened filesystem owns."""

    def resolve(self, user: str, group: str) -> tuple[int, int]: ...


class PosixAccountResolver:
    """The production resolver: the real POSIX passwd/group databases.

    A seam rather than an inline lookup so the hermetic tests exercise the adapter's REAL branches
    (account absent, account resolves to root) instead of monkeypatching a private method — the
    refusals are the point, so they must be reachable in a test.
    """

    def __repr__(self) -> str:
        return "PosixAccountResolver(<posix>)"

    def resolve(self, user: str, group: str) -> tuple[int, int]:
        # `pwd`/`grp` are POSIX-only and carry no stubs on a Windows type-check host, so the
        # attribute access is ignored rather than the import. Reaching here on a non-POSIX host is
        # already impossible: every caller passes require_supported_install_host() first.
        import grp
        import pwd

        return (
            pwd.getpwnam(user).pw_uid,  # type: ignore[attr-defined]
            grp.getgrnam(group).gr_gid,  # type: ignore[attr-defined]
        )


# --- the real service manager --------------------------------------------------------------------


@dataclass
class PosixServiceManager:
    """Real systemd unit installation, activation, health verification, restart and ROLLBACK.

    Satisfies :class:`~secp_management.worker_installer.ServiceManager`. Every method is host-local;
    none contacts the controller, and none ever receives enrollment material.
    """

    ctx: RealAdapterContext
    accounts: AccountResolver = field(default_factory=PosixAccountResolver)

    def __repr__(self) -> str:  # bounded: never a path, digest, queue or unit body
        return "PosixServiceManager(<posix>)"

    # -- helpers ---------------------------------------------------------------------------------

    def _systemctl(self, verb: str, *args: str, reason: str) -> str:
        if verb not in _SYSTEMCTL_VERBS:  # closed set; a computed verb cannot reach the runner
            _reject("installer_service_verb_not_authorized")
        return self.ctx.run(
            self.ctx.executables.service_manager,
            (verb, *args),
            timeout=_SYSTEMCTL_TIMEOUT,
            reason=reason,
            fault_reason=reason,
        )

    def _resolve(self, service_name: str, role: WorkerRole) -> str:
        """The unit name this adapter will act on, after proving the operator's ``service_name``
        matches the code-owned name for ``role``. The operator's value selects nothing."""
        expected = _unit_name_for_role(role)
        if service_name != expected:
            _reject("installer_service_name_not_fixed")
        return expected

    def _role_of_installed_unit(self, service_name: str) -> WorkerRole:
        """Recover the role for the methods the installer calls with only a service name.

        ``enable``/``is_active``/``disable``/``restart`` take no role, so the mapping is inverted
        from the same code-owned table ``install`` used. An unrecognised name is refused rather than
        being treated as a unit path.
        """
        for role, name in _ROLE_UNIT_NAMES.items():
            if name == service_name:
                return role
        _reject("installer_service_name_not_fixed")

    def _require_worker_account(self) -> tuple[int, int]:
        """The dedicated unprivileged account must already exist; refuse rather than fall back."""
        try:
            uid, gid = self.accounts.resolve(_WORKER_USER, _WORKER_GROUP)
        except Exception:  # noqa: BLE001 - any resolution failure is "no usable worker account"
            _reject("installer_worker_account_absent")
        if not isinstance(uid, int) or not isinstance(gid, int):
            _reject("installer_worker_account_absent")
        if uid == _ROOT_UID or gid == _ROOT_GID:
            # a "worker" account that resolves to root defeats the whole point of the unit's
            # User=/Group=; refuse instead of installing a root-running worker
            _reject("installer_worker_account_privileged")
        return uid, gid

    def _worker_executable(self) -> str:
        return f"{self.ctx.locations.worker_root}/bin/secp-worker"

    def _state_dir(self) -> str:
        return f"{self.ctx.locations.worker_root}/state"

    # -- ServiceManager --------------------------------------------------------------------------

    def install(self, service_name: str, *, role: str, task_queue: str) -> None:
        """Render and install the hardened unit for this role, then reload systemd.

        Refuses BEFORE writing anything if the host is unsupported, the service name is not the
        code-owned one for the role, the worker runtime is not installed, or the unprivileged worker
        account does not exist — so a host that cannot actually run a worker never gains a unit.
        """
        require_supported_install_host()
        parsed = _parse_role(role)
        unit_name = self._resolve(service_name, parsed)
        unit_path = _unit_path_for_role(self.ctx.locations, parsed)

        if not isinstance(task_queue, str) or not task_queue.strip():
            _reject("installer_queue_not_configured")

        executable = self._worker_executable()
        try:
            stat = self.ctx.fs.lstat(executable)
        except FilesystemError:
            _reject("installer_worker_runtime_absent")
        if stat is None or stat.is_dir or stat.is_symlink:
            # a unit pointing at an absent or symlinked entrypoint would install cleanly and then
            # never start; refuse now rather than discovering it at verify_service_health
            _reject("installer_worker_runtime_absent")

        uid, gid = self._require_worker_account()
        state_dir = self._state_dir()
        self.ctx.locations.assert_writable(state_dir)
        try:
            self.ctx.fs.makedir(state_dir, uid=uid, gid=gid, mode=_STATE_MODE)
        except FilesystemError:
            # already present is not an error; an unusable state dir surfaces as a failed start
            pass

        try:
            content = render_service_unit(
                description=f"SECP worker ({parsed.value})",
                exec_argv=(executable, "--role", parsed.value, "--task-queue", task_queue),
                user=_WORKER_USER,
                group=_WORKER_GROUP,
                read_write_paths=(state_dir,),
                wanted_by="multi-user.target",
            )
        except ManagementError:
            _reject("installer_service_unit_invalid")

        data = content.encode("utf-8")
        if len(data) > _MAX_UNIT_BYTES:
            _reject("installer_service_unit_invalid")
        try:
            self.ctx.fs.atomic_install(
                unit_path, data, uid=_ROOT_UID, gid=_ROOT_GID, mode=_UNIT_MODE
            )
        except FilesystemError:
            _reject("installer_service_install_failed")

        self._systemctl("daemon-reload", reason="installer_service_install_failed")
        # prove the unit is now known to systemd; a unit file on disk that systemd will not load is
        # not an installed service
        self._systemctl("is-enabled", unit_name, reason="installer_service_install_failed")

    def enable(self, service_name: str) -> None:
        """Enable AND start the unit, then prove it is enabled.

        ``--now`` is required, not a convenience: the installer's next step verifies health, and
        health is observed from a RUNNING service. The ``is-enabled`` re-read is what makes restart
        persistence real — an enabled unit is the one that comes back after a reboot.
        """
        require_supported_install_host()
        role = self._role_of_installed_unit(service_name)
        unit_name = _unit_name_for_role(role)
        self._systemctl("enable", "--now", unit_name, reason="installer_service_enable_failed")
        state = self._systemctl(
            "is-enabled", unit_name, reason="installer_service_enable_failed"
        ).strip()
        if state != "enabled":
            _reject("installer_service_not_enabled")

    def is_active(self, service_name: str) -> bool:
        """True only on an EXACT ``active`` answer from systemd.

        Every other outcome — inactive, failed, unknown unit, a runner fault, an unparseable
        answer — is False. An unobservable service is never read as a healthy one.
        """
        require_supported_install_host()
        role = self._role_of_installed_unit(service_name)
        unit_name = _unit_name_for_role(role)
        try:
            out = self._systemctl(
                "is-active", unit_name, reason="installer_service_state_unreadable"
            )
        except ManagementError:
            return False  # non-zero exit (inactive/failed) or runner fault -> not active
        return out.strip() == "active"

    def disable(self, service_name: str) -> None:
        """ROLLBACK: stop, disable, REMOVE the unit file, reload, and prove the unit is gone.

        Removal rather than deactivation. The installer calls this when activation succeeded but
        authenticated enrollment did not, and a unit that is merely stopped is still installed,
        still enable-able, and still one boot away from polling a controller that holds no verified
        identity for this host.

        Raises if the unit could not be proven absent. The installer's ``_rollback`` deliberately
        swallows that so the operator sees the ORIGINAL failure rather than a secondary symptom —
        that is the reviewed sequencer's choice, not a claim by this adapter that removal succeeded.
        """
        require_supported_install_host()
        role = self._role_of_installed_unit(service_name)
        unit_name = _unit_name_for_role(role)
        unit_path = _unit_path_for_role(self.ctx.locations, role)

        try:
            self._systemctl(
                "disable", "--now", unit_name, reason="installer_service_rollback_failed"
            )
        except ManagementError:
            # a unit that is already gone/never enabled must not stop the removal below
            pass

        try:
            self.ctx.fs.remove_file(unit_path)
        except FilesystemError:
            pass  # absence is the goal; the proof below decides

        self._systemctl("daemon-reload", reason="installer_service_rollback_failed")

        try:
            remaining = self.ctx.fs.lstat(unit_path)
        except FilesystemError:
            _reject("installer_service_rollback_failed")
        if remaining is not None:
            _reject("installer_service_rollback_failed")

    def restart(self, service_name: str) -> None:
        require_supported_install_host()
        role = self._role_of_installed_unit(service_name)
        unit_name = _unit_name_for_role(role)
        self._systemctl("restart", unit_name, reason="installer_restart_verification_failed")


# --- the real durable identity store -------------------------------------------------------------


@dataclass
class PosixDurableIdentityStore:
    """The worker's durable installation identity, persisted 0600 owner-only across restarts.

    Satisfies :class:`~secp_management.worker_installer.DurableIdentityStore`. Stores identities,
    digests, a role, a plane and a queue name — never the invitation, an attestation, or key
    material. Fails CLOSED: if the record cannot be written, or cannot be read back as the document
    that was written, the installation refuses rather than continuing without a durable identity.
    """

    ctx: RealAdapterContext

    def __repr__(self) -> str:  # bounded: never a path or a record field
        return "PosixDurableIdentityStore(<posix>)"

    def _path(self) -> str:
        path = f"{self.ctx.locations.bootstrap_state}/worker-installation-identity.json"
        self.ctx.locations.assert_writable(path)
        return path

    def load(self) -> dict | None:
        """The persisted record, or None when there is none.

        None means ONLY "no record exists". A record that exists but cannot be read as a root-owned
        JSON object is a refusal, never a None that the replay check would read as a clean host.
        """
        require_supported_install_host()
        path = self._path()
        try:
            stat = self.ctx.fs.lstat(path)
        except FilesystemError:
            _reject("installer_identity_not_durable")
        if stat is None:
            return None
        if stat.is_dir or stat.is_symlink or stat.uid != _ROOT_UID:
            # a symlink, a directory, or a non-root-owned file at the fixed path is not our record
            _reject("installer_identity_not_durable")
        try:
            raw = self.ctx.fs.safe_read(path, max_bytes=_MAX_IDENTITY_BYTES, expected_uid=_ROOT_UID)
        except FilesystemError:
            _reject("installer_identity_not_durable")
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            _reject("installer_identity_not_durable")
        if not isinstance(record, dict):
            _reject("installer_identity_not_durable")
        return record

    def persist(self, record: dict) -> None:
        """Write the record atomically, 0600 root-owned, and READ IT BACK before returning.

        The read-back is the difference between "the write call returned" and "the identity is
        durable". A store that reported success on a full or read-only filesystem would let the
        installer enable a service for a worker whose identity did not survive the call, which is
        the exact state the installer's ordering exists to prevent.
        """
        require_supported_install_host()
        if not isinstance(record, dict):
            _reject("installer_identity_not_durable")
        try:
            data = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            _reject("installer_identity_not_durable")
        if len(data) > _MAX_IDENTITY_BYTES:
            _reject("installer_identity_not_durable")

        path = self._path()
        try:
            self.ctx.fs.atomic_install(
                path, data, uid=_ROOT_UID, gid=_ROOT_GID, mode=_IDENTITY_MODE
            )
        except FilesystemError:
            _reject("installer_identity_not_durable")

        written = self.load()
        if written != record:
            _reject("installer_identity_not_durable")


# --- production composition ----------------------------------------------------------------------


def build_posix_installer_deps(enroller: WorkerEnroller | None = None) -> InstallerDeps:
    """Compose the installer over the REAL host adapters on a supported POSIX host.

    This is the composition ``build_installer_deps`` deliberately would not make while the host
    seams had no reviewed adapter. It refuses on an unsupported host BEFORE building anything, so
    the failure is a bounded reason code and never a silently degraded installer.

    The pinned executables, hardened filesystem and fixed locations come from the same fixed
    root-controlled production inputs the management engine uses — no CLI, API, env var or global
    selects an adapter here.
    """
    require_supported_install_host()

    import datetime as _dt

    from secp_commissioning.runtime import RealFilesystem
    from secp_operator_deployment.host_process import RealCommandRunner

    from secp_management.production import _load_executables, _production_paths
    from secp_management.worker_enroller import build_worker_enroller

    locations = ManagementLocations()
    filesystem = RealFilesystem()
    ctx = RealAdapterContext(
        locations=locations,
        fs=filesystem,
        runner=RealCommandRunner(),
        executables=_load_executables(filesystem, _production_paths(locations)["executables"]),
    )
    return InstallerDeps(
        services=PosixServiceManager(ctx),
        identities=PosixDurableIdentityStore(ctx),
        enroller=enroller if enroller is not None else build_worker_enroller(),
        now=lambda: _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
    )


__all__ = [
    "AccountResolver",
    "PosixAccountResolver",
    "PosixDurableIdentityStore",
    "PosixServiceManager",
    "build_posix_installer_deps",
    "require_supported_install_host",
]
