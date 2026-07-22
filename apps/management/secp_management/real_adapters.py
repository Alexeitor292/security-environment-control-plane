"""Production management-plane host adapters (SECP-PR5G).

The engine performs NO host effect directly; these are the REAL leaves for the four closed, typed
seams whose shipped defaults are sealed (see ``adapters.py``).  They are thin, closed orchestrations
that COMPOSE already-reviewed primitives and never reimplement security-sensitive behavior:

* every host command runs through the ONE reviewed subprocess seam
  :class:`~secp_operator_deployment.host_process.RealCommandRunner` via an object-pinned
  :class:`~secp_operator_deployment.pinned_exec.ExecutablePin` (absolute, root-owned, regular,
  single-link, digest-pinned, ``O_NOFOLLOW``, executed through the verified fd, ``shell=False``,
  fixed ``PATH``/``LC_ALL`` env only, stdin ``DEVNULL``, bounded stdout + timeout, own process
  group, group-killed + disappearance-proven).  There is NO generic subprocess/shell/argv/path verb;
  every argv is derived from fixed constants + the typed plan;
* every write goes through the hardened :class:`~secp_commissioning.runtime.RealFilesystem`
  (directory-fd-relative, trusted-ancestor walk from ``/``, symlink/hardlink/owner/mode fail-closed,
  atomic install) to a FIXED :class:`~secp_management.layout.ManagementLocations` path — never a
  caller path; systemd units go only through the stricter exact-path unit authority;
* image loads verify the LOADED image digest against the signed purpose-specific runtime digest
  (never the archive digest, never a floating tag, never a registry pull);
* each mutation adapter accumulates an exact :class:`BootstrapReceipt` and exposes a closed
  ``compensate(receipt)`` that removes ONLY transaction-created objects in reverse reviewed order,
  verifying current content/metadata before touching anything and returning a
  :class:`CompensationResult` whose residual forces the engine to ``recovery_required``.

Real leaves are constructed ONLY by the fixed production composition (``production.py``); the
``EngineDeps()`` and CLI construction remain sealed, and no CLI/API/env/global selects an adapter.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from secp_commissioning.canonical import sha256_bytes
from secp_commissioning.runtime import FilesystemBackend, FilesystemError
from secp_operator_deployment.host_process import CommandRunner
from secp_operator_deployment.pinned_exec import ExecutablePin

from secp_management import ManagementError
from secp_management.adapters import (
    BootstrapReceipt,
    CompensationResult,
    ReviewedConfig,
    ReviewedUnit,
    VerifiedArtifact,
)
from secp_management.layout import ManagementLocations
from secp_management.signing import sign_ed25519, verify_ed25519
from secp_management.topology import (
    CONTROLLER_MIGRATION_ARGV,
    EXPECTED_CONTROLLER_COMPONENTS,
    ORDINARY_CONTAINER_NAME,
)

_ROOT_UID = 0
_ROOT_GID = 0
_MANAGED_MODE = 0o640
_UNIT_MODE = 0o644
_STAGING_MODE = 0o600
_MAX_OUTPUT = 64 * 1024
_LOAD_TIMEOUT = 300
_INSPECT_TIMEOUT = 20
_MIGRATE_TIMEOUT = 600
_START_TIMEOUT = 300
_STOP_TIMEOUT = 120
_SYSTEMCTL_TIMEOUT = 30
_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_CONTROLLER_MIGRATION_SERVICE = (
    "api"  # the reviewed component that runs alembic (see CONTROLLER_STACK)
)


@dataclass(frozen=True)
class PinnedExecutables:
    """The independently reviewed identities of every host binary the adapters invoke.  Each is an
    absolute path + content digest; the runner re-verifies the object at every call."""

    container_runtime: ExecutablePin
    compose_runtime: ExecutablePin
    service_manager: ExecutablePin  # systemctl


@dataclass(frozen=True)
class RealAdapterContext:
    """The fixed production composition context: hardened filesystem, pinned runner + executables,
    fixed locations, and closed compose project names.  Built only by ``production.py`` from a
    reviewed out-of-band source — never from a CLI/API argument."""

    locations: ManagementLocations
    fs: FilesystemBackend
    runner: CommandRunner
    executables: PinnedExecutables
    controller_project: str = "secp-controller"
    worker_project: str = "secp-worker"

    def _staging_path(self, role: str) -> str:
        path = f"{self.locations.bootstrap_root}/staging/{role}-image-load.tar"
        self.locations.assert_writable(path)
        return path

    def run(self, pin: ExecutablePin, argv: tuple[str, ...], *, timeout: int, reason: str) -> str:
        """Run one closed pinned command; return bounded stdout or raise ``reason`` on non-zero exit
        or runner fault.  Never a shell/generic-argv verb — argv is fixed by the caller."""
        try:
            result = self.runner.run(
                pin, argv, timeout_seconds=timeout, max_output_bytes=_MAX_OUTPUT
            )
        except Exception:  # noqa: BLE001 - any runner fault is a fail-closed host-op error
            raise ManagementError(reason) from None
        if result.exit_code != 0:
            raise ManagementError(reason)
        return result.stdout


def _load_and_verify_image(
    ctx: RealAdapterContext, artifact: VerifiedArtifact, *, role: str, purpose_prefix: str
) -> str:
    """Stage the digest-checked archive, load it through the pinned container runtime, and prove the
    LOADED image (the signed purpose-specific digest) is present, never the archive digest alone."""
    if not (isinstance(artifact.purpose, str) and artifact.purpose.startswith(purpose_prefix)):
        raise ManagementError("bootstrap_image_purpose_mismatch")
    if not artifact.image_digest:
        raise ManagementError("bootstrap_image_digest_missing")
    data = artifact.read()  # exact verified archive bytes (size + content digest checked)
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise ManagementError("bootstrap_image_too_large")
    staging = ctx._staging_path(role)
    try:
        ctx.fs.atomic_install(staging, data, uid=_ROOT_UID, gid=_ROOT_GID, mode=_STAGING_MODE)
    except FilesystemError:
        raise ManagementError("bootstrap_image_stage_failed") from None
    try:
        ctx.run(
            ctx.executables.container_runtime,
            ("load", "-i", staging),
            timeout=_LOAD_TIMEOUT,
            reason="bootstrap_image_load_failed",
        )
        out = ctx.run(
            ctx.executables.container_runtime,
            ("image", "inspect", "--format", "{{.Id}}", artifact.image_digest),
            timeout=_INSPECT_TIMEOUT,
            reason="bootstrap_image_absent_after_load",
        )
        if out.strip() != artifact.image_digest:
            raise ManagementError("bootstrap_image_absent_after_load")
        artifact.verify_loaded_image(artifact.image_digest)  # loaded == signed purpose digest
    finally:
        try:
            ctx.fs.remove_file(staging)  # a transaction temp, never part of the receipt
        except FilesystemError:
            pass
    return artifact.image_digest


def _install_file(
    ctx: RealAdapterContext, path: str, content: bytes, *, mode: int, unit: bool
) -> None:
    if unit:
        ctx.locations.assert_unit_writable(path)
    else:
        ctx.locations.assert_writable(path)
    try:
        ctx.fs.atomic_install(path, content, uid=_ROOT_UID, gid=_ROOT_GID, mode=mode)
    except FilesystemError:
        raise ManagementError("bootstrap_file_install_failed") from None


def _remove_created_file(
    ctx: RealAdapterContext, path: str, expected_digest: str, *, unit: bool
) -> bool:
    """Remove a transaction-created file ONLY after proving its current bytes are exactly what we
    installed (drifted content is not ours → not removed).  Returns True iff proven removed."""
    try:
        if unit:
            ctx.locations.assert_unit_writable(path)
        else:
            ctx.locations.assert_writable(path)
        stat = ctx.fs.lstat(path)
        if stat is None:
            return True  # already absent → nothing owned to remove
        current = ctx.fs.safe_read(path, max_bytes=_MAX_ARTIFACT_BYTES, expected_uid=_ROOT_UID)
        if sha256_bytes(current) != expected_digest:
            return False  # drifted → not the object we created; do not touch it
        ctx.fs.remove_file(path)
        return ctx.fs.lstat(path) is None
    except (FilesystemError, ManagementError):
        return False


def _remove_image(ctx: RealAdapterContext, digest: str) -> bool:
    try:
        ctx.run(
            ctx.executables.container_runtime,
            ("image", "rm", "--force", digest),
            timeout=_INSPECT_TIMEOUT,
            reason="compensation_image_remove_failed",
        )
    except ManagementError:
        pass  # tolerate "already absent"; the presence check below is the proof
    out_reason = "compensation_image_present"
    try:
        ctx.run(
            ctx.executables.container_runtime,
            ("image", "inspect", "--format", "{{.Id}}", digest),
            timeout=_INSPECT_TIMEOUT,
            reason=out_reason,
        )
    except ManagementError:
        return True  # inspect failed → image absent → proven removed
    return False  # still present → not proven removed


def _compose_down(ctx: RealAdapterContext, project: str, compose_path: str) -> bool:
    try:
        ctx.run(
            ctx.executables.compose_runtime,
            ("--project-name", project, "--file", compose_path, "down", "--remove-orphans"),
            timeout=_STOP_TIMEOUT,
            reason="compensation_stack_stop_failed",
        )
        return True
    except ManagementError:
        return False


# --------------------------------------------------------------------------- controller adapter


class RealControllerBootstrapAdapter:
    """The exact reviewed controller bootstrap sequence from the typed ControllerBootstrapPlan.
    No generic subprocess/shell/argv/path/Compose/service/container/unit/migration surface is
    ever exposed to the engine or caller."""

    def __init__(self, ctx: RealAdapterContext) -> None:
        self._ctx = ctx
        self._ops: list[str] = []
        self._images: list[str] = []
        self._configs: list[str] = []
        self._units: list[str] = []
        self._services: list[str] = []

    def load_image(self, artifact: VerifiedArtifact) -> None:
        digest = _load_and_verify_image(
            self._ctx, artifact, role="controller", purpose_prefix="controller/"
        )
        self._ops.append(f"load_image:{artifact.digest}")
        self._images.append(digest)

    def install_config(self, config: ReviewedConfig) -> None:
        config.verify()
        _install_file(
            self._ctx,
            self._ctx.locations.controller_compose_path(),
            config.content,
            mode=_MANAGED_MODE,
            unit=False,
        )
        self._ops.append("install_config")
        self._configs.append(config.identity)

    def install_unit(self, unit: ReviewedUnit) -> None:
        unit.verify()
        _install_file(
            self._ctx,
            self._ctx.locations.controller_unit_path(),
            unit.content,
            mode=_UNIT_MODE,
            unit=True,
        )
        self._ops.append("install_unit")
        self._units.append(unit.identity)

    def daemon_reload(self) -> None:
        # only AFTER the unit file is proven installed (install_unit ran first per the plan order)
        self._ctx.run(
            self._ctx.executables.service_manager,
            ("daemon-reload",),
            timeout=_SYSTEMCTL_TIMEOUT,
            reason="daemon_reload_failed",
        )
        self._ops.append("daemon_reload")

    def run_migrations(self, *, migration_identity: str) -> None:
        self._ctx.run(
            self._ctx.executables.compose_runtime,
            (
                "--project-name",
                self._ctx.controller_project,
                "--file",
                self._ctx.locations.controller_compose_path(),
                "run",
                "--rm",
                "--no-deps",
                _CONTROLLER_MIGRATION_SERVICE,
                *CONTROLLER_MIGRATION_ARGV,
            ),
            timeout=_MIGRATE_TIMEOUT,
            reason="migration_failed",
        )
        self._ops.append(f"run_migrations:{migration_identity}")

    def start_stack(self, *, expected_components: tuple[str, ...]) -> None:
        if tuple(expected_components) != tuple(EXPECTED_CONTROLLER_COMPONENTS):
            raise ManagementError("controller_components_mismatch")
        self._ctx.run(
            self._ctx.executables.compose_runtime,
            (
                "--project-name",
                self._ctx.controller_project,
                "--file",
                self._ctx.locations.controller_compose_path(),
                "up",
                "--detach",
                "--no-deps",
                "--no-build",
                "--pull",
                "never",
                *expected_components,
            ),
            timeout=_START_TIMEOUT,
            reason="controller_start_failed",
        )
        self._ops.append("start_stack")
        self._services.extend(expected_components)

    def receipt(self) -> BootstrapReceipt:
        return BootstrapReceipt(
            operations=tuple(self._ops),
            loaded_images=tuple(self._images),
            installed_configs=tuple(self._configs),
            installed_units=tuple(self._units),
            started_services=tuple(self._services),
        )

    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult:
        if type(receipt) is not BootstrapReceipt:
            return CompensationResult(proven=False, residual=("malformed_receipt",))
        ctx = self._ctx
        residual: list[str] = []
        # reverse reviewed order: stop the stack, remove the unit, remove the config, remove images.
        if receipt.started_services and not _compose_down(
            ctx, ctx.controller_project, ctx.locations.controller_compose_path()
        ):
            residual.append("controller_stack")
        for identity in receipt.installed_units:
            if not _remove_created_file(
                ctx, ctx.locations.controller_unit_path(), identity, unit=True
            ):
                residual.append("controller_unit")
        for identity in receipt.installed_configs:
            if not _remove_created_file(
                ctx, ctx.locations.controller_compose_path(), identity, unit=False
            ):
                residual.append("controller_config")
        for digest in receipt.loaded_images:
            if not _remove_image(ctx, digest):
                residual.append("controller_image")
        return CompensationResult(proven=not residual, residual=tuple(residual))


# --------------------------------------------------------------------------- worker adapter


class RealWorkerBootstrapAdapter:
    """The exact reviewed worker bootstrap sequence derived from the typed WorkerBootstrapPlan.  The
    operator unit is installed DISABLED + STOPPED and is NEVER enabled or started; only the ordinary
    worker is started."""

    def __init__(self, ctx: RealAdapterContext) -> None:
        self._ctx = ctx
        self._ops: list[str] = []
        self._images: list[str] = []
        self._configs: list[str] = []
        self._units: list[str] = []
        self._packages: list[str] = []
        self._services: list[str] = []

    def load_image(self, artifact: VerifiedArtifact) -> None:
        digest = _load_and_verify_image(
            self._ctx, artifact, role="worker", purpose_prefix="worker/"
        )
        self._ops.append(f"load_image:{artifact.digest}")
        self._images.append(digest)

    def install_ordinary_config(self, config: ReviewedConfig) -> None:
        config.verify()
        _install_file(
            self._ctx,
            self._ctx.locations.worker_compose_path(),
            config.content,
            mode=_MANAGED_MODE,
            unit=False,
        )
        self._ops.append("install_ordinary_config")
        self._configs.append(config.identity)

    def install_deployment_package(self, package: VerifiedArtifact, *, aggregate: str) -> None:
        if package.purpose != "worker/deployment-package":
            raise ManagementError("bootstrap_image_purpose_mismatch")
        data = package.read()
        _install_file(
            self._ctx,
            self._ctx.locations.worker_deployment_package_path(),
            data,
            mode=_MANAGED_MODE,
            unit=False,
        )
        self._ops.append("install_deployment_package")
        self._packages.append(aggregate)

    def install_operator_unit_disabled(self, unit: ReviewedUnit) -> None:
        unit.verify()
        # write the DISABLED unit file only; NEVER systemctl enable/start - the reviewed unit has
        # no [Install]/WantedBy, so it can never be enabled or auto-started (see systemd.py).
        _install_file(
            self._ctx,
            self._ctx.locations.operator_unit_path(),
            unit.content,
            mode=_UNIT_MODE,
            unit=True,
        )
        self._ops.append("install_operator_unit_disabled")
        self._units.append(unit.identity)

    def daemon_reload(self) -> None:
        self._ctx.run(
            self._ctx.executables.service_manager,
            ("daemon-reload",),
            timeout=_SYSTEMCTL_TIMEOUT,
            reason="daemon_reload_failed",
        )
        self._ops.append("daemon_reload")

    def start_ordinary(self) -> None:
        # start ONLY the ordinary worker service; the operator is never started here.
        self._ctx.run(
            self._ctx.executables.compose_runtime,
            (
                "--project-name",
                self._ctx.worker_project,
                "--file",
                self._ctx.locations.worker_compose_path(),
                "up",
                "--detach",
                "--no-deps",
                "--force-recreate",
                "--no-build",
                "--pull",
                "never",
                ORDINARY_CONTAINER_NAME,
            ),
            timeout=_START_TIMEOUT,
            reason="worker_start_failed",
        )
        self._ops.append("start_ordinary")
        self._services.append(ORDINARY_CONTAINER_NAME)

    def receipt(self) -> BootstrapReceipt:
        return BootstrapReceipt(
            operations=tuple(self._ops),
            loaded_images=tuple(self._images),
            installed_configs=tuple(self._configs),
            installed_units=tuple(self._units),
            installed_packages=tuple(self._packages),
            started_services=tuple(self._services),
        )

    def compensate(self, receipt: BootstrapReceipt) -> CompensationResult:
        if type(receipt) is not BootstrapReceipt:
            return CompensationResult(proven=False, residual=("malformed_receipt",))
        ctx = self._ctx
        residual: list[str] = []
        if receipt.started_services and not _compose_down(
            ctx, ctx.worker_project, ctx.locations.worker_compose_path()
        ):
            residual.append("ordinary_worker")
        for identity in receipt.installed_units:
            if not _remove_created_file(
                ctx, ctx.locations.operator_unit_path(), identity, unit=True
            ):
                residual.append("operator_unit")
        for _aggregate in receipt.installed_packages:
            stat = None
            try:
                stat = ctx.fs.lstat(ctx.locations.worker_deployment_package_path())
                if stat is not None:
                    ctx.fs.remove_file(ctx.locations.worker_deployment_package_path())
                if ctx.fs.lstat(ctx.locations.worker_deployment_package_path()) is not None:
                    residual.append("deployment_package")
            except FilesystemError:
                residual.append("deployment_package")
        for identity in receipt.installed_configs:
            if not _remove_created_file(
                ctx, ctx.locations.worker_compose_path(), identity, unit=False
            ):
                residual.append("ordinary_config")
        for digest in receipt.loaded_images:
            if not _remove_image(ctx, digest):
                residual.append("worker_image")
        return CompensationResult(proven=not residual, residual=tuple(residual))


# --------------------------------------------------------------------------- rollback adapter


class RealManagementRollbackAdapter:
    """Removes exactly one bootstrap-created management document identified by its topology-safe
    binding, mapping the binding to its OWN fixed layout path and removing it through the hardened
    filesystem after proving the on-disk object.  Exposes NO generic delete-any-path verb."""

    def __init__(self, fs: FilesystemBackend, locations: ManagementLocations) -> None:
        from secp_management.evidence import path_binding_digest

        self._fs = fs
        self._map: dict[str, str] = {}
        for role in ("controller", "worker"):
            for path in (
                locations.identity_path(role),
                locations.release_record_path(role),
                locations.release_sig_path(role),
                locations.evidence_path(role),
                locations.evidence_attestation_path(role),
            ):
                locations.assert_writable(path)  # every mapped path is a fixed owned document
                self._map[path_binding_digest(role, path)] = path

    def remove_object(self, *, binding: str, kind: str) -> None:
        path = self._map.get(binding)
        if path is None:
            raise ManagementError("rollback_unknown_binding")
        try:
            if self._fs.lstat(path) is not None:
                self._fs.remove_file(path)
        except FilesystemError:
            raise ManagementError("rollback_remove_failed") from None


# --------------------------------------------------------------------------- evidence authenticator


class LocalManagementEvidenceAuthenticator:
    """Attests the exact engine-derived evidence-attestation message with the reviewed management
    Ed25519 signing key.  It signs ONLY the message the engine hands it, never arbitrary bytes
    chosen by a caller.  Production commits no private key; ``production.py`` loads a root-owned key
    out of band, tests inject an ephemeral key.  The key material never leaves this object."""

    def __init__(self, private_key_hex: str, public_key_hex: str) -> None:
        if len(bytes.fromhex(public_key_hex)) != 32 or len(bytes.fromhex(private_key_hex)) != 32:
            raise ManagementError("evidence_key_material_invalid")
        # prove the private key derives the claimed public key (no mismatched pair)
        if sign_and_public(private_key_hex) != public_key_hex:
            raise ManagementError("evidence_key_material_invalid")
        self._private_hex = private_key_hex
        self._public_hex = public_key_hex
        self._key_id = "sha256:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()

    def __repr__(self) -> str:  # never expose key material
        return f"LocalManagementEvidenceAuthenticator(key_id={self._key_id})"

    def key_id(self) -> str:
        return self._key_id

    def public_key_hex(self) -> str:
        return self._public_hex

    def attest(self, message: bytes) -> str:
        if not isinstance(message, (bytes, bytearray)) or not message:
            raise ManagementError("evidence_attestation_message_invalid")
        signature = sign_ed25519(self._private_hex, bytes(message))
        if not verify_ed25519(self._public_hex, bytes(message), signature):
            raise ManagementError("evidence_attestation_failed")
        return signature


def sign_and_public(private_key_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


__all__ = [
    "PinnedExecutables",
    "RealAdapterContext",
    "RealControllerBootstrapAdapter",
    "RealWorkerBootstrapAdapter",
    "RealManagementRollbackAdapter",
    "LocalManagementEvidenceAuthenticator",
]
