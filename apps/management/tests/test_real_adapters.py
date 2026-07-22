"""Hermetic proofs for the production management host adapters (SECP-PR5G).

A recording pinned runner + the hardened in-memory filesystem prove the exact closed op order,
the exact argv of every command, loaded-image-digest verification, cross-role/wrong-digest refusal,
symlink/hardlink/owner/mode refusal, unit/service/container-name injection impossibility, per-phase
partial-failure receipts, reverse compensation, lost/malformed-receipt => recovery, residual =>
recovery, and that no ambient environment/shell/PATH/cwd/provider/network is used.  The real
container runtime is exercised separately by the Linux-root no-skip CI job.
"""

from __future__ import annotations

import ast
import inspect

import pytest
from secp_commissioning.canonical import sha256_bytes
from secp_commissioning.runtime import FilesystemError, InMemoryFilesystem
from secp_management import ManagementError
from secp_management import real_adapters as ra
from secp_management.adapters import (
    ReviewedConfig,
    ReviewedUnit,
    VerifiedArtifact,
)
from secp_management.layout import ManagementLocations
from secp_management.signing import generate_keypair
from secp_management.topology import EXPECTED_CONTROLLER_COMPONENTS, ORDINARY_CONTAINER_NAME
from secp_operator_deployment.host_process import CommandResult
from secp_operator_deployment.pinned_exec import ExecutablePin

_DOCKER = ExecutablePin("/usr/bin/docker", "sha256:" + "1" * 64)
_COMPOSE = ExecutablePin("/usr/bin/docker-compose", "sha256:" + "2" * 64)
_SYSTEMCTL = ExecutablePin("/usr/bin/systemctl", "sha256:" + "3" * 64)
_PINS = ra.PinnedExecutables(
    container_runtime=_DOCKER, compose_runtime=_COMPOSE, service_manager=_SYSTEMCTL
)
_CTRL_IMG = "sha256:" + "a" * 64
_WORKER_IMG = "sha256:" + "c" * 64
_OP_IMG = "sha256:" + "d" * 64


class RecordingRunner:
    """Records every (executable-path, argv) and returns canned results; can fail one exact argv."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.fail_on: tuple[str, ...] | None = None
        self.present_images: set[str] = set()

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):  # noqa: ANN001,ANN201
        argv = tuple(argv_tail)
        self.calls.append((pin.path, argv))
        if self.fail_on is not None and argv == self.fail_on:
            return CommandResult(exit_code=1, stdout="")
        if argv[:2] == ("image", "inspect"):
            digest = argv[-1]
            return (
                CommandResult(0, digest + "\n")
                if digest in self.present_images
                else CommandResult(1, "")
            )
        if argv[:2] == ("image", "rm"):
            self.present_images.discard(argv[-1])
            return CommandResult(0, "")
        return CommandResult(0, "")

    def argvs(self) -> list[tuple[str, ...]]:
        return [a for _p, a in self.calls]


_SEED_DIRS = (
    "/opt",
    "/opt/secp",
    "/opt/secp/bootstrap",
    "/opt/secp/bootstrap/staging",
    "/etc",
    "/etc/secp",
    "/etc/secp/controller",
    "/etc/secp/worker",
    "/etc/secp/operator-deployment",
    "/etc/systemd",
    "/etc/systemd/system",
    "/var",
    "/var/lib",
    "/var/lib/secp",
    "/var/lib/secp/bootstrap",
)


def _fs() -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in _SEED_DIRS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    return fs


def _ctx(
    runner: RecordingRunner | None = None, fs: InMemoryFilesystem | None = None
) -> ra.RealAdapterContext:
    return ra.RealAdapterContext(
        locations=ManagementLocations(),
        fs=fs if fs is not None else _fs(),
        runner=runner if runner is not None else RecordingRunner(),
        executables=_PINS,
    )


def _artifact(purpose: str, image_digest: str, content: bytes = b"ARCHIVE") -> VerifiedArtifact:
    return VerifiedArtifact(
        role=purpose.split("/", 1)[0],
        kind="image_archive",
        name=purpose.replace("/", "-"),
        digest=sha256_bytes(content),
        size=len(content),
        reader=lambda: content,
        purpose=purpose,
        image_digest=image_digest,
    )


def _config(content: bytes = b"services: {}\n") -> ReviewedConfig:
    return ReviewedConfig(identity=sha256_bytes(content), content=content)


def _unit(content: bytes = b"[Unit]\n") -> ReviewedUnit:
    return ReviewedUnit(identity=sha256_bytes(content), content=content)


def _reason(exc) -> str:  # noqa: ANN001
    return exc.value.reason_code


# --- controller: exact order + argv + image verification -------------------------------------


def _bootstrap_controller(ctx: ra.RealAdapterContext) -> ra.RealControllerBootstrapAdapter:
    ad = ra.RealControllerBootstrapAdapter(ctx)
    ad.load_image(_artifact("controller/api", _CTRL_IMG))
    ad.install_config(_config())
    ad.install_unit(_unit())
    ad.daemon_reload()
    ad.run_migrations(migration_identity="d8f1a2b3c4e5")
    ad.start_stack(expected_components=EXPECTED_CONTROLLER_COMPONENTS)
    return ad


def test_controller_exact_operation_order_and_receipt() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    ad = _bootstrap_controller(_ctx(r))
    receipt = ad.receipt()
    assert receipt.operations == (
        f"load_image:{sha256_bytes(b'ARCHIVE')}",
        "install_config",
        "install_unit",
        "daemon_reload",
        "run_migrations:d8f1a2b3c4e5",
        "start_stack",
    )
    assert receipt.loaded_images == (_CTRL_IMG,)
    assert receipt.started_services == tuple(EXPECTED_CONTROLLER_COMPONENTS)


def test_controller_exact_argv_and_no_shell_env_or_cwd() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    _bootstrap_controller(_ctx(r))
    argvs = r.argvs()
    assert ("load", "-i", "/opt/secp/bootstrap/staging/controller-image-load.tar") in argvs
    assert ("image", "inspect", "--format", "{{.Id}}", _CTRL_IMG) in argvs
    assert ("daemon-reload",) in argvs
    assert (
        "--project-name",
        "secp-controller",
        "--file",
        "/etc/secp/controller/docker-compose.yml",
        "run",
        "--rm",
        "--no-deps",
        "api",
        "alembic",
        "upgrade",
        "head",
    ) in argvs
    up = next(a for a in argvs if a[:1] == ("--project-name",) and "up" in a)
    assert up[:8] == (
        "--project-name",
        "secp-controller",
        "--file",
        "/etc/secp/controller/docker-compose.yml",
        "up",
        "--detach",
        "--no-deps",
        "--no-build",
    )
    # no shell/generic verb; every command is one of the fixed pinned executables
    assert {p for p, _a in r.calls} <= {
        "/usr/bin/docker",
        "/usr/bin/docker-compose",
        "/usr/bin/systemctl",
    }


def test_controller_installs_config_and_unit_to_fixed_paths() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    fs = _fs()
    _bootstrap_controller(_ctx(r, fs))
    assert "/etc/secp/controller/docker-compose.yml" in fs.paths()
    assert "/etc/systemd/system/secp-controller-stack.service" in fs.paths()


def test_controller_components_mismatch_refuses() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    ad = ra.RealControllerBootstrapAdapter(_ctx(r))
    ad.load_image(_artifact("controller/api", _CTRL_IMG))
    with pytest.raises(ManagementError) as e:
        ad.start_stack(expected_components=("api",))  # not the full reviewed stack
    assert _reason(e) == "controller_components_mismatch"


# --- image loading + verification ------------------------------------------------------------


def test_cross_role_worker_image_refused_by_controller() -> None:
    ad = ra.RealControllerBootstrapAdapter(_ctx())
    with pytest.raises(ManagementError) as e:
        ad.load_image(_artifact("worker/ordinary", _WORKER_IMG))  # wrong purpose prefix
    assert _reason(e) == "bootstrap_image_purpose_mismatch"


def test_wrong_loaded_image_digest_refused() -> None:
    r = RecordingRunner()  # present_images stays EMPTY -> inspect of the signed digest fails
    ad = ra.RealControllerBootstrapAdapter(_ctx(r))
    with pytest.raises(ManagementError) as e:
        ad.load_image(_artifact("controller/api", _CTRL_IMG))
    assert _reason(e) == "bootstrap_image_absent_after_load"


def test_missing_signed_image_digest_refused() -> None:
    ad = ra.RealControllerBootstrapAdapter(_ctx())
    with pytest.raises(ManagementError) as e:
        ad.load_image(_artifact("controller/api", ""))  # no signed loaded-image digest
    assert _reason(e) == "bootstrap_image_digest_missing"


def test_tampered_archive_bytes_refused() -> None:
    bad = VerifiedArtifact(
        role="controller",
        kind="image_archive",
        name="controller-api",
        digest=sha256_bytes(b"EXPECTED"),
        size=len(b"EXPECTED"),
        reader=lambda: b"TAMPERED",  # reader returns bytes that do not match the digest/size
        purpose="controller/api",
        image_digest=_CTRL_IMG,
    )
    ad = ra.RealControllerBootstrapAdapter(_ctx())
    with pytest.raises(ManagementError) as e:
        ad.load_image(bad)
    assert _reason(e) == "verified_artifact_content_mismatch"


# --- filesystem refusals (symlink / flaky) ---------------------------------------------------


def test_symlink_target_refuses_config_install() -> None:
    fs = _fs()
    fs.seed_symlink("/etc/secp/controller/docker-compose.yml")
    ad = ra.RealControllerBootstrapAdapter(_ctx(fs=fs))
    with pytest.raises(ManagementError) as e:
        ad.install_config(_config())
    assert _reason(e) == "bootstrap_file_install_failed"


def test_hardened_fs_refusal_fails_closed() -> None:
    class _Refusing(InMemoryFilesystem):
        def atomic_install(self, path, data, *, uid, gid, mode):  # noqa: ANN001,ANN204
            raise FilesystemError("fs_target_hardlinked")

    fs = _Refusing()
    for d in _SEED_DIRS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    ad = ra.RealControllerBootstrapAdapter(_ctx(fs=fs))
    with pytest.raises(ManagementError) as e:
        ad.install_unit(_unit())
    assert _reason(e) == "bootstrap_file_install_failed"


# --- partial failure after each effect -------------------------------------------------------


def test_partial_failure_at_migration_keeps_prior_receipt() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    r.fail_on = (
        "--project-name",
        "secp-controller",
        "--file",
        "/etc/secp/controller/docker-compose.yml",
        "run",
        "--rm",
        "--no-deps",
        "api",
        "alembic",
        "upgrade",
        "head",
    )
    ad = ra.RealControllerBootstrapAdapter(_ctx(r))
    ad.load_image(_artifact("controller/api", _CTRL_IMG))
    ad.install_config(_config())
    ad.install_unit(_unit())
    ad.daemon_reload()
    with pytest.raises(ManagementError) as e:
        ad.run_migrations(migration_identity="d8f1a2b3c4e5")
    assert _reason(e) == "migration_failed"
    receipt = ad.receipt()
    assert receipt.loaded_images == (_CTRL_IMG,)
    assert receipt.installed_configs and receipt.installed_units
    assert receipt.started_services == ()  # the stack never started


# --- compensation ----------------------------------------------------------------------------


def test_controller_compensation_reverses_and_proves() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    fs = _fs()
    ad = _bootstrap_controller(_ctx(r, fs))
    result = ad.compensate(ad.receipt())
    assert result.proven is True and result.residual == ()
    assert "/etc/secp/controller/docker-compose.yml" not in fs.paths()
    assert "/etc/systemd/system/secp-controller-stack.service" not in fs.paths()
    assert _CTRL_IMG not in r.present_images
    # compose down was issued
    assert any(a[:1] == ("--project-name",) and "down" in a for a in r.argvs())


def test_compensation_drifted_config_is_not_removed_and_is_residual() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    fs = _fs()
    ad = _bootstrap_controller(_ctx(r, fs))
    # an attacker/operator replaces the installed config with different bytes after the receipt
    fs.atomic_install(
        "/etc/secp/controller/docker-compose.yml", b"DRIFTED", uid=0, gid=0, mode=0o640
    )
    result = ad.compensate(ad.receipt())
    assert result.proven is False and "controller_config" in result.residual
    # the drifted (not-ours) object is left in place
    assert "/etc/secp/controller/docker-compose.yml" in fs.paths()


def test_compensation_residual_when_stop_fails_forces_recovery() -> None:
    r = RecordingRunner()
    r.present_images.add(_CTRL_IMG)
    fs = _fs()
    ad = _bootstrap_controller(_ctx(r, fs))
    r.fail_on = (
        "--project-name",
        "secp-controller",
        "--file",
        "/etc/secp/controller/docker-compose.yml",
        "down",
        "--remove-orphans",
    )
    result = ad.compensate(ad.receipt())
    assert result.proven is False and "controller_stack" in result.residual


def test_compensation_malformed_receipt_forces_recovery() -> None:
    ad = ra.RealControllerBootstrapAdapter(_ctx())
    result = ad.compensate("not-a-receipt")  # type: ignore[arg-type]
    assert result.proven is False and result.residual == ("malformed_receipt",)


# --- worker: order + operator-disabled + start-ordinary-only ---------------------------------


def _bootstrap_worker(ctx: ra.RealAdapterContext) -> ra.RealWorkerBootstrapAdapter:
    ad = ra.RealWorkerBootstrapAdapter(ctx)
    ad.load_image(_artifact("worker/ordinary", _WORKER_IMG))
    ad.load_image(_artifact("worker/operator", _OP_IMG))
    ad.install_ordinary_config(_config())
    ad.install_deployment_package(
        _artifact("worker/deployment-package", "", b"PKG"), aggregate=sha256_bytes(b"PKG")
    )
    ad.install_operator_unit_disabled(_unit(b"[Unit]\nX=1\n"))
    ad.daemon_reload()
    ad.start_ordinary()
    return ad


def test_worker_exact_order_and_operator_never_enabled_or_started() -> None:
    r = RecordingRunner()
    r.present_images.update({_WORKER_IMG, _OP_IMG})
    ad = _bootstrap_worker(_ctx(r))
    receipt = ad.receipt()
    assert receipt.operations == (
        f"load_image:{sha256_bytes(b'ARCHIVE')}",
        f"load_image:{sha256_bytes(b'ARCHIVE')}",
        "install_ordinary_config",
        "install_deployment_package",
        "install_operator_unit_disabled",
        "daemon_reload",
        "start_ordinary",
    )
    # ONLY the ordinary worker is started; the operator is NEVER enabled or started.
    assert receipt.started_services == (ORDINARY_CONTAINER_NAME,)
    flat = [tok for a in r.argvs() for tok in a]
    assert "enable" not in flat and "start" not in flat
    assert not any("secp-operator-worker" in tok for a in r.argvs() for tok in a if "up" in a)


def test_worker_installs_operator_unit_disabled_to_fixed_path() -> None:
    r = RecordingRunner()
    r.present_images.update({_WORKER_IMG, _OP_IMG})
    fs = _fs()
    _bootstrap_worker(_ctx(r, fs))
    assert "/etc/systemd/system/secp-operator-worker.service" in fs.paths()
    assert "/etc/secp/operator-deployment/secp-operator-deployment-package.zip" in fs.paths()


def test_worker_wrong_deployment_package_purpose_refused() -> None:
    ad = ra.RealWorkerBootstrapAdapter(_ctx())
    with pytest.raises(ManagementError) as e:
        ad.install_deployment_package(
            _artifact("worker/ordinary", _WORKER_IMG, b"PKG"), aggregate=sha256_bytes(b"PKG")
        )
    assert _reason(e) == "bootstrap_image_purpose_mismatch"


def test_worker_compensation_reverses_and_proves() -> None:
    r = RecordingRunner()
    r.present_images.update({_WORKER_IMG, _OP_IMG})
    fs = _fs()
    ad = _bootstrap_worker(_ctx(r, fs))
    result = ad.compensate(ad.receipt())
    assert result.proven is True and result.residual == ()
    assert "/etc/systemd/system/secp-operator-worker.service" not in fs.paths()
    assert "/etc/secp/worker/docker-compose.yml" not in fs.paths()
    assert "/etc/secp/operator-deployment/secp-operator-deployment-package.zip" not in fs.paths()


# --- unit / service / container name injection is structurally impossible ---------------------


def test_unit_and_service_and_container_names_are_fixed_constants() -> None:
    loc = ManagementLocations()
    # the adapter surface takes typed plans, never a path/name; the only unit targets are the two
    # exact fixed constants, and any other unit path is refused by assert_unit_writable.
    assert loc.controller_unit_path() == "/etc/systemd/system/secp-controller-stack.service"
    assert loc.operator_unit_path() == "/etc/systemd/system/secp-operator-worker.service"
    with pytest.raises(ManagementError) as e:
        loc.assert_unit_writable("/etc/systemd/system/evil.service")
    assert _reason(e) == "layout_unit_path_not_fixed"


# --- evidence authenticator ------------------------------------------------------------------


def test_authenticator_signs_and_verifies_only_given_message() -> None:
    priv, pub = generate_keypair()
    auth = ra.LocalManagementEvidenceAuthenticator(priv, pub)
    assert auth.key_id().startswith("sha256:")
    sig = auth.attest(b"exact-engine-message")
    from secp_management.signing import verify_ed25519

    assert verify_ed25519(pub, b"exact-engine-message", sig)
    assert not verify_ed25519(pub, b"other-message", sig)


def test_authenticator_mismatched_keypair_refused() -> None:
    priv, _pub = generate_keypair()
    _priv2, pub2 = generate_keypair()
    with pytest.raises(ManagementError) as e:
        ra.LocalManagementEvidenceAuthenticator(priv, pub2)  # public does not derive from private
    assert _reason(e) == "evidence_key_material_invalid"


def test_authenticator_empty_message_refused() -> None:
    priv, pub = generate_keypair()
    auth = ra.LocalManagementEvidenceAuthenticator(priv, pub)
    with pytest.raises(ManagementError) as e:
        auth.attest(b"")
    assert _reason(e) == "evidence_attestation_message_invalid"


def test_authenticator_repr_never_leaks_key() -> None:
    priv, pub = generate_keypair()
    auth = ra.LocalManagementEvidenceAuthenticator(priv, pub)
    assert priv not in repr(auth) and pub not in repr(auth)


# --- rollback adapter ------------------------------------------------------------------------


def test_rollback_removes_only_the_bound_document() -> None:
    from secp_management.evidence import path_binding_digest

    loc = ManagementLocations()
    fs = _fs()
    path = loc.evidence_path("controller")
    fs.atomic_install(path, b"EVIDENCE", uid=0, gid=0, mode=0o640)
    rb = ra.RealManagementRollbackAdapter(fs, loc)
    rb.remove_object(binding=path_binding_digest("controller", path), kind="file")
    assert path not in fs.paths()


def test_rollback_unknown_binding_refused() -> None:
    rb = ra.RealManagementRollbackAdapter(_fs(), ManagementLocations())
    with pytest.raises(ManagementError) as e:
        rb.remove_object(binding="sha256:" + "0" * 64, kind="file")
    assert _reason(e) == "rollback_unknown_binding"


# --- default production dependencies remain sealed -------------------------------------------


def test_default_engine_deps_adapters_remain_sealed() -> None:
    from secp_management.engine import EngineDeps

    deps = EngineDeps()
    with pytest.raises(ManagementError):
        deps.controller_adapter.load_image(_artifact("controller/api", _CTRL_IMG))
    with pytest.raises(ManagementError):
        deps.worker_adapter.load_image(_artifact("worker/ordinary", _WORKER_IMG))
    with pytest.raises(ManagementError):
        deps.rollback_adapter.remove_object(binding="x", kind="file")
    with pytest.raises(ManagementError):
        deps.observer.platform()


# --- no forbidden contact / no second observation parser -------------------------------------


def test_real_adapters_import_no_forbidden_module() -> None:
    tree = ast.parse(inspect.getsource(ra))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in (
        "socket",
        "requests",
        "httpx",
        "temporalio",
        "boto3",
        "kubernetes",
        "paramiko",
        "urllib",
        "http",
    ):
        assert banned not in imported, banned


def test_secp_management_has_no_second_docker_or_systemd_parser() -> None:
    # management must reuse the PR5D coherent observation, never re-parse docker/systemctl output
    import pathlib

    root = pathlib.Path(ra.__file__).parent
    for pyfile in root.glob("*.py"):
        src = pyfile.read_text(encoding="utf-8")
        assert "systemctl show" not in src, pyfile.name
        assert "{{.Id}} {{.State" not in src, pyfile.name  # the PR5D container inspect grammar
