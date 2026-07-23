"""Linux-root END-TO-END execution of the REAL controller bootstrap adapter + observer against a
REAL Docker/Compose stack and a REAL Alembic migration (SECP-PR5G, Commit 4b).

Follows the green Commit 4a worker-mechanics job.  It drives the ACTUAL
``RealControllerBootstrapAdapter`` (install_config, install_unit, daemon_reload, run_migrations,
start_stack, compensate) + ``RealManagementHostObserver.observe_controller`` through the pinned
``RealCommandRunner`` + hardened ``RealFilesystem`` against a real controller compose stack, and
proves ``observe_controller`` coherent over the EXACT 8 controller components with a REAL migration
head.

Fidelity (per the reviewed 4b scope decision): ``postgres`` + ``api`` are the REAL images and
REAL ``alembic upgrade head`` against a real database; the six non-migration components (minio,
keycloak, temporal, temporal-ui, worker, web) run as lightweight real stand-in containers.
observe_controller's coherence never inspects those six beyond exact container name, non-privileged,
and before/after generation stability, and never compares their images to an expected map — so the
stand-ins are a faithful proof of the observer's 8-component coherence algorithm + the real
adapter + the real migration.  (Full engine signed-bundle adoption — all-8 running+healthy + exact
signed image-map equality — is a later gate.)

The load-bearing detail: each compose service pins ``container_name: secp-controller-<component>``
``docker inspect {{.Name}}`` yields exactly the names ``_component_of`` expects (compose's default
``<project>-<service>-1`` naming would break exact-component-key equality).

Requires POSIX + effective root + real docker + a STANDALONE docker-compose (global flags before the
subcommand, matching the adapter argv) + systemctl; SKIPS otherwise.  The CI job runs it under sudo
and FAILS CLOSED on any skip.  Scaffolding uses plain subprocess; every PROOF goes through the
adapter/observer path.  No operator is enabled/started, no workflow is submitted, no provider or
OpenTofu is contacted.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time

import pytest

_HAVE_DOCKER = shutil.which("docker") is not None
_HAVE_COMPOSE = shutil.which("docker-compose") is not None
_HAVE_SYSTEMCTL = shutil.which("systemctl") is not None
_IS_ROOT = os.name == "posix" and getattr(os, "geteuid", lambda: 1)() == 0

pytestmark = pytest.mark.skipif(
    not (_IS_ROOT and _HAVE_DOCKER and _HAVE_COMPOSE and _HAVE_SYSTEMCTL),
    reason="controller real-adapter E2E requires POSIX root + docker + docker-compose + systemctl",
)

_PROJECT = "secp-controller"  # must equal RealAdapterContext.controller_project
_API_IMAGE = "secp/api:ci"  # built from infra/dev/Dockerfile.python by the CI job
_STANDIN = "busybox:latest"  # lightweight real container for the 6 non-migration components
_DB_URL = "postgresql+psycopg://secp:secp@postgres:5432/secp"

# The controller compose the adapter installs verbatim to controller_compose_path.  Each service
# pins container_name to secp-controller-<component> (the single change that makes the stack
# observable), no service is privileged, postgres+api are real, the six others are stand-ins.
_CONTROLLER_COMPOSE = f"""services:
  postgres:
    image: postgres:16-alpine
    container_name: secp-controller-postgres
    environment:
      POSTGRES_USER: secp
      POSTGRES_PASSWORD: secp
      POSTGRES_DB: secp
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U secp -d secp"]
      interval: 3s
      timeout: 3s
      retries: 30
  api:
    image: {_API_IMAGE}
    container_name: secp-controller-api
    working_dir: /app/apps/api
    environment:
      SECP_APP_ENV: test
      SECP_DATABASE_URL: {_DB_URL}
    command: ["sleep", "infinity"]
  minio:
    image: {_STANDIN}
    container_name: secp-controller-minio
    command: ["sleep", "infinity"]
  keycloak:
    image: {_STANDIN}
    container_name: secp-controller-keycloak
    command: ["sleep", "infinity"]
  temporal:
    image: {_STANDIN}
    container_name: secp-controller-temporal
    command: ["sleep", "infinity"]
  temporal-ui:
    image: {_STANDIN}
    container_name: secp-controller-temporal-ui
    command: ["sleep", "infinity"]
  worker:
    image: {_STANDIN}
    container_name: secp-controller-worker
    command: ["sleep", "infinity"]
  web:
    image: {_STANDIN}
    container_name: secp-controller-web
    command: ["sleep", "infinity"]
""".encode()

_CONTROLLER_UNIT = b"""[Unit]
Description=SECP controller stack wrapper (management-installed, inert)

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
"""


def _sh(*argv: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, check=check, capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL
    )


def _pin(name: str):  # noqa: ANN202
    import hashlib

    from secp_operator_deployment.pinned_exec import ExecutablePin

    real = os.path.realpath(shutil.which(name))  # type: ignore[arg-type]
    with open(real, "rb") as fh:
        digest = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
    return ExecutablePin(real, digest)


def _reviewed(content: bytes, unit: bool):  # noqa: ANN202
    from secp_commissioning.canonical import sha256_bytes
    from secp_management.adapters import ReviewedConfig, ReviewedUnit

    identity = sha256_bytes(content)
    return (ReviewedUnit if unit else ReviewedConfig)(identity=identity, content=content)


def _dc(ctx, *args: str, check: bool = True) -> subprocess.CompletedProcess:  # noqa: ANN001
    """Scaffolding compose invocation (pre-start postgres / settle / teardown) using the same
    standalone binary + project + file the pinned adapter uses."""
    compose = os.path.realpath(shutil.which("docker-compose"))  # type: ignore[arg-type]
    return _sh(
        compose,
        "--project-name",
        _PROJECT,
        "--file",
        ctx.locations.controller_compose_path(),
        *args,
        check=check,
    )


def _inspect(container: str, fmt: str) -> str:
    r = _sh("docker", "inspect", "--format", fmt, container, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


@pytest.fixture(scope="module")
def controller_stack():  # noqa: ANN201
    """Bootstrap the real controller stack ONCE through the real adapter, yield the driven objects,
    and tear everything down.  Any bootstrap failure errors every dependent test (fail-closed)."""
    from secp_commissioning.runtime import RealFilesystem
    from secp_management.layout import ManagementLocations
    from secp_management.real_adapters import (
        PinnedExecutables,
        RealAdapterContext,
        RealControllerBootstrapAdapter,
        RealManagementHostObserver,
    )
    from secp_management.topology import EXPECTED_CONTROLLER_COMPONENTS
    from secp_operator_deployment.host_process import RealCommandRunner

    parent = os.environ.get("SECP_ROOT_TEST_DIR", "/root/secp-mgmt-real")
    base = tempfile.mkdtemp(prefix="secp-ctrl-real-", dir=parent)
    os.chown(base, 0, 0)
    os.chmod(base, 0o755)

    def _sub(name: str) -> str:
        p = os.path.join(base, name)
        os.makedirs(p, exist_ok=True)
        os.chown(p, 0, 0)
        os.chmod(p, 0o755)
        return p

    locations = ManagementLocations(
        controller_root=_sub("controller"),
        worker_root=_sub("worker"),
        bootstrap_root=_sub("bootstrap"),
        bootstrap_state=_sub("state"),
        controller_config=_sub("etc-controller"),
        worker_config=_sub("etc-worker"),
        operator_deployment_config=_sub("etc-operator-deployment"),
    )
    unit_path = locations.controller_unit_path()
    assert not os.path.exists(unit_path), f"pre-existing {unit_path}; refusing to clobber"

    docker_pin = _pin("docker")
    executables = PinnedExecutables(
        container_runtime=docker_pin,
        compose_runtime=_pin("docker-compose"),
        service_manager=_pin("systemctl"),
    )
    ctx = RealAdapterContext(
        locations=locations,
        fs=RealFilesystem(),
        runner=RealCommandRunner(),
        executables=executables,
    )
    adapter = RealControllerBootstrapAdapter(ctx)
    observer = RealManagementHostObserver(ctx)
    expected = tuple(EXPECTED_CONTROLLER_COMPONENTS)
    result: dict = {}
    try:
        # 1) install the real compose + a benign controller unit through the REAL adapter
        adapter.install_config(_reviewed(_CONTROLLER_COMPOSE, unit=False))
        adapter.install_unit(_reviewed(_CONTROLLER_UNIT, unit=True))
        adapter.daemon_reload()
        # 2) pre-start postgres (run_migrations is --no-deps and will not start the DB) and wait
        _dc(ctx, "up", "--detach", "--no-build", "--pull", "never", "postgres")
        _wait_pg(ctx)
        # 3) the REAL migration through the adapter: run --rm --no-deps api alembic upgrade head
        adapter.run_migrations(migration_identity="controller")
        # 4) start the full 8-component stack through the adapter
        adapter.start_stack(expected_components=expected)
        _wait_running(expected)
        head = _alembic_head()
        result = {
            "ctx": ctx,
            "adapter": adapter,
            "observer": observer,
            "receipt": adapter.receipt(),
            "expected": expected,
            "head": head,
        }
        yield result
    finally:
        _dc(ctx, "down", "--remove-orphans", "--volumes", "--timeout", "10", check=False)
        for comp in expected:
            _sh("docker", "rm", "-f", f"secp-controller-{comp}", check=False)
        if os.path.exists(unit_path):
            os.remove(unit_path)
            _sh("systemctl", "daemon-reload", check=False)
        shutil.rmtree(base, ignore_errors=True)


def _wait_pg(ctx, timeout: float = 90.0) -> None:  # noqa: ANN001
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        health = _inspect("secp-controller-postgres", "{{.State.Health.Status}}")
        if health == "healthy":
            return
        r = _sh(
            "docker",
            "exec",
            "secp-controller-postgres",
            "pg_isready",
            "-U",
            "secp",
            "-d",
            "secp",
            check=False,
        )
        if r.returncode == 0:
            return
        time.sleep(2)
    raise AssertionError("postgres did not become ready")


def _wait_running(expected: tuple[str, ...], timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(_inspect(f"secp-controller-{c}", "{{.State.Running}}") == "true" for c in expected):
            time.sleep(2)  # brief settle so observe_controller's before==after is not raced
            return
        time.sleep(2)
    missing = [
        c for c in expected if _inspect(f"secp-controller-{c}", "{{.State.Running}}") != "true"
    ]
    raise AssertionError(f"controller components not running: {missing}")


def _alembic_head() -> str:
    """The migration head id, derived from the running api container (not hardcoded)."""
    out = _sh("docker", "exec", "secp-controller-api", "alembic", "heads", check=False).stdout
    m = re.search(r"\b([0-9a-f]{12})\b", out)
    assert m, f"could not derive alembic head from: {out!r}"
    return m.group(1)


# --- proofs (share the one expensive bootstrap; read-only, definition order) ------------------


def test_observe_controller_coherent(controller_stack) -> None:
    obs = controller_stack["observer"].observe_controller()
    assert obs.coherent is True
    assert obs.unknown_privileged == ()


def test_observe_controller_exact_eight_components(controller_stack) -> None:
    obs = controller_stack["observer"].observe_controller()
    assert set(obs.container_image_digests) == set(controller_stack["expected"])
    assert all(d.startswith("sha256:") for d in obs.container_image_digests.values())


def test_real_migration_reached_head(controller_stack) -> None:
    obs = controller_stack["observer"].observe_controller()
    head = controller_stack["head"]
    assert re.fullmatch(r"[0-9a-f]{12}", head)
    assert obs.migration_identity == head  # the observed head == the real alembic head
    current = _sh("docker", "exec", "secp-controller-api", "alembic", "current", check=False).stdout
    assert "(head)" in current  # the DB is genuinely at head, not merely stamped


def test_generation_marker_opaque_and_stable(controller_stack) -> None:
    observer = controller_stack["observer"]
    obs = observer.observe_controller()
    assert obs.generation_marker.startswith("sha256:") and len(obs.generation_marker) == 71
    for cid in obs.container_ids.values():
        assert cid not in obs.generation_marker  # raw ids hashed, never embedded
    # re-observation of the same stable generation yields the same opaque marker
    assert observer.observe_controller().generation_marker == obs.generation_marker


def test_controller_components_mismatch_refused(controller_stack) -> None:
    from secp_management import ManagementError
    from secp_management.real_adapters import RealControllerBootstrapAdapter

    adapter = RealControllerBootstrapAdapter(controller_stack["ctx"])
    with pytest.raises(ManagementError):  # a wrong expected-set is refused before any host effect
        adapter.start_stack(expected_components=("postgres", "api"))


def test_zzz_compensation_tears_down_zero_residual(controller_stack) -> None:
    ctx = controller_stack["ctx"]
    adapter = controller_stack["adapter"]
    result = adapter.compensate(controller_stack["receipt"])
    assert result.proven is True and result.residual == ()
    for comp in controller_stack["expected"]:
        assert _inspect(f"secp-controller-{comp}", "{{.Id}}") == ""  # all containers gone
    assert not os.path.exists(ctx.locations.controller_compose_path())  # config removed
    assert not os.path.exists(ctx.locations.controller_unit_path())  # unit removed
