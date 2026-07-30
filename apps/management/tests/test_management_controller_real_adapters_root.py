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

import json
import os
import re
import shutil
import subprocess
import tempfile
import time

import pytest
import yaml

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

# SECP-PR5H-B2 2b-3c-c: the ordinary API's two reviewed read-only binds. These are the SAME
# plane-neutral constants the strict signed-Compose validator, the API's gate primitive and the
# management transport use -- if this document drifts from them, `install_config` refuses it.
from secp_commissioning.enrollment_signer_binding_digest import (  # noqa: E402
    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH as _GATE_TARGET,
)
from secp_commissioning.enrollment_signer_binding_digest import (  # noqa: E402
    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH as _GATE_HOST_DEFAULT,
)
from secp_commissioning.enrollment_signer_marker import (  # noqa: E402
    ENROLLMENT_SIGNER_MARKER_PATH as _MARKER_HOST_DEFAULT,
)
from secp_management.controller_compose_validation import (  # noqa: E402
    controller_compose_contract_reason,
)
from secp_management.topology import API_RUNTIME_GID  # noqa: E402

# The fixture relocates the controller config root under a root-only temp base, so the reviewed
# SOURCES are the relocated ones; the container TARGET is fixed and never relocated.
_GATE_HOST = _GATE_HOST_DEFAULT
_MARKER_HOST = _MARKER_HOST_DEFAULT

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
    volumes:
      - type: bind
        source: {_MARKER_HOST}
        target: {_MARKER_HOST}
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: {_GATE_HOST}
        target: {_GATE_TARGET}
        read_only: true
        bind:
          create_host_path: false
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


#: the exact readiness-gate body: 256 bits of lowercase hex plus one LF (the on-disk contract).
_GATE_VALUE = "7c" * 32


def _seed_api_mount_sources() -> None:
    """Create the two reviewed mount SOURCES with their exact production posture, as root."""
    for path, body, mode, gid in (
        (_GATE_HOST, (_GATE_VALUE + "\n").encode(), 0o640, API_RUNTIME_GID),
        (_MARKER_HOST, b"{}\n", 0o644, 0),
    ):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)
        os.chown(path, 0, gid)
        os.chmod(path, mode)


def _installed_compose_path(stack: dict) -> str:
    return str(stack["ctx"].locations.controller_compose_path())


def _sha(data: bytes) -> str:
    from secp_commissioning.canonical import sha256_bytes

    return sha256_bytes(data)


def _api_mounts() -> list[dict]:
    """Every mount Docker ACTUALLY resolved for the API container, from the running container."""
    raw = _sh(
        "docker",
        "inspect",
        "--format",
        "{{json .Mounts}}",
        "secp-controller-api",
        check=False,
    )
    return json.loads(raw.stdout) if raw.returncode == 0 and raw.stdout.strip() else []


def _gate_mounts() -> list[dict]:
    return [m for m in _api_mounts() if m.get("Destination") == _GATE_TARGET]


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
        # The gate and marker MUST exist before any Compose operation that mounts them: the
        # contract binds both with create_host_path:false, so Docker refuses to invent them -- and
        # WITHOUT that flag Docker would silently create a DIRECTORY where a secret belongs.
        _seed_api_mount_sources()
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


# ------------------------------------- the signed readiness-gate mount, proven against real Docker


def test_compose_config_resolves_exactly_one_readiness_gate_mount(controller_stack) -> None:
    """`docker compose config` is the runtime's OWN reading of the installed bytes. If it resolves
    anything other than exactly one long-form read-only bind for the gate target, the signed
    artifact and the running container disagree -- which is precisely the gap this closes."""
    ctx = controller_stack["ctx"]
    rendered = yaml.safe_load(_dc(ctx, "config").stdout)
    volumes = rendered["services"]["api"]["volumes"]
    gate = [v for v in volumes if v.get("target") == _GATE_TARGET]
    assert len(gate) == 1, volumes
    entry = gate[0]
    assert entry["type"] == "bind"
    assert entry["source"] == _GATE_HOST
    assert entry["read_only"] is True
    # `compose config` normalizes `bind.create_host_path` away, so assert that directive where it
    # actually lives and is enforceable: the INSTALLED signed bytes, re-read from disk and put
    # through the same strict validator every trust boundary uses. Docker's own guarantee -- that it
    # did not fabricate anything at the source -- is proven by the container seeing a FILE below.
    installed = open(ctx.locations.controller_compose_path(), "rb").read()
    assert controller_compose_contract_reason(installed) is None
    declared = yaml.safe_load(installed)["services"]["api"]["volumes"]
    gate_declared = [v for v in declared if v.get("target") == _GATE_TARGET]
    assert len(gate_declared) == 1
    assert gate_declared[0]["bind"]["create_host_path"] is False


def test_the_running_container_resolved_the_declared_gate_mount(controller_stack) -> None:
    """The mount Docker actually attached is the one the SIGNED artifact declared -- not an alias,
    not a second bind, not a writable one."""
    mounts = _gate_mounts()
    assert len(mounts) == 1, _api_mounts()
    mount = mounts[0]
    assert mount["Type"] == "bind"
    assert os.path.realpath(mount["Source"]) == os.path.realpath(_GATE_HOST)
    assert mount["RW"] is False  # read-only as declared


def test_the_api_container_sees_the_exact_gate_file(controller_stack) -> None:
    seen = _sh("docker", "exec", "secp-controller-api", "cat", _GATE_TARGET, check=False)
    assert seen.returncode == 0, seen.stderr
    assert seen.stdout.strip() == _GATE_VALUE  # byte-identical to the host object
    kind = _sh("docker", "exec", "secp-controller-api", "test", "-f", _GATE_TARGET, check=False)
    assert kind.returncode == 0, "the gate must be a FILE, never a Docker-created directory"


def test_the_api_process_cannot_write_the_gate(controller_stack) -> None:
    """A read-only bind: the ordinary API may prove it holds the gate, never change it."""
    wrote = _sh(
        "docker",
        "exec",
        "secp-controller-api",
        "sh",
        "-c",
        f"echo tampered > {_GATE_TARGET}",
        check=False,
    )
    assert wrote.returncode != 0
    assert _sh("docker", "exec", "secp-controller-api", "cat", _GATE_TARGET).stdout.strip() == (
        _GATE_VALUE
    )


def test_the_marker_mount_is_also_read_only(controller_stack) -> None:
    marker = [m for m in _api_mounts() if m.get("Destination") == _MARKER_HOST]
    assert len(marker) == 1, _api_mounts()
    assert marker[0]["RW"] is False


def test_readiness_is_404_without_the_gate_and_served_with_it(controller_stack) -> None:
    """The end-to-end authorization proof, run INSIDE the API container against the REAL mounted
    gate: an unauthorized call is a byte-identical 404 that never reaches the observation, and only
    a caller presenting the mounted secret gets a different answer."""
    script = (
        "import json;"
        "from fastapi.testclient import TestClient;"
        "from secp_api.main import create_app;"
        "from secp_api.signer_readiness import SIGNER_READINESS_PATH as P;"
        "from secp_commissioning.enrollment_signer_binding_digest import"
        " ENROLLMENT_SIGNER_READINESS_GATE_HEADER as H,"
        " ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH as G;"
        "v=open(G).read().strip();"
        "c=TestClient(create_app());"
        "none=c.get(P); wrong=c.get(P,headers={H:'e'*64});"
        "dup=c.get(P,headers=[(H,v),(H,v)]); good=c.get(P,headers={H:v});"
        "print(json.dumps({'none':none.status_code,'wrong':wrong.status_code,"
        "'dup':dup.status_code,'good':good.status_code,"
        "'same':none.content==wrong.content==dup.content,'secret_in_body':v in none.text}))"
    )
    out = _sh("docker", "exec", "secp-controller-api", "python", "-c", script, check=False)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout.strip().splitlines()[-1])
    assert got["none"] == 404 and got["wrong"] == 404 and got["dup"] == 404
    assert got["same"] is True  # no oracle distinguishes absent / wrong / duplicated
    assert got["secret_in_body"] is False
    assert got["good"] != 404  # the mounted gate authenticates; the surface exists for it alone


# ------------------------------- R8: Compose NORMALIZES aliases; the validator must refuse them


def _alias_template(target: str) -> bytes:
    """The installed valid template plus ONE hostile writable bind aimed at ``target``."""
    installed = _CONTROLLER_COMPOSE.decode()
    hostile = (
        "    volumes:\n"
        "      - type: bind\n"
        "        source: /tmp/secp-evil\n"
        f"        target: {target}\n"
        "        read_only: false\n"
        "        bind:\n"
        "          create_host_path: true\n"
    )
    # append the hostile entry to the api service's existing volume list
    marker = "    volumes:\n"
    head, _sep, tail = installed.partition(marker)
    return (head + marker + hostile[len(marker) :] + tail).encode()


#: the four spellings compose-go collapses onto the reviewed readiness-gate target.
_ALIAS_TARGETS = {
    "parent-segment": "/run/secp/../secp/enrollment-signer-readiness-gate.secret",
    "trailing-slash": _GATE_TARGET + "/",
    "repeated-separator": "/run//secp/enrollment-signer-readiness-gate.secret",
    "dot-segment": "/run/secp/./enrollment-signer-readiness-gate.secret",
}


@pytest.mark.parametrize("name", list(_ALIAS_TARGETS))
def test_the_validator_refuses_the_alias_that_compose_itself_waves_through(
    controller_stack, name
) -> None:
    """Two facts, in the order that matters for security.

    1. The strict OFFLINE validator refuses the alias document, so it can never be signed, never
       reach ``install_config``, and never reach ``compose up``. This is the actual control.
    2. Real Compose RENDERS that same document without complaint -- so Compose is not a gate here at
       all, and relying on a later runtime error would place the check after the mutation.

    Exact-head CI corrected an assumption in an earlier version of this test: ``docker compose
    config`` does NOT apply POSIX ``path.Clean`` at render time, it echoes the alias verbatim. Where
    normalization actually happens is proven separately, against the ENGINE, in
    :func:`test_the_engine_resolves_an_alias_to_the_reviewed_destination`."""
    target = _ALIAS_TARGETS[name]
    template = _alias_template(target)

    # 1: the control -- refused offline, before anything could be installed or started.
    reason = controller_compose_contract_reason(template)
    assert reason is not None, "the alias must be refused offline"
    assert reason == "controller_compose_target_not_canonical"

    # 2: Compose is content with it, which is exactly why the offline refusal has to exist.
    installed = _installed_compose_path(controller_stack)
    scratch = os.path.join(os.path.dirname(installed), f"alias-{name}.yml")
    with open(scratch, "wb") as fh:
        fh.write(template)
    os.chmod(scratch, 0o640)
    compose = os.path.realpath(shutil.which("docker-compose"))
    try:
        rendered = _sh(
            compose, "--project-name", f"{_PROJECT}-alias", "--file", scratch, "config", check=False
        )
    finally:
        os.unlink(scratch)
    if rendered.returncode == 0:
        targets = [
            v.get("target") for v in yaml.safe_load(rendered.stdout)["services"]["api"]["volumes"]
        ]
        # the alias survives rendering as its own distinct string: Compose did not reject the
        # duplicate destination, and did not clean the path either.
        assert target in targets, targets
    else:
        # some Compose versions refuse the duplicate destination -- agreement, never the gate.
        assert "duplicate" in (rendered.stderr + rendered.stdout).lower()


@pytest.mark.parametrize("name", list(_ALIAS_TARGETS))
def test_the_engine_resolves_an_alias_to_the_reviewed_destination(controller_stack, name) -> None:
    """WHERE the normalization actually happens, and why an alias is not a different mount.

    A throwaway container is CREATED (never started) with the alias spelling as its only mount
    target, and the engine's own view of that container is inspected. The reported destination is
    the CLEANED path -- i.e. the reviewed target -- so an alias entry alongside the required
    mount is a second mount on the gate's destination, not a mount somewhere else. That is the
    fact that makes raw-string comparison unsafe, and why the validator must refuse first."""
    alias = _ALIAS_TARGETS[name]
    created = _sh(
        "docker",
        "create",
        "--volume",
        f"{_GATE_HOST}:{alias}:ro",
        _STANDIN,
        "true",
        check=False,
    )
    assert created.returncode == 0, created.stderr
    container = created.stdout.strip()
    try:
        raw = _sh("docker", "inspect", "--format", "{{json .Mounts}}", container)
        destinations = [m.get("Destination") for m in json.loads(raw.stdout)]
        assert _GATE_TARGET in destinations, (
            f"the engine resolved {alias!r} to {destinations} -- if this ever stops equalling the "
            "reviewed target, the canonicalization rule must be revisited"
        )
    finally:
        _sh("docker", "rm", "--force", container, check=False)


def test_no_invalid_alias_template_can_reach_install_config(controller_stack) -> None:
    """The adapter is the last boundary before the bytes become the host's Compose config: every
    alias is refused there too, so nothing invalid can reach `compose up` even by mistake."""
    from secp_management.adapters import ReviewedConfig
    from secp_management.controller_compose_validation import ControllerComposeContractError

    adapter = controller_stack["adapter"]
    installed_before = open(_installed_compose_path(controller_stack), "rb").read()
    for name, target in _ALIAS_TARGETS.items():
        template = _alias_template(target)
        config = ReviewedConfig(identity=_sha(template), content=template)
        with pytest.raises(ControllerComposeContractError):
            adapter.install_config(config)
        assert open(_installed_compose_path(controller_stack), "rb").read() == installed_before, (
            f"{name} mutated the installed config"
        )


def test_the_valid_template_still_resolves_one_and_only_one_gate_mount(controller_stack) -> None:
    """The positive control for the whole R8 matrix: after all of the above, the real installed
    template still resolves exactly one gate mount, and the running container's is read-only."""
    ctx = controller_stack["ctx"]
    rendered = yaml.safe_load(_dc(ctx, "config").stdout)
    targets = [v.get("target") for v in rendered["services"]["api"]["volumes"]]
    assert targets.count(_GATE_TARGET) == 1
    mounts = _gate_mounts()
    assert len(mounts) == 1
    assert mounts[0]["RW"] is False
    assert os.path.realpath(mounts[0]["Source"]) == os.path.realpath(_GATE_HOST)


# --------------------- R9: alternate API mount surfaces -- Compose accepts them, we refuse them


def _surface_template(block: str, extra: str = "") -> bytes:
    """The installed valid template with ``block`` added to the api service, plus any top-level
    ``extra`` the field needs to be a well-formed Compose document."""
    installed = _CONTROLLER_COMPOSE.decode()
    head, sep, tail = installed.partition("  api:\n")
    assert sep, "the api service must be present"
    return (head + sep + block + tail + extra).encode()


#: One representative per alternate surface, each aimed at (or capable of masking) the reviewed
#: readiness-gate destination while the correct reviewed mounts remain present and valid.
_R9_SURFACES = {
    "configs": (
        f"    configs:\n      - source: hostile\n        target: {_GATE_TARGET}\n",
        "configs:\n  hostile:\n    file: ./known-value\n",
    ),
    "secrets": (
        f"    secrets:\n      - source: hostile\n        target: {_GATE_TARGET}\n",
        "secrets:\n  hostile:\n    file: ./known-value\n",
    ),
    "tmpfs": (f"    tmpfs:\n      - {_GATE_TARGET}\n", ""),
    "volumes_from": ("    volumes_from:\n      - minio\n", ""),
    "devices": (f"    devices:\n      - /dev/null:{_GATE_TARGET}\n", ""),
    "use_api_socket": ("    use_api_socket: true\n", ""),
}


@pytest.mark.parametrize("field", list(_R9_SURFACES))
def test_the_validator_refuses_an_alternate_surface_compose_is_happy_with(
    controller_stack, field
) -> None:
    """The point of doing this against real Compose: for most of these fields Compose is perfectly
    content, so there is no runtime error to lean on. The offline refusal is the only control,
    and it happens before signing, before ``install_config`` and before ``compose up``."""
    block, extra = _R9_SURFACES[field]
    template = _surface_template(block, extra)

    # the control, asserted first: refused offline, with the bounded contract-class reason.
    reason = controller_compose_contract_reason(template)
    assert reason == "controller_compose_api_alternate_mount_surface_forbidden"

    # and now the reason the control has to exist: Compose renders it without objecting.
    installed = _installed_compose_path(controller_stack)
    scratch = os.path.join(os.path.dirname(installed), f"surface-{field}.yml")
    known = os.path.join(os.path.dirname(installed), "known-value")
    with open(known, "wb") as fh:
        fh.write(b"hostile\n")
    with open(scratch, "wb") as fh:
        fh.write(template)
    os.chmod(scratch, 0o640)
    compose = os.path.realpath(shutil.which("docker-compose"))
    try:
        rendered = _sh(
            compose,
            "--project-name",
            f"{_PROJECT}-surface",
            "--file",
            scratch,
            "config",
            check=False,
        )
    finally:
        os.unlink(scratch)
        os.unlink(known)
    if rendered.returncode == 0:
        # Compose accepted a document that would mount over the gate's destination.
        assert field.split("_")[0] in rendered.stdout or field in rendered.stdout, rendered.stdout
    else:
        # some fields need a resolvable referent; a Compose-side error is agreement, never the gate.
        assert rendered.stderr.strip() or rendered.stdout.strip()


def test_no_alternate_surface_template_can_reach_install_config(controller_stack) -> None:
    """The adapter boundary refuses every alternate surface too, and the installed config is proven
    byte-unchanged -- so none of these can reach ``compose up`` even by mistake."""
    from secp_management.adapters import ReviewedConfig
    from secp_management.controller_compose_validation import ControllerComposeContractError

    adapter = controller_stack["adapter"]
    installed_path = _installed_compose_path(controller_stack)
    before = open(installed_path, "rb").read()
    for field, (block, extra) in _R9_SURFACES.items():
        template = _surface_template(block, extra)
        config = ReviewedConfig(identity=_sha(template), content=template)
        with pytest.raises(ControllerComposeContractError):
            adapter.install_config(config)
        assert open(installed_path, "rb").read() == before, f"{field} mutated the installed config"


def test_the_running_stack_still_has_only_the_reviewed_mounts_and_the_real_gate(
    controller_stack,
) -> None:
    """After the whole R8+R9 matrix: the running API still has exactly the two reviewed mounts, and
    the readiness route is still backed by the genuine root-generated gate file."""
    mounts = _api_mounts()
    destinations = sorted(m.get("Destination") for m in mounts)
    assert destinations == sorted({_GATE_TARGET, _MARKER_HOST}), destinations
    assert all(m["RW"] is False for m in mounts)
    seen = _sh("docker", "exec", "secp-controller-api", "cat", _GATE_TARGET)
    assert seen.stdout.strip() == _GATE_VALUE  # the real gate, not a config/secret/tmpfs stand-in


def test_zzz_compensation_tears_down_zero_residual(controller_stack) -> None:
    ctx = controller_stack["ctx"]
    adapter = controller_stack["adapter"]
    result = adapter.compensate(controller_stack["receipt"])
    assert result.proven is True and result.residual == ()
    for comp in controller_stack["expected"]:
        assert _inspect(f"secp-controller-{comp}", "{{.Id}}") == ""  # all containers gone
    assert not os.path.exists(ctx.locations.controller_compose_path())  # config removed
    assert not os.path.exists(ctx.locations.controller_unit_path())  # unit removed
