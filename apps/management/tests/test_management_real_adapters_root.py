"""Linux-root END-TO-END execution of the REAL management adapters against a REAL Docker daemon and
REAL systemd (SECP-PR5G, Commit 4a — mechanics slice).

Unlike ``test_management_root.py`` (real filesystem, fake host adapters), this module drives the
ACTUAL production leaves — ``RealWorkerBootstrapAdapter``, ``RealManagementHostObserver``,
``RealManagementRollbackAdapter`` — through the pinned ``RealCommandRunner`` + hardened
``RealFilesystem`` against disposable real containers and a real, DISABLED + STOPPED operator unit.
It proves: image load + loaded-digest verification (right digest loads, wrong digest refuses);
operator unit installed disabled + stopped (never enabled/started); ordinary container observed
running + healthy with an opaque generation marker; status reobservation; partial-bootstrap
compensation with zero residual; rollback of an exact document; and idempotent retry.

The full 8-service controller stack + real migration are proven by the follow-on Commit 4b job.

Requires POSIX + effective root + a real ``docker`` + ``systemctl``; SKIPS otherwise (dev boxes).
The CI job runs it under sudo and FAILS CLOSED on any skip (the adapters must actually execute).
Test scaffolding (pull/save/run/cleanup) uses plain subprocess; every PROOF goes through the pinned
adapter path.  No operator is ever enabled/started, no OpenTofu/provider/workflow is contacted.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile

import pytest

_HAVE_DOCKER = shutil.which("docker") is not None
_HAVE_SYSTEMCTL = shutil.which("systemctl") is not None
_IS_ROOT = os.name == "posix" and getattr(os, "geteuid", lambda: 1)() == 0

pytestmark = pytest.mark.skipif(
    not (_IS_ROOT and _HAVE_DOCKER and _HAVE_SYSTEMCTL),
    reason="real management adapter E2E requires POSIX root + docker + systemctl",
)

_ORDINARY = "secp-ordinary-worker"  # must equal topology.ORDINARY_CONTAINER_NAME
_OPERATOR_UNIT = "secp-operator-worker.service"  # must equal topology.OPERATOR_SERVICE_NAME
_LOAD_IMAGE = "hello-world:latest"  # tiny disposable image for the load/digest-verify proof
_BASE_IMAGE = "busybox:latest"  # disposable base for the observable ordinary container

# A fake `/usr/bin/python3` mirroring the REAL secp_worker.health exec contract
# (`python3 -m secp_worker.health <check|queues>`): check -> exit 0 when ready; queues -> print
# the recorded ordinary task queue (one per line), exit 0.  See apps/worker/secp_worker/health.py;
# the real contract is proven hermetically in test_worker_health.py.  Lets a stock busybox
# container satisfy the observer's health/queue probes without a bespoke image build.
_FAKE_PY3 = """#!/bin/sh
for a in "$@"; do last="$a"; done
case "$last" in
  check) exit 0 ;;
  queues) echo "secp-orchestration"; exit 0 ;;
  *) exit 2 ;;
esac
"""

# A valid, DISABLED operator unit: it HAS an [Install] section (so systemd reports
# UnitFileState=disabled, classified not-enabled) but is NEVER `systemctl enable`d or started.
_OPERATOR_UNIT_CONTENT = b"""[Unit]
Description=SECP operator worker (prepared, disabled, never started)

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
"""


def _sh(*argv: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, check=check, capture_output=capture, text=True, timeout=300, stdin=subprocess.DEVNULL
    )


def _docker(*argv: str, check: bool = True) -> str:
    return _sh("docker", *argv, check=check).stdout.strip()


def _pin(name: str):  # noqa: ANN202
    from secp_operator_deployment.pinned_exec import ExecutablePin

    real = os.path.realpath(shutil.which(name))  # type: ignore[arg-type]
    with open(real, "rb") as fh:
        digest = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
    return ExecutablePin(real, digest)


@pytest.fixture(scope="module")
def real_ctx():  # noqa: ANN201
    """A production RealAdapterContext against the real host, with fixed layout roots redirected to
    a root-owned sandbox (except systemd_dir, which stays /etc/systemd/system so systemctl sees the
    unit).  Tears down every container/image/unit/dir it created."""
    from secp_commissioning.runtime import RealFilesystem
    from secp_management.layout import ManagementLocations
    from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
    from secp_operator_deployment.host_process import RealCommandRunner

    parent = os.environ.get("SECP_ROOT_TEST_DIR", "/opt")
    base = tempfile.mkdtemp(prefix="secp-mgmt-real-", dir=parent)
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
    staging = os.path.join(locations.bootstrap_root, "staging")
    os.makedirs(staging, exist_ok=True)
    os.chown(staging, 0, 0)
    os.chmod(staging, 0o755)

    unit_path = locations.operator_unit_path()
    assert not os.path.exists(unit_path), f"pre-existing {unit_path}; refusing to clobber"

    docker_pin = _pin("docker")
    executables = PinnedExecutables(
        container_runtime=docker_pin,
        compose_runtime=docker_pin,  # placeholder: 4a never invokes the compose argv
        service_manager=_pin("systemctl"),
    )
    ctx = RealAdapterContext(
        locations=locations,
        fs=RealFilesystem(),
        runner=RealCommandRunner(),
        executables=executables,
    )
    try:
        yield ctx
    finally:
        _docker("rm", "-f", _ORDINARY, check=False)
        _docker("image", "rm", "-f", _LOAD_IMAGE, check=False)
        if os.path.exists(unit_path):
            os.remove(unit_path)
            _sh("systemctl", "daemon-reload", check=False)
        shutil.rmtree(base, ignore_errors=True)


def _save_tar(image_ref: str) -> bytes:
    """Bytes of a real ``docker save`` tar of ``image_ref`` (captured while the image exists)."""
    tar = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    tar.close()
    try:
        _docker("save", image_ref, "-o", tar.name)
        with open(tar.name, "rb") as fh:
            return fh.read()
    finally:
        os.unlink(tar.name)


def _image_artifact(data: bytes, image_digest: str):  # noqa: ANN202
    """A VerifiedArtifact over captured save-tar bytes carrying the given signed loaded-image
    digest."""
    from secp_management.adapters import VerifiedArtifact

    return VerifiedArtifact(
        role="worker",
        kind="image_archive",
        name="ordinary-runtime",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        size=len(data),
        reader=lambda: data,
        purpose="worker/runtime-image",
        image_digest=image_digest,
    )


def _reviewed(content: bytes, unit: bool):  # noqa: ANN202
    from secp_commissioning.canonical import sha256_bytes
    from secp_management.adapters import ReviewedConfig, ReviewedUnit

    identity = sha256_bytes(content)
    return (ReviewedUnit if unit else ReviewedConfig)(identity=identity, content=content)


# --- image load + loaded-digest verification -------------------------------------------------


def test_real_image_load_and_wrong_digest_refusal(real_ctx) -> None:
    from secp_management import ManagementError
    from secp_management.real_adapters import RealWorkerBootstrapAdapter

    _docker("pull", _LOAD_IMAGE)
    image_id = _docker("image", "inspect", "--format", "{{.Id}}", _LOAD_IMAGE)
    assert image_id.startswith("sha256:")
    data = _save_tar(_LOAD_IMAGE)  # capture the archive WHILE the image exists
    _docker("image", "rm", "-f", _LOAD_IMAGE)  # prove the adapter's load actually restores it

    # wrong signed digest -> the loaded image is not the signed one -> refuse
    bad = RealWorkerBootstrapAdapter(real_ctx)
    with pytest.raises(ManagementError):
        bad.load_image(_image_artifact(data, image_digest="sha256:" + "0" * 64))
    _docker("image", "rm", "-f", _LOAD_IMAGE, check=False)

    # correct signed digest -> loads and verifies the LOADED image digest
    good = RealWorkerBootstrapAdapter(real_ctx)
    good.load_image(_image_artifact(data, image_digest=image_id))
    present = _docker("image", "inspect", "--format", "{{.Id}}", image_id)
    assert present == image_id
    assert good.receipt().loaded_images == (image_id,)

    residual = good.compensate(good.receipt())
    assert residual.proven and residual.residual == ()
    absent = _sh("docker", "image", "inspect", image_id, check=False)
    assert absent.returncode != 0  # compensation removed the loaded image (zero residual)


# --- operator unit installed disabled + stopped ----------------------------------------------


def _install_operator_unit(ctx) -> object:  # noqa: ANN001
    from secp_management.real_adapters import RealWorkerBootstrapAdapter

    adapter = RealWorkerBootstrapAdapter(ctx)
    adapter.install_operator_unit_disabled(_reviewed(_OPERATOR_UNIT_CONTENT, unit=True))
    adapter.daemon_reload()
    return adapter


def test_real_operator_unit_disabled_and_stopped(real_ctx) -> None:
    from secp_management.real_adapters import RealManagementHostObserver

    _install_operator_unit(real_ctx)
    # the real unit is present in the system search path, loaded, inactive, NOT enabled
    assert _sh("systemctl", "is-enabled", _OPERATOR_UNIT, check=False).stdout.strip() == "disabled"
    assert _sh("systemctl", "is-active", _OPERATOR_UNIT, check=False).stdout.strip() == "inactive"

    obs = RealManagementHostObserver(real_ctx).observe_worker()
    assert obs.operator_present is True
    assert obs.operator_enabled is False
    assert obs.operator_running is False

    # cleanup for isolation from later tests
    os.remove(real_ctx.locations.operator_unit_path())
    _sh("systemctl", "daemon-reload", check=False)


# --- ordinary container observed running + healthy -------------------------------------------


def _run_ordinary(script_dir: str) -> None:
    # the fake python3 is the docker bind-mount source; it lives OUTSIDE the hardened root tree so
    # the daemon can mount it and its perms are independent of the layout's ancestor-trust rules.
    py3 = os.path.join(script_dir, "python3")
    with open(py3, "w") as fh:
        fh.write(_FAKE_PY3)
    os.chmod(py3, 0o755)
    _docker("rm", "-f", _ORDINARY, check=False)
    _docker("pull", _BASE_IMAGE)
    _docker(
        "run",
        "-d",
        "--name",
        _ORDINARY,
        "-v",
        f"{py3}:/usr/bin/python3:ro",
        _BASE_IMAGE,
        "sleep",
        "100000",
    )


def test_real_ordinary_observed_prepared_and_marker_opaque(real_ctx) -> None:
    from secp_management.real_adapters import RealManagementHostObserver

    scripts = tempfile.mkdtemp(prefix="secp-py3-")  # /tmp: docker-mountable, outside the root tree
    try:
        _run_ordinary(scripts)
        adapter = _install_operator_unit(real_ctx)  # operator present, disabled
        adapter.install_ordinary_config(_reviewed(b"# ordinary worker compose\n", unit=False))

        observer = RealManagementHostObserver(real_ctx)
        obs = observer.observe_worker()
        assert obs.coherent is True
        assert obs.ordinary_running is True and obs.ordinary_healthy is True
        assert obs.ordinary_polls_operator_queue is False
        assert obs.operator_present and not obs.operator_enabled and not obs.operator_running
        assert obs.ordinary_image_digest.startswith("sha256:")
        assert obs.commissioning_status == "prepared"
        # the opaque marker never embeds the raw container id (a 64-hex id inside the digest would
        # require an astronomically unlikely collision)
        assert obs.generation_marker.startswith("sha256:")
        assert obs.ordinary_container_id not in obs.generation_marker

        # status reobservation is stable (same generation -> same opaque marker)
        assert observer.observe_worker().generation_marker == obs.generation_marker
    finally:
        _docker("rm", "-f", _ORDINARY, check=False)
        up = real_ctx.locations.operator_unit_path()
        if os.path.exists(up):
            os.remove(up)
            _sh("systemctl", "daemon-reload", check=False)
        shutil.rmtree(scripts, ignore_errors=True)


# --- partial-bootstrap compensation + zero residual ------------------------------------------


def test_real_partial_bootstrap_compensation_zero_residual(real_ctx) -> None:
    from secp_management.real_adapters import RealWorkerBootstrapAdapter

    loc = real_ctx.locations
    adapter = RealWorkerBootstrapAdapter(real_ctx)
    # a partial bootstrap: config + package + operator unit installed, then a failure before start
    adapter.install_ordinary_config(_reviewed(b"# ordinary compose\n", unit=False))
    adapter.install_deployment_package(_deployment_pkg_artifact(), aggregate="sha256:" + "a" * 64)
    adapter.install_operator_unit_disabled(_reviewed(_OPERATOR_UNIT_CONTENT, unit=True))
    adapter.daemon_reload()

    for path in (
        loc.worker_compose_path(),
        loc.worker_deployment_package_path(),
        loc.operator_unit_path(),
    ):
        assert os.path.exists(path)

    result = adapter.compensate(adapter.receipt())
    assert result.proven is True and result.residual == ()
    for path in (
        loc.worker_compose_path(),
        loc.worker_deployment_package_path(),
        loc.operator_unit_path(),
    ):
        assert not os.path.exists(path)  # exactly the created objects removed; zero residual

    # idempotent retry: compensating an already-clean receipt is still proven, still zero residual
    again = adapter.compensate(adapter.receipt())
    assert again.proven is True and again.residual == ()
    _sh("systemctl", "daemon-reload", check=False)


def _deployment_pkg_artifact():  # noqa: ANN202
    from secp_management.adapters import VerifiedArtifact

    data = b"PK\x03\x04 disposable operator deployment package"
    return VerifiedArtifact(
        role="worker",
        kind="deployment_package",
        name="operator-deployment",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        size=len(data),
        reader=lambda: data,
        purpose="worker/deployment-package",
    )


# --- rollback of an exact document -----------------------------------------------------------


def test_real_rollback_removes_exact_document(real_ctx) -> None:
    from secp_management import ManagementError
    from secp_management.evidence import path_binding_digest
    from secp_management.real_adapters import RealManagementRollbackAdapter

    loc = real_ctx.locations
    evidence_path = loc.evidence_path("worker")
    real_ctx.fs.atomic_install(evidence_path, b'{"evidence":true}', uid=0, gid=0, mode=0o640)
    assert os.path.exists(evidence_path)

    rollback = RealManagementRollbackAdapter(real_ctx.fs, loc)
    rollback.remove_object(binding=path_binding_digest("worker", evidence_path), kind="evidence")
    assert not os.path.exists(evidence_path)  # exactly the bound document removed

    with pytest.raises(ManagementError):
        rollback.remove_object(binding="sha256:" + "0" * 64, kind="evidence")  # unknown binding
