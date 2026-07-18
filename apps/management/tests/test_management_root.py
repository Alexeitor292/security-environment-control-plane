"""Root-only POSIX bootstrap over the REAL hardened filesystem (SECP-PR5E §15).

Exercises the production :class:`~secp_commissioning.runtime.RealFilesystem` (directory-fd-relative
trusted-ancestor walk, atomic install, ownership/mode) for a management-plane worker bootstrap: the
identity + installed-release record + evidence + its detached attestation are written root-owned
with
the exact mode, status revalidates against a live observation, and rollback removes exactly the
created documents. The
closed host effects (image load, config/unit install, ordinary start) are driven through the exact
fake adapters (no real container runtime/systemd in CI); the filesystem writes are REAL. Requires
POSIX + root (only root can build the root-owned managed tree); skips otherwise. Built beneath
``$SECP_ROOT_TEST_DIR`` whose ancestors are root-owned. Wired into the deployment/management
root-security CI job.
"""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest
from _mgmt_support import (
    _EVIDENCE_TRUST,
    EphemeralEvidenceAuthenticator,
    FakeControllerAdapter,
    FakeObserver,
    FakeRollbackAdapter,
    FakeWorkerAdapter,
    ephemeral_trust_root,
    fresh_worker_world,
    prepared_worker_world,
    seed_signed_bundle_real,
)
from secp_management.cli import run

pytestmark = pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 1)() != 0,  # type: ignore[attr-defined]
    reason="management root bootstrap requires POSIX + root",
)


@pytest.fixture
def root_base():  # noqa: ANN201
    parent = os.environ.get("SECP_ROOT_TEST_DIR", "/opt")
    base = tempfile.mkdtemp(prefix="secp-mgmt-root-", dir=parent)
    os.chmod(base, 0o755)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _real_deps(root_base, world):
    from secp_commissioning.runtime import RealFilesystem
    from secp_management.engine import EngineDeps
    from secp_management.hostview import HostView, StaticHostProbe
    from secp_management.layout import ManagementLocations

    worker_root = os.path.join(root_base, "worker")
    bootstrap_root = os.path.join(root_base, "bootstrap")
    state_root = os.path.join(root_base, "state")
    release_dir = os.path.join(state_root, "release")
    for d in (
        worker_root,
        bootstrap_root,
        state_root,
        release_dir,
        os.path.join(release_dir, "images"),
    ):
        os.makedirs(d, exist_ok=True)
        os.chown(d, 0, 0)
        os.chmod(d, 0o755)
    locations = ManagementLocations(
        worker_root=worker_root, bootstrap_root=bootstrap_root, bootstrap_state=state_root
    )
    trust, kid, priv, _pub = ephemeral_trust_root()
    seed_signed_bundle_real(release_dir, "worker", kid, priv)
    fs = RealFilesystem()
    probe = StaticHostProbe(
        HostView(
            os_name="linux",
            arch="x86_64",
            is_root=True,
            docker_present=False,
            compose_present=False,
        )
    )
    deps = EngineDeps(
        locations=locations,
        trust_root=trust,
        probe=probe,
        observer=FakeObserver(world),
        controller_adapter=FakeControllerAdapter(world),
        worker_adapter=FakeWorkerAdapter(world),
        rollback_adapter=FakeRollbackAdapter(fs, locations),
        evidence_authenticator=EphemeralEvidenceAuthenticator(),
        evidence_trust_root=_EVIDENCE_TRUST,
        fs=fs,
        clock=lambda: "2026-07-18T00:00:00+00:00",
    )
    return deps, release_dir, state_root


def test_worker_bootstrap_writes_root_owned_documents(root_base):
    deps, release_dir, state_root = _real_deps(root_base, fresh_worker_world())
    code, rep = run(["bootstrap", "worker", "--bundle", release_dir, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"

    for name in (
        "worker-evidence.json",
        "worker-evidence.attestation.json",
        "worker-identity.json",
        "worker-installed-release.json",
    ):
        stt = os.lstat(os.path.join(state_root, name))
        assert stt.st_uid == 0 and stt.st_gid == 0
        assert (stt.st_mode & 0o777) == 0o640

    code, status = run(["status", "worker"], deps)
    assert code == 0 and status["ok"] is True

    code, rb = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 0 and rb["mode"] == "written"
    assert not os.path.exists(os.path.join(state_root, "worker-evidence.json"))
    assert not os.path.exists(os.path.join(state_root, "worker-evidence.attestation.json"))


def test_managed_write_refuses_group_writable_state_ancestor(root_base):
    deps, release_dir, state_root = _real_deps(root_base, fresh_worker_world())
    os.chmod(state_root, 0o775)  # group-writable ancestor → the trusted-ancestor walk refuses
    code, rep = run(["bootstrap", "worker", "--bundle", release_dir, "--write", "--confirm"], deps)
    assert code == 2 and rep.get("mode") == "refused"
    assert not os.path.exists(os.path.join(state_root, "worker-evidence.json"))


def test_adopt_writes_only_root_owned_evidence(root_base):
    deps, release_dir, state_root = _real_deps(root_base, prepared_worker_world())
    code, rep = run(["adopt", "worker", "--bundle", release_dir, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "adopted"
    for name in ("worker-evidence.json", "worker-evidence.attestation.json"):
        stt = os.lstat(os.path.join(state_root, name))
        assert stt.st_uid == 0 and (stt.st_mode & 0o777) == 0o640
