"""Linux-root proofs for the fixed PR5F worker-state filesystem transaction.

The production backend deliberately cannot be redirected to a temporary path.  Consequently these
tests run only in the dedicated ephemeral CI job, as root, with an exact opt-in sentinel.  They fail
if the production leaf or either test-owned sibling exists before a test; teardown removes only
those exact paths that were proven absent at fixture entry.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import pytest
import secp_discovery_activation.state as state_module
from secp_discovery_activation.state import RealWorkerStateFilesystem, WorkerStateError

_OPT_IN_NAME = "SECP_DISCOVERY_ACTIVATION_ROOT_TEST"
_OPT_IN_VALUE = "fixed-layout-ci-only"
_STATE_PARENT = Path("/var/lib/secp")
_STATE_ROOT = _STATE_PARENT / "discovery-worker"
_SYMLINK_TARGET = _STATE_PARENT / "pr5f-discovery-root-test-target"
_ORIGINAL_ROOT = _STATE_PARENT / "pr5f-discovery-root-test-original"
_EXACT_TEST_PATHS = (_STATE_ROOT, _SYMLINK_TARGET, _ORIGINAL_ROOT)
_WORKER_UID = 12345
_WORKER_GID = 12346


def _root_gate_enabled() -> bool:
    return bool(
        os.name == "posix"
        and getattr(os, "geteuid", lambda: -1)() == 0
        and os.environ.get(_OPT_IN_NAME) == _OPT_IN_VALUE
    )


pytestmark = pytest.mark.skipif(
    not _root_gate_enabled(),
    reason="requires dedicated Linux-root fixed-layout PR5F CI gate",
)


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _remove_exact_test_path(path: Path) -> None:
    assert path in _EXACT_TEST_PATHS
    if not _lexists(path):
        return
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        path.unlink()
    else:
        shutil.rmtree(path)


def _assert_trusted_parent() -> None:
    assert _STATE_PARENT == Path("/var/lib/secp")
    current = Path("/")
    for part in _STATE_PARENT.parts[1:]:
        current /= part
        status = current.lstat()
        assert stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode)
        assert status.st_uid == 0 and status.st_gid == 0
        assert stat.S_IMODE(status.st_mode) & 0o022 == 0


@pytest.fixture(autouse=True)
def _fixed_layout_guard() -> None:
    assert _root_gate_enabled()
    _assert_trusted_parent()
    preexisting = [str(path) for path in _EXACT_TEST_PATHS if _lexists(path)]
    assert preexisting == [], f"refusing to touch pre-existing fixed-layout state: {preexisting}"
    try:
        yield
    finally:
        for path in _EXACT_TEST_PATHS:
            _remove_exact_test_path(path)


def _owned_directory(path: Path, *, uid: int = _WORKER_UID, gid: int = _WORKER_GID) -> None:
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid, follow_symlinks=False)
    os.chmod(path, 0o700, follow_symlinks=False)


def _complete_empty_tree(*, uid: int = _WORKER_UID, gid: int = _WORKER_GID) -> None:
    _owned_directory(_STATE_ROOT, uid=uid, gid=gid)
    _owned_directory(_STATE_ROOT / "worker-keys", uid=uid, gid=gid)
    _owned_directory(_STATE_ROOT / "discovery-bundle", uid=uid, gid=gid)


def _write_worker_file(path: Path, content: bytes = b"inert-root-test-data") -> None:
    path.write_bytes(content)
    os.chown(path, _WORKER_UID, _WORKER_GID, follow_symlinks=False)
    os.chmod(path, 0o600, follow_symlinks=False)


def test_real_state_prepare_inspect_and_compensate_round_trip() -> None:
    backend = RealWorkerStateFilesystem()
    assert backend.inspect(uid=_WORKER_UID, gid=_WORKER_GID).present is False

    receipt = backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    assert receipt.classification == "created"
    assert receipt.root_created and receipt.keys_created and receipt.bundle_created

    observed = backend.inspect(uid=_WORKER_UID, gid=_WORKER_GID)
    assert observed.present and observed.prepared
    assert observed.owner_uid == _WORKER_UID and observed.owner_gid == _WORKER_GID
    for path in (
        _STATE_ROOT,
        _STATE_ROOT / "worker-keys",
        _STATE_ROOT / "discovery-bundle",
    ):
        status = path.lstat()
        assert stat.S_ISDIR(status.st_mode)
        assert (status.st_uid, status.st_gid, stat.S_IMODE(status.st_mode)) == (
            _WORKER_UID,
            _WORKER_GID,
            0o700,
        )

    assert backend.compensate(receipt, uid=_WORKER_UID, gid=_WORKER_GID) is True
    assert not _lexists(_STATE_ROOT)


def test_real_state_adopts_complete_tree_and_never_removes_it() -> None:
    _complete_empty_tree()
    backend = RealWorkerStateFilesystem()
    receipt = backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    assert receipt.classification == "adopted"
    assert not receipt.root_created and not receipt.keys_created and not receipt.bundle_created
    assert backend.compensate(receipt, uid=_WORKER_UID, gid=_WORKER_GID) is True
    assert _STATE_ROOT.is_dir()
    assert (_STATE_ROOT / "worker-keys").is_dir()
    assert (_STATE_ROOT / "discovery-bundle").is_dir()


def test_real_state_refuses_partial_tree_without_repairing_it() -> None:
    _owned_directory(_STATE_ROOT)
    _owned_directory(_STATE_ROOT / "worker-keys")
    backend = RealWorkerStateFilesystem()
    with pytest.raises(WorkerStateError) as error:
        backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    assert error.value.reason_code == "worker_state_root_foreign_or_partial"
    assert (_STATE_ROOT / "worker-keys").is_dir()
    assert not (_STATE_ROOT / "discovery-bundle").exists()


def test_real_state_refuses_symlink_without_touching_target() -> None:
    _SYMLINK_TARGET.mkdir(mode=0o700)
    marker = _SYMLINK_TARGET / "marker"
    marker.write_bytes(b"must-survive")
    _STATE_ROOT.symlink_to(_SYMLINK_TARGET, target_is_directory=True)

    backend = RealWorkerStateFilesystem()
    with pytest.raises(WorkerStateError) as error:
        backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    assert error.value.reason_code == "worker_state_root_open_failed"
    assert _STATE_ROOT.is_symlink()
    assert marker.read_bytes() == b"must-survive"


def test_real_state_refuses_unsafe_mode_without_chmod_repair() -> None:
    _complete_empty_tree()
    os.chmod(_STATE_ROOT, 0o750, follow_symlinks=False)
    backend = RealWorkerStateFilesystem()
    with pytest.raises(WorkerStateError) as error:
        backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    assert error.value.reason_code == "worker_state_root_unsafe_mode"
    assert stat.S_IMODE(_STATE_ROOT.lstat().st_mode) == 0o750


def test_rollback_preflights_all_children_before_removing_anything() -> None:
    backend = RealWorkerStateFilesystem()
    receipt = backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    marker = _STATE_ROOT / "worker-keys" / "worker-owned-after-prepare"
    _write_worker_file(marker)

    assert backend.compensate(receipt, uid=_WORKER_UID, gid=_WORKER_GID) is False
    # A refusal must not partially remove an earlier child before discovering later worker data.
    assert (_STATE_ROOT / "worker-keys").is_dir()
    assert (_STATE_ROOT / "discovery-bundle").is_dir()
    assert marker.read_bytes() == b"inert-root-test-data"


def test_rollback_refuses_inode_drift_and_preserves_both_trees() -> None:
    backend = RealWorkerStateFilesystem()
    receipt = backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    _STATE_ROOT.rename(_ORIGINAL_ROOT)
    _complete_empty_tree()

    assert backend.compensate(receipt, uid=_WORKER_UID, gid=_WORKER_GID) is False
    assert _STATE_ROOT.is_dir()
    assert _ORIGINAL_ROOT.is_dir()
    assert _STATE_ROOT.lstat().st_ino != receipt.root_inode
    assert _ORIGINAL_ROOT.lstat().st_ino == receipt.root_inode


def test_rollback_quarantines_then_restores_a_source_name_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RealWorkerStateFilesystem()
    receipt = backend.prepare(uid=_WORKER_UID, gid=_WORKER_GID)
    original_rename = state_module._rename_noreplace_at
    injected = False

    def substitute(directory_fd: int, source: str, destination: str) -> None:
        nonlocal injected
        if not injected and source == "discovery-worker":
            injected = True
            os.rename(
                source,
                _ORIGINAL_ROOT.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            _complete_empty_tree()
        original_rename(directory_fd, source, destination)

    monkeypatch.setattr(state_module, "_rename_noreplace_at", substitute)

    assert backend.compensate(receipt, uid=_WORKER_UID, gid=_WORKER_GID) is False
    assert _STATE_ROOT.is_dir()
    assert _ORIGINAL_ROOT.is_dir()
    assert _STATE_ROOT.lstat().st_ino != receipt.root_inode
    assert _ORIGINAL_ROOT.lstat().st_ino == receipt.root_inode
    assert not any(path.name.startswith(".secp-pr5f-rollback-") for path in _STATE_PARENT.iterdir())


def test_real_state_refuses_hardlinked_complete_key_set_without_removal() -> None:
    _complete_empty_tree()
    keys = _STATE_ROOT / "worker-keys"
    first = keys / "admission_key"
    _write_worker_file(first)
    os.link(first, keys / "admission_anchor")
    _write_worker_file(keys / "ssh_id_ed25519")
    _write_worker_file(keys / "ssh_id_ed25519.pub")

    backend = RealWorkerStateFilesystem()
    with pytest.raises(WorkerStateError) as error:
        backend.inspect(uid=_WORKER_UID, gid=_WORKER_GID)
    assert error.value.reason_code == "worker_state_key_file_hardlinked_or_not_regular"
    assert first.lstat().st_nlink == 2
    assert len(tuple(keys.iterdir())) == 4


def test_real_state_refuses_wrong_owner_without_repair() -> None:
    _complete_empty_tree()
    os.chown(_STATE_ROOT, 0, 0, follow_symlinks=False)
    backend = RealWorkerStateFilesystem()
    with pytest.raises(WorkerStateError) as error:
        backend.inspect(uid=_WORKER_UID, gid=_WORKER_GID)
    assert error.value.reason_code == "worker_state_root_wrong_owner"
    status = _STATE_ROOT.lstat()
    assert (status.st_uid, status.st_gid) == (0, 0)
