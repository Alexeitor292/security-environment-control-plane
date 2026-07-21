"""Linux-root filesystem-security proofs for the fixed controller Compose environment file (PR5F.1).

The production backend deliberately cannot be redirected to a temporary path: the controller
environment file is always the code-owned ``/etc/secp/controller/secp.env``.  These tests therefore
run only in the dedicated ephemeral CI job, as root, behind the same opt-in sentinel as the other
PR5F root tests.  They prove the hardened read enforces a real regular file, no symlink, exactly one
hard link, root ownership, a safe (0600/0640) mode, bounded nonzero size, and that only a private
digest/owner/mode binding is exposed — never the file bytes.  They refuse to touch a pre-existing
production leaf and remove only the exact paths proven absent at fixture entry.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
import secp_discovery_activation.local_adapter as local_adapter

_OPT_IN_NAME = "SECP_DISCOVERY_ACTIVATION_ROOT_TEST"
_OPT_IN_VALUE = "fixed-layout-ci-only"
_CONTROLLER_DIR = Path("/etc/secp/controller")
_ENV_PATH = Path(local_adapter.CONTROLLER_ENV_FILE_PATH)
_HARDLINK = _CONTROLLER_DIR / "secp.env.pr5f1-root-test-hardlink"
_TARGET = _CONTROLLER_DIR / "secp.env.pr5f1-root-test-target"
_EXACT_TEST_PATHS = (_ENV_PATH, _HARDLINK, _TARGET)
_TEST_UID = 12345

_ENV_BYTES = (
    b"# fixed controller environment (values secret)\n"
    b"SECP_API_IMAGE=sha256:" + b"a" * 64 + b"\n"
    b"SECP_DATABASE_URL=postgresql://redacted\n"
)


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


def _assert_trusted_controller_dir() -> None:
    current = Path("/")
    for part in _CONTROLLER_DIR.parts[1:]:
        current /= part
        status = current.lstat()
        assert stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode)
        assert status.st_uid == 0 and status.st_gid == 0
        assert stat.S_IMODE(status.st_mode) & 0o022 == 0


def _remove_exact(path: Path) -> None:
    assert path in _EXACT_TEST_PATHS
    if os.path.lexists(os.fspath(path)):
        path.unlink()


@pytest.fixture(autouse=True)
def _controller_env_guard():
    assert _root_gate_enabled()
    _assert_trusted_controller_dir()
    preexisting = [str(p) for p in _EXACT_TEST_PATHS if os.path.lexists(os.fspath(p))]
    assert preexisting == [], f"refusing to touch pre-existing fixed-layout paths: {preexisting}"
    try:
        yield
    finally:
        for path in _EXACT_TEST_PATHS:
            _remove_exact(path)


def _write_env(*, mode: int = 0o640, uid: int = 0, content: bytes = _ENV_BYTES) -> None:
    fd = os.open(os.fspath(_ENV_PATH), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    os.chmod(_ENV_PATH, mode)
    if uid != 0:
        os.chown(_ENV_PATH, uid, 0)


def _record():
    return local_adapter.PosixActivationArtifactStore._controller_env_record()


def _refuses(reason_in: set[str]) -> None:
    with pytest.raises(local_adapter.ActivationAdapterError) as caught:
        _record()
    assert caught.value.reason_code in reason_in


def test_valid_env_file_returns_a_private_binding_without_content() -> None:
    _write_env(mode=0o640)
    record = _record()
    assert record.uid == 0 and record.mode == 0o640
    assert record.digest == local_adapter._digest(_ENV_BYTES)
    # the journal/public binding never carries the bytes
    assert set(record.safe()) == {"digest", "uid", "gid", "mode"}
    assert "content" not in record.safe() and "content_b64" not in record.safe()
    assert "SECP_DATABASE_URL" not in repr(record) and "redacted" not in repr(record)


def test_mode_0600_is_accepted() -> None:
    _write_env(mode=0o600)
    assert _record().mode == 0o600


def test_missing_env_file_refuses() -> None:
    _refuses({"controller_env_missing"})


def test_empty_env_file_refuses() -> None:
    _write_env(content=b"")
    _refuses({"controller_env_missing_or_empty"})


def test_symlink_env_file_refuses() -> None:
    _TARGET.write_bytes(_ENV_BYTES)
    os.chmod(_TARGET, 0o640)
    os.symlink(os.fspath(_TARGET), os.fspath(_ENV_PATH))
    _refuses({"activation_artifact_open_failed", "controller_env_missing"})


def test_multi_hard_link_env_file_refuses() -> None:
    _write_env(mode=0o640)
    os.link(os.fspath(_ENV_PATH), os.fspath(_HARDLINK))
    _refuses({"activation_artifact_unsafe"})


def test_non_root_owner_env_file_refuses() -> None:
    _write_env(mode=0o640, uid=_TEST_UID)
    _refuses({"activation_artifact_unsafe", "controller_env_metadata_unsafe"})


def test_world_readable_mode_env_file_refuses() -> None:
    _write_env(mode=0o644)
    _refuses({"controller_env_metadata_unsafe"})


def test_group_writable_mode_env_file_refuses() -> None:
    _write_env(mode=0o660)
    _refuses({"activation_artifact_unsafe"})


def test_oversized_env_file_refuses() -> None:
    _write_env(content=b"SECP_X=" + b"a" * (local_adapter._MAX_CONTROLLER_ENV_BYTES + 16))
    _refuses({"activation_artifact_unsafe"})


def test_content_or_metadata_drift_changes_the_binding() -> None:
    # The transaction binding is exactly what assert_controller_env_unchanged compares; a content or
    # metadata change flips it, so activation/rollback refuse closed on any drift.
    _write_env(mode=0o640)
    staged = _record().fixed_input()
    _ENV_PATH.write_bytes(_ENV_BYTES + b"SECP_EXTRA=1\n")
    os.chmod(_ENV_PATH, 0o640)
    assert _record().fixed_input() != staged  # content drift
    _ENV_PATH.unlink()
    _write_env(mode=0o600)
    assert _record().fixed_input() != staged  # metadata (mode) drift


# --- Linux-root production-store journal round trip: controller_env survives staging ---
#
# The controller transaction journals the fixed environment file's private binding under the
# code-owned /var/lib/secp/discovery-activation journal.  This exercises the REAL production store's
# write_journal -> receipt/load cycle against the real root-owned journal path (not a fake store),
# so the role-dependent schema (a controller journal MUST carry controller_env) is proven end to end
# on a POSIX-root host and cannot regress behind Windows skips.

_JOURNAL_DIR = Path("/var/lib/secp/discovery-activation")
_CONTROLLER_JOURNAL = _JOURNAL_DIR / "controller-transaction.json"
_JOURNAL_EXACT_PATHS = (_CONTROLLER_JOURNAL, _JOURNAL_DIR)
_SHA = "sha256:" + "a" * 64
_TXN = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
_ENV_LEAK_SENTINEL = b"SECP_ADMIN_TOKEN=do-not-persist-these-bytes"


def _valid_controller_journal() -> dict[str, object]:
    roles = local_adapter._roles_for(local_adapter.LocalHostRole.controller)
    return {
        "schema": local_adapter._JOURNAL_SCHEMA,
        "transaction_id": _TXN,
        "host_role": "controller",
        "status": "staged",
        "render_manifest_sha256": _SHA,
        "profile_content_digest": _SHA,
        "base_compose": {"digest": _SHA, "uid": 0, "gid": 0, "mode": 0o640},
        "before": {role: None for role in roles},
        "after": {role: None for role in roles},
        "effects": {
            "effects_started": False,
            "controller_changed": False,
            "controller_runtime_changed": False,
            "worker_config_changed": False,
            "worker_recreated": False,
            "evidence_committed": False,
        },
        "operation_count": 0,
        "state_receipt": None,
        "execution": {
            "container_path": "/usr/bin/podman",
            "container_digest": _SHA,
            "compose_path": "/usr/bin/docker-compose",
            "compose_digest": _SHA,
        },
        "before_worker": None,
        "before_controller": {
            "controller_config_installed": False,
            "proxy_running": False,
            "proxy_healthy": False,
            "private_listener_only": False,
            "tls_ready": False,
            "activation_route_enabled": False,
            "api_runtime": None,
            "proxy_runtime": None,
            "migration_head": None,
            "migration_head_ready": False,
            "configuration_artifact_digests": [],
        },
        "runtime_after": None,
        "worker_tls_proof": None,
        "controller_env": {"digest": _SHA, "uid": 0, "gid": 0, "mode": 0o640},
    }


@pytest.fixture
def _journal_guard():
    # /var/lib/secp must be a trusted root-owned ancestor before the store creates the journal dir.
    current = Path("/")
    for part in _JOURNAL_DIR.parent.parts[1:]:
        current /= part
        status = current.lstat()
        assert stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode)
        assert status.st_uid == 0 and status.st_gid == 0
        assert stat.S_IMODE(status.st_mode) & 0o022 == 0
    preexisting = [str(p) for p in _JOURNAL_EXACT_PATHS if os.path.lexists(os.fspath(p))]
    assert preexisting == [], f"refusing to touch pre-existing journal paths: {preexisting}"
    try:
        yield
    finally:
        if os.path.lexists(os.fspath(_CONTROLLER_JOURNAL)):
            _CONTROLLER_JOURNAL.unlink()
        if os.path.lexists(os.fspath(_JOURNAL_DIR)):
            _JOURNAL_DIR.rmdir()


def test_real_store_round_trips_controller_env_and_persists_no_bytes(_journal_guard: None) -> None:
    store = local_adapter.PosixActivationArtifactStore(local_adapter.LocalHostRole.controller)
    store._write_journal(_valid_controller_journal(), expected=None)  # real root-owned FS write
    receipt = store.receipt()  # real _load_journal -> _validate_journal -> receipt
    assert receipt.journal_present is True and receipt.transaction_id == _TXN
    written = _CONTROLLER_JOURNAL.lstat()
    assert written.st_uid == 0 and written.st_gid == 0 and stat.S_IMODE(written.st_mode) == 0o600
    loaded = json.loads(_CONTROLLER_JOURNAL.read_bytes())
    assert set(loaded["controller_env"]) == {"digest", "uid", "gid", "mode"}
    assert (
        "content" not in loaded["controller_env"] and "content_b64" not in loaded["controller_env"]
    )
    assert _ENV_LEAK_SENTINEL not in _CONTROLLER_JOURNAL.read_bytes()


def test_real_store_rejects_controller_journal_without_env(_journal_guard: None) -> None:
    store = local_adapter.PosixActivationArtifactStore(local_adapter.LocalHostRole.controller)
    journal = _valid_controller_journal()
    del journal["controller_env"]
    store._write_journal(journal, expected=None)
    with pytest.raises(local_adapter.ActivationAdapterError) as caught:
        store.receipt()
    assert caught.value.reason_code == "transaction_journal_malformed"
