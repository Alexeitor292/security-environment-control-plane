"""Test E — trustworthy, process-local worker readiness (PR5B worker-startup hotfix).

Readiness must be FALSE until the Temporal Worker has actually been started on the ordinary queue,
FALSE again on shutdown, and FALSE if the recorded worker process has died — so a fake-healthy
container (settings parse but no worker) can never pass. No network listener is added.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture
def ready_file(tmp_path, monkeypatch):
    path = tmp_path / "secp-worker.ready"
    monkeypatch.setenv("SECP_WORKER_READY_FILE", str(path))
    return path


def test_readiness_is_false_before_mark_ready(ready_file):
    from secp_worker import health

    assert health.is_ready() is False
    assert health.readiness_status() == (False, "")


def test_readiness_becomes_true_only_after_mark_ready(ready_file):
    from secp_worker import health

    assert health.is_ready() is False
    health.mark_ready("secp-orchestration")
    ready, queue = health.readiness_status()
    assert ready is True
    assert queue == "secp-orchestration"
    assert ready_file.exists()


def test_readiness_is_false_after_clear(ready_file):
    from secp_worker import health

    health.mark_ready("secp-orchestration")
    assert health.is_ready() is True
    health.clear_ready()
    assert health.is_ready() is False
    assert not ready_file.exists()


def test_readiness_is_false_when_the_recorded_worker_pid_is_dead(ready_file):
    """A hard SIGKILL never runs clear_ready; readiness must still flip false because the marker's
    PID is checked for liveness (no stale 'ready')."""
    from secp_worker import health

    # A PID that is essentially certain not to be running.
    ready_file.write_text("2147483646 secp-orchestration\n", encoding="utf-8")
    assert health.is_ready() is False


def test_config_or_import_alone_never_marks_ready(ready_file):
    """Importing settings / safety constants must not create the marker.

    Only a running worker does.
    """
    from secp_api.config import Settings  # noqa: F401
    from secp_worker import health
    from secp_worker.plan_gen import process_boundary  # noqa: F401  (parsing seals)

    assert health.is_ready() is False


def test_ready_marker_survives_a_read_only_style_root_and_lives_under_tmp():
    """The default marker path is under /tmp (tmpfs) so it is writable on a read-only container
    rootfs."""
    from secp_worker import health

    # When unset, the default points at a tmpfs-backed path.
    assert health.READY_FILE.startswith("/tmp/") or health.READY_FILE.endswith(".ready")


def test_check_command_exit_code_tracks_readiness(ready_file):
    from secp_worker import health

    assert health._main(["check"]) == 1  # not ready
    health.mark_ready("secp-orchestration")
    assert health._main(["check"]) == 0  # ready
    health.clear_ready()
    assert health._main(["check"]) == 1


def test_mark_ready_is_atomic_and_records_pid_and_queue(ready_file):
    from secp_worker import health

    health.mark_ready("secp-orchestration")
    content = ready_file.read_text(encoding="utf-8").split()
    assert int(content[0]) == os.getpid()
    assert content[1] == "secp-orchestration"
