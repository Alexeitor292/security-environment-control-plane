"""Blocker 4 — adversarial readiness timing (PR5B worker-startup hotfix).

The danger: if the worker marked itself ready and THEN awaited ``Worker.run()``, a ``run()`` that
fails immediately would leave the readiness marker briefly visible on disk while the (still-alive)
process is actually dying — a health probe could observe a false "ready". The fix begins polling as
a task and re-raises an immediate startup failure BEFORE ``mark_ready`` is ever called, so on that
path the marker is never written and cannot be observed.

These tests prove, against the REAL ``secp_worker.health`` marker and the REAL
``secp_worker.main._run_temporal``:

* marker absent before Temporal validation;
* marker absent after Worker construction failure;
* marker absent after an IMMEDIATE ``Worker.run`` failure (``mark_ready`` is never even called);
* marker true only while a genuinely running worker is polling;
* marker removed after normal shutdown;
* a stale marker whose recorded PID is dead is unhealthy.

No unauthenticated network listener is added; Temporal sandboxing is not disabled; the fail-closed
behaviour is not weakened.
"""

from __future__ import annotations

import asyncio
import threading

import pytest


class _TemporalSettings:
    workflow_dispatch_mode = "temporal"
    temporal_host = "localhost:7233"
    temporal_namespace = "default"
    temporal_task_queue = "secp-orchestration"
    temporal_operator_task_queue = ""


def _install_common(monkeypatch, tmp_path, worker_cls):
    """Wire the shipped ordinary worker with fakes; return a mark_ready call recorder."""
    pytest.importorskip("temporalio")
    import temporalio.client
    import temporalio.worker
    from secp_worker import health, main

    monkeypatch.setattr(main, "get_settings", lambda: _TemporalSettings())
    monkeypatch.setenv("SECP_WORKER_READY_FILE", str(tmp_path / "secp-worker.ready"))

    async def _fake_connect(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        return object()

    monkeypatch.setattr(temporalio.client.Client, "connect", _fake_connect)
    monkeypatch.setattr(temporalio.worker, "Worker", worker_cls)
    # Never start real daemon threads.
    for name in (
        "_start_staging_lab_consumer",
        "_start_readonly_preflight_consumer",
        "_start_deployment_consumer",
        "_start_discovery_consumer",
        "_start_discovery_bundle_prep",
    ):
        monkeypatch.setattr(main, name, lambda _ev: None)

    async def _noop_publisher():  # noqa: ANN202
        return None

    monkeypatch.setattr(main, "_run_outbox_publisher_loop", _noop_publisher)

    # Spy on mark_ready while preserving real marker semantics.
    calls: list[str] = []
    real_mark = health.mark_ready

    def _spy_mark(task_queue):  # noqa: ANN001, ANN202
        calls.append(task_queue)
        return real_mark(task_queue)

    monkeypatch.setattr(health, "mark_ready", _spy_mark)
    # Start from a clean slate regardless of any leaked marker.
    health.clear_ready()
    return calls


def test_marker_absent_before_temporal_validation(monkeypatch, tmp_path):
    from secp_worker import health

    class _Unused:  # never constructed in this test
        pass

    _install_common(monkeypatch, tmp_path, _Unused)
    # Nothing has run the worker yet.
    assert health.is_ready() is False
    assert health.readiness_status() == (False, "")


def test_marker_absent_after_worker_construction_failure(monkeypatch, tmp_path):
    from secp_worker import health, main

    class _ConstructionBoom:
        def __init__(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN204
            raise RuntimeError("worker validation failed during construction")

    calls = _install_common(monkeypatch, tmp_path, _ConstructionBoom)

    with pytest.raises(RuntimeError, match="construction"):
        asyncio.run(main._run_temporal(threading.Event()))

    assert calls == []  # mark_ready never called
    assert health.is_ready() is False


def test_marker_absent_after_immediate_worker_run_failure(monkeypatch, tmp_path):
    """The key adversarial case: Worker.run raises immediately. mark_ready must NEVER be called, so
    the marker is never written and no health probe could ever observe a false 'ready'."""
    from secp_worker import health, main

    ready_path = tmp_path / "secp-worker.ready"

    class _ImmediateRunBoom:
        def __init__(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN204
            pass

        async def run(self):  # noqa: ANN202
            raise RuntimeError("run failed before functional polling")

    calls = _install_common(monkeypatch, tmp_path, _ImmediateRunBoom)

    with pytest.raises(RuntimeError, match="before functional polling"):
        asyncio.run(main._run_temporal(threading.Event()))

    # Never marked → never written → never observable. This is stronger than checking the marker
    # only after unwinding: the marker's absence is guaranteed because the write never happened.
    assert calls == []
    assert not ready_path.exists()
    assert health.is_ready() is False


def test_marker_true_only_while_a_genuinely_running_worker_polls_then_cleared(
    monkeypatch, tmp_path
):
    """Marker is true ONLY while a real (mocked) worker is actually polling, and is removed after a
    normal shutdown."""
    from secp_worker import health, main

    release = asyncio.Event()

    class _RunningWorker:
        def __init__(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN204
            pass

        async def run(self):  # noqa: ANN202
            await release.wait()  # blocks: the worker is "functionally polling"
            return None

    calls = _install_common(monkeypatch, tmp_path, _RunningWorker)

    async def _drive() -> None:
        assert health.is_ready() is False  # not ready before startup
        task = asyncio.ensure_future(main._run_temporal(threading.Event()))
        # Let _run_temporal reach mark_ready (worker task is blocked on `release`, never immediate).
        for _ in range(10000):
            await asyncio.sleep(0)
            if health.is_ready():
                break
        assert health.is_ready() is True  # true while the worker is genuinely running
        assert calls == ["secp-orchestration"]
        ready, queue = health.readiness_status()
        assert ready is True
        assert queue == "secp-orchestration"
        # Normal shutdown: run() returns; the finally must clear the marker.
        release.set()
        await task
        assert health.is_ready() is False  # cleared after normal shutdown

    asyncio.run(_drive())
    assert health.is_ready() is False


def test_stale_marker_with_dead_pid_is_unhealthy(monkeypatch, tmp_path):
    from secp_worker import health

    monkeypatch.setenv("SECP_WORKER_READY_FILE", str(tmp_path / "secp-worker.ready"))
    # A hard SIGKILL never runs clear_ready; a leftover marker with a dead PID must read unhealthy.
    (tmp_path / "secp-worker.ready").write_text("2147483646 secp-orchestration\n", encoding="utf-8")
    assert health.is_ready() is False
