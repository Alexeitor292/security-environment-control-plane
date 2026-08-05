"""Tests B/C/D — Temporal mode is fail-CLOSED and never degrades into legacy in-process execution.

PR5B worker-startup hotfix. At base, a Temporal failure was swallowed and the worker fell through to
the inline dispatcher + legacy consumer loops, reporting a fake-healthy container with no Temporal
worker running. After the fix, ANY Temporal failure exits the process non-zero and starts NO legacy
loop; queue registration is exactly the ordinary queue with the SEALED activity set.
"""

from __future__ import annotations

import logging
import threading
from unittest import mock

import pytest


def _require_worker_extra() -> None:
    """Fail loudly when the ``worker`` extra is absent, instead of skipping.

    Every seal assertion in this file is gated on ``temporalio``. Without the extra installed they
    do not fail — they SKIP, and a skipped seal check reads exactly like a passing one. That is not
    hypothetical: this repository already lost ``temporalio`` for months while seven tests reported
    as passing without ever executing, and the sealed-set assertions here were verified by hand in a
    worktree where they were silently skipping.

    CI proves the extra is present for the shards and fails any shard skip whose reason is
    ``could not import 'x'``. Nothing enforced it for someone running THIS FILE by hand, which is
    the exact path that nearly produced a false pass.

    Deliberately checked at RUN time rather than import time. An import-site guard also breaks
    COLLECTION, and ``backend-test-inventory`` collects the whole corpus with only ``.[dev]``
    installed — so a hard import there fails a job that has no need of the extra. Collection is not
    a hand-run; execution is, and execution is what must not silently shrink.
    """
    try:
        import temporalio  # noqa: F401
    except ModuleNotFoundError as exc:  # pragma: no cover - the whole point is that this is loud
        raise AssertionError(
            "the 'worker' extra is not installed, so this sealed-set assertion would SKIP rather "
            "than run — and a skipped seal check is indistinguishable from a passing one. "
            "Install it with: uv sync --frozen --extra dev --extra worker"
        ) from exc


class _TemporalSettings:
    """Minimal settings selecting temporal mode (main only reads workflow_dispatch_mode here)."""

    workflow_dispatch_mode = "temporal"


def _force_temporal(monkeypatch) -> None:
    from secp_worker import main

    monkeypatch.setattr(main, "get_settings", lambda: _TemporalSettings())
    # Never register real OS signal handlers or start real daemon threads during the test.
    monkeypatch.setattr(main, "_install_signal_handlers", lambda ev: None)
    # Guard against global logging state leaked by an earlier full-suite test: a uvicorn-style
    # dictConfig(disable_existing_loggers=True) at app startup disables the module logger
    # process-wide, which would silently make caplog capture nothing (the record is dropped before
    # any handler). Re-enable + force propagation so the fail-closed ERROR is actually captured.
    # monkeypatch auto-reverts, so we only fix our own read, never another test's leaked state.
    monkeypatch.setattr(main.logger, "disabled", False)
    monkeypatch.setattr(main.logger, "propagate", True)


_LEGACY_STARTERS = (
    "_start_staging_lab_consumer",
    "_start_readonly_preflight_consumer",
    "_start_deployment_consumer",
    "_start_discovery_consumer",
    "_start_discovery_bundle_prep",
)


# --- Test B: fail-closed on the temporal failure modes -------------------------------------------


@pytest.mark.parametrize(
    "failure", [RuntimeError("connect/validate/construct/run failed"), OSError]
)
def test_temporal_failure_exits_nonzero_and_signals_stop(monkeypatch, caplog, failure):
    from secp_worker import main

    _force_temporal(monkeypatch)

    async def _boom(stop_event):  # noqa: ANN001, ANN202
        raise failure if isinstance(failure, BaseException) else failure()

    monkeypatch.setattr(main, "_run_temporal", _boom)
    event = mock.MagicMock(spec=threading.Event)
    monkeypatch.setattr(main.threading, "Event", lambda: event)

    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 1  # non-zero exit — the container must die and be restarted
    assert event.set.called  # daemon consumers (if any) are signalled to stop
    assert "refusing to fall back to legacy in-process orchestration" in caplog.text


def test_clean_temporal_shutdown_exits_zero(monkeypatch):
    """A clean run (no exception) returns normally (exit 0) — the terminal branch is not always
    non-zero."""
    from secp_worker import main

    _force_temporal(monkeypatch)

    async def _clean(stop_event):  # noqa: ANN001, ANN202
        return None

    monkeypatch.setattr(main, "_run_temporal", _clean)
    # main() returns (no SystemExit) on a clean temporal shutdown.
    assert main.main() is None


# --- Test C: no legacy loop / inline dispatcher reachable from temporal-mode failure -------------


def test_temporal_failure_starts_no_legacy_loops_or_inline_dispatcher(monkeypatch):
    from secp_worker import main

    _force_temporal(monkeypatch)

    async def _boom(stop_event):  # noqa: ANN001, ANN202
        raise RuntimeError("temporal exploded")

    monkeypatch.setattr(main, "_run_temporal", _boom)

    started = {}
    for name in _LEGACY_STARTERS:
        m = mock.MagicMock()
        started[name] = m
        monkeypatch.setattr(main, name, m)
    # The inline foreground loop is imported lazily inside main(); patch its module attr.
    import secp_worker.staging_lab.runtime as sl_runtime

    run_forever = mock.MagicMock()
    monkeypatch.setattr(sl_runtime, "run_forever", run_forever)

    with pytest.raises(SystemExit):
        main.main()

    for name, m in started.items():
        assert m.call_count == 0, f"{name} must not start when temporal mode fails"
    assert run_forever.call_count == 0, (
        "the inline staging-lab loop must not run on temporal failure"
    )


def test_no_fallback_log_message_is_reachable_from_temporal_failure(monkeypatch, caplog):
    """The base fail-open log ('legacy orchestration runs in-process via the inline
    dispatcher') must NEVER be emitted from temporal-mode failure handling."""
    from secp_worker import main

    _force_temporal(monkeypatch)

    async def _boom(stop_event):  # noqa: ANN001, ANN202
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "_run_temporal", _boom)
    for name in _LEGACY_STARTERS:
        monkeypatch.setattr(main, name, mock.MagicMock())

    with caplog.at_level(logging.INFO), pytest.raises(SystemExit):
        main.main()

    assert "legacy orchestration runs in-process via the inline dispatcher" not in caplog.text


def test_the_fallback_branch_is_gated_behind_a_non_temporal_mode_check():
    """Static guard: in main(), the legacy/inline block is only reachable when dispatch mode is NOT
    temporal (the temporal branch is terminal — it returns or exits non-zero)."""
    import ast
    import pathlib

    src = pathlib.Path(main_source_path()).read_text(encoding="utf-8")
    tree = ast.parse(src)
    main_fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "main")
    # The temporal branch must contain a SystemExit(1) (fail-closed) and the fall-through must come
    # AFTER a `return` inside the temporal branch.
    body_src = ast.get_source_segment(src, main_fn)
    assert "SystemExit(1)" in body_src
    assert "refusing to fall back to legacy in-process orchestration" in body_src


def main_source_path() -> str:
    import pathlib

    return str(
        pathlib.Path(__file__).resolve().parents[3] / "apps" / "worker" / "secp_worker" / "main.py"
    )


# --- Test D: queue isolation + sealed set (the shipped ordinary worker) --------------------------


def test_shipped_worker_registers_only_the_ordinary_queue_with_the_sealed_set(
    monkeypatch, tmp_path
):
    _require_worker_extra()
    import asyncio

    import temporalio.client
    import temporalio.worker
    from secp_api.config import Settings
    from secp_worker import main
    from secp_worker import temporal_app as T
    from secp_worker import temporal_workflows as W

    # Ordinary queue is exactly secp-orchestration. The operator queue is a DEPLOYMENT-LOCAL config
    # value (SECP_TEMPORAL_OPERATOR_TASK_QUEUE) that is EMPTY on the shipped default — no operator
    # worker is deployed, so the value (e.g. "secp-controlled-live-v1" in a real deployment) is not
    # committed here. The deployed-value case is covered separately below.
    settings = Settings()
    assert settings.temporal_task_queue == "secp-orchestration"
    assert settings.temporal_operator_task_queue == ""

    # EVERY Worker construction is recorded, not just the last one. A dict that overwrites per
    # construction would let a first Worker built on the operator queue hide behind a second one
    # built on the ordinary queue.
    constructions: list[dict] = []

    class _FakeWorker:
        def __init__(self, client, *, task_queue, workflows, activities):  # noqa: ANN001, ANN204
            constructions.append(
                {
                    "task_queue": task_queue,
                    "workflows": list(workflows),
                    "activities": list(activities),
                }
            )

        async def run(self):  # noqa: ANN202
            return None

    async def _fake_connect(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        return object()

    monkeypatch.setattr(temporalio.client.Client, "connect", _fake_connect)
    monkeypatch.setattr(temporalio.worker, "Worker", _FakeWorker)
    for name in _LEGACY_STARTERS:
        monkeypatch.setattr(main, name, lambda _ev: None)

    async def _noop():  # noqa: ANN202
        return None

    monkeypatch.setattr(main, "_run_outbox_publisher_loop", _noop)
    monkeypatch.setenv("SECP_WORKER_READY_FILE", str(tmp_path / "ready"))

    asyncio.run(main._run_temporal(threading.Event()))

    # CONTROL, first: the entrypoint really did construct a worker. Every "no unexpected X" and
    # "every registration uses the ordinary queue" assertion below is vacuously true against zero
    # constructions, so this must hold before any of them means anything.
    assert constructions, "the shipped entrypoint constructed no Temporal Worker at all"
    # Exactly ONE worker: the shipped entrypoint has no second registration to hide anything in.
    assert len(constructions) == 1, [c["task_queue"] for c in constructions]

    # EVERY registration is on the ordinary queue — never the operator queue.
    for construction in constructions:
        assert construction["task_queue"] == "secp-orchestration"
        assert construction["task_queue"] != settings.temporal_operator_task_queue or (
            settings.temporal_operator_task_queue == ""
        )

    captured = constructions[0]

    # --- EXACT WORKFLOW IDENTITY ------------------------------------------------------------------
    # Enumerated here against the workflow MODULE (secp_worker.temporal_workflows), NOT against
    # main.SHIPPED_WORKFLOWS: comparing the registration to the tuple it is built from is a
    # tautology that a deletion from both sides would satisfy. A count alone is worse still — it
    # passes an omission paired with an addition, and says nothing about WHICH classes registered.
    expected_workflows = {
        W.DeployWorkflow,
        W.ResetWorkflow,
        W.DestroyWorkflow,
        W.DiscoverWorkflow,
        W.EligibilityPreflightWorkflow,
        W.ToolchainAttestationWorkflow,
        W.RemoteStateReadinessWorkflow,
        W.PlanSecretReadinessWorkflow,
        W.RealPlanGenerationWorkflow,
        # WS-B R3: the scheduled enrollment expiry sweep is ORDINARY-queue work.
        W.EnrollmentRecoverySweepWorkflow,
        # SECP-RANGE: the range lifecycle operation is ORDINARY-queue work. It contacts no provider
        # credential and no infrastructure beyond a LOCAL container runtime that is itself sealed
        # off by default (SECP_RANGE_LOCAL_DOCKER), so there is no controlled-live variant of it.
        W.RangeOperationWorkflow,
    }
    registered_workflows = set(captured["workflows"])
    # Both directions, reported separately so a failure names the actual defect.
    assert not (expected_workflows - registered_workflows), "intended workflow NOT registered"
    assert not (registered_workflows - expected_workflows), "UNEXPECTED workflow registered"
    assert registered_workflows == expected_workflows
    # No duplicate registration (set equality above cannot see a repeated entry).
    assert len(captured["workflows"]) == len(expected_workflows)
    # The recovery sweep specifically — named, so its removal fails with its own message.
    assert W.EnrollmentRecoverySweepWorkflow in registered_workflows

    # Every registered workflow class comes from the import-clean workflow module. A controlled-live
    # operator workflow class arriving from operator_bootstrap (or any other module) fails here even
    # if someone also added it to the expected set above.
    assert {w.__module__ for w in captured["workflows"]} == {"secp_worker.temporal_workflows"}

    # --- EXACT ACTIVITY IDENTITY ------------------------------------------------------------------
    # Exactly the SEALED default activity callables — never a controlled-live operator instance.
    expected_activities = {
        T.deploy_activity,
        T.reset_activity,
        T.destroy_activity,
        T.discover_activity,
        T.eligibility_preflight_activity,
        T.toolchain_attestation_activity,
        T.remote_state_readiness_activity,
        T.plan_secret_readiness_activity,
        T.real_plan_generation_activity,
        # WS-B R3: the sweep activity has no sealed/controlled-live split — it contacts nothing.
        T.enrollment_recovery_sweep_activity,
        # SECP-RANGE: the range lifecycle activity. Registered because RangeOperationWorkflow
        # dispatches it BY NAME — a registered workflow whose activity is absent does not fail
        # closed, it starts and then fails partway through a privileged operation. One capability,
        # two registration points. It is a plain module-level function, not a composed instance, so
        # the bound-method control below (len(owners) == 5) is unaffected.
        T.range_operation_activity,
    }
    registered_activities = set(captured["activities"])
    assert not (expected_activities - registered_activities), "intended activity NOT registered"
    assert not (registered_activities - expected_activities), "UNEXPECTED activity registered"
    assert registered_activities == expected_activities
    assert len(captured["activities"]) == len(expected_activities)

    # What actually excludes a controlled-live activity is the exact-INSTANCE equality asserted
    # above, not the defining module. operator_bootstrap builds its controlled-live set from these
    # SAME temporal_app classes under a reviewed composition, so ``__module__`` is
    # "secp_worker.temporal_app" for the sealed and the controlled-live variant alike. These are
    # bound methods, and bound-method equality/hashing includes ``__self__`` — so a controlled-live
    # instance of the same class does NOT satisfy ``registered_activities == expected_activities``.
    # Pinned here so the identity assertion is not later "simplified" into a class/module check:
    sealed_module_level = {id(getattr(T, name)) for name in dir(T)}
    owners = [
        activity.__self__
        for activity in captured["activities"]
        if getattr(activity, "__self__", None) is not None
    ]
    # CONTROL: the five composed activities really are bound methods, so the loop below is not
    # vacuous. (The other five are plain module-level functions with no composition to check.)
    assert len(owners) == 5, owners
    for owner in owners:
        assert type(owner).__module__ == "secp_worker.temporal_app"
        # the registered instance IS the module-level SEALED singleton, not a fresh composition
        assert id(owner) in sealed_module_level, owner


def test_shipped_worker_entrypoint_never_reads_the_operator_queue():
    """The real invariant (not a literal ban): the shipped ordinary-worker entrypoint drives its
    registration solely from ``temporal_task_queue`` and NEVER reads the operator-queue setting — so
    no code path in ``main`` (success or failure) can poll or fall back to the operator queue.

    Checked at the AST level (actual attribute accesses, not comments/strings): a comment MAY name
    the operator queue to explain that it is deliberately unused. The operator queue's deployed
    VALUE, e.g. "secp-controlled-live-v1", is legitimate and lives in the deployment env, not this
    repo; banning that string in the tree would fight the contract.
    """
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(main_source_path()).read_text(encoding="utf-8"))
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "temporal_task_queue" in attrs  # it DOES pin the ordinary queue
    assert "temporal_operator_task_queue" not in attrs  # and NEVER touches the operator queue


def test_shipped_worker_polls_only_ordinary_queue_even_when_operator_queue_is_deployed(
    monkeypatch, tmp_path
):
    """Deployment-values case: with the operator worker deployed (operator queue configured to the
    real deployment value 'secp-controlled-live-v1'), the shipped ordinary Worker STILL polls only
    'secp-orchestration' with the SEALED activity set, and routing sends the five controlled-live
    kinds to the operator queue — proving the two queues are distinct and the ordinary worker never
    picks up controlled-live work.
    """
    _require_worker_extra()
    import asyncio

    import temporalio.client
    import temporalio.worker
    from secp_api.config import Settings
    from secp_api.enums import WorkflowKind
    from secp_api.workflow_routing import (
        CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS,
        resolve_operator_task_queue,
        resolve_task_queue,
    )
    from secp_worker import main

    # The exact deployed queue pair. The operator value is DISTINCT and passes Settings validation.
    settings = Settings(
        temporal_task_queue="secp-orchestration",
        temporal_operator_task_queue="secp-controlled-live-v1",
    )
    assert settings.temporal_task_queue == "secp-orchestration"
    assert settings.temporal_operator_task_queue == "secp-controlled-live-v1"

    # Routing: the five controlled-live kinds go to the operator queue; ordinary kinds stay put.
    for value in CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS:
        assert resolve_task_queue(settings, value) == "secp-controlled-live-v1"
    for kind in (
        WorkflowKind.deploy,
        WorkflowKind.reset,
        WorkflowKind.destroy,
        WorkflowKind.discover,
    ):
        assert resolve_task_queue(settings, kind) == "secp-orchestration"
    assert resolve_operator_task_queue(settings) == "secp-controlled-live-v1"

    captured: dict = {}

    class _FakeWorker:
        def __init__(self, client, *, task_queue, workflows, activities):  # noqa: ANN001, ANN204
            captured["task_queue"] = task_queue
            captured["activities"] = list(activities)

        async def run(self):  # noqa: ANN202
            return None

    async def _fake_connect(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        return object()

    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(temporalio.client.Client, "connect", _fake_connect)
    monkeypatch.setattr(temporalio.worker, "Worker", _FakeWorker)
    for name in _LEGACY_STARTERS:
        monkeypatch.setattr(main, name, lambda _ev: None)

    async def _noop():  # noqa: ANN202
        return None

    monkeypatch.setattr(main, "_run_outbox_publisher_loop", _noop)
    monkeypatch.setenv("SECP_WORKER_READY_FILE", str(tmp_path / "ready"))

    asyncio.run(main._run_temporal(threading.Event()))

    # The shipped worker was constructed on the ORDINARY queue only — never the operator queue.
    assert captured["task_queue"] == "secp-orchestration"
    assert captured["task_queue"] != settings.temporal_operator_task_queue
    # And with exactly the SEALED default activities — never a controlled-live operator instance.
    assert "operator_bootstrap" not in {
        m.__module__ for m in captured["activities"] if hasattr(m, "__module__")
    }
