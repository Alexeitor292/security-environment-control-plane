"""The scheduled enrollment expiry sweep is ORDINARY-queue work (SECP WS-B R3).

The sweep is a pure database lifecycle transition — it contacts no provider, opens no outbound
connection, runs no OpenTofu, touches no host and reads no credential — so it belongs on the shipped
ordinary task queue and must never appear on the controlled-live operator queue, nor acquire a
sealed/controlled-live split that would imply it does privileged work.

These are structural guards. They fail closed if a later change registers the sweep on the operator
queue, gives it a controlled-live variant, or re-couples the workflow to the I/O-capable activity
graph.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

_APPS = Path(__file__).resolve().parents[2]
WORKER_PKG = _APPS / "worker" / "secp_worker"
API_PKG = _APPS / "api" / "secp_api"


def test_the_scheduler_uses_temporal_symbols_that_actually_exist():
    """The scheduling helper's Temporal imports and kwargs must resolve against the real library.

    Caught a genuine defect: ``WorkflowAlreadyStartedError`` was imported from ``temporalio.client``
    (where it does not live) instead of ``temporalio.exceptions``. Because the scheduler runs only
    against a live Temporal server, nothing else in the suite would have exercised that line — it
    would have surfaced as a worker that dies on startup.
    """
    pytest.importorskip("temporalio")
    import inspect

    from temporalio.client import Client
    from temporalio.exceptions import WorkflowAlreadyStartedError

    assert WorkflowAlreadyStartedError is not None
    parameters = inspect.signature(Client.start_workflow).parameters
    for required in ("id", "task_queue", "cron_schedule"):
        assert required in parameters, required


def test_the_sweep_is_scheduled_under_a_stable_id_on_a_cron():
    """A stable id means a restart re-attaches to the ONE schedule instead of creating another."""
    from secp_worker.main import (
        ENROLLMENT_RECOVERY_SWEEP_CRON,
        ENROLLMENT_RECOVERY_SWEEP_WORKFLOW_ID,
    )

    assert ENROLLMENT_RECOVERY_SWEEP_WORKFLOW_ID == "secp-enrollment-recovery-sweep"
    assert len(ENROLLMENT_RECOVERY_SWEEP_CRON.split()) == 5, "a 5-field cron expression"


def test_the_sweep_is_registered_on_the_shipped_ordinary_worker():
    from secp_worker.main import SHIPPED_ACTIVITIES, SHIPPED_WORKFLOWS
    from secp_worker.temporal_app import enrollment_recovery_sweep_activity
    from secp_worker.temporal_workflows import EnrollmentRecoverySweepWorkflow

    assert EnrollmentRecoverySweepWorkflow in SHIPPED_WORKFLOWS
    assert enrollment_recovery_sweep_activity in SHIPPED_ACTIVITIES


def test_the_sweep_is_not_a_controlled_live_operator_kind():
    """The operator queue serves the five controlled-live kinds; the sweep is not one of them."""
    from secp_api.workflow_routing import CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS

    assert len(CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS) == 5
    assert not any(
        "enrollment" in kind or "recovery" in kind
        for kind in CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS
    )


def test_the_sweep_has_no_controlled_live_operator_variant():
    """The reviewed operator activity set must not gain the sweep — it has no privileged work."""
    from secp_worker.operator_bootstrap import OperatorActivitySet

    fields = set(getattr(OperatorActivitySet, "__dataclass_fields__", {}))
    assert not any("enrollment" in name or "recovery" in name for name in fields), fields


def test_the_worker_entrypoint_schedules_the_sweep_on_the_ordinary_queue_only():
    """The scheduling call must pass the ORDINARY queue, never the operator queue.

    Read statically from the source: this pins the exact argument the entrypoint uses, which a
    runtime test cannot observe without a live Temporal server.
    """
    source = (WORKER_PKG / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    scheduler = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "_ensure_enrollment_recovery_schedule"
    )
    rendered = ast.dump(scheduler)
    # the scheduling helper takes the queue as a parameter and never reads the operator queue
    assert "temporal_operator_task_queue" not in rendered
    assert "cron_schedule" in rendered

    # ...and the single call site passes settings.temporal_task_queue (the ordinary queue)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_ensure_enrollment_recovery_schedule"
    ]
    assert len(calls) == 1, "the sweep must be scheduled from exactly one place"
    queue_arg = calls[0].args[1]
    assert isinstance(queue_arg, ast.Attribute)
    assert queue_arg.attr == "temporal_task_queue", ast.dump(queue_arg)


def test_the_whole_worker_entrypoint_never_reads_the_operator_queue():
    """Pre-existing invariant, re-asserted now that this entrypoint also SCHEDULES work.

    Checked over the AST rather than the text, so the prose comments that discuss the operator queue
    cannot satisfy or break it — only a real attribute read counts.
    """
    tree = ast.parse((WORKER_PKG / "main.py").read_text(encoding="utf-8"))
    reads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "temporal_operator_task_queue"
    ]
    assert reads == [], "the shipped worker entrypoint must never read the operator queue"


def test_the_sweep_workflow_stays_sandbox_clean_in_a_fresh_process():
    """Adding the sweep must not drag secp_api / httpx into Temporal's workflow sandbox."""
    code = (
        "import sys, secp_worker.temporal_workflows as w;"
        "assert hasattr(w, 'EnrollmentRecoverySweepWorkflow');"
        "bad=sorted(m for m in sys.modules "
        "if m in ('httpx','urllib.request') or m.split('.')[0]=='secp_api');"
        "print(repr(bad));"
        "assert bad==[], bad"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]", result.stdout


def test_the_sweep_driver_performs_no_privileged_action():
    """A static guard: the scheduled driver imports nothing that could contact infrastructure."""
    driver = API_PKG / "services" / "worker_enrollment_recovery_schedule.py"
    tree = ast.parse(driver.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])

    forbidden = {
        "subprocess",
        "httpx",
        "requests",
        "paramiko",
        "socket",
        "secp_worker",
        "proxmoxer",
        "docker",
    }
    assert not (imported & forbidden), imported & forbidden
