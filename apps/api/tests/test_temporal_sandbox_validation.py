"""Test A — the production Temporal workflow set validates under the DEFAULT sandboxed runner.

PR5B worker-startup hotfix. On the BASE commit these FAIL: the 9 workflow classes lived in
``secp_worker.temporal_app``, whose module scope imported the sealed providers →
``secp_worker.readiness`` → ``secp_api.readiness_binding`` → ``services.eligibility`` → ``auth`` →
``oidc`` → ``httpx`` → ``httpx/_models.py`` (``class
_CookieCompatRequest(urllib.request.Request)``).
Temporal's workflow sandbox re-imports each workflow class's ``__module__`` during ``Worker``
validation and restricts ``urllib.request.Request``, so validation raised "Failed validating
workflow
DeployWorkflow". After the fix the workflows live in the import-clean
``secp_worker.temporal_workflows``
and dispatch activities BY NAME, so nothing I/O-capable enters the sandbox.

These tests do NOT replace the default runner with an unsandboxed one.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

# --- the worker extra must be PRESENT, not optional, for this file -------------------------------
#
# Every seal assertion below is gated on ``temporalio``. Without the ``worker`` extra installed they
# do not fail — they SKIP, and a skipped seal check reads exactly like a passing one. That is not
# hypothetical here: this repository already lost ``temporalio`` for months while seven tests
# reported as passing without ever executing, and the sealed-set assertions in this file were
# verified by hand in a worktree where they were silently skipping.
#
# CI proves the extra is present for the shards ("Prove the worker extra is actually present (no
# silent re-skip)") and fails any shard skip whose reason is ``could not import 'x'``. Nothing
# enforced it for someone running THIS FILE by hand, which is the exact path that nearly reported a
# pass. So the import is hard: an absent extra fails loudly at collection instead of shrinking the
# run. The fix is one command — ``uv sync --frozen --extra dev --extra worker``.
#
# The per-test ``pytest.importorskip("temporalio")`` calls below can therefore no longer mask an
# absent extra; they are left in place as belt-and-braces, not as a live skip path.
try:
    import temporalio as _require_worker_extra  # noqa: F401
except ModuleNotFoundError as _exc:  # pragma: no cover - the whole point is that this is loud
    raise RuntimeError(
        "the 'worker' extra is not installed, so the sealed-set assertions in this file would "
        "SKIP rather than run — and a skipped seal check is indistinguishable from a passing one. "
        "Install it with: uv sync --frozen --extra dev --extra worker"
    ) from _exc

WORKFLOW_NAMES = (
    "DeployWorkflow",
    "ResetWorkflow",
    "DestroyWorkflow",
    "DiscoverWorkflow",
    "EligibilityPreflightWorkflow",
    "ToolchainAttestationWorkflow",
    "RemoteStateReadinessWorkflow",
    "PlanSecretReadinessWorkflow",
    "RealPlanGenerationWorkflow",
    # WS-B R3: the scheduled enrollment expiry sweep. It must satisfy the SAME sandbox rule as every
    # other workflow — dispatch by activity NAME only, so nothing I/O-capable enters the sandbox.
    "EnrollmentRecoverySweepWorkflow",
    # SECP-RANGE: the range lifecycle operation. Privileged Docker execution must be dispatched to
    # the worker (Charter Invariants 6/7, ADR-005), and a worker cannot run a workflow the sealed
    # set does not name. Same sandbox rule as the rest — it dispatches its activity BY NAME, so
    # nothing I/O-capable enters the sandbox.
    "RangeOperationWorkflow",
)


def test_workflow_module_import_is_clean_in_a_fresh_process():
    """Importing the sandbox-imported module must drag in NO httpx / urllib.request / secp_api.

    Run in a fresh subprocess so nothing another test already imported can mask a leak. This is the
    exact heavy chain that broke sandbox validation; a regression that re-couples the workflows to
    the
    activity graph makes this fail. (No temporalio needed — the guard falls back to a stub.)
    """
    code = (
        "import sys, secp_worker.temporal_workflows;"
        "bad=sorted(m for m in sys.modules "
        "if m in ('httpx','urllib.request') or m.split('.')[0]=='secp_api');"
        "print(repr(bad));"
        "assert bad==[], bad"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]", result.stdout


def test_every_production_workflow_validates_under_the_default_sandbox():
    """The exact production registration list validates under the DEFAULT sandbox — DeployWorkflow
    (which raised at base) and every later workflow."""
    pytest.importorskip("temporalio")
    import asyncio

    from secp_worker.main import SHIPPED_WORKFLOWS
    from temporalio import workflow as tw
    from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner

    assert len(SHIPPED_WORKFLOWS) == len(WORKFLOW_NAMES)

    async def _validate() -> None:
        runner = SandboxedWorkflowRunner()  # the DEFAULT sandboxed runner (never unsandboxed)
        for wf in SHIPPED_WORKFLOWS:
            # This is the exact validation step that raised RestrictedWorkflowAccessError at base.
            runner.prepare_workflow(tw._Definition.must_from_class(wf))
            assert wf.__module__ == "secp_worker.temporal_workflows", wf.__module__

    asyncio.run(_validate())  # prepare_workflow requires a running event loop


def test_workflow_classes_live_in_the_clean_workflow_module():
    from secp_worker import temporal_app, temporal_workflows

    for name in WORKFLOW_NAMES:
        cls = getattr(temporal_workflows, name)
        assert cls.__module__ == "secp_worker.temporal_workflows"
        # temporal_app re-exports the SAME class object (backward compat), unchanged __module__.
        assert getattr(temporal_app, name) is cls
