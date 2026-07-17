"""Deterministic, workflow-safe Temporal workflow definitions (ADR-010, B1B).

**This module is RE-IMPORTED by Temporal's workflow sandbox during ``Worker`` validation** (the
sandbox imports each workflow class's ``__module__`` and everything that module imports). It
therefore
imports ONLY deterministic, workflow-safe code — the Temporal guard and the activity-name strings —
and NEVER an activity, adapter, HTTP client, SQLAlchemy/DB, provider, ``os``, ``uuid``, or any
``secp_api`` module.

Every workflow dispatches its activity BY NAME (a string), so no activity implementation module is
dragged into the sandbox. This is the STRUCTURAL fix for the PR5B worker-startup defect: previously
these workflows lived in :mod:`secp_worker.temporal_app` alongside the I/O-capable activity graph,
so
sandbox validation transited ``…→ secp_api.oidc → httpx → httpx/_models.py (class
_CookieCompatRequest(urllib.request.Request))`` and raised ``RestrictedWorkflowAccessError`` →
"Failed
validating workflow DeployWorkflow". The same nine classes are re-exported from ``temporal_app`` for
backward-compatible importers; their ``__module__`` stays ``secp_worker.temporal_workflows`` so the
sandbox only ever imports THIS clean module.

The shipped worker registers the SEALED activity instances under these names; a separately reviewed,
deployment-local operator worker registers CONTROLLED-LIVE instances under the SAME names on a
distinct
queue. The workflow neither knows nor cares which is served — it dispatches only the name string.
"""

from __future__ import annotations

from secp_worker.temporal_activity_names import (
    DEPLOY_ACTIVITY_NAME,
    DESTROY_ACTIVITY_NAME,
    DISCOVER_ACTIVITY_NAME,
    ELIGIBILITY_PREFLIGHT_ACTIVITY_NAME,
    PLAN_SECRET_READINESS_ACTIVITY_NAME,
    REAL_PLAN_GENERATION_ACTIVITY_NAME,
    REMOTE_STATE_READINESS_ACTIVITY_NAME,
    RESET_ACTIVITY_NAME,
    TOOLCHAIN_ATTESTATION_ACTIVITY_NAME,
)
from secp_worker.temporal_runtime import workflow


def _activity_timeout():  # noqa: ANN202 - timedelta imported lazily (kept out of module scope)
    from datetime import timedelta

    return timedelta(minutes=10)


@workflow.defn
class DeployWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            DEPLOY_ACTIVITY_NAME, arg, result_type=str, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class ResetWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            RESET_ACTIVITY_NAME, arg, result_type=str, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class DestroyWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            DESTROY_ACTIVITY_NAME, arg, result_type=str, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class DiscoverWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            DISCOVER_ACTIVITY_NAME, arg, result_type=str, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class EligibilityPreflightWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        # Dispatch BY the stable activity NAME, so the worker's registered instance (sealed on the
        # shipped worker, controlled-live on a reviewed operator worker) is served; the workflow
        # neither constructs nor imports the composition/provider.
        return await workflow.execute_activity(
            ELIGIBILITY_PREFLIGHT_ACTIVITY_NAME,
            arg,
            result_type=str,
            start_to_close_timeout=_activity_timeout(),
        )


@workflow.defn
class ToolchainAttestationWorkflow:
    """Durable, worker-only PR2 toolchain attestation (B1B-PR4 §1). It STOPS at the record.

    A hard PREREQUISITE of both readiness operations — and it triggers neither. It runs no OpenTofu.
    """

    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            TOOLCHAIN_ATTESTATION_ACTIVITY_NAME,
            arg,
            result_type=str,
            start_to_close_timeout=_activity_timeout(),
        )


@workflow.defn
class RemoteStateReadinessWorkflow:
    """Durable, worker-only remote-state readiness (B1B-PR4). It STOPS at readiness.

    It never dispatches a plan, an apply, or a destroy: completing readiness triggers nothing.
    """

    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            REMOTE_STATE_READINESS_ACTIVITY_NAME,
            arg,
            result_type=str,
            start_to_close_timeout=_activity_timeout(),
        )


@workflow.defn
class PlanSecretReadinessWorkflow:
    """Durable, worker-only plan-secret readiness (B1B-PR4). It STOPS at readiness.

    A SEPARATE operation from remote-state readiness: neither workflow invokes the other, and
    completing both never creates a plan.
    """

    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            PLAN_SECRET_READINESS_ACTIVITY_NAME,
            arg,
            result_type=str,
            start_to_close_timeout=_activity_timeout(),
        )


@workflow.defn
class RealPlanGenerationWorkflow:
    """Durable, worker-only real plan generation (B1B-PR5B, ADR-022).

    Every prerequisite readiness operation is a hard precondition, and this workflow triggers none
    of
    them. It dispatches the ``real_plan_generation_activity`` BY NAME (never constructing or
    importing
    a composition/provider). On the shipped worker the registered activity injects the SEALED
    composition, so the orchestration refuses at the composition gate before any OpenTofu,
    credential,
    workspace, or plan; on a reviewed operator worker it injects a controlled-live composition and
    the
    activity STOPS at a redacted change set + a pending human approval. Completing it authorizes NO
    apply and NO destroy — those seals are independent code constants that stay True.
    """

    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            REAL_PLAN_GENERATION_ACTIVITY_NAME,
            arg,
            result_type=str,
            start_to_close_timeout=_activity_timeout(),
        )
