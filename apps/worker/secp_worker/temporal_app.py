"""Temporal workflow/activity definitions (production-shaped path, ADR-005).

Wired but not exercised in CI. Requires the optional ``worker`` extra
(``temporalio``) and a running Temporal server. Activities wrap the SAME shared
orchestration used by the inline dispatcher, so there is one implementation of
deploy/reset/destroy — Temporal only adds durability.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

try:  # temporalio is an optional dependency (the 'worker' extra).
    from temporalio import activity, workflow

    TEMPORAL_AVAILABLE = True
except Exception:  # pragma: no cover - import guard
    TEMPORAL_AVAILABLE = False

    class _Stub:
        def defn(self, *a, **k):  # type: ignore[no-untyped-def]
            def deco(cls):
                return cls

            return deco

        def __getattr__(self, _name):  # type: ignore[no-untyped-def]
            def deco(fn=None, **_k):
                return fn if fn else (lambda f: f)

            return deco

    activity = workflow = _Stub()  # type: ignore[assignment]


@dataclass
class DeployInput:
    exercise_id: str


@dataclass
class ResetInput:
    exercise_id: str
    instance_id: str


@dataclass
class DestroyInput:
    exercise_id: str


@activity.defn
async def deploy_activity(arg: DeployInput) -> str:
    from secp_api.db import session_scope

    from secp_worker.orchestration import run_deploy

    with session_scope() as session:
        run = run_deploy(session, uuid.UUID(arg.exercise_id), dispatch_mode="temporal")
        return run.correlation_id


@activity.defn
async def reset_activity(arg: ResetInput) -> str:
    from secp_api.db import session_scope

    from secp_worker.orchestration import run_reset

    with session_scope() as session:
        run = run_reset(
            session,
            uuid.UUID(arg.exercise_id),
            uuid.UUID(arg.instance_id),
            dispatch_mode="temporal",
        )
        return run.correlation_id


@activity.defn
async def destroy_activity(arg: DestroyInput) -> str:
    from secp_api.db import session_scope

    from secp_worker.orchestration import run_destroy

    with session_scope() as session:
        run = run_destroy(session, uuid.UUID(arg.exercise_id), dispatch_mode="temporal")
        return run.correlation_id


@workflow.defn
class DeployWorkflow:
    @workflow.run
    async def run(self, arg: DeployInput) -> str:  # pragma: no cover - needs Temporal
        from datetime import timedelta

        return await workflow.execute_activity(
            deploy_activity, arg, start_to_close_timeout=timedelta(minutes=10)
        )


@workflow.defn
class ResetWorkflow:
    @workflow.run
    async def run(self, arg: ResetInput) -> str:  # pragma: no cover - needs Temporal
        from datetime import timedelta

        return await workflow.execute_activity(
            reset_activity, arg, start_to_close_timeout=timedelta(minutes=10)
        )


@workflow.defn
class DestroyWorkflow:
    @workflow.run
    async def run(self, arg: DestroyInput) -> str:  # pragma: no cover - needs Temporal
        from datetime import timedelta

        return await workflow.execute_activity(
            destroy_activity, arg, start_to_close_timeout=timedelta(minutes=10)
        )
