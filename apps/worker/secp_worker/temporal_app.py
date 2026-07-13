"""Temporal workflow/activity definitions (durable path, ADR-010).

Requires the optional ``worker`` extra (``temporalio``) and a running Temporal
server. Activities wrap the SAME shared orchestration used by the inline
dispatcher, so there is one implementation of deploy/reset/destroy/discover —
Temporal only adds durability. Workflows/activities take plain dict args matching
``TemporalWorkflowRequest.args`` constructed by the dispatcher, so the API never
imports worker types.

Discovery is read-only and, in SECP-002A, never runs against a real endpoint.
"""

from __future__ import annotations

import uuid
from datetime import UTC

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


def _opt_uuid(value: str | None) -> uuid.UUID | None:
    return uuid.UUID(value) if value else None


@activity.defn
async def deploy_activity(arg: dict) -> str:
    from secp_api.db import session_scope

    from secp_worker.orchestration import run_deploy

    with session_scope() as session:
        run = run_deploy(
            session,
            uuid.UUID(arg["exercise_id"]),
            dispatch_mode="temporal",
            workflow_run_id=_opt_uuid(arg.get("workflow_run_id")),
        )
        return run.correlation_id


@activity.defn
async def reset_activity(arg: dict) -> str:
    from secp_api.db import session_scope

    from secp_worker.orchestration import run_reset

    with session_scope() as session:
        run = run_reset(
            session,
            uuid.UUID(arg["exercise_id"]),
            uuid.UUID(arg["instance_id"]),
            dispatch_mode="temporal",
            workflow_run_id=_opt_uuid(arg.get("workflow_run_id")),
        )
        return run.correlation_id


@activity.defn
async def destroy_activity(arg: dict) -> str:
    from secp_api.db import session_scope

    from secp_worker.orchestration import run_destroy

    with session_scope() as session:
        run = run_destroy(
            session,
            uuid.UUID(arg["exercise_id"]),
            dispatch_mode="temporal",
            workflow_run_id=_opt_uuid(arg.get("workflow_run_id")),
        )
        return run.correlation_id


@activity.defn
async def discover_activity(arg: dict) -> str:
    from secp_api.db import session_scope
    from secp_api.enums import WorkflowStatus
    from secp_api.models import ProviderInventorySnapshot, WorkflowRun

    from secp_worker.discovery import build_provider_plugin, run_discovery
    from secp_worker.secrets import EnvSecretResolver

    snapshot_id = uuid.UUID(arg["snapshot_id"])
    run_id = _opt_uuid(arg.get("workflow_run_id"))
    with session_scope() as session:
        snap = session.get(ProviderInventorySnapshot, snapshot_id)
        if snap is None:
            raise RuntimeError("snapshot not found")
        if run_id is not None:
            run = session.get(WorkflowRun, run_id)
            if run is not None:
                run.status = WorkflowStatus.running
        # Real secret resolution happens here, in the worker, just-in-time.
        plugin = build_provider_plugin(snap.plugin_name)
        run_discovery(session, snapshot_id, plugin=plugin, resolver=EnvSecretResolver())
        if run_id is not None:
            run = session.get(WorkflowRun, run_id)
            if run is not None:
                from datetime import datetime

                run.status = WorkflowStatus.completed
                run.finished_at = datetime.now(UTC)
        return str(snapshot_id)


def _cancelled() -> bool:
    """True only inside a real, cancelled Temporal activity; False without Temporal or in tests."""
    if not TEMPORAL_AVAILABLE:
        return False
    try:
        return bool(activity.is_cancelled())
    except Exception:
        return False


def _finish_run(session, run_id, now) -> None:
    from secp_api.enums import WorkflowStatus
    from secp_api.models import WorkflowRun

    if run_id is None:
        return
    run = session.get(WorkflowRun, run_id)
    if run is not None:
        run.status = WorkflowStatus.completed
        run.finished_at = now


def run_eligibility_preflight_activity_body(arg: dict) -> str:
    """Durable worker-owned read-only eligibility preflight body (sync core; the activity awaits).

    Loads the authoritative records from a FRESH worker session, resolves the current approved
    authorization + worker identity, checks cancellation / the deployment-local stop posture BEFORE
    any contact, then runs the sealed-by-default ``run_real_eligibility_preflight``. The shipped
    composition is fully sealed, so this durable path runs end to end but refuses at the seal before
    any transport/resolver/collector/target contact. Returns the closed outcome string.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    from secp_api import audit
    from secp_api.config import get_settings
    from secp_api.db import session_scope
    from secp_api.enums import AuditAction, EligibilityOutcome
    from secp_api.models import TargetOnboarding, WorkflowRun

    from secp_worker.onboarding.eligibility_preflight import (
        build_eligibility_composition,
        resolve_eligibility_preflight_request,
        run_real_eligibility_preflight,
    )

    onboarding_id = _uuid.UUID(arg["onboarding_id"])
    run_id = _opt_uuid(arg.get("workflow_run_id"))
    now = datetime.now(UTC)

    with session_scope() as session:
        if run_id is not None:
            run = session.get(WorkflowRun, run_id)
            if run is not None:
                from secp_api.enums import WorkflowStatus

                run.status = WorkflowStatus.running

        ob = session.get(TargetOnboarding, onboarding_id)
        if ob is None:
            _finish_run(session, run_id, now)
            return EligibilityOutcome.refused.value
        org_id = ob.organization_id

        def _refuse(reason: str) -> str:
            audit.record(
                session,
                action=AuditAction.eligibility_preflight_refused,
                resource_type="target_onboarding",
                resource_id=onboarding_id,
                organization_id=org_id,
                actor="worker",
                outcome="refused",
                data={"reason_category": reason, "onboarding_id": str(onboarding_id)},
            )
            _finish_run(session, run_id, now)
            return EligibilityOutcome.refused.value

        # Cancellation / deployment-local stop posture is checked BEFORE any contact or record work.
        if _cancelled():
            return _refuse("emergency_stop")

        request, reason = resolve_eligibility_preflight_request(session, onboarding_id, now)
        if request is None:
            return _refuse(reason.value if reason is not None else "gate_incomplete")

        # Re-check cancellation immediately before invoking the seam (its only contact is deep
        # inside, and is itself sealed by the default composition).
        if _cancelled():
            return _refuse("emergency_stop")

        result = run_real_eligibility_preflight(
            session,
            request=request,
            composition=build_eligibility_composition(get_settings()),
            now=now,
        )
        _finish_run(session, run_id, now)
        return result.outcome


@activity.defn
async def eligibility_preflight_activity(arg: dict) -> str:
    return run_eligibility_preflight_activity_body(arg)


def _activity_timeout():
    from datetime import timedelta

    return timedelta(minutes=10)


@workflow.defn
class DeployWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            deploy_activity, arg, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class ResetWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            reset_activity, arg, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class DestroyWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            destroy_activity, arg, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class DiscoverWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            discover_activity, arg, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class EligibilityPreflightWorkflow:
    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            eligibility_preflight_activity, arg, start_to_close_timeout=_activity_timeout()
        )
