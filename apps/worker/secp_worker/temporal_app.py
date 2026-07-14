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


def run_toolchain_attestation_activity_body(arg: dict) -> str:
    """Durable worker-owned PR2 toolchain attestation (B1B-PR4 §1). It STOPS at the record.

    The Temporal argument carries ONLY a manifest id + the workflow-run id — never a path, a layout,
    a digest, or an environment. The reviewed deployment-local filesystem LAYOUT comes exclusively
    from the worker's own composition, which is **sealed by default**: the shipped runtime therefore
    refuses at the seal and reads no disk.

    It executes no binary, opens no socket, loads no provider, renders no workspace, and constructs
    no ``OpenTofuRunner``, process executor, or activation grant.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    from secp_api.config import get_settings
    from secp_api.db import session_scope
    from secp_api.enums import ToolchainAttestationOutcome, WorkflowStatus
    from secp_api.models import ProvisioningManifest, WorkflowRun

    from secp_worker.readiness.composition import build_readiness_composition
    from secp_worker.readiness.toolchain_attestation import run_toolchain_attestation

    manifest_id = _uuid.UUID(arg["manifest_id"])
    run_id = _opt_uuid(arg.get("workflow_run_id"))
    now = datetime.now(UTC)
    failed = ToolchainAttestationOutcome.failed.value

    with session_scope() as session:
        if run_id is not None:
            run = session.get(WorkflowRun, run_id)
            if run is not None:
                run.status = WorkflowStatus.running

        manifest = session.get(ProvisioningManifest, manifest_id)
        if manifest is None or manifest.toolchain_profile_id is None or _cancelled():
            _finish_run(session, run_id, now)
            return failed

        composition = build_readiness_composition(get_settings())
        result = run_toolchain_attestation(
            session,
            toolchain_profile_id=manifest.toolchain_profile_id,
            layout=composition.toolchain_layout,
            now=now,
        )
        _finish_run(session, run_id, now)
        return result.outcome


@activity.defn
async def toolchain_attestation_activity(arg: dict) -> str:
    return run_toolchain_attestation_activity_body(arg)


def _run_readiness_activity_body(arg: dict, *, kind: str) -> str:
    """Durable worker-owned readiness body (sync core; the activity awaits).

    Opens a FRESH worker session and loads every authoritative record itself — the Temporal argument
    carries ONLY a manifest id and the workflow-run id (no endpoint, backend reference, backend
    kind,
    state key, namespace, secret reference, credential, target config, evidence payload, or adapter
    configuration). Cancellation / the deployment-local stop posture is checked BEFORE any contact.

    The shipped composition is fully **sealed**, so this durable path runs end to end but refuses at
    the seal before any state backend or secret manager is contacted. Returns the closed outcome.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    from secp_api import audit
    from secp_api.config import get_settings
    from secp_api.db import session_scope
    from secp_api.enums import (
        AuditAction,
        PlanSecretReadinessOutcome,
        RemoteStateReadinessOutcome,
        WorkflowStatus,
    )
    from secp_api.models import ProvisioningManifest, WorkflowRun

    from secp_worker.readiness.composition import build_readiness_composition
    from secp_worker.readiness.plan_secret_readiness import run_plan_secret_readiness
    from secp_worker.readiness.state_readiness import run_remote_state_readiness

    is_state = kind == "remote_state_readiness"
    refused = (
        RemoteStateReadinessOutcome.refused.value
        if is_state
        else PlanSecretReadinessOutcome.refused.value
    )
    refused_action = (
        AuditAction.remote_state_readiness_refused
        if is_state
        else AuditAction.plan_secret_readiness_refused
    )

    manifest_id = _uuid.UUID(arg["manifest_id"])
    run_id = _opt_uuid(arg.get("workflow_run_id"))
    now = datetime.now(UTC)

    with session_scope() as session:
        if run_id is not None:
            run = session.get(WorkflowRun, run_id)
            if run is not None:
                run.status = WorkflowStatus.running

        manifest = session.get(ProvisioningManifest, manifest_id)
        if manifest is None:
            _finish_run(session, run_id, now)
            return refused
        org_id = manifest.organization_id

        def _refuse(reason: str) -> str:
            audit.record(
                session,
                action=refused_action,
                resource_type="provisioning_manifest",
                resource_id=manifest_id,
                organization_id=org_id,
                actor="worker",
                outcome="refused",
                data={
                    "operation_kind": kind,
                    "provisioning_manifest_id": str(manifest_id),
                    "reason_code": reason,
                },
            )
            _finish_run(session, run_id, now)
            return refused

        # Cancellation / the deployment-local stop posture is checked BEFORE any contact.
        if _cancelled():
            return _refuse("operation_cancelled")

        composition = build_readiness_composition(get_settings())

        # Re-check cancellation immediately before invoking the seam (its only external contact is
        # deep inside, and is itself sealed by the default composition).
        if _cancelled():
            return _refuse("operation_cancelled")

        if is_state:
            state_result = run_remote_state_readiness(
                session, manifest_id=manifest_id, composition=composition, now=now
            )
            _finish_run(session, run_id, now)
            return state_result.outcome
        secret_result = run_plan_secret_readiness(
            session, manifest_id=manifest_id, composition=composition, now=now
        )
        _finish_run(session, run_id, now)
        return secret_result.outcome


def run_remote_state_readiness_activity_body(arg: dict) -> str:
    return _run_readiness_activity_body(arg, kind="remote_state_readiness")


def run_plan_secret_readiness_activity_body(arg: dict) -> str:
    return _run_readiness_activity_body(arg, kind="plan_secret_readiness")


@activity.defn
async def remote_state_readiness_activity(arg: dict) -> str:
    return run_remote_state_readiness_activity_body(arg)


@activity.defn
async def plan_secret_readiness_activity(arg: dict) -> str:
    return run_plan_secret_readiness_activity_body(arg)


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


@workflow.defn
class ToolchainAttestationWorkflow:
    """Durable, worker-only PR2 toolchain attestation (B1B-PR4 §1). It STOPS at the record.

    A hard PREREQUISITE of both readiness operations — and it triggers neither. It runs no OpenTofu.
    """

    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            toolchain_attestation_activity, arg, start_to_close_timeout=_activity_timeout()
        )


@workflow.defn
class RemoteStateReadinessWorkflow:
    """Durable, worker-only remote-state readiness (B1B-PR4). It STOPS at readiness.

    It never dispatches a plan, an apply, or a destroy: completing readiness triggers nothing.
    """

    @workflow.run
    async def run(self, arg: dict) -> str:  # pragma: no cover - needs Temporal
        return await workflow.execute_activity(
            remote_state_readiness_activity, arg, start_to_close_timeout=_activity_timeout()
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
            plan_secret_readiness_activity, arg, start_to_close_timeout=_activity_timeout()
        )
