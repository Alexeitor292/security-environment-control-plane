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

# Worker-bootstrap composition providers. Importing the SEALED defaults here (never a live provider)
# lets the shipped worker construct its default, always-sealed activity instances at import time.
from secp_worker.onboarding.eligibility_provider import (  # noqa: E402 - after the temporal guard
    SealedEligibilityCompositionProvider,
)
from secp_worker.plan_gen.composition_provider import (  # noqa: E402 - after the temporal guard
    SealedPlanExecutionCompositionProvider,
)
from secp_worker.readiness.composition_provider import (  # noqa: E402 - after the temporal guard
    SealedReadinessCompositionProvider,
)

# The Temporal guard is defined ONCE in a shared, import-clean module, and the stable activity NAMES
# come from another. This module (temporal_app) is HOST-ONLY: it holds the I/O-capable activities
# and
# is NEVER imported by Temporal's workflow sandbox — the workflows live in the import-clean
# secp_worker.temporal_workflows (which dispatches by these same NAME strings). This split is the
# structural fix for the PR5B worker-startup sandbox failure (httpx -> urllib.request.Request).
from secp_worker.temporal_activity_names import (  # noqa: E402 - after the temporal guard
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
from secp_worker.temporal_runtime import TEMPORAL_AVAILABLE, activity  # noqa: E402


def _opt_uuid(value: str | None) -> uuid.UUID | None:
    return uuid.UUID(value) if value else None


# The stable activity NAME constants are imported above from secp_worker.temporal_activity_names
# (the
# single source of truth). Each activity registers UNDER its exact name and the workflow dispatches
# BY that same name — so the shipped SEALED instance or a reviewed operator worker's CONTROLLED-LIVE
# instance is served identically. The four legacy names equal the original implicit function names,
# so pinning ``name=`` below changes no registration.


@activity.defn(name=DEPLOY_ACTIVITY_NAME)
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


@activity.defn(name=RESET_ACTIVITY_NAME)
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


@activity.defn(name=DESTROY_ACTIVITY_NAME)
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


@activity.defn(name=DISCOVER_ACTIVITY_NAME)
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


def run_eligibility_preflight_activity_body(arg: dict, *, eligibility_provider) -> str:  # noqa: ANN001
    """Durable worker-owned read-only eligibility preflight body (sync core; the activity awaits).

    Loads the authoritative records from a FRESH worker session, resolves the current approved
    authorization + worker identity, checks cancellation / the deployment-local stop posture BEFORE
    any contact, then runs ``run_real_eligibility_preflight`` with the composition obtained
    EXCLUSIVELY
    from the injected ``eligibility_provider``. The shipped worker injects the sealed provider, so
    this
    durable path runs end to end but refuses at the seal before any
    transport/resolver/collector/target
    contact. A separately reviewed operator worker injects a controlled-live provider. Returns the
    closed outcome string.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    from secp_api import audit
    from secp_api.db import session_scope
    from secp_api.enums import AuditAction, EligibilityOutcome
    from secp_api.models import TargetOnboarding, WorkflowRun

    from secp_worker.onboarding.eligibility_preflight import (
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
            composition=eligibility_provider.get(),
            now=now,
        )
        _finish_run(session, run_id, now)
        return result.outcome


class EligibilityPreflightActivity:
    """Class-based Temporal activity with a constructor-injected eligibility composition provider.

    The shipped worker constructs it with the SEALED provider (below); a reviewed operator worker
    constructs it with a controlled-live provider via the operator bootstrap factory. The registered
    activity NAME is stable regardless of which provider is injected.
    """

    def __init__(self, eligibility_provider) -> None:  # noqa: ANN001
        if eligibility_provider is None:
            raise ValueError("eligibility_provider is required")
        self._eligibility_provider = eligibility_provider

    @activity.defn(name=ELIGIBILITY_PREFLIGHT_ACTIVITY_NAME)
    async def run(self, arg: dict) -> str:
        return run_eligibility_preflight_activity_body(
            arg, eligibility_provider=self._eligibility_provider
        )


def run_toolchain_attestation_activity_body(arg: dict, *, readiness_provider) -> str:  # noqa: ANN001
    """Durable worker-owned PR2 toolchain attestation (B1B-PR4 §1). It STOPS at the record.

    The Temporal argument carries ONLY a manifest id + the workflow-run id — never a path, a layout,
    a digest, or an environment. The reviewed deployment-local filesystem LAYOUT comes exclusively
    from the composition obtained from the injected ``readiness_provider``, which is the SEALED
    provider on the shipped worker: the shipped runtime therefore refuses at the seal and reads no
    disk. A reviewed operator worker injects a controlled-live provider.

    It executes no binary, opens no socket, loads no provider, renders no workspace, and constructs
    no ``OpenTofuRunner``, process executor, or activation grant.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    from secp_api.db import session_scope
    from secp_api.enums import ToolchainAttestationOutcome, WorkflowStatus
    from secp_api.models import ProvisioningManifest, WorkflowRun

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

        composition = readiness_provider.get()
        result = run_toolchain_attestation(
            session,
            toolchain_profile_id=manifest.toolchain_profile_id,
            layout=composition.toolchain_layout,
            now=now,
        )
        _finish_run(session, run_id, now)
        return result.outcome


class ToolchainAttestationActivity:
    """Class-based Temporal activity with a constructor-injected readiness composition provider."""

    def __init__(self, readiness_provider) -> None:  # noqa: ANN001
        if readiness_provider is None:
            raise ValueError("readiness_provider is required")
        self._readiness_provider = readiness_provider

    @activity.defn(name=TOOLCHAIN_ATTESTATION_ACTIVITY_NAME)
    async def run(self, arg: dict) -> str:
        return run_toolchain_attestation_activity_body(
            arg, readiness_provider=self._readiness_provider
        )


def _run_readiness_activity_body(arg: dict, *, kind: str, readiness_provider) -> str:  # noqa: ANN001
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
    from secp_api.db import session_scope
    from secp_api.enums import (
        AuditAction,
        PlanSecretReadinessOutcome,
        RemoteStateReadinessOutcome,
        WorkflowStatus,
    )
    from secp_api.models import ProvisioningManifest, WorkflowRun

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

        composition = readiness_provider.get()

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


def run_remote_state_readiness_activity_body(arg: dict, *, readiness_provider) -> str:  # noqa: ANN001
    return _run_readiness_activity_body(
        arg, kind="remote_state_readiness", readiness_provider=readiness_provider
    )


def run_plan_secret_readiness_activity_body(arg: dict, *, readiness_provider) -> str:  # noqa: ANN001
    return _run_readiness_activity_body(
        arg, kind="plan_secret_readiness", readiness_provider=readiness_provider
    )


class RemoteStateReadinessActivity:
    """Class-based Temporal activity with a constructor-injected readiness composition provider.

    A SEPARATE authority from plan-secret readiness: it uses only the composition's state adapter +
    state activation. It never triggers plan-secret readiness or plan generation.
    """

    def __init__(self, readiness_provider) -> None:  # noqa: ANN001
        if readiness_provider is None:
            raise ValueError("readiness_provider is required")
        self._readiness_provider = readiness_provider

    @activity.defn(name=REMOTE_STATE_READINESS_ACTIVITY_NAME)
    async def run(self, arg: dict) -> str:
        return run_remote_state_readiness_activity_body(
            arg, readiness_provider=self._readiness_provider
        )


class PlanSecretReadinessActivity:
    """Class-based Temporal activity with a constructor-injected readiness composition provider.

    A SEPARATE authority from remote-state readiness: it uses only the composition's resolver
    self-test + plan-secret activation. It never triggers remote-state readiness or plan generation.
    """

    def __init__(self, readiness_provider) -> None:  # noqa: ANN001
        if readiness_provider is None:
            raise ValueError("readiness_provider is required")
        self._readiness_provider = readiness_provider

    @activity.defn(name=PLAN_SECRET_READINESS_ACTIVITY_NAME)
    async def run(self, arg: dict) -> str:
        return run_plan_secret_readiness_activity_body(
            arg, readiness_provider=self._readiness_provider
        )


def run_real_plan_generation_activity_body(arg: dict, *, composition_provider) -> str:  # noqa: ANN001
    """Durable worker-owned real-plan-generation body (B1B-PR5B, ADR-022 §11).

    Opens a FRESH worker session and re-derives the complete authoritative binding itself — the
    Temporal argument carries ONLY a manifest id and the workflow-run id (no composition, endpoint,
    credential, secret reference, dossier payload, authorization token, capability, or path). It
    obtains the :class:`PlanExecutionComposition` EXCLUSIVELY from the injected
    ``composition_provider``
    and passes it to ``run_plan_generation``. The shipped worker injects the SEALED provider, so the
    orchestration refuses at the composition gate before any
    filesystem/render/resolver/secret/process
    and NEVER returns ``completed``; a separately reviewed operator worker injects a controlled-live
    provider. Returns the closed outcome string.
    """
    import uuid as _uuid
    from datetime import UTC, datetime

    from secp_api.db import session_scope
    from secp_api.enums import PlanGenerationAttemptStatus, WorkflowStatus
    from secp_api.models import WorkflowRun

    from secp_worker.plan_gen.orchestration import run_plan_generation

    manifest_id = _uuid.UUID(arg["manifest_id"])
    run_id = _opt_uuid(arg.get("workflow_run_id"))
    now = datetime.now(UTC)

    with session_scope() as session:
        if run_id is not None:
            run = session.get(WorkflowRun, run_id)
            if run is not None:
                run.status = WorkflowStatus.running

        # Cancellation / the deployment-local stop posture is checked BEFORE the composition is even
        # obtained from the provider, and BEFORE any authoritative load.
        if _cancelled():
            _finish_run(session, run_id, now)
            return PlanGenerationAttemptStatus.refused.value

        composition = composition_provider.get()
        result = run_plan_generation(
            session, manifest_id=manifest_id, composition=composition, now=now
        )
        _finish_run(session, run_id, now)
        return result.outcome


class RealPlanGenerationActivity:
    """Class-based Temporal activity with a constructor-injected plan-execution composition
    provider.

    This is the seam through which a separately reviewed operator worker injects the controlled-live
    :class:`PlanExecutionComposition` into the EXISTING durable activity — without any manual direct
    ``run_plan_generation(..., composition=...)`` invocation. The shipped worker constructs it with
    the SEALED provider (below); the operator bootstrap constructs it with a controlled-live
    provider. The registered activity NAME is stable regardless of which provider is injected, and
    the composition never enters a Temporal argument (it is held here as instance state).
    """

    def __init__(self, composition_provider) -> None:  # noqa: ANN001
        if composition_provider is None:
            raise ValueError("composition_provider is required")
        self._composition_provider = composition_provider

    @activity.defn(name=REAL_PLAN_GENERATION_ACTIVITY_NAME)
    async def run(self, arg: dict) -> str:
        return run_real_plan_generation_activity_body(
            arg, composition_provider=self._composition_provider
        )


# --- The DEFAULT activities the SHIPPED (sealed-by-default) worker registers
# -----------------------
# Each is constructed with its SEALED provider, so ordinary worker startup refuses at the
# composition/seam gate before any I/O. These are IMMUTABLE default instances — never a mutable
# module-global composition, never monkeypatched, never a service locator. A reviewed operator
# worker
# builds its OWN instances via ``secp_worker.operator_bootstrap.build_operator_activity_set`` and
# registers those bound methods under the SAME stable activity names.
_SEALED_ELIGIBILITY_ACTIVITY = EligibilityPreflightActivity(SealedEligibilityCompositionProvider())
_SEALED_TOOLCHAIN_ACTIVITY = ToolchainAttestationActivity(SealedReadinessCompositionProvider())
_SEALED_REMOTE_STATE_ACTIVITY = RemoteStateReadinessActivity(SealedReadinessCompositionProvider())
_SEALED_PLAN_SECRET_ACTIVITY = PlanSecretReadinessActivity(SealedReadinessCompositionProvider())
_SEALED_REAL_PLAN_GENERATION_ACTIVITY = RealPlanGenerationActivity(
    SealedPlanExecutionCompositionProvider()
)

# The registered activity callables (bound methods) the shipped ``main.py`` imports + registers.
eligibility_preflight_activity = _SEALED_ELIGIBILITY_ACTIVITY.run
toolchain_attestation_activity = _SEALED_TOOLCHAIN_ACTIVITY.run
remote_state_readiness_activity = _SEALED_REMOTE_STATE_ACTIVITY.run
plan_secret_readiness_activity = _SEALED_PLAN_SECRET_ACTIVITY.run
real_plan_generation_activity = _SEALED_REAL_PLAN_GENERATION_ACTIVITY.run

# --- Re-exports: the 9 workflow classes (defined in the import-clean
# secp_worker.temporal_workflows)
# and the activity NAME constants. Backward-compatible for importers of
# ``secp_worker.temporal_app``.
# The re-export does NOT change the workflow classes' ``__module__`` (still
# ``secp_worker.temporal_workflows``), so Temporal's workflow sandbox still imports ONLY that clean
# module — never this host-only activity module. ``_activity_timeout`` moved there with the
# workflows.
from secp_worker.temporal_workflows import (  # noqa: E402 - re-export at module end
    DeployWorkflow,
    DestroyWorkflow,
    DiscoverWorkflow,
    EligibilityPreflightWorkflow,
    PlanSecretReadinessWorkflow,
    RealPlanGenerationWorkflow,
    RemoteStateReadinessWorkflow,
    ResetWorkflow,
    ToolchainAttestationWorkflow,
)

__all__ = [
    "DEPLOY_ACTIVITY_NAME",
    "DESTROY_ACTIVITY_NAME",
    "DISCOVER_ACTIVITY_NAME",
    "ELIGIBILITY_PREFLIGHT_ACTIVITY_NAME",
    "PLAN_SECRET_READINESS_ACTIVITY_NAME",
    "REAL_PLAN_GENERATION_ACTIVITY_NAME",
    "REMOTE_STATE_READINESS_ACTIVITY_NAME",
    "RESET_ACTIVITY_NAME",
    "TOOLCHAIN_ATTESTATION_ACTIVITY_NAME",
    "DeployWorkflow",
    "DestroyWorkflow",
    "DiscoverWorkflow",
    "EligibilityPreflightWorkflow",
    "PlanSecretReadinessWorkflow",
    "RealPlanGenerationWorkflow",
    "RemoteStateReadinessWorkflow",
    "ResetWorkflow",
    "ToolchainAttestationWorkflow",
    "EligibilityPreflightActivity",
    "ToolchainAttestationActivity",
    "RemoteStateReadinessActivity",
    "PlanSecretReadinessActivity",
    "RealPlanGenerationActivity",
    "deploy_activity",
    "reset_activity",
    "destroy_activity",
    "discover_activity",
    "eligibility_preflight_activity",
    "toolchain_attestation_activity",
    "remote_state_readiness_activity",
    "plan_secret_readiness_activity",
    "real_plan_generation_activity",
    "run_eligibility_preflight_activity_body",
    "run_toolchain_attestation_activity_body",
    "run_remote_state_readiness_activity_body",
    "run_plan_secret_readiness_activity_body",
    "run_real_plan_generation_activity_body",
]
