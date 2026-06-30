"""Workflow dispatch seam (ADR-005, ADR-010).

The API only ever *dispatches*; it never executes plugin side effects. Two
implementations:

* ``InlineDispatcher`` runs the shared orchestration synchronously in-process. It
  is the dev/test default and is safe only because the Simulator's side effects are
  simulated rows. It refuses any non-Simulator plugin and refuses provider
  discovery (which has no inline-safe provider).
* ``TemporalDispatcher`` creates a queued ``WorkflowRun`` and *enqueues* the
  workflow on Temporal; the separate worker executes it durably. A ``submitter`` is
  injectable so request construction is testable without a live server.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy.orm import Session

from secp_api.config import Settings, get_settings
from secp_api.enums import WorkflowKind, WorkflowStatus
from secp_api.errors import NotFoundError
from secp_api.models import ProviderInventorySnapshot, WorkflowRun


class WorkflowDispatcher(Protocol):
    mode: str

    def dispatch_deploy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun: ...

    def dispatch_reset(
        self, session: Session, exercise_id: uuid.UUID, instance_id: uuid.UUID
    ) -> WorkflowRun: ...

    def dispatch_destroy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun: ...

    def dispatch_discovery(self, session: Session, snapshot_id: uuid.UUID) -> WorkflowRun: ...


class InlineDispatcher:
    """Runs orchestration synchronously in the caller's session/transaction."""

    mode = "inline"

    def dispatch_deploy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        from secp_worker.orchestration import run_deploy

        return run_deploy(session, exercise_id, dispatch_mode=self.mode)

    def dispatch_reset(
        self, session: Session, exercise_id: uuid.UUID, instance_id: uuid.UUID
    ) -> WorkflowRun:
        from secp_worker.orchestration import run_reset

        return run_reset(session, exercise_id, instance_id, dispatch_mode=self.mode)

    def dispatch_destroy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        from secp_worker.orchestration import run_destroy

        return run_destroy(session, exercise_id, dispatch_mode=self.mode)

    def dispatch_discovery(self, session: Session, snapshot_id: uuid.UUID) -> WorkflowRun:
        # Provider discovery has no inline-safe provider (the Simulator does not
        # discover). Refuse inline; discovery requires the Temporal worker path.
        from secp_api.safety import InlineExecutionForbidden

        raise InlineExecutionForbidden(
            "provider discovery is not permitted via the inline dispatcher; "
            "it must run through the Temporal worker path (set "
            "SECP_WORKFLOW_DISPATCH_MODE=temporal)"
        )


# --- Temporal path ------------------------------------------------------------


@dataclass
class TemporalWorkflowRequest:
    """A request to start a durable workflow (testable without a live server)."""

    workflow: str
    workflow_id: str
    task_queue: str
    args: dict = field(default_factory=dict)


class TemporalSubmitter(Protocol):
    def submit(self, request: TemporalWorkflowRequest) -> None: ...


class TemporalClientSubmitter:
    """Default submitter: starts the workflow on Temporal (lazy import).

    Requires the optional ``worker`` extra (``temporalio``) and a running Temporal
    server. Not exercised in unit tests (a fake submitter is injected there).
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def submit(self, request: TemporalWorkflowRequest) -> None:  # pragma: no cover
        import asyncio

        asyncio.run(self._submit_async(request))

    async def _submit_async(self, request: TemporalWorkflowRequest) -> None:  # pragma: no cover
        from temporalio.client import Client

        client = await Client.connect(
            self.settings.temporal_host, namespace=self.settings.temporal_namespace
        )
        await client.start_workflow(
            request.workflow,
            request.args,
            id=request.workflow_id,
            task_queue=request.task_queue,
        )


class TemporalDispatcher:
    """Creates a queued WorkflowRun and enqueues the workflow on Temporal."""

    mode = "temporal"

    def __init__(self, settings: Settings, submitter: TemporalSubmitter | None = None) -> None:
        self.settings = settings
        self.submitter = submitter or TemporalClientSubmitter(settings)

    def _queue_run(
        self,
        session: Session,
        *,
        kind: WorkflowKind,
        organization_id: uuid.UUID,
        workflow_id: str,
        exercise_id: uuid.UUID | None = None,
        execution_target_id: uuid.UUID | None = None,
        snapshot_id: uuid.UUID | None = None,
        target_instance_id: uuid.UUID | None = None,
    ) -> WorkflowRun:
        run = WorkflowRun(
            organization_id=organization_id,
            exercise_id=exercise_id,
            execution_target_id=execution_target_id,
            snapshot_id=snapshot_id,
            kind=kind,
            status=WorkflowStatus.queued,
            dispatch_mode=self.mode,
            correlation_id=uuid.uuid4().hex,
            workflow_id=workflow_id,
            target_instance_id=target_instance_id,
        )
        session.add(run)
        session.flush()
        return run

    def _exercise_org(self, session: Session, exercise_id: uuid.UUID) -> uuid.UUID:
        from secp_api.models import Exercise

        exercise = session.get(Exercise, exercise_id)
        if exercise is None:
            raise NotFoundError(f"exercise {exercise_id} not found")
        return exercise.organization_id

    def dispatch_deploy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        wid = f"deploy-{exercise_id}-{uuid.uuid4().hex[:8]}"
        run = self._queue_run(
            session,
            kind=WorkflowKind.deploy,
            organization_id=self._exercise_org(session, exercise_id),
            workflow_id=wid,
            exercise_id=exercise_id,
        )
        self.submitter.submit(
            TemporalWorkflowRequest(
                workflow="DeployWorkflow",
                workflow_id=wid,
                task_queue=self.settings.temporal_task_queue,
                args={"exercise_id": str(exercise_id), "workflow_run_id": str(run.id)},
            )
        )
        return run

    def dispatch_reset(
        self, session: Session, exercise_id: uuid.UUID, instance_id: uuid.UUID
    ) -> WorkflowRun:
        wid = f"reset-{instance_id}-{uuid.uuid4().hex[:8]}"
        run = self._queue_run(
            session,
            kind=WorkflowKind.reset,
            organization_id=self._exercise_org(session, exercise_id),
            workflow_id=wid,
            exercise_id=exercise_id,
            target_instance_id=instance_id,
        )
        self.submitter.submit(
            TemporalWorkflowRequest(
                workflow="ResetWorkflow",
                workflow_id=wid,
                task_queue=self.settings.temporal_task_queue,
                args={
                    "exercise_id": str(exercise_id),
                    "instance_id": str(instance_id),
                    "workflow_run_id": str(run.id),
                },
            )
        )
        return run

    def dispatch_destroy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        wid = f"destroy-{exercise_id}-{uuid.uuid4().hex[:8]}"
        run = self._queue_run(
            session,
            kind=WorkflowKind.destroy,
            organization_id=self._exercise_org(session, exercise_id),
            workflow_id=wid,
            exercise_id=exercise_id,
        )
        self.submitter.submit(
            TemporalWorkflowRequest(
                workflow="DestroyWorkflow",
                workflow_id=wid,
                task_queue=self.settings.temporal_task_queue,
                args={"exercise_id": str(exercise_id), "workflow_run_id": str(run.id)},
            )
        )
        return run

    def dispatch_discovery(self, session: Session, snapshot_id: uuid.UUID) -> WorkflowRun:
        snap = session.get(ProviderInventorySnapshot, snapshot_id)
        if snap is None:
            raise NotFoundError(f"snapshot {snapshot_id} not found")
        wid = f"discover-{snapshot_id}"
        run = self._queue_run(
            session,
            kind=WorkflowKind.discover,
            organization_id=snap.organization_id,
            workflow_id=wid,
            execution_target_id=snap.execution_target_id,
            snapshot_id=snap.id,
        )
        self.submitter.submit(
            TemporalWorkflowRequest(
                workflow="DiscoverWorkflow",
                workflow_id=wid,
                task_queue=self.settings.temporal_task_queue,
                args={"snapshot_id": str(snapshot_id), "workflow_run_id": str(run.id)},
            )
        )
        return run


def get_dispatcher(
    settings: Settings | None = None, submitter: TemporalSubmitter | None = None
) -> WorkflowDispatcher:
    settings = settings or get_settings()
    if settings.workflow_dispatch_mode == "temporal":
        return TemporalDispatcher(settings, submitter=submitter)
    # Defense in depth: the inline dispatcher must never be selected in production
    # (the Settings validator already refuses this combination at construction).
    if settings.is_production:
        from secp_api.safety import InlineExecutionForbidden

        raise InlineExecutionForbidden(
            "inline dispatcher is forbidden when APP_ENV=production; "
            "configure SECP_WORKFLOW_DISPATCH_MODE=temporal"
        )
    return InlineDispatcher()
