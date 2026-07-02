"""Workflow dispatch seam (ADR-005, ADR-010).

The API only ever *dispatches*; it never executes plugin side effects. Two
implementations:

* ``InlineDispatcher`` runs the shared orchestration synchronously in-process. It
  is the dev/test default and is safe only because the Simulator's side effects are
  simulated rows. It refuses any non-Simulator plugin and refuses provider
  discovery (which has no inline-safe provider).
* ``TemporalDispatcher`` creates a queued ``WorkflowRun`` plus a durable outbox
  record. A worker-side publisher submits committed outbox rows to Temporal; the
  separate Temporal worker executes them durably.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.config import Settings, get_settings
from secp_api.enums import WorkflowKind, WorkflowStatus
from secp_api.errors import NotFoundError
from secp_api.models import (
    ProviderInventorySnapshot,
    TargetPreflight,
    WorkflowDispatchOutbox,
    WorkflowRun,
)

OUTBOX_PENDING = "pending"
OUTBOX_FAILED = "failed"
OUTBOX_SUBMITTED = "submitted"


class WorkflowDispatcher(Protocol):
    mode: str

    def dispatch_deploy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun: ...

    def dispatch_reset(
        self, session: Session, exercise_id: uuid.UUID, instance_id: uuid.UUID
    ) -> WorkflowRun: ...

    def dispatch_destroy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun: ...

    def dispatch_discovery(self, session: Session, snapshot_id: uuid.UUID) -> WorkflowRun: ...

    def dispatch_simulated_preflight(
        self,
        session: Session,
        onboarding_id: uuid.UUID,
        *,
        checks: list[dict],
        verification_level: str,
        collector_kind: str,
        collector_identity: str,
        created_by: uuid.UUID | None,
    ) -> TargetPreflight: ...


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

    def dispatch_simulated_preflight(
        self,
        session: Session,
        onboarding_id: uuid.UUID,
        *,
        checks: list[dict],
        verification_level: str,
        collector_kind: str,
        collector_identity: str,
        created_by: uuid.UUID | None,
    ) -> TargetPreflight:
        from secp_worker.onboarding.orchestration import run_simulated_preflight

        return run_simulated_preflight(  # type: ignore[return-value]
            session,
            onboarding_id,
            checks=checks,
            verification_level=verification_level,
            collector_kind=collector_kind,
            collector_identity=collector_identity,
            created_by=created_by,
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
        from temporalio.exceptions import WorkflowAlreadyStartedError

        client = await Client.connect(
            self.settings.temporal_host, namespace=self.settings.temporal_namespace
        )
        try:
            await client.start_workflow(
                request.workflow,
                request.args,
                id=request.workflow_id,
                task_queue=request.task_queue,
            )
        except WorkflowAlreadyStartedError:
            # Deterministic workflow ids make duplicate publisher attempts safe.
            return


class TemporalDispatcher:
    """Creates queued workflow state plus a durable outbox record.

    The API transaction must commit before any Temporal submission is attempted.
    ``WorkflowOutboxPublisher`` is the only component that calls the submitter.
    """

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
            target_instance_id=target_instance_id,
        )
        session.add(run)
        session.flush()
        run.workflow_id = f"{kind.value}-{run.id}"
        session.flush()
        return run

    def _queue_outbox(
        self,
        session: Session,
        run: WorkflowRun,
        *,
        workflow: str,
        args: dict,
    ) -> None:
        if run.workflow_id is None:  # pragma: no cover - defensive
            raise RuntimeError("workflow_run.workflow_id must be assigned before outbox enqueue")
        session.add(
            WorkflowDispatchOutbox(
                organization_id=run.organization_id,
                workflow_run_id=run.id,
                workflow=workflow,
                workflow_id=run.workflow_id,
                task_queue=self.settings.temporal_task_queue,
                args=args,
                status=OUTBOX_PENDING,
            )
        )
        session.flush()

    def _exercise_org(self, session: Session, exercise_id: uuid.UUID) -> uuid.UUID:
        from secp_api.models import Exercise

        exercise = session.get(Exercise, exercise_id)
        if exercise is None:
            raise NotFoundError(f"exercise {exercise_id} not found")
        return exercise.organization_id

    def dispatch_deploy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        # Defense in depth: refuse target-pinned plans before any WorkflowRun,
        # outbox row, or Temporal interaction is created.
        from secp_api.services.planning import assert_deployment_eligible

        assert_deployment_eligible(session, exercise_id)
        run = self._queue_run(
            session,
            kind=WorkflowKind.deploy,
            organization_id=self._exercise_org(session, exercise_id),
            exercise_id=exercise_id,
        )
        self._queue_outbox(
            session,
            run,
            workflow="DeployWorkflow",
            args={"exercise_id": str(exercise_id), "workflow_run_id": str(run.id)},
        )
        return run

    def dispatch_reset(
        self, session: Session, exercise_id: uuid.UUID, instance_id: uuid.UUID
    ) -> WorkflowRun:
        run = self._queue_run(
            session,
            kind=WorkflowKind.reset,
            organization_id=self._exercise_org(session, exercise_id),
            exercise_id=exercise_id,
            target_instance_id=instance_id,
        )
        self._queue_outbox(
            session,
            run,
            workflow="ResetWorkflow",
            args={
                "exercise_id": str(exercise_id),
                "instance_id": str(instance_id),
                "workflow_run_id": str(run.id),
            },
        )
        return run

    def dispatch_destroy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        run = self._queue_run(
            session,
            kind=WorkflowKind.destroy,
            organization_id=self._exercise_org(session, exercise_id),
            exercise_id=exercise_id,
        )
        self._queue_outbox(
            session,
            run,
            workflow="DestroyWorkflow",
            args={"exercise_id": str(exercise_id), "workflow_run_id": str(run.id)},
        )
        return run

    def dispatch_discovery(self, session: Session, snapshot_id: uuid.UUID) -> WorkflowRun:
        snap = session.get(ProviderInventorySnapshot, snapshot_id)
        if snap is None:
            raise NotFoundError(f"snapshot {snapshot_id} not found")
        run = self._queue_run(
            session,
            kind=WorkflowKind.discover,
            organization_id=snap.organization_id,
            execution_target_id=snap.execution_target_id,
            snapshot_id=snap.id,
        )
        self._queue_outbox(
            session,
            run,
            workflow="DiscoverWorkflow",
            args={"snapshot_id": str(snapshot_id), "workflow_run_id": str(run.id)},
        )
        return run

    def dispatch_simulated_preflight(
        self,
        session: Session,
        onboarding_id: uuid.UUID,
        *,
        checks: list[dict],
        verification_level: str,
        collector_kind: str,
        collector_identity: str,
        created_by: uuid.UUID | None,
    ) -> TargetPreflight:
        from secp_api.errors import DomainError

        raise DomainError(
            "simulated preflight orchestration is not supported via the Temporal dispatcher "
            "in SECP-002B-1B-1; use the inline dispatcher (SECP_WORKFLOW_DISPATCH_MODE=inline) "
            "for dev/test, or wait for a future durable B1-B implementation"
        )


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _redacted_submit_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: workflow submission failed"


class WorkflowOutboxPublisher:
    """Publishes committed workflow outbox rows to Temporal."""

    def __init__(self, settings: Settings, submitter: TemporalSubmitter | None = None) -> None:
        self.settings = settings
        self.submitter = submitter or TemporalClientSubmitter(settings)

    def publish_one(self, session: Session, outbox_id: uuid.UUID) -> bool:
        outbox = session.get(WorkflowDispatchOutbox, outbox_id)
        if outbox is None:
            raise NotFoundError(f"workflow dispatch outbox {outbox_id} not found")
        if outbox.status == OUTBOX_SUBMITTED:
            return False

        outbox.attempts += 1
        outbox.updated_at = _utcnow()
        request = TemporalWorkflowRequest(
            workflow=outbox.workflow,
            workflow_id=outbox.workflow_id,
            task_queue=outbox.task_queue,
            args=dict(outbox.args),
        )
        try:
            self.submitter.submit(request)
        except Exception as exc:
            outbox.status = OUTBOX_FAILED
            outbox.last_error = _redacted_submit_error(exc)
            outbox.updated_at = _utcnow()
            session.flush()
            return False

        outbox.status = OUTBOX_SUBMITTED
        outbox.last_error = None
        outbox.submitted_at = _utcnow()
        outbox.updated_at = outbox.submitted_at
        if outbox.workflow_run.workflow_id != outbox.workflow_id:
            outbox.workflow_run.workflow_id = outbox.workflow_id
        session.flush()
        return True

    def publish_pending(self, session: Session, *, limit: int = 100) -> int:
        rows = (
            session.execute(
                select(WorkflowDispatchOutbox)
                .where(WorkflowDispatchOutbox.status.in_([OUTBOX_PENDING, OUTBOX_FAILED]))
                .order_by(WorkflowDispatchOutbox.created_at)
                .limit(limit)
            )
            .scalars()
            .all()
        )
        published = 0
        for row in rows:
            if self.publish_one(session, row.id):
                published += 1
        return published


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
