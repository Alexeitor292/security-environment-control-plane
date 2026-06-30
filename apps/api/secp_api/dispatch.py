"""Workflow dispatch seam (ADR-005).

The API only ever *dispatches*; it never executes plugin side effects itself. Two
implementations:

* ``InlineDispatcher`` runs the shared orchestration synchronously in-process. It
  is the dev/test default and is safe only because the Simulator's side effects
  are simulated rows. It still passes through the approval gate and lifecycle
  machine.
* ``TemporalDispatcher`` enqueues the workflow on Temporal; the separate worker
  process executes it durably. Production-shaped path.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.orm import Session

from secp_api.config import Settings, get_settings
from secp_api.models import WorkflowRun


class WorkflowDispatcher(Protocol):
    mode: str

    def dispatch_deploy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun: ...

    def dispatch_reset(
        self, session: Session, exercise_id: uuid.UUID, instance_id: uuid.UUID
    ) -> WorkflowRun: ...

    def dispatch_destroy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun: ...


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


class TemporalDispatcher:
    """Production-shaped path: enqueue durable workflows on Temporal.

    Wired but not exercised in CI (ADR-005 placeholder). Requires the optional
    ``worker`` dependency group (``temporalio``) and a running Temporal server.
    """

    mode = "temporal"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _unavailable(self) -> RuntimeError:
        return RuntimeError(
            "TemporalDispatcher requires the 'worker' extra (temporalio) and a "
            "running Temporal server. Set SECP_WORKFLOW_DISPATCH_MODE=inline for "
            "local runs without Temporal."
        )

    def dispatch_deploy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        raise self._unavailable()

    def dispatch_reset(
        self, session: Session, exercise_id: uuid.UUID, instance_id: uuid.UUID
    ) -> WorkflowRun:
        raise self._unavailable()

    def dispatch_destroy(self, session: Session, exercise_id: uuid.UUID) -> WorkflowRun:
        raise self._unavailable()


def get_dispatcher(settings: Settings | None = None) -> WorkflowDispatcher:
    settings = settings or get_settings()
    if settings.workflow_dispatch_mode == "temporal":
        return TemporalDispatcher(settings)
    # Defense in depth: the inline dispatcher must never be selected in production
    # (the Settings validator already refuses this combination at construction).
    if settings.is_production:
        from secp_api.safety import InlineExecutionForbidden

        raise InlineExecutionForbidden(
            "inline dispatcher is forbidden when APP_ENV=production; "
            "configure SECP_WORKFLOW_DISPATCH_MODE=temporal"
        )
    return InlineDispatcher()
