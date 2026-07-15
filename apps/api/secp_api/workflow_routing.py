"""Deterministic Temporal task-queue routing (B1B-PR5B / ADR-022 §12).

Two workers may exist for one deployment:

* the SHIPPED, sealed worker — it owns ``settings.temporal_task_queue`` and executes the ordinary
  deploy / reset / destroy / discover work. Its plan/readiness activity registrations are the
  always-sealed defaults, so if a controlled-live workflow ever reached that queue it would refuse
  at the composition gate.
* a separately reviewed, deployment-local CONTROLLED-LIVE operator worker — a root-controlled
  entrypoint maintained OUTSIDE this repository. It polls ``settings.temporal_operator_task_queue``
  (a DISTINCT queue) and registers the controlled-live activity set built by
  :func:`secp_worker.operator_bootstrap.build_operator_activity_set`.

If both workers polled the SAME queue they would register the SAME activity names, and Temporal
would route a real-plan-generation task non-deterministically to EITHER — sometimes to the sealed
worker (refuse) and sometimes to the operator worker (proceed). This module removes that ambiguity:
the controlled-live real-plan-generation workflow and its operator readiness prerequisites route to
the operator queue WHEN one is configured, and everything else stays on the shipped queue.

This module is PURE: it performs no I/O, imports no worker/transport/Temporal code, and holds no
endpoint, credential, or backend value. Configuring an operator queue activates nothing on its own —
a live plan still requires the reviewed controlled-live composition AND every authoritative database
gate passing at request time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from secp_api.enums import WorkflowKind

if TYPE_CHECKING:
    from secp_api.config import Settings


class OperatorTaskQueueUnavailable(Exception):
    """The operator task queue is not configured or not distinct. Fail closed; carries no value."""


# The workflow kinds a deployed controlled-live operator worker OWNS. Each is worker-only, sealed by
# default in the shipped worker, and produces controlled-live evidence (or a redacted change set)
# only under a reviewed deployment-local composition. Deploy / reset / destroy / discover are NOT
# here: they run on the shipped worker and never route to the operator queue.
CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS: frozenset[str] = frozenset(
    {
        WorkflowKind.eligibility_preflight.value,
        WorkflowKind.toolchain_attestation.value,
        WorkflowKind.remote_state_readiness.value,
        WorkflowKind.plan_secret_readiness.value,
        WorkflowKind.real_plan_generation.value,
    }
)


def _kind_value(kind: WorkflowKind | str) -> str:
    return getattr(kind, "value", kind)


def is_controlled_live_operator_kind(kind: WorkflowKind | str) -> bool:
    """True when ``kind`` is a controlled-live operator-owned workflow kind."""
    return _kind_value(kind) in CONTROLLED_LIVE_OPERATOR_WORKFLOW_KINDS


def operator_queue_configured(settings: Settings) -> bool:
    """True only when a DISTINCT operator queue is configured.

    An empty operator queue means no operator worker is deployed. A value equal to the shipped queue
    is treated as unconfigured here (the Settings validator already refuses that combination, so
    this is defence in depth): controlled-live work then stays on the shipped queue and refuses at
    the seal rather than sharing a queue non-deterministically.
    """
    operator = settings.temporal_operator_task_queue
    return bool(operator) and operator != settings.temporal_task_queue


def resolve_task_queue(settings: Settings, kind: WorkflowKind | str) -> str:
    """The task queue a workflow of ``kind`` must be dispatched to (deterministic per kind).

    Controlled-live operator-owned kinds route to the operator queue WHEN a distinct one is
    configured; otherwise they stay on the shipped queue (where the sealed worker refuses). Every
    other kind always routes to the shipped queue.
    """
    if is_controlled_live_operator_kind(kind) and operator_queue_configured(settings):
        return settings.temporal_operator_task_queue
    return settings.temporal_task_queue


def resolve_operator_task_queue(settings: Settings) -> str:
    """The DISTINCT operator queue the controlled-live operator worker must poll, or fail closed.

    Used by the reviewed deployment-local operator entrypoint. It refuses (never guesses or falls
    back to the shipped queue) unless a distinct operator queue is configured — an operator worker
    that shared the shipped queue would reintroduce the non-deterministic routing this module exists
    to remove.
    """
    if not operator_queue_configured(settings):
        raise OperatorTaskQueueUnavailable(
            "no distinct SECP_TEMPORAL_OPERATOR_TASK_QUEUE is configured; the controlled-live "
            "operator worker must poll a queue distinct from the shipped SECP_TEMPORAL_TASK_QUEUE"
        )
    return settings.temporal_operator_task_queue
