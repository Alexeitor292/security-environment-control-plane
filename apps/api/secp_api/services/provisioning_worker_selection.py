"""Which worker executes a provisioning operation. Chosen by the control plane, written once.

ADR-030 condition 2 says the executing worker's identity must match the durable operation. Until
this module existed there was nothing to match against: ``provisioning_operation`` recorded no
selection, so the authority derivation refused every execution with
``execution_worker_selection_not_durable``. This is the source that closes it.

WHO CHOOSES, AND WHO MAY NOT
------------------------------
The control plane chooses. Not the request body, not a Temporal payload, not the worker's own
claim, not an environment variable, and not the executor. Each of those is a value the party being
authorized controls, and a binding chosen by the party it constrains is not a binding.

So :func:`select_provisioning_worker` takes an organization and an operation and reads enrolled
workers. There is no ``worker_installation_id`` parameter anywhere on this surface — a caller
cannot express a preference, which is stronger than a caller's preference being ignored.

WRITTEN BEFORE DISPATCHABILITY, AND IMMUTABLE AFTER
-----------------------------------------------------
:func:`bind_provisioning_worker` writes the selection and is the ONLY writer. It refuses to
overwrite an existing binding: re-selecting is not an edit to an authorized execution, it is a new
operation. That refusal is what makes "the worker that was authorized" and "the worker that
executes" the same fact across a retry — an exact retry of the same operation keeps its binding
because there is no path that changes it.

An operation whose binding is NULL is not dispatchable. The check lives in
:func:`assert_dispatchable`, which the enqueue path calls before it transitions status.

WHY NOT SIMPLY "ANY HEALTHY ENROLLED WORKER"
----------------------------------------------
Because that is not a binding. It authorizes every healthy worker in the organization to execute
every operation in it, which is precisely the property condition 2 exists to remove. Selection
happens once, is recorded, and is then compared — the comparison is the point, and a comparison
against "anyone eligible" always passes.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.models import ProvisioningOperation

#: Recorded nowhere durable; a version so a refusal is attributable to a known selection rule.
PROVISIONING_WORKER_SELECTION_VERSION = "secp.provisioning-worker-selection/v1"

#: The enrollment state a worker must be in to be selectable. A worker whose enrollment reached
#: ``refused`` or ``recovery_required`` is a record that it EXISTS, not a statement that it may act.
_SELECTABLE_ENROLLMENT_STATE = "healthy"

#: Every refusal, closed. Distinct per requirement 7 so an operator is told what to fix.
SELECTION_REFUSAL_REASONS: tuple[str, ...] = (
    "provisioning_worker_none_enrolled",
    "provisioning_worker_registration_absent",
    "provisioning_worker_organization_mismatch",
    "provisioning_worker_release_absent",
    "provisioning_worker_state_not_healthy",
    "provisioning_worker_binding_already_set",
    "provisioning_worker_binding_absent",
    "provisioning_worker_operation_absent",
)


class ProvisioningWorkerSelectionRefused(Exception):
    """Refused. ONE closed reason code; never a row's contents."""

    def __init__(self, reason: str) -> None:
        if reason not in SELECTION_REFUSAL_REASONS:
            raise ValueError(f"unknown provisioning worker selection reason: {reason!r}")
        super().__init__(reason)
        self.reason = reason


def select_provisioning_worker(session: Session, *, organization_id: uuid.UUID) -> str:
    """The worker the control plane selects, or a refusal.

    Deterministic rather than round-robin or random: the lowest installation id among the
    selectable workers. A deterministic rule means a retry that somehow reached selection again
    picks the same worker, and it makes the choice reviewable — "why that one" has an answer.
    Load balancing is a later concern and belongs in a rule that is still deterministic per
    operation, not in an arbitrary pick.
    """
    from secp_api import worker_enrollment_models as enrollment

    rows = (
        session.execute(
            select(enrollment.WorkerEnrollmentState).where(
                enrollment.WorkerEnrollmentState.organization_id == organization_id
            )
        )
        .scalars()
        .all()
    )
    selectable = sorted(
        {
            str(row.worker_installation_id)
            for row in rows
            if row.state == _SELECTABLE_ENROLLMENT_STATE
            and str(row.worker_installation_id or "").strip()
            and str(row.release_digest or "").strip()
        }
    )
    if not selectable:
        raise ProvisioningWorkerSelectionRefused("provisioning_worker_none_enrolled")
    return selectable[0]


def bind_provisioning_worker(
    session: Session,
    *,
    operation: ProvisioningOperation,
    worker_installation_id: str,
) -> str:
    """Write the selection. The ONLY writer, and it never overwrites.

    Returns the bound identity, which is the existing one when it already matches — so calling
    this twice with the same selection is idempotent, and calling it with a DIFFERENT one is a
    refusal rather than a silent re-point.
    """
    candidate = (worker_installation_id or "").strip()
    if not candidate:
        raise ProvisioningWorkerSelectionRefused("provisioning_worker_binding_absent")

    current = (operation.worker_installation_id or "").strip()
    if current:
        if current != candidate:
            # Re-selecting is not an edit to an authorized execution. It is a new operation, and
            # the repository's idempotency-key model already gives one per (manifest, kind).
            raise ProvisioningWorkerSelectionRefused("provisioning_worker_binding_already_set")
        return current

    operation.worker_installation_id = candidate
    session.flush()
    return candidate


def assert_dispatchable(operation: ProvisioningOperation) -> str:
    """An operation with no durable worker binding may not become dispatchable.

    Called by the enqueue path BEFORE it transitions status, so the binding is persisted before —
    or in the same transaction as — the operation becoming executable. An operation that reached a
    dispatchable status without a binding would be one the authority derivation must then refuse,
    which is a queue full of work that can never run.
    """
    bound = (operation.worker_installation_id or "").strip()
    if not bound:
        raise ProvisioningWorkerSelectionRefused("provisioning_worker_binding_absent")
    return bound
