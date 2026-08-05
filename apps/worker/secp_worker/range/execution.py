"""Worker-side execution of a range operation.

This is the privileged half of the range lifecycle. The API creates the operation row and stops;
everything that touches a provider — and therefore, for the local Docker provider, a root-equivalent
socket — happens HERE, in the worker process, per Charter Invariants 6/7 and ADR-005.

The split is not cosmetic. The API genuinely cannot reach a provider: it holds only the contract
types in :mod:`secp_api.range_providers`, and ``tests/test_architecture_boundary.py`` refuses
``subprocess`` and direct ``reset``/``destroy`` calls anywhere under ``secp_api``. Moving this file
without moving the execution would have been guard evasion; moving the execution is the fix.

The function opens no session of its own — the caller (a Temporal activity, or a test) supplies one,
exactly as the other worker orchestration entry points do.

Everything else about the design is unchanged and still load-bearing:

* A state is only ever written from an OBSERVATION. ``ready`` requires every component to have been
  seen responding; ``destroyed`` requires a residue verdict of ``clean``, which requires a probe
  that
  proved itself working. When the provider could not observe, the range goes to
  ``recovery_required`` and says so.
* ``_persist_resources`` NEVER marks a resource removed. ``removed`` is writable from exactly one
  place — :func:`_run_destroy`, from a real teardown observation — because a failed operation that
  silently retired the rows it did not mention once produced a ``clean`` teardown while a container
  and a network were still running.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from secp_api.range_enums import (
    RangeOperationKind,
    RangeOperationStatus,
    RangeResourceState,
    RangeState,
    RangeStepStatus,
    ResidueVerdict,
)
from secp_api.range_models import (
    RangeDeploymentOperation,
    RangeInstance,
    RangeProviderResource,
    RangeTeardownEvidence,
)
from secp_api.range_providers.base import (
    OperationContext,
    RangeSpec,
    RecordedStep,
    ResourceObservation,
    TeardownResourceOutcome,
)
from secp_api.services.ranges import build_spec, record_event
from sqlalchemy import select
from sqlalchemy.orm import Session

logger = logging.getLogger("secp.worker.range")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _step_dict(step: RecordedStep) -> dict:
    return {
        "key": step.key,
        "label": step.label,
        "status": step.status.value if hasattr(step.status, "value") else str(step.status),
        "detail": step.detail,
        "at": step.at,
    }


def execute_range_operation(session: Session, operation_id: uuid.UUID) -> None:
    """Run one operation to completion against the provider and persist every observation.

    The caller supplies the session (a Temporal activity, or a test). Progress is committed as it
    happens so a poller sees movement; the final state is written once, from the provider's result.
    """
    operation = session.get(RangeDeploymentOperation, operation_id)
    if operation is None:
        logger.warning("range operation %s vanished before execution", operation_id)
        return
    instance = session.get(RangeInstance, operation.range_instance_id)
    if instance is None:
        logger.warning("range %s vanished before execution", operation.range_instance_id)
        return

    from secp_worker.range import get_provider

    provider = get_provider(instance.provider)
    spec = build_spec(session, instance)

    # THE WORKER PLANS THE STEPS, not the API. Asking a provider what it is about to do means
    # holding a provider, so the API — which may not — creates the operation with no steps and the
    # plan appears on the first poll after the worker picks the operation up. That is also the
    # more honest boundary: the control plane genuinely does not know what a given provider will do.
    steps = [
        RecordedStep(
            key=item["key"],
            label=item["label"],
            status=RangeStepStatus(item.get("status", "pending")),
            detail=item.get("detail"),
            at=item.get("at"),
        )
        for item in (operation.steps or [])
    ]
    if not steps:
        steps = provider.plan_steps(spec, operation.kind.value)
        operation.steps = [_step_dict(step) for step in steps]
        operation.total_steps = len(steps)
        session.commit()

    def on_change(current: list[RecordedStep], phase: str | None) -> None:
        now = _utcnow().isoformat()
        payload = []
        completed = 0
        for step in current:
            if step.status in (
                RangeStepStatus.succeeded,
                RangeStepStatus.failed,
                RangeStepStatus.unproven,
            ):
                completed += 1
                if step.at is None:
                    step.at = now
            payload.append(_step_dict(step))
        operation.steps = payload
        operation.completed_steps = completed
        operation.phase = phase
        operation.status = RangeOperationStatus.running
        session.commit()

    def on_event(kind: str, message: str, level: str, data: dict) -> None:
        record_event(
            session,
            instance,
            kind=kind,
            message=message,
            level=level,
            data=data,
            operation_id=operation.id,
        )
        session.commit()

    ctx = OperationContext(steps, on_change, on_event)
    operation.status = RangeOperationStatus.running
    session.commit()

    existing = tuple(_observation_of(row) for row in _live_resources(session, instance))

    try:
        if operation.kind is RangeOperationKind.destroy:
            _run_destroy(session, instance, operation, provider, spec, existing, ctx)
        elif operation.kind is RangeOperationKind.reset:
            _run_bring_up(
                session,
                instance,
                operation,
                provider.reset(spec, existing, ctx),
                ctx,
                reset=True,
            )
        else:
            _run_bring_up(session, instance, operation, provider.deploy(spec, ctx), ctx)
    except Exception as exc:  # pragma: no cover - defensive; a provider bug must not wedge a range
        logger.exception("range operation %s failed unexpectedly", operation_id)
        session.rollback()
        operation = session.get(RangeDeploymentOperation, operation_id)
        instance = session.get(RangeInstance, operation.range_instance_id) if operation else None
        if operation is not None and instance is not None:
            operation.status = RangeOperationStatus.failed
            operation.failure_code = "internal_error"
            operation.failure_message = str(exc)[:500]
            operation.finished_at = _utcnow()
            instance.state = RangeState.failed
            instance.state_reason = f"the {operation.kind.value} operation failed unexpectedly"
            record_event(
                session,
                instance,
                kind="operation_failed",
                message=f"The {operation.kind.value} operation failed unexpectedly: {exc}",
                level="error",
                operation_id=operation.id,
            )
            session.commit()


def _live_resources(session: Session, instance: RangeInstance) -> list[RangeProviderResource]:
    return list(
        session.execute(
            select(RangeProviderResource).where(
                RangeProviderResource.range_instance_id == instance.id,
                RangeProviderResource.removed_at.is_(None),
            )
        )
        .scalars()
        .all()
    )


def _observation_of(row: RangeProviderResource) -> ResourceObservation:
    return ResourceObservation(
        kind=row.kind,
        name=row.name,
        component_key=row.component_key,
        external_id=row.external_id,
        image=row.image,
        image_digest=row.image_digest,
        owner_label=row.owner_label,
        host_port=row.host_port,
        verified=row.state is RangeResourceState.verified,
        detail=dict(row.detail or {}),
    )


def _run_bring_up(
    session: Session,
    instance: RangeInstance,
    operation: RangeDeploymentOperation,
    result,
    ctx: OperationContext,
    *,
    reset: bool = False,
) -> None:
    _persist_resources(session, instance, result.resources)
    operation.finished_at = _utcnow()
    if reset:
        # A reset returns the ENVIRONMENT to its initial state, so the scores earned against the
        # old environment no longer describe anything that exists. Imported lazily: the competition
        # service imports this module, and the dependency only runs in this direction here.
        from secp_api.services.competitions import reset_scores_for_range

        reset_scores_for_range(session, instance)
    if result.ok:
        operation.status = RangeOperationStatus.succeeded
        instance.state = RangeState.ready
        instance.state_reason = None
        instance.deployed_at = instance.deployed_at or _utcnow()
        record_event(
            session,
            instance,
            kind="range_ready",
            message=(
                "Range reset complete; every component was observed responding"
                if reset
                else "Range deployed; every component was observed responding"
            ),
            operation_id=operation.id,
        )
    else:
        operation.status = RangeOperationStatus.failed
        operation.failure_code = result.failure_code
        operation.failure_message = result.failure_message
        instance.state = RangeState.failed
        instance.state_reason = result.failure_message
        record_event(
            session,
            instance,
            kind="range_failed",
            message=result.failure_message or "The operation failed",
            level="error",
            operation_id=operation.id,
        )
    session.commit()


def _persist_resources(
    session: Session,
    instance: RangeInstance,
    observations: tuple[ResourceObservation, ...],
) -> None:
    """Write the provider's observations to the resource table.

    ``state`` is ``verified`` ONLY where the provider set ``verified`` — i.e. where it actually got
    a response. A created-but-unresponsive container is recorded as ``created``, which is honest and
    is why ``ready`` cannot be reached from it.

    THIS FUNCTION NEVER MARKS A RESOURCE REMOVED, and that is the whole point. It used to reconcile
    the live set by retiring any row missing from the new observations, which quietly turned "this
    operation did not mention it" into "it is gone". A real failed reset did exactly that: the
    provider could not remove one container, so it never restarted it and never reported it, the
    row was retired as removed, and the subsequent destroy proved absence only of the rows that
    were left — reporting ``clean`` with a container and a network still running on the daemon.
    Every individual probe was honest; the SET they were asked about had been silently narrowed.

    So ``removed`` is now writable from exactly one place: :func:`_run_destroy`, from an actual
    teardown observation. The live set only ever grows until absence is proved, and a destroy
    therefore always sweeps everything this range has ever created.
    """
    for observation in observations:
        row = (
            session.execute(
                select(RangeProviderResource).where(
                    RangeProviderResource.range_instance_id == instance.id,
                    RangeProviderResource.name == observation.name,
                    RangeProviderResource.kind == observation.kind,
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            row = RangeProviderResource(
                organization_id=instance.organization_id,
                range_instance_id=instance.id,
                kind=observation.kind,
                provider=instance.provider,
                name=observation.name,
                owner_label=observation.owner_label,
            )
            session.add(row)
        row.component_key = observation.component_key
        row.external_id = observation.external_id
        row.image = observation.image
        row.image_digest = observation.image_digest
        row.owner_label = observation.owner_label
        row.host_port = observation.host_port
        row.detail = observation.detail
        row.removed_at = None
        row.state = (
            RangeResourceState.verified if observation.verified else RangeResourceState.created
        )
    session.flush()


def _run_destroy(
    session: Session,
    instance: RangeInstance,
    operation: RangeDeploymentOperation,
    provider,
    spec: RangeSpec,
    existing: tuple[ResourceObservation, ...],
    ctx: OperationContext,
) -> None:
    result = provider.destroy(spec, existing, ctx)

    by_name = {row.name: row for row in _live_resources(session, instance)}
    removed = present = unproven = 0
    resource_payload: list[dict] = []
    for observation in result.observations:
        row = by_name.get(observation.name)
        if observation.outcome is TeardownResourceOutcome.removed:
            removed += 1
            if row is not None:
                row.state = RangeResourceState.removed
                row.removed_at = _utcnow()
        elif observation.outcome is TeardownResourceOutcome.present:
            present += 1
            if row is not None:
                row.state = RangeResourceState.failed
        else:
            unproven += 1
            if row is not None:
                row.state = RangeResourceState.unproven
        resource_payload.append(
            {
                "kind": observation.kind.value,
                "name": observation.name,
                "external_id": observation.external_id,
                "verdict": observation.outcome.value,
                "detail": observation.detail,
            }
        )

    if not result.probe_reachable or unproven:
        verdict = ResidueVerdict.unproven
    elif present:
        verdict = ResidueVerdict.residue
    else:
        verdict = ResidueVerdict.clean

    reason = result.reason
    if reason is None and verdict is ResidueVerdict.residue:
        reason = f"{present} owned resource(s) were still present after removal"

    evidence = RangeTeardownEvidence(
        organization_id=instance.organization_id,
        range_instance_id=instance.id,
        operation_id=operation.id,
        verdict=verdict,
        probe_reachable=result.probe_reachable,
        expected_count=len(result.observations),
        removed_confirmed=removed,
        still_present=present,
        unproven_count=unproven,
        reason=reason,
        resources=resource_payload,
    )
    session.add(evidence)

    instance.residue_verdict = verdict
    operation.finished_at = _utcnow()

    if verdict is ResidueVerdict.clean:
        operation.status = RangeOperationStatus.succeeded
        instance.state = RangeState.destroyed
        instance.destroyed_at = _utcnow()
        instance.state_reason = None
        record_event(
            session,
            instance,
            kind="range_destroyed",
            message=(
                f"Range destroyed; all {removed} owned resource(s) confirmed absent by a "
                "verified probe"
            ),
            operation_id=operation.id,
        )
    elif verdict is ResidueVerdict.residue:
        operation.status = RangeOperationStatus.failed
        operation.failure_code = "residue_present"
        operation.failure_message = reason
        instance.state = RangeState.recovery_required
        instance.state_reason = reason
        record_event(
            session,
            instance,
            kind="range_residue",
            message=reason or "Owned resources were still present after teardown",
            level="error",
            operation_id=operation.id,
        )
    else:
        # UNPROVEN. Not destroyed, not failed — unknown. A human has to look.
        operation.status = RangeOperationStatus.unproven
        operation.failure_code = "residue_unproven"
        operation.failure_message = reason
        instance.state = RangeState.recovery_required
        instance.state_reason = (
            reason or "teardown could not be observed, so it is unknown whether resources remain"
        )
        record_event(
            session,
            instance,
            kind="range_teardown_unproven",
            message=(
                "Teardown could not be observed. This is NOT a clean destroy: the existence check "
                "shares a failure mode with the removal, so its silence is not evidence of "
                "absence. Check the provider by hand before reusing these resource names."
            ),
            level="warning",
            operation_id=operation.id,
        )
    session.commit()
