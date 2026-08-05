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
from typing import assert_never

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
from secp_api.services.ranges import (
    build_spec,
    operation_staleness,
    record_event,
    retain_resources_as_unproven,
)
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


class RangeExecutionUnresolvable(RuntimeError):
    """This worker cannot execute the operation it was handed, and says so instead of succeeding.

    Raised — never returned — for every way the dispatched work fails to resolve to something this
    process may run: the operation row is not in this database, its range is not, the argument
    describes another environment's rows, or the operation is no longer in flight.

    ``retryable`` is the Temporal classification and is a statement about whether waiting could
    change the answer. A row that is merely not visible YET (replica lag, a read replica behind the
    API's commit) is retryable and bounded by the activity's retry policy. A row that resolves to
    the wrong range, or an operation an operator has already abandoned, will never become correct
    by retrying, and retrying it is worse than failing: it is a second writer racing a recovery.
    """

    def __init__(self, reason: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.reason = reason
        self.retryable = retryable


def execute_range_operation(
    session: Session,
    operation_id: uuid.UUID,
    *,
    expected_range_instance_id: uuid.UUID | None = None,
    expected_organization_id: uuid.UUID | None = None,
) -> None:
    """Run one operation to completion against the provider and persist every observation.

    The caller supplies the session (a Temporal activity, or a test). Progress is committed as it
    happens so a poller sees movement; the final state is written once, from the provider's result.

    THIS FUNCTION NEVER RETURNS NORMALLY WITHOUT HAVING RUN THE OPERATION. It used to: an operation
    it could not find was a warning and a ``return``, which the activity reported as success and
    Temporal recorded as ``Completed`` — while the operation stayed ``pending``, the range stayed
    ``resetting``, and both ``destroy`` and ``reset`` refused with 409 because those are not states
    you may act from. The only recovery was UPDATE by hand. Work this worker cannot resolve is now
    a classified, bounded error, and where the operation row IS reachable the failure is persisted
    first so an operator sees it without reading worker logs.

    The ``expected_*`` ids are the caller's claim about which rows this id denotes. They come from
    the dispatching database, so a worker attached to a DIFFERENT database — the trigger of the
    original incident, two workers on one ``secp-orchestration`` queue against two deployments —
    either fails to resolve the id at all or resolves it to rows that do not match, and refuses.
    """
    operation = session.get(RangeDeploymentOperation, operation_id)
    if operation is None:
        # Not "vanished" — not present HERE. The row is very likely alive and waiting in the
        # database this worker is not attached to.
        raise RangeExecutionUnresolvable(
            "operation_not_found",
            f"range operation {operation_id} is not in this worker's database. It may not have "
            "committed yet, or this worker may be attached to a different deployment than the one "
            "that dispatched it.",
            retryable=True,
        )

    # ENVIRONMENT MISMATCH — refuse, and deliberately WITHOUT WRITING ANYTHING.
    #
    # A mismatch means this id denotes different rows here than where it was dispatched. The row in
    # front of us is then some OTHER deployment's legitimate operation that merely shares an id,
    # and marking it failed would corrupt a healthy range to report a problem with a foreign one.
    # The honest move is to touch nothing and refuse loudly: the operator-visible record belongs in
    # the dispatching database, which this worker cannot reach, and where the expired lease will
    # surface it.
    mismatch = _environment_mismatch(
        operation,
        expected_organization_id=expected_organization_id,
        expected_range_instance_id=expected_range_instance_id,
    )
    if mismatch is not None:
        logger.error("refusing range operation %s: %s", operation_id, mismatch)
        raise RangeExecutionUnresolvable("environment_mismatch", mismatch, retryable=False)

    if operation.status not in (RangeOperationStatus.pending, RangeOperationStatus.running):
        # Already resolved — most likely abandoned by an operator who waited out the lease. Picking
        # it up now would put a second writer on a range somebody is actively recovering.
        raise RangeExecutionUnresolvable(
            "operation_not_in_flight",
            f"range operation {operation_id} is already {operation.status.value} and will not be "
            "executed; it was resolved without this worker.",
            retryable=False,
        )

    staleness = operation_staleness(operation)
    if staleness.stale:
        # The lease this operation was dispatched under has expired, so an operator is entitled to
        # abandon it at any moment. Starting the provider work now would race that recovery.
        _fail_operation(
            session,
            operation,
            "lease_expired",
            f"this operation was picked up after its lease expired at "
            f"{staleness.expires_at.isoformat()}, so it was not executed. {staleness.reason}",
        )
        raise RangeExecutionUnresolvable(
            "lease_expired",
            f"range operation {operation_id} expired at {staleness.expires_at.isoformat()} "
            "before this worker reached it",
            retryable=False,
        )

    instance = session.get(RangeInstance, operation.range_instance_id)
    if instance is None:
        # The operation row IS reachable, so unlike the not-found case this failure can be made
        # visible where an operator will look for it.
        _fail_operation(
            session,
            operation,
            "range_not_found",
            f"range {operation.range_instance_id} does not exist in this worker's database, so "
            "the operation could not be executed.",
        )
        raise RangeExecutionUnresolvable(
            "range_not_found",
            f"range {operation.range_instance_id} for operation {operation_id} is not in this "
            "worker's database",
            retryable=False,
        )

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
        # EXHAUSTIVE, with no ``else``. This dispatch used to end in
        # ``else: _run_bring_up(... provider.deploy(...))``, so any operation kind the worker did
        # not recognise ran a DEPLOY — the fail-open pointed at the most creative action available.
        # A new ``RangeOperationKind`` member added upstream would have been executed as a deploy
        # against real hardware without anyone deciding it should be, and no type checker or test
        # would have said a word. ``assert_never`` makes mypy refuse the file until the new member
        # is given an execution path deliberately.
        if operation.kind is RangeOperationKind.deploy:
            _run_bring_up(session, instance, operation, provider.deploy(spec, ctx), ctx)
        elif operation.kind is RangeOperationKind.reset:
            _run_bring_up(
                session,
                instance,
                operation,
                provider.reset(spec, existing, ctx),
                ctx,
                reset=True,
            )
        elif operation.kind is RangeOperationKind.destroy:
            _run_destroy(session, instance, operation, provider, spec, existing, ctx)
        else:
            assert_never(operation.kind)
    except Exception as exc:  # pragma: no cover - defensive; a provider bug must not wedge a range
        logger.exception("range operation %s failed unexpectedly", operation_id)
        # The rollback discards the identity map, so both rows are re-read. They are bound to NEW
        # names rather than reassigned: ``operation`` and ``instance`` are captured by the
        # ``on_change``/``on_event`` closures above, and rebinding them to an Optional would both
        # widen their type there and, worse, let a later callback write through a different object
        # than the one the operation ran against.
        session.rollback()
        failed_operation = session.get(RangeDeploymentOperation, operation_id)
        failed_instance = (
            session.get(RangeInstance, failed_operation.range_instance_id)
            if failed_operation is not None
            else None
        )
        if failed_operation is not None and failed_instance is not None:
            kind = failed_operation.kind.value
            failed_operation.status = RangeOperationStatus.failed
            failed_operation.failure_code = "internal_error"
            failed_operation.failure_message = str(exc)[:500]
            failed_operation.finished_at = _utcnow()
            failed_instance.state = RangeState.failed
            failed_instance.state_reason = f"the {kind} operation failed unexpectedly"
            record_event(
                session,
                failed_instance,
                kind="operation_failed",
                message=f"The {kind} operation failed unexpectedly: {exc}",
                level="error",
                operation_id=failed_operation.id,
            )
            session.commit()


def _environment_mismatch(
    operation: RangeDeploymentOperation,
    *,
    expected_organization_id: uuid.UUID | None,
    expected_range_instance_id: uuid.UUID | None,
) -> str | None:
    """How the resolved rows differ from what the dispatcher said they were, or ``None``."""
    if (
        expected_organization_id is not None
        and operation.organization_id != expected_organization_id
    ):
        return (
            f"range operation {operation.id} resolves to organization "
            f"{operation.organization_id} in this worker's database, but was dispatched for "
            f"{expected_organization_id}. This worker is attached to a different deployment than "
            "the one that dispatched the work; nothing was executed and nothing was written."
        )
    if (
        expected_range_instance_id is not None
        and operation.range_instance_id != expected_range_instance_id
    ):
        return (
            f"range operation {operation.id} resolves to range {operation.range_instance_id} in "
            f"this worker's database, but was dispatched for range {expected_range_instance_id}. "
            "Nothing was executed and nothing was written."
        )
    return None


def _fail_operation(
    session: Session,
    operation: RangeDeploymentOperation,
    failure_code: str,
    message: str,
) -> None:
    """Persist an operator-visible failure for an operation this worker refuses to run.

    Called only where the operation row is known to belong to THIS database. The range, when it is
    resolvable, goes to ``recovery_required`` rather than ``failed``: this worker did not observe
    the operation go wrong, it declined to start it, and what a previous attempt may have already
    done to the provider is unknown. Every resource row is retained — see
    :func:`secp_api.services.ranges.abandon_operation`, which this mirrors.
    """
    session.rollback()
    row = session.get(RangeDeploymentOperation, operation.id)
    if row is None:  # pragma: no cover - it was just read in this session
        return
    row.status = RangeOperationStatus.failed
    row.failure_code = failure_code
    row.failure_message = message[:500]
    row.finished_at = _utcnow()

    instance = session.get(RangeInstance, row.range_instance_id)
    if instance is not None:
        retain_resources_as_unproven(session, instance)
        instance.state = RangeState.recovery_required
        instance.state_reason = message
        record_event(
            session,
            instance,
            kind="operation_unresolvable",
            message=message,
            level="error",
            operation_id=row.id,
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

    # COVERAGE. A verdict is about the range's whole live set, but the loop above only ever visits
    # what the provider CHOSE to mention. A provider that reports "reachable, and here is nothing"
    # would otherwise score removed=present=unproven=0 and fall straight through to ``clean`` —
    # proving absence of nothing while every resource is still recorded as live.
    #
    # That is not a hypothetical shape. This repo has already shipped a false ``clean`` from a
    # silently narrowed set, and the abandon path deliberately retains every row precisely so the
    # destroy after a recovery is asked about all of them. A teardown that then declines to answer
    # for some of them has not observed them, and unobserved is ``unproven``.
    silent = sorted(name for name in by_name if name not in {o.name for o in result.observations})
    for name in silent:
        row = by_name[name]
        row.state = RangeResourceState.unproven
        unproven += 1
        resource_payload.append(
            {
                "kind": row.kind.value,
                "name": name,
                "external_id": row.external_id,
                "verdict": "unproven",
                "detail": "the teardown returned no observation for this resource",
            }
        )

    # Precedence, strongest CLAIM first — not "worst outcome first".
    #
    # An unreachable probe observed nothing at all, so nothing else it reports means anything:
    # ``unproven``. Otherwise a resource CONFIRMED present is a fact, and a fact outranks an
    # absence of information — reporting ``unproven`` for a range we know still has a container
    # running would understate what we actually established. Only when nothing was confirmed
    # present does unfinished business (an ``unproven`` observation, or a resource the teardown
    # said nothing about) decide it. ``clean`` therefore still requires every live resource to have
    # been individually proved absent.
    #
    # Either way the range lands in ``recovery_required`` and the per-resource states and the
    # evidence row carry the full picture; this only chooses the single headline verdict.
    if not result.probe_reachable:
        verdict = ResidueVerdict.unproven
    elif present:
        verdict = ResidueVerdict.residue
    elif unproven:
        verdict = ResidueVerdict.unproven
    else:
        verdict = ResidueVerdict.clean

    reason = result.reason
    if reason is None:
        parts = []
        if present:
            parts.append(f"{present} owned resource(s) were still present after removal")
        if silent:
            parts.append(
                f"the teardown said nothing about {len(silent)} owned resource(s) "
                f"({', '.join(silent)}), so their absence was not proved"
            )
        reason = "; ".join(parts) or None

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
