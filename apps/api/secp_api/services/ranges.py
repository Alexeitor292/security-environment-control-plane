"""Provider-neutral range lifecycle.

This module owns the state machine and the system of record. It never imports Docker: it asks a
:class:`~secp_api.range_providers.base.RangeProvider` to act and persists what the provider
observed. Swapping in a second provider changes nothing here.

The one rule the whole module is organised around: **a state is only written from an observation.**
There is no code path that sets ``ready`` because a create call returned zero, and no code path
that sets ``destroyed`` because a removal was attempted. ``ready`` requires every component to have
been verified; ``destroyed`` requires a residue verdict of ``clean``, which in turn requires a
probe that proved itself working. When the provider could not observe, the range goes to
``recovery_required`` and says so.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import DomainError, NotFoundError
from secp_api.range_catalog import CATALOG, template_spec_document
from secp_api.range_enums import (
    RANGE_TERMINAL_STATES,
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
    RangeLifecycleEvent,
    RangeProviderResource,
    RangeTeardownEvidence,
    RangeTemplate,
)
from secp_api.range_providers.base import (
    ComponentSpec,
    OperationContext,
    RangeSpec,
    RecordedStep,
    ResourceObservation,
    TeardownResourceOutcome,
)

logger = logging.getLogger("secp.api.range")


class RangeNotFoundError(NotFoundError):
    code = "range_not_found"


class RangeInvalidTransitionError(DomainError):
    http_status = 409
    code = "range_invalid_transition"


class RangeProviderUnavailableError(DomainError):
    http_status = 503
    code = "range_provider_unavailable"


#: Which states each operation may start from.
_ALLOWED_FROM: dict[RangeOperationKind, frozenset[RangeState]] = {
    RangeOperationKind.deploy: frozenset({RangeState.draft, RangeState.failed}),
    RangeOperationKind.reset: frozenset({RangeState.ready, RangeState.active, RangeState.failed}),
    RangeOperationKind.destroy: frozenset(
        {
            RangeState.draft,
            RangeState.ready,
            RangeState.active,
            RangeState.failed,
            RangeState.recovery_required,
        }
    ),
}

_IN_FLIGHT: dict[RangeOperationKind, RangeState] = {
    RangeOperationKind.deploy: RangeState.deploying,
    RangeOperationKind.reset: RangeState.resetting,
    RangeOperationKind.destroy: RangeState.destroying,
}


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --- catalog ------------------------------------------------------------------


def sync_catalog(session: Session) -> list[RangeTemplate]:
    """Upsert the shipped catalog into the templates table.

    A deployed range keeps a foreign key to the row it was built from, so rows are updated in place
    rather than replaced — an existing range must never lose its template.
    """
    rows: list[RangeTemplate] = []
    for template in CATALOG:
        row = session.execute(
            select(RangeTemplate).where(RangeTemplate.slug == template.slug)
        ).scalar_one_or_none()
        if row is None:
            row = RangeTemplate(slug=template.slug)
            session.add(row)
        row.name = template.name
        row.summary = template.summary
        row.description = template.description
        row.provider = template.provider
        row.difficulty = template.difficulty
        row.estimated_deploy_seconds = template.estimated_deploy_seconds
        row.warning = template.warning
        row.spec = template_spec_document(template)
        rows.append(row)
    session.flush()
    return rows


def list_templates(session: Session) -> list[RangeTemplate]:
    sync_catalog(session)
    return list(session.execute(select(RangeTemplate).order_by(RangeTemplate.name)).scalars().all())


def get_template_row(session: Session, slug: str) -> RangeTemplate:
    sync_catalog(session)
    row = session.execute(
        select(RangeTemplate).where(RangeTemplate.slug == slug)
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"range template '{slug}' not found")
    return row


# --- ranges -------------------------------------------------------------------


def create_range(
    session: Session,
    principal: Principal,
    *,
    template_slug: str,
    name: str | None = None,
) -> RangeInstance:
    principal.require(Permission.exercise_operate)
    template_row = get_template_row(session, template_slug)
    instance = RangeInstance(
        organization_id=principal.organization_id,
        template_id=template_row.id,
        name=(name or template_row.name).strip()[:200],
        provider=template_row.provider,
        state=RangeState.draft,
        resource_prefix=secrets.token_hex(3),
        created_by=principal.user_id,
    )
    session.add(instance)
    session.flush()
    record_event(
        session,
        instance,
        kind="range_created",
        message=f"Range '{instance.name}' created from template '{template_row.slug}'",
    )
    return instance


def list_ranges(
    session: Session,
    principal: Principal,
    *,
    states: list[RangeState] | None = None,
    include_destroyed: bool = False,
) -> list[RangeInstance]:
    principal.require(Permission.exercise_operate)
    stmt = select(RangeInstance).where(RangeInstance.organization_id == principal.organization_id)
    if states:
        stmt = stmt.where(RangeInstance.state.in_(states))
    elif not include_destroyed:
        stmt = stmt.where(RangeInstance.state != RangeState.destroyed)
    stmt = stmt.order_by(RangeInstance.created_at.desc())
    return list(session.execute(stmt).scalars().all())


def get_range(session: Session, principal: Principal, range_id: uuid.UUID) -> RangeInstance:
    principal.require(Permission.exercise_operate)
    instance = session.get(RangeInstance, range_id)
    if instance is None:
        raise RangeNotFoundError("range not found")
    principal.require_org(instance.organization_id)
    return instance


def list_resources(
    session: Session, principal: Principal, range_id: uuid.UUID
) -> list[RangeProviderResource]:
    instance = get_range(session, principal, range_id)
    return list(
        session.execute(
            select(RangeProviderResource)
            .where(RangeProviderResource.range_instance_id == instance.id)
            .order_by(RangeProviderResource.created_at)
        )
        .scalars()
        .all()
    )


def list_operations(
    session: Session, principal: Principal, range_id: uuid.UUID
) -> list[RangeDeploymentOperation]:
    instance = get_range(session, principal, range_id)
    return list(
        session.execute(
            select(RangeDeploymentOperation)
            .where(RangeDeploymentOperation.range_instance_id == instance.id)
            .order_by(RangeDeploymentOperation.started_at.desc())
        )
        .scalars()
        .all()
    )


def get_operation(
    session: Session, principal: Principal, operation_id: uuid.UUID
) -> RangeDeploymentOperation:
    principal.require(Permission.exercise_operate)
    operation = session.get(RangeDeploymentOperation, operation_id)
    if operation is None:
        raise NotFoundError("range operation not found")
    principal.require_org(operation.organization_id)
    return operation


def current_operation(session: Session, instance: RangeInstance) -> RangeDeploymentOperation | None:
    return session.execute(
        select(RangeDeploymentOperation)
        .where(RangeDeploymentOperation.range_instance_id == instance.id)
        .order_by(RangeDeploymentOperation.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def list_events(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    after_sequence: int = 0,
) -> list[RangeLifecycleEvent]:
    instance = get_range(session, principal, range_id)
    return list(
        session.execute(
            select(RangeLifecycleEvent)
            .where(
                RangeLifecycleEvent.range_instance_id == instance.id,
                RangeLifecycleEvent.sequence > after_sequence,
            )
            .order_by(RangeLifecycleEvent.sequence)
        )
        .scalars()
        .all()
    )


def list_teardown_evidence(
    session: Session, principal: Principal, range_id: uuid.UUID
) -> list[RangeTeardownEvidence]:
    instance = get_range(session, principal, range_id)
    return list(
        session.execute(
            select(RangeTeardownEvidence)
            .where(RangeTeardownEvidence.range_instance_id == instance.id)
            .order_by(RangeTeardownEvidence.observed_at.desc())
        )
        .scalars()
        .all()
    )


def record_event(
    session: Session,
    instance: RangeInstance,
    *,
    kind: str,
    message: str,
    level: str = "info",
    data: dict | None = None,
    operation_id: uuid.UUID | None = None,
) -> RangeLifecycleEvent:
    instance.event_sequence += 1
    event = RangeLifecycleEvent(
        organization_id=instance.organization_id,
        range_instance_id=instance.id,
        operation_id=operation_id,
        sequence=instance.event_sequence,
        kind=kind,
        level=level,
        message=message,
        data=data or {},
    )
    session.add(event)
    session.flush()
    return event


# --- operation start ----------------------------------------------------------


def build_spec(session: Session, instance: RangeInstance) -> RangeSpec:
    """The provider-facing spec, built from the template row that this range was created from."""
    template_row = session.get(RangeTemplate, instance.template_id)
    if template_row is None:
        raise NotFoundError("the range's template no longer exists")
    components = tuple(
        ComponentSpec(
            key=component["key"],
            name=component["name"],
            role=component.get("role", "target"),
            image=component["image"],
            container_port=component.get("container_port"),
            protocol=component.get("protocol", "http"),
            path=component.get("path", "/"),
            env=dict(component.get("env") or {}),
            readiness_timeout_seconds=int(component.get("readiness_timeout_seconds") or 180),
        )
        for component in (template_row.spec or {}).get("components", [])
    )
    return RangeSpec(
        range_id=str(instance.id),
        resource_prefix=instance.resource_prefix,
        components=components,
    )


def start_operation(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    kind: RangeOperationKind,
) -> tuple[RangeInstance, RangeDeploymentOperation]:
    """Validate the transition, create the operation row, and move the range into its in-flight
    state. The work itself is run by :mod:`secp_api.services.range_runner`."""
    instance = get_range(session, principal, range_id)
    permission = {
        RangeOperationKind.deploy: Permission.exercise_apply,
        RangeOperationKind.reset: Permission.exercise_reset,
        RangeOperationKind.destroy: Permission.exercise_destroy,
    }[kind]
    principal.require(permission)

    if instance.state in RANGE_TERMINAL_STATES:
        raise RangeInvalidTransitionError(f"a {instance.state.value} range cannot {kind.value}")
    if instance.state not in _ALLOWED_FROM[kind]:
        raise RangeInvalidTransitionError(
            f"cannot {kind.value} a range in state '{instance.state.value}'"
        )

    in_flight = (
        session.execute(
            select(RangeDeploymentOperation).where(
                RangeDeploymentOperation.range_instance_id == instance.id,
                RangeDeploymentOperation.status.in_(
                    [RangeOperationStatus.pending, RangeOperationStatus.running]
                ),
            )
        )
        .scalars()
        .first()
    )
    if in_flight is not None:
        raise RangeInvalidTransitionError(
            f"a {in_flight.kind.value} operation is already running on this range"
        )

    from secp_api.range_providers import get_provider

    provider = get_provider(instance.provider)
    spec = build_spec(session, instance)
    steps = provider.plan_steps(spec, kind.value)

    operation = RangeDeploymentOperation(
        organization_id=instance.organization_id,
        range_instance_id=instance.id,
        kind=kind,
        status=RangeOperationStatus.pending,
        total_steps=len(steps),
        completed_steps=0,
        steps=[_step_dict(step) for step in steps],
        requested_by=principal.user_id,
    )
    session.add(operation)
    instance.state = _IN_FLIGHT[kind]
    instance.state_reason = None
    session.flush()
    record_event(
        session,
        instance,
        kind=f"{kind.value}_requested",
        message=f"{kind.value.capitalize()} requested",
        operation_id=operation.id,
    )
    return instance, operation


def _step_dict(step: RecordedStep) -> dict:
    return {
        "key": step.key,
        "label": step.label,
        "status": step.status.value if hasattr(step.status, "value") else str(step.status),
        "detail": step.detail,
        "at": step.at,
    }


# --- operation execution (called by the runner, with its own session) ---------


def execute_operation(session: Session, operation_id: uuid.UUID) -> None:
    """Run one operation to completion against the provider and persist every observation.

    Called on a background thread with a dedicated session. Progress is committed as it happens so
    a poller sees movement; the final state is written once, from the provider's result.
    """
    operation = session.get(RangeDeploymentOperation, operation_id)
    if operation is None:
        logger.warning("range operation %s vanished before execution", operation_id)
        return
    instance = session.get(RangeInstance, operation.range_instance_id)
    if instance is None:
        logger.warning("range %s vanished before execution", operation.range_instance_id)
        return

    from secp_api.range_providers import get_provider

    provider = get_provider(instance.provider)
    spec = build_spec(session, instance)

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
