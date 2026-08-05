"""Provider-neutral range lifecycle — the CONTROL half.

This module owns the state machine, the authorization checks and the system of record. It does not
execute anything: it validates a transition, writes the operation row, and stops. The privileged
half — anything that reaches a provider, and therefore a Docker socket — lives in
:mod:`secp_worker.range.execution` and is reached only by dispatching through
:mod:`secp_api.dispatch` (Charter Invariants 6/7, ADR-005).

So there is deliberately no ``execute_*`` function here, and no provider is ever constructed. If
you are looking for where ``ready`` and ``destroyed`` get written, it is the worker.

The rule that governs both halves: **a state is only written from an observation.** Nothing sets
``ready`` because a create call returned zero, and nothing sets ``destroyed`` because a removal was
attempted. When the provider could not observe, the range goes to ``recovery_required`` and says so.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

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
)
from secp_api.range_models import (
    RangeDeploymentOperation,
    RangeInstance,
    RangeLifecycleEvent,
    RangeProviderResource,
    RangeTeardownEvidence,
    RangeTemplate,
)
from secp_api.range_providers.base import ComponentSpec, RangeSpec

logger = logging.getLogger("secp.api.range")


class RangeNotFoundError(NotFoundError):
    code = "range_not_found"


class RangeInvalidTransitionError(DomainError):
    http_status = 409
    code = "range_invalid_transition"


class RangeProviderUnavailableError(DomainError):
    http_status = 503
    code = "range_provider_unavailable"


class RangeOperationNotStaleError(DomainError):
    """Refuses to abandon an operation that may still be executing.

    Abandoning a LIVE operation is how you get two writers on one range, so the lease has to have
    expired — or the caller has to say, explicitly, that they have checked.
    """

    http_status = 409
    code = "range_operation_not_stale"


#: The statuses an operation can be stranded in. Terminal statuses are already resolved.
_IN_FLIGHT_OPERATION_STATUSES: frozenset[RangeOperationStatus] = frozenset(
    {RangeOperationStatus.pending, RangeOperationStatus.running}
)


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

#: The permission each operation kind requires — to START one, and equally to ABANDON one.
_KIND_PERMISSION: dict[RangeOperationKind, Permission] = {
    RangeOperationKind.deploy: Permission.exercise_apply,
    RangeOperationKind.reset: Permission.exercise_reset,
    RangeOperationKind.destroy: Permission.exercise_destroy,
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


#: How long an in-flight operation may go without observable progress before an operator is
#: allowed to treat it as stranded.
#:
#: This is a LEASE, not a timeout on the work: it is renewed by progress (see
#: :func:`operation_staleness`), so a slow-but-moving deploy never looks stale, while an operation
#: whose worker went away — crashed, pointed at another database, never picked it up — expires.
#:
#: Deliberately derived from columns that ALREADY EXIST. The range tables are created by
#: ``Base.metadata.create_all``, which creates missing TABLES but never adds a column to a table
#: that is already there. A new ``lease_expires_at`` column would therefore be present on fresh
#: databases and silently absent on every deployed one — the failure mode this whole file is about.
#: ``started_at`` and the per-step ``at`` stamps are durable, already written on every progress
#: commit, and mean the same thing on both.
OPERATION_LEASE_SECONDS = 900


@dataclass(frozen=True)
class OperationStaleness:
    """Whether an in-flight operation has stopped making observable progress, and why."""

    #: The most recent durable evidence that this operation was alive.
    last_progress_at: datetime
    #: ``last_progress_at`` + the lease. Past this, an operator may abandon the operation.
    expires_at: datetime
    stale: bool
    #: Operator-facing sentence. ``None`` exactly when ``stale`` is false.
    reason: str | None


def _parse_step_at(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def operation_staleness(
    operation: RangeDeploymentOperation, *, now: datetime | None = None
) -> OperationStaleness:
    """Derive the operation's lease from durable state alone.

    Progress renews the lease: every ``on_change`` commit in the worker stamps ``at`` on each step
    that reached a terminal status, so the newest step stamp is a heartbeat that survives a process
    restart. An operation that never got picked up has no step stamps at all and leases from
    ``started_at``, which is exactly right — dispatch is the last thing that was known to happen.

    A terminal operation is never stale: there is nothing left to strand.
    """
    moment = now or _utcnow()
    started = operation.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)

    stamps = [
        parsed
        for parsed in (_parse_step_at(step.get("at")) for step in (operation.steps or []))
        if parsed is not None
    ]
    last_progress_at = max([started, *stamps])
    expires_at = last_progress_at + timedelta(seconds=OPERATION_LEASE_SECONDS)

    if operation.status not in _IN_FLIGHT_OPERATION_STATUSES or moment <= expires_at:
        return OperationStaleness(
            last_progress_at=last_progress_at, expires_at=expires_at, stale=False, reason=None
        )

    if operation.status is RangeOperationStatus.pending:
        detail = (
            "it was never picked up by a worker — the queue may have no worker on it, or the "
            "worker that took it is connected to a different database"
        )
    else:
        detail = "the worker running it stopped reporting progress"
    elapsed = int((moment - last_progress_at).total_seconds())
    return OperationStaleness(
        last_progress_at=last_progress_at,
        expires_at=expires_at,
        stale=True,
        reason=(
            f"the {operation.kind.value} operation has made no observable progress for "
            f"{elapsed // 60} minute(s): {detail}"
        ),
    )


def abandon_operation(
    session: Session,
    principal: Principal,
    operation_id: uuid.UUID,
    *,
    force: bool = False,
) -> tuple[RangeInstance, RangeDeploymentOperation]:
    """Release a stranded operation and move its range to ``recovery_required``.

    This is the operator's replacement for the ``UPDATE range_deployment_operation`` surgery that
    was, before this existed, the only way out of a range wedged in ``resetting``.

    What it does NOT do is decide what happened. The operation becomes ``unproven``, never
    ``failed``: nobody observed it fail — it stopped being observable, which is a different claim.
    For the same reason the range becomes ``recovery_required`` rather than ``failed`` or
    ``destroyed``.

    **Every resource this range has ever created stays enumerated.** Rows are never retired here
    and ``removed_at`` is never written: execution disappearing is not evidence that anything was
    removed. Resources previously observed responding drop to ``unproven`` — they may still be
    running, and they are still this range's to clean up. A subsequent destroy therefore still
    sweeps the complete set, and can only reach ``clean`` by actually proving each one absent.
    """
    operation = get_operation(session, principal, operation_id)
    # AUTHORIZED as the operation's own kind, not merely as "can see this range". ``get_operation``
    # already checked ``exercise_operate``, which is the READ permission — anyone who can view a
    # range holds it. Abandoning changes state and opens the range to destroy, so the bar is the
    # one that would have let you start the operation in the first place: you may release a stuck
    # reset if you could have requested that reset.
    principal.require(_KIND_PERMISSION[operation.kind])

    if operation.status not in _IN_FLIGHT_OPERATION_STATUSES:
        raise RangeInvalidTransitionError(
            f"operation is already {operation.status.value}; there is nothing to abandon"
        )

    staleness = operation_staleness(operation)
    if not staleness.stale and not force:
        raise RangeOperationNotStaleError(
            f"the {operation.kind.value} operation is still within its lease until "
            f"{staleness.expires_at.isoformat()}; it may still be running. Abandon it anyway with "
            "force=true only if you have confirmed no worker is executing it."
        )

    instance = session.get(RangeInstance, operation.range_instance_id)
    if instance is None:  # pragma: no cover - FK makes this unreachable
        raise RangeNotFoundError("range not found")

    reason = staleness.reason or (
        f"the {operation.kind.value} operation was abandoned by an operator while in flight"
    )

    operation.status = RangeOperationStatus.unproven
    operation.failure_code = "abandoned_stale" if staleness.stale else "abandoned_by_operator"
    operation.failure_message = reason
    operation.finished_at = _utcnow()

    retained = retain_resources_as_unproven(session, instance)

    instance.state = RangeState.recovery_required
    instance.state_reason = reason
    session.flush()

    record_event(
        session,
        instance,
        kind="operation_abandoned",
        message=(
            f"The {operation.kind.value} operation was abandoned: {reason}. This is NOT a "
            f"failure and NOT a rollback — what the operation did or did not do is unknown. "
            f"{retained} resource(s) remain recorded as this range's to clean up; none were "
            "marked absent, because nothing observed them absent. Destroy the range to sweep "
            "them, which will prove each one gone or report that it could not."
        ),
        level="warning",
        operation_id=operation.id,
    )
    return instance, operation


def retain_resources_as_unproven(session: Session, instance: RangeInstance) -> int:
    """Keep every live resource row, downgrading proved-healthy ones to ``unproven``.

    ``removed_at`` is untouched on purpose — it is the flag that takes a row out of the destroy
    sweep, and writing it here would narrow the set a later teardown is asked about. That exact
    narrowing once produced a ``clean`` destroy with a container and a network still running.
    """
    rows = list(
        session.execute(
            select(RangeProviderResource).where(
                RangeProviderResource.range_instance_id == instance.id,
                RangeProviderResource.removed_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        if row.state is not RangeResourceState.failed:
            # ``verified`` meant "observed responding", which is no longer known. ``created`` and
            # ``pending`` are already honest about not being proved.
            row.state = RangeResourceState.unproven
    return len(rows)


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
    principal.require(_KIND_PERMISSION[kind])

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
                RangeDeploymentOperation.status.in_(sorted(_IN_FLIGHT_OPERATION_STATUSES)),
            )
        )
        .scalars()
        .first()
    )
    if in_flight is not None:
        # A blocked operator used to get "a reset operation is already running on this range" for
        # an operation that had not run in hours and never would. Say which it is, and name the
        # way out — the alternative, discovered the hard way, is hand-written UPDATE statements.
        staleness = operation_staleness(in_flight)
        if staleness.stale:
            raise RangeInvalidTransitionError(
                f"a {in_flight.kind.value} operation is stuck on this range: {staleness.reason}. "
                f"Abandon it (POST /api/v1/range-operations/{in_flight.id}/abandon) to move the "
                "range to recovery_required, then destroy it."
            )
        raise RangeInvalidTransitionError(
            f"a {in_flight.kind.value} operation is already running on this range"
        )

    # The operation is created with NO steps. Asking a provider what it plans to do requires
    # holding a provider, and the API may not (Charter Invariants 6/7) — so the worker plans the
    # steps when it picks the operation up, and they appear on the next poll. Until then
    # ``total_steps`` is 0 and ``percent`` is 0, which is exactly right for a ``pending`` operation.
    operation = RangeDeploymentOperation(
        organization_id=instance.organization_id,
        range_instance_id=instance.id,
        kind=kind,
        status=RangeOperationStatus.pending,
        total_steps=0,
        completed_steps=0,
        steps=[],
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
