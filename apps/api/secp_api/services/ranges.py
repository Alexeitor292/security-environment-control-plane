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
