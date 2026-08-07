"""Audit service. Every mutation creates an immutable AuditEvent (Invariant 10)."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from secp_api.enums import AuditAction, AuditOutcome
from secp_api.models import AuditEvent


def record(
    session: Session,
    *,
    action: AuditAction | str,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    actor: str = "system",
    organization_id: uuid.UUID | None = None,
    outcome: AuditOutcome = AuditOutcome.success,
    data: dict | None = None,
) -> AuditEvent:
    """Append an audit event to the session (committed with the surrounding tx).

    ``outcome`` is deliberately NOT ``AuditOutcome | str``. The union is what let a ninth spelling
    (``failure``, alongside the ``failed`` used everywhere else) and a whole foreign vocabulary
    (eligibility verdicts) into a column that is append-only and therefore unrepairable. Widening
    it back would restore exactly that. ``action`` still carries the union, and that is a separate
    problem this change does not pretend to have solved.
    """
    event = AuditEvent(
        organization_id=organization_id,
        actor=str(actor),
        action=action.value if isinstance(action, AuditAction) else str(action),
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        outcome=outcome.value,
        data=data or {},
    )
    session.add(event)
    return event
