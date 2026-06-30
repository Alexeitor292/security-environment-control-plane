"""Audit service. Every mutation creates an immutable AuditEvent (Invariant 10)."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from secp_api.enums import AuditAction
from secp_api.models import AuditEvent


def record(
    session: Session,
    *,
    action: AuditAction | str,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    actor: str = "system",
    organization_id: uuid.UUID | None = None,
    outcome: str = "success",
    data: dict | None = None,
) -> AuditEvent:
    """Append an audit event to the session (committed with the surrounding tx)."""
    event = AuditEvent(
        organization_id=organization_id,
        actor=str(actor),
        action=action.value if isinstance(action, AuditAction) else str(action),
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        outcome=outcome,
        data=data or {},
    )
    session.add(event)
    return event
