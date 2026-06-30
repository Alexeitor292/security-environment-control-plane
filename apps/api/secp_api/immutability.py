"""ORM-level immutability guards (Charter Invariants 2, 10; ADR-002).

These are the portable (SQLite + PostgreSQL) enforcement layer. The dev/prod
PostgreSQL migration additionally installs a database trigger so even raw SQL
cannot mutate a published version; the service layer provides no update path at
all. Defense in depth.
"""

from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from secp_api.errors import ImmutableResourceError
from secp_api.models import AuditEvent, EnvironmentVersion

_VERSION_PROTECTED = ("spec", "content_hash", "version_number", "api_version")


def _attr_changed(obj: object, attr: str) -> bool:
    state = inspect(obj)
    assert state is not None  # ORM-mapped instances always have inspection state
    return state.attrs[attr].history.has_changes()


@event.listens_for(Session, "before_flush")
def _block_immutable_mutations(session: Session, _flush_context, _instances) -> None:
    # Reject updates to protected columns of a published EnvironmentVersion.
    for obj in session.dirty:
        if isinstance(obj, EnvironmentVersion):
            changed = [a for a in _VERSION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    f"EnvironmentVersion is immutable after creation; attempted to change {changed}"
                )
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records are immutable")

    # Reject deletes of audit events (they are append-only).
    for obj in session.deleted:
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records cannot be deleted")


def install_guards() -> None:
    """Idempotent import hook. Importing this module registers the listeners."""
    # Listeners are registered at import time; this function exists so callers can
    # make the dependency explicit and obvious.
    return None
