"""Live-schema readiness for durable worker enrollment (SECP-PR5H-A, ADR-027).

Signed-artifact compatibility and live-schema readiness are **different questions with different
answers**, and conflating them is the failure this module exists to prevent:

* the deployment plane keeps a BOUNDED accepted-head window so an ALREADY-ISSUED PR5F
  ``ControllerOffer`` stays verifiable during a rolling upgrade;
* accepting such an offer says **nothing** about whether the PR5H enrollment tables exist.

Therefore every PR5H enrollment operation — repository read/write, transactional CAS, nonce-ledger
consumption, and the recovery sweep — must **independently observe the LIVE database head** and
require exactly :data:`RUNTIME_REQUIRED_MIGRATION_HEAD`.  An older (legacy) live schema, an unknown
head, a branched/multi-row ``alembic_version``, or an unreadable version table all refuse closed.

This module deliberately does NOT import the deployment plane (a reviewed plane boundary); the
control plane owns its own migrations, so it owns its own required head.  A cross-plane test proves
this value agrees with the deployment window's current head and with the real Alembic sole head.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import text
from sqlalchemy.orm import Session

#: The ONLY live schema head at which PR5H enrollment operations may run (never the legacy head).
RUNTIME_REQUIRED_MIGRATION_HEAD: Final = "b6e2f4a9c1d7"


class EnrollmentSchemaError(RuntimeError):
    """The live schema is not at the required PR5H head; carries a bounded closed reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def observed_migration_head(session: Session) -> str | None:
    """The single live Alembic head, or ``None`` when absent/unreadable/branched.

    A branched or multi-row ``alembic_version`` is deliberately reported as ``None`` (not "the first
    row"), so an ambiguous schema refuses closed rather than being silently accepted."""
    try:
        rows = session.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
    except Exception:  # noqa: BLE001 - a missing/unreadable version table is "not ready"
        return None
    if len(rows) != 1:
        return None
    head = rows[0]
    return head if isinstance(head, str) and head else None


def enrollment_schema_ready(session: Session) -> bool:
    """True only when the LIVE head is exactly the required PR5H head."""
    return observed_migration_head(session) == RUNTIME_REQUIRED_MIGRATION_HEAD


def assert_enrollment_schema_ready(session: Session) -> None:
    """Refuse closed unless the live schema is exactly at the required PR5H head.

    Called at the start of every enrollment repository / CAS / nonce-ledger / recovery operation."""
    if not enrollment_schema_ready(session):
        raise EnrollmentSchemaError("enrollment_schema_head_unavailable")


__all__ = [
    "RUNTIME_REQUIRED_MIGRATION_HEAD",
    "EnrollmentSchemaError",
    "assert_enrollment_schema_ready",
    "enrollment_schema_ready",
    "observed_migration_head",
]
