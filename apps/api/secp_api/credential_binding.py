"""Opaque, versioned target credential BINDING (B1B-PR4 amendment §2).

Closes the post-approval ``secret_ref`` substitution gap **without ever storing the reference or a
hash of it**.

The problem: ``ExecutionTarget.secret_ref`` is an opaque pointer, not an immutable column. A
plan-secret authorization could be approved against reference *A* and then silently serve reference
*B* — and PR4 may not persist a secret-reference hash (that is itself forbidden), so no stored value
would change.

The fix: a bare **opaque id + monotonic version** that names the target's *credential selection*
without describing it. Any change to ``secret_ref`` **rotates** the binding, and the binding id +
version are folded into the readiness **operation fingerprint** — so a rotation invalidates every
prior authorization and readiness record while leaving all historical evidence untouched.

Rotation is enforced twice:

* an ORM ``before_flush`` hook (in :mod:`secp_api.immutability`) — the portable SQLite + PostgreSQL
  layer, covering every ORM write; and
* a PostgreSQL trigger (installed by the PR4 migration) — covering a raw/Core ``UPDATE`` that
  bypasses the ORM entirely.

This module stores NO secret, NO secret reference, NO hash of a reference, NO locator, and
NO backend path. The actual reference stays worker-only and is compared **in memory only**.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from secp_api.enums import CredentialBindingStatus, CredentialPurposeClass
from secp_api.models import CredentialBinding, ExecutionTarget


def _utcnow() -> datetime:
    return datetime.now(UTC)


def active_credential_binding(
    session: Session,
    execution_target_id: uuid.UUID,
    purpose_class: CredentialPurposeClass = CredentialPurposeClass.provider_plan_read,
) -> CredentialBinding | None:
    """The single ACTIVE opaque binding for a (target, purpose class), or ``None``."""
    return (
        session.execute(
            select(CredentialBinding).where(
                CredentialBinding.execution_target_id == execution_target_id,
                CredentialBinding.purpose_class == purpose_class,
                CredentialBinding.status == CredentialBindingStatus.active,
            )
        )
        .scalars()
        .one_or_none()
    )


def _next_version(
    session: Session, execution_target_id: uuid.UUID, purpose_class: CredentialPurposeClass
) -> int:
    current = session.execute(
        select(func.max(CredentialBinding.binding_version)).where(
            CredentialBinding.execution_target_id == execution_target_id,
            CredentialBinding.purpose_class == purpose_class,
        )
    ).scalar()
    return int(current or 0) + 1


def ensure_credential_binding(
    session: Session,
    target: ExecutionTarget,
    purpose_class: CredentialPurposeClass = CredentialPurposeClass.provider_plan_read,
    *,
    created_by: uuid.UUID | None = None,
) -> CredentialBinding | None:
    """Return the active binding for the target's CURRENT credential selection, creating v1 if none.

    A target with no ``secret_ref`` has no credential selection, hence no binding (and therefore can
    never satisfy plan-secret readiness).
    """
    if not target.secret_ref:
        return None
    existing = active_credential_binding(session, target.id, purpose_class)
    if existing is not None:
        return existing
    # The id is assigned CLIENT-side: ``rotate_credential_binding`` runs inside the ORM
    # ``before_flush`` hook, where a nested ``Session.flush()`` is illegal — so no function here may
    # flush, and the audit record must be able to name the row immediately.
    row = CredentialBinding(
        id=uuid.uuid4(),
        organization_id=target.organization_id,
        execution_target_id=target.id,
        purpose_class=purpose_class,
        binding_version=_next_version(session, target.id, purpose_class),
        status=CredentialBindingStatus.active,
        created_by=created_by,
    )
    session.add(row)
    _audit(session, row, created=True)
    return row


def rotate_credential_binding(
    session: Session,
    target: ExecutionTarget,
    purpose_class: CredentialPurposeClass = CredentialPurposeClass.provider_plan_read,
    *,
    rotated_by: uuid.UUID | None = None,
) -> CredentialBinding | None:
    """Retire the active binding and issue the next version.

    Called automatically whenever ``ExecutionTarget.secret_ref`` changes. It is NOT a caller
    decision: a credential replacement can never be invisible.
    """
    now = _utcnow()
    _announce_rotation(session)
    existing = active_credential_binding(session, target.id, purpose_class)
    if existing is not None:
        existing.status = CredentialBindingStatus.rotated
        existing.rotated_at = now
    if not target.secret_ref:
        # The credential selection was removed entirely: no active binding remains.
        return None
    row = CredentialBinding(
        id=uuid.uuid4(),
        organization_id=target.organization_id,
        execution_target_id=target.id,
        purpose_class=purpose_class,
        binding_version=_next_version(session, target.id, purpose_class),
        status=CredentialBindingStatus.active,
        created_by=rotated_by,
    )
    session.add(row)
    _audit(session, row, created=False)
    return row


def _announce_rotation(session: Session) -> None:
    """Tell PostgreSQL that the SUPPORTED rotation path is handling this ``secret_ref`` change.

    The migration installs a ``BEFORE UPDATE`` trigger on ``execution_target`` that AUTO-ROTATES the
    opaque binding whenever ``secret_ref`` changes — so a raw/Core ``UPDATE`` that bypasses the ORM
    entirely still cannot replace a credential UNNOTICED. This transaction-scoped flag tells the
    trigger the ORM has already rotated, so the rotation is applied exactly once.

    The flag is set only while a rotation is genuinely in flight, and ``SET LOCAL`` confines it to
    the current transaction. On SQLite it is a no-op (the ORM hook is the whole enforcement there).
    """
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    # ``SET LOCAL`` is confined to the CURRENT transaction, so the announcement can never leak into
    # a later transaction on the same pooled connection and silently suppress the trigger there.
    session.execute(text("SET LOCAL secp.credential_rotation = 'on'"))


def _audit(session: Session, row: CredentialBinding, *, created: bool) -> None:
    """Bounded, secret-free audit. It carries an OPAQUE id + version and nothing else."""
    from secp_api import audit
    from secp_api.enums import AuditAction

    audit.record(
        session,
        action=(
            AuditAction.credential_binding_created
            if created
            else AuditAction.credential_binding_rotated
        ),
        resource_type="credential_binding",
        resource_id=row.id,
        organization_id=row.organization_id,
        actor="system",
        data={
            "credential_binding_id": str(row.id),
            "credential_binding_version": row.binding_version,
            "execution_target_id": str(row.execution_target_id),
            "purpose_class": getattr(row.purpose_class, "value", row.purpose_class),
        },
    )
