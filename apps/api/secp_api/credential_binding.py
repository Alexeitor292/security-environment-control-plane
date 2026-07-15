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

**B1B-PR5A — operation-specific credential separation (ADR-022).** A target may carry two distinct,
independently-rotating opaque credential selections:

* ``provider_plan_read`` — sourced from the dedicated ``ExecutionTarget.provider_plan_secret_ref``,
  falling back to the generic ``secret_ref`` for simulated/dev compatibility. (A real-plan gate
  additionally REQUIRES the dedicated column and refuses the generic fallback.)
* ``state_backend_plan`` — sourced ONLY from the dedicated
``ExecutionTarget.state_backend_secret_ref``
  (never the generic ``secret_ref``).

Each purpose has its own versioned binding; changing one reference rotates only its matching
binding.
Apply and destroy purposes are unrepresentable, so no apply/destroy binding can ever be created.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from secp_api.enums import (
    CredentialBindingSource,
    CredentialBindingStatus,
    CredentialPurposeClass,
)
from secp_api.models import CredentialBinding, ExecutionTarget

# Every credential purpose a target binding may serve. Rotation + ensure iterate over these.
CREDENTIAL_PURPOSES: tuple[CredentialPurposeClass, ...] = (
    CredentialPurposeClass.provider_plan_read,
    CredentialPurposeClass.state_backend_plan,
)

# B1B-PR5A amendment §1. The provider plan-read credential and the state-backend plan credential
# MUST be two distinct authoritative selections. Sharing one reference across both purposes is
# permitted ONLY under an explicit, reviewed provider contract — which does not exist yet, so the
# real-plan gate always requires distinct references.
REAL_PLAN_SHARED_CREDENTIAL_CONTRACT_VERSION: str | None = None


class RealPlanCredentialError(Exception):
    """A real-plan credential prerequisite is not satisfied by a DEDICATED, distinct selection.

    Raised by the strict real-plan resolvers. It never echoes a reference or a value — only a
    bounded reason code identifying which dedicated selection is missing/invalid.
    """

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def purpose_reference(target: ExecutionTarget, purpose_class: CredentialPurposeClass) -> str | None:
    """The opaque reference that SOURCES one purpose's binding — never persisted, never hashed.

    This is the DEV/SIMULATED-compatible resolver used by ``ensure``/``rotate`` to decide whether a
    binding exists at all. ``provider_plan_read`` prefers the dedicated ``provider_plan_secret_ref``
    and falls back to the generic ``secret_ref``; ``state_backend_plan`` uses ONLY the dedicated
    ``state_backend_secret_ref``. The REAL-PLAN path never calls this — it calls
    :func:`require_real_plan_credential_reference`, which refuses the generic fallback outright.

    Returns ``None`` when the purpose has no selected reference (hence no active binding).
    """
    if purpose_class is CredentialPurposeClass.provider_plan_read:
        return getattr(target, "provider_plan_secret_ref", None) or target.secret_ref
    if purpose_class is CredentialPurposeClass.state_backend_plan:
        return getattr(target, "state_backend_secret_ref", None)
    return None  # pragma: no cover - defensive; no other purpose is representable


def dedicated_reference(
    target: ExecutionTarget, purpose_class: CredentialPurposeClass
) -> str | None:
    """The DEDICATED operation reference for a purpose — NEVER the generic ``secret_ref`` fallback.

    ``provider_plan_read`` → ``provider_plan_secret_ref`` only; ``state_backend_plan`` →
    ``state_backend_secret_ref`` only. Returns ``None`` when the dedicated reference is absent.
    """
    if purpose_class is CredentialPurposeClass.provider_plan_read:
        return getattr(target, "provider_plan_secret_ref", None)
    if purpose_class is CredentialPurposeClass.state_backend_plan:
        return getattr(target, "state_backend_secret_ref", None)
    return None  # pragma: no cover - defensive; no other purpose is representable


def _binding_source(
    target: ExecutionTarget, purpose_class: CredentialPurposeClass
) -> CredentialBindingSource:
    """Classify how the CURRENT binding for a purpose is sourced (dedicated vs generic fallback)."""
    if dedicated_reference(target, purpose_class) is not None:
        return CredentialBindingSource.dedicated_operation
    return CredentialBindingSource.legacy_generic


def require_real_plan_credential_reference(
    target: ExecutionTarget, purpose_class: CredentialPurposeClass
) -> str:
    """Return the DEDICATED reference for a real-plan purpose, or raise — NEVER a generic fallback.

    This is the ONLY resolver a real-plan gate may use. It refuses when the dedicated operation
    reference is absent, so ``ExecutionTarget.secret_ref`` can never satisfy either real-plan
    purpose. It returns the opaque reference (worker-only, never persisted or hashed here).
    """
    ref = dedicated_reference(target, purpose_class)
    if not ref:
        raise RealPlanCredentialError(f"{purpose_class.value}_reference_missing")
    return ref


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

    A target with no selected reference for this purpose has no credential selection, hence no
    binding
    (and therefore can never satisfy the corresponding readiness gate).
    """
    if not purpose_reference(target, purpose_class):
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
        binding_source=_binding_source(target, purpose_class),
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
    """Retire this purpose's active binding and issue the next version.

    Called automatically whenever the purpose's SOURCE reference changes. It is NOT a caller
    decision: a credential replacement can never be invisible.
    """
    now = _utcnow()
    _announce_rotation(session)
    existing = active_credential_binding(session, target.id, purpose_class)
    if existing is not None:
        existing.status = CredentialBindingStatus.rotated
        existing.rotated_at = now
    if not purpose_reference(target, purpose_class):
        # The credential selection was removed entirely: no active binding remains.
        return None
    row = CredentialBinding(
        id=uuid.uuid4(),
        organization_id=target.organization_id,
        execution_target_id=target.id,
        purpose_class=purpose_class,
        binding_version=_next_version(session, target.id, purpose_class),
        status=CredentialBindingStatus.active,
        binding_source=_binding_source(target, purpose_class),
        created_by=rotated_by,
    )
    session.add(row)
    _audit(session, row, created=False)
    return row


def real_plan_credential_bindings(
    session: Session, target: ExecutionTarget
) -> tuple[CredentialBinding, CredentialBinding]:
    """The single strict gate for real-plan credentials — returns ``(provider, state)`` or raises.

    It enforces EVERY real-plan credential prerequisite (B1B-PR5A amendment §1) in one place, so no
    caller can accidentally admit the generic fallback:

    * both DEDICATED references are explicitly present (``provider_plan_secret_ref`` +
      ``state_backend_secret_ref``) — never ``secret_ref``;
    * the two references are DISTINCT authoritative selections (unless a reviewed shared-provider
      contract permits, which does not exist yet);
    * each maps to its own ACTIVE opaque binding whose ``binding_source`` is ``dedicated_operation``
      — a ``legacy_generic`` binding derived from ``secret_ref`` can never satisfy the gate;
    * the two bindings are distinct rows and neither purpose reuses the other's binding.

    Raises :class:`RealPlanCredentialError` with a bounded reason code; never echoes a reference.
    """
    provider_ref = require_real_plan_credential_reference(
        target, CredentialPurposeClass.provider_plan_read
    )
    state_ref = require_real_plan_credential_reference(
        target, CredentialPurposeClass.state_backend_plan
    )
    if provider_ref == state_ref and REAL_PLAN_SHARED_CREDENTIAL_CONTRACT_VERSION is None:
        # The same selection cannot serve both the provider read and the state backend.
        raise RealPlanCredentialError("provider_state_credential_reference_shared")

    provider = active_credential_binding(
        session, target.id, CredentialPurposeClass.provider_plan_read
    )
    state = active_credential_binding(session, target.id, CredentialPurposeClass.state_backend_plan)
    if provider is None or provider.binding_source != CredentialBindingSource.dedicated_operation:
        raise RealPlanCredentialError("provider_plan_credential_not_dedicated")
    if state is None or state.binding_source != CredentialBindingSource.dedicated_operation:
        raise RealPlanCredentialError("state_backend_credential_not_dedicated")
    if provider.id == state.id:  # pragma: no cover - impossible (distinct purpose classes)
        raise RealPlanCredentialError("credential_binding_reused_across_purposes")
    return provider, state


def ensure_all_credential_bindings(
    session: Session, target: ExecutionTarget, *, created_by: uuid.UUID | None = None
) -> None:
    """Ensure the active binding for EVERY representable purpose whose reference is selected.

    A target with only a generic ``secret_ref`` gets the ``provider_plan_read`` binding (dev). A
    target that also sets the dedicated references gets the matching operation-specific bindings.
    """
    for purpose in CREDENTIAL_PURPOSES:
        ensure_credential_binding(session, target, purpose, created_by=created_by)


def _announce_rotation(session: Session) -> None:
    """Tell PostgreSQL that the SUPPORTED rotation path is handling this reference change.

    The migration installs a ``BEFORE UPDATE`` trigger on ``execution_target`` that AUTO-ROTATES the
    matching opaque binding whenever a purpose's source reference changes — so a raw/Core ``UPDATE``
    that bypasses the ORM entirely still cannot replace a credential UNNOTICED. This
    transaction-scoped flag tells the trigger the ORM has already rotated, so it is applied once.

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
