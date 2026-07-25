"""Controller enrollment-identity sourcing + rotation (SECP-PR5H-B1, F3).

The enrollment API binds the controller identity from the authoritative, persisted, independently
verified ACTIVE row — never a caller-supplied value and never an environment variable. Identity is
deployment-scoped (one per control-plane deployment); the actor's organization stays the tenancy and
authorization boundary. Rotation appends history and preserves superseded/revoked rows so an
invitation issued under a prior identity remains verifiable.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api.controller_identity_models import (
    CONTROLLER_IDENTITY_ACTIVE,
    CONTROLLER_IDENTITY_SUPERSEDED,
    ControllerEnrollmentIdentity,
)
from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import _utcnow
from secp_api.worker_enrollment_contract import is_sha256_digest, sha256_digest_of_hex


@dataclass(frozen=True)
class ActiveControllerIdentity:
    """The exact authoritative controller identity bound into a new invitation."""

    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str


def _consistent(row: ControllerEnrollmentIdentity) -> bool:
    """The persisted key id must be the digest of the persisted trust anchor, and the identity must
    be independently verified — otherwise it is refused as unavailable (never silently used)."""
    return (
        bool(row.verified)
        and is_sha256_digest(row.controller_key_id)
        and sha256_digest_of_hex(row.controller_trust_anchor_hex) == row.controller_key_id
    )


def load_active_controller_identity(session: Session) -> ActiveControllerIdentity:
    """The single ACTIVE controller identity, or a bounded refusal.

    Refuses ``enrollment_controller_identity_unavailable`` when there is no active identity, or the
    active identity is not independently verified / internally inconsistent — before any enrollment
    or audit write. ``UNIQUE(active_marker)`` guarantees at most one active row."""
    rows = (
        session.execute(
            select(ControllerEnrollmentIdentity).where(
                ControllerEnrollmentIdentity.status == CONTROLLER_IDENTITY_ACTIVE
            )
        )
        .scalars()
        .all()
    )
    if len(rows) != 1 or not _consistent(rows[0]):
        raise WorkerEnrollmentError(EC.controller_identity_unavailable)
    row = rows[0]
    return ActiveControllerIdentity(
        controller_installation_id=row.controller_installation_id,
        controller_key_id=row.controller_key_id,
        controller_trust_anchor_hex=row.controller_trust_anchor_hex,
        controller_origin=row.controller_origin,
        release_digest=row.release_digest,
    )


def activate_controller_identity(
    session: Session,
    *,
    controller_installation_id: str,
    controller_key_id: str,
    controller_trust_anchor_hex: str,
    controller_origin: str,
    release_digest: str,
    verified: bool = True,
) -> ControllerEnrollmentIdentity:
    """Rotate the deployment controller identity: verify, insert the new ACTIVE row and supersede
    the prior active one, atomically, leaving exactly one active row. Concurrent rotations collide
    on the ``active_marker`` UNIQUE — one wins, the other refuses ``enrollment_identity_conflict``.
    Does NOT commit — the caller owns the transaction boundary. (Population is wired by bootstrap
    in PR5H-B2; this is the durable primitive + dev/test writer.)"""
    if not is_sha256_digest(controller_key_id) or (
        sha256_digest_of_hex(controller_trust_anchor_hex) != controller_key_id
    ):
        raise WorkerEnrollmentError(EC.trust_anchor_invalid)
    now = _utcnow()
    # lock the current active set so a concurrent rotation serializes behind us (no-op on SQLite;
    # the UNIQUE(active_marker) is the durable single-active guarantee regardless)
    stmt = select(ControllerEnrollmentIdentity).where(
        ControllerEnrollmentIdentity.status == CONTROLLER_IDENTITY_ACTIVE
    )
    if session.get_bind().dialect.name == "postgresql":
        stmt = stmt.with_for_update()
    current = session.execute(stmt).scalars().all()
    for row in current:
        row.status = CONTROLLER_IDENTITY_SUPERSEDED
        row.active_marker = None
        row.superseded_at = now
    new_row = ControllerEnrollmentIdentity(
        status=CONTROLLER_IDENTITY_ACTIVE,
        active_marker=True,
        controller_installation_id=controller_installation_id,
        controller_key_id=controller_key_id,
        controller_trust_anchor_hex=controller_trust_anchor_hex,
        controller_origin=controller_origin,
        release_digest=release_digest,
        verified=verified,
        verified_at=now if verified else None,
        activated_at=now,
    )
    session.add(new_row)
    try:
        session.flush()
    except IntegrityError:
        raise WorkerEnrollmentError(EC.identity_conflict) from None
    return new_row


__all__ = [
    "ActiveControllerIdentity",
    "activate_controller_identity",
    "load_active_controller_identity",
]
