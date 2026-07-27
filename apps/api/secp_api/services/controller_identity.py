"""Controller enrollment-identity sourcing + rotation (SECP-PR5H-B1, F3/R1).

The enrollment API binds the controller identity from the authoritative, persisted, independently
verified ACTIVE row — never a caller-supplied value and never an environment variable. Identity is
deployment-scoped (one per control-plane deployment); the actor's organization stays the tenancy and
authorization boundary. Rotation appends history and preserves superseded/revoked rows so an
invitation issued under a prior identity remains verifiable.

Activation accepts ONLY a :class:`VerifiedControllerIdentity` — a typed value that already
represents a completed verification of the root-controlled management identity, the attested
bootstrap evidence, the exact installation/release/origin agreement, and a DEDICATED enrollment key
(separated from the management-evidence and release-signing keys). There is no raw-field / boolean
seam. The production writer that constructs this proof from the root-gated bootstrap path is
**PR5H-B2** and is deliberately not present yet, so production population stays unavailable (the
enrollment API then refuses ``enrollment_controller_identity_unavailable``, fail-closed). The dev
seed and tests construct proofs through ``controller_identity_dev.build_test_verified_controller_
identity`` — a TEST/DEV-only factory kept OUTSIDE this production service module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from secp_commissioning.controller_enrollment_signer import ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY
from sqlalchemy import select, text
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

_INSTALL = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")
_HTTPS_ORIGIN = re.compile(r"https://[a-z0-9.-]{1,253}(?::[1-9][0-9]{0,4})?")


@dataclass(frozen=True)
class VerifiedControllerIdentity:
    """A COMPLETED verification of the deployment controller enrollment identity.

    Constructing this value ASSERTS that the root-gated bootstrap path independently verified: (1) a
    root-controlled management-plane identity; (2) authenticated bootstrap evidence + proof;
    (3) exact installation-id agreement; (4) exact running-release agreement; (5) the canonical
    HTTPS public origin; (6) the dedicated controller-enrollment public key + key id; and (7)
    that the enrollment key is separated from the management-evidence and release keys. It is
    the ONLY input :func:`activate_controller_identity` accepts."""

    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    management_identity_digest: str
    bootstrap_evidence_digest: str
    enrollment_key_proof_id: str


@dataclass(frozen=True)
class ActiveControllerIdentity:
    """The exact authoritative controller identity bound into a new invitation."""

    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str


def _validate_proof(proof: VerifiedControllerIdentity) -> None:
    """Validate every shape and binding of a verified-identity proof. Raised BEFORE any write, so a
    malformed proof never supersedes the current active identity."""
    if not _INSTALL.fullmatch(proof.controller_installation_id):
        raise WorkerEnrollmentError(EC.identity_invalid)
    if len(proof.controller_origin) > 269 or not _HTTPS_ORIGIN.fullmatch(proof.controller_origin):
        raise WorkerEnrollmentError(EC.origin_not_https)
    if len(proof.controller_trust_anchor_hex) != 64 or not re.fullmatch(
        r"[0-9a-f]{64}", proof.controller_trust_anchor_hex
    ):
        raise WorkerEnrollmentError(EC.trust_anchor_invalid)
    if not is_sha256_digest(proof.controller_key_id) or (
        sha256_digest_of_hex(proof.controller_trust_anchor_hex) != proof.controller_key_id
    ):
        raise WorkerEnrollmentError(EC.trust_anchor_invalid)
    for digest in (
        proof.release_digest,
        proof.management_identity_digest,
        proof.bootstrap_evidence_digest,
    ):
        if not is_sha256_digest(digest):
            raise WorkerEnrollmentError(EC.identity_invalid)
    if not (8 <= len(proof.enrollment_key_proof_id) <= 120):
        raise WorkerEnrollmentError(EC.identity_invalid)
    # key separation: the dedicated enrollment key id must not collide with the management-evidence
    # or release-signing digests
    if proof.controller_key_id in (
        proof.management_identity_digest,
        proof.bootstrap_evidence_digest,
        proof.release_digest,
    ):
        raise WorkerEnrollmentError(EC.identity_invalid)


def _consistent(row: ControllerEnrollmentIdentity) -> bool:
    """Re-validate every persisted shape/binding that can be checked without host I/O: the row must
    be verified, the key id must derive from the anchor, all source digests well-formed, the
    enrollment-key proof present, and the enrollment key separated from the source digests."""
    try:
        _validate_proof(
            VerifiedControllerIdentity(
                controller_installation_id=row.controller_installation_id,
                controller_key_id=row.controller_key_id,
                controller_trust_anchor_hex=row.controller_trust_anchor_hex,
                controller_origin=row.controller_origin,
                release_digest=row.release_digest,
                management_identity_digest=row.management_identity_digest,
                bootstrap_evidence_digest=row.bootstrap_evidence_digest,
                enrollment_key_proof_id=row.enrollment_key_proof_id,
            )
        )
    except WorkerEnrollmentError:
        return False
    return bool(row.verified)


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
    session: Session, proof: VerifiedControllerIdentity
) -> ControllerEnrollmentIdentity:
    """Rotate the deployment controller identity from a VERIFIED proof: validate every field, then
    insert the new ACTIVE row and supersede the prior active one, atomically, leaving exactly one
    active row. A malformed proof refuses BEFORE the prior active identity is superseded (a failed
    rotation leaves the previous identity active). Concurrent rotations collide on the
    ``active_marker`` UNIQUE — one wins, the other refuses ``enrollment_identity_conflict``. No
    commit — the caller owns the transaction boundary."""
    _validate_proof(proof)  # refuse malformed input before touching the active set
    now = _utcnow()
    is_pg = session.get_bind().dialect.name == "postgresql"
    # C4: take the SAME fixed transaction-level advisory lock the signer lease holds, so a rotation
    # blocks until an in-flight signing lease's transaction exits (and vice versa) even though the
    # SELECT-only signer role can take no row lock. Then lock the active set (belt-and-suspenders
    # for concurrent rotations; the UNIQUE(active_marker) is the durable single-active guarantee).
    stmt = select(ControllerEnrollmentIdentity).where(
        ControllerEnrollmentIdentity.status == CONTROLLER_IDENTITY_ACTIVE
    )
    if is_pg:
        session.execute(
            text("SELECT pg_advisory_xact_lock(:k)"),
            {"k": ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY},
        )
        stmt = stmt.with_for_update()
    for row in session.execute(stmt).scalars().all():
        row.status = CONTROLLER_IDENTITY_SUPERSEDED
        row.active_marker = None
        row.superseded_at = now
    new_row = ControllerEnrollmentIdentity(
        status=CONTROLLER_IDENTITY_ACTIVE,
        active_marker=True,
        controller_installation_id=proof.controller_installation_id,
        controller_key_id=proof.controller_key_id,
        controller_trust_anchor_hex=proof.controller_trust_anchor_hex,
        controller_origin=proof.controller_origin,
        release_digest=proof.release_digest,
        management_identity_digest=proof.management_identity_digest,
        bootstrap_evidence_digest=proof.bootstrap_evidence_digest,
        enrollment_key_proof_id=proof.enrollment_key_proof_id,
        verified=True,
        verified_at=now,
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
    "VerifiedControllerIdentity",
    "activate_controller_identity",
    "load_active_controller_identity",
]
