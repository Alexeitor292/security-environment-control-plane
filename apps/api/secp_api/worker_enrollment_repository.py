"""Durable worker-enrollment repository (SECP-PR5H-A, ADR-027).

The PostgreSQL-backed data-access layer over the four enrollment tables. It is the ONLY module that
turns persisted rows back into the pure :class:`EnrollmentState`, and it refuses closed unless a
rehydrated row is *fully* valid — so no read/status/sweep/recovery path can ever hand a corrupted or
same-key row to a caller, even though those paths never invoke a transition function.

Boundaries this layer holds:

* it selects rows ONLY by the opaque enrollment/invitation identity — never by a caller-supplied
  ``organization_id`` or ``deployment_site_label`` (the service compares those against the
  authoritative persisted binding *after* selection);
* it never silently repairs, normalizes or overwrites a corrupted row — it raises a bounded
  :class:`RepositoryRefusal` and leaves the row for explicit recovery handling;
* every state-changing write is a conditional compare-and-swap over ``(revision, state_digest)``
  plus an append-only history row, and the single-use nonce is consumed by a conditional UPDATE —
  a stale or concurrent writer affects zero rows and refuses.

The pure transition contract (:mod:`secp_api.worker_enrollment_contract`) stays authoritative for
semantics; this module only persists and re-validates.
"""

from __future__ import annotations

import datetime as _dt
import re
import uuid
from dataclasses import dataclass
from typing import Any, Final

from secp_commissioning.canonical import is_sha256_digest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secp_api.worker_enrollment_contract import (
    ENROLLMENT_CONTRACT_VERSION,
    HEALTHY,
    INVITED,
    OFFER_TRANSPORTED,
    RECOVERY_REQUIRED,
    REFUSED,
    RESULT_TRANSPORTED,
    VERIFIED,
    WORKER_BOUND,
    EnrollmentState,
    WorkerEnrollmentInvitation,
    is_deployment_site_label,
    open_enrollment,
)
from secp_api.worker_enrollment_models import (
    WORKER_ENROLLMENT_STATES,
    WORKER_ENROLLMENT_STEPS,
)
from secp_api.worker_enrollment_models import (
    WorkerEnrollmentInvitation as InvitationRow,
)
from secp_api.worker_enrollment_models import (
    WorkerEnrollmentRevision as RevisionRow,
)
from secp_api.worker_enrollment_models import (
    WorkerEnrollmentState as StateRow,
)
from secp_api.worker_enrollment_models import (
    WorkerEnrollmentStepReceipt as ReceiptRow,
)

#: Mirrors the pure contract's reason grammar (bounded lowercase snake_case; no path/endpoint/secret
#: can ride through). Kept local so the repository has no dependency on a private contract name.
_REASON_CODE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")

#: Mirrors the contract's installation-id grammar. Re-validated on rehydration so a corrupted or
#: secret-shaped installation id (which is NOT covered by the digest alone once the digest is
#: re-forged, and which flows into ``public_view``) cannot load as valid.
_INSTALLATION_ID: Final = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")

#: Per-state field-presence expectations, used to reject a malformed/incomplete ACTIVE row.
#: value = (fields that must be non-empty, fields that must be empty).
_WORKER_FIELDS = ("worker_installation_id", "worker_key_id")
_PIPELINE_SHAPE: Final[dict[str, tuple[tuple[str, ...], tuple[str, ...]]]] = {
    INVITED: ((), (*_WORKER_FIELDS, "offer_digest", "result_digest")),
    WORKER_BOUND: (_WORKER_FIELDS, ("offer_digest", "result_digest")),
    OFFER_TRANSPORTED: ((*_WORKER_FIELDS, "offer_digest"), ("result_digest",)),
    RESULT_TRANSPORTED: ((*_WORKER_FIELDS, "offer_digest", "result_digest"), ()),
    VERIFIED: ((*_WORKER_FIELDS, "offer_digest", "result_digest"), ()),
    HEALTHY: ((*_WORKER_FIELDS, "offer_digest", "result_digest"), ()),
}


class RepositoryRefusal(Exception):
    """A bounded, closed persistence refusal. Carries ONLY a reason code (an ``enrollment_*`` value
    from the closed catalog) — never prose, a path, an endpoint, an identity or a raw exception."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _refuse(reason: str) -> RepositoryRefusal:
    return RepositoryRefusal(reason)


@dataclass(frozen=True)
class LoadedEnrollment:
    """A rehydrated, fully-validated enrollment plus its authoritative tenancy binding.

    ``expected_revision`` / ``expected_state_digest`` are the persisted head's CAS coordinates: a
    transition writes only if the row is still exactly here.
    """

    state: EnrollmentState
    organization_id: uuid.UUID
    deployment_site_label: str
    expected_revision: int
    expected_state_digest: str


# --------------------------------------------------------------------------- timestamp helpers


def parse_canonical_utc(value: object) -> _dt.datetime | None:
    """Parse a canonical UTC timestamp string exactly as the contract does, or None if malformed /
    non-UTC. The caller decides which bounded code a None means in its context."""
    if not isinstance(value, str) or not (1 <= len(value) <= 64):
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != _dt.timedelta(0):
        return None
    return parsed


def _parse_utc(value: str) -> _dt.datetime:
    """Parse a persisted canonical timestamp; a malformed value is row corruption."""
    parsed = parse_canonical_utc(value)
    if parsed is None:
        raise _refuse("enrollment_state_corrupt")
    return parsed


def _as_utc(value: _dt.datetime) -> _dt.datetime:
    """Normalize a persisted shadow timestamp to aware-UTC (SQLite returns naive; assume UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.UTC)
    return value.astimezone(_dt.UTC)


def _same_instant(canonical_text: str, shadow: _dt.datetime) -> bool:
    """Independently prove the verbatim canonical text and the shadow are the SAME instant."""
    return _parse_utc(canonical_text) == _as_utc(shadow)


def _shadow_of(canonical_text: str) -> _dt.datetime:
    """Derive the shadow timestamp FROM the canonical text, so the two are one instant by
    construction. The canonical text is still what gets stored and digested; the shadow exists only
    for indexable comparison/sweeps."""
    return _parse_utc(canonical_text)


# --------------------------------------------------------------------------- rehydration + validate


def _rehydrate_state(row: StateRow) -> EnrollmentState:
    return EnrollmentState(
        contract_version=row.contract_version,
        enrollment_id=row.enrollment_id,
        state=row.state,
        revision=row.revision,
        sequence=row.sequence,
        predecessor_digest=row.predecessor_digest,
        controller_installation_id=row.controller_installation_id,
        controller_key_id=row.controller_key_id,
        worker_installation_id=row.worker_installation_id,
        worker_key_id=row.worker_key_id,
        release_digest=row.release_digest,
        transaction_id=row.transaction_id,
        offer_digest=row.offer_digest,
        result_digest=row.result_digest,
        expires_at=row.expires_at,
        updated_at=row.updated_at,
        refusal_reason=row.refusal_reason,
    )


def _digest_or_empty_ok(value: str) -> bool:
    return value == "" or is_sha256_digest(value)


def _validate_rehydrated(state: EnrollmentState, row: StateRow) -> None:
    """Fully validate a rehydrated head row. ANY failure is a bounded corruption refusal — never a
    silent repair. This is the single choke point every read/status/sweep/recovery path passes
    through, so a corrupted or same-key row can never be returned as usable."""
    if state.contract_version != ENROLLMENT_CONTRACT_VERSION:
        raise _refuse("enrollment_state_corrupt")
    if state.state not in WORKER_ENROLLMENT_STATES:
        raise _refuse("enrollment_state_corrupt")
    if not isinstance(state.revision, int) or state.revision < 0:
        raise _refuse("enrollment_state_corrupt")
    if not isinstance(state.sequence, int) or state.sequence < 0:
        raise _refuse("enrollment_state_corrupt")

    # structural state<->revision invariant: INVITED is the ONLY revision-0 state and the only one
    # with no predecessor; any other state at revision 0 (or INVITED past 0) is structurally
    # impossible and must not load even if its digest and single-row history were fully re-forged.
    is_genesis = state.revision == 0
    if is_genesis != (state.state == INVITED) or is_genesis != (state.predecessor_digest == ""):
        raise _refuse("enrollment_state_corrupt")

    # digest grammars
    if not is_sha256_digest(state.enrollment_id):
        raise _refuse("enrollment_state_corrupt")
    if not is_sha256_digest(state.controller_key_id):
        raise _refuse("enrollment_state_corrupt")
    if not is_sha256_digest(state.release_digest):
        raise _refuse("enrollment_state_corrupt")
    for value in (
        state.predecessor_digest,
        state.worker_key_id,
        state.offer_digest,
        state.result_digest,
    ):
        if not _digest_or_empty_ok(value):
            raise _refuse("enrollment_state_corrupt")

    # identity + label grammars (NOT covered by the digest once it is re-forged, and these flow into
    # public_view / scope comparison): a corrupted or secret/path-shaped value cannot load as valid.
    if not _INSTALLATION_ID.fullmatch(state.controller_installation_id):
        raise _refuse("enrollment_state_corrupt")
    if state.worker_installation_id and not _INSTALLATION_ID.fullmatch(
        state.worker_installation_id
    ):
        raise _refuse("enrollment_state_corrupt")
    if not is_deployment_site_label(row.deployment_site_label):
        raise _refuse("enrollment_state_corrupt")

    # participant separation: the confirmed-defect invariant, re-asserted on the PERSISTED pair so
    # corrupted/rehydrated same-key row is caught even by code that never calls a transition.
    if state.worker_key_id and state.worker_key_id == state.controller_key_id:
        raise _refuse("enrollment_state_corrupt")
    if (
        state.worker_installation_id
        and state.worker_installation_id == state.controller_installation_id
    ):
        raise _refuse("enrollment_state_corrupt")

    # reason-code grammar + placement
    if state.refusal_reason:
        if not _REASON_CODE.fullmatch(state.refusal_reason):
            raise _refuse("enrollment_state_corrupt")
        if state.state not in (REFUSED, RECOVERY_REQUIRED):
            raise _refuse("enrollment_state_corrupt")

    # pipeline shape: no malformed/incomplete ACTIVE (or healthy) row
    shape = _PIPELINE_SHAPE.get(state.state)
    if shape is not None:
        required_present, required_empty = shape
        for field in required_present:
            if not getattr(state, field):
                raise _refuse("enrollment_state_corrupt")
        for field in required_empty:
            if getattr(state, field):
                raise _refuse("enrollment_state_corrupt")

    # timestamps: canonical text well-formed AND the same instant as the shadow column
    _parse_utc(state.updated_at)
    if not _same_instant(state.expires_at, row.expires_at_ts):
        raise _refuse("enrollment_state_corrupt")

    # THE compare: the recomputed canonical digest must equal the persisted CAS digest
    if state.digest() != row.state_digest:
        raise _refuse("enrollment_state_corrupt")


def _build_loaded(session: Session, row: StateRow) -> LoadedEnrollment:
    state = _rehydrate_state(row)
    _validate_rehydrated(state, row)
    _cross_check_invitation(session, row, state)
    return LoadedEnrollment(
        state=state,
        organization_id=row.organization_id,
        deployment_site_label=row.deployment_site_label,
        expected_revision=row.revision,
        expected_state_digest=row.state_digest,
    )


def _cross_check_invitation(session: Session, row: StateRow, state: EnrollmentState) -> None:
    """The state row's tenancy binding and enrollment identity are re-derived from the AUTHORITATIVE
    invitation, so a tampered ``organization_id`` / ``deployment_site_label`` on the state row does
    not silently become the tenancy boundary, and the ``enrollment_id == invitation.digest()``
    relation is proven exact. Any disagreement is corruption — never trusted, never repaired."""
    invitation_row = session.execute(
        select(InvitationRow).where(InvitationRow.enrollment_id == row.enrollment_id)
    ).scalar_one_or_none()
    if invitation_row is None:  # a head row with no authoritative invitation is corrupt
        raise _refuse("enrollment_state_corrupt")
    if invitation_row.organization_id != row.organization_id:
        raise _refuse("enrollment_state_corrupt")
    if invitation_row.deployment_site_label != row.deployment_site_label:
        raise _refuse("enrollment_state_corrupt")
    # re-derive the enrollment id from the invitation and prove the relationship is exact
    invitation = WorkerEnrollmentInvitation(
        contract_version=ENROLLMENT_CONTRACT_VERSION,
        invitation_id=invitation_row.invitation_id,
        controller_installation_id=invitation_row.controller_installation_id,
        controller_key_id=invitation_row.controller_key_id,
        controller_trust_anchor_hex=invitation_row.controller_trust_anchor_hex,
        controller_origin=invitation_row.controller_origin,
        release_digest=invitation_row.release_digest,
        transaction_id=invitation_row.transaction_id,
        sequence=0,
        created_at=invitation_row.invitation_created_at,
        expires_at=invitation_row.expires_at,
    )
    try:
        invitation.validate()
    except Exception:  # noqa: BLE001 - any invitation-validity failure is corruption of a stored row
        raise _refuse("enrollment_state_corrupt") from None
    if invitation.digest() != state.enrollment_id:
        raise _refuse("enrollment_state_corrupt")
    # the state must carry the invitation's controller binding, transaction and release verbatim
    if (
        state.controller_installation_id != invitation.controller_installation_id
        or state.controller_key_id != invitation.controller_key_id
        or state.transaction_id != invitation.transaction_id
        or state.release_digest != invitation.release_digest
    ):
        raise _refuse("enrollment_state_corrupt")


# --------------------------------------------------------------------------- history consistency


def verify_history_consistent(session: Session, enrollment_id: str, state: EnrollmentState) -> None:
    """Prove the append-only history and the head agree: contiguous revisions 0..N, the head equals
    the latest history row, and each row's predecessor_digest chains the prior canonical digest. An
    inconsistent chain refuses rehydration/recovery rather than being trusted."""
    rows = (
        session.execute(
            select(RevisionRow)
            .where(RevisionRow.enrollment_id == enrollment_id)
            .order_by(RevisionRow.revision)
        )
        .scalars()
        .all()
    )
    if not rows:
        raise _refuse("enrollment_history_inconsistent")
    # contiguous 0..N
    if [r.revision for r in rows] != list(range(len(rows))):
        raise _refuse("enrollment_history_inconsistent")
    head = rows[-1]
    if head.revision != state.revision or head.state_digest != state.digest():
        raise _refuse("enrollment_history_inconsistent")
    if head.state != state.state or head.predecessor_digest != state.predecessor_digest:
        raise _refuse("enrollment_history_inconsistent")
    # chain: each row's predecessor_digest == prior row's state_digest (revision 0 has none)
    if rows[0].revision != 0 or rows[0].predecessor_digest != "":
        raise _refuse("enrollment_history_inconsistent")
    for prev, cur in zip(rows, rows[1:], strict=False):
        if cur.predecessor_digest != prev.state_digest:
            raise _refuse("enrollment_history_inconsistent")


# --------------------------------------------------------------------------- loads


def _for_update(session: Session) -> Any:
    """SELECT ... FOR UPDATE on PostgreSQL (the authoritative row lock); no-op on SQLite (writers
    serialize at the database). The conditional CAS is the durable guarantee regardless."""
    return True if session.get_bind().dialect.name == "postgresql" else None


def load_for_update(session: Session, enrollment_id: str) -> LoadedEnrollment | None:
    """Lock + freshly read the head row, then fully rehydrate and validate. Returns None only when
    the row is absent; a present-but-corrupt row RAISES (never returns)."""
    row = session.get(
        StateRow, enrollment_id, populate_existing=True, with_for_update=_for_update(session)
    )
    if row is None:
        return None
    return _build_loaded(session, row)


def load_read_only(session: Session, enrollment_id: str) -> LoadedEnrollment | None:
    """Fresh unlocked read that still fully rehydrates + validates (status/read paths). A corrupt
    row raises rather than being surfaced."""
    row = session.get(StateRow, enrollment_id, populate_existing=True)
    if row is None:
        return None
    return _build_loaded(session, row)


def load_invitation_for_update(session: Session, enrollment_id: str) -> InvitationRow | None:
    stmt = select(InvitationRow).where(InvitationRow.enrollment_id == enrollment_id)
    if _for_update(session):
        stmt = stmt.with_for_update()
    return session.execute(stmt).scalar_one_or_none()


# --------------------------------------------------------------------------- creation


def create_invitation_and_open(
    session: Session,
    *,
    organization_id: uuid.UUID,
    invitation: WorkerEnrollmentInvitation,
    invitation_created_at: str,
    deployment_site_label: str,
    now: str,
) -> LoadedEnrollment:
    """The repository creation contract: persist the invitation (unconsumed) AND open the enrollment
    at revision 0 (INVITED) with its revision-0 history row, atomically. ``enrollment_id`` is the
    invitation digest, so a duplicate nonce OR a duplicate invitation collides on a UNIQUE/PK
    constraint and the second creation refuses.

    Does NOT commit — the caller owns the transaction boundary.
    """
    invitation.validate()
    state = open_enrollment(invitation, now=now)  # INVITED, revision 0; asserts freshness
    if invitation.digest() != state.enrollment_id:
        raise _refuse("enrollment_internal_failure")

    expires_shadow = _shadow_of(state.expires_at)
    session.add(
        InvitationRow(
            organization_id=organization_id,
            deployment_site_label=deployment_site_label,
            invitation_id=invitation.invitation_id,
            enrollment_id=state.enrollment_id,
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_trust_anchor_hex=invitation.controller_trust_anchor_hex,
            controller_origin=invitation.controller_origin,
            release_digest=invitation.release_digest,
            transaction_id=invitation.transaction_id,
            invitation_created_at=invitation_created_at,
            expires_at=invitation.expires_at,
            expires_at_ts=_shadow_of(invitation.expires_at),
            consumed=False,
            revoked=False,
        )
    )
    _insert_state_row(session, organization_id, deployment_site_label, state, expires_shadow)
    # The revision-0 history row FK-references the head row; flush the head first so the FK is
    # satisfied (PostgreSQL enforces it; the models declare no ``relationship()`` to order the UOW).
    session.flush()
    _insert_revision_row(session, state)
    return LoadedEnrollment(
        state=state,
        organization_id=organization_id,
        deployment_site_label=deployment_site_label,
        expected_revision=state.revision,
        expected_state_digest=state.digest(),
    )


def _insert_state_row(
    session: Session,
    organization_id: uuid.UUID,
    deployment_site_label: str,
    state: EnrollmentState,
    expires_shadow: _dt.datetime,
) -> None:
    session.add(
        StateRow(
            enrollment_id=state.enrollment_id,
            organization_id=organization_id,
            deployment_site_label=deployment_site_label,
            contract_version=state.contract_version,
            state=state.state,
            revision=state.revision,
            sequence=state.sequence,
            predecessor_digest=state.predecessor_digest,
            controller_installation_id=state.controller_installation_id,
            controller_key_id=state.controller_key_id,
            worker_installation_id=state.worker_installation_id,
            worker_key_id=state.worker_key_id,
            release_digest=state.release_digest,
            transaction_id=state.transaction_id,
            offer_digest=state.offer_digest,
            result_digest=state.result_digest,
            expires_at=state.expires_at,
            updated_at=state.updated_at,
            refusal_reason=state.refusal_reason,
            state_digest=state.digest(),
            expires_at_ts=expires_shadow,
        )
    )


def _insert_revision_row(session: Session, state: EnrollmentState) -> None:
    session.add(
        RevisionRow(
            enrollment_id=state.enrollment_id,
            revision=state.revision,
            state=state.state,
            state_digest=state.digest(),
            predecessor_digest=state.predecessor_digest,
        )
    )


# --------------------------------------------------------------------------- transition write (CAS)


def commit_transition(
    session: Session,
    *,
    prior: LoadedEnrollment,
    new_state: EnrollmentState,
    step: str | None,
    input_digest: str | None,
) -> None:
    """Persist one committed transition: append the revision-history row, compare-and-swap the head
    over the PRIOR ``(revision, state_digest)``, and (for a named step) write the step receipt.
    A stale or concurrent writer fails the CAS (rowcount != 1) and refuses closed. Flushes so the
    unique/CAS effects fire now; the caller commits."""
    enrollment_id = prior.state.enrollment_id
    _insert_revision_row(session, new_state)

    result = session.execute(
        update(StateRow)
        .where(
            StateRow.enrollment_id == enrollment_id,
            StateRow.revision == prior.expected_revision,
            StateRow.state_digest == prior.expected_state_digest,
        )
        .values(
            state=new_state.state,
            revision=new_state.revision,
            sequence=new_state.sequence,
            predecessor_digest=new_state.predecessor_digest,
            worker_installation_id=new_state.worker_installation_id,
            worker_key_id=new_state.worker_key_id,
            offer_digest=new_state.offer_digest,
            result_digest=new_state.result_digest,
            updated_at=new_state.updated_at,
            refusal_reason=new_state.refusal_reason,
            state_digest=new_state.digest(),
            expires_at_ts=_shadow_of(new_state.expires_at),
        )
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise _refuse("enrollment_revision_conflict")

    if step is not None:
        if step not in WORKER_ENROLLMENT_STEPS or input_digest is None:
            raise _refuse("enrollment_internal_failure")
        session.add(
            ReceiptRow(
                enrollment_id=enrollment_id,
                step=step,
                input_digest=input_digest,
                resulting_revision=new_state.revision,
                resulting_state_digest=new_state.digest(),
            )
        )
    session.flush()


# --------------------------------------------------------------------------- nonce consumption


def consume_invitation(session: Session, *, enrollment_id: str, consumed_at: _dt.datetime) -> None:
    """Consume the single-use nonce with a conditional UPDATE: only an unconsumed, unrevoked
    invitation flips. rowcount != 1 means it was already consumed/revoked or a concurrent consumer
    won — refuse closed. This is the second, durable guard behind the head-row lock."""
    result = session.execute(
        update(InvitationRow)
        .where(
            InvitationRow.enrollment_id == enrollment_id,
            InvitationRow.consumed.is_(False),
            InvitationRow.revoked.is_(False),
        )
        .values(consumed=True, consumed_at=consumed_at)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise _refuse("enrollment_invitation_conflict")
    session.flush()


# --------------------------------------------------------------------------- receipts


def find_receipt(
    session: Session, *, enrollment_id: str, step: str, input_digest: str
) -> ReceiptRow | None:
    return session.execute(
        select(ReceiptRow).where(
            ReceiptRow.enrollment_id == enrollment_id,
            ReceiptRow.step == step,
            ReceiptRow.input_digest == input_digest,
        )
    ).scalar_one_or_none()


def revision_state_digest(session: Session, *, enrollment_id: str, revision: int) -> str | None:
    """The persisted canonical digest recorded in history at ``revision``, or None if absent."""
    return session.execute(
        select(RevisionRow.state_digest).where(
            RevisionRow.enrollment_id == enrollment_id,
            RevisionRow.revision == revision,
        )
    ).scalar_one_or_none()


__all__ = [
    "LoadedEnrollment",
    "RepositoryRefusal",
    "commit_transition",
    "consume_invitation",
    "create_invitation_and_open",
    "find_receipt",
    "load_for_update",
    "load_invitation_for_update",
    "load_read_only",
    "parse_canonical_utc",
    "revision_state_digest",
    "verify_history_consistent",
]
