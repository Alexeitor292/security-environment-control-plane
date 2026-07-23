"""Transactional worker-enrollment service (SECP-PR5H-A, ADR-027).

Wraps the API-side *pure* transition contract (:mod:`secp_api.worker_enrollment_contract`) in a
durable, compare-and-swap application service. It is the authoritative scope-binding and
concurrency-control layer:

* ``organization_id`` is derived from the authenticated control-plane :class:`Principal` — it is the
  ONLY authorization boundary — and ``deployment_site_label`` is loaded from the authoritative
  persisted invitation/state. A worker-supplied ``organization_id`` or ``deployment_site_label`` is
  NEVER used to select a row; it is only compared against the authoritative binding *after* the row
  has been selected by its opaque enrollment identity.
* every state-changing operation loads and locks the head row, fully re-validates the rehydrated
  state, verifies the caller's declared ``(revision, state_digest, sequence, predecessor_digest)``,
  runs the pure transition, appends the revision-history row, compare-and-swaps the head, and writes
  the exact step receipt — committing only when all effects succeed. A stale or concurrent
  transaction affects zero rows and refuses with a bounded conflict code.
* the durable single-use nonce is consumed at the FIRST successful worker-identity binding, in the
  same transaction as the first advanced revision — neither can commit without the other.

ADR-027 "delegate, never pre-screen": the service loads and calls the pure transition, then surfaces
the transition's OWN bounded reason code rather than re-deriving one, so check order stays part of
the observable contract.

This module does NOT commit — the caller (router/test) owns the transaction boundary — except that a
fail-closed refusal which also materialized a durable recovery transition is flagged so the caller
commits it before re-raising. No network transport, API route, CLI, host mutation, provider contact,
workflow, OpenTofu or operator activation lives here; PR5H-A stays an inert durable foundation.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

from secp_commissioning.canonical import sha256_digest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import worker_enrollment_repository as repo
from secp_api.auth import Principal
from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import _utcnow
from secp_api.worker_enrollment_contract import (
    EnrollmentState,
    HandoffFacts,
    WorkerEnrollmentContractError,
    WorkerEnrollmentInvitation,
    bind_worker_identity,
    is_deployment_site_label,
    mark_healthy,
    mark_verified,
    record_controller_offer,
    record_worker_result,
    refuse,
    require_recovery,
)
from secp_api.worker_enrollment_models import WorkerEnrollmentStepReceipt as ReceiptRow
from secp_api.worker_enrollment_repository import LoadedEnrollment, RepositoryRefusal
from secp_api.worker_enrollment_schema import EnrollmentSchemaError, assert_enrollment_schema_ready

# --------------------------------------------------------------------------- request/response types


@dataclass(frozen=True)
class ExpectedRevision:
    """The caller's declared concurrency token — what they last observed. A state-changing request
    must supply it; a mismatch (lost update / concurrent advance) refuses ``revision_conflict``."""

    revision: int
    state_digest: str
    sequence: int
    predecessor_digest: str


@dataclass(frozen=True)
class ClaimedScope:
    """Worker-supplied tenancy claims. NEVER used to select a row — only compared against the
    authoritative persisted binding after selection by opaque enrollment identity."""

    organization_id: uuid.UUID | None = None
    deployment_site_label: str | None = None
    transaction_id: str | None = None


@dataclass(frozen=True)
class TransitionOutcome:
    state: EnrollmentState
    committed_revision: int
    deduplicated: bool


# --------------------------------------------------------------------------- error mapping


def _surface(exc: RepositoryRefusal | WorkerEnrollmentContractError) -> WorkerEnrollmentError:
    """Map a bounded repository/contract reason code onto the closed service error. Unknown codes
    fail closed as an internal failure rather than leaking an unbounded string."""
    code = exc.reason_code
    try:
        EC(code)
    except ValueError:
        return WorkerEnrollmentError(EC.internal_failure)
    return WorkerEnrollmentError(code)


# --------------------------------------------------------------------------- scope + expectation


def _assert_schema_ready(session: Session) -> None:
    try:
        assert_enrollment_schema_ready(session)
    except EnrollmentSchemaError:
        raise WorkerEnrollmentError(EC.schema_unavailable) from None


def _authorize(actor: Principal, loaded: LoadedEnrollment) -> None:
    # organization is the ONLY authorization boundary, and it comes from the authenticated identity
    if actor.organization_id != loaded.organization_id:
        raise WorkerEnrollmentError(EC.forbidden)


def _check_scope(loaded: LoadedEnrollment, claimed: ClaimedScope | None) -> None:
    if claimed is None:
        return
    if claimed.organization_id is not None and claimed.organization_id != loaded.organization_id:
        raise WorkerEnrollmentError(EC.scope_mismatch)
    if (
        claimed.deployment_site_label is not None
        and claimed.deployment_site_label != loaded.deployment_site_label
    ):
        raise WorkerEnrollmentError(EC.scope_mismatch)
    if claimed.transaction_id is not None and claimed.transaction_id != loaded.state.transaction_id:
        raise WorkerEnrollmentError(EC.scope_mismatch)


def _verify_expected(loaded: LoadedEnrollment, expected: ExpectedRevision) -> None:
    state = loaded.state
    if (
        expected.revision != state.revision
        or expected.state_digest != loaded.expected_state_digest
        or expected.sequence != state.sequence
        or expected.predecessor_digest != state.predecessor_digest
    ):
        raise WorkerEnrollmentError(EC.revision_conflict)


def _load_authorized(
    session: Session, actor: Principal, enrollment_id: str, claimed: ClaimedScope | None
) -> LoadedEnrollment:
    try:
        loaded = repo.load_for_update(session, enrollment_id)
    except RepositoryRefusal as exc:  # a present-but-corrupt row is preserved, never repaired
        raise _surface(exc) from None
    if loaded is None:
        raise WorkerEnrollmentError(EC.not_found)
    _authorize(actor, loaded)
    _check_scope(loaded, claimed)
    try:
        repo.verify_history_consistent(session, enrollment_id, loaded.state)
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    return loaded


# --------------------------------------------------------------------------- step input digests


def _input_digest(step: str, payload: dict[str, object]) -> str:
    return sha256_digest({"step": step, **payload})


# --------------------------------------------------------------------------- receipt dedup


def _serve_receipt(
    session: Session, loaded: LoadedEnrollment, step: str, input_digest: str
) -> TransitionOutcome | None:
    receipt = repo.find_receipt(
        session, enrollment_id=loaded.state.enrollment_id, step=step, input_digest=input_digest
    )
    if receipt is None:
        return None
    # the recorded result must still agree with the append-only history and the current head
    recorded = repo.revision_state_digest(
        session, enrollment_id=loaded.state.enrollment_id, revision=receipt.resulting_revision
    )
    if recorded is None:
        raise WorkerEnrollmentError(EC.history_inconsistent)
    if recorded != receipt.resulting_state_digest:
        raise WorkerEnrollmentError(EC.receipt_conflict)
    if loaded.state.revision < receipt.resulting_revision:
        raise WorkerEnrollmentError(EC.history_inconsistent)
    return TransitionOutcome(
        state=loaded.state, committed_revision=receipt.resulting_revision, deduplicated=True
    )


def _commit(
    session: Session,
    loaded: LoadedEnrollment,
    new_state: EnrollmentState,
    step: str | None,
    input_digest: str | None,
) -> None:
    try:
        repo.commit_transition(
            session, prior=loaded, new_state=new_state, step=step, input_digest=input_digest
        )
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    except IntegrityError:
        # a concurrent writer inserted the same revision / receipt first
        raise WorkerEnrollmentError(EC.revision_conflict) from None


def _run_pure(fn: Callable[[], EnrollmentState]) -> EnrollmentState:
    try:
        return fn()
    except WorkerEnrollmentContractError as exc:
        raise _surface(exc) from None


# --------------------------------------------------------------------------- creation


def create_invitation_and_open(
    session: Session,
    actor: Principal,
    *,
    invitation: WorkerEnrollmentInvitation,
    invitation_created_at: str,
    deployment_site_label: str,
    now: str,
) -> TransitionOutcome:
    """Persist a controller invitation and open its enrollment at revision 0, atomically.

    ``organization_id`` comes from the authenticated actor; ``deployment_site_label`` is fixed here
    and is immutable thereafter. A duplicate nonce or invitation collides on a UNIQUE/PK constraint
    and refuses ``creation_conflict``.
    """
    _assert_schema_ready(session)
    if not is_deployment_site_label(deployment_site_label):
        raise WorkerEnrollmentError(EC.scope_mismatch)
    try:
        loaded = repo.create_invitation_and_open(
            session,
            organization_id=actor.organization_id,
            invitation=invitation,
            invitation_created_at=invitation_created_at,
            deployment_site_label=deployment_site_label,
            now=now,
        )
        session.flush()
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    except WorkerEnrollmentContractError as exc:
        raise _surface(exc) from None
    except IntegrityError:
        raise WorkerEnrollmentError(EC.creation_conflict) from None
    return TransitionOutcome(state=loaded.state, committed_revision=0, deduplicated=False)


# --------------------------------------------------------------------------- state-changing steps


def bind_worker(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    worker_installation_id: str,
    worker_key_id: str,
    transaction_id: str,
    now: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    """The nonce-consumption point: the first successful worker-identity binding. Consumes the
    single-use invitation and persists the first advanced revision in ONE transaction."""
    _assert_schema_ready(session)
    step = "bind_worker_identity"
    input_digest = _input_digest(
        step,
        {
            "worker_installation_id": worker_installation_id,
            "worker_key_id": worker_key_id,
            "transaction_id": transaction_id,
        },
    )
    loaded = _load_authorized(session, actor, enrollment_id, claimed_scope)

    # A recorded exact retry (same step + same input) short-circuits BEFORE the expected-revision
    # check: an at-least-once retry legitimately carries the same (now stale) token the client first
    # sent, so this is a truthful no-op, not a lost update. The expected-revision check below only
    # applies to a FRESH attempt (no receipt).
    served = _serve_receipt(session, loaded, step, input_digest)
    if served is not None:
        return served
    _verify_expected(loaded, expected)

    # authoritative invitation gate (unconsumed / unrevoked / unexpired), selected by enrollment id
    invitation = repo.load_invitation_for_update(session, enrollment_id)
    if invitation is None:
        raise WorkerEnrollmentError(EC.invitation_not_found)
    if invitation.revoked:
        raise WorkerEnrollmentError(EC.invitation_revoked)
    if invitation.consumed:
        raise WorkerEnrollmentError(EC.invitation_consumed)
    _assert_invitation_unexpired(invitation, now)
    # the invitation/enrollment identity relationship must be exact
    if (
        invitation.enrollment_id != enrollment_id
        or invitation.transaction_id != loaded.state.transaction_id
    ):
        raise WorkerEnrollmentError(EC.scope_mismatch)

    new_state = _run_pure(
        lambda: bind_worker_identity(
            loaded.state,
            worker_installation_id=worker_installation_id,
            worker_key_id=worker_key_id,
            transaction_id=transaction_id,
            now=now,
        )
    )
    if (
        new_state is loaded.state
    ):  # idempotent at-target (a lost receipt) — record, do not re-advance
        _ensure_receipt(session, loaded, step, input_digest)
        return TransitionOutcome(loaded.state, loaded.state.revision, deduplicated=True)

    try:
        repo.consume_invitation(session, enrollment_id=enrollment_id, consumed_at=_utcnow())
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    _commit(session, loaded, new_state, step, input_digest)
    return TransitionOutcome(new_state, new_state.revision, deduplicated=False)


def record_offer(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    facts: HandoffFacts,
    now: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _advance_step(
        session,
        actor,
        enrollment_id=enrollment_id,
        step="record_controller_offer",
        input_payload={
            "kind": facts.kind,
            "digest": facts.digest,
            "transaction_id": facts.transaction_id,
            "signer_key_id": facts.signer_key_id,
        },
        transition=lambda state: record_controller_offer(state, facts, now=now),
        expected=expected,
        claimed_scope=claimed_scope,
    )


def record_result(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    facts: HandoffFacts,
    now: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _advance_step(
        session,
        actor,
        enrollment_id=enrollment_id,
        step="record_worker_result",
        input_payload={
            "kind": facts.kind,
            "digest": facts.digest,
            "transaction_id": facts.transaction_id,
            "signer_key_id": facts.signer_key_id,
        },
        transition=lambda state: record_worker_result(state, facts, now=now),
        expected=expected,
        claimed_scope=claimed_scope,
    )


def verify_release(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    release_digest: str,
    now: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _advance_step(
        session,
        actor,
        enrollment_id=enrollment_id,
        step="mark_verified",
        input_payload={"release_digest": release_digest},
        transition=lambda state: mark_verified(state, release_digest=release_digest, now=now),
        expected=expected,
        claimed_scope=claimed_scope,
    )


def mark_enrollment_healthy(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    now: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _advance_step(
        session,
        actor,
        enrollment_id=enrollment_id,
        step="mark_healthy",
        input_payload={},
        transition=lambda state: mark_healthy(state, now=now),
        expected=expected,
        claimed_scope=claimed_scope,
    )


def _advance_step(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    step: str,
    input_payload: dict[str, object],
    transition: Callable[[EnrollmentState], EnrollmentState],
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None,
) -> TransitionOutcome:
    _assert_schema_ready(session)
    input_digest = _input_digest(step, input_payload)
    loaded = _load_authorized(session, actor, enrollment_id, claimed_scope)

    # exact-retry dedup precedes the expected-revision check (see bind_worker for the rationale)
    served = _serve_receipt(session, loaded, step, input_digest)
    if served is not None:
        return served
    _verify_expected(loaded, expected)

    new_state = _run_pure(lambda: transition(loaded.state))
    if new_state is loaded.state:  # idempotent at-target with a lost receipt
        _ensure_receipt(session, loaded, step, input_digest)
        return TransitionOutcome(loaded.state, loaded.state.revision, deduplicated=True)

    _commit(session, loaded, new_state, step, input_digest)
    return TransitionOutcome(new_state, new_state.revision, deduplicated=False)


def _ensure_receipt(
    session: Session, loaded: LoadedEnrollment, step: str, input_digest: str
) -> None:
    """Record an at-least-once receipt for an idempotent at-target call whose original receipt is
    missing, without bumping the revision. Idempotent: a concurrent insert of the same key is a
    no-op (the row already records this exact result)."""
    existing = repo.find_receipt(
        session, enrollment_id=loaded.state.enrollment_id, step=step, input_digest=input_digest
    )
    if existing is not None:
        return
    session.add(
        ReceiptRow(
            enrollment_id=loaded.state.enrollment_id,
            step=step,
            input_digest=input_digest,
            resulting_revision=loaded.state.revision,
            resulting_state_digest=loaded.state.digest(),
        )
    )
    try:
        session.flush()
    except IntegrityError:
        raise WorkerEnrollmentError(EC.revision_conflict) from None


# ----------------------------------------------------------------------- lifecycle (refuse/recover)


def refuse_enrollment(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    reason: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _lifecycle(
        session,
        actor,
        enrollment_id=enrollment_id,
        transition=lambda state: refuse(state, reason),
        expected=expected,
        claimed_scope=claimed_scope,
    )


def recover_enrollment(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    reason: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _lifecycle(
        session,
        actor,
        enrollment_id=enrollment_id,
        transition=lambda state: require_recovery(state, reason),
        expected=expected,
        claimed_scope=claimed_scope,
    )


def _lifecycle(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    transition: Callable[[EnrollmentState], EnrollmentState],
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None,
) -> TransitionOutcome:
    _assert_schema_ready(session)
    loaded = _load_authorized(session, actor, enrollment_id, claimed_scope)
    _verify_expected(loaded, expected)
    new_state = _run_pure(lambda: transition(loaded.state))
    if new_state is loaded.state:  # already at that terminal — no write
        return TransitionOutcome(loaded.state, loaded.state.revision, deduplicated=True)
    # refuse()/require_recovery() carry no step receipt (not at-least-once worker steps)
    _commit(session, loaded, new_state, step=None, input_digest=None)
    return TransitionOutcome(new_state, new_state.revision, deduplicated=False)


# --------------------------------------------------------------------------- read / status


def load_public_view(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    claimed_scope: ClaimedScope | None = None,
) -> dict[str, object]:
    """A bounded, secret-free status projection. Fully rehydrates + validates, so a corrupt or
    same-key row RAISES rather than being surfaced."""
    _assert_schema_ready(session)
    try:
        loaded = repo.load_read_only(session, enrollment_id)
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    if loaded is None:
        raise WorkerEnrollmentError(EC.not_found)
    _authorize(actor, loaded)
    _check_scope(loaded, claimed_scope)
    try:
        repo.verify_history_consistent(session, enrollment_id, loaded.state)
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    # The projection runs the pure secret-scan; after full rehydration nothing should trip it, but a
    # non-bounded escape would break the closed-code contract, so any projection failure maps to the
    # bounded corruption code (defense in depth — never leak a raw exception).
    try:
        return loaded.state.public_view()
    except WorkerEnrollmentError:
        raise
    except Exception:  # noqa: BLE001 - a projection failure must not escape as an unbounded error
        raise WorkerEnrollmentError(EC.state_corrupt) from None


# --------------------------------------------------------------------------- invitation expiry


def _assert_invitation_unexpired(invitation: object, now: str) -> None:
    now_dt = repo.parse_canonical_utc(now)
    if now_dt is None:
        raise WorkerEnrollmentError(EC.time_invalid)
    expires_dt = repo.parse_canonical_utc(getattr(invitation, "expires_at", None))
    if expires_dt is None:  # a persisted invitation with a malformed expiry is corrupt
        raise WorkerEnrollmentError(EC.state_corrupt)
    if now_dt >= expires_dt:
        raise WorkerEnrollmentError(EC.invitation_expired)


__all__ = [
    "ClaimedScope",
    "ExpectedRevision",
    "TransitionOutcome",
    "bind_worker",
    "create_invitation_and_open",
    "load_public_view",
    "mark_enrollment_healthy",
    "recover_enrollment",
    "record_offer",
    "record_result",
    "refuse_enrollment",
    "verify_release",
]
