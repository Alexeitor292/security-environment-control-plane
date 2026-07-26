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

This module does NOT commit — the caller (router/test) owns the transaction boundary — and it never
partially materializes a transition on a refusal: a refusal raises before any write, so the caller
simply rolls back. No network transport, API route, CLI, host mutation, provider contact, workflow,
OpenTofu or operator activation lives here; PR5H-A stays an inert durable foundation.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from secp_commissioning.canonical import sha256_digest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api import worker_enrollment_repository as repo
from secp_api.auth import Principal
from secp_api.enums import AuditAction, Permission
from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import _utcnow
from secp_api.services import controller_identity
from secp_api.worker_enrollment_contract import (
    ENROLLMENT_CONTRACT_VERSION,
    INVITED,
    RECOVERY_REQUIRED,
    REFUSED,
    EnrollmentState,
    HandoffFacts,
    WorkerEnrollmentContractError,
    WorkerEnrollmentInvitation,
    bind_worker_identity,
    create_invitation,
    is_deployment_site_label,
    mark_healthy,
    mark_verified,
    open_enrollment,
    record_controller_offer,
    record_worker_result,
    refuse,
    require_recovery,
)
from secp_api.worker_enrollment_models import WorkerEnrollmentInvitation as InvitationRow
from secp_api.worker_enrollment_models import WorkerEnrollmentStepReceipt as ReceiptRow
from secp_api.worker_enrollment_repository import LoadedEnrollment, RepositoryRefusal
from secp_api.worker_enrollment_schema import EnrollmentSchemaError, assert_enrollment_schema_ready

#: Domain separator for the idempotency-key -> durable nonce digest (never reused for another
#: purpose; bumping the suffix would intentionally invalidate all prior idempotency bindings).
_IDEMPOTENCY_DOMAIN = b"secp:enrollment:invitation-idempotency:v1\x00"

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


def build_invitation(
    *,
    controller_installation_id: str,
    controller_key_id: str,
    controller_trust_anchor_hex: str,
    controller_origin: str,
    release_digest: str,
    transaction_id: str,
    nonce: str,
    created_at: str,
    expires_at: str,
) -> WorkerEnrollmentInvitation:
    """Build + validate a controller invitation from raw caller fields, surfacing any pure-contract
    refusal as a bounded ``WorkerEnrollmentError`` so an API caller receives a closed code (e.g.
    ``enrollment_origin_not_https``) rather than an unhandled internal error."""
    try:
        return create_invitation(
            controller_installation_id=controller_installation_id,
            controller_key_id=controller_key_id,
            controller_trust_anchor_hex=controller_trust_anchor_hex,
            controller_origin=controller_origin,
            release_digest=release_digest,
            transaction_id=transaction_id,
            nonce=nonce,
            created_at=created_at,
            expires_at=expires_at,
        )
    except WorkerEnrollmentContractError as exc:
        raise _surface(exc) from None


def create_invitation_and_open(
    session: Session,
    actor: Principal,
    *,
    invitation: WorkerEnrollmentInvitation,
    deployment_site_label: str,
    now: str,
) -> TransitionOutcome:
    """Persist a controller invitation and open its enrollment at revision 0, atomically.

    ``organization_id`` comes from the authenticated actor; ``deployment_site_label`` is fixed here
    and is immutable thereafter. A duplicate nonce or invitation collides on a UNIQUE/PK constraint
    and refuses ``creation_conflict``.

    Creating an invitation is a manage-permission mutation and is enforced HERE (not only in the
    router), so a direct service call cannot bypass RBAC. The invitation-created audit event is
    appended in the SAME transaction as the durable rows, so state and audit commit or roll back
    together; it carries only org, actor, action, enrollment id, site label, state and revision —
    never the nonce, trust-anchor bytes, origin, transaction id or a full digest.
    """
    actor.require(Permission.enrollment_manage)
    _assert_schema_ready(session)
    if not is_deployment_site_label(deployment_site_label):
        raise WorkerEnrollmentError(EC.scope_mismatch)
    try:
        loaded = repo.create_invitation_and_open(
            session,
            organization_id=actor.organization_id,
            invitation=invitation,
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
    audit.record(
        session,
        action=AuditAction.enrollment_invitation_created,
        resource_type="worker_enrollment",
        resource_id=loaded.state.enrollment_id,
        actor=str(actor.user_id),
        organization_id=actor.organization_id,
        outcome="success",
        data={
            "deployment_site_label": deployment_site_label,
            "state": loaded.state.state,
            "revision": loaded.state.revision,
        },
    )
    return TransitionOutcome(state=loaded.state, committed_revision=0, deduplicated=False)


# ------------------------------------------------------------------- supported idempotent creation


@dataclass(frozen=True)
class SupportedInvitationResult:
    """The full, non-secret invitation response — identical whether freshly created or replayed."""

    enrollment_id: str
    invitation_id: str
    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    transaction_id: str
    deployment_site_label: str
    created_at: str
    expires_at: str
    state: str
    revision: int
    deduplicated: bool


def _idempotency_nonce(organization_id: uuid.UUID, idempotency_key: str) -> str:
    """A domain-separated, org-bound digest of the client idempotency key — the durable single-use
    nonce (== invitation_id). The RAW key is never persisted or logged; only its digest is."""
    digest = hashlib.sha256()
    digest.update(_IDEMPOTENCY_DOMAIN)
    digest.update(organization_id.bytes)
    digest.update(b"\x00")
    digest.update(idempotency_key.encode("utf-8"))
    return "sha256:" + digest.hexdigest()


def _duration_seconds(created_at: str, expires_at: str) -> int | None:
    created = repo.parse_canonical_utc(created_at)
    expires = repo.parse_canonical_utc(expires_at)
    if created is None or expires is None:
        return None
    return int((expires - created).total_seconds())


def create_supported_invitation(
    session: Session,
    actor: Principal,
    *,
    idempotency_key: str,
    deployment_site_label: str,
    ttl_seconds: int,
    created_at: str,
    expires_at: str,
) -> SupportedInvitationResult:
    """The supported, retry-safe invitation-creation path.

    The controller identity is sourced from the authoritative ACTIVE record (never the caller). The
    durable nonce is a domain-separated digest of the org + client idempotency key, so a retry
    collides on ``UNIQUE(invitation_id)`` and returns the ORIGINAL invitation; the same key with
    different bound input (site or TTL) refuses ``enrollment_idempotency_conflict``. No commit here.
    """
    actor.require(Permission.enrollment_manage)
    _assert_schema_ready(session)
    if not is_deployment_site_label(deployment_site_label):
        raise WorkerEnrollmentError(EC.scope_mismatch)
    identity = controller_identity.load_active_controller_identity(session)
    nonce = _idempotency_nonce(actor.organization_id, idempotency_key)
    invitation = build_invitation(
        controller_installation_id=identity.controller_installation_id,
        controller_key_id=identity.controller_key_id,
        controller_trust_anchor_hex=identity.controller_trust_anchor_hex,
        controller_origin=identity.controller_origin,
        release_digest=identity.release_digest,
        transaction_id="txn-" + secrets.token_hex(16),  # >= 128 bits of entropy
        nonce=nonce,
        created_at=created_at,
        expires_at=expires_at,
    )
    try:
        # R3: isolate the speculative insert in a SAVEPOINT so a UNIQUE-nonce collision rolls back
        # ONLY this insert — the caller's outer transaction (any unrelated staged rows) survives.
        with session.begin_nested():
            outcome = create_invitation_and_open(
                session,
                actor,
                invitation=invitation,
                deployment_site_label=deployment_site_label,
                now=created_at,
            )
    except WorkerEnrollmentError as exc:
        if exc.code != EC.creation_conflict.value:
            raise
        return _replay_or_conflict(
            session, actor, identity, nonce, deployment_site_label, ttl_seconds
        )
    state = outcome.state
    return SupportedInvitationResult(
        enrollment_id=state.enrollment_id,
        invitation_id=invitation.invitation_id,
        controller_installation_id=invitation.controller_installation_id,
        controller_key_id=invitation.controller_key_id,
        controller_trust_anchor_hex=invitation.controller_trust_anchor_hex,
        controller_origin=invitation.controller_origin,
        release_digest=invitation.release_digest,
        transaction_id=invitation.transaction_id,
        deployment_site_label=deployment_site_label,
        created_at=invitation.created_at,
        expires_at=invitation.expires_at,
        state=state.state,
        revision=state.revision,
        deduplicated=False,
    )


def _replay_or_conflict(
    session: Session,
    actor: Principal,
    identity: controller_identity.ActiveControllerIdentity,
    nonce: str,
    deployment_site_label: str,
    ttl_seconds: int,
) -> SupportedInvitationResult:
    """Recover the ORIGINAL invitation on a UNIQUE-nonce collision. The caller's outer tx is
    intact (only the savepoint rolled back — R3). The persisted invitation's ENTIRE bound input
    must match the current request, INCLUDING the exact active identity/origin/release (R2), so
    a key reused after rotation/origin/release change refuses ``enrollment_idempotency_conflict``.
    The response is the IMMUTABLE original create (invited / revision 0), reconstructed + verified
    the invitation + revision-zero history — never the current head, which may advance (R4)."""
    row = repo.load_invitation_by_nonce(session, nonce)
    if row is None:  # the nonce is not (yet) durable — a non-idempotency conflict
        raise WorkerEnrollmentError(EC.creation_conflict)
    if (
        row.organization_id != actor.organization_id
        or row.deployment_site_label != deployment_site_label
        or _duration_seconds(row.invitation_created_at, row.expires_at) != ttl_seconds
        or row.controller_installation_id != identity.controller_installation_id
        or row.controller_key_id != identity.controller_key_id
        or row.controller_trust_anchor_hex != identity.controller_trust_anchor_hex
        or row.controller_origin != identity.controller_origin
        or row.release_digest != identity.release_digest
    ):
        raise WorkerEnrollmentError(EC.idempotency_conflict)
    original = _reconstruct_original_create(session, row)
    return SupportedInvitationResult(
        enrollment_id=row.enrollment_id,
        invitation_id=row.invitation_id,
        controller_installation_id=row.controller_installation_id,
        controller_key_id=row.controller_key_id,
        controller_trust_anchor_hex=row.controller_trust_anchor_hex,
        controller_origin=row.controller_origin,
        release_digest=row.release_digest,
        transaction_id=row.transaction_id,
        deployment_site_label=row.deployment_site_label,
        created_at=row.invitation_created_at,
        expires_at=row.expires_at,
        state=original.state,  # always INVITED
        revision=original.revision,  # always 0
        deduplicated=True,
    )


def _reconstruct_original_create(session: Session, row: InvitationRow) -> EnrollmentState:
    """Rebuild the ORIGINAL revision-0 (INVITED) enrollment state from the immutable invitation row
    and prove it against the append-only revision-zero history — independent of the current head."""
    invitation = WorkerEnrollmentInvitation(
        contract_version=ENROLLMENT_CONTRACT_VERSION,
        invitation_id=row.invitation_id,
        controller_installation_id=row.controller_installation_id,
        controller_key_id=row.controller_key_id,
        controller_trust_anchor_hex=row.controller_trust_anchor_hex,
        controller_origin=row.controller_origin,
        release_digest=row.release_digest,
        transaction_id=row.transaction_id,
        sequence=0,
        created_at=row.invitation_created_at,
        expires_at=row.expires_at,
    )
    original = _run_pure(lambda: open_enrollment(invitation, now=row.invitation_created_at))
    rev0 = repo.load_revision_row(session, row.enrollment_id, 0)
    if (
        rev0 is None
        or original.state != INVITED
        or original.revision != 0
        or original.enrollment_id != row.enrollment_id
        or rev0.state_digest != original.digest()
    ):
        raise WorkerEnrollmentError(EC.state_corrupt)
    return original


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
        target_state=REFUSED,
        reason=reason,
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
        target_state=RECOVERY_REQUIRED,
        reason=reason,
        expected=expected,
        claimed_scope=claimed_scope,
    )


#: The bounded refusal-reason code recorded when an operator revokes an enrollment invitation.
_REVOKE_REASON = "operator_revoked"


def revoke_enrollment(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    expected_revision: int,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    """Operator revocation: drive an active enrollment to the ``refused`` terminal on the durable
    CAS lifecycle. Requires ``enrollment_manage`` (enforced here, not only in the router) and the
    organization boundary. **Idempotent**: an already-terminal enrollment returns its state with no
    write and no new audit. A stale ``expected_revision`` on a live enrollment refuses
    ``revision_conflict``; concurrent revokes collide on the head CAS so exactly one wins. Exactly
    one bounded, secret-free audit event is recorded — only for the winning transition. Does NOT
    commit — the caller owns the transaction boundary."""
    actor.require(Permission.enrollment_manage)
    _assert_schema_ready(session)
    loaded = _load_authorized(session, actor, enrollment_id, claimed_scope)
    state = loaded.state
    if state.state in (REFUSED, RECOVERY_REQUIRED):
        return TransitionOutcome(state, state.revision, deduplicated=True)  # already terminal
    if state.revision != expected_revision:
        raise WorkerEnrollmentError(EC.revision_conflict)
    new_state = _run_pure(lambda: refuse(state, _REVOKE_REASON))
    if new_state is state:  # defensive: the contract treated it as a no-op
        return TransitionOutcome(state, state.revision, deduplicated=True)
    _commit(session, loaded, new_state, step=None, input_digest=None)
    audit.record(
        session,
        action=AuditAction.enrollment_revoked,
        resource_type="worker_enrollment",
        resource_id=enrollment_id,
        actor=str(actor.user_id),
        organization_id=actor.organization_id,
        outcome="success",
        data={"state": new_state.state, "revision": new_state.revision},
    )
    return TransitionOutcome(new_state, new_state.revision, deduplicated=False)


def _serve_lifecycle_retry(
    session: Session,
    loaded: LoadedEnrollment,
    *,
    target_state: str,
    reason: str,
    expected: ExpectedRevision,
) -> TransitionOutcome | None:
    """Explicit lost-response recovery for a LIFECYCLE transition (`refuse` / `require_recovery`).

    Lifecycle transitions carry **no worker step receipt** by design: the step-receipt ledger is
    at-least-once dedup for the five *externally delivered* worker protocol steps, while the durable
    outcome record for an internal lifecycle transition (and for the expiry sweep) is the
    append-only **revision-history row**. This narrowly-bounded path recognises an EXACT retry of
    the same lifecycle request from that record, so a committed transition whose response was lost
    resolves to a truthful no-op instead of a spurious conflict.

    Returns a deduplicated outcome ONLY when every condition holds. Anything else returns ``None``
    and falls through to the ordinary expected-revision check (bounded ``revision_conflict``), or
    — where the append-only history itself disagrees — refuses ``history_inconsistent``. Being
    terminal is never on its own sufficient.
    """
    current = loaded.state
    # (1) the head is exactly the requested terminal target
    # (2) the persisted reason is exactly the requested bounded reason code
    # (3) the head is exactly ONE revision beyond the caller's expectation
    # (4) the chain links the caller's expected state to the head
    if (
        current.state != target_state
        or current.refusal_reason != reason
        or current.revision != expected.revision + 1
        or current.predecessor_digest != expected.state_digest
    ):
        return None

    enrollment_id = current.enrollment_id
    # (5) the history row at the EXPECTED revision exists and matches the caller's token exactly
    prior_row = repo.revision_row(session, enrollment_id=enrollment_id, revision=expected.revision)
    if prior_row is None:
        # history is contiguous 0..N (already verified), so a missing predecessor row is corruption
        raise WorkerEnrollmentError(EC.history_inconsistent)
    if (
        prior_row.revision != expected.revision
        or prior_row.state_digest != expected.state_digest
        or prior_row.predecessor_digest != expected.predecessor_digest
    ):
        return None  # the caller's token does not match what was actually recorded

    # (6) the history row at the CURRENT revision matches the head digest, state and predecessor
    current_row = repo.revision_row(session, enrollment_id=enrollment_id, revision=current.revision)
    if (
        current_row is None
        or current_row.state_digest != current.digest()
        or current_row.state != current.state
        or current_row.predecessor_digest != current.predecessor_digest
    ):
        raise WorkerEnrollmentError(EC.history_inconsistent)

    # (7) the head is still the IMMEDIATE result of that operation — no later revision occurred
    highest = repo.max_revision(session, enrollment_id=enrollment_id)
    if highest is None or highest != current.revision:
        return None

    # (8) organization, deployment_site_label, transaction, release and the controller/worker
    #     identities are the authoritative persisted ones: ``_load_authorized`` bound the org and
    #     compared the claimed scope, and the repository's invitation cross-check re-derived the
    #     tenancy binding, transaction, release, controller identity and expiry from the
    #     tamper-evident invitation. (9) The full rehydration + history invariants passed there too.
    return TransitionOutcome(current, current.revision, deduplicated=True)


def _lifecycle(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    transition: Callable[[EnrollmentState], EnrollmentState],
    target_state: str,
    reason: str,
    expected: ExpectedRevision,
    claimed_scope: ClaimedScope | None,
) -> TransitionOutcome:
    _assert_schema_ready(session)
    loaded = _load_authorized(session, actor, enrollment_id, claimed_scope)
    # An exact lifecycle retry is recognised from the append-only history BEFORE the caller's
    # now-stale expectation is rejected — the retried request legitimately carries the token it
    # first sent (mirrors the step-receipt ordering for worker steps).
    served = _serve_lifecycle_retry(
        session, loaded, target_state=target_state, reason=reason, expected=expected
    )
    if served is not None:
        return served
    _verify_expected(loaded, expected)
    new_state = _run_pure(lambda: transition(loaded.state))
    if new_state is loaded.state:  # already at that terminal — no write
        return TransitionOutcome(loaded.state, loaded.state.revision, deduplicated=True)
    # refuse()/require_recovery() carry no step receipt (not at-least-once worker steps); the
    # revision-history row is the durable lifecycle transition record.
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
    same-key row RAISES rather than being surfaced.

    Requires the read permission (enforced HERE so a direct service call cannot bypass RBAC);
    organization isolation is still enforced independently by ``_authorize`` after the row loads."""
    actor.require(Permission.enrollment_read)
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
