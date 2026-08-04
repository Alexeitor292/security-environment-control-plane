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

import base64
import datetime as _dt
import hashlib
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Final

from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_digest
from secp_commissioning.controller_enrollment_signer import AuthorizedControllerOfferContext
from secp_commissioning.enrollment_attestation import (
    WORKER_RESULT_OUTCOME_HEALTHY,
    DetachedAttestation,
    claim_digest,
    health_evidence_complete,
    worker_binding_claim,
    worker_result_claim,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api import worker_enrollment_repository as repo
from secp_api.auth import Principal
from secp_api.enrollment_evidence import (
    verify_controller_offer,
    verify_worker_binding_pop,
    verify_worker_result,
)
from secp_api.enrollment_signer_client import EnrollmentOfferSignerClient
from secp_api.enums import AuditAction, Permission
from secp_api.enums import WorkerEnrollmentErrorCode as EC
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import _utcnow
from secp_api.services import controller_identity
from secp_api.worker_enrollment_contract import (
    ALL_STATES,
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
    deployment_site_label_refusal,
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


@dataclass(frozen=True)
class VerifiedEnrollmentExchangeActor:
    """A cryptographically-verified worker-exchange authority (C1).

    Produced ONLY by the service AFTER it has (1) loaded the authoritative persisted
    invitation/enrollment and (2) verified the worker's signed evidence (the bind proof-of-
    possession, or the signed worker result against the already-bound key) against that
    authoritative state. It is the security authority the evidence-driven mutation services require
    — NOT a control-plane :class:`Principal`, and NEVER synthesized from HTTP fields.
    ``enrollment:progress`` is never granted or inferred from the wire. Every field is bound from
    PERSISTENCE
    (organization / deployment site / invitation / transaction / release / expiry) or DERIVED from
    the presented public key (the worker key id); a worker-supplied organization / site is only ever
    COMPARED against the authoritative binding, never used to select a row or grant authority."""

    enrollment_id: str
    organization_id: uuid.UUID
    deployment_site_label: str
    invitation_id: str
    worker_installation_id: str
    worker_key_id: str
    transaction_id: str
    release_digest: str
    expires_at: str

    @property
    def audit_actor(self) -> str:
        """A bounded, code-owned worker fingerprint for the audit ``actor`` field — derived from
        the PUBLIC worker key id (itself a sha256 digest), never caller free-text or a key byte."""
        fingerprint = self.worker_key_id.split(":", 1)[-1][:16]
        return f"worker-exchange:{fingerprint}"


#: The authority a progression mutation runs under: either the cryptographically-verified worker
#: exchange actor (the SUPPORTED evidence-driven path) or a control-plane :class:`Principal` (the
#: SEALED claim-only routes, which stay RBAC-gated and refused in production).
ExchangeAuthority = Principal | VerifiedEnrollmentExchangeActor


def _require_progress(authority: ExchangeAuthority) -> None:
    """A :class:`VerifiedEnrollmentExchangeActor` IS the cryptographic proof of an authorized worker
    exchange, so it carries its own authority and needs no RBAC grant. A control-plane
    :class:`Principal` (the sealed claim-only routes) must hold ``enrollment:progress`` — which is
    NEVER granted or inferred from HTTP fields on the supported path."""
    if isinstance(authority, Principal):
        authority.require(Permission.enrollment_progress)


def _audit_actor(authority: ExchangeAuthority) -> str:
    """The bounded audit ``actor``: a Principal's user id, or the verified actor's code-owned worker
    fingerprint — never worker-supplied free-text."""
    if isinstance(authority, VerifiedEnrollmentExchangeActor):
        return authority.audit_actor
    return str(authority.user_id)


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


def _authorize(actor: ExchangeAuthority, loaded: LoadedEnrollment) -> None:
    # organization is the ONLY authorization boundary. For a control-plane Principal it is the
    # authenticated identity's org; for a VerifiedEnrollmentExchangeActor it is the org bound from
    # persistence when the signed evidence was verified — either way it must equal the loaded row's.
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


def _verify_expected_revision(loaded: LoadedEnrollment, expected_revision: int) -> None:
    """The PUBLIC optimistic pre-check for a progression step: the caller's last-observed revision
    (all a customer/worker/UI ever sees or supplies) must equal the loaded head's revision. The
    internal CAS ``state_digest`` / ``sequence`` / ``predecessor_digest`` are DERIVED from the exact
    loaded state — never caller-supplied — and the durable repository CAS still compare-and-swaps on
    the head's ``(revision, state_digest)``, so a lost update / concurrent advance still refuses."""
    if expected_revision != loaded.state.revision:
        raise WorkerEnrollmentError(EC.revision_conflict)


def _load_authorized(
    session: Session, actor: ExchangeAuthority, enrollment_id: str, claimed: ClaimedScope | None
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


def _load_for_exchange(
    session: Session, enrollment_id: str, claimed: ClaimedScope | None
) -> LoadedEnrollment:
    """Load + lock + history-verify the authoritative enrollment for a WORKER EXCHANGE (C1).

    There is NO control-plane principal on the supported worker path — the worker authenticates by
    signed evidence, not an OIDC bearer — so organization and deployment site are taken
    AUTHORITATIVELY from the persisted row and never from a caller claim. A worker-supplied
    ``claimed_scope`` is only COMPARED against the authoritative binding (``_check_scope``), never
    used to select or authorize the row."""
    try:
        loaded = repo.load_for_update(session, enrollment_id)
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    if loaded is None:
        raise WorkerEnrollmentError(EC.not_found)
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
    # T3: a delayed exact retry returns the ORIGINAL step result — rehydrate the IMMUTABLE history
    # state the receipt recorded (its ``resulting_revision``), never the current head. After the
    # enrollment later reaches (say) healthy or refused, replaying bind still returns worker_bound.
    try:
        historical = repo.load_revision_state(
            session, loaded.state.enrollment_id, receipt.resulting_revision
        )
    except RepositoryRefusal as exc:  # missing / malformed / tampered history snapshot
        raise _surface(exc) from None
    if historical is None:  # a receipt pointing at a non-existent revision is corruption
        raise WorkerEnrollmentError(EC.state_corrupt)
    # the rehydrated history digest must equal the digest the receipt independently recorded
    if historical.digest() != receipt.resulting_state_digest:
        raise WorkerEnrollmentError(EC.state_corrupt)
    if loaded.state.revision < receipt.resulting_revision:  # head behind a recorded result
        raise WorkerEnrollmentError(EC.history_inconsistent)
    # The history snapshot is CANONICAL material, so it cannot carry the non-canonical
    # ``deployment_site_label``. Re-stamp it from the authoritative loaded row (the label is
    # immutable for an enrollment and is cross-checked against the invitation on every load), so a
    # delayed idempotent retry projects the same site as the original response. Done AFTER every
    # digest/consistency compare above — and harmless to them, since the label is not canonical.
    historical = replace(historical, deployment_site_label=loaded.deployment_site_label)
    return TransitionOutcome(
        state=historical, committed_revision=receipt.resulting_revision, deduplicated=True
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
    # A SPECIFIC code: `scope_mismatch` means "a worker claimed a site that disagrees with the
    # authoritative binding", and creation has no binding to disagree with yet. Reporting it here
    # sent an operator to look at permissions when the answer was "rename your site".
    label_refusal = deployment_site_label_refusal(deployment_site_label)
    if label_refusal is not None:
        raise WorkerEnrollmentError(label_refusal)
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
    # A SPECIFIC code: `scope_mismatch` means "a worker claimed a site that disagrees with the
    # authoritative binding", and creation has no binding to disagree with yet. Reporting it here
    # sent an operator to look at permissions when the answer was "rename your site".
    label_refusal = deployment_site_label_refusal(deployment_site_label)
    if label_refusal is not None:
        raise WorkerEnrollmentError(label_refusal)
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
    actor: ExchangeAuthority,
    *,
    enrollment_id: str,
    worker_installation_id: str,
    worker_key_id: str,
    transaction_id: str,
    now: str,
    expected_revision: int,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    """The nonce-consumption point: the first successful worker-identity binding. Consumes the
    single-use invitation and persists the first advanced revision in ONE transaction."""
    _require_progress(actor)
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
    _verify_expected_revision(loaded, expected_revision)

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
    _audit_progress(session, actor, enrollment_id, step, new_state)
    return TransitionOutcome(new_state, new_state.revision, deduplicated=False)


@dataclass(frozen=True)
class ExchangeOutcome:
    """The bind-exchange result: the internally-signed controller offer envelope (public material
    only), the bounded status projection, and whether this was a deduplicated lost-response
    retry."""

    signed_offer: dict[str, object]
    status: dict[str, object]
    deduplicated: bool


def _offer_envelope(claim: dict[str, str], attestation: DetachedAttestation) -> dict[str, object]:
    return {
        "claim": claim,
        "attestation": {
            "algorithm": attestation.algorithm,
            "key_id": attestation.key_id,
            "public_key_hex": attestation.public_key_hex,
            "signature": attestation.signature,
        },
    }


def _bind_input_digest(
    *,
    enrollment_id: str,
    invitation_id: str,
    worker_installation_id: str,
    worker_key_id: str,
    pop_claim_digest: str,
    attestation: DetachedAttestation,
    expected_revision: int,
    transaction_id: str,
    release_digest: str,
) -> str:
    """The digest binding the EXACT winning bind request (C2): the enrollment, invitation, the
    VERIFIED worker installation id, the DERIVED worker key id, the PoP claim digest, the detached
    attestation's identity + signature, the expected initial revision, the controller transaction,
    and the release. An exact retry recomputes this and requires equality with the winning row; a
    different worker / key / PoP / initial request produces a different digest and conflicts."""
    return _input_digest(
        "bind_exchange",
        {
            "enrollment_id": enrollment_id,
            "invitation_id": invitation_id,
            "worker_installation_id": worker_installation_id,
            "worker_key_id": worker_key_id,
            "pop_claim_digest": pop_claim_digest,
            "attestation_key_id": attestation.key_id,
            "attestation_public_key_hex": attestation.public_key_hex,
            "attestation_signature": attestation.signature,
            "expected_revision": expected_revision,
            "controller_transaction_id": transaction_id,
            "release_digest": release_digest,
        },
    )


def _replay_bind_record(
    session: Session,
    record: repo.SignedOfferRecord,
    *,
    enrollment_id: str,
    bind_input_digest: str,
    worker_installation_id: str,
    worker_key_id: str,
) -> ExchangeOutcome:
    """EXACT winning-bind replay (C2). The PoP was already re-verified by the caller. Requires the
    recomputed ``bind_input_digest`` AND the presented worker installation/key to equal the winning
    row; re-proves the offer-claim, resulting-state and history digests; then returns the EXACT
    original BindExchangeOut bytes/status — never the (possibly advanced) current head, never the
    signer. A different worker / key / PoP / initial request conflicts (bounded
    ``enrollment_idempotency_conflict``)."""
    # (3) require the winning bind input + the same worker identity — else a bounded conflict
    if (
        bind_input_digest != record.bind_input_digest
        or worker_installation_id != record.worker_installation_id
        or worker_key_id != record.worker_key_id
    ):
        raise WorkerEnrollmentError(EC.idempotency_conflict)
    # (5) validate the offer-claim digest against the persisted envelope, and the resulting-state
    #     digest against the append-only history at the recorded resulting revision
    try:
        envelope = json.loads(record.envelope)
        response = json.loads(record.response_json)
    except Exception:  # noqa: BLE001 - a malformed persisted row is corruption, never re-signed
        raise WorkerEnrollmentError(EC.state_corrupt) from None
    if (
        not isinstance(envelope, dict)
        or not isinstance(envelope.get("claim"), dict)
        or claim_digest(envelope["claim"]) != record.offer_claim_digest
    ):
        raise WorkerEnrollmentError(EC.state_corrupt)
    history_digest = repo.revision_state_digest(
        session, enrollment_id=enrollment_id, revision=record.resulting_revision
    )
    if history_digest is None or history_digest != record.resulting_state_digest:
        raise WorkerEnrollmentError(EC.state_corrupt)
    if (
        not isinstance(response, dict)
        or not isinstance(response.get("signed_offer"), dict)
        or not isinstance(response.get("enrollment"), dict)
    ):
        raise WorkerEnrollmentError(EC.state_corrupt)
    # (6) return the EXACT original response/status (never the current head); no signer, no write
    return ExchangeOutcome(
        signed_offer=response["signed_offer"], status=response["enrollment"], deduplicated=True
    )


def bind_worker_exchange(
    session: Session,
    *,
    signer: EnrollmentOfferSignerClient,
    enrollment_id: str,
    worker_installation_id: str,
    worker_public_key_hex: str,
    pop_attestation: DetachedAttestation,
    expected_revision: int,
    now: str,
    claimed_scope: ClaimedScope | None = None,
) -> ExchangeOutcome:
    """The supported, evidence-driven bind exchange (SECP-PR5H-B1 Phase 3, C1).

    This path is authenticated by the WORKER'S SIGNED EVIDENCE, not a control-plane OIDC principal:
    it takes no :class:`Principal`. It verifies the worker's proof-of-possession against the
    controller's OWN authoritative invitation (deriving the worker key id from the presented public
    key), PRODUCES a :class:`VerifiedEnrollmentExchangeActor` whose organization / site / invitation
    / transaction / release / expiry are bound from PERSISTENCE, then — authorized by that verified
    actor — binds the worker + consumes the single-use nonce, mints an internally-signed controller
    offer via the injected ROOT-GATED signer (the non-root API never holds the key), INDEPENDENTLY
    re-verifies that offer, records the controller-offer transition, and persists the exact signed
    offer WRITE-ONCE — all inside the caller's single transaction, so any refusal rolls back every
    effect (no consumed nonce, no bind, no offer, no signed-offer row, no audit). A lost-response
    retry (an already-persisted signed offer) re-verifies the repeated PoP and returns the
    BYTE-EQUIVALENT original offer without calling the signer or advancing the state again — true
    even after the controller key rotates."""
    _assert_schema_ready(session)
    loaded = _load_for_exchange(session, enrollment_id, claimed_scope)
    invitation = repo.load_invitation_for_update(session, enrollment_id)
    if invitation is None:
        raise WorkerEnrollmentError(EC.invitation_not_found)

    # (1) verify the worker PoP against the controller's authoritative invitation fields — this
    #     DERIVES the worker key id from the presented public key (a wire id is impossible).
    verified = verify_worker_binding_pop(
        enrollment_id=enrollment_id,
        invitation_id=invitation.invitation_id,
        controller_installation_id=invitation.controller_installation_id,
        controller_key_id=invitation.controller_key_id,
        controller_transaction_id=invitation.transaction_id,
        release_digest=invitation.release_digest,
        expires_at=invitation.expires_at,
        worker_installation_id=worker_installation_id,
        worker_public_key_hex=worker_public_key_hex,
        attestation=pop_attestation,
    )
    # (2) controller/worker key separation — a worker can never present the controller's own key
    if verified.worker_key_id == invitation.controller_key_id:
        raise WorkerEnrollmentError(EC.pop_invalid)

    # (2b) ONLY NOW — after the signed PoP verified against the authoritative invitation — mint the
    #      verified worker-exchange authority. Its org/site/invitation/transaction/release/expiry
    #      are bound from PERSISTENCE; the worker key id is DERIVED from the presented key. This is
    #      the authority every subsequent mutation runs under (never a synthesized Principal).
    actor = VerifiedEnrollmentExchangeActor(
        enrollment_id=enrollment_id,
        organization_id=loaded.organization_id,
        deployment_site_label=loaded.deployment_site_label,
        invitation_id=invitation.invitation_id,
        worker_installation_id=worker_installation_id,
        worker_key_id=verified.worker_key_id,
        transaction_id=invitation.transaction_id,
        release_digest=invitation.release_digest,
        expires_at=invitation.expires_at,
    )

    # (2c) the digest binding this EXACT bind request (C2) — recomputed identically on a retry
    pop_claim = worker_binding_claim(
        enrollment_id=enrollment_id,
        invitation_id=invitation.invitation_id,
        controller_installation_id=invitation.controller_installation_id,
        controller_key_id=invitation.controller_key_id,
        controller_transaction_id=invitation.transaction_id,
        worker_installation_id=worker_installation_id,
        worker_key_id=verified.worker_key_id,
        release_digest=invitation.release_digest,
        expires_at=invitation.expires_at,
    )
    bind_input_digest = _bind_input_digest(
        enrollment_id=enrollment_id,
        invitation_id=invitation.invitation_id,
        worker_installation_id=worker_installation_id,
        worker_key_id=verified.worker_key_id,
        pop_claim_digest=claim_digest(pop_claim),
        attestation=pop_attestation,
        expected_revision=expected_revision,
        transaction_id=invitation.transaction_id,
        release_digest=invitation.release_digest,
    )

    # (3) lost-response durability: an already-persisted winning offer means this exchange is done;
    #     re-verify the SAME winning request and return the EXACT original response — no re-sign, no
    #     re-advance. A different worker / key / PoP / initial request is a bounded conflict.
    try:
        record = repo.load_signed_offer_record(session, enrollment_id)
    except RepositoryRefusal as exc:  # a tampered / NULL-binding row is corruption, never re-signed
        raise _surface(exc) from None
    if record is not None:
        return _replay_bind_record(
            session,
            record,
            enrollment_id=enrollment_id,
            bind_input_digest=bind_input_digest,
            worker_installation_id=worker_installation_id,
            worker_key_id=verified.worker_key_id,
        )

    # (4) bind the worker + atomically consume the single-use nonce (invited -> worker_bound)
    bound = bind_worker(
        session,
        actor,
        enrollment_id=enrollment_id,
        worker_installation_id=worker_installation_id,
        worker_key_id=verified.worker_key_id,
        transaction_id=invitation.transaction_id,
        now=now,
        expected_revision=expected_revision,
        claimed_scope=claimed_scope,
    )
    predecessor_digest = bound.state.digest()

    # (5) mint the internally-signed offer from the locked authoritative state via the injected
    #     signer. The context's controller_* are the invitation's pinned identity; the signer
    #     cross-checks them against the LIVE active identity and refuses a stale (rotated) offer.
    context = AuthorizedControllerOfferContext(
        enrollment_id=enrollment_id,
        invitation_id=invitation.invitation_id,
        controller_installation_id=invitation.controller_installation_id,
        controller_key_id=invitation.controller_key_id,
        controller_origin=invitation.controller_origin,
        controller_transaction_id=invitation.transaction_id,
        worker_installation_id=worker_installation_id,
        worker_key_id=verified.worker_key_id,
        release_digest=invitation.release_digest,
        expires_at=invitation.expires_at,
        predecessor_digest=predecessor_digest,
    )
    try:
        offer = signer.sign_offer(context, now=now)
    except WorkerEnrollmentError:
        raise
    except Exception:  # noqa: BLE001 - any signer/broker failure is a bounded closed refusal
        raise WorkerEnrollmentError(EC.signer_unavailable) from None

    # (6) INDEPENDENTLY re-verify the offer the signer/broker returned (defence in depth)
    verified_offer = verify_controller_offer(
        attestation=offer.attestation,
        enrollment_id=enrollment_id,
        invitation_id=invitation.invitation_id,
        controller_installation_id=invitation.controller_installation_id,
        controller_key_id=invitation.controller_key_id,
        controller_origin=invitation.controller_origin,
        controller_transaction_id=invitation.transaction_id,
        worker_installation_id=worker_installation_id,
        worker_key_id=verified.worker_key_id,
        release_digest=invitation.release_digest,
        expires_at=invitation.expires_at,
        predecessor_digest=predecessor_digest,
    )
    offer_claim = verified_offer.claim

    # (7) record the controller-offer transition (worker_bound -> offer_transported)
    recorded = record_offer(
        session,
        actor,
        enrollment_id=enrollment_id,
        facts=HandoffFacts(
            kind="controller-offer",
            digest=claim_digest(offer_claim),
            transaction_id=invitation.transaction_id,
            signer_key_id=offer.attestation.key_id,
        ),
        now=now,
        expected_revision=bound.committed_revision,
        claimed_scope=claimed_scope,
    )

    # (8) persist the EXACT signed public offer WRITE-ONCE per enrollment (a lost race -> conflict),
    #     pinning the C2 winning-bind bindings + the EXACT original response so a retry is provable.
    envelope = _offer_envelope(offer_claim, offer.attestation)
    status_view = recorded.state.public_view()
    response = {"signed_offer": envelope, "enrollment": status_view}
    try:
        repo.persist_signed_offer(
            session,
            enrollment_id=enrollment_id,
            organization_id=loaded.organization_id,
            offer_revision=recorded.committed_revision,
            signer_key_id=offer.attestation.key_id,
            signed_offer=canonical_json(envelope),
            bind_input_digest=bind_input_digest,
            offer_claim_digest=claim_digest(offer_claim),
            resulting_revision=recorded.committed_revision,
            resulting_state_digest=recorded.state.digest(),
            worker_installation_id=worker_installation_id,
            worker_key_id=verified.worker_key_id,
            response_json=canonical_json(response),
        )
    except RepositoryRefusal as exc:
        raise _surface(exc) from None
    return ExchangeOutcome(signed_offer=envelope, status=status_view, deduplicated=False)


def record_offer(
    session: Session,
    actor: ExchangeAuthority,
    *,
    enrollment_id: str,
    facts: HandoffFacts,
    now: str,
    expected_revision: int,
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
        expected_revision=expected_revision,
        claimed_scope=claimed_scope,
    )


def record_result(
    session: Session,
    actor: ExchangeAuthority,
    *,
    enrollment_id: str,
    facts: HandoffFacts,
    now: str,
    expected_revision: int,
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
        expected_revision=expected_revision,
        claimed_scope=claimed_scope,
    )


def verify_release(
    session: Session,
    actor: ExchangeAuthority,
    *,
    enrollment_id: str,
    release_digest: str,
    now: str,
    expected_revision: int,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _advance_step(
        session,
        actor,
        enrollment_id=enrollment_id,
        step="mark_verified",
        input_payload={"release_digest": release_digest},
        transition=lambda state: mark_verified(state, release_digest=release_digest, now=now),
        expected_revision=expected_revision,
        claimed_scope=claimed_scope,
    )


def mark_enrollment_healthy(
    session: Session,
    actor: ExchangeAuthority,
    *,
    enrollment_id: str,
    now: str,
    expected_revision: int,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    return _advance_step(
        session,
        actor,
        enrollment_id=enrollment_id,
        step="mark_healthy",
        input_payload={},
        transition=lambda state: mark_healthy(state, now=now),
        expected_revision=expected_revision,
        claimed_scope=claimed_scope,
    )


@dataclass(frozen=True)
class ResultExchangeOutcome:
    """The result-exchange result: the final bounded status projection (verified/healthy) and
    whether every step was a deduplicated lost-response retry."""

    status: dict[str, object]
    deduplicated: bool


def _persisted_offer_bindings(session: Session, enrollment_id: str) -> tuple[str, str, str]:
    """Derive the three retry-stable, worker-derivable result bindings from the persisted signed
    offer: the predecessor (the offer's ``sha256:`` content address), the generation (the controller
    signer key id that minted it), and the challenge (the exact offer signature). Together they
    chain the result to THAT exact signed offer, so a result can never be replayed onto a different
    exchange or a re-signed offer. An enrollment with no persisted offer cannot receive a result."""
    persisted = repo.load_signed_offer(session, enrollment_id)
    if persisted is None:
        raise WorkerEnrollmentError(EC.wrong_state)
    try:
        envelope = json.loads(persisted)
        offer_claim = envelope["claim"]
        generation = envelope["attestation"]["key_id"]
        challenge = envelope["attestation"]["signature"]
    except (KeyError, TypeError, ValueError):
        raise WorkerEnrollmentError(EC.state_corrupt) from None
    if not isinstance(offer_claim, dict) or not isinstance(generation, str):
        raise WorkerEnrollmentError(EC.state_corrupt)
    return claim_digest(offer_claim), generation, challenge


def record_worker_result_exchange(
    session: Session,
    *,
    enrollment_id: str,
    worker_public_key_hex: str,
    outcome: str,
    attestation: DetachedAttestation,
    health_evidence: dict[str, bool],
    expected_revision: int,
    now: str,
    claimed_scope: ClaimedScope | None = None,
) -> ResultExchangeOutcome:
    """The supported, evidence-driven result exchange (SECP-PR5H-B1 Phase 3, C1).

    Authenticated by the WORKER'S SIGNED result, not a control-plane OIDC principal (it takes no
    :class:`Principal`). Verifies the SIGNED worker result against the already-bound worker key and
    the authoritative bindings (transaction, release, the persisted offer's content-address/
    generation/challenge, and the ``sha256:`` digest the controller recomputes from the received
    health evidence); then — ONLY because that authenticated evidence attests a successful outcome
    AND every required health check — PRODUCES a :class:`VerifiedEnrollmentExchangeActor` from the
    bound authoritative state and advances result_transported -> verified -> healthy as durable CAS
    transitions under that authority. A lost-response retry re-verifies and dedups every step from
    its receipt (a stale token never conflicts). No endpoint can set verified/healthy from an
    unsigned digest, a release digest alone, or an empty health request: the signature + the
    complete health evidence are the sole authority."""
    _assert_schema_ready(session)
    loaded = _load_for_exchange(session, enrollment_id, claimed_scope)
    state = loaded.state
    if not state.worker_key_id:  # a result requires an already-bound worker
        raise WorkerEnrollmentError(EC.wrong_state)
    invitation = repo.load_invitation_for_update(session, enrollment_id)
    if invitation is None:
        raise WorkerEnrollmentError(EC.invitation_not_found)
    predecessor_digest, generation, challenge = _persisted_offer_bindings(session, enrollment_id)
    health_evidence_digest = sha256_digest(health_evidence)

    # (a) verify the signed worker result — derives the worker key id from the presented public key
    #     and requires it to equal the bound key; rebuilds the claim from authoritative bindings.
    verify_worker_result(
        enrollment_id=enrollment_id,
        controller_transaction_id=state.transaction_id,
        predecessor_digest=predecessor_digest,
        release_digest=state.release_digest,
        outcome=outcome,
        health_evidence_digest=health_evidence_digest,
        generation=generation,
        challenge=challenge,
        bound_worker_key_id=state.worker_key_id,
        worker_public_key_hex=worker_public_key_hex,
        attestation=attestation,
    )
    # (b) verified/healthy derive ONLY from authenticated evidence
    if outcome != WORKER_RESULT_OUTCOME_HEALTHY or not health_evidence_complete(health_evidence):
        raise WorkerEnrollmentError(EC.health_incomplete)

    # (b2) ONLY NOW — after the signed result verified against the bound key + complete evidence —
    #      mint the verified worker-exchange authority from the AUTHORITATIVE bound state.
    actor = VerifiedEnrollmentExchangeActor(
        enrollment_id=enrollment_id,
        organization_id=loaded.organization_id,
        deployment_site_label=loaded.deployment_site_label,
        invitation_id=invitation.invitation_id,
        worker_installation_id=state.worker_installation_id,
        worker_key_id=state.worker_key_id,
        transaction_id=state.transaction_id,
        release_digest=state.release_digest,
        expires_at=invitation.expires_at,
    )

    result_claim = worker_result_claim(
        enrollment_id=enrollment_id,
        controller_transaction_id=state.transaction_id,
        worker_key_id=state.worker_key_id,
        predecessor_digest=predecessor_digest,
        release_digest=state.release_digest,
        outcome=outcome,
        health_evidence_digest=health_evidence_digest,
        generation=generation,
        challenge=challenge,
    )
    result_facts = HandoffFacts(
        kind="worker-result",
        digest=claim_digest(result_claim),
        transaction_id=state.transaction_id,
        signer_key_id=state.worker_key_id,
    )
    # (c) record result -> verified -> healthy (each a durable CAS step; receipts dedup a retry)
    recorded = record_result(
        session,
        actor,
        enrollment_id=enrollment_id,
        facts=result_facts,
        now=now,
        expected_revision=expected_revision,
        claimed_scope=claimed_scope,
    )
    verified = verify_release(
        session,
        actor,
        enrollment_id=enrollment_id,
        release_digest=state.release_digest,
        now=now,
        expected_revision=recorded.committed_revision,
        claimed_scope=claimed_scope,
    )
    healthy = mark_enrollment_healthy(
        session,
        actor,
        enrollment_id=enrollment_id,
        now=now,
        expected_revision=verified.committed_revision,
        claimed_scope=claimed_scope,
    )
    dedup = recorded.deduplicated and verified.deduplicated and healthy.deduplicated
    # C3: return the AUTHORITATIVE CURRENT HEAD, never the (possibly deduped-historical) step state,
    # so a worker reconciling on restart observes a LATER revoke/refusal/recovery rather than a
    # stale ``healthy``. On the fresh path this is the just-committed healthy head.
    head = _load_for_exchange(session, enrollment_id, claimed_scope)
    return ResultExchangeOutcome(status=head.state.public_view(), deduplicated=dedup)


def _advance_step(
    session: Session,
    actor: ExchangeAuthority,
    *,
    enrollment_id: str,
    step: str,
    input_payload: dict[str, object],
    transition: Callable[[EnrollmentState], EnrollmentState],
    expected_revision: int,
    claimed_scope: ClaimedScope | None,
) -> TransitionOutcome:
    _require_progress(actor)
    _assert_schema_ready(session)
    input_digest = _input_digest(step, input_payload)
    loaded = _load_authorized(session, actor, enrollment_id, claimed_scope)

    # exact-retry dedup precedes the expected-revision check (see bind_worker for the rationale)
    served = _serve_receipt(session, loaded, step, input_digest)
    if served is not None:
        return served
    _verify_expected_revision(loaded, expected_revision)

    new_state = _run_pure(lambda: transition(loaded.state))
    if new_state is loaded.state:  # idempotent at-target with a lost receipt
        _ensure_receipt(session, loaded, step, input_digest)
        return TransitionOutcome(loaded.state, loaded.state.revision, deduplicated=True)

    _commit(session, loaded, new_state, step, input_digest)
    _audit_progress(session, actor, enrollment_id, step, new_state)
    return TransitionOutcome(new_state, new_state.revision, deduplicated=False)


#: step -> the bounded, secret-free audit action for a WINNING progression transition.
_PROGRESS_AUDIT: dict[str, AuditAction] = {
    "bind_worker_identity": AuditAction.enrollment_worker_bound,
    "record_controller_offer": AuditAction.enrollment_offer_recorded,
    "record_worker_result": AuditAction.enrollment_result_recorded,
    "mark_verified": AuditAction.enrollment_verified,
    "mark_healthy": AuditAction.enrollment_healthy,
}


def _audit_progress(
    session: Session,
    actor: ExchangeAuthority,
    enrollment_id: str,
    step: str,
    state: EnrollmentState,
) -> None:
    """One bounded, secret-free audit per WINNING progression transition — org, actor, action,
    enrollment id, resulting state and revision. The ``actor`` is a Principal's user id or (on the
    supported worker path) a bounded code-owned worker fingerprint — never caller free-text, a
    nonce, key, handoff byte or path."""
    audit.record(
        session,
        action=_PROGRESS_AUDIT[step],
        resource_type="worker_enrollment",
        resource_id=enrollment_id,
        actor=_audit_actor(actor),
        organization_id=actor.organization_id,
        outcome="success",
        data={"state": state.state, "revision": state.revision},
    )


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


#: The bounded reason code recorded when an OPERATOR marks an enrollment recovery-required. Distinct
#: from the sweep's ``expiry_recovery``, so an operator decision and an automatic expiry are always
#: distinguishable in the durable record.
_OPERATOR_RECOVERY_REASON = "operator_recovery_required"


def mark_recovery_required(
    session: Session,
    actor: Principal,
    *,
    enrollment_id: str,
    expected_revision: int,
    claimed_scope: ClaimedScope | None = None,
) -> TransitionOutcome:
    """Operator-triggered recovery: drive an enrollment to the ``recovery_required`` terminal.

    The complement of the scheduled expiry sweep. The sweep reaches enrollments that ran out of
    time; this reaches one an operator has decided is stuck — a worker that will never bind, a site
    that was decommissioned mid-enrollment — without waiting for the TTL.

    Shaped exactly like :func:`revoke_enrollment`, deliberately: it requires ``enrollment_manage``
    (enforced here, not only in the router), enforces the organization boundary against the
    authoritative persisted row, and takes ONLY the caller's last-observed ``expected_revision``.
    The durable CAS coordinates are derived server-side from the loaded state and never cross the
    public boundary.

    **Idempotent**: an already-terminal enrollment returns its state with no write and no new audit.
    A stale ``expected_revision`` on a live enrollment refuses ``revision_conflict``; concurrent
    callers collide on the head CAS so exactly one wins. Exactly one bounded, secret-free audit
    event is recorded, and only for the winning transition. Does NOT commit — the caller owns the
    transaction boundary.
    """
    actor.require(Permission.enrollment_manage)
    _assert_schema_ready(session)
    loaded = _load_authorized(session, actor, enrollment_id, claimed_scope)
    state = loaded.state
    if state.state in (REFUSED, RECOVERY_REQUIRED):
        return TransitionOutcome(state, state.revision, deduplicated=True)  # already terminal
    if state.revision != expected_revision:
        raise WorkerEnrollmentError(EC.revision_conflict)
    new_state = _run_pure(lambda: require_recovery(state, _OPERATOR_RECOVERY_REASON))
    if new_state is state:  # defensive: the contract treated it as a no-op
        return TransitionOutcome(state, state.revision, deduplicated=True)
    _commit(session, loaded, new_state, step=None, input_digest=None)
    audit.record(
        session,
        action=AuditAction.enrollment_recovery_required,
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
    # Operator lifecycle transitions are MANAGE operations, and the check lives HERE so it cannot be
    # bypassed by a direct service call or by a future router that forgets it. Without this, refuse
    # / recover would have been authorized by the organization boundary ALONE — every other
    # state-changing operation on this service (revoke, create, the progression steps) requires an
    # explicit permission, and these two were the exception.
    actor.require(Permission.enrollment_manage)
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


# --------------------------------------------------------------- org-scoped inventory listing (R1)

#: The default page size when the caller does not ask for one.
DEFAULT_LIST_LIMIT: Final = 50

#: The hard, code-owned server-side ceiling on one page. Re-applied HERE as well as in the router
#: and the repository, so a direct service call can never exceed it either.
MAX_LIST_LIMIT: Final = repo.MAX_LIST_PAGE

#: The cursor is an opaque url-safe base64 blob over
#: ``"<canonical utc>|<enrollment id>|<filter digest>"``. Every part is re-validated on decode, and
#: a decoded cursor is only ever used as a keyset position WITHIN the caller's own
#: organization-scoped query — so a forged or replayed cursor can at worst skip the caller past
#: their own rows, never reach another organization's.
_CURSOR_SEPARATOR: Final = "|"
_MAX_CURSOR_LEN: Final = 256

#: The sentinel filter digest for "no state filter" — distinct from any real digest.
_NO_FILTER: Final = "all"


def _filter_digest(states: tuple[str, ...] | None) -> str:
    """A short, stable digest of the CANONICALISED state filter a cursor was minted under.

    A keyset cursor is only meaningful within the filtered order that produced it. Replaying a
    cursor from one filter against another silently skips every row the new filter matches that
    sorts before the old cursor's position — a short page that looks exactly like a genuinely short
    page. Binding the filter in turns that silent wrong answer into a bounded refusal.

    Canonicalised (sorted, de-duplicated) so a caller reordering ``?state=`` parameters, or
    repeating one, still gets a cursor that matches — the filter is a set, and its digest must
    behave like one.
    """
    if not states:
        return _NO_FILTER
    joined = ",".join(sorted(set(states)))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _encode_cursor(expires_at: str, enrollment_id: str, states: tuple[str, ...] | None) -> str:
    raw = _CURSOR_SEPARATOR.join((expires_at, enrollment_id, _filter_digest(states)))
    return base64.urlsafe_b64encode(raw.encode()).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str, states: tuple[str, ...] | None) -> tuple[_dt.datetime, str]:
    """Decode an opaque cursor to its ``(expires_at_ts, enrollment_id)`` keyset position.

    Refuses when the cursor was minted under a DIFFERENT state filter than the request presenting
    it. Every failure — malformed, over-long, non-decoding, or filter-mismatched — is the SAME
    bounded ``enrollment_cursor_invalid``: the rejected value is never echoed, the filter it was
    minted under is never echoed, and a bad cursor is never allowed to degrade into a silently
    incomplete page or an unfiltered scan.
    """
    if not isinstance(cursor, str) or not (1 <= len(cursor) <= _MAX_CURSOR_LEN):
        raise WorkerEnrollmentError(EC.cursor_invalid)
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise WorkerEnrollmentError(EC.cursor_invalid) from None
    parts = raw.split(_CURSOR_SEPARATOR)
    if len(parts) != 3:
        raise WorkerEnrollmentError(EC.cursor_invalid)
    head, enrollment_id, bound_filter = parts
    expires_ts = repo.parse_canonical_utc(head)
    if expires_ts is None or not is_sha256_digest(enrollment_id):
        raise WorkerEnrollmentError(EC.cursor_invalid)
    if bound_filter != _filter_digest(states):
        # a position carried across filters would silently omit matching rows — refuse, never serve
        raise WorkerEnrollmentError(EC.cursor_invalid)
    return expires_ts, enrollment_id


def _validated_states(states: tuple[str, ...] | None) -> tuple[str, ...] | None:
    """Reduce the requested filter to a closed-set tuple, or None for "every state".

    An unknown state name is refused rather than ignored: silently dropping it would return a page
    the operator did not ask for. Duplicates collapse; the caller's order is irrelevant because the
    filter is a set membership test, not a sort key.
    """
    if states is None:
        return None
    unique = tuple(sorted({state for state in states}))
    if not unique:
        return None
    if any(state not in ALL_STATES for state in unique):
        raise WorkerEnrollmentError(EC.state_invalid)
    return unique


def list_public_views(
    session: Session,
    actor: Principal,
    *,
    states: tuple[str, ...] | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    after: str | None = None,
) -> tuple[list[dict[str, object]], str | None]:
    """One org-scoped page of bounded, secret-free status projections + the next opaque cursor.

    Authorization is the organization boundary and nothing else: the query is filtered in SQL by the
    authenticated principal's own organization, and every loaded row is INDEPENDENTLY re-checked
    with :meth:`Principal.require_org` — never a raw id comparison — so a repository change that
    dropped the SQL filter would fail closed here rather than leaking another tenant's inventory.

    ``enrollment:read`` is required, enforced HERE so a direct service call cannot bypass RBAC.
    ``enrollment:manage`` does NOT imply it (pinned decision: strict read/manage separation).

    NO invitation material is returned — only :meth:`EnrollmentState.public_view`. Unlike the expiry
    sweep's candidate query, the page includes revoked, terminal and healthy enrollments.

    ``next_cursor`` is a WEAK signal, deliberately: it is non-null whenever this page came back
    FULL, which includes the case where the page behind it turns out to be empty. It means "there
    MAY be more", never "there certainly is". A caller must page until it comes back null rather
    than treating a non-null value as proof of a further page. (Same rule the recovery sweep uses
    for its own keyset continuation.)

    A row that cannot be projected raises the DISTINCT ``enrollment_page_integrity`` — "this page
    contains a row I cannot render", not "this one enrollment is corrupt" — carrying an opaque
    ``recovery_cursor`` so the caller can page PAST it and still reach the rest of the inventory.
    """
    actor.require(Permission.enrollment_read)
    _assert_schema_ready(session)
    bounded_limit = max(1, min(int(limit), MAX_LIST_LIMIT))
    selected = _validated_states(states)
    cursor = _decode_cursor(after, selected) if after is not None else None

    try:
        page = repo.load_page(
            session,
            organization_id=actor.organization_id,
            states=selected,
            limit=bounded_limit,
            after=cursor,
        )
    except repo.PageIntegrityRefusal as exc:
        # The row is preserved, never repaired, and never silently dropped. Two things happen:
        # (1) the failing enrollment id is recorded SERVER-SIDE so the condition is diagnosable at
        #     all — it is org-scoped and audited, never returned as free text or logged bare;
        # (2) the caller gets an opaque cursor positioned AT the failing row, bound to the SAME
        #     state filter, so `after=<recovery_cursor>` steps past it. Without this, every
        #     enrollment ordered after a poison row is permanently unreachable from the list.
        _audit_page_integrity(session, actor, exc)
        raise WorkerEnrollmentError(
            EC.page_integrity,
            # the audit row above must SURVIVE this failed request — ``db_session`` would otherwise
            # roll it back, and an audit entry that only exists on the happy path is no audit at all
            durable_transition=True,
            recovery_cursor=_encode_cursor(exc.expires_at, exc.enrollment_id, selected),
        ) from None
    except RepositoryRefusal as exc:  # a corrupt row is preserved, never surfaced, never repaired
        raise _surface(exc) from None

    items: list[dict[str, object]] = []
    for loaded in page:
        # organization is the ONLY authorization boundary — re-proven per row against the
        # authoritative binding, independently of the SQL filter that selected it
        actor.require_org(loaded.organization_id)
        try:
            items.append(loaded.state.public_view())
        except WorkerEnrollmentError:
            raise
        except Exception:  # noqa: BLE001 - a projection failure must not escape unbounded
            raise WorkerEnrollmentError(EC.state_corrupt) from None

    next_cursor = None
    if len(page) == bounded_limit and page:
        last = page[-1].state
        next_cursor = _encode_cursor(last.expires_at, last.enrollment_id, selected)
    return items, next_cursor


def _audit_page_integrity(
    session: Session, actor: Principal, exc: repo.PageIntegrityRefusal
) -> None:
    """Record WHICH row could not be projected, server-side, so the condition is diagnosable.

    The enrollment id appears here and nowhere else on this path: the audit row is organization-
    scoped and durable, whereas a bare log line is neither. ``reason`` is the bounded repository
    code, never free text. Auditing must never convert a bounded refusal into an unbounded one, so
    a failure to record is swallowed — the caller still gets the page-integrity refusal.
    """
    try:
        audit.record(
            session,
            action=AuditAction.enrollment_page_integrity_failed,
            resource_type="worker_enrollment",
            resource_id=exc.enrollment_id,
            actor=str(actor.user_id),
            organization_id=actor.organization_id,
            outcome="failure",
            data={"reason": exc.reason_code},
        )
    except Exception:  # noqa: BLE001 - never let auditing mask or replace the bounded refusal
        pass


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
    "DEFAULT_LIST_LIMIT",
    "MAX_LIST_LIMIT",
    "ClaimedScope",
    "ExchangeOutcome",
    "ExpectedRevision",
    "ResultExchangeOutcome",
    "TransitionOutcome",
    "VerifiedEnrollmentExchangeActor",
    "bind_worker",
    "bind_worker_exchange",
    "create_invitation_and_open",
    "list_public_views",
    "load_public_view",
    "mark_recovery_required",
    "mark_enrollment_healthy",
    "recover_enrollment",
    "record_offer",
    "record_result",
    "record_worker_result_exchange",
    "refuse_enrollment",
    "verify_release",
]
