"""Durable worker-enrollment state machine + signed-handoff binding contracts (SECP-PR5G).

The management plane automates the PR5F controller-offer / worker-result handoff so an administrator
never hand-copies files between hosts.  This module owns the *provider-neutral* enrollment domain:

* :class:`WorkerEnrollmentInvitation` — a short-lived, single-use, content-addressed, **non-secret**
  invitation the controller issues (browser-displayable / downloadable).  It binds the controller
  installation identity, HTTPS origin, pinned trust anchor, release digest, transaction, nonce and
  expiry — and carries **no** provider (Proxmox/K8s/cloud) field, host path, private key, or secret.
* :class:`EnrollmentState` — the durable state machine
  ``invited → worker_bound → offer_transported → result_transported → verified → healthy`` with
  explicit ``refused`` / ``recovery_required`` terminals.  Every transition is revision-guarded,
  sequence/predecessor-chained, transaction-bound, expiring, single-use and replay-refusing; an
  retry is idempotent, a conflicting or stale message refuses closed.
* the signed handoff is verified at an injectable :class:`HandoffVerifier` boundary whose default
  reuses the PR5F ``verify_handoff`` over the canonical ``ControllerOffer`` / ``WorkerResult``
  records **verbatim** (bytes/signatures never altered); the state machine binds only the
  :class:`HandoffFacts` (digest + transaction + signer key id).
* the actual network exchange is an :class:`EnrollmentTransport` whose shipped default is **sealed**
  (``enrollment_transport_not_activated``) — the socket-level worker→controller HTTPS is SECP-PR5H.

Everything here is pure/deterministic and hermetically testable: it opens no socket, spawns no
process, constructs no Temporal worker, submits no workflow, runs no OpenTofu, and contacts no
provider or infrastructure.  Timestamps are passed in by the caller (never read from a clock).
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, replace
from typing import Protocol

from secp_commissioning.canonical import is_sha256_digest, sha256_digest
from secp_commissioning.descriptor import scan_forbidden

from secp_management import ManagementError

ENROLLMENT_CONTRACT_VERSION = "secp.management-enrollment/v1alpha1"
_INVITATION_SCHEMA = "secp.management.worker-enrollment-invitation/v1"
_STATE_SCHEMA = "secp.management.enrollment-state/v1"

# Bounded, code-owned limits (never deployment knobs).
_MAX_TTL_SECONDS = 24 * 3600
_MIN_TTL_SECONDS = 1
_MAX_FIELD_LEN = 512
_MAX_ORIGIN_LEN = 253 + 16
_HEX64 = re.compile(r"[0-9a-f]{64}")
_INSTALLATION_ID = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")
_HTTPS_ORIGIN = re.compile(r"https://[a-z0-9.-]{1,253}(?::[1-9][0-9]{0,4})?")

# The closed, ordered enrollment states.
INVITED = "invited"
WORKER_BOUND = "worker_bound"
OFFER_TRANSPORTED = "offer_transported"
RESULT_TRANSPORTED = "result_transported"
VERIFIED = "verified"
HEALTHY = "healthy"
REFUSED = "refused"
RECOVERY_REQUIRED = "recovery_required"

# forward edge -> the exact predecessor state it requires
_ADVANCE = {
    WORKER_BOUND: INVITED,
    OFFER_TRANSPORTED: WORKER_BOUND,
    RESULT_TRANSPORTED: OFFER_TRANSPORTED,
    VERIFIED: RESULT_TRANSPORTED,
    HEALTHY: VERIFIED,
}
_ACTIVE = (INVITED, WORKER_BOUND, OFFER_TRANSPORTED, RESULT_TRANSPORTED, VERIFIED)


def _closed(reason: str) -> ManagementError:
    return ManagementError(reason)


def _parse_ts(value: object, reason: str) -> _dt.datetime:
    if not isinstance(value, str) or not (1 <= len(value) <= 64):
        raise _closed(reason)
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _closed(reason) from None
    if parsed.tzinfo is None or parsed.utcoffset() != _dt.timedelta(0):
        raise _closed(reason)  # UTC-only, explicit offset
    return parsed


def _short_field(value: object, reason: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not (1 <= len(value) <= _MAX_FIELD_LEN):
        raise _closed(reason)
    if pattern is not None and not pattern.fullmatch(value):
        raise _closed(reason)
    return value


# A refusal/recovery reason is a bounded lowercase snake_case CODE, never free-form prose: it cannot
# contain a '/', ':', '.', space, or uppercase, so no host path, endpoint, IP, or secret can ride
# into refusal_reason and out through public_view (which surfaces it).
_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _reason_code(reason: str) -> str:
    return _short_field(reason, "enrollment_reason_code_invalid", pattern=_REASON_CODE)


# --------------------------------------------------------------------------- invitation contract


@dataclass(frozen=True)
class WorkerEnrollmentInvitation:
    """A short-lived, single-use, non-secret worker-enrollment invitation from the controller."""

    contract_version: str
    invitation_id: str  # single-use nonce (sha256 digest)
    controller_installation_id: str
    controller_key_id: str  # sha256 of the controller Ed25519 public key
    controller_trust_anchor_hex: str  # the controller public key (hex) the worker pins
    controller_origin: str  # exact HTTPS origin the worker connects OUTBOUND to
    release_digest: str  # the signed release the worker must enroll under
    transaction_id: str
    sequence: int
    created_at: str
    expires_at: str

    def canonical(self) -> dict[str, object]:
        return {
            "schema": _INVITATION_SCHEMA,
            "contract_version": self.contract_version,
            "invitation_id": self.invitation_id,
            "controller_installation_id": self.controller_installation_id,
            "controller_key_id": self.controller_key_id,
            "controller_trust_anchor_hex": self.controller_trust_anchor_hex,
            "controller_origin": self.controller_origin,
            "release_digest": self.release_digest,
            "transaction_id": self.transaction_id,
            "sequence": self.sequence,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def digest(self) -> str:
        return sha256_digest(self.canonical())

    def validate(self) -> None:
        if self.contract_version != ENROLLMENT_CONTRACT_VERSION:
            raise _closed("enrollment_invitation_invalid")
        if not is_sha256_digest(self.invitation_id):
            raise _closed("enrollment_invitation_invalid")
        _short_field(
            self.controller_installation_id,
            "enrollment_invitation_invalid",
            pattern=_INSTALLATION_ID,
        )
        if not is_sha256_digest(self.controller_key_id):
            raise _closed("enrollment_invitation_invalid")
        if not _HEX64.fullmatch(self.controller_trust_anchor_hex):
            raise _closed("enrollment_trust_anchor_invalid")
        # the pinned public key must derive the pinned key id (no free-floating trust anchor)
        if sha256_digest_of_hex(self.controller_trust_anchor_hex) != self.controller_key_id:
            raise _closed("enrollment_trust_anchor_invalid")
        if len(self.controller_origin) > _MAX_ORIGIN_LEN or not _HTTPS_ORIGIN.fullmatch(
            self.controller_origin
        ):
            raise _closed("enrollment_origin_not_https")
        if not is_sha256_digest(self.release_digest):
            raise _closed("enrollment_invitation_invalid")
        _short_field(self.transaction_id, "enrollment_invitation_invalid")
        if not isinstance(self.sequence, int) or self.sequence != 0:
            raise _closed("enrollment_invitation_invalid")
        created = _parse_ts(self.created_at, "enrollment_invitation_invalid")
        expires = _parse_ts(self.expires_at, "enrollment_invitation_invalid")
        ttl = (expires - created).total_seconds()
        if not (_MIN_TTL_SECONDS <= ttl <= _MAX_TTL_SECONDS):
            raise _closed("enrollment_invitation_invalid")
        scan_forbidden(self.canonical())  # non-secret: no secret-like field name/value at any depth

    def assert_fresh(self, now: str) -> None:
        if _parse_ts(now, "enrollment_time_invalid") >= _parse_ts(
            self.expires_at, "enrollment_invitation_invalid"
        ):
            raise _closed("enrollment_invitation_expired")


def sha256_digest_of_hex(hex_value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(bytes.fromhex(hex_value)).hexdigest()


def create_invitation(
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
    """Create + validate a controller worker-enrollment invitation.  ``nonce`` is a caller-provided
    single-use sha256 value (the invitation id); the caller derives it from a secure random source —
    this module never reads a clock or a random source, so it stays deterministic and testable."""
    invitation = WorkerEnrollmentInvitation(
        contract_version=ENROLLMENT_CONTRACT_VERSION,
        invitation_id=nonce,
        controller_installation_id=controller_installation_id,
        controller_key_id=controller_key_id,
        controller_trust_anchor_hex=controller_trust_anchor_hex,
        controller_origin=controller_origin,
        release_digest=release_digest,
        transaction_id=transaction_id,
        sequence=0,
        created_at=created_at,
        expires_at=expires_at,
    )
    invitation.validate()
    return invitation


# --------------------------------------------------------------------------- signed-handoff binding


@dataclass(frozen=True)
class HandoffFacts:
    """The exact facts bound from a verified signed handoff record (never the record bytes)."""

    kind: str  # "controller-offer" | "worker-result"
    digest: str
    transaction_id: str
    signer_key_id: str


class HandoffVerifier(Protocol):
    """Verifies a canonical handoff record + attestation against a pinned signer key id and returns
    the bound facts.  The default reuses the PR5F ``verify_handoff`` over the real records."""

    def verify_controller_offer(
        self, record: object, attestation: object, *, key_id: str
    ) -> str: ...
    def verify_worker_result(self, record: object, attestation: object, *, key_id: str) -> str: ...


def bind_controller_offer(
    record: object, attestation: object, *, expected_key_id: str, verifier: HandoffVerifier
) -> HandoffFacts:
    if not is_sha256_digest(expected_key_id):
        raise _closed("enrollment_controller_mismatch")
    transaction_id = verifier.verify_controller_offer(record, attestation, key_id=expected_key_id)
    return HandoffFacts(
        kind="controller-offer",
        digest=_record_digest(record),
        transaction_id=_short_field(transaction_id, "enrollment_handoff_invalid"),
        signer_key_id=expected_key_id,
    )


def bind_worker_result(
    record: object, attestation: object, *, expected_key_id: str, verifier: HandoffVerifier
) -> HandoffFacts:
    if not is_sha256_digest(expected_key_id):
        raise _closed("enrollment_worker_mismatch")
    transaction_id = verifier.verify_worker_result(record, attestation, key_id=expected_key_id)
    return HandoffFacts(
        kind="worker-result",
        digest=_record_digest(record),
        transaction_id=_short_field(transaction_id, "enrollment_handoff_invalid"),
        signer_key_id=expected_key_id,
    )


def _record_digest(record: object) -> str:
    digest = getattr(record, "digest", None)
    value = digest() if callable(digest) else None
    if not is_sha256_digest(value):
        raise _closed("enrollment_handoff_invalid")
    return value  # type: ignore[return-value]


# --------------------------------------------------------------------------- enrollment state


@dataclass(frozen=True)
class EnrollmentState:
    """One durable, content-addressed enrollment record.  ``predecessor_digest`` chains a revision
    to the previous state's digest, so a persisted state's revision history is tamper-evident and a
    stale/replayed transition is detectable."""

    contract_version: str
    enrollment_id: str  # == the invitation digest
    state: str
    revision: int
    sequence: int
    predecessor_digest: str
    controller_installation_id: str
    controller_key_id: str
    worker_installation_id: str
    worker_key_id: str
    release_digest: str
    transaction_id: str
    offer_digest: str
    result_digest: str
    expires_at: str
    updated_at: str
    refusal_reason: str

    def canonical(self) -> dict[str, object]:
        return {
            "schema": _STATE_SCHEMA,
            "contract_version": self.contract_version,
            "enrollment_id": self.enrollment_id,
            "state": self.state,
            "revision": self.revision,
            "sequence": self.sequence,
            "predecessor_digest": self.predecessor_digest,
            "controller_installation_id": self.controller_installation_id,
            "controller_key_id": self.controller_key_id,
            "worker_installation_id": self.worker_installation_id,
            "worker_key_id": self.worker_key_id,
            "release_digest": self.release_digest,
            "transaction_id": self.transaction_id,
            "offer_digest": self.offer_digest,
            "result_digest": self.result_digest,
            "expires_at": self.expires_at,
            "updated_at": self.updated_at,
            "refusal_reason": self.refusal_reason,
        }

    def digest(self) -> str:
        return sha256_digest(self.canonical())

    def public_view(self) -> dict[str, object]:
        """A bounded, non-secret projection for status/browser surfaces — identities are shown by
        their short key-id/digest fingerprints only; no key material, path, or secret is exposed."""
        view = {
            "enrollment_id": self.enrollment_id,
            "state": self.state,
            "revision": self.revision,
            "controller_installation_id": self.controller_installation_id,
            "controller_key_fingerprint": _fingerprint(self.controller_key_id),
            "worker_installation_id": self.worker_installation_id,
            "worker_key_fingerprint": _fingerprint(self.worker_key_id),
            "release_fingerprint": _fingerprint(self.release_digest),
            "offer_fingerprint": _fingerprint(self.offer_digest),
            "result_fingerprint": _fingerprint(self.result_digest),
            "expires_at": self.expires_at,
            "updated_at": self.updated_at,
            "refusal_reason": self.refusal_reason,
        }
        scan_forbidden(view)
        return view


def _fingerprint(value: str) -> str:
    # a short, non-reversible display fingerprint of a digest/key id (never the full secret-bearing
    # value; a full content digest is not a public oracle here because these are public identities).
    if not value:
        return ""
    tail = value.split(":", 1)[-1]
    return tail[:12] if _HEX64.fullmatch(tail) or len(tail) >= 12 else ""


def open_enrollment(invitation: WorkerEnrollmentInvitation, *, now: str) -> EnrollmentState:
    invitation.validate()
    invitation.assert_fresh(now)
    _parse_ts(now, "enrollment_time_invalid")
    return EnrollmentState(
        contract_version=ENROLLMENT_CONTRACT_VERSION,
        enrollment_id=invitation.digest(),
        state=INVITED,
        revision=0,
        sequence=0,
        predecessor_digest="",
        controller_installation_id=invitation.controller_installation_id,
        controller_key_id=invitation.controller_key_id,
        worker_installation_id="",
        worker_key_id="",
        release_digest=invitation.release_digest,
        transaction_id=invitation.transaction_id,
        offer_digest="",
        result_digest="",
        expires_at=invitation.expires_at,
        updated_at=now,
        refusal_reason="",
    )


def _advance(
    state: EnrollmentState, target: str, *, now: str, **changes: object
) -> EnrollmentState:
    if state.state not in _ACTIVE:
        raise _closed("enrollment_wrong_state")
    if state.state != _ADVANCE[target]:
        raise _closed("enrollment_wrong_state")
    if _parse_ts(now, "enrollment_time_invalid") >= _parse_ts(
        state.expires_at, "enrollment_state_invalid"
    ):
        raise _closed("enrollment_expired")
    return replace(
        state,
        state=target,
        revision=state.revision + 1,
        sequence=state.sequence + 1,
        predecessor_digest=state.digest(),
        updated_at=now,
        refusal_reason="",
        **changes,  # type: ignore[arg-type]
    )


def bind_worker_identity(
    state: EnrollmentState,
    *,
    worker_installation_id: str,
    worker_key_id: str,
    transaction_id: str,
    now: str,
) -> EnrollmentState:
    _short_field(worker_installation_id, "enrollment_worker_mismatch", pattern=_INSTALLATION_ID)
    if not is_sha256_digest(worker_key_id):
        raise _closed("enrollment_worker_mismatch")
    if transaction_id != state.transaction_id:
        raise _closed("enrollment_transaction_mismatch")
    if worker_installation_id == state.controller_installation_id:
        raise _closed(
            "enrollment_installation_mismatch"
        )  # controller cannot enrol as its own worker
    # idempotent EXACT retry
    if state.state == WORKER_BOUND:
        if (
            state.worker_installation_id == worker_installation_id
            and state.worker_key_id == worker_key_id
        ):
            return state
        raise _closed("enrollment_already_bound")  # single-use: a different worker cannot rebind
    return _advance(
        state,
        WORKER_BOUND,
        now=now,
        worker_installation_id=worker_installation_id,
        worker_key_id=worker_key_id,
    )


def record_controller_offer(
    state: EnrollmentState, facts: HandoffFacts, *, now: str
) -> EnrollmentState:
    if facts.kind != "controller-offer":
        raise _closed("enrollment_handoff_invalid")
    if facts.signer_key_id != state.controller_key_id:
        raise _closed("enrollment_controller_mismatch")
    if facts.transaction_id != state.transaction_id:
        raise _closed("enrollment_transaction_mismatch")
    if state.state == OFFER_TRANSPORTED:
        if state.offer_digest == facts.digest:
            return state  # idempotent exact retry
        raise _closed(
            "enrollment_replay"
        )  # a different offer for the same step is a replay/conflict
    return _advance(state, OFFER_TRANSPORTED, now=now, offer_digest=facts.digest)


def record_worker_result(
    state: EnrollmentState, facts: HandoffFacts, *, now: str
) -> EnrollmentState:
    if facts.kind != "worker-result":
        raise _closed("enrollment_handoff_invalid")
    if facts.signer_key_id != state.worker_key_id:
        raise _closed("enrollment_worker_mismatch")
    if facts.transaction_id != state.transaction_id:
        raise _closed("enrollment_transaction_mismatch")
    if state.state == RESULT_TRANSPORTED:
        if state.result_digest == facts.digest:
            return state  # idempotent exact retry
        raise _closed("enrollment_replay")
    return _advance(state, RESULT_TRANSPORTED, now=now, result_digest=facts.digest)


def mark_verified(state: EnrollmentState, *, release_digest: str, now: str) -> EnrollmentState:
    if release_digest != state.release_digest:
        raise _closed("enrollment_release_mismatch")
    if state.state == VERIFIED:
        return state  # idempotent
    return _advance(state, VERIFIED, now=now)


def mark_healthy(state: EnrollmentState, *, now: str) -> EnrollmentState:
    if state.state == HEALTHY:
        return state  # idempotent terminal-success retry
    return _advance(state, HEALTHY, now=now)


def refuse(state: EnrollmentState, reason: str) -> EnrollmentState:
    _reason_code(reason)
    if state.state in (REFUSED, RECOVERY_REQUIRED):
        return state
    return replace(
        state,
        state=REFUSED,
        revision=state.revision + 1,
        predecessor_digest=state.digest(),
        refusal_reason=reason,
    )


def require_recovery(state: EnrollmentState, reason: str) -> EnrollmentState:
    _reason_code(reason)
    if state.state == RECOVERY_REQUIRED:
        return state
    return replace(
        state,
        state=RECOVERY_REQUIRED,
        revision=state.revision + 1,
        predecessor_digest=state.digest(),
        refusal_reason=reason,
    )


# ----------------------------------------------------------------------- sealed network transport


class EnrollmentTransport(Protocol):
    """The worker→controller outbound HTTPS exchange that carries the signed handoff records.  The
    shipped default is sealed; the socket-level protocol is SECP-PR5H (see ADR-026)."""

    def deliver_controller_offer(self, *, enrollment_id: str, payload: bytes) -> bytes: ...
    def retrieve_worker_result(self, *, enrollment_id: str) -> bytes: ...


class SealedEnrollmentTransport:
    """No network transport is activated in this PR; every exchange fails closed."""

    def deliver_controller_offer(self, *, enrollment_id: str, payload: bytes) -> bytes:
        raise _closed("enrollment_transport_not_activated")

    def retrieve_worker_result(self, *, enrollment_id: str) -> bytes:
        raise _closed("enrollment_transport_not_activated")


# ----------------------------------------------------------------------- default handoff verifier


def default_handoff_verifier() -> HandoffVerifier:
    """The production verifier reuses PR5F ``verify_handoff`` over the real ``ControllerOffer`` /
    ``WorkerResult`` records verbatim; imported lazily so this module has no hard dependency on the
    discovery-activation package when only the state machine is exercised."""

    from secp_discovery_activation.handoff import (
        ControllerOffer,
        WorkerResult,
        verify_handoff,
    )

    def _verify(record: object, attestation: object, *, key_id: str, expected_type: type) -> str:
        if type(record) is not expected_type:
            raise _closed("enrollment_handoff_invalid")
        verify_handoff(record, attestation, expected_key_id=key_id)  # type: ignore[arg-type]
        return str(getattr(record, "transaction_id"))  # noqa: B009 - dynamic attr on a verified record

    class _DiscoveryHandoffVerifier:
        def verify_controller_offer(
            self, record: object, attestation: object, *, key_id: str
        ) -> str:
            return _verify(record, attestation, key_id=key_id, expected_type=ControllerOffer)

        def verify_worker_result(self, record: object, attestation: object, *, key_id: str) -> str:
            return _verify(record, attestation, key_id=key_id, expected_type=WorkerResult)

    return _DiscoveryHandoffVerifier()


__all__ = [
    "ENROLLMENT_CONTRACT_VERSION",
    "WorkerEnrollmentInvitation",
    "create_invitation",
    "HandoffFacts",
    "HandoffVerifier",
    "bind_controller_offer",
    "bind_worker_result",
    "EnrollmentState",
    "open_enrollment",
    "bind_worker_identity",
    "record_controller_offer",
    "record_worker_result",
    "mark_verified",
    "mark_healthy",
    "refuse",
    "require_recovery",
    "EnrollmentTransport",
    "SealedEnrollmentTransport",
    "default_handoff_verifier",
    "sha256_digest_of_hex",
    "INVITED",
    "WORKER_BOUND",
    "OFFER_TRANSPORTED",
    "RESULT_TRANSPORTED",
    "VERIFIED",
    "HEALTHY",
    "REFUSED",
    "RECOVERY_REQUIRED",
]
