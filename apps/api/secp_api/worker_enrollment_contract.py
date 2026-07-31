"""API-side mirror of the pure worker-enrollment transition contract (SECP-PR5H-A, ADR-027).

**Why this file exists.** The reviewed plane boundary forbids ``apps/api/secp_api`` from importing
any ``secp_management`` module, and that boundary is NOT weakened for enrollment: there is no
allowlist entry for ``secp_management.enrollment``.  The control-plane persistence service still
needs the exact transition semantics, so this module mirrors — narrowly and purely — only what the
API needs, exactly as the five existing ``*_contract.py`` precedents do.

**Scope.** Contract/schema versions, closed state names, permitted transitions, canonical field
ordering, bounded field grammar + validation, canonical serialization, digest derivation,
exact-retry semantics, bounded refusal/recovery reason codes, and the safe public projection.

It deliberately contains NO persistence, SQLAlchemy, network/HTTP, transport, filesystem,
host-adapter, systemd, Docker/Compose, subprocess, provider/IaC/workflow, key-loading, signing, or
any other privileged behavior.  Duplication is permitted ONLY to preserve the boundary; it is not
licence to duplicate privileged management behavior.

**Parity.** ``tests/test_worker_enrollment_contract_parity.py`` imports BOTH implementations (only
the test layer may) and requires, over a deterministic corpus, either byte-identical canonical
output AND digest, or refusal with the SAME bounded reason code.  The canonical/digest rule and the
secret-scan are physically SHARED (both sides import them from the pure ``secp_commissioning``
helpers), so serialization and redaction cannot drift; the corpus proves the semantics.  Any future
contract edit must update both copies and the corpus together or CI fails closed.

**Authority.** ``apps/management/secp_management/enrollment.py`` stays authoritative for semantics.
A discrepancy is a defect to be reported and proven — never silently "fixed" here to simplify the
mirror.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress as _ipaddress
import re
from dataclasses import dataclass, replace

from secp_commissioning.canonical import is_sha256_digest, sha256_digest
from secp_commissioning.descriptor import scan_forbidden

ENROLLMENT_CONTRACT_VERSION = "secp.management-enrollment/v1alpha1"
INVITATION_SCHEMA = "secp.management.worker-enrollment-invitation/v1"
STATE_SCHEMA = "secp.management.enrollment-state/v1"

# Bounded, code-owned limits (never deployment knobs).
MAX_TTL_SECONDS = 24 * 3600
MIN_TTL_SECONDS = 1
MAX_FIELD_LEN = 512
MAX_ORIGIN_LEN = 253 + 16
#: The maximum canonical timestamp string length.  It MUST equal the width of the VARCHAR(40)
#: ``created_at`` / ``expires_at`` / ``updated_at`` columns: the pure parser once accepted up to 64
#: characters, so a long fractional-second timestamp both planes accepted then failed on PostgreSQL
#: persistence.  ``tests/test_pr5h_schema_parity.py`` pins this to the real column widths.
MAX_TS_LEN = 40
_HEX64 = re.compile(r"[0-9a-f]{64}")
_INSTALLATION_ID = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")
_HTTPS_ORIGIN = re.compile(r"https://[a-z0-9.-]{1,253}(?::[1-9][0-9]{0,4})?")

# A refusal/recovery reason is a bounded lowercase snake_case CODE, never free-form prose: it cannot
# contain '/', ':', '.', space or uppercase, so no host path, endpoint, IP or secret can ride into
# refusal_reason and out through public_view (which surfaces it).
_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")

#: An opaque deployment-site grouping label (ADR-027).  Organization remains the ONLY authorization
#: boundary; this is a grouping/binding label that is never *interpreted* as a tenant, address,
#: region, endpoint or provider.  The grammar forbids '/', ':', '@' and whitespace (so no URL, path
#: or scheme), and :func:`is_deployment_site_label` additionally rejects every IP-address literal;
#: a string that merely LOOKS like a provider/region/hostname is permitted but carries no meaning.
#: It is deliberately NOT part of the canonical contract, so it can never affect a digest.
DEPLOYMENT_SITE_LABEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$"
_DEPLOYMENT_SITE_LABEL = re.compile(DEPLOYMENT_SITE_LABEL_PATTERN)

# The closed, ordered enrollment states.
INVITED = "invited"
WORKER_BOUND = "worker_bound"
OFFER_TRANSPORTED = "offer_transported"
RESULT_TRANSPORTED = "result_transported"
VERIFIED = "verified"
HEALTHY = "healthy"
REFUSED = "refused"
RECOVERY_REQUIRED = "recovery_required"

#: forward edge -> the exact predecessor state it requires
ADVANCE = {
    WORKER_BOUND: INVITED,
    OFFER_TRANSPORTED: WORKER_BOUND,
    RESULT_TRANSPORTED: OFFER_TRANSPORTED,
    VERIFIED: RESULT_TRANSPORTED,
    HEALTHY: VERIFIED,
}
ACTIVE = (INVITED, WORKER_BOUND, OFFER_TRANSPORTED, RESULT_TRANSPORTED, VERIFIED)

#: Every state the contract can hold (the five active ones plus the two terminals and healthy).
ALL_STATES = (
    INVITED,
    WORKER_BOUND,
    OFFER_TRANSPORTED,
    RESULT_TRANSPORTED,
    VERIFIED,
    HEALTHY,
    REFUSED,
    RECOVERY_REQUIRED,
)


class WorkerEnrollmentContractError(Exception):
    """A bounded, closed refusal.  Carries ONLY a reason code — never free-form prose, a path, an
    endpoint, an IP, key material or a raw exception."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _closed(reason: str) -> WorkerEnrollmentContractError:
    return WorkerEnrollmentContractError(reason)


def _parse_ts(value: object, reason: str) -> _dt.datetime:
    if not isinstance(value, str) or not (1 <= len(value) <= MAX_TS_LEN):
        raise _closed(reason)
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _closed(reason) from None
    if parsed.tzinfo is None or parsed.utcoffset() != _dt.timedelta(0):
        raise _closed(reason)  # UTC-only, explicit offset
    return parsed


def _short_field(value: object, reason: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not (1 <= len(value) <= MAX_FIELD_LEN):
        raise _closed(reason)
    if pattern is not None and not pattern.fullmatch(value):
        raise _closed(reason)
    return value


def _reason_code(reason: str) -> str:
    return _short_field(reason, "enrollment_reason_code_invalid", pattern=_REASON_CODE)


def _assert_participants_separated(controller_key_id: str, worker_key_id: str) -> None:
    """The controller and the worker MUST be two distinct signers.

    The installation-id guard alone is not sufficient: an enrollment whose worker declares a
    different installation id but reuses the CONTROLLER's key id collapses both signature bindings
    (``record_controller_offer`` checks the signer against ``controller_key_id``,
    ``record_worker_result`` against ``worker_key_id``) onto a single key.  Every check would then
    report success while the two-distinct-signers property the offer/result exchange exists to
    establish is gone — a self-enrolment that reaches ``healthy``.

    This is the single pure assertion for that invariant.  It is applied to the PROPOSED identity at
    binding time AND to the state's own pair on every later transition, so a directly constructed,
    corrupted or rehydrated same-key state cannot advance, exact-retry, verify or become healthy.
    It is deliberately NOT applied to :func:`refuse` / :func:`require_recovery`: a corrupted
    enrollment must always remain movable to a terminal so an operator can remediate it.

    Refuses with the existing bounded ``enrollment_worker_mismatch`` code — a same-key configuration
    is a worker-identity mismatch, and a dedicated code would tell a prober exactly which of the two
    identity checks it tripped.

    The persistence layer must apply this same assertion when REHYDRATING a stored state, before the
    state is used (see the SECP-PR5H-A commit-4 ledger in ADR-027).
    """
    if worker_key_id == controller_key_id:
        raise _closed("enrollment_worker_mismatch")


def sha256_digest_of_hex(hex_value: str) -> str:
    return "sha256:" + hashlib.sha256(bytes.fromhex(hex_value)).hexdigest()


def _is_ip_literal(value: str) -> bool:
    """True if ``value`` parses as any IPv4/IPv6 address literal, using deterministic stdlib parsing
    rather than a substring heuristic.  (IPv6 forms also fail the label grammar, which forbids ':',
    but this parse is the authoritative, complete rejection for every representable form.)"""
    try:
        _ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_deployment_site_label(value: object) -> bool:
    """The single shared grammar helper for the opaque deployment-site label (ADR-027).

    The label is treated as OPAQUE: organization is the only authorization boundary, and the label
    is never interpreted as a hostname, provider, region or network endpoint — a string that merely
    looks like one is permitted but confers no such meaning.  Every IP-address literal (IPv4/IPv6 of
    any scope: private, loopback, link-local, multicast, unspecified or public) is rejected by
    deterministic parsing, so no address can ride a grouping label into persisted produced output.
    """
    if not isinstance(value, str) or _DEPLOYMENT_SITE_LABEL.fullmatch(value) is None:
        return False
    return not _is_ip_literal(value)


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
            "schema": INVITATION_SCHEMA,
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
        if len(self.controller_origin) > MAX_ORIGIN_LEN or not _HTTPS_ORIGIN.fullmatch(
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
        if not (MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS):
            raise _closed("enrollment_invitation_invalid")
        scan_forbidden(self.canonical())  # non-secret: no secret-like field name/value at any depth

    def assert_fresh(self, now: str) -> None:
        # Freshness is a CLOSED window on BOTH ends: created_at <= now < expires_at.  Bounding only
        # the upper end let a future-minted invitation (a far-future created_at with a bounded TTL)
        # be accepted years early, bypassing the TTL cap.  No clock-skew knob — the window is exact.
        now_ts = _parse_ts(now, "enrollment_time_invalid")
        created = _parse_ts(self.created_at, "enrollment_invitation_invalid")
        expires = _parse_ts(self.expires_at, "enrollment_invitation_invalid")
        if not (created <= now_ts < expires):
            raise _closed("enrollment_invitation_expired")


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
    single-use sha256 value (the invitation id); this module never reads a clock or a random
    source, so it stays deterministic and testable."""
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


# --------------------------------------------------------------------------- bound handoff facts


@dataclass(frozen=True)
class HandoffFacts:
    """The exact facts bound from a verified signed handoff record (never the record bytes).

    The API mirror consumes ALREADY-BOUND facts; it deliberately performs no signature verification
    and imports no signing implementation."""

    kind: str  # "controller-offer" | "worker-result"
    digest: str
    transaction_id: str
    signer_key_id: str


# --------------------------------------------------------------------------- enrollment state


@dataclass(frozen=True)
class EnrollmentState:
    """One durable, content-addressed enrollment record.  ``predecessor_digest`` chains a revision
    to the previous state's digest, so a persisted revision history is tamper-evident and a
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
    #: The opaque deployment-site grouping label (ADR-027), carried for the STATUS PROJECTION only.
    #:
    #: Deliberately NON-CANONICAL: it is absent from :meth:`canonical`, so it can never enter
    #: ``state_digest``, the predecessor chain, the CAS comparison, the append-only history
    #: snapshot, or any existing invariant — the parity corpus pins that (see
    #: ``tests/test_worker_enrollment_contract_parity.py``:
    #: ``test_deployment_site_label_is_not_part_of_the_canonical_contract``). It is therefore also
    #: NOT mirrored by the authoritative ``secp_management.enrollment`` contract, which owns only
    #: canonical semantics.
    #:
    #: It defaults to empty so a state rehydrated from a canonical snapshot (which cannot carry a
    #: non-canonical field) is still constructible; the AUTHORITATIVE value always comes from the
    #: persisted row and is re-stamped by the repository/service on every load. Every transition
    #: uses :func:`dataclasses.replace`, so the label rides along unchanged and cannot be mutated
    #: by a transition.
    deployment_site_label: str = ""

    def canonical(self) -> dict[str, object]:
        return {
            "schema": STATE_SCHEMA,
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
        their short key-id/digest fingerprints only; no key material, path, or secret is exposed.

        ``deployment_site_label`` is included so an operator inventory can GROUP workers without a
        second round trip. It is safe by construction: the grammar forbids '/', ':', '@' and
        whitespace (so no URL, path or scheme can ride in), every IP-address literal is rejected,
        and the ``scan_forbidden`` pass below runs over this projection's own output — so a
        secret-shaped label could not reach a browser even if one were somehow persisted.
        """
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
            "deployment_site_label": self.deployment_site_label,
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


def open_enrollment(
    invitation: WorkerEnrollmentInvitation, *, now: str, deployment_site_label: str = ""
) -> EnrollmentState:
    """Open an enrollment at INVITED/revision 0.

    ``deployment_site_label`` is the NON-CANONICAL projection label (see
    :class:`EnrollmentState`). It is validated by the caller against
    :func:`is_deployment_site_label` and stored on the row; passing it here only pre-stamps the
    in-memory state so the creation response projects the same value a later load would. It cannot
    reach ``canonical`` / ``digest``, so the invitation digest and the enrollment id are identical
    with or without it — which is exactly why it defaults to empty and stays optional.
    """
    invitation.validate()
    invitation.assert_fresh(now)
    _parse_ts(now, "enrollment_time_invalid")
    return EnrollmentState(
        deployment_site_label=deployment_site_label,
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
    # backstop: no forward edge may ever be taken from a state whose participants are not separated
    _assert_participants_separated(state.controller_key_id, state.worker_key_id)
    if state.state not in ACTIVE:
        raise _closed("enrollment_wrong_state")
    if state.state != ADVANCE[target]:
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
        # controller cannot enrol as its own worker
        raise _closed("enrollment_installation_mismatch")
    # ...and it cannot enrol as its own worker under a DIFFERENT installation id either: the key
    # must differ too.  Checked for the proposed identity AND for the state's own (possibly
    # corrupted or rehydrated) pair BEFORE the exact-retry branch, so a same-key pre-bound state is
    # never waved through as an idempotent retry.
    _assert_participants_separated(state.controller_key_id, worker_key_id)
    _assert_participants_separated(state.controller_key_id, state.worker_key_id)
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
    _assert_participants_separated(state.controller_key_id, state.worker_key_id)
    if facts.kind != "controller-offer":
        raise _closed("enrollment_handoff_invalid")
    if facts.signer_key_id != state.controller_key_id:
        raise _closed("enrollment_controller_mismatch")
    if facts.transaction_id != state.transaction_id:
        raise _closed("enrollment_transaction_mismatch")
    # the bound handoff digest must be a well-formed sha256 digest BEFORE it enters a durable state:
    # the portable DB CHECK only enforces length + prefix, so a shape-valid non-hex digest would
    # otherwise commit and be refused by the next rehydration as corrupt.  Precedence is pinned:
    # kind -> signer -> transaction -> digest-shape -> idempotent-retry/advance.
    if not is_sha256_digest(facts.digest):
        raise _closed("enrollment_handoff_invalid")
    if state.state == OFFER_TRANSPORTED:
        if state.offer_digest == facts.digest:
            return state  # idempotent exact retry
        # a different offer for the same step is a replay/conflict
        raise _closed("enrollment_replay")
    return _advance(state, OFFER_TRANSPORTED, now=now, offer_digest=facts.digest)


def record_worker_result(
    state: EnrollmentState, facts: HandoffFacts, *, now: str
) -> EnrollmentState:
    _assert_participants_separated(state.controller_key_id, state.worker_key_id)
    if facts.kind != "worker-result":
        raise _closed("enrollment_handoff_invalid")
    if facts.signer_key_id != state.worker_key_id:
        raise _closed("enrollment_worker_mismatch")
    if facts.transaction_id != state.transaction_id:
        raise _closed("enrollment_transaction_mismatch")
    # digest-shape guard, same precedence as the offer path (kind -> signer -> transaction ->
    # digest-shape -> retry/advance): a non-hex result digest must never enter a durable state.
    if not is_sha256_digest(facts.digest):
        raise _closed("enrollment_handoff_invalid")
    if state.state == RESULT_TRANSPORTED:
        if state.result_digest == facts.digest:
            return state  # idempotent exact retry
        raise _closed("enrollment_replay")
    return _advance(state, RESULT_TRANSPORTED, now=now, result_digest=facts.digest)


def mark_verified(state: EnrollmentState, *, release_digest: str, now: str) -> EnrollmentState:
    _assert_participants_separated(state.controller_key_id, state.worker_key_id)
    if release_digest != state.release_digest:
        raise _closed("enrollment_release_mismatch")
    if state.state == VERIFIED:
        return state  # idempotent
    return _advance(state, VERIFIED, now=now)


def mark_healthy(state: EnrollmentState, *, now: str) -> EnrollmentState:
    _assert_participants_separated(state.controller_key_id, state.worker_key_id)
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


__all__ = [
    "ACTIVE",
    "ADVANCE",
    "ALL_STATES",
    "DEPLOYMENT_SITE_LABEL_PATTERN",
    "ENROLLMENT_CONTRACT_VERSION",
    "HEALTHY",
    "INVITATION_SCHEMA",
    "INVITED",
    "MAX_FIELD_LEN",
    "MAX_ORIGIN_LEN",
    "MAX_TS_LEN",
    "MAX_TTL_SECONDS",
    "MIN_TTL_SECONDS",
    "OFFER_TRANSPORTED",
    "RECOVERY_REQUIRED",
    "REFUSED",
    "RESULT_TRANSPORTED",
    "STATE_SCHEMA",
    "VERIFIED",
    "WORKER_BOUND",
    "EnrollmentState",
    "HandoffFacts",
    "WorkerEnrollmentContractError",
    "WorkerEnrollmentInvitation",
    "bind_worker_identity",
    "create_invitation",
    "is_deployment_site_label",
    "mark_healthy",
    "mark_verified",
    "open_enrollment",
    "record_controller_offer",
    "record_worker_result",
    "refuse",
    "require_recovery",
    "sha256_digest_of_hex",
]
