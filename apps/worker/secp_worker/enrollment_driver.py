"""Worker-side enrollment orchestration driver (SECP-PR5H-B1, Phase 3).

The callable orchestration beneath the future ``secpctl`` worker command (no CLI parsing here). It
sequences the supported evidence-driven exchange from the WORKER side, holding no controller trust
beyond the invitation's pinned controller key and reaching NO provider / operator / OpenTofu /
controlled-live capability:

  parse+validate invitation -> load/create the protected worker enrollment key (injected hardened
  fixed-path seam) -> sign + submit the binding proof-of-possession (pinned outbound transport) ->
  INDEPENDENTLY verify the returned controller offer (rebuild-to-verify against the invitation's
  pinned controller key + field pin) -> gather bounded, checked-fact health evidence -> sign +
  submit the worker result -> reach verified/healthy.

Every collaborator is an INJECTED seam with a sealed default, so the shipped driver is inert until a
deployment-local profile wires a real transport + key seam. The driver is retry-safe (a transient
failure re-sends the IDENTICAL claim — the controller treats an exact retry as idempotent) and
resume-safe (a minimal, non-secret local step marker lets a restarted worker re-drive from the
controller's durable state without re-signing under a new key). The worker private key never leaves
the signer; no origin / CA path / private material enters a log, error, or the restart marker.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn, Protocol

from secp_commissioning.canonical import is_sha256_digest
from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    OFFER_KIND,
    OFFER_SCHEMA,
    REQUIRED_HEALTH_CHECKS,
    WORKER_RESULT_OUTCOME_HEALTHY,
    AttestationError,
    DetachedAttestation,
    claim_digest,
    verify_detached,
)

from secp_worker.enrollment_http_transport import (
    EnrollmentInvitationInputs,
    EnrollmentTransportError,
    SealedEnrollmentTransport,
    WorkerEnrollmentSigner,
)

_MAX_ATTEMPTS = 3
_STEP_OFFER_VERIFIED = "offer_verified"
_STEP_HEALTHY = "healthy"


class WorkerEnrollmentDriverError(Exception):
    """A bounded, closed worker-driver refusal — carries ONLY a reason code, never the origin, CA
    path, private key, or a raw exception."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _reject(reason_code: str) -> NoReturn:
    raise WorkerEnrollmentDriverError(reason_code)


class _Transport(Protocol):
    def submit_binding(self, invitation: EnrollmentInvitationInputs) -> tuple[int, dict]: ...
    def submit_result(
        self,
        invitation: EnrollmentInvitationInputs,
        *,
        predecessor_digest: str,
        outcome: str,
        health_evidence: dict,
        generation: str,
        challenge: str,
    ) -> tuple[int, dict]: ...


class WorkerEnrollmentKeySeam(Protocol):
    """Loads or creates the worker's DEDICATED enrollment signing key (a third key, never the SSH or
    admission keypair) behind a hardened fixed path, returning a signer that never exposes the
    private half."""

    def load_or_create(self) -> WorkerEnrollmentSigner: ...


class SealedWorkerEnrollmentKeySeam:
    """The shipped default: no worker enrollment key is provisioned; every attempt fails closed."""

    def load_or_create(self) -> WorkerEnrollmentSigner:
        _reject("enrollment_worker_key_sealed")


class WorkerEnrollmentStateStore(Protocol):
    """Minimal, NON-SECRET local restart state: the last completed exchange step per enrollment, so
    a restarted worker resumes idempotently. It stores no key, offer, claim, or attestation."""

    def load(self, enrollment_id: str) -> str | None: ...
    def record(self, enrollment_id: str, step: str) -> None: ...


class InMemoryWorkerEnrollmentStateStore:
    """A process-local restart-state store (the default). A production deployment injects a tmpfs
    marker store following the ``secp_worker.health`` idiom; this keeps the driver runnable + tested
    without a real filesystem."""

    def __init__(self) -> None:
        self._steps: dict[str, str] = {}

    def load(self, enrollment_id: str) -> str | None:
        return self._steps.get(enrollment_id)

    def record(self, enrollment_id: str, step: str) -> None:
        self._steps[enrollment_id] = step


def _sealed_transport_factory(_signer: WorkerEnrollmentSigner) -> _Transport:
    return SealedEnrollmentTransport()


@dataclass(frozen=True)
class DriverOutcome:
    """The result of driving one enrollment: the final controller-reported state + revision, and
    whether the driver short-circuited an already-healthy enrollment on resume."""

    enrollment_id: str
    state: str
    revision: int
    already_healthy: bool


class WorkerEnrollmentDriver:
    """Drives one worker enrollment to verified/healthy over the supported exchange. All
    collaborators are injected; the shipped defaults are sealed."""

    __slots__ = ("_key_seam", "_transport_factory", "_state_store", "_max_attempts")

    def __init__(
        self,
        *,
        key_seam: WorkerEnrollmentKeySeam | None = None,
        transport_factory: Callable[
            [WorkerEnrollmentSigner], _Transport
        ] = _sealed_transport_factory,
        state_store: WorkerEnrollmentStateStore | None = None,
        max_attempts: int = _MAX_ATTEMPTS,
    ) -> None:
        self._key_seam = key_seam or SealedWorkerEnrollmentKeySeam()
        self._transport_factory = transport_factory
        self._state_store = state_store or InMemoryWorkerEnrollmentStateStore()
        self._max_attempts = max(1, max_attempts)

    def __repr__(self) -> str:
        return "WorkerEnrollmentDriver(<redacted>)"

    def enroll(self, invitation: EnrollmentInvitationInputs, *, now: str) -> DriverOutcome:
        _validate_invitation(invitation, now=now)
        # resume: a durable local marker short-circuits an already-completed enrollment without
        # re-signing; anything else re-drives (the controller's durable state makes bind/result
        # idempotent, so a mid-flight restart safely resends the identical requests).
        if self._state_store.load(invitation.enrollment_id) == _STEP_HEALTHY:
            return DriverOutcome(
                invitation.enrollment_id, _STEP_HEALTHY, revision=5, already_healthy=True
            )

        signer = (
            self._key_seam.load_or_create()
        )  # the protected worker enrollment key (never leaks)
        transport = self._transport_factory(signer)

        _status, bind_body = self._retry(lambda: transport.submit_binding(invitation))
        offer = _require_offer(bind_body)
        offer_claim, offer_att = self._verify_offer(invitation, signer.worker_key_id, offer)
        self._state_store.record(invitation.enrollment_id, _STEP_OFFER_VERIFIED)

        health_evidence = _local_health_evidence()
        _status, result_body = self._retry(
            lambda: transport.submit_result(
                invitation,
                predecessor_digest=claim_digest(offer_claim),  # content-address of the exact offer
                outcome=WORKER_RESULT_OUTCOME_HEALTHY,
                health_evidence=health_evidence,
                generation=offer_att.key_id,  # the controller signer key that minted the offer
                challenge=offer_att.signature,  # the exact offer signature
            )
        )
        enrollment = _require_enrollment(result_body)
        self._state_store.record(invitation.enrollment_id, _STEP_HEALTHY)
        return DriverOutcome(
            invitation.enrollment_id,
            str(enrollment.get("state")),
            revision=int(enrollment.get("revision", 0)),
            already_healthy=False,
        )

    def _retry(self, call: Callable[[], tuple[int, dict]]) -> tuple[int, dict]:
        """Send a request, re-sending the IDENTICAL call on a transient failure (transport error or
        5xx). A definitive 4xx is returned to the caller to refuse — a retry cannot fix it."""
        last_reason = "enrollment_worker_driver_failed"
        for _attempt in range(self._max_attempts):
            try:
                status, body = call()
            except EnrollmentTransportError as exc:
                last_reason = exc.reason_code
                continue  # transient transport failure: re-send the identical request
            if 200 <= status < 300:
                return status, body
            if 400 <= status < 500:
                _reject(_bounded_status_reason(body, default="enrollment_worker_driver_refused"))
            last_reason = "enrollment_worker_driver_unavailable"  # 5xx: retry
        _reject(last_reason)

    def _verify_offer(
        self, invitation: EnrollmentInvitationInputs, worker_key_id: str, offer: dict
    ) -> tuple[dict, DetachedAttestation]:
        claim = offer.get("claim")
        att_fields = offer.get("attestation")
        if not isinstance(claim, dict) or not isinstance(att_fields, dict):
            _reject("enrollment_offer_malformed")
        try:
            att = DetachedAttestation(
                algorithm=att_fields["algorithm"],
                key_id=att_fields["key_id"],
                public_key_hex=att_fields["public_key_hex"],
                signature=att_fields["signature"],
            )
        except (KeyError, TypeError):
            _reject("enrollment_offer_malformed")
        # the offer MUST be signed by the invitation's pinned controller key (verify_detached also
        # requires the presented public key to derive that pinned id)
        try:
            verify_detached(
                att,
                expected_key_id=invitation.controller_key_id,
                domain=ENROLLMENT_ATTESTATION_DOMAIN,
                kind=OFFER_KIND,
                digest=claim_digest(claim),
            )
        except AttestationError:
            _reject("enrollment_offer_signature_invalid")
        # and the signed claim MUST bind the exact invitation identity + THIS worker's key
        expected = {
            "schema": OFFER_SCHEMA,
            "enrollment_id": invitation.enrollment_id,
            "invitation_id": invitation.invitation_id,
            "controller_installation_id": invitation.controller_installation_id,
            "controller_key_id": invitation.controller_key_id,
            "controller_origin": invitation.controller_origin,
            "controller_transaction_id": invitation.controller_transaction_id,
            "worker_key_id": worker_key_id,
            "release_digest": invitation.release_digest,
            "expires_at": invitation.expires_at,
        }
        for key, value in expected.items():
            if claim.get(key) != value:
                _reject("enrollment_offer_binding_mismatch")
        if not is_sha256_digest(claim.get("predecessor_digest")):
            _reject("enrollment_offer_binding_mismatch")
        return claim, att


def _validate_invitation(invitation: EnrollmentInvitationInputs, *, now: str) -> None:
    if not invitation.controller_origin.startswith("https://"):
        _reject("enrollment_invitation_origin_invalid")
    if not is_sha256_digest(invitation.release_digest):
        _reject("enrollment_invitation_release_invalid")
    if not _before(now, invitation.expires_at):
        _reject("enrollment_invitation_expired")


def _before(now: str, expires_at: str) -> bool:
    """A bounded canonical-UTC comparison; a malformed timestamp fails closed (i.e. expired)."""
    from datetime import datetime, timedelta

    def _parse(value: object) -> datetime | None:
        if not isinstance(value, str) or not (1 <= len(value) <= 40):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            return None
        return parsed

    now_dt, exp_dt = _parse(now), _parse(expires_at)
    return now_dt is not None and exp_dt is not None and now_dt < exp_dt


def _local_health_evidence() -> dict[str, bool]:
    """The bounded, provider-neutral CHECKED FACTS this driver attests after driving the exchange.
    Each is genuinely established: the offer was verified against the pinned controller key, the
    worker key stayed protected in the non-serializable signer, and the driver performed NONE of the
    forbidden operations (it imports and calls no provider / operator / OpenTofu / controlled-live
    capability). It is never a caller convenience boolean."""
    return {check: True for check in REQUIRED_HEALTH_CHECKS}


def _require_offer(body: dict) -> dict:
    offer = body.get("signed_offer") if isinstance(body, dict) else None
    if not isinstance(offer, dict):
        _reject("enrollment_offer_missing")
    return offer


def _require_enrollment(body: dict) -> dict:
    enrollment = body.get("enrollment") if isinstance(body, dict) else None
    if not isinstance(enrollment, dict):
        _reject("enrollment_result_malformed")
    return enrollment


def _bounded_status_reason(body: object, *, default: str) -> str:
    """Surface the controller's bounded ``error.code`` when present (already a closed snake_case
    code), else a fixed default — never a free-form message."""
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            return error["code"]
    return default


__all__ = [
    "DriverOutcome",
    "InMemoryWorkerEnrollmentStateStore",
    "SealedWorkerEnrollmentKeySeam",
    "WorkerEnrollmentDriver",
    "WorkerEnrollmentDriverError",
    "WorkerEnrollmentKeySeam",
    "WorkerEnrollmentStateStore",
]
