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

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, Protocol

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

if TYPE_CHECKING:  # type-only, so the worker package keeps its lazy-import posture
    from secp_commissioning.runtime import FilesystemBackend

    from secp_worker.worker_ownership import WorkerControllerOwnership

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


class SealedWorkerEnrollmentStateStore:
    """The SHIPPED DEFAULT restart-state store (C3): it persists NOTHING across restarts (``load``
    is always ``None``, ``record`` is a no-op). Production composes a fixed-path HARDENED marker
    store (following the ``secp_worker.health`` idiom) — until then the marker is simply absent, so
    a restarted worker safely RE-DRIVES the idempotent exchange and reconciles against the
    controller's authoritative state rather than trusting a local marker."""

    def load(self, enrollment_id: str) -> str | None:
        return None

    def record(self, enrollment_id: str, step: str) -> None:
        return None


class InMemoryWorkerEnrollmentStateStore:
    """A process-local restart-state store for TESTS (inspectable). It is never the shipped default;
    production composes a fixed-path hardened marker store. It stores no key, offer, claim, or
    attestation — only the last completed step per enrollment (a retry HINT, never trusted as the
    authoritative outcome)."""

    def __init__(self) -> None:
        self._steps: dict[str, str] = {}

    def load(self, enrollment_id: str) -> str | None:
        return self._steps.get(enrollment_id)

    def record(self, enrollment_id: str, step: str) -> None:
        self._steps[enrollment_id] = step


# --- health evidence: OBSERVED, never fabricated (C3) --------------------------------------------


@dataclass(frozen=True)
class HealthObservationContext:
    """The bounded, PUBLIC context an observer needs to bind its observations to THIS exchange — the
    release digest to confirm running, the controller transaction and the verified offer's content
    address to confirm the offer/transaction, and the worker key id to confirm the protected key.
    All are public digests/ids; no path, secret or private key is present."""

    enrollment_id: str
    release_digest: str
    controller_transaction_id: str
    worker_key_id: str
    offer_claim_digest: str


@dataclass(frozen=True)
class ObservedHealthEvidence:
    """A strict, immutable health-evidence object built from ACTUAL bounded local observations.
    Construction requires EXACTLY the ``REQUIRED_HEALTH_CHECKS`` keys with boolean values (a missing
    key, extra key, or non-bool refuses closed), and it carries ONLY those booleans — never a path,
    release digest, key id, or any secret. A failed/unavailable observation is a ``False`` check
    (never a fabricated ``True``), so an unhealthy worker can never reach ``healthy``."""

    checks: Mapping[str, bool]

    def __post_init__(self) -> None:
        if set(self.checks) != set(REQUIRED_HEALTH_CHECKS) or any(
            not isinstance(v, bool) for v in self.checks.values()
        ):
            _reject("enrollment_worker_health_evidence_invalid")

    def all_true(self) -> bool:
        return all(self.checks[check] is True for check in REQUIRED_HEALTH_CHECKS)

    def as_evidence(self) -> dict[str, bool]:
        """The bounded booleans-only structure the worker signs (deterministic key order)."""
        return {check: self.checks[check] for check in REQUIRED_HEALTH_CHECKS}


class WorkerEnrollmentHealthObserver(Protocol):
    """Produces the worker's health evidence from ACTUAL bounded local observations (the installed +
    signature-trusted + running release, the protected enrollment-key identity, the verified
    controller offer + transaction, the required bootstrap/service state, the operator worker
    disabled+stopped, and the absence of any provider / OpenTofu / controlled-live / operator-queue
    activity). It returns a strict :class:`ObservedHealthEvidence`; a failed observation is a
    ``False`` check, never a fabricated ``True``."""

    def observe(self, context: HealthObservationContext) -> ObservedHealthEvidence: ...


class SealedWorkerEnrollmentHealthObserver:
    """The SHIPPED DEFAULT: no host-local health observer is composed, so every attempt fails closed
    (C3). The driver cannot reach ``healthy`` until a deployment wires a real observer — it never
    falls back to fabricating an all-true evidence structure."""

    def observe(self, context: HealthObservationContext) -> ObservedHealthEvidence:
        _reject("enrollment_worker_health_observer_sealed")


class WorkerHealthProbes(Protocol):
    """The bounded, host-local probes a deployment wires into :class:`LocalWorkerHealthObserver` —
    one per required check. Each returns a REAL ``True``/``False`` from an actual observation; a
    probe that raises is treated as ``False`` (fail-closed). No probe returns or handles a
    secret."""

    def invitation_and_offer_verified(self, ctx: HealthObservationContext) -> bool: ...
    def controller_key_pinned(self, ctx: HealthObservationContext) -> bool: ...
    def expected_transaction(self, ctx: HealthObservationContext) -> bool: ...
    def expected_predecessor(self, ctx: HealthObservationContext) -> bool: ...
    def exact_release(self, ctx: HealthObservationContext) -> bool: ...
    def worker_enrollment_key_protected(self, ctx: HealthObservationContext) -> bool: ...
    def local_enrollment_state_present(self, ctx: HealthObservationContext) -> bool: ...
    def operator_worker_disabled(self, ctx: HealthObservationContext) -> bool: ...
    def no_provider_contact(self, ctx: HealthObservationContext) -> bool: ...
    def no_opentofu_execution(self, ctx: HealthObservationContext) -> bool: ...
    def no_controlled_live_submission(self, ctx: HealthObservationContext) -> bool: ...


class LocalWorkerHealthObserver:
    """The production observer: it calls the injected host-local :class:`WorkerHealthProbes` — one
    real observation per required check — and returns a strict :class:`ObservedHealthEvidence`. A
    probe that raises is a ``False`` observation (fail-closed), never a fabricated ``True``. The
    deployment composes the concrete probes; this class only orchestrates and validates them."""

    __slots__ = ("_probes",)

    def __init__(self, probes: WorkerHealthProbes) -> None:
        self._probes = probes

    def __repr__(self) -> str:
        return "LocalWorkerHealthObserver(<redacted>)"

    def observe(self, context: HealthObservationContext) -> ObservedHealthEvidence:
        checks: dict[str, bool] = {}
        for check in REQUIRED_HEALTH_CHECKS:
            probe = getattr(self._probes, check, None)
            try:
                checks[check] = probe(context) is True if callable(probe) else False
            except Exception:  # noqa: BLE001 - an unavailable probe is a False observation
                checks[check] = False
        return ObservedHealthEvidence(checks=checks)


def _sealed_transport_factory(
    _signer: WorkerEnrollmentSigner, _invitation: EnrollmentInvitationInputs
) -> _Transport:
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

    __slots__ = (
        "_key_seam",
        "_transport_factory",
        "_state_store",
        "_health_observer",
        "_max_attempts",
        "_ownership_store",
    )

    def __init__(
        self,
        *,
        key_seam: WorkerEnrollmentKeySeam | None = None,
        # The factory takes the INVITATION as well as the signer: the controller origin and CA chain
        # are per-invitation values (the CA travels in the invitation), so a transport cannot be
        # built once at construction time. The driver is long-lived; `enroll()` is per-invitation.
        transport_factory: Callable[
            [WorkerEnrollmentSigner, EnrollmentInvitationInputs], _Transport
        ] = _sealed_transport_factory,
        state_store: WorkerEnrollmentStateStore | None = None,
        health_observer: WorkerEnrollmentHealthObserver | None = None,
        max_attempts: int = _MAX_ATTEMPTS,
        # The hardened filesystem the durable ownership document lives on. `None` is NOT "unowned"
        # — the gate refuses without it, because a driver that cannot read the binding must not act
        # as though there is none.
        ownership_store: FilesystemBackend | None = None,
    ) -> None:
        self._key_seam = key_seam or SealedWorkerEnrollmentKeySeam()
        self._transport_factory = transport_factory
        # sealed by default (C3): production composes a fixed-path hardened marker store + a real
        # host-local health observer; the shipped defaults persist nothing and refuse to fabricate.
        self._state_store = state_store or SealedWorkerEnrollmentStateStore()
        self._health_observer = health_observer or SealedWorkerEnrollmentHealthObserver()
        self._max_attempts = max(1, max_attempts)
        self._ownership_store = ownership_store

    def __repr__(self) -> str:
        return "WorkerEnrollmentDriver(<redacted>)"

    def enroll(
        self,
        invitation: EnrollmentInvitationInputs,
        *,
        now: str,
        expected_controller_key_id: str | None = None,
    ) -> DriverOutcome:
        """Drive one enrollment. Ownership is settled BEFORE the first packet leaves this host.

        ``expected_controller_key_id`` is the independent first-contact trust fact for an UNOWNED
        worker: the controller's enrollment-key fingerprint, obtained by a local administrator from
        an authenticated SECP surface and supplied here out of band. It is public material, so the
        point is provenance rather than secrecy — it must not come from the invitation, whose whole
        contents an attacker who can substitute it also chooses.

        Adding one more value to the invitation would have been self-authentication: the invitation
        already carries the controller origin, the controller key id AND the TLS CA, so an attacker
        who supplies all three supplies a coherent identity that TLS and signature checks then
        correctly authenticate. The only fix is a fact that did not travel with the invitation.
        """
        _validate_invitation(invitation, now=now)
        # BEFORE the transport exists and before any packet leaves: does this invitation belong to
        # the controller that owns this worker, or — if unowned — to the one an administrator
        # independently named? A refusal here means an attacker controlling another valid SECP
        # installation never even receives a proof-of-possession attempt from an owned worker.
        owner = self._ownership_gate(invitation, expected_controller_key_id)
        # C3: the local marker is only a RETRY HINT — it is NEVER trusted as the outcome. The driver
        # always re-drives the idempotent exchange and RECONCILES against the controller's
        # AUTHORITATIVE reported state/revision; a revoked / refused / recovery-required / advanced
        # controller state therefore overrides a stale "healthy" marker (no hard-coded revision).
        prior_marker = self._state_store.load(invitation.enrollment_id)

        signer = (
            self._key_seam.load_or_create()
        )  # the protected worker enrollment key (never leaks)
        # built per-invitation, never cached across enrollments: the origin + CA chain are the
        # validated invitation's own, so one driver serving two invitations cannot cross them
        transport = self._transport_factory(signer, invitation)

        _status, bind_body = self._retry(lambda: transport.submit_binding(invitation))
        offer = _require_offer(bind_body)
        offer_claim, offer_att = self._verify_offer(invitation, signer.worker_key_id, offer)
        # Bind ownership from the VERIFIED OWNERSHIP claim — not from the invitation, and not from
        # the offer. The offer authenticates the exchange but says nothing about the organization
        # or the TLS trust anchor; the ownership claim signs both, and its anchor is checked
        # against the one this worker actually negotiated.
        ownership_claim = self._verify_ownership_claim(invitation, signer.worker_key_id, bind_body)
        owner = self._bind_ownership(owner, ownership_claim, signer.worker_key_id)
        self._state_store.record(invitation.enrollment_id, _STEP_OFFER_VERIFIED)

        # OBSERVE (never fabricate) the health evidence from actual bounded local observations. A
        # failed/unavailable observation is a False check, so the driver refuses locally rather than
        # signing a healthy claim it cannot back — and the sealed default refuses outright.
        evidence = self._health_observer.observe(
            HealthObservationContext(
                enrollment_id=invitation.enrollment_id,
                release_digest=invitation.release_digest,
                controller_transaction_id=invitation.controller_transaction_id,
                worker_key_id=signer.worker_key_id,
                offer_claim_digest=claim_digest(offer_claim),
            )
        )
        if not evidence.all_true():
            _reject("enrollment_worker_health_incomplete")
        health_evidence = evidence.as_evidence()

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
        # RECONCILE: the state + revision come from the controller's authoritative response — not a
        # hard-coded value. Only record the healthy marker when the controller actually reports it.
        state = str(enrollment.get("state"))
        revision = int(enrollment.get("revision", 0))
        if state == _STEP_HEALTHY:
            self._state_store.record(invitation.enrollment_id, _STEP_HEALTHY)
        return DriverOutcome(
            invitation.enrollment_id,
            state,
            revision=revision,
            already_healthy=(prior_marker == _STEP_HEALTHY and state == _STEP_HEALTHY),
        )

    def _ownership_gate(
        self,
        invitation: EnrollmentInvitationInputs,
        expected_controller_key_id: str | None,
    ) -> WorkerControllerOwnership | None:
        """Settle ownership before any network contact. Returns the current owner, or ``None``.

        Two paths, and neither can be reached from the other:

        * **Owned.** Every identity in the invitation must equal the pinned one. A mismatch refuses
          here — not after a handshake, and not after this worker has signed anything — so a
          hostile controller learns nothing and receives no proof of possession.
        * **Unowned.** An independently-supplied ``expected_controller_key_id`` is REQUIRED, and the
          invitation's controller key must equal it. With neither, the worker has no fact by which
          to tell a real controller from an attacker-supplied one, and enrolling anyway is the
          hijack this gate exists to prevent — so it refuses rather than proceeding hopefully.

        A CORRUPT ownership document raises out of :func:`load_worker_ownership` rather than
        reading as unowned. That direction matters: the opposite would make "damage the file" a
        remote worker-claim primitive.
        """
        from secp_worker.worker_ownership import load_worker_ownership

        store = self._ownership_store
        if store is None:
            # No ownership seam wired: the driver cannot prove who owns this worker, so it must not
            # act as though nobody does. The shipped composition supplies the real store.
            _reject("enrollment_ownership_store_unavailable")
        owner = load_worker_ownership(store)

        if owner is None:
            if not expected_controller_key_id or not expected_controller_key_id.strip():
                _reject("enrollment_ownership_expected_controller_required")
            if expected_controller_key_id != invitation.controller_key_id:
                _reject("enrollment_ownership_expected_controller_mismatch")
            return None

        # An owned worker ignores `expected_controller_key_id` entirely rather than letting it
        # override the pin: a locally-supplied value must never be able to re-point an owned worker,
        # or the local flag becomes the transfer mechanism the reset is supposed to be.
        if invitation.controller_installation_id != owner.controller_installation_id:
            _reject("enrollment_ownership_controller_installation_mismatch")
        if invitation.controller_key_id != owner.controller_key_id:
            _reject("enrollment_ownership_controller_key_mismatch")
        if invitation.controller_origin != owner.controller_origin:
            _reject("enrollment_ownership_controller_origin_mismatch")
        return owner

    def _verify_ownership_claim(
        self,
        invitation: EnrollmentInvitationInputs,
        worker_key_id: str,
        body: dict,
    ) -> dict:
        """Verify the controller-signed OWNERSHIP claim, and prove the CA was not swapped.

        This is the half the offer signature cannot cover. A proxying attacker presents the real
        controller's ``controller_key_id``, forwards the exchange so every existing signature
        verifies, and swaps only the TLS CA — terminating the connection itself. Nothing in the
        offer says anything about the CA, so nothing caught it.

        The claim is verified under the SAME independently-trusted controller key the ownership gate
        already established, and then its ``controller_trust_anchor_id`` is compared against the
        anchor this worker ACTUALLY negotiated — recomputed here from the bundle the transport built
        its TLS context from, not read back out of the claim. A proxy that swapped the CA cannot
        make those agree without the controller's signing key.
        """
        from secp_commissioning.enrollment_attestation import (
            OWNERSHIP_KIND,
            controller_ownership_claim,
        )
        from secp_commissioning.trust_anchor import TrustAnchorError, trust_anchor_id_for

        signed = body.get("signed_ownership") if isinstance(body, dict) else None
        if not isinstance(signed, dict):
            _reject("enrollment_ownership_claim_missing")
        claim = signed.get("claim")
        att_fields = signed.get("attestation")
        if not isinstance(claim, dict) or not isinstance(att_fields, dict):
            _reject("enrollment_ownership_claim_malformed")
        try:
            att = DetachedAttestation(
                algorithm=att_fields["algorithm"],
                key_id=att_fields["key_id"],
                public_key_hex=att_fields["public_key_hex"],
                signature=att_fields["signature"],
            )
        except (KeyError, TypeError):
            _reject("enrollment_ownership_claim_malformed")

        # The anchor this worker really negotiated. Computed from the bundle the transport used —
        # never taken from the claim, or the comparison below would be the claim agreeing with
        # itself.
        try:
            observed_anchor = trust_anchor_id_for(invitation.controller_ca_bundle_pem)
        except TrustAnchorError:
            _reject("enrollment_ownership_trust_anchor_unreadable")

        try:
            verify_detached(
                att,
                expected_key_id=invitation.controller_key_id,
                domain=ENROLLMENT_ATTESTATION_DOMAIN,
                kind=OWNERSHIP_KIND,
                digest=claim_digest(claim),
            )
        except AttestationError:
            _reject("enrollment_ownership_claim_signature_invalid")

        # REBUILD to verify: the claim must be exactly the one this exchange implies, with the
        # observed anchor in it. A claim carrying a different anchor produces different bytes, so it
        # cannot have been signed by the controller for THIS connection.
        expected = controller_ownership_claim(
            organization_id=str(claim.get("organization_id", "")),
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_origin=invitation.controller_origin,
            controller_trust_anchor_id=observed_anchor,
            worker_key_id=worker_key_id,
            enrollment_id=invitation.enrollment_id,
            invitation_id=invitation.invitation_id,
            controller_transaction_id=invitation.controller_transaction_id,
            release_digest=invitation.release_digest,
            predecessor_digest=str(claim.get("predecessor_digest", "")),
        )
        if claim_digest(claim) != claim_digest(expected):
            # The single most likely cause is a swapped CA: every other input is one the gate has
            # already pinned or the invitation already fixed.
            _reject("enrollment_ownership_trust_anchor_mismatch")
        if not str(claim.get("organization_id", "")).strip():
            _reject("enrollment_ownership_claim_malformed")
        return claim

    def _bind_ownership(
        self,
        owner: WorkerControllerOwnership | None,
        ownership_claim: dict,
        worker_key_id: str,
    ) -> WorkerControllerOwnership:
        """Persist the owner, or prove the existing one still holds. Never best-effort.

        Runs AFTER the offer signature verifies and BEFORE the worker reports healthy. If the write
        fails the enrollment refuses, because a controller must never regard a privileged worker as
        healthy while the worker failed to remember who owns it — that is precisely the state a
        later hijack needs.

        Writing before the final acknowledgement is deliberate. If the acknowledgement then fails,
        the SAME controller retries and `install_worker_ownership` is idempotent for an identical
        record; a DIFFERENT controller meets an owned worker and is refused at the gate. The
        interrupted state is therefore useless to an attacker, which is not true the other way
        round.
        """
        from secp_worker.worker_ownership import (
            WorkerControllerOwnership,
            install_worker_ownership,
        )

        candidate = WorkerControllerOwnership(
            organization_id=str(ownership_claim["organization_id"]),
            controller_installation_id=str(ownership_claim["controller_installation_id"]),
            controller_key_id=str(ownership_claim["controller_key_id"]),
            controller_origin=str(ownership_claim["controller_origin"]),
            controller_trust_anchor_id=str(ownership_claim["controller_trust_anchor_id"]),
            worker_key_id=worker_key_id,
            binding_generation=owner.binding_generation if owner is not None else 1,
        )
        if owner is not None and not owner.matches(candidate):
            # The gate already compared the invitation; this compares what was actually SIGNED.
            _reject("enrollment_ownership_signed_offer_mismatch")
        store = self._ownership_store
        if store is None:  # pragma: no cover - the gate refuses first; re-narrowed for the checker
            _reject("enrollment_ownership_store_unavailable")
        return install_worker_ownership(store, candidate)

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
    # the CA chain is the worker's ONLY server-TLS trust anchor; an invitation without one cannot
    # produce a verifying transport, so refuse here rather than at connect time. Checked
    # independently of the CLI's file validation so a programmatic caller cannot skip it.
    if not invitation.controller_ca_bundle_pem.strip():
        _reject("enrollment_invitation_ca_missing")
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
    "HealthObservationContext",
    "InMemoryWorkerEnrollmentStateStore",
    "LocalWorkerHealthObserver",
    "ObservedHealthEvidence",
    "SealedWorkerEnrollmentHealthObserver",
    "SealedWorkerEnrollmentKeySeam",
    "SealedWorkerEnrollmentStateStore",
    "WorkerEnrollmentDriver",
    "WorkerEnrollmentDriverError",
    "WorkerEnrollmentHealthObserver",
    "WorkerEnrollmentKeySeam",
    "WorkerEnrollmentStateStore",
    "WorkerHealthProbes",
]
