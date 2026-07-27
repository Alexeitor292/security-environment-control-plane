"""Worker-side enrollment orchestration driver (SECP-PR5H-B1, Phase 3).

Hermetic: a faithful in-process fake controller transport (the worker signs real PoP/result claims
via the shared primitive; the fake verifies them and mints a real controller-signed offer), so the
driver's full orchestration + independent offer verification + result signing runs with no network.
Proves the happy path to healthy, the sealed defaults, offer verification (bad signer key, bound-
field mismatch), retry-safety (transient failure then success), resume (already-healthy short
circuit), and invitation validation.
"""

from __future__ import annotations

import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_management.signing import generate_keypair
from secp_worker.enrollment_driver import (
    DriverOutcome,
    InMemoryWorkerEnrollmentStateStore,
    WorkerEnrollmentDriver,
    WorkerEnrollmentDriverError,
)
from secp_worker.enrollment_http_transport import (
    EnrollmentInvitationInputs,
    EnrollmentTransportError,
    WorkerEnrollmentSigner,
)

NOW = "2026-07-26T00:00:00+00:00"
FUTURE = "2999-01-01T00:00:00+00:00"


def _invitation(controller_pub: str, **over) -> EnrollmentInvitationInputs:
    fields = dict(
        enrollment_id="sha256:" + "1" * 64,
        invitation_id="sha256:" + "2" * 64,
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=ea.key_id_for(controller_pub),
        controller_origin="https://ctrl.example.test",
        controller_transaction_id="txn-0001",
        release_digest="sha256:" + "a" * 64,
        expires_at=FUTURE,
    )
    fields.update(over)
    return EnrollmentInvitationInputs(**fields)


def _installation_from_key(worker_key_id: str) -> str:
    return "worker-" + worker_key_id.split(":", 1)[-1][:16]


class _FakeController:
    """A faithful in-process controller double built around the worker signer. It verifies the
    worker PoP and mints a REAL controller-signed offer, then verifies the worker result."""

    def __init__(
        self,
        signer: WorkerEnrollmentSigner,
        *,
        controller_priv: str,
        controller_pub: str,
        offer_signer_priv: str | None = None,
        offer_field_override: dict | None = None,
        transient_binds: int = 0,
        result_status: int = 200,
    ) -> None:
        self._signer = signer
        self._controller_priv = controller_priv
        self._controller_pub = controller_pub
        # a distinct key to mint the offer with (to exercise the pinned-key refusal)
        self._offer_priv = offer_signer_priv or controller_priv
        self._offer_field_override = offer_field_override or {}
        self._transient_binds = transient_binds
        self._result_status = result_status

    def submit_binding(self, invitation: EnrollmentInvitationInputs) -> tuple[int, dict]:
        if self._transient_binds > 0:
            self._transient_binds -= 1
            raise EnrollmentTransportError("enrollment_transport_failed")
        # the worker signs its PoP (as the real transport would)
        binding = ea.worker_binding_claim(
            enrollment_id=invitation.enrollment_id,
            invitation_id=invitation.invitation_id,
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_transaction_id=invitation.controller_transaction_id,
            worker_installation_id=_installation_from_key(self._signer.worker_key_id),
            worker_key_id=self._signer.worker_key_id,
            release_digest=invitation.release_digest,
            expires_at=invitation.expires_at,
        )
        pop = self._signer.sign_binding(ea.claim_digest(binding))
        ea.verify_detached(  # controller verifies the PoP
            pop,
            expected_key_id=self._signer.worker_key_id,
            domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
            kind=ea.POP_KIND,
            digest=ea.claim_digest(binding),
        )
        # mint the controller offer (real signature under the controller key)
        offer_claim = ea.controller_offer_claim(
            enrollment_id=invitation.enrollment_id,
            invitation_id=invitation.invitation_id,
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_origin=invitation.controller_origin,
            controller_transaction_id=invitation.controller_transaction_id,
            worker_installation_id=_installation_from_key(self._signer.worker_key_id),
            worker_key_id=self._signer.worker_key_id,
            release_digest=invitation.release_digest,
            expires_at=invitation.expires_at,
            predecessor_digest="sha256:" + "b" * 64,
        )
        offer_claim = {**offer_claim, **self._offer_field_override}
        offer_att = ea.sign_detached(
            self._offer_priv,
            domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
            kind=ea.OFFER_KIND,
            digest=ea.claim_digest(offer_claim),
        )
        signed_offer = {
            "claim": offer_claim,
            "attestation": {
                "algorithm": offer_att.algorithm,
                "key_id": offer_att.key_id,
                "public_key_hex": offer_att.public_key_hex,
                "signature": offer_att.signature,
            },
        }
        return 200, {
            "signed_offer": signed_offer,
            "enrollment": {"state": "offer_transported", "revision": 2},
        }

    def submit_result(
        self,
        invitation: EnrollmentInvitationInputs,
        *,
        predecessor_digest: str,
        outcome: str,
        health_evidence: dict,
        generation: str,
        challenge: str,
    ) -> tuple[int, dict]:
        if self._result_status != 200:
            return self._result_status, {"error": {"code": "enrollment_health_incomplete"}}
        result = ea.worker_result_claim(
            enrollment_id=invitation.enrollment_id,
            controller_transaction_id=invitation.controller_transaction_id,
            worker_key_id=self._signer.worker_key_id,
            predecessor_digest=predecessor_digest,
            release_digest=invitation.release_digest,
            outcome=outcome,
            health_evidence_digest=ea.sha256_digest(health_evidence),
            generation=generation,
            challenge=challenge,
        )
        att = self._signer.sign_result(ea.claim_digest(result))
        ea.verify_detached(  # controller verifies the signed result
            att,
            expected_key_id=self._signer.worker_key_id,
            domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
            kind=ea.RESULT_KIND,
            digest=ea.claim_digest(result),
        )
        return 200, {"enrollment": {"state": "healthy", "revision": 5}}


class _KeySeam:
    def __init__(self, priv_hex: str) -> None:
        self._priv = priv_hex

    def load_or_create(self) -> WorkerEnrollmentSigner:
        return WorkerEnrollmentSigner(self._priv)


def _driver(
    controller_priv, controller_pub, *, state_store=None, **fake_kw
) -> WorkerEnrollmentDriver:
    wpriv, _wpub = generate_keypair()
    return WorkerEnrollmentDriver(
        key_seam=_KeySeam(wpriv),
        transport_factory=lambda signer: _FakeController(
            signer, controller_priv=controller_priv, controller_pub=controller_pub, **fake_kw
        ),
        state_store=state_store or InMemoryWorkerEnrollmentStateStore(),
    )


# --- happy path ----------------------------------------------------------------------------------


def test_driver_reaches_healthy_over_the_supported_exchange():
    cpriv, cpub = generate_keypair()
    outcome = _driver(cpriv, cpub).enroll(_invitation(cpub), now=NOW)
    assert isinstance(outcome, DriverOutcome)
    assert outcome.state == "healthy" and outcome.revision == 5
    assert outcome.already_healthy is False


# --- sealed defaults -----------------------------------------------------------------------------


def test_the_sealed_key_seam_default_fails_closed():
    cpriv, cpub = generate_keypair()
    driver = WorkerEnrollmentDriver()  # both seams sealed
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW)
    assert ei.value.reason_code == "enrollment_worker_key_sealed"


def test_the_sealed_transport_default_fails_closed():
    wpriv, _ = generate_keypair()
    cpriv, cpub = generate_keypair()
    driver = WorkerEnrollmentDriver(key_seam=_KeySeam(wpriv))  # sealed transport factory
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW)
    assert ei.value.reason_code == "enrollment_transport_not_activated"


# --- offer verification --------------------------------------------------------------------------


def test_an_offer_signed_by_a_non_pinned_key_is_refused():
    cpriv, cpub = generate_keypair()
    other_priv, _ = generate_keypair()
    driver = _driver(cpriv, cpub, offer_signer_priv=other_priv)  # offer signed by the WRONG key
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW)
    assert ei.value.reason_code == "enrollment_offer_signature_invalid"


def test_an_offer_bound_to_a_different_release_is_refused():
    cpriv, cpub = generate_keypair()
    # override the offer's release_digest AFTER it is signed-consistent, so the signature is valid
    # but the field pin against the invitation fails
    driver = _driver(cpriv, cpub, offer_field_override={"release_digest": "sha256:" + "9" * 64})
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW)
    assert ei.value.reason_code == "enrollment_offer_binding_mismatch"


# --- retry + resume ------------------------------------------------------------------------------


def test_a_transient_bind_failure_is_retried_then_succeeds():
    cpriv, cpub = generate_keypair()
    outcome = _driver(cpriv, cpub, transient_binds=2).enroll(_invitation(cpub), now=NOW)
    assert outcome.state == "healthy"


def test_a_persistent_transport_failure_refuses_after_bounded_retries():
    cpriv, cpub = generate_keypair()
    outcome_driver = _driver(cpriv, cpub, transient_binds=99)  # always fails
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        outcome_driver.enroll(_invitation(cpub), now=NOW)
    assert ei.value.reason_code == "enrollment_transport_failed"


def test_a_4xx_result_is_refused_with_the_bounded_controller_code():
    cpriv, cpub = generate_keypair()
    driver = _driver(cpriv, cpub, result_status=422)
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW)
    assert ei.value.reason_code == "enrollment_health_incomplete"


def test_resume_short_circuits_an_already_healthy_enrollment():
    cpriv, cpub = generate_keypair()
    store = InMemoryWorkerEnrollmentStateStore()
    inv = _invitation(cpub)
    store.record(inv.enrollment_id, "healthy")
    # a sealed driver would fail if it tried to bind — resume must short-circuit before transport
    driver = WorkerEnrollmentDriver(state_store=store)
    outcome = driver.enroll(inv, now=NOW)
    assert outcome.already_healthy is True and outcome.state == "healthy"


# --- invitation validation -----------------------------------------------------------------------


def test_an_expired_invitation_is_refused():
    cpriv, cpub = generate_keypair()
    driver = _driver(cpriv, cpub)
    inv = _invitation(cpub, expires_at="2000-01-01T00:00:00+00:00")
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(inv, now=NOW)
    assert ei.value.reason_code == "enrollment_invitation_expired"
