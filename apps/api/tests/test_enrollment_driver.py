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
    HealthObservationContext,
    InMemoryWorkerEnrollmentStateStore,
    ObservedHealthEvidence,
    SealedWorkerEnrollmentHealthObserver,
    WorkerEnrollmentDriver,
    WorkerEnrollmentDriverError,
)
from secp_worker.enrollment_http_transport import (
    EnrollmentInvitationInputs,
    EnrollmentTransportError,
    WorkerEnrollmentSigner,
)
from secp_worker.enrollment_key import WORKER_ENROLLMENT_ROOT

NOW = "2026-07-26T00:00:00+00:00"
FUTURE = "2999-01-01T00:00:00+00:00"


def _self_signed_ca(common_name: str = "secp-test-ca") -> str:
    """A REAL parseable CA. The transport is still a double — no socket is opened.

    It has to be real now: the ownership claim binds the trust-anchor identity, and that identity is
    derived by PARSING the bundle. The previous grammar-valid placeholder could not be parsed, so a
    fake CA would make the anchor comparison untestable — and that comparison is the one thing
    closing CA substitution.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


CA_PEM = _self_signed_ca()
#: A DIFFERENT real CA — what a proxying attacker would terminate TLS with.
ATTACKER_CA_PEM = _self_signed_ca("attacker-ca")


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
        controller_ca_bundle_pem=CA_PEM,
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
        result_enrollment: dict | None = None,
        organization_id: str = "11111111-1111-1111-1111-111111111111",
        trust_anchor_id: str | None = None,
        ownership_signer_priv: str | None = None,
        omit_ownership: bool = False,
    ) -> None:
        self._signer = signer
        self._controller_priv = controller_priv
        self._controller_pub = controller_pub
        # a distinct key to mint the offer with (to exercise the pinned-key refusal)
        self._offer_priv = offer_signer_priv or controller_priv
        self._offer_field_override = offer_field_override or {}
        self._transient_binds = transient_binds
        self._result_status = result_status
        # the AUTHORITATIVE enrollment head the controller reports on the result (default healthy)
        self._result_enrollment = result_enrollment or {"state": "healthy", "revision": 5}
        self._organization_id = organization_id
        # `trust_anchor_id` overrides the honestly-derived anchor, so a test can simulate a
        # CA-swapping proxy: the claim says one anchor, the worker computes another.
        self._trust_anchor_id = trust_anchor_id
        self._ownership_priv = ownership_signer_priv
        self._omit_ownership = omit_ownership

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
        # The controller ALSO mints the domain-separated ownership claim, binding the two facts
        # the offer cannot: the organization and the TLS trust anchor the worker must keep seeing.
        from secp_commissioning.trust_anchor import trust_anchor_id_for

        ownership_claim = ea.controller_ownership_claim(
            organization_id=self._organization_id,
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_origin=invitation.controller_origin,
            controller_trust_anchor_id=(
                self._trust_anchor_id
                if self._trust_anchor_id is not None
                else trust_anchor_id_for(invitation.controller_ca_bundle_pem)
            ),
            worker_key_id=self._signer.worker_key_id,
            enrollment_id=invitation.enrollment_id,
            invitation_id=invitation.invitation_id,
            controller_transaction_id=invitation.controller_transaction_id,
            release_digest=invitation.release_digest,
            predecessor_digest="sha256:" + "b" * 64,
        )
        ownership_att = ea.sign_detached(
            self._ownership_priv or self._offer_priv,
            domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
            kind=ea.OWNERSHIP_KIND,
            digest=ea.claim_digest(ownership_claim),
        )
        body = {
            "signed_offer": signed_offer,
            "enrollment": {"state": "offer_transported", "revision": 2},
        }
        if not self._omit_ownership:
            body["signed_ownership"] = {
                "claim": ownership_claim,
                "attestation": {
                    "algorithm": ownership_att.algorithm,
                    "key_id": ownership_att.key_id,
                    "public_key_hex": ownership_att.public_key_hex,
                    "signature": ownership_att.signature,
                },
            }
        return 200, body

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
        # the AUTHORITATIVE current head the controller reports (default healthy; overridable to
        # simulate a revoked/advanced enrollment on a reconciling resume)
        return 200, {"enrollment": self._result_enrollment}


class _FakeObserver:
    """An inspectable health observer for tests: returns a controllable evidence structure and
    (optionally) records the context it was called with. It is NEVER a blind all-true helper — the
    checks are supplied explicitly."""

    def __init__(self, *, checks: dict | None = None, seen: list | None = None) -> None:
        self._checks = checks
        self._seen = seen

    def observe(self, context: HealthObservationContext) -> ObservedHealthEvidence:
        if self._seen is not None:
            self._seen.append(context)
        checks = (
            self._checks
            if self._checks is not None
            else dict.fromkeys(ea.REQUIRED_HEALTH_CHECKS, True)
        )
        return ObservedHealthEvidence(checks=checks)


class _KeySeam:
    def __init__(self, priv_hex: str) -> None:
        self._priv = priv_hex

    def load_or_create(self) -> WorkerEnrollmentSigner:
        return WorkerEnrollmentSigner(self._priv)


def _ownership_fs():
    """A REAL hardened in-memory filesystem, not a stub.

    The ownership gate is fail-closed by design: a driver with no store refuses. Tests therefore
    supply a store EXPLICITLY rather than the production default being loosened — there is no
    `allow_unowned` switch and there must never be one.
    """
    from secp_commissioning.runtime import InMemoryFilesystem

    fs = InMemoryFilesystem()
    fs.makedir(WORKER_ENROLLMENT_ROOT, uid=0, gid=0, mode=0o700)
    return fs


def _expected(controller_pub: str) -> str:
    """The independent first-contact trust fact an UNOWNED worker requires.

    Derived from the controller's public key the test generated — i.e. from the operator channel,
    NOT from the invitation. `test_the_first_contact_trust_fact_cannot_come_from_the_invitation`
    asserts that distinction structurally.
    """
    return ea.key_id_for(controller_pub)


def _driver(
    controller_priv,
    controller_pub,
    *,
    state_store=None,
    health_observer=None,
    ownership_store=None,
    **fake_kw,
) -> WorkerEnrollmentDriver:
    wpriv, _wpub = generate_keypair()
    return WorkerEnrollmentDriver(
        ownership_store=ownership_store if ownership_store is not None else _ownership_fs(),
        key_seam=_KeySeam(wpriv),
        transport_factory=lambda signer, _invitation: _FakeController(
            signer, controller_priv=controller_priv, controller_pub=controller_pub, **fake_kw
        ),
        state_store=state_store or InMemoryWorkerEnrollmentStateStore(),
        # a real (inspectable) observer whose observations are supplied explicitly — never a blind
        # all-true helper. Individual tests override it to exercise sealed / failed observations.
        health_observer=health_observer or _FakeObserver(),
    )


# --- the per-invitation transport seam (CA travels in the invitation) ----------------------------


def test_the_transport_is_built_from_the_invitation_being_enrolled():
    """The factory takes the invitation because the origin and CA chain are per-invitation values.
    A factory that ignored it could only ever have been built from stale construction-time input."""
    cpriv, cpub = generate_keypair()
    wpriv, _ = generate_keypair()
    invitation = _invitation(cpub)
    seen: list[EnrollmentInvitationInputs] = []

    def factory(signer, built_for):
        seen.append(built_for)
        return _FakeController(signer, controller_priv=cpriv, controller_pub=cpub)

    WorkerEnrollmentDriver(
        ownership_store=_ownership_fs(),
        key_seam=_KeySeam(wpriv),
        transport_factory=factory,
        state_store=InMemoryWorkerEnrollmentStateStore(),
        health_observer=_FakeObserver(),
    ).enroll(invitation, now=NOW, expected_controller_key_id=_expected(cpub))

    assert seen == [invitation]
    assert seen[0].controller_ca_bundle_pem == CA_PEM


def test_two_enrollments_get_two_transports_and_never_share_one():
    """The driver is long-lived and `enroll()` is per-invitation. If a transport were cached across
    invitations, invitation A's binding could be posted to invitation B's controller."""
    cpriv, cpub = generate_keypair()
    wpriv, _ = generate_keypair()
    built: list[tuple] = []

    def factory(signer, built_for):
        controller = _FakeController(signer, controller_priv=cpriv, controller_pub=cpub)
        built.append((built_for, controller))
        return controller

    driver = WorkerEnrollmentDriver(
        ownership_store=_ownership_fs(),
        key_seam=_KeySeam(wpriv),
        transport_factory=factory,
        state_store=InMemoryWorkerEnrollmentStateStore(),
        health_observer=_FakeObserver(),
    )
    first = _invitation(cpub)
    second = _invitation(cpub, enrollment_id="sha256:" + "3" * 64)
    driver.enroll(first, now=NOW, expected_controller_key_id=_expected(cpub))
    driver.enroll(second, now=NOW, expected_controller_key_id=_expected(cpub))

    assert [b[0] for b in built] == [first, second]
    assert built[0][1] is not built[1][1]  # never reused across invitations


def test_an_invitation_without_a_ca_chain_refuses_before_any_transport_is_built():
    """The CA is the worker's ONLY server-TLS trust anchor, so an invitation without one cannot
    produce a verifying transport. Checked in the driver, so a programmatic caller that bypasses the
    CLI's file validation cannot skip it."""
    cpriv, cpub = generate_keypair()
    wpriv, _ = generate_keypair()
    built = []

    driver = WorkerEnrollmentDriver(
        ownership_store=_ownership_fs(),
        key_seam=_KeySeam(wpriv),
        transport_factory=lambda s, i: (
            built.append(i) or _FakeController(s, controller_priv=cpriv, controller_pub=cpub)
        ),
        state_store=InMemoryWorkerEnrollmentStateStore(),
        health_observer=_FakeObserver(),
    )

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(
            _invitation(cpub, controller_ca_bundle_pem="   "),
            now=NOW,
            expected_controller_key_id=_expected(cpub),
        )

    assert ei.value.reason_code == "enrollment_invitation_ca_missing"
    assert built == []  # refused before anything was constructed


# --- happy path ----------------------------------------------------------------------------------


def test_driver_reaches_healthy_over_the_supported_exchange():
    cpriv, cpub = generate_keypair()
    outcome = _driver(cpriv, cpub).enroll(
        _invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub)
    )
    assert isinstance(outcome, DriverOutcome)
    assert outcome.state == "healthy" and outcome.revision == 5
    assert outcome.already_healthy is False


# --- sealed defaults -----------------------------------------------------------------------------


def test_the_sealed_key_seam_default_fails_closed():
    cpriv, cpub = generate_keypair()
    driver = WorkerEnrollmentDriver(ownership_store=_ownership_fs())  # both seams sealed
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_worker_key_sealed"


def test_the_sealed_transport_default_fails_closed():
    wpriv, _ = generate_keypair()
    cpriv, cpub = generate_keypair()
    driver = WorkerEnrollmentDriver(
        ownership_store=_ownership_fs(),
        key_seam=_KeySeam(wpriv),
    )  # sealed transport factory
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_transport_not_activated"


# --- offer verification --------------------------------------------------------------------------


def test_an_offer_signed_by_a_non_pinned_key_is_refused():
    cpriv, cpub = generate_keypair()
    other_priv, _ = generate_keypair()
    driver = _driver(cpriv, cpub, offer_signer_priv=other_priv)  # offer signed by the WRONG key
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_offer_signature_invalid"


def test_an_offer_bound_to_a_different_release_is_refused():
    cpriv, cpub = generate_keypair()
    # override the offer's release_digest AFTER it is signed-consistent, so the signature is valid
    # but the field pin against the invitation fails
    driver = _driver(cpriv, cpub, offer_field_override={"release_digest": "sha256:" + "9" * 64})
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_offer_binding_mismatch"


# --- retry + resume ------------------------------------------------------------------------------


def test_a_transient_bind_failure_is_retried_then_succeeds():
    cpriv, cpub = generate_keypair()
    outcome = _driver(cpriv, cpub, transient_binds=2).enroll(
        _invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub)
    )
    assert outcome.state == "healthy"


def test_a_persistent_transport_failure_refuses_after_bounded_retries():
    cpriv, cpub = generate_keypair()
    outcome_driver = _driver(cpriv, cpub, transient_binds=99)  # always fails
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        outcome_driver.enroll(
            _invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub)
        )
    assert ei.value.reason_code == "enrollment_transport_failed"


def test_a_4xx_result_is_refused_with_the_bounded_controller_code():
    cpriv, cpub = generate_keypair()
    driver = _driver(cpriv, cpub, result_status=422)
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_health_incomplete"


def test_resume_reconciles_healthy_from_the_controller_not_a_hard_coded_marker():
    """C3: a healthy marker is only a hint — the driver RE-DRIVES and returns the controller's
    AUTHORITATIVE state/revision (here revision 7, not a hard-coded 5)."""
    cpriv, cpub = generate_keypair()
    store = InMemoryWorkerEnrollmentStateStore()
    inv = _invitation(cpub)
    store.record(inv.enrollment_id, "healthy")
    driver = _driver(
        cpriv, cpub, state_store=store, result_enrollment={"state": "healthy", "revision": 7}
    )
    outcome = driver.enroll(inv, now=NOW, expected_controller_key_id=_expected(cpub))
    assert outcome.already_healthy is True
    assert outcome.state == "healthy" and outcome.revision == 7  # authoritative, not hard-coded 5


def test_resume_with_a_revoked_controller_state_is_never_reported_healthy():
    """C3: a stale 'healthy' marker does NOT win — if the controller now reports the enrollment
    refused (revoked), the driver reconciles and reports refused, never healthy."""
    cpriv, cpub = generate_keypair()
    store = InMemoryWorkerEnrollmentStateStore()
    inv = _invitation(cpub)
    store.record(inv.enrollment_id, "healthy")
    driver = _driver(
        cpriv, cpub, state_store=store, result_enrollment={"state": "refused", "revision": 6}
    )
    outcome = driver.enroll(inv, now=NOW, expected_controller_key_id=_expected(cpub))
    assert outcome.state == "refused" and outcome.revision == 6
    assert outcome.already_healthy is False


# --- C3: observed (never fabricated) health evidence ---------------------------------------------


def test_the_sealed_health_observer_default_fails_closed():
    cpriv, cpub = generate_keypair()
    driver = _driver(cpriv, cpub, health_observer=SealedWorkerEnrollmentHealthObserver())
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_worker_health_observer_sealed"


def test_a_failed_observation_refuses_healthy_and_submits_nothing():
    cpriv, cpub = generate_keypair()
    checks = dict.fromkeys(ea.REQUIRED_HEALTH_CHECKS, True)
    checks["no_provider_contact"] = False  # one real observation failed
    driver = _driver(cpriv, cpub, health_observer=_FakeObserver(checks=checks))
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_worker_health_incomplete"


def test_the_observer_sees_the_exchange_context_and_returns_only_booleans():
    cpriv, cpub = generate_keypair()
    seen: list = []
    inv = _invitation(cpub)
    driver = _driver(cpriv, cpub, health_observer=_FakeObserver(seen=seen))
    outcome = driver.enroll(inv, now=NOW, expected_controller_key_id=_expected(cpub))
    assert outcome.state == "healthy"
    assert len(seen) == 1
    ctx = seen[0]
    assert ctx.enrollment_id == inv.enrollment_id
    assert ctx.release_digest == inv.release_digest
    assert ctx.controller_transaction_id == inv.controller_transaction_id
    assert ctx.worker_key_id.startswith("sha256:")
    assert ctx.offer_claim_digest.startswith("sha256:")  # the verified offer's content address


def test_observed_evidence_rejects_a_malformed_structure():
    with pytest.raises(WorkerEnrollmentDriverError):
        ObservedHealthEvidence(checks={"only_one": True})  # not the required closed set
    with pytest.raises(WorkerEnrollmentDriverError):
        ObservedHealthEvidence(checks=dict.fromkeys(ea.REQUIRED_HEALTH_CHECKS, "yes"))  # non-bool


# --- invitation validation -----------------------------------------------------------------------


def test_an_expired_invitation_is_refused():
    cpriv, cpub = generate_keypair()
    driver = _driver(cpriv, cpub)
    inv = _invitation(cpub, expires_at="2000-01-01T00:00:00+00:00")
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(inv, now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_invitation_expired"


# === CA / trust-anchor substitution — the half #147 could not close ==============================


def test_a_proxying_attacker_who_swaps_the_ca_is_refused_and_persists_nothing():
    """THE test this slice exists for.

    The attacker presents the REAL controller's key id and forwards the exchange, so the offer
    signature verifies exactly as it should — that is what makes this attack invisible to every
    check that existed before. What it cannot do is make the controller sign an anchor for a CA the
    controller does not serve, so the worker's own computation disagrees.
    """
    from secp_worker.worker_ownership import load_worker_ownership

    cpriv, cpub = generate_keypair()
    fs = _ownership_fs()
    driver = _driver(
        cpriv,
        cpub,
        ownership_store=fs,
        # the claim names the anchor for a CA the worker is NOT actually using
        trust_anchor_id="sha256:" + "9" * 64,
    )
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_ownership_trust_anchor_mismatch"
    # nothing was written: a refused enrollment must not leave a half-claimed worker
    assert load_worker_ownership(fs) is None


def test_swapping_the_actual_ca_bundle_is_refused():
    """The same attack from the other direction: the claim is honest, the connection is not.

    Here the controller signs the anchor for the CA it really serves, and the worker was handed a
    DIFFERENT bundle — which is what a substituted invitation plus a terminating proxy looks like.
    """
    cpriv, cpub = generate_keypair()
    fs = _ownership_fs()
    controllers = []

    def factory(signer, invitation):
        # the controller signs the anchor of the REAL CA, not the one the worker was given
        c = _FakeController(
            signer,
            controller_priv=cpriv,
            controller_pub=cpub,
            trust_anchor_id=__import__(
                "secp_commissioning.trust_anchor", fromlist=["trust_anchor_id_for"]
            ).trust_anchor_id_for(CA_PEM),
        )
        controllers.append(c)
        return c

    wpriv, _ = generate_keypair()
    driver = WorkerEnrollmentDriver(
        ownership_store=fs,
        key_seam=_KeySeam(wpriv),
        transport_factory=factory,
        state_store=InMemoryWorkerEnrollmentStateStore(),
        health_observer=_FakeObserver(),
    )
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(
            _invitation(cpub, controller_ca_bundle_pem=ATTACKER_CA_PEM),
            now=NOW,
            expected_controller_key_id=_expected(cpub),
        )
    assert ei.value.reason_code == "enrollment_ownership_trust_anchor_mismatch"


def test_a_missing_ownership_claim_refuses():
    """A controller that does not sign ownership cannot enrol a worker.

    Fail-closed on absence, not "skip the check when it is not offered" — which is how an attacker
    downgrades a protocol by simply omitting the part that inconveniences them.
    """
    cpriv, cpub = generate_keypair()
    driver = _driver(cpriv, cpub, omit_ownership=True)
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_ownership_claim_missing"


def test_an_ownership_claim_signed_by_a_different_key_refuses():
    """The claim must be signed by the INDEPENDENTLY trusted controller key, like the offer."""
    cpriv, cpub = generate_keypair()
    other_priv, _other_pub = generate_keypair()
    driver = _driver(cpriv, cpub, ownership_signer_priv=other_priv)
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert ei.value.reason_code == "enrollment_ownership_claim_signature_invalid"


def test_a_successful_enrollment_pins_the_organization_and_the_trust_anchor():
    """The positive case: what actually gets written after the whole chain verifies."""
    from secp_commissioning.trust_anchor import trust_anchor_id_for
    from secp_worker.worker_ownership import load_worker_ownership

    cpriv, cpub = generate_keypair()
    fs = _ownership_fs()
    driver = _driver(cpriv, cpub, ownership_store=fs)
    outcome = driver.enroll(_invitation(cpub), now=NOW, expected_controller_key_id=_expected(cpub))
    assert outcome.state == "healthy"

    owner = load_worker_ownership(fs)
    assert owner is not None
    assert owner.organization_id == "11111111-1111-1111-1111-111111111111"
    # the pinned anchor is the one derived from the bundle actually in use
    assert owner.controller_trust_anchor_id == trust_anchor_id_for(CA_PEM)
    assert owner.controller_key_id == ea.key_id_for(cpub)
