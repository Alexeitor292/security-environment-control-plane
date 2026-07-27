"""Controller-side verification of worker enrollment evidence (SECP-PR5H-B1, T2).

Proves the controller verifies a worker's proof-of-possession / signed result by reconstructing the
canonical claim from its OWN authoritative invitation fields (never the worker's echo) and checking
the detached Ed25519 signature — accepting a genuine PoP and refusing a forged signature, an
unpinned/substituted key, or a worker that agreed to different invitation values.
"""

from __future__ import annotations

import pytest
from secp_api.enrollment_evidence import (
    verify_worker_binding_pop,
    verify_worker_result,
)
from secp_api.errors import WorkerEnrollmentError
from secp_commissioning import enrollment_attestation as ea
from secp_management.signing import generate_keypair

# the AUTHORITATIVE invitation the controller holds
INV = dict(
    enrollment_id="sha256:" + "a" * 64,
    invitation_id="sha256:" + "b" * 64,
    controller_installation_id="controller-aaaaaaaa",
    controller_key_id="sha256:" + "c" * 64,
    controller_transaction_id="txn-0001",
    release_digest="sha256:" + "d" * 64,
    expires_at="2026-07-21T01:00:00+00:00",
)


def _worker_pop(priv, pub, **override_claim):
    kid = ea.key_id_for(pub)
    fields = dict(
        enrollment_id=INV["enrollment_id"],
        invitation_id=INV["invitation_id"],
        controller_installation_id=INV["controller_installation_id"],
        controller_key_id=INV["controller_key_id"],
        controller_transaction_id=INV["controller_transaction_id"],
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id=kid,
        release_digest=INV["release_digest"],
        expires_at=INV["expires_at"],
    )
    fields.update(override_claim)
    claim = ea.worker_binding_claim(**fields)
    return ea.sign_detached(
        priv,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.POP_KIND,
        digest=ea.claim_digest(claim),
    )


def test_a_genuine_binding_pop_verifies_and_returns_the_possessed_worker_key():
    priv, pub = generate_keypair()
    att = _worker_pop(priv, pub)
    verified = verify_worker_binding_pop(
        **INV, worker_installation_id="worker-bbbbbbbb", worker_public_key_hex=pub, attestation=att
    )
    assert verified.worker_key_id == ea.key_id_for(pub)
    assert verified.worker_installation_id == "worker-bbbbbbbb"


def test_a_worker_that_signed_a_different_release_is_refused():
    # the worker signed a claim binding a DIFFERENT release; the controller rebuilds the claim from
    # its AUTHORITATIVE release, so the digest differs and the signature no longer verifies
    priv, pub = generate_keypair()
    att = _worker_pop(priv, pub, release_digest="sha256:" + "9" * 64)
    with pytest.raises(WorkerEnrollmentError) as ei:
        verify_worker_binding_pop(
            **INV,
            worker_installation_id="worker-bbbbbbbb",
            worker_public_key_hex=pub,
            attestation=att,
        )
    assert ei.value.code == "enrollment_pop_invalid"


def test_a_substituted_public_key_is_refused():
    priv, pub = generate_keypair()
    _, other_pub = generate_keypair()
    att = _worker_pop(priv, pub)
    # present a DIFFERENT public key than the one that signed -> derived key id/pin mismatch
    with pytest.raises(WorkerEnrollmentError) as ei:
        verify_worker_binding_pop(
            **INV,
            worker_installation_id="worker-bbbbbbbb",
            worker_public_key_hex=other_pub,
            attestation=att,
        )
    assert ei.value.code == "enrollment_pop_invalid"


def test_a_tampered_signature_is_refused():
    priv, pub = generate_keypair()
    att = _worker_pop(priv, pub)
    forged = ea.DetachedAttestation(
        algorithm=att.algorithm,
        key_id=att.key_id,
        public_key_hex=att.public_key_hex,
        signature=("0" * 128),
    )
    with pytest.raises(WorkerEnrollmentError) as ei:
        verify_worker_binding_pop(
            **INV,
            worker_installation_id="worker-bbbbbbbb",
            worker_public_key_hex=pub,
            attestation=forged,
        )
    assert ei.value.code == "enrollment_pop_invalid"


def test_a_malformed_public_key_is_refused_without_raising_raw():
    priv, pub = generate_keypair()
    att = _worker_pop(priv, pub)
    with pytest.raises(WorkerEnrollmentError) as ei:
        verify_worker_binding_pop(
            **INV,
            worker_installation_id="worker-bbbbbbbb",
            worker_public_key_hex="zz",
            attestation=att,
        )
    assert ei.value.code == "enrollment_pop_invalid"


_RESULT_EVIDENCE = dict(
    health_evidence_digest="sha256:" + "f" * 64,
    generation="2",
    challenge="sha256:" + "1" * 64,
)


def test_a_signed_worker_result_verifies_and_rejects_a_wrong_bound_key():
    priv, pub = generate_keypair()
    kid = ea.key_id_for(pub)
    claim = ea.worker_result_claim(
        enrollment_id=INV["enrollment_id"],
        controller_transaction_id=INV["controller_transaction_id"],
        worker_key_id=kid,
        predecessor_digest="sha256:" + "e" * 64,
        release_digest=INV["release_digest"],
        outcome="ready",
        **_RESULT_EVIDENCE,
    )
    att = ea.sign_detached(
        priv,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.RESULT_KIND,
        digest=ea.claim_digest(claim),
    )
    # verifies against the bound key
    verify_worker_result(
        enrollment_id=INV["enrollment_id"],
        controller_transaction_id=INV["controller_transaction_id"],
        predecessor_digest="sha256:" + "e" * 64,
        release_digest=INV["release_digest"],
        outcome="ready",
        bound_worker_key_id=kid,
        worker_public_key_hex=pub,
        attestation=att,
        **_RESULT_EVIDENCE,
    )
    # a result signed by a worker whose key is NOT the bound key is refused
    with pytest.raises(WorkerEnrollmentError) as ei:
        verify_worker_result(
            enrollment_id=INV["enrollment_id"],
            controller_transaction_id=INV["controller_transaction_id"],
            predecessor_digest="sha256:" + "e" * 64,
            release_digest=INV["release_digest"],
            outcome="ready",
            bound_worker_key_id="sha256:" + "7" * 64,
            worker_public_key_hex=pub,
            attestation=att,
            **_RESULT_EVIDENCE,
        )
    assert ei.value.code == "enrollment_pop_invalid"


def test_a_result_with_swapped_health_evidence_digest_is_refused():
    # the worker signed over one health-evidence digest; the controller rebuilds the claim with the
    # digest it recomputed from the RECEIVED evidence, so a swapped evidence body fails verification
    priv, pub = generate_keypair()
    kid = ea.key_id_for(pub)
    claim = ea.worker_result_claim(
        enrollment_id=INV["enrollment_id"],
        controller_transaction_id=INV["controller_transaction_id"],
        worker_key_id=kid,
        predecessor_digest="sha256:" + "e" * 64,
        release_digest=INV["release_digest"],
        outcome="ready",
        **_RESULT_EVIDENCE,
    )
    att = ea.sign_detached(
        priv,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.RESULT_KIND,
        digest=ea.claim_digest(claim),
    )
    with pytest.raises(WorkerEnrollmentError) as ei:
        verify_worker_result(
            enrollment_id=INV["enrollment_id"],
            controller_transaction_id=INV["controller_transaction_id"],
            predecessor_digest="sha256:" + "e" * 64,
            release_digest=INV["release_digest"],
            outcome="ready",
            bound_worker_key_id=kid,
            worker_public_key_hex=pub,
            attestation=att,
            health_evidence_digest="sha256:" + "0" * 64,  # controller recomputed a DIFFERENT digest
            generation="2",
            challenge="sha256:" + "1" * 64,
        )
    assert ei.value.code == "enrollment_pop_invalid"


def _controller_offer(priv, pub, **override):
    """A controller-signed offer under the pinned controller key ``pub``."""
    fields = dict(
        enrollment_id=INV["enrollment_id"],
        invitation_id=INV["invitation_id"],
        controller_installation_id=INV["controller_installation_id"],
        controller_key_id=ea.key_id_for(pub),
        controller_origin="https://controller.example.com",
        controller_transaction_id=INV["controller_transaction_id"],
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id="sha256:" + "9" * 64,
        release_digest=INV["release_digest"],
        expires_at=INV["expires_at"],
        predecessor_digest="sha256:" + "e" * 64,
    )
    fields.update(override)
    claim = ea.controller_offer_claim(**fields)
    att = ea.sign_detached(
        priv,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.OFFER_KIND,
        digest=ea.claim_digest(claim),
    )
    return fields, att


def test_a_genuine_controller_offer_reverifies_under_the_pinned_key():
    from secp_api.enrollment_evidence import verify_controller_offer

    priv, pub = generate_keypair()
    fields, att = _controller_offer(priv, pub)
    verified = verify_controller_offer(attestation=att, **fields)
    assert verified.controller_key_id == ea.key_id_for(pub)
    assert verified.claim["schema"] == ea.OFFER_SCHEMA


def test_a_controller_offer_signed_by_the_wrong_key_is_signer_unavailable():
    from secp_api.enrollment_evidence import verify_controller_offer

    priv, pub = generate_keypair()
    other_priv, _ = generate_keypair()
    fields, _ = _controller_offer(priv, pub)
    # sign the SAME claim with a different key than the pinned controller_key_id
    claim = ea.controller_offer_claim(**fields)
    forged = ea.sign_detached(
        other_priv,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.OFFER_KIND,
        digest=ea.claim_digest(claim),
    )
    with pytest.raises(WorkerEnrollmentError) as ei:
        verify_controller_offer(attestation=forged, **fields)
    assert ei.value.code == "enrollment_signer_unavailable"
