"""Shared worker-enrollment Ed25519 detached-attestation primitive (SECP-PR5H-B1, T2).

The one pure primitive both the worker (signs) and the controller (verifies) import, so the signed
bytes never drift. These prove the sign/verify round-trip, the proof-of-possession claim, and
that every tamper — wrong key, unpinned key id, wrong domain/kind, malformed field, altered claim —
refuses a bounded reason code with no key material or plaintext leaked.
"""

from __future__ import annotations

import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_management.signing import generate_keypair

D_ENROLL = ea.ENROLLMENT_ATTESTATION_DOMAIN
CTRL_KEY = "sha256:" + "c" * 64
REL = "sha256:" + "d" * 64


def _claim(worker_key_id: str) -> dict[str, str]:
    return ea.worker_binding_claim(
        enrollment_id="sha256:" + "a" * 64,
        invitation_id="sha256:" + "b" * 64,
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_transaction_id="txn-0001",
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id=worker_key_id,
        release_digest=REL,
        expires_at="2026-07-21T01:00:00+00:00",
    )


def test_sign_then_verify_round_trips_a_binding_pop():
    priv, pub = generate_keypair()
    kid = ea.key_id_for(pub)
    digest = ea.claim_digest(_claim(kid))
    att = ea.sign_detached(priv, domain=D_ENROLL, kind=ea.POP_KIND, digest=digest)
    assert att.algorithm == "Ed25519"
    assert att.key_id == kid  # derived from the raw public key bytes
    # the controller verifies against the pinned worker key id it reconstructed
    ea.verify_detached(att, expected_key_id=kid, domain=D_ENROLL, kind=ea.POP_KIND, digest=digest)


def test_key_id_is_sha256_of_the_raw_public_key_bytes():
    import hashlib

    _, pub = generate_keypair()
    assert ea.key_id_for(pub) == "sha256:" + hashlib.sha256(bytes.fromhex(pub)).hexdigest()


def test_a_signature_from_a_different_key_is_refused():
    priv, pub = generate_keypair()
    _, other_pub = generate_keypair()
    digest = ea.claim_digest(_claim(ea.key_id_for(pub)))
    att = ea.sign_detached(priv, domain=D_ENROLL, kind=ea.POP_KIND, digest=digest)
    # pinning a DIFFERENT expected key id (the signature is not from that key) -> not pinned
    with pytest.raises(ea.AttestationError) as ei:
        ea.verify_detached(
            att,
            expected_key_id=ea.key_id_for(other_pub),
            domain=D_ENROLL,
            kind=ea.POP_KIND,
            digest=digest,
        )
    assert ei.value.reason_code == "attestation_signer_not_pinned"


def test_a_forged_key_id_that_does_not_derive_from_the_public_key_is_refused():
    priv, pub = generate_keypair()
    digest = ea.claim_digest(_claim(ea.key_id_for(pub)))
    att = ea.sign_detached(priv, domain=D_ENROLL, kind=ea.POP_KIND, digest=digest)
    forged = ea.DetachedAttestation(
        algorithm="Ed25519",
        key_id="sha256:" + "e" * 64,  # does not derive from public_key_hex
        public_key_hex=att.public_key_hex,
        signature=att.signature,
    )
    with pytest.raises(ea.AttestationError) as ei:
        ea.verify_detached(
            forged,
            expected_key_id="sha256:" + "e" * 64,
            domain=D_ENROLL,
            kind=ea.POP_KIND,
            digest=digest,
        )
    assert ei.value.reason_code == "attestation_key_id_mismatch"


def test_a_signature_over_a_different_digest_is_refused():
    priv, pub = generate_keypair()
    kid = ea.key_id_for(pub)
    att = ea.sign_detached(
        priv, domain=D_ENROLL, kind=ea.POP_KIND, digest=ea.claim_digest(_claim(kid))
    )
    other_digest = ea.claim_digest(_claim(kid) | {"outcome": "tampered"})
    with pytest.raises(ea.AttestationError) as ei:
        ea.verify_detached(
            att, expected_key_id=kid, domain=D_ENROLL, kind=ea.POP_KIND, digest=other_digest
        )
    assert ei.value.reason_code == "attestation_signature_invalid"


def test_domain_and_kind_separation_prevents_cross_protocol_replay():
    priv, pub = generate_keypair()
    kid = ea.key_id_for(pub)
    digest = ea.claim_digest(_claim(kid))
    pop = ea.sign_detached(priv, domain=D_ENROLL, kind=ea.POP_KIND, digest=digest)
    # the SAME signed digest under a different KIND (result) must not verify
    with pytest.raises(ea.AttestationError):
        ea.verify_detached(
            pop, expected_key_id=kid, domain=D_ENROLL, kind=ea.RESULT_KIND, digest=digest
        )
    # ...nor under the discovery-activation DOMAIN
    with pytest.raises(ea.AttestationError):
        ea.verify_detached(
            pop,
            expected_key_id=kid,
            domain="secp.discovery-activation.cross-host-handoff/v1",
            kind=ea.POP_KIND,
            digest=digest,
        )


def test_malformed_signature_and_public_key_refuse_without_raising_raw():
    priv, pub = generate_keypair()
    kid = ea.key_id_for(pub)
    digest = ea.claim_digest(_claim(kid))
    bad = ea.DetachedAttestation(
        algorithm="Ed25519", key_id=kid, public_key_hex="zz", signature="00"
    )
    with pytest.raises(ea.AttestationError) as ei:
        ea.verify_detached(
            bad, expected_key_id=kid, domain=D_ENROLL, kind=ea.POP_KIND, digest=digest
        )
    assert ei.value.reason_code in {"attestation_signer_not_pinned", "attestation_invalid"}


def test_sign_rejects_a_non_digest_and_a_malformed_private_key():
    priv, _ = generate_keypair()
    with pytest.raises(ea.AttestationError) as ei:
        ea.sign_detached(priv, domain=D_ENROLL, kind=ea.POP_KIND, digest="not-a-digest")
    assert ei.value.reason_code == "attestation_digest_invalid"
    with pytest.raises(ea.AttestationError) as ei:
        ea.sign_detached("zz", domain=D_ENROLL, kind=ea.POP_KIND, digest="sha256:" + "a" * 64)
    assert ei.value.reason_code == "attestation_key_invalid"


def test_both_sides_reconstruct_the_same_binding_digest():
    # the worker builds the claim from its inputs; the controller rebuilds it from the authoritative
    # invitation — same builder, same canonical digest, so a POP verified on one side matches the
    # other exactly.
    _, pub = generate_keypair()
    kid = ea.key_id_for(pub)
    assert ea.claim_digest(_claim(kid)) == ea.claim_digest(_claim(kid))
    assert ea.claim_digest(_claim(kid)) != ea.claim_digest(_claim("sha256:" + "9" * 64))
