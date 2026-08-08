"""The ownership claim is a NEW signed kind, not a changed one.

The whole reason it is a separate ``kind`` rather than three more fields on the controller offer is
that the offer's ``/v1`` schema identifier must keep meaning exactly what it meant. These tests pin
that: the offer's canonical bytes are unchanged, and the two kinds can never be substituted for each
other.
"""

from __future__ import annotations

import pytest
from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    OFFER_KIND,
    OFFER_SCHEMA,
    OWNERSHIP_KIND,
    OWNERSHIP_SCHEMA,
    AttestationError,
    attestation_message,
    claim_digest,
    controller_offer_claim,
    controller_ownership_claim,
    sign_detached,
    verify_detached,
)
from secp_management.signing import generate_keypair

DIGEST = "sha256:" + "a" * 64


def _ownership(**over) -> dict:
    base = dict(
        organization_id="11111111-1111-1111-1111-111111111111",
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id="sha256:" + "c" * 64,
        controller_origin="https://ctrl.example.test",
        controller_trust_anchor_id="sha256:" + "d" * 64,
        worker_key_id="sha256:" + "w" * 64,
        enrollment_id="sha256:" + "1" * 64,
        invitation_id="sha256:" + "2" * 64,
        controller_transaction_id="txn-0001",
        release_digest="sha256:" + "r" * 64,
        predecessor_digest="sha256:" + "p" * 64,
    )
    base.update(over)
    return controller_ownership_claim(**base)


def test_the_offer_claim_is_byte_for_byte_unchanged():
    """The `/v1` offer identifier still covers exactly the fields it always covered.

    This is the property that would be quietly false if the ownership fields had been bolted onto
    `OFFER_SCHEMA`: every existing statement about signed-byte compatibility, and every historical
    signature, depends on it.
    """
    offer = controller_offer_claim(
        enrollment_id="sha256:" + "1" * 64,
        invitation_id="sha256:" + "2" * 64,
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id="sha256:" + "c" * 64,
        controller_origin="https://ctrl.example.test",
        controller_transaction_id="txn-0001",
        worker_installation_id="worker-aaaaaaaa",
        worker_key_id="sha256:" + "w" * 64,
        release_digest="sha256:" + "r" * 64,
        expires_at="2999-01-01T00:00:00+00:00",
        predecessor_digest="sha256:" + "p" * 64,
    )
    assert offer["schema"] == OFFER_SCHEMA
    assert set(offer) == {
        "schema",
        "enrollment_id",
        "invitation_id",
        "controller_installation_id",
        "controller_key_id",
        "controller_origin",
        "controller_transaction_id",
        "worker_installation_id",
        "worker_key_id",
        "release_digest",
        "expires_at",
        "predecessor_digest",
    }
    # and it carries NONE of the ownership-only facts
    for absent in ("organization_id", "controller_trust_anchor_id"):
        assert absent not in offer


def test_the_ownership_claim_carries_the_facts_the_offer_cannot_authenticate():
    claim = _ownership()
    assert claim["schema"] == OWNERSHIP_SCHEMA
    assert claim["organization_id"]
    assert claim["controller_trust_anchor_id"]


def test_the_two_kinds_produce_different_signed_bytes():
    """Domain separation, at the byte level.

    Identical digests under different kinds must not collide, or an offer signature could be
    presented as an ownership signature.
    """
    offer_bytes = attestation_message(
        domain=ENROLLMENT_ATTESTATION_DOMAIN, kind=OFFER_KIND, digest=DIGEST
    )
    ownership_bytes = attestation_message(
        domain=ENROLLMENT_ATTESTATION_DOMAIN, kind=OWNERSHIP_KIND, digest=DIGEST
    )
    assert offer_bytes != ownership_bytes


def test_an_offer_signature_cannot_be_replayed_as_an_ownership_signature():
    """The attack the separate kind exists to prevent, exercised end to end with real signatures."""
    priv, pub = generate_keypair()
    signed_as_offer = sign_detached(
        priv, domain=ENROLLMENT_ATTESTATION_DOMAIN, kind=OFFER_KIND, digest=DIGEST
    )
    # it verifies as what it is...
    verify_detached(
        signed_as_offer,
        expected_key_id=signed_as_offer.key_id,
        domain=ENROLLMENT_ATTESTATION_DOMAIN,
        kind=OFFER_KIND,
        digest=DIGEST,
    )
    # ...and not as what it is not
    with pytest.raises(AttestationError):
        verify_detached(
            signed_as_offer,
            expected_key_id=signed_as_offer.key_id,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=OWNERSHIP_KIND,
            digest=DIGEST,
        )


@pytest.mark.parametrize(
    "field",
    [
        "organization_id",
        "controller_installation_id",
        "controller_key_id",
        "controller_origin",
        "controller_trust_anchor_id",
        "worker_key_id",
        "enrollment_id",
        "invitation_id",
        "controller_transaction_id",
        "release_digest",
        "predecessor_digest",
    ],
)
def test_every_field_is_inside_the_signature(field):
    """A field outside the digest is a field an attacker may change freely.

    Asserted per field rather than once, because the failure mode is one field being dropped from
    the canonical builder — which a single whole-claim comparison would still catch, but would not
    tell you WHICH.
    """
    baseline = claim_digest(_ownership())
    assert claim_digest(_ownership(**{field: "something-else"})) != baseline


def test_the_trust_anchor_is_what_makes_this_claim_worth_having():
    """Named explicitly: without this field the claim adds nothing the offer did not already bind.

    A proxying attacker presents the real controller's key id and forwards the exchange, so every
    other field in this claim is one the real controller would have signed anyway.
    """
    baseline = claim_digest(_ownership())
    swapped = claim_digest(_ownership(controller_trust_anchor_id="sha256:" + "e" * 64))
    assert swapped != baseline
