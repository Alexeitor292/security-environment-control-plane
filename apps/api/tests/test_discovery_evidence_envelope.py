"""A signature over a binding, not a hash over a file.

The adversary model is a party who can write the `DiscoverySnapshot` row: they can recompute an
unkeyed content hash freely, so every test here asks whether they can also produce something the
control plane will accept as a worker's observation.
"""

from __future__ import annotations

import dataclasses

import pytest
from secp_api.discovery_evidence_envelope import (
    DISCOVERY_ATTESTATION_DOMAIN,
    ENVELOPE_KEY,
    SNAPSHOT_KIND,
    DiscoveryBinding,
    DiscoveryEnvelopeError,
    ProbeRecord,
    anchor_matches,
    binding_digest,
    canonical_binding,
    envelope_for_storage,
    facts_hash,
    sign_discovery_binding,
    verify_discovery_binding,
)
from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    POP_KIND,
    key_id_for,
    sign_detached,
)
from secp_management.signing import generate_keypair

FACTS = {
    "schema_version": 1,
    "version_major": 9,
    "version_minor": 1,
    "version_patch": 1,
    "node": "pve-node-1",
    "storages": [{"storage": "local-lvm", "avail_mb": 400000, "usable": True}],
}


def _keys() -> tuple[str, str]:
    return generate_keypair()


def _binding(priv: str, pub: str, **overrides) -> DiscoveryBinding:
    base = dict(
        discovery_document_version="secp-discovery/contract/v1",
        facts_hash=facts_hash(FACTS),
        target_identity="target-abc",
        cluster_identity="cluster-xyz",
        worker_installation_id="wk-0001",
        worker_role="proxmox_privileged",
        worker_release_fingerprint="sha256:" + "b" * 64,
        signing_key_fingerprint=key_id_for(pub),
        observation_started_at="2026-08-06T12:00:00+00:00",
        observation_completed_at="2026-08-06T12:00:30+00:00",
        freshness_bound_seconds=1800,
        probe_manifest=(
            ProbeRecord(
                probe_code="host_package_version",
                argv=("pveversion",),
                result_digest="sha256:" + "1" * 64,
                outcome="observed",
            ),
            ProbeRecord(
                probe_code="version",
                argv=("pvesh", "get", "/version", "--output-format", "json"),
                result_digest="sha256:" + "2" * 64,
                outcome="observed",
            ),
        ),
        projection_implementation_id="secp-discovery/projection/v1",
        observed_required_facts=("pve_version", "storage"),
        unobserved_required_facts=(("sdn_zones", "permission_denied"),),
    )
    base.update(overrides)
    return DiscoveryBinding(**base)


# --- the property the whole module exists for -----------------------------------------------------


def test_a_valid_envelope_verifies():
    priv, pub = _keys()
    binding = _binding(priv, pub)
    att = sign_discovery_binding(priv, binding)
    assert (
        verify_discovery_binding(binding, att, expected_key_id=key_id_for(pub), evidence=FACTS)
        == ()
    )


def test_a_recomputed_content_hash_does_not_authenticate_anything():
    """The defect being closed, stated as the attack.

    A party who can write the row recomputes the unkeyed hash freely. What they cannot do is
    produce a signature over the binding, and verification refuses without one.
    """
    priv, pub = _keys()
    binding = _binding(priv, pub)
    attacker_priv, attacker_pub = _keys()
    forged = sign_discovery_binding(
        attacker_priv,
        dataclasses.replace(binding, signing_key_fingerprint=key_id_for(attacker_pub)),
    )
    reasons = verify_discovery_binding(
        dataclasses.replace(binding, signing_key_fingerprint=key_id_for(attacker_pub)),
        forged,
        expected_key_id=key_id_for(pub),  # the control plane's own anchor, for the REAL worker
    )
    assert any("discovery_attestation_invalid" in r for r in reasons)


def test_no_trust_anchor_fails_closed():
    """A caller with no anchor cannot verify anything, and must not report "no objections"."""
    priv, pub = _keys()
    binding = _binding(priv, pub)
    att = sign_discovery_binding(priv, binding)
    assert verify_discovery_binding(binding, att, expected_key_id="") == (
        "discovery_evidence_no_trust_anchor",
    )


def test_the_anchor_must_come_from_the_control_plane_not_the_envelope():
    """An envelope that supplies its own expected key verifies itself.

    Demonstrated rather than asserted: signing with an unrelated key and then presenting THAT key's
    id as the expectation passes — which is exactly why `expected_key_id` must be read from
    WorkerIdentityRegistration.verification_anchor_fingerprint and never from the envelope.
    """
    other_priv, other_pub = _keys()
    binding = _binding(other_priv, other_pub)
    att = sign_discovery_binding(other_priv, binding)
    # Self-supplied anchor: verifies. This is the mistake the call site must not make.
    assert verify_discovery_binding(binding, att, expected_key_id=att.key_id) == ()
    # Control-plane anchor for a different worker: refuses.
    _p, real_pub = _keys()
    assert verify_discovery_binding(binding, att, expected_key_id=key_id_for(real_pub)) != ()


# --- tamper -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_identity", "target-other"),
        ("cluster_identity", "cluster-other"),
        ("worker_installation_id", "wk-9999"),
        ("worker_release_fingerprint", "sha256:" + "0" * 64),
        ("observation_completed_at", "2026-08-06T18:00:00+00:00"),
        ("freshness_bound_seconds", 86400),
        ("facts_hash", "sha256:" + "0" * 64),
        ("projection_implementation_id", "secp-discovery/projection/v0"),
        ("discovery_document_version", "secp-discovery/contract/v0"),
    ],
)
def test_editing_any_bound_field_breaks_the_signature(field, value):
    priv, pub = _keys()
    binding = _binding(priv, pub)
    att = sign_discovery_binding(priv, binding)
    tampered = dataclasses.replace(binding, **{field: value})
    reasons = verify_discovery_binding(tampered, att, expected_key_id=key_id_for(pub))
    assert any("discovery_attestation_invalid" in r for r in reasons), field


def test_editing_the_probe_manifest_breaks_the_signature():
    """The argv is evidence. A run that claims the version probe but executed something else must
    not verify."""
    priv, pub = _keys()
    binding = _binding(priv, pub)
    att = sign_discovery_binding(priv, binding)
    swapped = dataclasses.replace(
        binding,
        probe_manifest=(
            ProbeRecord(
                probe_code="version",
                argv=("pvesh", "set", "/cluster/sdn"),  # a mutating argv
                result_digest="sha256:" + "2" * 64,
                outcome="observed",
            ),
        ),
    )
    assert verify_discovery_binding(swapped, att, expected_key_id=key_id_for(pub)) != ()


def test_editing_an_unobserved_fact_state_breaks_the_signature():
    """A consumer must not be told a fact was merely absent when the producer recorded it as
    permission-denied — so the STATE is inside the signature, not beside it."""
    priv, pub = _keys()
    binding = _binding(priv, pub)
    att = sign_discovery_binding(priv, binding)
    softened = dataclasses.replace(
        binding, unobserved_required_facts=(("sdn_zones", "not_requested"),)
    )
    assert verify_discovery_binding(softened, att, expected_key_id=key_id_for(pub)) != ()


def test_a_valid_signature_cannot_be_reattached_to_different_facts():
    """The facts-hash check. Without it, a real signature over a real binding could be stored beside
    a substituted fact set and the envelope alone would still verify."""
    priv, pub = _keys()
    binding = _binding(priv, pub)
    att = sign_discovery_binding(priv, binding)
    other_facts = dict(FACTS, version_patch=9, node="pve-node-evil")
    reasons = verify_discovery_binding(
        binding, att, expected_key_id=key_id_for(pub), evidence=other_facts
    )
    assert "discovery_facts_hash_mismatch" in reasons


def test_the_signer_named_in_the_binding_must_be_the_signer():
    priv, pub = _keys()
    _other_priv, other_pub = _keys()
    with pytest.raises(DiscoveryEnvelopeError, match="different signing key"):
        sign_discovery_binding(
            priv, _binding(priv, pub, signing_key_fingerprint=key_id_for(other_pub))
        )


# --- cross-protocol replay ------------------------------------------------------------------------


def test_an_enrollment_attestation_cannot_verify_a_discovery_binding():
    """Domain separation, tested as the replay it prevents.

    This is why discovery gets its own DOMAIN rather than a new `kind` inside the enrollment
    domain: a worker's enrollment proof-of-possession must not be presentable as an observation of
    a cluster.
    """
    priv, pub = _keys()
    binding = _binding(priv, pub)
    enrollment_att = sign_detached(
        priv,
        domain=ENROLLMENT_ATTESTATION_DOMAIN,
        kind=POP_KIND,
        digest=binding_digest(binding),
    )
    assert verify_discovery_binding(binding, enrollment_att, expected_key_id=key_id_for(pub)) != ()


def test_the_discovery_domain_is_distinct_from_every_other_signing_domain():
    assert DISCOVERY_ATTESTATION_DOMAIN != ENROLLMENT_ATTESTATION_DOMAIN
    assert SNAPSHOT_KIND != POP_KIND


# --- non-circularity ------------------------------------------------------------------------------


def test_the_facts_hash_excludes_the_envelope_so_the_signature_is_not_circular():
    """The envelope lives BESIDE the facts. If the hash covered the dict containing the envelope,
    signing would require knowing the signature first."""
    priv, pub = _keys()
    binding = _binding(priv, pub)
    att = sign_discovery_binding(priv, binding)

    stored = dict(FACTS)
    stored[ENVELOPE_KEY] = envelope_for_storage(binding, att)

    # The hash is unchanged by storing the envelope, so it verifies after storage exactly as before.
    assert facts_hash(stored) == facts_hash(FACTS) == binding.facts_hash
    assert (
        verify_discovery_binding(binding, att, expected_key_id=key_id_for(pub), evidence=stored)
        == ()
    )


def test_the_stored_envelope_carries_public_material_only():
    priv, pub = _keys()
    binding = _binding(priv, pub)
    stored = envelope_for_storage(binding, sign_discovery_binding(priv, binding))
    assert set(stored["attestation"]) == {
        "algorithm",
        "key_id",
        "public_key_hex",
        "signature",
    }
    # The private key never appears anywhere in the serialized envelope.
    assert priv not in repr(stored)


def test_the_canonical_binding_is_json_safe_and_deterministic():
    """Signed bytes must be reproducible. Tuples become lists; the same binding digests identically
    every time."""
    import json

    priv, pub = _keys()
    binding = _binding(priv, pub)
    payload = canonical_binding(binding)
    json.dumps(payload)  # raises if anything is not JSON-safe
    assert binding_digest(binding) == binding_digest(binding)
    assert isinstance(payload["probe_manifest"][0]["argv"], list)


def test_anchor_matches_derives_from_the_key_not_the_hex():
    priv, pub = _keys()
    assert anchor_matches(pub, key_id_for(pub)) is True
    assert anchor_matches(pub, "sha256:" + "0" * 64) is False
    assert anchor_matches("not-hex", "sha256:" + "0" * 64) is False
