"""The signed discovery trust chain, end to end.

Fake worker identity material, fake credentials, a bounded fake transport. Nothing contacts a host.

**The property that matters most is a refusal.** A `/version`-only run produces a perfectly valid
signature over six honestly observed facts — and must still be compilation- and apply-ineligible,
because twenty required facts were never observed. A system that granted eligibility on the strength
of a signature would be cryptographically impeccable and operationally dangerous, and that is
precisely the shape this file is written to prevent.
"""

from __future__ import annotations

import dataclasses
import pickle
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.discovery_required_facts import (
    facts_required_before_apply,
    facts_required_before_compilation,
)
from secp_api.discovery_verification import (
    BINDING_MATCHED,
    BINDING_MISMATCHED,
    DISCOVERY_CONTRACT_VERSION,
    DISCOVERY_SNAPSHOT_DOMAIN,
    DISCOVERY_SNAPSHOT_KIND,
    ELIGIBILITY_ELIGIBLE,
    ELIGIBILITY_REFUSED,
    FRESHNESS_CLOCK_SKEW,
    FRESHNESS_CURRENT,
    FRESHNESS_INVALID_WINDOW,
    FRESHNESS_STALE,
    FRESHNESS_UNBOUNDED,
    SIGNATURE_INVALID,
    SIGNATURE_NO_REGISTERED_ANCHOR,
    SIGNATURE_UNREGISTERED_SIGNER,
    SIGNATURE_VALID,
    DiscoverySnapshotBinding,
    DiscoveryVerificationError,
    ExpectedWorkerRegistration,
    VerifiedDiscoverySnapshot,
    verify_discovery_snapshot,
)
from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    POP_KIND,
    key_id_for,
    sign_detached,
)
from secp_management.signing import generate_keypair

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
FACTS_HASH = "sha256:" + "f" * 64
MANIFEST_HASH = "sha256:" + "m" * 64
ORG = "org-1"
TARGET = "target-abc"
OPERATION = "op-1"
GENERATION = 3

# A `/version`-only run: six version facts observed, everything else never asked for.
_VERSION_FACTS = (
    ("exact_pve_version", "observed"),
    ("cluster_identity", "not_requested"),
)


def _keys():
    return generate_keypair()


def _binding(pub: str, **overrides) -> DiscoverySnapshotBinding:
    base = dict(
        discovery_contract_version=DISCOVERY_CONTRACT_VERSION,
        operation_identity=OPERATION,
        operation_generation=GENERATION,
        organization_identity=ORG,
        target_identity=TARGET,
        requested_target_authority="pve.example.test:8006",
        worker_installation_id="wk-1",
        worker_role="proxmox_privileged",
        worker_release_fingerprint="sha256:" + "r" * 64,
        signer_fingerprint=key_id_for(pub),
        observation_started_at=(NOW - timedelta(seconds=30)).isoformat(),
        observation_completed_at=(NOW - timedelta(seconds=10)).isoformat(),
        freshness_bound_seconds=1800,
        facts_hash=FACTS_HASH,
        operation_manifest_hash=MANIFEST_HASH,
        projection_implementation_id="secp-discovery/projection/v1",
        required_fact_observation_states=_VERSION_FACTS,
    )
    base.update(overrides)
    return DiscoverySnapshotBinding(**base)


def _registration(pub: str, **overrides) -> ExpectedWorkerRegistration:
    base = dict(
        worker_installation_id="wk-1",
        worker_role="proxmox_privileged",
        worker_release_fingerprint="sha256:" + "r" * 64,
        verification_anchor_fingerprint=key_id_for(pub),
        target_identity=TARGET,
        organization_identity=ORG,
    )
    base.update(overrides)
    return ExpectedWorkerRegistration(**base)


def _sign(priv: str, binding: DiscoverySnapshotBinding):
    return sign_detached(
        priv,
        domain=DISCOVERY_SNAPSHOT_DOMAIN,
        kind=DISCOVERY_SNAPSHOT_KIND,
        digest=binding.digest(),
    )


def _verify(binding, attestation, registration, **overrides):
    kwargs = dict(
        binding=binding,
        attestation=attestation,
        registration=registration,
        expected_operation_identity=OPERATION,
        expected_operation_generation=GENERATION,
        expected_target_identity=TARGET,
        expected_organization_identity=ORG,
        facts_hash=FACTS_HASH,
        operation_manifest_hash=MANIFEST_HASH,
        compilation_required_facts=facts_required_before_compilation(),
        apply_required_facts=facts_required_before_apply(),
        now=NOW,
    )
    kwargs.update(overrides)
    return verify_discovery_snapshot(**kwargs)


def _good():
    priv, pub = _keys()
    binding = _binding(pub)
    return binding, _sign(priv, binding), _registration(pub)


# === THE CENTRAL PROPERTY ========================================================================


def test_a_valid_signature_does_not_make_an_incomplete_target_eligible():
    """The named test.

    A `/version`-only run signs six honestly observed facts. The signature is valid, the anchor
    matches, the bindings match, the observation is current — and the target is still refused for
    both compilation and apply, because the other required facts were never observed.

    Granting eligibility here would mean a plan could be compiled against a cluster whose VMIDs,
    VLANs, subnets, storage and SDN state nobody looked at, on the strength of knowing its version.
    """
    binding, attestation, registration = _good()
    projection, authority = _verify(binding, attestation, registration)

    assert projection.signature == SIGNATURE_VALID
    assert projection.identity_and_target_binding == BINDING_MATCHED
    assert projection.freshness == FRESHNESS_CURRENT
    assert projection.authenticated is True

    assert projection.required_fact_completeness == "incomplete"
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert projection.apply_eligibility == ELIGIBILITY_REFUSED
    assert len(projection.missing_compilation_facts) > 10

    # The authority IS issued — authenticity held. It just does not authorise compilation.
    assert isinstance(authority, VerifiedDiscoverySnapshot)


def test_the_six_results_are_reported_separately():
    """Not one `verified` flag: authenticity, binding, freshness, completeness and the two
    eligibilities answer different questions and fail for different reasons."""
    binding, attestation, registration = _good()
    projection, _ = _verify(binding, attestation, registration)
    assert projection.signature == SIGNATURE_VALID
    assert projection.identity_and_target_binding == BINDING_MATCHED
    assert projection.freshness == FRESHNESS_CURRENT
    assert projection.required_fact_completeness == "incomplete"
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert projection.apply_eligibility == ELIGIBILITY_REFUSED


def test_a_complete_fact_set_does_become_eligible():
    """A gate that never opens is not a gate."""
    priv, pub = _keys()
    complete = tuple(
        (fact, "observed")
        for fact in (*facts_required_before_compilation(), *facts_required_before_apply())
    )
    binding = _binding(pub, required_fact_observation_states=complete)
    projection, authority = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.compilation_eligibility == ELIGIBILITY_ELIGIBLE
    assert projection.apply_eligibility == ELIGIBILITY_ELIGIBLE
    assert authority is not None


def test_a_compilation_complete_but_apply_incomplete_set_splits_the_two():
    """The two gates are disjoint — a plan may be compiled and reviewed while apply is refused."""
    priv, pub = _keys()
    states = tuple((f, "observed") for f in facts_required_before_compilation())
    binding = _binding(pub, required_fact_observation_states=states)
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.compilation_eligibility == ELIGIBILITY_ELIGIBLE
    assert projection.apply_eligibility == ELIGIBILITY_REFUSED


# === THE ANCHOR COMES FROM DURABLE REGISTRATION ==================================================


def test_the_verifier_takes_no_expected_key_parameter():
    """There is nowhere for a caller to supply the answer."""
    import inspect

    params = set(inspect.signature(verify_discovery_snapshot).parameters)
    for banned in (
        "expected_key",
        "expected_key_id",
        "signature_valid",
        "public_key_hex",
        "trusted_keys",
    ):
        assert banned not in params, banned


def test_a_missing_registration_fails_closed():
    binding, attestation, _ = _good()
    projection, authority = _verify(binding, attestation, None)
    assert projection.signature == SIGNATURE_NO_REGISTERED_ANCHOR
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert "discovery_worker_registration_missing" in projection.reasons
    assert authority is None


def test_a_registration_with_no_anchor_fails_closed():
    """ "We could not find the expected key" is not "any key will do"."""
    binding, attestation, registration = _good()
    projection, authority = _verify(
        binding, attestation, dataclasses.replace(registration, verification_anchor_fingerprint="")
    )
    assert projection.signature == SIGNATURE_NO_REGISTERED_ANCHOR
    assert authority is None


def test_a_registration_invalid_for_this_target_fails_closed():
    binding, attestation, registration = _good()
    projection, _ = _verify(
        binding, attestation, dataclasses.replace(registration, is_valid_for_target=False)
    )
    assert projection.signature == SIGNATURE_NO_REGISTERED_ANCHOR


def test_an_envelope_self_signed_by_an_unregistered_key_refuses():
    """The self-verification attack. The envelope's own key must never establish trust."""
    _priv, registered_pub = _keys()
    attacker_priv, attacker_pub = _keys()
    binding = _binding(attacker_pub)  # names the attacker as signer
    attestation = _sign(attacker_priv, binding)  # and is validly signed BY the attacker

    projection, authority = _verify(binding, attestation, _registration(registered_pub))
    assert projection.signature == SIGNATURE_UNREGISTERED_SIGNER
    assert "discovery_signer_not_the_registered_worker" in projection.reasons
    assert authority is None


def test_a_wrong_signing_key_refuses():
    priv, pub = _keys()
    other_priv, _other_pub = _keys()
    binding = _binding(pub)
    projection, _ = _verify(binding, _sign(other_priv, binding), _registration(pub))
    assert projection.signature == SIGNATURE_UNREGISTERED_SIGNER


def test_a_missing_or_malformed_attestation_refuses():
    binding, _attestation, registration = _good()
    for impostor in (None, {"signature": "x"}, "not-an-attestation", object()):
        projection, authority = _verify(binding, impostor, registration)
        assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
        assert authority is None


def test_an_enrollment_envelope_replayed_as_discovery_refuses():
    """Domain separation, as the replay it prevents."""
    priv, pub = _keys()
    binding = _binding(pub)
    enrollment = sign_detached(
        priv, domain=ENROLLMENT_ATTESTATION_DOMAIN, kind=POP_KIND, digest=binding.digest()
    )
    projection, authority = _verify(binding, enrollment, _registration(pub))
    assert projection.signature == SIGNATURE_INVALID
    assert authority is None


# === BINDINGS ====================================================================================


@pytest.mark.parametrize(
    "field,value,label",
    [
        ("worker_installation_id", "wk-9999", "worker_installation"),
        ("worker_role", "ordinary", "worker_role"),
        ("worker_release_fingerprint", "sha256:" + "0" * 64, "worker_release"),
        ("target_identity", "target-other", "target"),
        ("organization_identity", "org-other", "organization"),
        ("operation_identity", "op-other", "operation"),
    ],
)
def test_a_binding_mismatch_refuses_and_names_it(field, value, label):
    priv, pub = _keys()
    binding = _binding(pub, **{field: value})
    projection, authority = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.identity_and_target_binding == BINDING_MISMATCHED
    assert f"discovery_binding_mismatch:{label}" in projection.reasons
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert authority is None


def test_a_generation_mismatch_refuses():
    """Cross-generation replay: the same worker, target and operation, an earlier run."""
    priv, pub = _keys()
    binding = _binding(pub, operation_generation=2)
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert "discovery_binding_mismatch:operation_generation" in projection.reasons


def test_facts_changed_after_signing_refuses():
    binding, attestation, registration = _good()
    projection, _ = _verify(binding, attestation, registration, facts_hash="sha256:" + "0" * 64)
    assert "discovery_facts_changed_after_signing" in projection.reasons


def test_the_operation_manifest_changed_after_signing_refuses():
    """Why the manifest hash is bound alongside the facts hash.

    Signing only the facts would leave the response digest, the rendered path and the parser
    identity unattested — the conclusions could keep their signature while the request that
    produced them was rewritten.
    """
    binding, attestation, registration = _good()
    projection, _ = _verify(
        binding, attestation, registration, operation_manifest_hash="sha256:" + "0" * 64
    )
    assert "discovery_operation_manifest_changed_after_signing" in projection.reasons


@pytest.mark.parametrize(
    "field",
    [
        "facts_hash",
        "operation_manifest_hash",
        "requested_target_authority",
        "projection_implementation_id",
    ],
)
def test_editing_any_signed_field_breaks_the_signature(field):
    priv, pub = _keys()
    binding = _binding(pub)
    attestation = _sign(priv, binding)
    tampered = dataclasses.replace(binding, **{field: "sha256:" + "9" * 64})
    projection, _ = _verify(tampered, attestation, _registration(pub))
    assert projection.signature == SIGNATURE_INVALID


def test_changed_observation_states_break_the_signature():
    """The states are inside the signature so a consumer cannot be told a fact was merely absent
    when the producer recorded it permission-denied."""
    priv, pub = _keys()
    binding = _binding(pub)
    attestation = _sign(priv, binding)
    softened = dataclasses.replace(
        binding, required_fact_observation_states=(("exact_pve_version", "observed"),)
    )
    projection, _ = _verify(softened, attestation, _registration(pub))
    assert projection.signature == SIGNATURE_INVALID


# === FRESHNESS ===================================================================================


def test_a_stale_snapshot_refuses_eligibility_while_staying_authentic():
    """Authenticity and freshness are separate: the signature is still valid on an old snapshot."""
    priv, pub = _keys()
    binding = _binding(
        pub,
        observation_completed_at=(NOW - timedelta(hours=5)).isoformat(),
        observation_started_at=(NOW - timedelta(hours=5, seconds=30)).isoformat(),
    )
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.signature == SIGNATURE_VALID
    assert projection.freshness == FRESHNESS_STALE
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED


def test_a_future_stamped_snapshot_is_skew_not_fresh():
    priv, pub = _keys()
    binding = _binding(pub, observation_completed_at=(NOW + timedelta(minutes=5)).isoformat())
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.freshness == FRESHNESS_CLOCK_SKEW


def test_an_implausibly_future_snapshot_is_an_invalid_window():
    priv, pub = _keys()
    binding = _binding(pub, observation_completed_at=(NOW + timedelta(days=2)).isoformat())
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.freshness == FRESHNESS_INVALID_WINDOW


def test_a_missing_completion_time_is_unbounded_and_refused():
    priv, pub = _keys()
    binding = _binding(pub, observation_completed_at="")
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.freshness == FRESHNESS_UNBOUNDED
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED


def test_completion_before_start_is_an_invalid_window():
    priv, pub = _keys()
    binding = _binding(
        pub,
        observation_started_at=NOW.isoformat(),
        observation_completed_at=(NOW - timedelta(minutes=5)).isoformat(),
    )
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.freshness == FRESHNESS_INVALID_WINDOW


def test_a_non_positive_freshness_bound_is_an_invalid_window():
    priv, pub = _keys()
    binding = _binding(pub, freshness_bound_seconds=0)
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.freshness == FRESHNESS_INVALID_WINDOW


def test_arrival_time_does_not_refresh_an_old_observation():
    """A newly received envelope carrying a week-old observation is still stale."""
    priv, pub = _keys()
    binding = _binding(
        pub,
        observation_started_at=(NOW - timedelta(days=7)).isoformat(),
        observation_completed_at=(NOW - timedelta(days=7)).isoformat(),
    )
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.freshness == FRESHNESS_STALE


# === THE OPAQUE AUTHORITY ========================================================================


def test_the_authority_cannot_be_constructed_directly():
    binding, _a, _r = _good()
    with pytest.raises(DiscoveryVerificationError, match="cannot be constructed directly"):
        VerifiedDiscoverySnapshot(object(), binding)


def test_the_authority_cannot_be_serialized():
    binding, attestation, registration = _good()
    _projection, authority = _verify(binding, attestation, registration)
    with pytest.raises(DiscoveryVerificationError, match="cannot be pickled"):
        pickle.dumps(authority)
    with pytest.raises(DiscoveryVerificationError, match="cannot be serialized"):
        authority.__getstate__()
    assert "redacted" in repr(authority)


def test_no_authority_is_issued_when_binding_fails():
    """The authority is issued only when authenticity AND binding hold — not on signature alone."""
    priv, pub = _keys()
    binding = _binding(pub, target_identity="target-other")
    _projection, authority = _verify(binding, _sign(priv, binding), _registration(pub))
    assert authority is None


def test_the_authority_is_bound_to_its_own_snapshot():
    """An authority for one snapshot cannot be read as covering another."""
    binding, attestation, registration = _good()
    _projection, authority = _verify(binding, attestation, registration)
    assert authority.binding.facts_hash == FACTS_HASH
    assert authority.binding.operation_manifest_hash == MANIFEST_HASH
    assert authority.binding.target_identity == TARGET
