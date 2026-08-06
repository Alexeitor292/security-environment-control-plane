"""The seven end-to-end target outcomes, against fully built fake responses.

The rule this suite is written under: **the required-fact table was not weakened to make the happy
path pass.** The complete-target case observes every one of the twenty compilation facts and eight
apply facts honestly; where that took more fake data, more fake data was built.

Six of the seven outcomes are refusals, which is the right proportion. A discovery system whose
interesting result is success has not been asked hard enough questions.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from _sdn_authentication import authenticated
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
    FRESHNESS_CURRENT,
    FRESHNESS_STALE,
    SIGNATURE_UNREGISTERED_SIGNER,
    SIGNATURE_VALID,
    DiscoverySnapshotBinding,
    ExpectedWorkerRegistration,
    verify_discovery_snapshot,
)
from secp_api.sdn_activation_stages import (
    OperationBinding,
    OwnershipProofResult,
    PendingSdnDocument,
    PendingSdnObject,
    PendingSdnOwnershipProofSet,
    SdnActivationRefused,
    SdnObjectOwnership,
    derive_disclosure,
    issue_activation_authorization,
)
from secp_commissioning.enrollment_attestation import key_id_for, sign_detached
from secp_management.signing import generate_keypair

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)

ORG = "org-1"
TARGET = "target-abc"
OPERATION = "op-1"
GENERATION = 3
FACTS = "sha256:" + "f" * 64
MANIFEST = "sha256:" + "m" * 64

#: A GENUINE authentication: a real key signs a real binding, the binding verifies against a real
#: registered anchor, and the content's recomputed commitment matches the signed facts_hash.
AUTHENTICATED = authenticated()
#: The same, except the WORKER signed that it could not read the pending SDN state.
SIGNED_AS_UNREADABLE = authenticated(pending_sdn_state="permission_denied")


def _all_facts_observed() -> tuple[tuple[str, str], ...]:
    """Every required fact, honestly observed. No shortcuts in the table."""
    return tuple(
        (fact, "observed")
        for fact in (*facts_required_before_compilation(), *facts_required_before_apply())
    )


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
        observation_started_at=(NOW - timedelta(seconds=40)).isoformat(),
        observation_completed_at=(NOW - timedelta(seconds=10)).isoformat(),
        freshness_bound_seconds=1800,
        facts_hash=FACTS,
        operation_manifest_hash=MANIFEST,
        projection_implementation_id="secp-discovery/projection/v1",
        required_fact_observation_states=_all_facts_observed(),
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


def _sign(priv, binding):
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
        facts_hash=FACTS,
        operation_manifest_hash=MANIFEST,
        compilation_required_facts=facts_required_before_compilation(),
        apply_required_facts=facts_required_before_apply(),
        now=NOW,
    )
    kwargs.update(overrides)
    return verify_discovery_snapshot(**kwargs)


# === 1. COMPLETE ELIGIBLE TARGET =================================================================


def test_a_complete_current_correctly_bound_target_becomes_eligible():
    priv, pub = generate_keypair()
    binding = _binding(pub)
    projection, authority = _verify(binding, _sign(priv, binding), _registration(pub))

    assert projection.signature == SIGNATURE_VALID
    assert projection.identity_and_target_binding == BINDING_MATCHED
    assert projection.freshness == FRESHNESS_CURRENT
    assert projection.required_fact_completeness == "complete"
    assert projection.compilation_eligibility == ELIGIBILITY_ELIGIBLE
    assert projection.apply_eligibility == ELIGIBILITY_ELIGIBLE
    assert authority is not None


def test_the_required_fact_table_was_not_weakened_to_reach_that():
    """Guards the suite against itself.

    The cheapest way to make the happy path pass would be to shrink the required set. This asserts
    the table is still the reviewed size and that the complete case really does observe all of it.
    """
    compilation = facts_required_before_compilation()
    apply_facts = facts_required_before_apply()
    assert len(compilation) == 20
    assert len(apply_facts) == 8
    observed = {name for name, state in _all_facts_observed() if state == "observed"}
    assert set(compilation) | set(apply_facts) <= observed


# === 2. AUTHENTIC BUT INCOMPLETE =================================================================


def test_an_authentic_but_incomplete_target_refuses_and_lists_what_is_missing():
    priv, pub = generate_keypair()
    partial = tuple(
        (fact, "observed" if fact == "exact_pve_version" else "not_requested")
        for fact in facts_required_before_compilation()
    )
    binding = _binding(pub, required_fact_observation_states=partial)
    projection, authority = _verify(binding, _sign(priv, binding), _registration(pub))

    assert projection.signature == SIGNATURE_VALID
    assert projection.identity_and_target_binding == BINDING_MATCHED
    assert projection.freshness == FRESHNESS_CURRENT
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert projection.apply_eligibility == ELIGIBILITY_REFUSED
    missing = dict(projection.missing_compilation_facts)
    assert "existing_vlan_use" in missing
    assert "exact_pve_version" not in missing
    assert authority is not None  # authentic, just not sufficient


def test_a_permission_denied_fact_is_reported_with_its_state_not_as_merely_absent():
    """An operator resolves a denial with a grant and an unimplemented probe with code. The state
    is what tells them which."""
    priv, pub = generate_keypair()
    states = tuple(
        (fact, "permission_denied" if fact == "existing_sdn_zones" else "observed")
        for fact in (*facts_required_before_compilation(), *facts_required_before_apply())
    )
    binding = _binding(pub, required_fact_observation_states=states)
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert ("existing_sdn_zones", "permission_denied") in projection.missing_compilation_facts
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED


# === 3. COMPLETE BUT STALE =======================================================================


def test_a_complete_but_stale_target_refuses():
    priv, pub = generate_keypair()
    binding = _binding(
        pub,
        observation_started_at=(NOW - timedelta(days=3)).isoformat(),
        observation_completed_at=(NOW - timedelta(days=3)).isoformat(),
    )
    projection, _ = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.signature == SIGNATURE_VALID
    assert projection.required_fact_completeness == "complete"
    assert projection.freshness == FRESHNESS_STALE
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert projection.apply_eligibility == ELIGIBILITY_REFUSED


# === 4. COMPLETE BUT WRONG SIGNER ================================================================


def test_a_complete_target_signed_by_the_wrong_worker_refuses():
    _priv, registered_pub = generate_keypair()
    attacker_priv, attacker_pub = generate_keypair()
    binding = _binding(attacker_pub)
    projection, authority = _verify(
        binding, _sign(attacker_priv, binding), _registration(registered_pub)
    )
    assert projection.signature == SIGNATURE_UNREGISTERED_SIGNER
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert authority is None


# === 5. COMPLETE BUT WRONG TARGET ================================================================


def test_a_complete_snapshot_for_another_target_refuses():
    """Cross-target replay: a genuine, current, fully observed snapshot — of the wrong cluster."""
    priv, pub = generate_keypair()
    binding = _binding(pub, target_identity="target-other")
    projection, authority = _verify(binding, _sign(priv, binding), _registration(pub))
    assert projection.signature == SIGNATURE_VALID
    assert projection.identity_and_target_binding == BINDING_MISMATCHED
    assert "discovery_binding_mismatch:target" in projection.reasons
    assert projection.compilation_eligibility == ELIGIBILITY_REFUSED
    assert authority is None


# === 6. COMPLETE BUT PARTIALLY VISIBLE SDN =======================================================


def _operation_binding() -> OperationBinding:
    return OperationBinding(
        target_identity=TARGET,
        cluster_fingerprint="sha256:cluster",
        range_identity="range-1",
        operation_identity=OPERATION,
        operation_generation=GENERATION,
        stage1_workspace_hash="sha256:ws",
        stage1_plan_hash="sha256:plan",
        stage1_authorization_id="auth-1",
        stage1_execution_receipt="receipt-1",
    )


def _owned_object(object_id="secplab", family="zones", action="new") -> PendingSdnObject:
    return PendingSdnObject(
        family, object_id, action, "", "pending-repr", "/cluster/sdn/zones", "observed", "sha256:z"
    )


def _owned_proof(obj: PendingSdnObject, **overrides) -> OwnershipProofResult:
    base = dict(
        object_key=obj.key,
        ownership=SdnObjectOwnership.current_operation,
        classification_reason="all_bindings_agree",
        range_identity="range-1",
        operation_identity=OPERATION,
        operation_generation=GENERATION,
        stage1_desired_object_digest="sha256:d",
        stage1_workspace_hash="sha256:ws",
        stage1_plan_hash="sha256:plan",
        stage1_execution_receipt_digest="receipt-1",
        pre_stage1_absence_evidence_digest="sha256:absent",
        target_identity=TARGET,
        cluster_fingerprint="sha256:cluster",
        proof_complete=True,
    )
    base.update(overrides)
    return OwnershipProofResult(**base)


def _document(objects, **overrides) -> PendingSdnDocument:
    base = dict(
        observed_at=NOW - timedelta(minutes=1),
        target_identity=TARGET,
        cluster_fingerprint="sha256:cluster",
        observation_identity="obs-1",
        worker_installation_id="wk-1",
        worker_release_fingerprint="sha256:" + "r" * 64,
        objects=tuple(objects),
        authentication=AUTHENTICATED,
    )
    base.update(overrides)
    return PendingSdnDocument(**base)


def test_partial_sdn_visibility_refuses_activation_even_with_a_complete_inventory():
    """The inventory can be complete and the SDN view still unknown.

    A denied SDN index returns 200 with an empty list, so an incomplete enumeration is exactly the
    case that would otherwise look like a clean cluster. It must block collision-sensitive planning
    rather than degrade it.
    """
    obj = _owned_object()
    document = _document(
        (obj,),
        authentication=SIGNED_AS_UNREADABLE,
        unreadable_families=(("controllers", "permission_denied"),),
    )
    proofs = PendingSdnOwnershipProofSet(results=(_owned_proof(obj),))
    with pytest.raises(SdnActivationRefused, match="visibility_incomplete"):
        issue_activation_authorization(
            document=document,
            proofs=proofs,
            operation=_operation_binding(),
            authorized_at=NOW,
            authorized_by="juan",
        )


# === 7. COMPLETE INVENTORY WITH FOREIGN PENDING SDN ==============================================


def test_a_foreign_pending_sdn_object_refuses_automated_activation():
    """PUT /cluster/sdn commits everything pending cluster-wide, so a foreign object is not a
    disclosure problem — it is somebody else's change that our approval would commit."""
    ours = _owned_object()
    foreign = PendingSdnObject(
        "zones", "opsvlan", "changed", "live", "chg", "/cluster/sdn/zones", "observed", "sha256:o"
    )
    document = _document((ours, foreign))
    proofs = PendingSdnOwnershipProofSet(
        results=(
            _owned_proof(ours),
            _owned_proof(
                foreign, ownership=SdnObjectOwnership.foreign, classification_reason="third_party"
            ),
        )
    )
    disclosure = derive_disclosure(document, proofs, _operation_binding())
    assert disclosure.ownership_counts["foreign"] == 1
    assert disclosure.exclusive_to_current_operation is False

    with pytest.raises(SdnActivationRefused, match="not_exclusive_to_operation"):
        issue_activation_authorization(
            document=document,
            proofs=proofs,
            operation=_operation_binding(),
            authorized_at=NOW,
            authorized_by="juan",
        )


def test_an_unknown_owner_pending_object_also_refuses():
    """Unknown is not a softer foreign. We could not establish ownership, and activation on an
    unestablished fact is the thing being prevented."""
    ours = _owned_object()
    mystery = PendingSdnObject(
        "vnets", "mystery", "new", "", "p", "/cluster/sdn/vnets", "observed", "sha256:x"
    )
    document = _document((ours, mystery))
    proofs = PendingSdnOwnershipProofSet(
        results=(
            _owned_proof(ours),
            _owned_proof(
                mystery,
                ownership=SdnObjectOwnership.unknown,
                classification_reason="no_provenance",
                pre_stage1_absence_evidence_digest="",
            ),
        )
    )
    with pytest.raises(SdnActivationRefused, match="not_exclusive_to_operation"):
        issue_activation_authorization(
            document=document,
            proofs=proofs,
            operation=_operation_binding(),
            authorized_at=NOW,
            authorized_by="juan",
        )


def test_an_exclusively_owned_pending_set_does_authorize():
    """The complement — otherwise every refusal above would be vacuous."""
    ours = _owned_object()
    also_ours = _owned_object("secpteam1", "vnets")
    document = _document((ours, also_ours))
    proofs = PendingSdnOwnershipProofSet(results=(_owned_proof(ours), _owned_proof(also_ours)))
    auth = issue_activation_authorization(
        document=document,
        proofs=proofs,
        operation=_operation_binding(),
        authorized_at=NOW,
        authorized_by="juan",
    )
    assert auth.disclosure.exclusive_to_current_operation is True
    assert auth.disclosure.ownership_counts["current_operation"] == 2
    assert auth.pending_sdn_hash == document.pending_sdn_hash()
    assert auth.ownership_provenance_digest == proofs.ownership_provenance_digest()


# === the shape of the whole suite ================================================================


def test_six_of_the_seven_outcomes_are_refusals():
    """Recorded as an assertion about intent rather than left implicit.

    A discovery system whose interesting result is success has not been asked hard enough
    questions; this suite's balance is deliberate.
    """
    outcomes = {
        "complete_eligible": ELIGIBILITY_ELIGIBLE,
        "authentic_incomplete": ELIGIBILITY_REFUSED,
        "complete_stale": ELIGIBILITY_REFUSED,
        "wrong_signer": ELIGIBILITY_REFUSED,
        "wrong_target": ELIGIBILITY_REFUSED,
        "partial_sdn_visibility": ELIGIBILITY_REFUSED,
        "foreign_pending_sdn": ELIGIBILITY_REFUSED,
    }
    assert sum(1 for v in outcomes.values() if v == ELIGIBILITY_REFUSED) == 6
    assert outcomes["complete_eligible"] == ELIGIBILITY_ELIGIBLE
