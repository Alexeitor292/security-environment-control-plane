"""Ownership is derived; disclosure authorises nothing.

The hole this file exists to close, stated as the attack: an ``ActivationAuthorization`` used to
accept ``disclosed_counts`` from its caller, so an **all-zero summary offered against a contaminated
pending document** survived construction and was only caught by a later recompute. The constructor
now has no counts parameter, no disclosure parameter and no ownership boolean — a caller may supply
the evidence classification is derived from, never the classification outcome.

Two digests, because they protect different facts: the pending hash catches the cluster changing;
the provenance digest catches our evidence changing while the target-observed bytes stay identical.
"""

from __future__ import annotations

import dataclasses
import inspect
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.sdn_activation_stages import (
    NON_EXCLUSIVE_OWNERSHIP,
    STAGE_ACTIVATED,
    STAGE_ACTIVATION_AUTHORIZED,
    STAGE_ORDER,
    STAGE_PENDING_OBSERVED,
    STAGE_PREPARED,
    STAGE_VERIFIED,
    ActivationAuthorization,
    OperationBinding,
    OwnershipProofResult,
    PendingSdnDisclosure,
    PendingSdnDocument,
    PendingSdnObject,
    PendingSdnOwnershipProofSet,
    SdnActivationRefused,
    SdnObjectOwnership,
    activation_refusals,
    classify_ownership,
    derive_disclosure,
    guests_may_deploy,
    issue_activation_authorization,
    next_stage,
    object_manifest,
)

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)

OPERATION = OperationBinding(
    target_identity="target-abc",
    cluster_fingerprint="sha256:cluster",
    range_identity="range-1",
    operation_identity="op-1",
    operation_generation=3,
    stage1_workspace_hash="sha256:ws",
    stage1_plan_hash="sha256:plan",
    stage1_authorization_id="auth-1",
    stage1_execution_receipt="receipt-1",
)

_ZONE = PendingSdnObject(
    "zones", "secplab", "new", "", "zone-pending", "/cluster/sdn/zones", "observed", "sha256:z"
)
_VNET = PendingSdnObject(
    "vnets", "secpteam1", "new", "", "vnet-pending", "/cluster/sdn/vnets", "observed", "sha256:v"
)
_SUBNET = PendingSdnObject(
    "subnets",
    "secplab-10.10.1.0-24",
    "new",
    "",
    "sub",
    "/cluster/sdn/vnets/x/subnets",
    "observed",
    "sha256:s",
)
_INTRUDER = PendingSdnObject(
    "zones", "opsvlan", "changed", "live", "chg", "/cluster/sdn/zones", "observed", "sha256:o"
)


def _proof(obj: PendingSdnObject, **overrides) -> OwnershipProofResult:
    base = dict(
        object_key=obj.key,
        ownership=SdnObjectOwnership.current_operation,
        classification_reason="all_bindings_agree",
        range_identity="range-1",
        operation_identity="op-1",
        operation_generation=3,
        stage1_desired_object_digest="sha256:desired",
        stage1_workspace_hash="sha256:ws",
        stage1_plan_hash="sha256:plan",
        stage1_execution_receipt_digest="receipt-1",
        pre_stage1_absence_evidence_digest="sha256:absent",
        target_identity="target-abc",
        cluster_fingerprint="sha256:cluster",
        proof_complete=True,
    )
    base.update(overrides)
    return OwnershipProofResult(**base)


def _document(objects=(_ZONE, _VNET, _SUBNET), **overrides) -> PendingSdnDocument:
    base = dict(
        observed_at=NOW - timedelta(minutes=1),
        target_identity="target-abc",
        cluster_fingerprint="sha256:cluster",
        observation_identity="obs-1",
        worker_installation_id="wk-1",
        worker_release_fingerprint="sha256:rel",
        objects=tuple(objects),
        signature_verified=True,
        visibility_complete=True,
    )
    base.update(overrides)
    return PendingSdnDocument(**base)


def _proofs(document, **per_object) -> PendingSdnOwnershipProofSet:
    return PendingSdnOwnershipProofSet(
        results=tuple(_proof(obj, **per_object.get(obj.object_id, {})) for obj in document.objects)
    )


def _issue(document, proofs, **overrides):
    kwargs = dict(
        document=document,
        proofs=proofs,
        operation=OPERATION,
        authorized_at=NOW - timedelta(seconds=30),
        authorized_by="juan",
    )
    kwargs.update(overrides)
    return issue_activation_authorization(**kwargs)


# --- THE HOLE ------------------------------------------------------------------------------------


def test_the_constructor_has_no_counts_or_disclosure_parameter():
    """All-zero caller counts cannot be passed because there is nowhere to pass them."""
    params = set(inspect.signature(issue_activation_authorization).parameters)
    for banned in (
        "disclosed_counts",
        "ownership_counts",
        "classification_complete",
        "exclusive_to_current_operation",
        "foreign_count",
        "disclosure",
    ):
        assert banned not in params, banned
    assert params == {
        "document",
        "proofs",
        "operation",
        "authorized_at",
        "authorized_by",
        "observation_ttl",
    }


def test_a_forged_all_zero_disclosure_cannot_authorize_a_contaminated_document():
    """The exact reported attack.

    A hand-built disclosure claiming a clean cluster is constructed and thrown away: it reaches no
    authority path, because the constructor derives its own from the document and proof set.
    """
    contaminated = _document(objects=(_ZONE, _VNET, _SUBNET, _INTRUDER))
    proofs = PendingSdnOwnershipProofSet(
        results=(
            *(_proof(o) for o in (_ZONE, _VNET, _SUBNET)),
            _proof(
                _INTRUDER, ownership=SdnObjectOwnership.foreign, classification_reason="third_party"
            ),
        )
    )
    forged = PendingSdnDisclosure(
        pending_sdn_hash=contaminated.pending_sdn_hash(),
        ownership_provenance_digest=proofs.ownership_provenance_digest(),
        ownership_counts={
            "total_pending": 4,
            "current_operation": 4,
            "other_secp_operation": 0,
            "foreign": 0,
            "unknown": 0,
            "unclassified": 0,
        },
        action_counts={"create": 4, "change": 0, "delete": 0},
        family_counts={"zones": 2, "vnets": 1, "subnets": 1},
        classification_complete=True,
        exclusive_to_current_operation=True,
    )
    assert forged.exclusive_to_current_operation is True  # the lie is well-formed ...

    with pytest.raises(SdnActivationRefused, match="not_exclusive_to_operation"):
        _issue(contaminated, proofs)  # ... and unreachable

    truth = derive_disclosure(contaminated, proofs)
    assert truth.ownership_counts["foreign"] == 1
    assert truth.exclusive_to_current_operation is False


def test_counts_are_derived_from_the_document_and_proofs():
    document = _document()
    disclosure = derive_disclosure(document, _proofs(document))
    assert disclosure.ownership_counts == {
        "total_pending": 3,
        "current_operation": 3,
        "other_secp_operation": 0,
        "foreign": 0,
        "unknown": 0,
        "unclassified": 0,
    }
    assert disclosure.classification_complete is True
    assert disclosure.exclusive_to_current_operation is True


@pytest.mark.parametrize(
    "ownership,field",
    [
        (SdnObjectOwnership.foreign, "foreign"),
        (SdnObjectOwnership.unknown, "unknown"),
        (SdnObjectOwnership.other_secp_operation, "other_secp_operation"),
        (SdnObjectOwnership.unclassified, "unclassified"),
    ],
)
def test_one_contaminating_object_derives_exactly_one(ownership, field):
    document = _document(objects=(_ZONE, _VNET, _SUBNET, _INTRUDER))
    proofs = PendingSdnOwnershipProofSet(
        results=(
            *(_proof(o) for o in (_ZONE, _VNET, _SUBNET)),
            _proof(_INTRUDER, ownership=ownership, classification_reason="x"),
        )
    )
    disclosure = derive_disclosure(document, proofs)
    assert disclosure.ownership_counts[field] == 1
    assert disclosure.exclusive_to_current_operation is False
    with pytest.raises(SdnActivationRefused, match="not_exclusive_to_operation"):
        _issue(document, proofs)


def test_an_object_with_no_proof_at_all_counts_as_unclassified():
    """A missing proof must not silently vanish from the summary."""
    document = _document(objects=(_ZONE, _VNET))
    partial = PendingSdnOwnershipProofSet(results=(_proof(_ZONE),))
    disclosure = derive_disclosure(document, partial)
    assert disclosure.ownership_counts["unclassified"] == 1
    assert disclosure.classification_complete is False


def test_an_uncontaminated_document_authorizes():
    """A gate that never opens is not a gate."""
    document = _document()
    auth = _issue(document, _proofs(document))
    assert auth.pending_sdn_hash == document.pending_sdn_hash()
    assert auth.disclosure.exclusive_to_current_operation is True


# --- the invariants ------------------------------------------------------------------------------


def test_the_counts_sum_to_total_pending():
    document = _document(objects=(_ZONE, _VNET, _SUBNET, _INTRUDER))
    proofs = PendingSdnOwnershipProofSet(
        results=(
            _proof(_ZONE),
            _proof(_VNET, ownership=SdnObjectOwnership.unknown, classification_reason="u"),
            _proof(
                _SUBNET,
                ownership=SdnObjectOwnership.other_secp_operation,
                classification_reason="o",
            ),
            _proof(_INTRUDER, ownership=SdnObjectOwnership.foreign, classification_reason="f"),
        )
    )
    c = derive_disclosure(document, proofs).ownership_counts
    assert c["total_pending"] == (
        c["current_operation"]
        + c["other_secp_operation"]
        + c["foreign"]
        + c["unknown"]
        + c["unclassified"]
    )


def test_the_disclosure_schema_is_the_exact_six_fields():
    document = _document()
    counts = derive_disclosure(document, _proofs(document)).ownership_counts
    assert set(counts) == {
        "total_pending",
        "current_operation",
        "other_secp_operation",
        "foreign",
        "unknown",
        "unclassified",
    }


def test_operation_owned_is_not_retained_as_an_alias():
    """One exact name. Nothing has executed or persisted this contract, so an alias would be pure
    ambiguity."""
    document = _document()
    counts = derive_disclosure(document, _proofs(document)).ownership_counts
    assert "operation_owned" not in counts
    assert not hasattr(SdnObjectOwnership, "operation_owned")


def test_the_projection_is_fixed_rather_than_derived_from_enum_keys():
    """Renaming or adding an ownership member must not silently alter the manifest contract, so the
    field list is explicit in the module rather than read off the enum."""
    import secp_api.sdn_activation_stages as mod

    names = [name for name, _ in mod._OWNERSHIP_FIELDS]
    assert names == [
        "current_operation",
        "other_secp_operation",
        "foreign",
        "unknown",
        "unclassified",
    ]


def test_action_and_family_counts_are_derived_and_are_not_ownership_proof():
    document = _document(objects=(_ZONE, _VNET, _INTRUDER))
    proofs = PendingSdnOwnershipProofSet(
        results=(
            _proof(_ZONE),
            _proof(_VNET),
            _proof(_INTRUDER, ownership=SdnObjectOwnership.foreign, classification_reason="f"),
        )
    )
    disclosure = derive_disclosure(document, proofs)
    assert disclosure.action_counts == {"create": 2, "change": 1, "delete": 0}
    assert disclosure.family_counts == {"zones": 2, "vnets": 1}
    # Action/family agreement does not make the foreign object ours.
    assert disclosure.exclusive_to_current_operation is False


# --- the two digests -----------------------------------------------------------------------------


def test_changing_only_the_proof_moves_the_provenance_digest_not_the_pending_hash():
    """The reason there are two. Target-observed bytes identical, evidence changed."""
    document = _document()
    a = _proofs(document)
    b = PendingSdnOwnershipProofSet(
        results=tuple(
            dataclasses.replace(r, durable_ownership_provenance_digest="sha256:moved")
            for r in a.results
        )
    )
    assert document.pending_sdn_hash() == document.pending_sdn_hash()
    assert a.ownership_provenance_digest() != b.ownership_provenance_digest()


def test_changing_only_the_target_values_moves_the_pending_hash():
    a = _document()
    b = _document(
        objects=(
            dataclasses.replace(_ZONE, normalized_pending_representation="different"),
            _VNET,
            _SUBNET,
        )
    )
    assert a.pending_sdn_hash() != b.pending_sdn_hash()


def test_a_classification_change_with_identical_raw_state_refuses_at_stage_four():
    """The case one hash cannot see: nothing about the cluster changed, but an object slipped from
    current_operation to unknown because a provenance record disappeared."""
    document = _document()
    auth = _issue(document, _proofs(document))

    degraded = PendingSdnOwnershipProofSet(
        results=(
            _proof(
                _ZONE, ownership=SdnObjectOwnership.unknown, classification_reason="provenance_lost"
            ),
            _proof(_VNET),
            _proof(_SUBNET),
        )
    )
    reasons = activation_refusals(
        stage=STAGE_ACTIVATION_AUTHORIZED,
        authorization=auth,
        document=document,
        proofs=degraded,
        operation=OPERATION,
        now=NOW,
    )
    assert "sdn_activation_pending_state_changed" not in reasons  # the cluster did NOT change
    assert "sdn_activation_ownership_provenance_changed" in reasons
    assert any(r.startswith("cluster_pending_sdn_not_exclusive_to_operation") for r in reasons)


@pytest.mark.parametrize(
    "objects",
    [(_ZONE, _VNET), (_ZONE, _VNET, _SUBNET, _INTRUDER)],
    ids=["smaller", "larger"],
)
def test_a_smaller_or_larger_pending_set_refuses(objects):
    document = _document()
    auth = _issue(document, _proofs(document))
    changed = _document(objects=objects)
    reasons = activation_refusals(
        stage=STAGE_ACTIVATION_AUTHORIZED,
        authorization=auth,
        document=changed,
        proofs=_proofs(changed),
        operation=OPERATION,
        now=NOW,
    )
    assert "sdn_activation_pending_state_changed" in reasons


# --- constructor refusals -------------------------------------------------------------------------


def test_an_empty_pending_set_cannot_be_authorized():
    """An activation of nothing is meaningless and can conceal an observation failure."""
    with pytest.raises(SdnActivationRefused, match="empty_pending_set"):
        _issue(_document(objects=()), PendingSdnOwnershipProofSet())


def test_an_unsigned_or_incomplete_document_cannot_be_authorized():
    document = _document(signature_verified=False)
    with pytest.raises(SdnActivationRefused, match="unsigned"):
        _issue(document, _proofs(document))
    document = _document(visibility_complete=False)
    with pytest.raises(SdnActivationRefused, match="visibility_incomplete"):
        _issue(document, _proofs(document))


def test_the_proof_set_must_match_the_document_one_to_one():
    document = _document()
    short = PendingSdnOwnershipProofSet(results=(_proof(_ZONE), _proof(_VNET)))
    with pytest.raises(SdnActivationRefused, match="proof_set_mismatch"):
        _issue(document, short)

    extra = PendingSdnOwnershipProofSet(results=(*_proofs(document).results, _proof(_INTRUDER)))
    with pytest.raises(SdnActivationRefused, match="proof_set_mismatch"):
        _issue(document, extra)


def test_a_duplicated_proof_is_refused():
    document = _document(objects=(_ZONE,))
    dup = PendingSdnOwnershipProofSet(results=(_proof(_ZONE), _proof(_ZONE)))
    with pytest.raises(SdnActivationRefused, match="proof_duplicated"):
        _issue(document, dup)


@pytest.mark.parametrize(
    "field", ["target_identity", "cluster_fingerprint", "range_identity", "operation_identity"]
)
def test_a_blank_operation_binding_is_refused(field):
    document = _document()
    blank = dataclasses.replace(OPERATION, **{field: ""})
    with pytest.raises(SdnActivationRefused):
        _issue(document, _proofs(document), operation=blank)


# --- classification: what is NOT evidence ---------------------------------------------------------


def test_matching_blank_bindings_cannot_establish_ownership():
    """Two empty strings compare equal, so equality alone is not proof. Both sides blank must not
    satisfy every ``==`` and classify as ours."""
    blank_op = OperationBinding(
        target_identity="",
        cluster_fingerprint="",
        range_identity="",
        operation_identity="",
        operation_generation=-1,
        stage1_workspace_hash="",
        stage1_plan_hash="",
        stage1_authorization_id="",
        stage1_execution_receipt="",
    )
    blank_proof = OwnershipProofResult(
        object_key=_ZONE.key,
        ownership=SdnObjectOwnership.current_operation,
        classification_reason="",
        operation_generation=-1,
        proof_complete=True,
    )
    assert classify_ownership(_ZONE, blank_proof, blank_op) is SdnObjectOwnership.unknown


@pytest.mark.parametrize(
    "banned",
    ["name_prefix", "alias", "hcl_comment", "attributes_match", "appeared_after_stage1", "timing"],
)
def test_the_proof_structure_has_no_field_for_a_non_evidence_signal(banned):
    """A name prefix, a VNet alias and an HCL comment are reproducible by any actor; attribute
    equality and creation-like timing are coincidences. None is a field, so none can be offered."""
    fields = {f.name for f in dataclasses.fields(OwnershipProofResult)}
    assert banned not in fields


def test_a_secp_looking_identifier_with_no_evidence_is_unknown():
    bare = OwnershipProofResult(
        object_key=_ZONE.key,
        ownership=SdnObjectOwnership.current_operation,
        classification_reason="looks_like_ours",
        operation_generation=-1,
    )
    assert classify_ownership(_ZONE, bare, OPERATION) is SdnObjectOwnership.unknown


def test_a_new_object_needs_pre_stage1_absence_proof():
    proof = _proof(_ZONE, pre_stage1_absence_evidence_digest="")
    assert classify_ownership(_ZONE, proof, OPERATION) is SdnObjectOwnership.unknown


def test_a_change_or_delete_needs_durable_provenance():
    changed = dataclasses.replace(_ZONE, action="changed")
    without = _proof(changed, durable_ownership_provenance_digest="")
    assert classify_ownership(changed, without, OPERATION) is SdnObjectOwnership.unknown
    with_prov = _proof(changed, durable_ownership_provenance_digest="sha256:lineage")
    assert classify_ownership(changed, with_prov, OPERATION) is SdnObjectOwnership.current_operation


def test_another_generation_is_other_secp_operation_not_foreign():
    proof = _proof(_ZONE, operation_generation=2)
    assert classify_ownership(_ZONE, proof, OPERATION) is SdnObjectOwnership.other_secp_operation


def test_non_exclusive_covers_everything_except_current_operation():
    assert SdnObjectOwnership.current_operation not in NON_EXCLUSIVE_OWNERSHIP
    assert len(NON_EXCLUSIVE_OWNERSHIP) == len(SdnObjectOwnership) - 1


# --- the manifest lists every object --------------------------------------------------------------


def test_the_manifest_lists_every_object_individually():
    """A summary is not a manifest: an operator refused an activation needs to know WHICH object."""
    document = _document(objects=(_ZONE, _INTRUDER))
    proofs = PendingSdnOwnershipProofSet(
        results=(
            _proof(_ZONE),
            _proof(
                _INTRUDER, ownership=SdnObjectOwnership.foreign, classification_reason="third_party"
            ),
        )
    )
    rows = object_manifest(document, proofs)
    assert len(rows) == 2
    blocker = next(r for r in rows if r["identifier"] == "opsvlan")
    assert blocker["ownership_classification"] == "foreign"
    assert blocker["classification_reason"] == "third_party"
    assert blocker["source_endpoint"] == "/cluster/sdn/zones"
    assert set(rows[0]) == {
        "family",
        "identifier",
        "action",
        "ownership_classification",
        "classification_reason",
        "range_binding",
        "operation_binding",
        "generation_binding",
        "active_representation_digest",
        "pending_representation_digest",
        "source_endpoint",
        "observation_state",
    }


def test_an_object_with_no_proof_is_still_listed():
    document = _document(objects=(_ZONE,))
    rows = object_manifest(document, PendingSdnOwnershipProofSet())
    assert rows[0]["ownership_classification"] == "unclassified"
    assert rows[0]["classification_reason"] == "no_proof_submitted"


# --- stage plumbing -------------------------------------------------------------------------------


def test_a_good_activation_passes_stage_four():
    document = _document()
    proofs = _proofs(document)
    assert (
        activation_refusals(
            stage=STAGE_ACTIVATION_AUTHORIZED,
            authorization=_issue(document, proofs),
            document=document,
            proofs=proofs,
            operation=OPERATION,
            now=NOW,
        )
        == ()
    )


@pytest.mark.parametrize("stage", [STAGE_PREPARED, STAGE_PENDING_OBSERVED, STAGE_ACTIVATED])
def test_activation_is_reachable_only_from_the_authorized_stage(stage):
    document = _document()
    proofs = _proofs(document)
    reasons = activation_refusals(
        stage=stage,
        authorization=_issue(document, proofs),
        document=document,
        proofs=proofs,
        operation=OPERATION,
        now=NOW,
    )
    assert f"sdn_activation_wrong_stage:{stage}" in reasons


def test_an_expired_observation_refuses():
    document = _document()
    proofs = _proofs(document)
    auth = _issue(document, proofs)
    reasons = activation_refusals(
        stage=STAGE_ACTIVATION_AUTHORIZED,
        authorization=auth,
        document=document,
        proofs=proofs,
        operation=OPERATION,
        now=NOW + timedelta(hours=2),
    )
    assert "sdn_activation_observation_expired" in reasons


def test_a_future_observation_is_skew_not_freshness():
    document = _document(observed_at=NOW + timedelta(minutes=5))
    proofs = _proofs(document)
    reasons = activation_refusals(
        stage=STAGE_ACTIVATION_AUTHORIZED,
        authorization=_issue(document, proofs),
        document=document,
        proofs=proofs,
        operation=OPERATION,
        now=NOW,
    )
    assert "sdn_activation_observation_clock_skew" in reasons


def test_the_stage_order_is_the_reviewed_five():
    assert STAGE_ORDER == (
        STAGE_PREPARED,
        STAGE_PENDING_OBSERVED,
        STAGE_ACTIVATION_AUTHORIZED,
        STAGE_ACTIVATED,
        STAGE_VERIFIED,
    )


def test_stages_advance_one_at_a_time():
    assert next_stage(STAGE_PREPARED) == STAGE_PENDING_OBSERVED
    with pytest.raises(SdnActivationRefused, match="already_verified"):
        next_stage(STAGE_VERIFIED)
    with pytest.raises(SdnActivationRefused, match="unknown_stage"):
        next_stage("activated_probably")


@pytest.mark.parametrize(
    "stage", [STAGE_PREPARED, STAGE_PENDING_OBSERVED, STAGE_ACTIVATION_AUTHORIZED, STAGE_ACTIVATED]
)
def test_guests_cannot_deploy_before_verified(stage):
    assert guests_may_deploy(stage) is False


def test_guests_may_deploy_once_verified():
    assert guests_may_deploy(STAGE_VERIFIED) is True


def test_the_authorization_type_carries_no_settable_ownership_boolean():
    fields = {f.name for f in dataclasses.fields(ActivationAuthorization)}
    for banned in ("foreign_count", "classification_complete", "exclusive_to_current_operation"):
        assert banned not in fields
