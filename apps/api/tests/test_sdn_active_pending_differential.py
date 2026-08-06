"""Active and pending stay two sources; the action is a conclusion drawn from the pair.

Proxmox's ``?pending=1`` response merges them, and reading either half alone is wrong in a different
direction: top-level-only sees an almost-empty record for a create, merged-only cannot say what a
change would REPLACE. The old code kept one semantic object and copied the target's own ``state``
annotation as the action — so "what would activation do to this object" was answered by the target
rather than derived from what SECP observed.

``PUT /cluster/sdn`` commits every pending change on the cluster, so an object whose effect SECP
cannot state is one it would commit blind. Every such object is ``ambiguous``, stays IN the pending
set, and blocks activation.
"""

from __future__ import annotations

import pytest
from _sdn_authentication import NOW, authenticated
from secp_api.sdn_activation_stages import (
    OperationBinding,
    OwnershipProofResult,
    PendingSdnObject,
    PendingSdnOwnershipProofSet,
    SdnActivationRefused,
    SdnObjectOwnership,
    issue_activation_authorization,
    sdn_differential_refusals,
)
from secp_api.sdn_differential import (
    ACTION_AMBIGUOUS,
    ACTION_CHANGE,
    ACTION_CREATE,
    ACTION_DELETE,
    ACTION_UNCHANGED,
    SDN_ACTIONS,
    derive_differentials,
    derive_object_differential,
    differential_refusals,
)

AUTHENTICATED = authenticated()

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


def _row(**overrides) -> dict:
    base = {
        "family": "zones",
        "object_id": "z1",
        "state": "new",
        "observed": {"zone": "z1", "type": "vlan"},
        "active": {},
    }
    base.update(overrides)
    return base


# === the action is derived from the pair, never from the annotation ===============================


def test_pending_present_and_active_absent_is_a_create():
    d = derive_object_differential("zones", _row())
    assert d.action == ACTION_CREATE
    assert d.target_state == "new"  # the annotation is retained as evidence
    assert d.pending_present is True
    assert d.active_present is False


def test_active_present_and_pending_absent_is_a_delete():
    d = derive_object_differential(
        "zones", _row(state="deleted", active={"zone": "z1", "type": "vlan"}, observed={})
    )
    assert d.action == ACTION_DELETE
    assert d.active_digest


def test_both_present_and_different_is_a_change():
    d = derive_object_differential(
        "zones", _row(state="changed", active={"mtu": 1500}, observed={"mtu": 9000})
    )
    assert d.action == ACTION_CHANGE
    assert d.active_digest != d.pending_digest


def test_both_present_and_identical_is_unchanged():
    same = {"mtu": 1500}
    d = derive_object_differential("zones", _row(state="changed", active=same, observed=dict(same)))
    assert d.action == ACTION_UNCHANGED


def test_an_object_the_target_calls_new_but_whose_active_view_is_populated_is_not_a_create():
    """The annotation says one thing and the pair says another. Trusting the label is how an
    ADOPTION of somebody else's object passes as a creation."""
    d = derive_object_differential(
        "zones", _row(state="new", active={"zone": "z1", "type": "vlan"}, observed={"mtu": 9000})
    )
    assert d.target_state == "new"
    assert d.action == ACTION_CHANGE


def test_an_object_with_no_identifier_is_ambiguous_and_says_why():
    d = derive_object_differential("zones", _row(object_id=""))
    assert d.action == ACTION_AMBIGUOUS
    assert d.ambiguity_reason == "object_identifier_absent"


def test_a_row_whose_views_are_both_empty_is_ambiguous():
    d = derive_object_differential("zones", _row(observed={}, active={}))
    assert d.action == ACTION_AMBIGUOUS
    assert d.ambiguity_reason == "neither_view_carries_a_representation"


def test_a_delete_with_no_active_representation_is_ambiguous_not_a_delete():
    """A deletion of something nobody observed: what activation would remove is unknown.

    In the DERIVATION this lands on the neither-view-carries-a-representation branch, because a
    populated active view always yields a digest — the "delete with an empty active digest" shape
    can only be presented at the gate, and ``test_the_gate_refuses_a_delete_that_lost_its_active
    _evidence`` covers it there.
    """
    d = derive_object_differential("zones", _row(state="deleted", active={}, observed={}))
    assert d.action == ACTION_AMBIGUOUS
    assert d.ambiguity_reason == "neither_view_carries_a_representation"


def test_the_action_vocabulary_is_closed():
    assert set(SDN_ACTIONS) == {"create", "change", "delete", "unchanged", "ambiguous"}


# === nothing is filtered out ======================================================================


def test_every_observed_row_is_classified_including_the_unclassifiable_ones():
    families = {
        "zones": (_row(), _row(object_id=""), _row(object_id="z3", observed={}, active={})),
        "vnets": (_row(family="vnets", object_id="v1"),),
    }
    derived = derive_differentials(families)
    assert len(derived) == 4  # count out == count in
    assert sum(1 for d in derived if d.action == ACTION_AMBIGUOUS) == 2


def test_a_pending_object_merged_away_is_detected_by_count():
    """An object dropped between observation and classification stops blocking exclusivity."""
    reasons = differential_refusals(
        differentials=derive_differentials({"zones": (_row(),)}),
        observed_row_count=2,
        active_visibility_complete=True,
        pending_visibility_complete=True,
        absence_evidence_by_key={("zones", "z1"): "sha256:absent"},
    )
    assert any(r.startswith("sdn_pending_object_merged_away") for r in reasons)


# === the refusals =================================================================================


def test_incomplete_visibility_on_either_side_refuses():
    for active, pending, expected in (
        (False, True, "sdn_active_visibility_incomplete"),
        (True, False, "sdn_pending_visibility_incomplete"),
    ):
        reasons = differential_refusals(
            differentials=(),
            observed_row_count=0,
            active_visibility_complete=active,
            pending_visibility_complete=pending,
        )
        assert expected in reasons


def test_a_degraded_source_refuses_and_names_it():
    reasons = differential_refusals(
        differentials=(),
        observed_row_count=0,
        active_visibility_complete=True,
        pending_visibility_complete=True,
        degraded_sources=("sdn_zones_pending",),
    )
    assert "sdn_source_degraded:sdn_zones_pending" in reasons


def test_a_duplicated_identifier_refuses_because_the_proof_join_is_one_to_one():
    reasons = differential_refusals(
        differentials=derive_differentials({"zones": (_row(), _row())}),
        observed_row_count=2,
        active_visibility_complete=True,
        pending_visibility_complete=True,
        absence_evidence_by_key={("zones", "z1"): "sha256:absent"},
    )
    assert "sdn_identifier_not_unique:zones:z1" in reasons


def test_a_create_without_absence_evidence_refuses():
    reasons = differential_refusals(
        differentials=derive_differentials({"zones": (_row(),)}),
        observed_row_count=1,
        active_visibility_complete=True,
        pending_visibility_complete=True,
        absence_evidence_by_key={},
    )
    assert "sdn_create_without_absence_evidence:zones:z1" in reasons


def test_every_refusal_is_reported_not_only_the_first():
    """An operator who clears one refusal only to meet the next has been told half the truth
    twice."""
    reasons = differential_refusals(
        differentials=derive_differentials({"zones": (_row(), _row(object_id=""))}),
        observed_row_count=5,
        active_visibility_complete=False,
        pending_visibility_complete=False,
        degraded_sources=("sdn_vnets_pending",),
    )
    assert "sdn_active_visibility_incomplete" in reasons
    assert "sdn_pending_visibility_incomplete" in reasons
    assert "sdn_source_degraded:sdn_vnets_pending" in reasons
    assert any(r.startswith("sdn_pending_object_merged_away") for r in reasons)
    assert any(r.startswith("sdn_object_action_ambiguous") for r in reasons)
    assert any(r.startswith("sdn_create_without_absence_evidence") for r in reasons)


# === the activation gate enforces them ============================================================


def _object(action: str, **overrides) -> PendingSdnObject:
    base = dict(
        family="zones",
        object_id="z1",
        action=action,
        normalized_active_representation="sha256:a",
        normalized_pending_representation="sha256:p",
        source_endpoint="/cluster/sdn/zones",
        observation_state="observed",
        raw_result_digest="sha256:r",
    )
    base.update(overrides)
    return PendingSdnObject(**base)


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
        # A change or delete touches something that already existed, so ownership needs the durable
        # provenance record rather than the absence proof a create relies on.
        durable_ownership_provenance_digest="sha256:prov",
        target_identity="target-abc",
        cluster_fingerprint="sha256:cluster",
        proof_complete=True,
    )
    base.update(overrides)
    return OwnershipProofResult(**base)


def _document(objects):
    from datetime import timedelta

    from secp_api.sdn_activation_stages import PendingSdnDocument

    return PendingSdnDocument(
        observed_at=NOW - timedelta(minutes=1),
        target_identity="target-abc",
        cluster_fingerprint="sha256:cluster",
        observation_identity="obs-1",
        worker_installation_id="wk-1",
        worker_release_fingerprint="sha256:rel",
        objects=tuple(objects),
        authentication=AUTHENTICATED,
    )


def test_the_gate_refuses_an_ambiguous_object():
    obj = _object(ACTION_AMBIGUOUS, ambiguity_reason="delete_without_active_representation")
    document = _document((obj,))
    proofs = PendingSdnOwnershipProofSet(results=(_proof(obj),))

    assert any(
        r.startswith("sdn_object_action_ambiguous")
        for r in sdn_differential_refusals(document, proofs)
    )
    with pytest.raises(SdnActivationRefused, match="sdn_object_action_ambiguous"):
        issue_activation_authorization(
            document=document,
            proofs=proofs,
            operation=OPERATION,
            authorized_at=NOW,
            authorized_by="juan",
        )


def test_the_gate_refuses_a_create_whose_absence_evidence_is_missing():
    obj = _object(ACTION_CREATE)
    document = _document((obj,))
    proofs = PendingSdnOwnershipProofSet(
        results=(_proof(obj, pre_stage1_absence_evidence_digest=""),)
    )
    with pytest.raises(SdnActivationRefused, match="sdn_create_without_absence_evidence"):
        issue_activation_authorization(
            document=document,
            proofs=proofs,
            operation=OPERATION,
            authorized_at=NOW,
            authorized_by="juan",
        )


def test_the_gate_refuses_a_delete_that_lost_its_active_evidence():
    obj = _object(ACTION_DELETE, normalized_active_representation="")
    document = _document((obj,))
    proofs = PendingSdnOwnershipProofSet(results=(_proof(obj),))
    with pytest.raises(SdnActivationRefused, match="sdn_delete_without_active_evidence"):
        issue_activation_authorization(
            document=document,
            proofs=proofs,
            operation=OPERATION,
            authorized_at=NOW,
            authorized_by="juan",
        )


def test_the_gate_refuses_a_duplicated_identifier():
    """Two refusals cover this — the document's own duplicate check and the differential's — and
    both must be present, because the differential is also recomputed at stage four where the
    document check has already passed once."""
    obj = _object(ACTION_CHANGE)
    document = _document((obj, obj))
    proofs = PendingSdnOwnershipProofSet(results=(_proof(obj),))

    assert "sdn_identifier_not_unique:zones:z1" in sdn_differential_refusals(document, proofs)
    with pytest.raises(SdnActivationRefused, match="duplicate_object|identifier_not_unique"):
        issue_activation_authorization(
            document=document,
            proofs=proofs,
            operation=OPERATION,
            authorized_at=NOW,
            authorized_by="juan",
        )


def test_a_clean_change_passes_the_differential_gate():
    """The gate must open, or every refusal above is vacuous."""
    obj = _object(ACTION_CHANGE)
    document = _document((obj,))
    proofs = PendingSdnOwnershipProofSet(results=(_proof(obj),))
    assert sdn_differential_refusals(document, proofs) == ()
    authorization = issue_activation_authorization(
        document=document,
        proofs=proofs,
        operation=OPERATION,
        authorized_at=NOW,
        authorized_by="juan",
    )
    assert authorization.disclosure.exclusive_to_current_operation is True


def test_stage_four_reports_the_differential_refusals_too():
    """Recomputed at activation, not only at authorization: an object can become ambiguous between
    the two."""
    from secp_api.sdn_activation_stages import STAGE_ACTIVATION_AUTHORIZED, activation_refusals

    obj = _object(ACTION_CHANGE)
    document = _document((obj,))
    proofs = PendingSdnOwnershipProofSet(results=(_proof(obj),))
    authorization = issue_activation_authorization(
        document=document,
        proofs=proofs,
        operation=OPERATION,
        authorized_at=NOW,
        authorized_by="juan",
    )

    degraded = _document((_object(ACTION_AMBIGUOUS, ambiguity_reason="became_unclear"),))
    reasons = activation_refusals(
        stage=STAGE_ACTIVATION_AUTHORIZED,
        authorization=authorization,
        document=degraded,
        proofs=proofs,
        operation=OPERATION,
        now=NOW,
    )
    assert any(r.startswith("sdn_object_action_ambiguous") for r in reasons)


# === the derived action is inside the signed document =============================================


def test_both_views_and_the_derived_action_are_in_the_canonical_object():
    obj = _object(ACTION_CHANGE)
    canonical = obj.canonical()
    for key in (
        "action",
        "target_state",
        "ambiguity_reason",
        "active_present",
        "pending_present",
        "active",
        "pending",
    ):
        assert key in canonical, key


def test_changing_only_the_derived_action_moves_the_pending_hash():
    """The action is signed, so a reclassification is detectable even when both views are
    byte-identical."""
    a = _document((_object(ACTION_CHANGE),))
    b = _document((_object(ACTION_CREATE),))
    assert a.pending_sdn_hash() != b.pending_sdn_hash()


def test_changing_only_the_active_view_moves_the_pending_hash():
    a = _document((_object(ACTION_CHANGE),))
    b = _document((_object(ACTION_CHANGE, normalized_active_representation="sha256:other"),))
    assert a.pending_sdn_hash() != b.pending_sdn_hash()
