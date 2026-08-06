"""The five-stage SDN activation model, with MVP zero-tolerance and derived ownership.

Two properties drive everything here.

**Ownership is derived, never asserted.** The first cut of this module had
``PendingSdnObject.secp_owned: bool`` — a caller-supplied boolean, so whoever built the object
declared ownership rather than proving it. That is the same defect class as a plan document being
told its own validation result. Ownership now comes from :func:`classify_ownership` against binding
proof, and anything short of complete proof is ``unknown``.

**MVP refuses on ANY non-exclusive object.** `PUT /cluster/sdn` commits everything pending
cluster-wide. Disclosing a foreign object is not the same as it being safe to commit, and an
operator must not be able to accept that residual through ordinary Stage 3 approval. An
authorisation covering one is structurally unconstructable.
"""

from __future__ import annotations

import dataclasses
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
    ObjectOwnershipProof,
    OperationBinding,
    PendingSdnObject,
    PendingSdnObservation,
    SdnActivationRefused,
    SdnObjectOwnership,
    activation_refusals,
    classify_ownership,
    guests_may_deploy,
    next_stage,
)

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
TARGET = "target-abc"

OPERATION = OperationBinding(
    target_identity=TARGET,
    cluster_fingerprint="sha256:cluster",
    range_identity="range-1",
    operation_identity="op-1",
    operation_generation=3,
    stage1_workspace_hash="sha256:ws",
    stage1_plan_hash="sha256:plan",
    stage1_authorization_id="auth-1",
    stage1_execution_receipt="receipt-1",
)


def _owned(object_id="secplab", family="zones", state="new") -> PendingSdnObject:
    return PendingSdnObject(family, object_id, state, SdnObjectOwnership.operation_owned)


_SECP_OBJECTS = (
    _owned("secplab", "zones"),
    _owned("secpteam1", "vnets"),
    _owned("secplab-10.10.1.0-24", "subnets"),
)
_FOREIGN = PendingSdnObject("zones", "opsvlan", "changed", SdnObjectOwnership.foreign)
_UNKNOWN = PendingSdnObject("vnets", "mystery", "new", SdnObjectOwnership.unknown)
_OTHER_OP = PendingSdnObject("zones", "secpold", "new", SdnObjectOwnership.other_secp_operation)


def _proof(**overrides) -> ObjectOwnershipProof:
    base = dict(
        claimed_target_identity=TARGET,
        claimed_cluster_fingerprint="sha256:cluster",
        claimed_range_identity="range-1",
        claimed_operation_identity="op-1",
        claimed_operation_generation=3,
        stage1_desired_object_id="secplab",
        stage1_object_family="zones",
        stage1_expected_action="new",
        stage1_workspace_hash="sha256:ws",
        stage1_plan_hash="sha256:plan",
        stage1_authorization_id="auth-1",
        stage1_execution_receipt="receipt-1",
        post_stage1_observation_signed=True,
        pre_stage1_absence_proven=True,
    )
    base.update(overrides)
    return ObjectOwnershipProof(**base)


def _observation(objects=_SECP_OBJECTS, **overrides) -> PendingSdnObservation:
    base = dict(observed_at=NOW - timedelta(minutes=1), objects=tuple(objects), complete=True)
    base.update(overrides)
    return PendingSdnObservation(**base)


def _authorization(observation, **overrides) -> ActivationAuthorization:
    base = dict(
        authorized_pending_hash=observation.pending_hash(),
        authorized_at=NOW - timedelta(seconds=30),
        authorized_by="juan",
        target_identity=TARGET,
        operation_identity="op-1",
        operation_generation=3,
        disclosed_counts=observation.ownership_counts(),
    )
    base.update(overrides)
    return ActivationAuthorization(**base)


def _refusals(observation, authorization, *, stage=STAGE_ACTIVATION_AUTHORIZED, now=NOW):
    return activation_refusals(
        stage=stage,
        authorization=authorization,
        observation=observation,
        now=now,
        expected_target_identity=TARGET,
    )


# --- ownership is DERIVED ------------------------------------------------------------------------


def test_ownership_is_not_a_constructor_argument_anybody_can_assert():
    """The regression test for the defect this correction closes.

    An object nobody submitted for classification is ``unclassified`` — not owned, and not foreign
    either, because we have not established anything about it.
    """
    obj = PendingSdnObject("zones", "anything", "new")
    assert obj.ownership is SdnObjectOwnership.unclassified
    assert obj.ownership in NON_EXCLUSIVE_OWNERSHIP


def test_complete_proof_yields_operation_owned():
    """A gate that never opens is not a gate."""
    obj = PendingSdnObject("zones", "secplab", "new")
    assert classify_ownership(obj, _proof(), OPERATION) is SdnObjectOwnership.operation_owned


@pytest.mark.parametrize(
    "field,value",
    [
        ("claimed_target_identity", "target-other"),
        ("claimed_cluster_fingerprint", "sha256:other"),
        ("stage1_workspace_hash", "sha256:other"),
        ("stage1_plan_hash", "sha256:other"),
        ("stage1_authorization_id", "auth-other"),
        ("stage1_execution_receipt", "receipt-other"),
        ("stage1_desired_object_id", "somethingelse"),
        ("stage1_object_family", "vnets"),
        ("stage1_expected_action", "changed"),
        ("post_stage1_observation_signed", False),
    ],
)
def test_any_disagreeing_binding_yields_unknown_not_owned(field, value):
    """Unknown, not foreign: "we could not prove it is ours" and "we proved it is somebody else's"
    are different facts with different remediations."""
    obj = PendingSdnObject("zones", "secplab", "new")
    result = classify_ownership(obj, _proof(**{field: value}), OPERATION)
    assert result is SdnObjectOwnership.unknown


@pytest.mark.parametrize(
    "field",
    [
        "claimed_target_identity",
        "claimed_cluster_fingerprint",
        "claimed_range_identity",
        "claimed_operation_identity",
        "stage1_workspace_hash",
        "stage1_plan_hash",
        "stage1_authorization_id",
        "stage1_execution_receipt",
    ],
)
def test_an_empty_binding_is_not_a_matching_binding(field):
    """Two empty strings compare equal, so equality alone is not proof.

    The trap is BOTH sides empty — an unconfigured operation and an object with no proof would
    otherwise satisfy ``==`` on every field and classify as owned, which is the worst possible
    direction. So the operation binding is blanked in the same field as the proof: a plain mismatch
    would be caught by the comparison anyway and would not exercise this at all.

    (Written this way after the first version passed against a mutation that removed the
    non-emptiness guard — it had been comparing an empty proof field against a populated operation,
    which is just a mismatch wearing this test's name.)
    """
    obj = PendingSdnObject("zones", "secplab", "new")
    blank_both = (
        dataclasses.replace(OPERATION, **{field: ""})
        if field.startswith("stage1_")
        else dataclasses.replace(OPERATION, **{field.replace("claimed_", ""): ""})
    )
    proof = _proof(**{field: ""})
    assert classify_ownership(obj, proof, blank_both) is not SdnObjectOwnership.operation_owned


def test_an_object_with_no_proof_against_an_unconfigured_operation_is_never_owned():
    """The whole trap in one case: every field empty on both sides.

    Every ``==`` succeeds. Only the non-emptiness guard stops this classifying as owned.
    """
    obj = PendingSdnObject("zones", "secplab", "new")
    empty_operation = OperationBinding(
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
    empty_proof = ObjectOwnershipProof(
        claimed_operation_generation=-1,
        stage1_desired_object_id="secplab",
        stage1_object_family="zones",
        stage1_expected_action="new",
        post_stage1_observation_signed=True,
        pre_stage1_absence_proven=True,
    )
    assert classify_ownership(obj, empty_proof, empty_operation) is SdnObjectOwnership.unknown


def test_a_new_object_without_pre_stage1_absence_proof_is_unknown():
    """Otherwise SECP could adopt somebody else's object that happened to share the identifier."""
    obj = PendingSdnObject("zones", "secplab", "new")
    result = classify_ownership(obj, _proof(pre_stage1_absence_proven=False), OPERATION)
    assert result is SdnObjectOwnership.unknown


def test_a_change_or_delete_requires_durable_provenance():
    """A change or delete touches an object that already existed, so name and attribute agreement
    cannot establish that SECP created it."""
    for action in ("changed", "deleted"):
        obj = PendingSdnObject("zones", "secplab", action)
        proof = _proof(stage1_expected_action=action, durable_provenance_record="")
        assert classify_ownership(obj, proof, OPERATION) is SdnObjectOwnership.unknown

        with_provenance = _proof(
            stage1_expected_action=action, durable_provenance_record="range-1/lineage/7"
        )
        assert classify_ownership(obj, with_provenance, OPERATION) is (
            SdnObjectOwnership.operation_owned
        )


def test_another_secp_operation_is_distinguished_from_foreign():
    """An abandoned earlier run of our own needs a different remediation than a third party's
    object, so it gets its own classification rather than being lumped in."""
    obj = PendingSdnObject("zones", "secpold", "new")
    result = classify_ownership(obj, _proof(claimed_operation_generation=2), OPERATION)
    assert result is SdnObjectOwnership.other_secp_operation

    other_range = classify_ownership(obj, _proof(claimed_range_identity="range-9"), OPERATION)
    assert other_range is SdnObjectOwnership.other_secp_operation


def test_proven_foreign_beats_a_failing_binding():
    """Positive proof that it is somebody else's is stronger information than our binding failing,
    and the operator should be told the stronger thing."""
    obj = PendingSdnObject("zones", "opsvlan", "changed")
    result = classify_ownership(obj, _proof(proven_foreign=True), OPERATION)
    assert result is SdnObjectOwnership.foreign


def test_a_name_prefix_is_not_evidence():
    """The explicit rule. An identifier beginning with a SECP prefix is reproducible by any actor,
    so it appears nowhere in the proof structure and cannot make an object owned.
    """
    fields = {f.name for f in dataclasses.fields(ObjectOwnershipProof)}
    for banned in ("name_prefix", "alias", "attributes_match", "appeared_after_stage1"):
        assert banned not in fields
    # And an object whose id looks like ours, with no proof, is not ours.
    obj = PendingSdnObject("zones", "secplab", "new")
    empty = ObjectOwnershipProof()
    assert classify_ownership(obj, empty, OPERATION) is SdnObjectOwnership.unknown


# --- MVP zero tolerance --------------------------------------------------------------------------


@pytest.mark.parametrize("intruder", [_FOREIGN, _UNKNOWN, _OTHER_OP])
def test_any_non_exclusive_object_refuses_activation(intruder):
    observed = _observation(objects=(*_SECP_OBJECTS, intruder))
    # The authorisation cannot even be built for this observation (next test), so build one against
    # a clean set and then present the contaminated observation — the stage-4 re-check.
    clean = _observation()
    auth = _authorization(clean)
    reasons = _refusals(observed, auth)
    assert any(r.startswith("cluster_pending_sdn_not_exclusive_to_operation") for r in reasons)


@pytest.mark.parametrize("intruder", [_FOREIGN, _UNKNOWN, _OTHER_OP])
def test_an_authorization_covering_a_non_exclusive_object_is_unconstructable(intruder):
    """Structurally invalid, not merely refused.

    An operator must not be able to accept the foreign-object residual through ordinary Stage 3
    approval — a mixed-owner activation is a different operation kind with its own contract, and it
    must not be reachable by clicking through this one.
    """
    contaminated = _observation(objects=(*_SECP_OBJECTS, intruder))
    with pytest.raises(SdnActivationRefused, match="not_exclusive_to_operation"):
        _authorization(contaminated)


def test_the_refusal_reports_every_count():
    observed = _observation(objects=(*_SECP_OBJECTS, _FOREIGN, _UNKNOWN, _OTHER_OP))
    reasons = _refusals(observed, _authorization(_observation()))
    detail = next(
        r for r in reasons if r.startswith("cluster_pending_sdn_not_exclusive_to_operation")
    )
    assert "total=6" in detail
    assert "operation_owned=3" in detail
    assert "foreign=1" in detail
    assert "unknown=1" in detail
    assert "other_secp_operation=1" in detail


def test_a_fully_owned_pending_set_permits_activation():
    observed = _observation()
    assert observed.ownership_counts()["operation_owned"] == 3
    assert observed.non_exclusive_objects == ()
    assert _refusals(observed, _authorization(observed)) == ()


def test_non_exclusive_covers_every_classification_except_owned():
    assert SdnObjectOwnership.operation_owned not in NON_EXCLUSIVE_OWNERSHIP
    assert NON_EXCLUSIVE_OWNERSHIP == frozenset(
        {
            SdnObjectOwnership.foreign,
            SdnObjectOwnership.other_secp_operation,
            SdnObjectOwnership.unknown,
            SdnObjectOwnership.unclassified,
        }
    )


# --- the hash binding (unchanged behaviour, re-verified against the new shape) --------------------


def test_a_change_staged_after_authorization_refuses_activation():
    observed = _observation()
    auth = _authorization(observed)
    later = dataclasses.replace(observed, objects=(*_SECP_OBJECTS, _FOREIGN))
    assert "sdn_activation_pending_state_changed" in _refusals(later, auth)


def test_the_hash_covers_ownership_so_a_reclassification_moves_it():
    """An object whose classification changed between observation and activation is a different
    pending set, even at the same identifier and state."""
    owned = _observation(objects=(_owned("x", "zones"),))
    unknown = _observation(
        objects=(PendingSdnObject("zones", "x", "new", SdnObjectOwnership.unknown),)
    )
    assert owned.pending_hash() != unknown.pending_hash()


def test_the_hash_is_order_independent_but_content_sensitive():
    a = _observation(objects=(_SECP_OBJECTS[0], _SECP_OBJECTS[1], _SECP_OBJECTS[2]))
    b = _observation(objects=(_SECP_OBJECTS[2], _SECP_OBJECTS[0], _SECP_OBJECTS[1]))
    assert a.pending_hash() == b.pending_hash()
    changed = dataclasses.replace(_SECP_OBJECTS[0], state="deleted")
    assert _observation(objects=(changed, *_SECP_OBJECTS[1:])).pending_hash() != a.pending_hash()


def test_a_disclosure_mismatch_refuses():
    observed = _observation()
    understated = _authorization(observed, disclosed_counts={"total": 0, "operation_owned": 0})
    assert "sdn_activation_disclosure_mismatch" in _refusals(observed, understated)


# --- incomplete observation ----------------------------------------------------------------------


def test_a_partial_pending_view_cannot_back_an_activation():
    """ "We do not know what is pending" is not "nothing is pending". A denied SDN index returns 200
    with an empty list, which is exactly the case that would otherwise look like a clean cluster."""
    observed = _observation(
        complete=False, unreadable_families=(("controllers", "permission_denied"),)
    )
    reasons = _refusals(observed, _authorization(observed))
    assert "sdn_activation_pending_state_incomplete" in reasons
    assert "sdn_pending_family_unreadable:controllers:permission_denied" in reasons


def test_an_empty_but_complete_observation_is_usable():
    observed = _observation(objects=())
    assert observed.is_empty is True
    assert _refusals(observed, _authorization(observed)) == ()


# --- staleness, stages, guests -------------------------------------------------------------------


def test_an_expired_observation_refuses():
    old = _observation(observed_at=NOW - timedelta(hours=2))
    assert "sdn_activation_observation_expired" in _refusals(old, _authorization(old))


def test_an_observation_from_the_future_is_skew_not_freshness():
    ahead = _observation(observed_at=NOW + timedelta(minutes=5))
    assert "sdn_activation_observation_clock_skew" in _refusals(ahead, _authorization(ahead))


@pytest.mark.parametrize("stage", [STAGE_PREPARED, STAGE_PENDING_OBSERVED, STAGE_ACTIVATED])
def test_activation_is_reachable_only_from_the_authorized_stage(stage):
    observed = _observation()
    assert f"sdn_activation_wrong_stage:{stage}" in _refusals(
        observed, _authorization(observed), stage=stage
    )


def test_activation_without_an_authorization_or_observation_refuses():
    assert "sdn_activation_unauthorized" in _refusals(_observation(), None)
    observed = _observation()
    assert "sdn_activation_no_pending_observation" in _refusals(None, _authorization(observed))


def test_the_stage_order_is_the_reviewed_five():
    assert STAGE_ORDER == (
        STAGE_PREPARED,
        STAGE_PENDING_OBSERVED,
        STAGE_ACTIVATION_AUTHORIZED,
        STAGE_ACTIVATED,
        STAGE_VERIFIED,
    )


def test_stages_advance_one_at_a_time_and_cannot_skip():
    assert next_stage(STAGE_PREPARED) == STAGE_PENDING_OBSERVED
    assert next_stage(STAGE_ACTIVATION_AUTHORIZED) == STAGE_ACTIVATED
    with pytest.raises(SdnActivationRefused, match="already_verified"):
        next_stage(STAGE_VERIFIED)
    with pytest.raises(SdnActivationRefused, match="unknown_stage"):
        next_stage("activated_probably")


def test_a_target_mismatch_refuses():
    observed = _observation()
    assert "sdn_activation_target_mismatch" in _refusals(
        observed, _authorization(observed, target_identity="target-other")
    )


@pytest.mark.parametrize(
    "stage", [STAGE_PREPARED, STAGE_PENDING_OBSERVED, STAGE_ACTIVATION_AUTHORIZED, STAGE_ACTIVATED]
)
def test_guests_cannot_deploy_before_the_sdn_is_verified(stage):
    assert guests_may_deploy(stage) is False


def test_guests_may_deploy_once_verified():
    assert guests_may_deploy(STAGE_VERIFIED) is True
