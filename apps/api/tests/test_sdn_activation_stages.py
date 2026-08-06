"""The five-stage SDN activation model.

The scenario every test is written against: `PUT /cluster/sdn` commits **everything** pending on the
cluster. An operator approves what they were shown at stage 2; the commit happens at stage 4; and in
between, anybody with SDN.Allocate can stage something new. The hash binding is what stops that
change riding in on an authorisation that never saw it.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.sdn_activation_stages import (
    STAGE_ACTIVATED,
    STAGE_ACTIVATION_AUTHORIZED,
    STAGE_ORDER,
    STAGE_PENDING_OBSERVED,
    STAGE_PREPARED,
    STAGE_VERIFIED,
    ActivationAuthorization,
    PendingSdnObject,
    PendingSdnObservation,
    SdnActivationRefused,
    activation_refusals,
    guests_may_deploy,
    next_stage,
)

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
TARGET = "target-abc"

_SECP_OBJECTS = (
    PendingSdnObject("zones", "secplab", "new", secp_owned=True),
    PendingSdnObject("vnets", "secpteam1", "new", secp_owned=True),
    PendingSdnObject("subnets", "secplab-10.10.1.0-24", "new", secp_owned=True),
)
_FOREIGN = PendingSdnObject("zones", "opsvlan", "changed", secp_owned=False)


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
        disclosed_foreign_object_count=len(observation.foreign_objects),
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


# --- the window this model exists to close --------------------------------------------------------


def test_a_foreign_change_staged_after_authorization_refuses_activation():
    """THE scenario.

    The operator is shown three SECP objects and approves. Before activation, an unrelated team
    stages a zone change. `PUT /cluster/sdn` would commit theirs too — under an approval that never
    saw it. The hash moved, so activation refuses.
    """
    observed = _observation()
    auth = _authorization(observed)

    later = dataclasses.replace(observed, objects=(*_SECP_OBJECTS, _FOREIGN))
    reasons = _refusals(later, auth)

    assert "sdn_activation_pending_state_changed" in reasons


def test_a_foreign_change_that_disappears_also_refuses():
    """The binding is symmetric.

    Somebody rolling back their staged change between observation and activation also moves the
    hash. The operator approved committing a specific set; committing a different smaller set is
    still not what they approved.
    """
    observed = _observation(objects=(*_SECP_OBJECTS, _FOREIGN))
    auth = _authorization(observed)
    smaller = dataclasses.replace(observed, objects=_SECP_OBJECTS)
    assert "sdn_activation_pending_state_changed" in _refusals(smaller, auth)


def test_the_hash_covers_foreign_objects_not_just_secp_ones():
    """Hashing only SECP's changes would be stable while the thing actually being committed changed
    underneath it — which defeats the entire mechanism."""
    secp_only = _observation()
    with_foreign = _observation(objects=(*_SECP_OBJECTS, _FOREIGN))
    assert secp_only.pending_hash() != with_foreign.pending_hash()


def test_the_hash_is_order_independent_but_content_sensitive():
    """Proxmox does not promise enumeration order, so a reordered read must not read as a change —
    while a genuine state change must."""
    a = _observation(objects=(_SECP_OBJECTS[0], _SECP_OBJECTS[1], _SECP_OBJECTS[2]))
    b = _observation(objects=(_SECP_OBJECTS[2], _SECP_OBJECTS[0], _SECP_OBJECTS[1]))
    assert a.pending_hash() == b.pending_hash()

    changed = dataclasses.replace(_SECP_OBJECTS[0], state="deleted")
    c = _observation(objects=(changed, _SECP_OBJECTS[1], _SECP_OBJECTS[2]))
    assert c.pending_hash() != a.pending_hash()


def test_an_unchanged_pending_state_permits_activation():
    """A gate that never opens is not a gate."""
    observed = _observation()
    assert _refusals(observed, _authorization(observed)) == ()


# --- disclosure -----------------------------------------------------------------------------------


def test_foreign_objects_are_identified_rather_than_filtered():
    observed = _observation(objects=(*_SECP_OBJECTS, _FOREIGN))
    assert observed.foreign_objects == (_FOREIGN,)


def test_an_object_that_cannot_be_proven_ours_is_treated_as_foreign():
    """The safe direction. Absence of a SECP marker means foreign, so it is disclosed rather than
    quietly counted as ours — SDN objects carry no provider-side ownership attribute at all."""
    unmarked = PendingSdnObject("vnets", "someone-elses", "new")
    assert unmarked.secp_owned is False
    assert _observation(objects=(unmarked,)).foreign_objects == (unmarked,)


def test_an_authorization_that_understated_the_foreign_count_refuses():
    """An authorisation that did not disclose what it would commit did not describe the act being
    authorised, even when its hash matches."""
    observed = _observation(objects=(*_SECP_OBJECTS, _FOREIGN))
    understated = _authorization(observed, disclosed_foreign_object_count=0)
    assert "sdn_activation_foreign_disclosure_mismatch" in _refusals(observed, understated)


# --- incomplete observation -----------------------------------------------------------------------


def test_a_partial_pending_view_cannot_back_an_activation():
    """ "We do not know what is pending" is not "nothing is pending".

    A denied SDN index returns 200 with an empty list, so an incomplete enumeration is exactly the
    case that would otherwise look like a clean cluster.
    """
    observed = _observation(
        complete=False, unreadable_families=(("controllers", "permission_denied"),)
    )
    reasons = _refusals(observed, _authorization(observed))
    assert "sdn_activation_pending_state_incomplete" in reasons
    assert "sdn_pending_family_unreadable:controllers:permission_denied" in reasons


def test_an_empty_but_complete_observation_is_usable():
    """Genuinely nothing pending, with authority confirmed, is a real and permitted state."""
    observed = _observation(objects=())
    assert observed.is_empty is True
    assert _refusals(observed, _authorization(observed)) == ()


# --- staleness and stage order --------------------------------------------------------------------


def test_an_expired_observation_refuses():
    """The TTL bounds the window in which a foreign change could be staged unseen."""
    old = _observation(observed_at=NOW - timedelta(hours=2))
    assert "sdn_activation_observation_expired" in _refusals(old, _authorization(old))


def test_an_observation_from_the_future_is_skew_not_freshness():
    ahead = _observation(observed_at=NOW + timedelta(minutes=5))
    assert "sdn_activation_observation_clock_skew" in _refusals(ahead, _authorization(ahead))


@pytest.mark.parametrize("stage", [STAGE_PREPARED, STAGE_PENDING_OBSERVED, STAGE_ACTIVATED])
def test_activation_is_reachable_only_from_the_authorized_stage(stage):
    observed = _observation()
    reasons = _refusals(observed, _authorization(observed), stage=stage)
    assert f"sdn_activation_wrong_stage:{stage}" in reasons


def test_activation_without_an_authorization_refuses():
    assert "sdn_activation_unauthorized" in _refusals(_observation(), None)


def test_activation_without_an_observation_refuses():
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
    assert next_stage(STAGE_PENDING_OBSERVED) == STAGE_ACTIVATION_AUTHORIZED
    assert next_stage(STAGE_ACTIVATION_AUTHORIZED) == STAGE_ACTIVATED
    assert next_stage(STAGE_ACTIVATED) == STAGE_VERIFIED
    with pytest.raises(SdnActivationRefused, match="already_verified"):
        next_stage(STAGE_VERIFIED)
    with pytest.raises(SdnActivationRefused, match="unknown_stage"):
        next_stage("activated_probably")


def test_a_target_mismatch_refuses():
    observed = _observation()
    other = _authorization(observed, target_identity="target-other")
    assert "sdn_activation_target_mismatch" in _refusals(observed, other)


# --- stage 5 gates guests -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stage", [STAGE_PREPARED, STAGE_PENDING_OBSERVED, STAGE_ACTIVATION_AUTHORIZED, STAGE_ACTIVATED]
)
def test_guests_cannot_deploy_before_the_sdn_is_verified(stage):
    """Activated is not verified.

    `PUT /cluster/sdn` returning success means the task was accepted, not that every node reloaded
    and the bridges exist. A guest attached to a VNet that has not materialised on its node fails in
    a way that looks like a guest problem.
    """
    assert guests_may_deploy(stage) is False


def test_guests_may_deploy_once_verified():
    assert guests_may_deploy(STAGE_VERIFIED) is True


# --- all reasons at once --------------------------------------------------------------------------


def test_every_failing_condition_is_reported_not_just_the_first():
    observed = _observation(
        observed_at=NOW - timedelta(hours=3),
        objects=(*_SECP_OBJECTS, _FOREIGN),
        complete=False,
        unreadable_families=(("vnets", "permission_denied"),),
    )
    auth = _authorization(
        observed,
        authorized_pending_hash="sha256:" + "0" * 64,
        target_identity="target-other",
        disclosed_foreign_object_count=0,
    )
    reasons = _refusals(observed, auth)
    for expected in (
        "sdn_activation_pending_state_incomplete",
        "sdn_activation_pending_state_changed",
        "sdn_activation_observation_expired",
        "sdn_activation_target_mismatch",
        "sdn_activation_foreign_disclosure_mismatch",
    ):
        assert expected in reasons, expected


def test_reasons_are_deduplicated_and_stable():
    observed = _observation()
    auth = _authorization(observed, authorized_pending_hash="sha256:" + "0" * 64)
    assert _refusals(observed, auth) == _refusals(observed, auth)
    assert len(set(_refusals(observed, auth))) == len(_refusals(observed, auth))
