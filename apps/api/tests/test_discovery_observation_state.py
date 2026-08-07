"""An observed empty list and an unobserved list are different facts.

That sentence is the whole module under test. Every case here is a way of accidentally erasing the
distinction — by giving an unobserved fact a value, by projecting a null that reads as the fact, by
letting a denied read look like an absent object, or by treating "we have no probe for this" as
"there are none".

The Proxmox case that makes it urgent rather than theoretical: a privilege-denied SDN read can come
back as an EMPTY LIST rather than a 403. At the wire, "this cluster has no SDN zones" and "this
credential may not see SDN zones" are the same bytes. If the difference is not kept here, the plan
compiler allocates VLANs into a zone space it was never allowed to look at.
"""

from __future__ import annotations

import pytest
from secp_api.discovery_observation import (
    Observation,
    ObservationStateError,
    unusable_facts,
)
from secp_api.enums import DiscoveryObservationState as S

# --- the distinction ------------------------------------------------------------------------------


def test_an_observed_empty_list_is_a_fact_and_is_usable():
    """The target genuinely has no SDN zones. That is knowledge, and the compiler may rely on it."""
    obs = Observation.observed([])
    assert obs.is_usable is True
    assert obs.value == []
    assert obs.projected() == {"state": "observed", "value": []}


@pytest.mark.parametrize(
    "obs,label",
    [
        (Observation.not_requested("narrow_run"), "not_requested"),
        (Observation.not_implemented("no_sdn_probe"), "not_implemented"),
        (
            Observation.permission_denied(missing_privilege="SDN.Audit", reason_code="denied"),
            "permission_denied",
        ),
        (Observation.probe_refused("not_in_wrapper_allowlist"), "probe_refused"),
        (Observation.probe_failed("probe_timeout"), "probe_failed"),
        (Observation.source_unavailable("bootstrap_unavailable"), "source_unavailable"),
    ],
)
def test_an_unobserved_list_is_not_usable_and_carries_no_value(obs, label):
    assert obs.is_usable is False, label
    assert obs.value is None, label
    assert obs.was_looked_for is False, label
    # The key is ABSENT, not null. A consumer that ignores `state` gets a KeyError rather than a
    # plausible wrong answer — null would be read as "none", which is the whole mistake.
    assert "value" not in obs.projected(), label


def test_an_unobserved_fact_cannot_be_given_a_value():
    """Structural, not conventional. The mistake is refused at construction."""
    with pytest.raises(ObservationStateError, match="has no value"):
        Observation(state=S.permission_denied, value=[], reason_code="x", missing_privilege="y")
    with pytest.raises(ObservationStateError, match="has no value"):
        Observation(state=S.not_implemented, value=[], reason_code="x")


def test_an_unobserved_fact_must_explain_itself():
    with pytest.raises(ObservationStateError, match="no reason code"):
        Observation(state=S.probe_failed)


def test_permission_denied_must_name_the_privilege():
    """An operator told only "denied" goes looking. Told "SDN.Audit", they act."""
    with pytest.raises(ObservationStateError, match="name the privilege"):
        Observation(state=S.permission_denied, reason_code="denied")

    obs = Observation.permission_denied(missing_privilege="SDN.Audit", reason_code="denied")
    assert obs.projected()["missing_privilege"] == "SDN.Audit"


def test_an_observed_fact_must_carry_its_value():
    with pytest.raises(ObservationStateError, match="must carry its value"):
        Observation(state=S.observed)


# --- looked-at versus not-looked-at ---------------------------------------------------------------


@pytest.mark.parametrize(
    "obs",
    [
        Observation.observed(["z1"]),
        Observation.malformed("unparseable_json"),
        Observation.unsupported("sdn_absent_on_this_pve"),
    ],
)
def test_a_target_that_answered_counts_as_looked_for(obs):
    """``malformed`` and ``unsupported`` are evidence ABOUT THE TARGET — it was asked and replied.

    That is a different thing from SECP never asking, even though neither yields a usable value, and
    an operator investigating a gap needs to know which side the problem is on.
    """
    assert obs.was_looked_for is True
    assert obs.is_usable is (obs.state == S.observed)


def test_malformed_is_not_the_same_as_failed():
    """One says the target sent nonsense; the other says nothing came back. Different fixes."""
    assert Observation.malformed("x").state != Observation.probe_failed("x").state
    assert Observation.malformed("x").was_looked_for is True
    assert Observation.probe_failed("x").was_looked_for is False


# --- the whole vocabulary -------------------------------------------------------------------------


def test_the_state_vocabulary_is_exactly_the_nine_reviewed_members():
    """Pinned by CONTENT so a tenth member is a reviewed edit, not a quiet one.

    Keyed on the value set rather than a count: swapping one member for another keeps a count test
    green while changing what the compiler can be told.
    """
    assert {m.value for m in S} == {
        "observed",
        "observed_malformed",
        "observed_unsupported",
        "not_requested",
        "not_implemented",
        "permission_denied",
        "probe_refused",
        "probe_failed",
        "source_unavailable",
    }


def test_exactly_one_state_yields_a_usable_value():
    """If a second state were ever usable, every `is_usable` call site would silently widen."""
    usable = [s for s in S if s == S.observed]
    assert len(usable) == 1


def test_unusable_facts_reports_the_state_not_merely_the_name():
    """The compiler refuses differently per state.

    permission_denied is an operator action, not_implemented is a release blocker, and
    observed_unsupported may be acceptable on an older target.
    """
    facts = {
        "sdn_zones": Observation.permission_denied(
            missing_privilege="SDN.Audit", reason_code="denied"
        ),
        "pending_sdn": Observation.not_implemented("no_probe"),
        "storage": Observation.observed(["local-lvm"]),
        "vnets": Observation.observed([]),
    }
    assert unusable_facts(facts) == {
        "sdn_zones": "permission_denied",
        "pending_sdn": "not_implemented",
    }
    # The observed-empty vnet list is NOT reported as missing — it is knowledge.
    assert "vnets" not in unusable_facts(facts)
