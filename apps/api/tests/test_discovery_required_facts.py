"""The required-fact table, and the discipline that keeps it honest.

Two failure modes, opposite in direction, and both fatal to the table's usefulness:

* **Too permissive** — a fact that prevents a real collision is left optional, so a plan compiles
  against a cluster nobody checked and the damage happens at apply.
* **Too strict** — facts are marked required because they seem prudent, the required set grows until
  discovery can never complete, and someone eventually relaxes the gate wholesale.

The guard against the second is the rule that every blocking fact must NAME the unsafe decision it
prevents. A requirement nobody can argue with is a requirement nobody reviewed.
"""

from __future__ import annotations

import pytest
from secp_api.discovery_required_facts import (
    REQUIRED_FACTS,
    UNSAFE_CONDITIONS,
    FactRequirement,
    RequiredFact,
    apply_refusals,
    compilation_refusals,
    facts_required_before_apply,
    facts_required_before_compilation,
    privileges_required,
)

_BLOCKING = {
    FactRequirement.required_before_compilation,
    FactRequirement.required_before_apply,
}


# --- the discipline -------------------------------------------------------------------------------


def test_every_blocking_fact_names_the_unsafe_decision_it_prevents():
    """A requirement that cannot say what it prevents cannot be argued with, and a required set
    nobody can argue with grows without limit."""
    unexplained = [
        f.name for f in REQUIRED_FACTS if f.requirement in _BLOCKING and not f.unsafe_decision
    ]
    assert unexplained == [], f"blocking facts with no stated unsafe decision: {unexplained}"


def test_no_non_blocking_fact_pretends_to_block():
    """`operator_context`, `optional` and `unsupported` must never appear in a refusal set."""
    blocking = set(facts_required_before_compilation()) | set(facts_required_before_apply())
    for fact in REQUIRED_FACTS:
        if fact.requirement not in _BLOCKING:
            assert fact.name not in blocking, fact.name


def test_fact_names_are_unique():
    names = [f.name for f in REQUIRED_FACTS]
    assert len(names) == len(set(names))


def test_the_two_gates_are_disjoint():
    """A fact belongs to one gate. Appearing in both would mean compilation refuses for a reason
    that is really an execution constraint, blocking review that should have been possible."""
    assert set(facts_required_before_compilation()) & set(facts_required_before_apply()) == set()


# --- the twelve conditions ------------------------------------------------------------------------


def test_every_unsafe_condition_is_covered_by_at_least_one_required_fact():
    """The table exists to exclude these twelve. A condition with no fact behind it is a condition
    nothing actually prevents.

    Matched on the condition's own words appearing in some blocking fact's stated decision — which
    is loose, deliberately: a stricter key would be satisfied by relabelling rather than by
    covering.
    """
    blocking_text = " ".join(
        f.unsafe_decision.lower() for f in REQUIRED_FACTS if f.requirement in _BLOCKING
    )
    keywords = {
        "vmid_or_lxcid_collision": ["vmid collision", "collision for containers"],
        "vlan_collision": ["vlan collision"],
        "subnet_overlap": ["subnet overlap"],
        "management_network_overlap": ["management-network overlap"],
        "foreign_sdn_ownership": ["foreign sdn ownership"],
        "unsupported_storage_placement": ["unsupported storage placement"],
        "unsupported_template_or_image": ["unsupported template", "unsupported image"],
        "unsupported_firewall_capability": ["unsupported firewall capability"],
        "pending_sdn_state": ["pending"],
        "incomplete_target_identity": ["incomplete target identity"],
        "stale_discovery": ["stale discovery"],
        "unverifiable_discovery_producer": ["unverifiable discovery producer"],
    }
    assert set(keywords) == set(UNSAFE_CONDITIONS), "keyword map drifted from UNSAFE_CONDITIONS"
    uncovered = [
        condition
        for condition, phrases in keywords.items()
        if not any(p in blocking_text for p in phrases)
    ]
    assert uncovered == [], f"unsafe conditions no required fact prevents: {uncovered}"


# --- the collision facts specifically -------------------------------------------------------------


@pytest.mark.parametrize(
    "fact",
    [
        "existing_vm_ids",
        "existing_lxc_ids",
        "existing_vlan_use",
        "existing_subnets",
        "existing_sdn_zones",
        "existing_vnets",
        "pending_sdn_state",
        "management_cidrs",
        "management_bridges",
        "bridge_vlan_awareness",
    ],
)
def test_collision_sensitive_facts_block_compilation(fact):
    """These are the ones whose absence damages something real.

    ``bridge_vlan_awareness`` is in the list for a reason worth stating: a VLAN tag on a
    non-VLAN-aware bridge is silently ignored, so every team lands on one flat segment — an
    isolation failure that presents as a successful apply.

    ``existing_lxc_ids`` is separate from ``existing_vm_ids`` because the shipped probe passes
    `--type vm` and therefore cannot see containers at all.
    """
    assert fact in facts_required_before_compilation()


def test_pending_sdn_state_blocks_compilation_not_merely_apply():
    """Unknown pending state is not "nothing pending".

    An object staged for deletion still occupies its id, and one staged for creation is absent from
    the running config — so the id space the compiler reasons over is wrong in both directions.
    That is a content problem, not an execution constraint.
    """
    assert "pending_sdn_state" in facts_required_before_compilation()
    assert "pending_sdn_state" not in facts_required_before_apply()


# --- the refusal functions ------------------------------------------------------------------------


def test_compilation_refuses_with_the_reason_attached():
    usable = frozenset(facts_required_before_compilation()) - {"existing_vlan_use"}
    refusals = compilation_refusals(usable)
    assert len(refusals) == 1
    name, reason = refusals[0]
    assert name == "existing_vlan_use"
    assert "vlan collision" in reason.lower()


def test_a_complete_fact_set_produces_no_refusals():
    """A gate that never opens is not a gate."""
    assert compilation_refusals(frozenset(facts_required_before_compilation())) == ()
    assert apply_refusals(frozenset(facts_required_before_apply())) == ()


def test_compilation_refuses_only_on_the_compilation_set():
    """An apply-gate fact must not block compilation — the operator must still be able to review a
    plan for a node that happens to be offline."""
    usable = frozenset(facts_required_before_compilation())  # nothing from the apply set
    assert compilation_refusals(usable) == ()
    assert apply_refusals(usable) != ()


def test_an_empty_fact_set_refuses_everything_blocking():
    assert len(compilation_refusals(frozenset())) == len(facts_required_before_compilation())
    assert len(apply_refusals(frozenset())) == len(facts_required_before_apply())


# --- the privilege set is derived, not declared ---------------------------------------------------


def test_the_privilege_set_is_derived_from_the_table():
    """The credential proposal and the fact table cannot drift: the role is exactly what the
    required facts need.

    A privilege appearing here that no fact needs would be a grant nobody could justify — which is
    the direction credential proposals drift in.
    """
    assert privileges_required() == frozenset(
        {"Sys.Audit", "VM.Audit", "Datastore.Audit", "SDN.Audit"}
    )


def test_no_write_class_privilege_appears_anywhere_in_the_table():
    """SDN.Allocate is a WRITE-class privilege that some Proxmox detail endpoints demand. Those
    endpoints are redundant with their indexes and must never enter the required set."""
    forbidden = {
        "SDN.Allocate",
        "Sys.Modify",
        "VM.Allocate",
        "VM.PowerMgmt",
        "Datastore.Allocate",
        "Permissions.Modify",
    }
    assert privileges_required() & forbidden == set()
    for fact in REQUIRED_FACTS:
        assert fact.privilege not in forbidden, fact.name


def test_every_sdn_fact_requires_sdn_audit_and_nothing_stronger():
    sdn_facts = [f for f in REQUIRED_FACTS if "sdn" in f.name or f.name == "existing_vlan_use"]
    assert sdn_facts, "expected SDN facts in the table"
    for fact in sdn_facts:
        assert fact.privilege == "SDN.Audit", (fact.name, fact.privilege)


# --- shape ---------------------------------------------------------------------------------------


def test_the_table_is_frozen_data():
    """Frozen so a caller cannot narrow the required set at runtime — the gate must be the same one
    every reviewer read."""
    import dataclasses

    assert isinstance(REQUIRED_FACTS, tuple)
    assert all(isinstance(f, RequiredFact) for f in REQUIRED_FACTS)
    with pytest.raises(dataclasses.FrozenInstanceError):
        REQUIRED_FACTS[0].name = "mutated"  # type: ignore[misc]
