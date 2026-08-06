"""The two vocabularies must line up, and every way a fact could look present must be closed.

The failure this file exists to catch is not a crash. It is a snapshot that verifies, is fresh, is
signed by the right worker — and reports ``node_capacity`` as observed on the strength of one node
out of three, or reports an empty SDN zone list that the target only returned because the token was
not allowed to see any zones.
"""

from __future__ import annotations

import pytest
from secp_api.discovery_fact_projection import (
    REQUIRED_FACT_PROJECTION_ID,
    project_required_facts,
    required_fact_states,
    unobserved_privileges,
    usable_fact_names,
)
from secp_api.discovery_observation import Observation
from secp_api.discovery_required_facts import (
    REQUIRED_FACTS,
    facts_required_before_apply,
    facts_required_before_compilation,
)
from secp_api.enums import DiscoveryObservationState as S

NODES = ("pve-a", "pve-b")


def _sdn_authority() -> Observation:
    return Observation.observed({"cluster_sdn_readable": True, "sdn_audit_granted": True})


def _raw(**overrides) -> dict[str, Observation]:
    """A two-node cluster that answered everything. Overrides remove or replace one fact."""
    base: dict[str, Observation] = {
        "pve_version_major": Observation.observed(9),
        "pve_version_minor": Observation.observed(1),
        "pve_version_patch": Observation.observed(1),
        "pve_version_full": Observation.observed("9.1.1"),
        "pve_release": Observation.observed("9.1"),
        "pve_repoid": Observation.observed("abc1234567"),
        "cluster_identity": Observation.observed({"kind": "cluster", "cluster_name": "lab"}),
        "node_names": Observation.observed(NODES),
        "node_online_state": Observation.observed({n: "online" for n in NODES}),
        "node_capacity": Observation.observed({n: {"cpus": 8} for n in NODES}),
        "kernel_version": Observation.observed({n: "6.14" for n in NODES}),
        "node_versions": Observation.observed({n: "9.1.1" for n in NODES}),
        "raw_host_package_version": Observation.observed({n: {} for n in NODES}),
        "release_build_identifier": Observation.observed({n: "9.1.1" for n in NODES}),
        "bridges": Observation.observed({n: ("vmbr0",) for n in NODES}),
        "bridge_vlan_awareness": Observation.observed({f"{n}/vmbr0": True for n in NODES}),
        "management_bridges": Observation.observed({n: ("vmbr0",) for n in NODES}),
        "management_cidrs": Observation.observed({n: ("10.0.0.5/24",) for n in NODES}),
        "storage_ids": Observation.observed({n: ("local",) for n in NODES}),
        "storage_types": Observation.observed({f"{n}/local": "dir" for n in NODES}),
        "allowed_storage_content": Observation.observed({f"{n}/local": ("iso",) for n in NODES}),
        "available_capacity": Observation.observed({f"{n}/local": {"total": 1} for n in NODES}),
        "iso_and_container_template_availability": Observation.observed(
            {f"{n}/local": {"iso": ()} for n in NODES}
        ),
        "templates": Observation.observed({n: () for n in NODES}),
        "existing_vm_ids": Observation.observed({n: (100,) for n in NODES}),
        "existing_lxc_ids": Observation.observed({n: () for n in NODES}),
        "firewall_capability": Observation.observed({"cluster_options": {"enable": True}}),
        "sdn_read_authority": _sdn_authority(),
        "existing_sdn_zones": Observation.observed({"z1": {}}),
        "existing_vnets": Observation.observed({"v1": {}}),
        "existing_subnets": Observation.observed({"s1": {}}),
        "existing_vlan_use": Observation.observed({"vnet:v1": 100}),
        "pending_sdn_state": Observation.observed(
            {"zones": (), "vnets": (), "controllers": (), "subnets@v1": ()}
        ),
    }
    for key, value in overrides.items():
        if value is None:
            base.pop(key, None)
        else:
            base[key] = value
    return base


def _control_plane() -> dict[str, Observation]:
    return {
        "target_identity": Observation.observed("target-1"),
        "observation_timestamp": Observation.observed("2026-08-06T12:00:00+00:00"),
        "worker_identity": Observation.observed("wk-1"),
        "evidence_signature": Observation.observed("sig"),
        "worker_release_fingerprint": Observation.observed("sha256:" + "r" * 64),
        "target_tls_identity": Observation.observed("sha256:" + "t" * 64),
    }


# === the two vocabularies line up =================================================================


def test_every_required_fact_gets_an_observation_and_no_others():
    projected = project_required_facts(_raw(), control_plane_facts=_control_plane())
    assert set(projected) == {fact.name for fact in REQUIRED_FACTS}


def test_a_fully_answered_run_satisfies_both_gates():
    """The positive case has to exist, or every negative below could pass with a projection that
    refuses unconditionally."""
    projected = project_required_facts(_raw(), control_plane_facts=_control_plane())
    usable = usable_fact_names(projected)
    assert not [f for f in facts_required_before_compilation() if f not in usable]
    assert not [f for f in facts_required_before_apply() if f not in usable]


def test_the_states_that_go_into_the_signature_are_sorted_and_carry_the_state():
    projected = project_required_facts(_raw(), control_plane_facts=_control_plane())
    states = required_fact_states(projected)
    assert states == tuple(sorted(states))
    assert ("cluster_identity", "observed") in states
    assert len(states) == len(REQUIRED_FACTS)


def test_the_projection_names_itself():
    assert REQUIRED_FACT_PROJECTION_ID == "secp-discovery/projection/v1"


def test_a_required_fact_with_no_derivation_fails_at_import_rather_than_silently_refusing():
    """A fact added to the required table with no derivation here would project to not_requested
    forever — an invisible permanent refusal, which is worse than either a crash or a gap."""
    import secp_api.discovery_fact_projection as projection

    original = projection._ALL_DERIVATIONS
    try:
        projection._ALL_DERIVATIONS = original - {"cluster_identity"}
        with pytest.raises(projection.FactProjectionTableError, match="undeclared="):
            projection._assert_table_is_total()
    finally:
        projection._ALL_DERIVATIONS = original


def test_a_derivation_for_a_fact_the_table_does_not_name_also_fails():
    import secp_api.discovery_fact_projection as projection

    original = projection._ALL_DERIVATIONS
    try:
        projection._ALL_DERIVATIONS = original | {"invented_fact"}
        with pytest.raises(projection.FactProjectionTableError, match="invented="):
            projection._assert_table_is_total()
    finally:
        projection._ALL_DERIVATIONS = original


# === composed: the exact version ==================================================================


def test_the_exact_version_is_composed_from_three_raw_fields():
    projected = project_required_facts(_raw(), control_plane_facts=_control_plane())
    assert projected["exact_pve_version"].value == "9.1.1"


def test_a_missing_patch_component_makes_the_exact_version_unusable():
    """Provider compatibility is decided at the patch level, so a truncated 9.1 standing in for an
    actual 9.1.1 is a different answer, not a partial one."""
    raw = _raw(
        pve_version_patch=Observation.malformed("version_reported_without_a_patch_component")
    )
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["exact_pve_version"].is_usable is False
    assert projected["exact_pve_version"].state is S.observed_malformed
    assert projected["exact_pve_version"].reason_code == (
        "version_reported_without_a_patch_component"
    )


def test_a_component_state_is_carried_forward_rather_than_flattened():
    """permission_denied and observed_unsupported demand different operator responses; reporting
    both as "missing" hides which one applies."""
    raw = _raw(
        pve_version_minor=Observation.permission_denied(
            missing_privilege="Sys.Audit", reason_code="denied"
        )
    )
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["exact_pve_version"].state is S.permission_denied
    assert projected["exact_pve_version"].missing_privilege == "Sys.Audit"


# === node completeness ============================================================================


def test_a_fact_covering_one_node_of_two_is_not_observed():
    """This is what a plan compiler would read as "capacity is known" immediately before placing
    guests on the node nobody looked at."""
    raw = _raw(node_capacity=Observation.observed({"pve-a": {"cpus": 8}}))
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["node_capacity"].is_usable is False
    assert projected["node_capacity"].reason_code == "node_capacity_missing_for_nodes:pve-b"


def test_a_storage_scoped_fact_must_cover_every_node_too():
    raw = _raw(available_capacity=Observation.observed({"pve-a/local": {"total": 1}}))
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["available_capacity"].is_usable is False
    assert "pve-b" in projected["available_capacity"].reason_code


def test_a_node_with_none_of_the_thing_is_covered_vacuously():
    """A node with no bridges is fully described by an empty VLAN-awareness mapping. Without this,
    that node would look permanently unobserved and refuse compilation forever."""
    raw = _raw(
        bridges=Observation.observed({"pve-a": ("vmbr0",), "pve-b": ()}),
        bridge_vlan_awareness=Observation.observed({"pve-a/vmbr0": True}),
    )
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["bridge_vlan_awareness"].is_usable is True


def test_completeness_cannot_be_checked_without_the_node_list():
    raw = _raw(node_names=None)
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["node_capacity"].is_usable is False
    assert "without_node_names" in projected["node_capacity"].reason_code


def test_a_node_scoped_fact_that_is_not_a_mapping_is_malformed():
    raw = _raw(node_capacity=Observation.observed(("pve-a",)))
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["node_capacity"].state is S.observed_malformed


# === the SDN silent-filter gate ===================================================================


def test_without_the_root_read_every_sdn_fact_is_permission_denied():
    """Proxmox answers a privilege-denied SDN index with 200 and an empty list, so an empty zones
    result is indistinguishable at the wire from "no zones"."""
    raw = _raw(sdn_read_authority=None, existing_sdn_zones=Observation.observed({}))
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    for fact in (
        "existing_sdn_zones",
        "existing_vnets",
        "existing_subnets",
        "existing_vlan_use",
        "pending_sdn_state",
    ):
        assert projected[fact].state is S.permission_denied, fact
        assert projected[fact].missing_privilege == "SDN.Audit"
        assert projected[fact].reason_code == "sdn_read_authority_not_established"


def test_the_gate_applies_even_when_the_index_returned_rows():
    """Rows prove SOME visibility, never that the answer is complete — and completeness is what
    excluding a collision requires."""
    raw = _raw(
        sdn_read_authority=None,
        existing_sdn_zones=Observation.observed({"z1": {}, "z2": {}}),
    )
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["existing_sdn_zones"].state is S.permission_denied


def test_a_grant_claim_does_not_substitute_for_the_demonstrated_read():
    """/access/permissions reporting SDN.Audit is a claim about a grant; /cluster/sdn is a
    demonstrated read, and it is the endpoint that cannot answer 200-with-empty for a permission
    reason."""
    raw = _raw(sdn_read_authority=Observation.observed({"sdn_audit_granted": True}))
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["existing_sdn_zones"].state is S.permission_denied


def test_the_refused_privilege_is_reported_once_for_the_operator():
    raw = _raw(sdn_read_authority=None)
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert unobserved_privileges(projected) == ("SDN.Audit",)


# === pending SDN completeness =====================================================================


@pytest.mark.parametrize(
    "pending,expected_fragment",
    [
        ({"zones": (), "vnets": (), "subnets@v1": ()}, "controllers"),
        ({"zones": (), "controllers": (), "subnets@v1": ()}, "vnets"),
        ({"zones": (), "vnets": (), "controllers": ()}, "subnets@v1"),
    ],
)
def test_a_partial_pending_enumeration_is_an_unknown_not_a_smaller_answer(
    pending, expected_fragment
):
    """There is no read-only "does anything pend" boolean in the API, so completeness across every
    family is the only way to know."""
    raw = _raw(pending_sdn_state=Observation.observed(pending))
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["pending_sdn_state"].is_usable is False
    assert expected_fragment in projected["pending_sdn_state"].reason_code


def test_subnets_must_be_walked_for_every_observed_vnet():
    """There is no cluster-wide subnet index, so one vnet's answer must not stand in for all."""
    raw = _raw(
        existing_vnets=Observation.observed({"v1": {}, "v2": {}}),
        pending_sdn_state=Observation.observed(
            {"zones": (), "vnets": (), "controllers": (), "subnets@v1": ()}
        ),
    )
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert "subnets@v2" in projected["pending_sdn_state"].reason_code


def test_pending_completeness_cannot_be_claimed_without_a_vnet_index():
    raw = _raw(existing_vnets=Observation.probe_failed("x"))
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert "no_vnet_index" in projected["pending_sdn_state"].reason_code


# === control-plane facts ==========================================================================


def test_identity_and_signature_are_never_derived_from_a_payload():
    """A target asserting its own identity is the substitution the binding exists to prevent."""
    raw = _raw()
    raw["target_identity"] = Observation.observed("target-the-target-chose")
    raw["evidence_signature"] = Observation.observed("signature-the-target-chose")
    projected = project_required_facts(raw, control_plane_facts={})
    assert projected["target_identity"].is_usable is False
    assert projected["evidence_signature"].is_usable is False
    assert "not_supplied_by_the_control_plane" in projected["target_identity"].reason_code


def test_control_plane_facts_come_from_the_control_plane():
    projected = project_required_facts(_raw(), control_plane_facts=_control_plane())
    assert projected["worker_identity"].value == "wk-1"


# === no source is code to write, not a grant to request ===========================================


def test_a_fact_no_operation_answers_is_not_implemented():
    projected = project_required_facts(_raw(), control_plane_facts=_control_plane())
    assert projected["api_feature_availability"].state is S.not_implemented
    assert projected["credential_identity_reference"].state is S.not_implemented


def test_a_fact_this_run_did_not_ask_for_is_explained():
    raw = _raw(firewall_capability=None)
    projected = project_required_facts(raw, control_plane_facts=_control_plane())
    assert projected["firewall_capability"].state is S.not_requested
    assert projected["firewall_capability"].reason_code == (
        "firewall_capability_not_observed_by_this_run"
    )
