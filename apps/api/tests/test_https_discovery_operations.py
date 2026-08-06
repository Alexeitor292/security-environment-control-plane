"""The typed HTTPS operation inventory, non-SDN and SDN, on one engine.

Two rules are enforced across every operation and are the reason this is a type per request rather
than a path per call:

* **no caller-controlled path or query.** A dynamic segment must come from a prior validated
  response, and ``sourced_from`` is required so a well-formed identifier a caller invented is
  refused exactly like a malformed one — provenance, not shape;
* **no mutation is representable.** There is no method parameter anywhere on the surface.
"""

from __future__ import annotations

import dataclasses

import pytest
from secp_worker.proxmox_discovery_operations import (
    FIRST_MVP_OPERATIONS,
    MAX_DYNAMIC_EXPANSION,
    GetClusterFirewallGroupsOperation,
    GetClusterFirewallOptionsOperation,
    GetClusterResourcesOperation,
    GetClusterStatusOperation,
    GetNodeAptVersionsOperation,
    GetNodeLxcOperation,
    GetNodeNetworkOperation,
    GetNodeQemuOperation,
    GetNodesOperation,
    GetNodeStatusOperation,
    GetNodeStorageOperation,
    GetNodeVersionOperation,
    GetStorageContentOperation,
    GetVersionOperation,
    OperationParameterError,
    bounded_identifiers,
    validated_segment,
)
from secp_worker.proxmox_sdn_operations import (
    SDN_OPERATIONS,
    SDN_PENDING_FAMILIES,
    GetEffectivePermissionsOperation,
    GetNodeSdnBridgesOperation,
    GetNodeSdnZonesOperation,
    GetSdnControllersOperation,
    GetSdnFabricsOperation,
    GetSdnIpamStatusOperation,
    GetSdnRootOperation,
    GetSdnSubnetsOperation,
    GetSdnVnetsOperation,
    GetSdnZonesOperation,
    parse_pending_objects,
    pending_families_complete,
)

SRC = "prior:/nodes"


# --- the inventory -------------------------------------------------------------------------------


def test_the_non_sdn_operation_inventory_is_the_reviewed_set():
    assert set(FIRST_MVP_OPERATIONS) == {
        GetVersionOperation,
        GetClusterStatusOperation,
        GetNodesOperation,
        GetNodeStatusOperation,
        GetNodeVersionOperation,
        GetNodeAptVersionsOperation,
        GetNodeNetworkOperation,
        GetNodeStorageOperation,
        GetStorageContentOperation,
        GetClusterResourcesOperation,
        GetNodeQemuOperation,
        GetNodeLxcOperation,
        GetClusterFirewallOptionsOperation,
        GetClusterFirewallGroupsOperation,
    }


def test_the_container_inventory_does_not_depend_on_the_type_vm_filter():
    """``existing_lxc_ids`` blocks compilation, and an empty set read as "no containers" is how
    SECP would allocate a CTID somebody already holds. Whether ``/cluster/resources?type=vm``
    returns container rows is UNVERIFIED against a live target from this repository, so the cluster
    read does not claim the fact at all and a dedicated per-node index answers it."""
    assert "existing_lxc_ids" not in GetClusterResourcesOperation.observation_field_codes
    assert GetNodeLxcOperation.observation_field_codes == ("existing_lxc_ids",)
    assert GetNodeLxcOperation("pve-a", SRC).rendered_path() == "/nodes/pve-a/lxc"


def test_guest_templates_are_a_guest_fact_and_not_a_storage_fact():
    """The required-fact table gates ``templates`` on VM.Audit and describes cloning from an absent
    guest template. Storage content answers a different question — which ISO and container-template
    VOLUMES exist — and having one operation claim both made one code carry two meanings."""
    assert "templates" not in GetStorageContentOperation.observation_field_codes
    assert "templates" in GetClusterResourcesOperation.observation_field_codes
    assert "templates" in GetNodeQemuOperation.observation_field_codes


def test_the_sdn_operation_inventory_is_the_reviewed_set():
    assert set(SDN_OPERATIONS) == {
        GetSdnRootOperation,
        GetEffectivePermissionsOperation,
        GetSdnZonesOperation,
        GetSdnVnetsOperation,
        GetSdnSubnetsOperation,
        GetSdnControllersOperation,
        GetSdnIpamStatusOperation,
        GetSdnFabricsOperation,
        GetNodeSdnZonesOperation,
        GetNodeSdnBridgesOperation,
    }


@pytest.mark.parametrize(
    "op,path,params",
    [
        (GetVersionOperation(), "/version", ()),
        (GetClusterStatusOperation(), "/cluster/status", ()),
        (GetNodesOperation(), "/nodes", ()),
        (GetNodeStatusOperation("pve-a", SRC), "/nodes/pve-a/status", ()),
        (GetNodeVersionOperation("pve-a", SRC), "/nodes/pve-a/version", ()),
        (GetNodeAptVersionsOperation("pve-a", SRC), "/nodes/pve-a/apt/versions", ()),
        (GetNodeNetworkOperation("pve-a", SRC), "/nodes/pve-a/network", ()),
        (GetNodeStorageOperation("pve-a", SRC), "/nodes/pve-a/storage", ()),
        (
            GetStorageContentOperation("pve-a", "local-lvm", SRC),
            "/nodes/pve-a/storage/local-lvm/content",
            (),
        ),
        (GetClusterResourcesOperation(), "/cluster/resources", (("type", "vm"),)),
        (GetClusterFirewallOptionsOperation(), "/cluster/firewall/options", ()),
        (GetClusterFirewallGroupsOperation(), "/cluster/firewall/groups", ()),
        (GetSdnRootOperation(), "/cluster/sdn", ()),
        (GetEffectivePermissionsOperation(), "/access/permissions", ()),
        (GetSdnZonesOperation(), "/cluster/sdn/zones", (("pending", "1"),)),
        (GetSdnVnetsOperation(), "/cluster/sdn/vnets", (("pending", "1"),)),
        (
            GetSdnSubnetsOperation("secpteam1", SRC),
            "/cluster/sdn/vnets/secpteam1/subnets",
            (("pending", "1"),),
        ),
        (GetSdnControllersOperation(), "/cluster/sdn/controllers", (("pending", "1"),)),
        (GetSdnIpamStatusOperation(), "/cluster/sdn/ipams/pve/status", ()),
        (GetSdnFabricsOperation(), "/cluster/sdn/fabrics/all", (("pending", "1"),)),
        (GetNodeSdnZonesOperation("pve-a", SRC), "/nodes/pve-a/sdn/zones", ()),
        (
            GetNodeSdnBridgesOperation("pve-a", "secplab", SRC),
            "/nodes/pve-a/sdn/zones/secplab/bridges",
            (),
        ),
    ],
)
def test_each_operation_renders_its_exact_reviewed_request(op, path, params):
    assert op.rendered_path() == path
    assert op.query_parameters() == params


def test_no_operation_exposes_a_method_or_body():
    for op_type in (*FIRST_MVP_OPERATIONS, *SDN_OPERATIONS):
        for banned in ("method", "body", "data", "json", "headers"):
            assert not hasattr(op_type, banned), (op_type.__name__, banned)


def test_the_effective_permissions_operation_sends_no_userid():
    """Self-scoped is what keeps it inside a read-only grant: asking about another user requires
    Sys.Audit on /access."""
    assert GetEffectivePermissionsOperation().query_parameters() == ()
    assert "userid" not in GetEffectivePermissionsOperation().rendered_path()


def test_the_cluster_resources_type_is_fixed_not_a_caller_parameter():
    assert dataclasses.fields(GetClusterResourcesOperation) == ()
    assert GetClusterResourcesOperation().query_parameters() == (("type", "vm"),)


# --- dynamic identifiers -------------------------------------------------------------------------


def test_a_dynamic_identifier_without_provenance_is_refused():
    """Shape is not enough. A perfectly well-formed node name a caller invented must be refused
    exactly like a malformed one, because the rule is where it came from."""
    with pytest.raises(OperationParameterError, match="unsourced"):
        GetNodeStatusOperation("pve-a", "")


@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "pve-a/status",
        "pve-a?x=1",
        "pve a",
        "",
        "pve%2Fa",
        "-leading",
        "a" * 64,
        None,
        123,
    ],
)
def test_an_unsafe_dynamic_identifier_is_refused(bad):
    with pytest.raises(OperationParameterError, match="unsafe"):
        validated_segment(bad, field="node", sourced_from=SRC)


def test_a_dynamic_identifier_cannot_smuggle_another_host_or_query():
    for attempt in ("pve-a/../../cluster/sdn", "a//b", "x#frag"):
        with pytest.raises(OperationParameterError):
            GetNodeStatusOperation(attempt, SRC)


def test_dynamic_expansion_is_bounded():
    """A cluster reporting ten thousand nodes is a malformed answer, not a large cluster — and an
    unbounded expansion turns one read into a stampede."""
    assert bounded_identifiers(["pve-a", "pve-b"], field="node", sourced_from=SRC) == (
        "pve-a",
        "pve-b",
    )
    too_many = [f"pve{i}" for i in range(MAX_DYNAMIC_EXPANSION + 1)]
    with pytest.raises(OperationParameterError, match="too_large"):
        bounded_identifiers(too_many, field="node", sourced_from=SRC)


def test_a_malformed_identifier_list_is_refused():
    with pytest.raises(OperationParameterError, match="list_malformed"):
        bounded_identifiers("pve-a", field="node", sourced_from=SRC)


# --- pending-state parsing -----------------------------------------------------------------------


def test_a_new_object_takes_its_values_from_the_nested_pending_block():
    """THE parsing trap.

    For ``state: "new"`` Proxmox hoists only ``type`` and ``vnet`` to the top level; tag, bridge,
    nodes and cidr live under ``pending``. Top-level-only parsing sees an almost-empty record and
    reads it as a near-empty change — the opposite of the truth.
    """
    payload = [
        {
            "zone": "secplab",
            "type": "vlan",
            "state": "new",
            "pending": {"bridge": "vmbr0", "tag": 101, "nodes": "pve-a", "mtu": 1500},
        }
    ]
    (obj,) = parse_pending_objects("zones", payload)
    assert obj["state"] == "new"
    assert obj["bridge"] == "vmbr0"
    assert obj["tag"] == 101
    assert obj["nodes"] == "pve-a"
    assert "pending" not in obj


def test_a_changed_object_reports_the_values_activation_would_produce():
    """Top level holds the RUNNING values and ``pending`` the new ones, so nested-first precedence
    gives the post-activation state — which is what collision reasoning needs."""
    payload = [{"zone": "ops", "tag": 100, "state": "changed", "pending": {"tag": 200}}]
    (obj,) = parse_pending_objects("zones", payload)
    assert obj["tag"] == 200


def test_a_key_removed_by_a_pending_change_becomes_none_not_its_old_value():
    payload = [{"vnet": "v1", "alias": "old", "state": "changed", "pending": {"alias": "deleted"}}]
    (obj,) = parse_pending_objects("vnets", payload)
    assert obj["alias"] is None


def test_a_deleted_object_keeps_its_running_values():
    """An object staged for deletion still occupies its id until activation, so its values
    matter."""
    payload = [{"zone": "old", "tag": 55, "state": "deleted"}]
    (obj,) = parse_pending_objects("zones", payload)
    assert obj["state"] == "deleted"
    assert obj["tag"] == 55


def test_an_object_with_no_state_annotation_is_not_pending():
    """Identical in both configs — Proxmox annotates neither, and it is not a change."""
    assert parse_pending_objects("zones", [{"zone": "stable", "tag": 10}]) == ()


def test_no_pending_state_yields_an_empty_tuple_rather_than_an_error():
    assert parse_pending_objects("zones", []) == ()


@pytest.mark.parametrize("bad", [{}, "not-a-list", None, 42])
def test_a_malformed_pending_payload_is_refused_not_guessed(bad):
    with pytest.raises(ValueError, match="not_a_list"):
        parse_pending_objects("zones", bad)


def test_a_malformed_pending_row_is_refused():
    with pytest.raises(ValueError, match="not_an_object"):
        parse_pending_objects("zones", ["a string"])


# --- completeness --------------------------------------------------------------------------------


def test_every_pending_family_must_be_enumerated():
    """There is no read-only "does anything pend" boolean, so completeness across all four families
    is the only way to know. A partial enumeration is an unknown, not a smaller answer."""
    assert SDN_PENDING_FAMILIES == ("zones", "vnets", "subnets", "controllers")
    assert pending_families_complete({f: True for f in SDN_PENDING_FAMILIES}) is True
    for family in SDN_PENDING_FAMILIES:
        partial = {f: True for f in SDN_PENDING_FAMILIES}
        partial[family] = False
        assert pending_families_complete(partial) is False


def test_an_empty_enumeration_record_is_not_complete():
    assert pending_families_complete({}) is False
