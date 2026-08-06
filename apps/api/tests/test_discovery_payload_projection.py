"""Payloads become facts here, and this is where a confident wrong answer would be born.

Three properties carry the weight, and each is checked against the way it would actually fail:

* **an unrecognised non-empty payload is malformed, never empty.** "The target has no containers"
  and "this code did not understand the container list" are the same empty tuple to every consumer
  downstream, and the first permits a CTID collision;
* **every parser produces exactly the fields its operation declares.** A skipped field vanishes from
  the snapshot with no state and no reason; an invented one puts a fact into a signed document that
  no evidence record claims to have produced;
* **facts that exist per node or per storage are keyed mappings.** Anything else lets one node stand
  in for a cluster once the sequencer merges it.
"""

from __future__ import annotations

import pytest
from secp_api.enums import DiscoveryObservationState as S
from secp_worker.proxmox_discovery_operations import (
    FIRST_MVP_OPERATIONS,
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
)
from secp_worker.proxmox_discovery_projection import ProjectionError, observe
from secp_worker.proxmox_sdn_operations import (
    SDN_OPERATIONS,
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
)

SRC = "prior:/nodes"

#: One well-formed payload per operation, used for the whole-inventory coverage checks below.
_SAMPLES: dict[object, object] = {
    GetVersionOperation(): {"version": "9.1.1", "release": "9.1", "repoid": "abc1234567"},
    GetClusterStatusOperation(): [
        {"type": "cluster", "name": "lab", "id": "cluster/lab", "quorate": 1},
        {"type": "node", "name": "pve-a", "online": 1},
    ],
    GetNodesOperation(): [{"node": "pve-a", "status": "online"}],
    GetNodeStatusOperation("pve-a", SRC): {
        "cpuinfo": {"cpus": 8},
        "memory": {"total": 100, "free": 40},
        "rootfs": {"total": 200, "avail": 90},
        "kversion": "Linux 6.14",
        "pveversion": "pve-manager/9.1.1/abcdef0123456789",
    },
    GetNodeVersionOperation("pve-a", SRC): {"version": "9.1.1"},
    GetNodeAptVersionsOperation("pve-a", SRC): [
        {"Package": "pve-manager", "OldVersion": "9.1.1", "CurrentState": "Installed"}
    ],
    GetNodeNetworkOperation("pve-a", SRC): [
        {"iface": "vmbr0", "type": "bridge", "cidr": "10.0.0.5/24", "bridge_vlan_aware": 1}
    ],
    GetNodeStorageOperation("pve-a", SRC): [
        {"storage": "local", "type": "dir", "content": "iso,vztmpl", "total": 10, "avail": 5}
    ],
    GetStorageContentOperation("pve-a", "local", SRC): [
        {"volid": "local:iso/x.iso", "content": "iso"}
    ],
    GetClusterResourcesOperation(): [{"type": "qemu", "node": "pve-a", "vmid": 100}],
    GetNodeQemuOperation("pve-a", SRC): [{"vmid": 100, "name": "a"}],
    GetNodeLxcOperation("pve-a", SRC): [{"vmid": 200, "name": "c"}],
    GetClusterFirewallOptionsOperation(): {"enable": 1},
    GetClusterFirewallGroupsOperation(): [{"group": "secp-lab"}],
    GetSdnRootOperation(): [{"subdir": "zones"}],
    GetEffectivePermissionsOperation(): {"/sdn": {"SDN.Audit": 1}},
    GetSdnZonesOperation(): [{"zone": "z1", "type": "vlan"}],
    GetSdnVnetsOperation(): [{"vnet": "v1", "zone": "z1", "tag": 100}],
    GetSdnSubnetsOperation("v1", SRC): [{"subnet": "z1-10.0.0.0-24", "cidr": "10.0.0.0/24"}],
    GetSdnControllersOperation(): [],
    GetSdnIpamStatusOperation(): [{"subnet": "s1", "ip": "10.0.0.9", "vnet": "v1", "zone": "z1"}],
    GetSdnFabricsOperation(): [],
    GetNodeSdnZonesOperation("pve-a", SRC): [{"zone": "z1", "status": "available"}],
    GetNodeSdnBridgesOperation("pve-a", "z1", SRC): [{"bridge": "vmbr0", "vlan": 100}],
}


# === the inventory is completely covered ==========================================================


def test_every_reviewed_operation_has_a_parser():
    """An operation with no parser must not be silently executed: its payload would be discarded
    while its evidence record claimed the response was interpreted."""
    for operation_type in FIRST_MVP_OPERATIONS + SDN_OPERATIONS:
        sample = next(
            (op for op in _SAMPLES if type(op) is operation_type),
            None,
        )
        assert sample is not None, f"{operation_type.__name__} has no sample payload here"
        observe(sample, _SAMPLES[sample])


def test_an_operation_with_no_parser_refuses_rather_than_returning_nothing():
    class _Unknown:
        operation_code = "invented"
        observation_field_codes = ("pve_release",)

    with pytest.raises(ProjectionError, match="no_parser_for_operation:invented"):
        observe(_Unknown(), {})


@pytest.mark.parametrize("operation", list(_SAMPLES))
def test_each_parser_produces_exactly_the_fields_its_operation_declares(operation):
    produced = observe(operation, _SAMPLES[operation])
    assert set(produced) == set(operation.observation_field_codes)


@pytest.mark.parametrize("operation", list(_SAMPLES))
def test_a_malformed_payload_explains_every_declared_field(operation):
    """Not one field, and not silence: every field the operation promised gets a state and a
    reason, because a field missing from the mapping entirely has neither."""
    produced = observe(operation, object())
    assert set(produced) == set(operation.observation_field_codes)
    for observation in produced.values():
        assert observation.is_usable is False
        assert observation.state is S.observed_malformed
        assert observation.reason_code


def test_a_parser_that_skips_or_invents_a_field_is_refused():
    import secp_worker.proxmox_discovery_projection as projection

    original = projection._PARSERS[GetNodesOperation.operation_code]
    try:
        projection._PARSERS[GetNodesOperation.operation_code] = lambda op, payload: {}
        with pytest.raises(ProjectionError, match="parser_field_mismatch"):
            observe(GetNodesOperation(), [{"node": "pve-a", "status": "online"}])
    finally:
        projection._PARSERS[GetNodesOperation.operation_code] = original


# === unrecognised is never empty ==================================================================


@pytest.mark.parametrize(
    "operation,payload,expected_reason",
    [
        (GetNodesOperation(), [{"nodename": "pve-a"}], "node_index_rows_named_no_node"),
        (
            GetClusterResourcesOperation(),
            [{"kind": "vm", "id": 100}],
            "cluster_resources_shape_unrecognised",
        ),
        (GetNodeLxcOperation("pve-a", SRC), [{"id": "lxc/200"}], "node_lxc_shape_unrecognised"),
        (GetNodeQemuOperation("pve-a", SRC), [{"id": "qemu/100"}], "node_qemu_shape_unrecognised"),
        (
            GetNodeStorageOperation("pve-a", SRC),
            [{"name": "local"}],
            "node_storage_shape_unrecognised",
        ),
        (
            GetNodeNetworkOperation("pve-a", SRC),
            [{"device": "vmbr0"}],
            "node_network_shape_unrecognised",
        ),
        (GetSdnZonesOperation(), [{"name": "z1"}], "sdn_zones_shape_unrecognised"),
        (GetSdnVnetsOperation(), [{"name": "v1"}], "sdn_vnets_shape_unrecognised"),
        (
            GetNodeSdnBridgesOperation("pve-a", "z1", SRC),
            [{"iface": "vmbr0"}],
            "node_sdn_bridges_shape_unrecognised",
        ),
    ],
)
def test_rows_this_code_does_not_understand_are_malformed_not_empty(
    operation, payload, expected_reason
):
    produced = observe(operation, payload)
    for observation in produced.values():
        assert observation.state is S.observed_malformed
        assert observation.reason_code == expected_reason


def test_a_genuinely_empty_list_is_an_observation_and_not_a_failure():
    """The complement, and the reason the rule above is about UNRECOGNISED rows rather than
    ABSENT ones: a node with no containers really does report an empty list."""
    produced = observe(GetNodeLxcOperation("pve-a", SRC), [])
    assert produced["existing_lxc_ids"].is_usable is True
    assert produced["existing_lxc_ids"].value == {"pve-a": ()}


# === per-node and per-storage facts are keyed =====================================================


def test_node_scoped_facts_are_keyed_by_node():
    produced = observe(
        GetNodeStatusOperation("pve-a", SRC), _SAMPLES[GetNodeStatusOperation("pve-a", SRC)]
    )
    assert produced["node_capacity"].value == {
        "pve-a": {
            "cpus": 8,
            "memory_total": 100,
            "memory_free": 40,
            "rootfs_total": 200,
            "rootfs_available": 90,
        }
    }
    assert produced["kernel_version"].value == {"pve-a": "Linux 6.14"}


def test_storage_scoped_facts_are_keyed_by_node_and_storage():
    produced = observe(
        GetNodeStorageOperation("pve-a", SRC), _SAMPLES[GetNodeStorageOperation("pve-a", SRC)]
    )
    assert produced["storage_ids"].value == {"pve-a": ("local",)}
    assert produced["storage_types"].value == {"pve-a/local": "dir"}
    assert produced["allowed_storage_content"].value == {"pve-a/local": ("iso", "vztmpl")}
    assert produced["available_capacity"].value == {"pve-a/local": {"total": 10, "available": 5}}


def test_a_storage_reporting_no_numbers_says_so_rather_than_reporting_zero():
    """A null a consumer could read as "no free space" — or as unlimited — is worse than an
    explicit statement that the storage reported nothing."""
    produced = observe(
        GetNodeStorageOperation("pve-a", SRC), [{"storage": "offline", "type": "nfs"}]
    )
    assert produced["available_capacity"].value == {"pve-a/offline": {"unreported": True}}


def test_partial_node_capacity_is_malformed_rather_than_partially_reported():
    produced = observe(GetNodeStatusOperation("pve-a", SRC), {"cpuinfo": {"cpus": 8}})
    assert produced["node_capacity"].state is S.observed_malformed
    assert produced["node_capacity"].reason_code == "node_status_capacity_incomplete"


# === normalisation, so two sources agree instead of contradicting =================================


def test_the_two_version_sources_normalise_to_the_same_value():
    """/nodes/{n}/status reports ``pve-manager/9.1.1/abcdef`` and /nodes/{n}/version reports
    ``9.1.1``. Unnormalised, two sources that agree would be recorded as a disagreement."""
    from_status = observe(
        GetNodeStatusOperation("pve-a", SRC), _SAMPLES[GetNodeStatusOperation("pve-a", SRC)]
    )
    from_version = observe(GetNodeVersionOperation("pve-a", SRC), {"version": "9.1.1"})
    assert (
        from_status["node_versions"].value
        == from_version["node_versions"].value
        == {"pve-a": "9.1.1"}
    )


def test_an_unrecognised_manager_version_is_malformed_rather_than_passed_through():
    produced = observe(GetNodeStatusOperation("pve-a", SRC), {"pveversion": "something-else"})
    assert produced["node_versions"].state is S.observed_malformed


# === version fidelity =============================================================================


def test_a_two_component_version_does_not_fabricate_a_patch():
    produced = observe(GetVersionOperation(), {"version": "9.1", "release": "9.1", "repoid": "a"})
    assert produced["pve_version_patch"].state is S.observed_malformed
    assert produced["pve_version_major"].value == 9
    assert produced["pve_version_minor"].value == 1


def test_an_absent_release_is_explained_rather_than_defaulted():
    produced = observe(GetVersionOperation(), {"version": "9.1.1"})
    assert produced["pve_release"].state is S.observed_malformed
    assert produced["pve_repoid"].state is S.observed_malformed
    assert produced["pve_version_full"].value == "9.1.1"


# === safe-direction inferences ====================================================================


def test_a_bridge_without_the_vlan_aware_key_is_recorded_as_not_aware():
    """The safe direction: SECP declines to place VLAN tags rather than placing tags that are
    silently dropped, which would put every team on one flat segment."""
    produced = observe(
        GetNodeNetworkOperation("pve-a", SRC),
        [{"iface": "vmbr9", "type": "bridge", "cidr": "10.9.0.1/24"}],
    )
    assert produced["bridge_vlan_awareness"].value == {"pve-a/vmbr9": False}


def test_management_cidrs_are_a_superset_of_every_configured_address():
    """Naming the one true management interface would need to know which address SECP reached the
    node on. A superset over-refuses a colliding lab subnet, which is the failure that does not
    take the target away with it."""
    produced = observe(
        GetNodeNetworkOperation("pve-a", SRC),
        [
            {"iface": "vmbr0", "type": "bridge", "cidr": "10.0.0.5/24"},
            {"iface": "vmbr1", "type": "bridge", "cidr": "192.168.5.1/24"},
            {"iface": "vmbr2", "type": "bridge"},
        ],
    )
    assert produced["management_cidrs"].value == {"pve-a": ("10.0.0.5/24", "192.168.5.1/24")}
    assert produced["management_bridges"].value == {"pve-a": ("vmbr0", "vmbr1")}
    assert produced["bridges"].value == {"pve-a": ("vmbr0", "vmbr1", "vmbr2")}


def test_the_installed_package_version_is_recorded_without_choosing_a_key():
    """Which apt key names the INSTALLED version is unverified against a live target, so every
    version-bearing key is recorded rather than one being picked."""
    produced = observe(
        GetNodeAptVersionsOperation("pve-a", SRC),
        [{"Package": "pve-manager", "Version": "9.1.2", "OldVersion": "9.1.1"}],
    )
    assert produced["raw_host_package_version"].value == {
        "pve-a": {"pve-manager": {"Version": "9.1.2", "OldVersion": "9.1.1"}}
    }
    # Two candidate versions is an ambiguity, not a licence to prefer one.
    assert produced["release_build_identifier"].state is S.observed_malformed
    assert produced["release_build_identifier"].reason_code == (
        "pve_manager_installed_version_ambiguous"
    )


# === SDN =========================================================================================


def test_the_sdn_root_read_is_what_licenses_reading_an_empty_index_as_absence():
    produced = observe(GetSdnRootOperation(), [{"subdir": "zones"}])
    assert produced["sdn_read_authority"].value == {"cluster_sdn_readable": True}


def test_effective_permissions_reports_the_grant_it_actually_saw():
    granted = observe(GetEffectivePermissionsOperation(), {"/sdn": {"SDN.Audit": 1}})
    assert granted["sdn_read_authority"].value == {"sdn_audit_granted": True}
    withheld = observe(GetEffectivePermissionsOperation(), {"/sdn": {"SDN.Use": 1}})
    assert withheld["sdn_read_authority"].value == {"sdn_audit_granted": False}


def test_pending_state_is_keyed_per_vnet_for_subnets():
    """There is no cluster-wide subnet index, so completeness is a property of having enumerated
    EVERY vnet — one "subnets" key would let a single vnet's answer stand in for all of them."""
    produced = observe(
        GetSdnSubnetsOperation("v1", SRC),
        [
            {
                "subnet": "s1",
                "cidr": "10.0.0.0/24",
                "state": "new",
                "pending": {"gateway": "10.0.0.1"},
            }
        ],
    )
    pending = produced["pending_sdn_state"].value
    assert set(pending) == {"subnets@v1"}
    # The nested-pending rule survives the projection...
    (row,) = pending["subnets@v1"]
    assert row["observed"]["gateway"] == "10.0.0.1"
    # ...and the running view is kept apart from the post-activation one.
    assert "gateway" not in row["active"]
    assert row["object_id"] == "s1"
    assert row["state"] == "new"


def test_a_changed_object_keeps_the_running_values_alongside_the_pending_ones():
    """A merged-only record cannot say what activation would REPLACE, which is what an operator
    reading the manifest needs to see."""
    produced = observe(
        GetSdnZonesOperation(),
        [{"zone": "z1", "mtu": 1500, "state": "changed", "pending": {"mtu": 9000}}],
    )
    (row,) = produced["pending_sdn_state"].value["zones"]
    assert row["observed"]["mtu"] == 9000
    assert row["active"]["mtu"] == 1500


def test_an_unidentifiable_pending_object_is_kept_rather_than_dropped():
    """It still occupies the cluster. Dropping it would shrink the pending set that activation
    exclusivity is judged on, turning a contaminated cluster into a clean-looking one.

    Note the payload: one identifiable zone establishes that the response IS a zones list, so the
    shape rule is satisfied and the nameless row is a pending object with no id rather than
    evidence that this code misread the whole answer. A response where NOTHING is identifiable is
    the other case, and it is malformed — see the shape tests above.
    """
    produced = observe(
        GetSdnZonesOperation(),
        [
            {"zone": "z1", "type": "vlan"},
            {"type": "vlan", "state": "new", "pending": {"tag": 5}},
        ],
    )
    rows = produced["pending_sdn_state"].value["zones"]
    assert [r["object_id"] for r in rows] == [""]
    assert rows[0]["state"] == "new"


def test_the_cluster_index_and_the_node_runtime_view_describe_a_zone_without_colliding():
    """These two feed one field code, and the merge is what makes the partial-visibility
    differential possible. Their sub-keys must not overlap."""
    cluster = observe(GetSdnZonesOperation(), [{"zone": "z1", "type": "vlan"}])
    node = observe(GetNodeSdnZonesOperation("pve-a", SRC), [{"zone": "z1", "status": "available"}])
    assert set(cluster["existing_sdn_zones"].value["z1"]) == {"cluster_index"}
    assert set(node["existing_sdn_zones"].value["z1"]) == {"node_runtime"}


def test_vlan_use_is_keyed_by_the_claim_so_two_sources_cannot_collide_falsely():
    """A vnet carrying tag 100 and a bridge materialising tag 100 are two observations of the same
    tag from different angles, not a contradiction."""
    from_vnets = observe(GetSdnVnetsOperation(), [{"vnet": "v1", "zone": "z1", "tag": 100}])
    from_bridges = observe(
        GetNodeSdnBridgesOperation("pve-a", "z1", SRC), [{"bridge": "vmbr0", "vlan": 100}]
    )
    assert from_vnets["existing_vlan_use"].value == {"vnet:v1": 100}
    assert from_bridges["existing_vlan_use"].value == {"bridge:pve-a/vmbr0/100": 100}
    assert not set(from_vnets["existing_vlan_use"].value) & set(
        from_bridges["existing_vlan_use"].value
    )


def test_firewall_capability_is_assembled_from_two_complementary_reads():
    options = observe(GetClusterFirewallOptionsOperation(), {"enable": 1})
    groups = observe(GetClusterFirewallGroupsOperation(), [{"group": "secp-lab"}])
    assert options["firewall_capability"].value == {"cluster_options": {"enable": True}}
    assert groups["firewall_capability"].value == {"security_groups": ("secp-lab",)}
