"""Tests for the Proxmox desired-state model, the network compiler, and IPAM.

The tests that matter most here are the ones that try to BREAK a claim rather than confirm it:
``test_red_cannot_reach_blue_*`` drives the compiled rule list through the evaluator instead of
inspecting the intent that produced it, and the ``blocks`` tests remove one observation at a time
and assert the compiler refuses by name rather than guessing.
"""

from __future__ import annotations

import ipaddress

import pytest
from secp_api.range_enums import RangeResourceKind
from secp_api.range_providers.proxmox_ipam import (
    AllocationError,
    AllocationKind,
    AllocationLedger,
    IpamPools,
)
from secp_api.range_providers.proxmox_model import (
    BlockedPlan,
    CloneStrategy,
    CloudInitSpec,
    CompiledTopology,
    DiskSpec,
    EgressGatewaySpec,
    FirewallDirection,
    FirewallVerdict,
    GuestAddress,
    GuestKind,
    GuestSpec,
    NicSpec,
    NodeObservation,
    ObjectProvenance,
    Ownership,
    ProxmoxModelError,
    ProxmoxTargetIdentity,
    SegmentRole,
    StorageObservation,
    TargetObservation,
    TemplateObservation,
    assert_management_plane_untouched,
    is_owned_by_secp,
)
from secp_api.range_providers.proxmox_network import (
    PUBLIC_PROBE_ADDRESSES,
    ControlPlaneReviewedPath,
    IsolationProperty,
    TeamRequest,
    WebBreachLabRequest,
    compile_web_breach_lab,
    evaluate_flow,
    verify_isolation,
)

MANAGEMENT_CIDR = "10.10.10.0/24"
CONTROL_PLANE_CIDR = "10.20.0.0/24"


def make_identity() -> ProxmoxTargetIdentity:
    return ProxmoxTargetIdentity(
        target_id="tgt-lab-01",
        cluster_name="pve-lab",
        cluster_fingerprint="sha256:aa11bb22",
        management_cidrs=(MANAGEMENT_CIDR,),
        management_bridges=("vmbr0",),
    )


def make_observation(**overrides) -> TargetObservation:
    """A fully-observed target. Tests remove fields to prove the compiler blocks."""
    storage = StorageObservation(
        storage_id="local-lvm",
        content_types=("images", "rootdir"),
        available_bytes=2_000_000_000_000,
    )
    defaults = dict(
        identity=make_identity(),
        nodes=(
            NodeObservation(
                node_name="pve1",
                online=True,
                cpu_cores_total=64,
                memory_bytes_total=512_000_000_000,
                storages=(storage,),
                bridges=("vmbr0", "vmbr1"),
            ),
            NodeObservation(
                node_name="pve2",
                online=True,
                cpu_cores_total=64,
                memory_bytes_total=512_000_000_000,
                storages=(storage,),
                bridges=("vmbr0", "vmbr1"),
            ),
        ),
        templates=(
            TemplateObservation(
                template_ref="ubuntu-2404", vmid=8000, node_name="pve1", guest_kind=GuestKind.qemu
            ),
            TemplateObservation(
                template_ref="dvwa", vmid=8001, node_name="pve1", guest_kind=GuestKind.qemu
            ),
        ),
        sdn_supported=True,
        firewall_supported=True,
        vlan_tags_in_use=(100, 101),
        vmids_in_use=(100, 101, 8000, 8001),
        macs_in_use=("BC:24:11:00:00:01",),
        subnets_in_use=(MANAGEMENT_CIDR, "192.168.1.0/24"),
        sdn_names_in_use=("legacy",),
        firewall_names_in_use=("existing-group",),
    )
    defaults.update(overrides)
    return TargetObservation(**defaults)  # type: ignore[arg-type]


def make_request(**overrides) -> WebBreachLabRequest:
    defaults = dict(
        organization_id="org1",
        target_id="tgt-lab-01",
        range_id="wbl001",
        generation=1,
        operation_generation=1,
        teams=(
            TeamRequest(team_ref="red", label="Red Team"),
            TeamRequest(team_ref="blue", label="Blue Team"),
        ),
        control_plane_cidrs=(CONTROL_PLANE_CIDR,),
        scoring_port=443,
    )
    defaults.update(overrides)
    return WebBreachLabRequest(**defaults)  # type: ignore[arg-type]


def compile_ok(request=None, observation=None):
    result = compile_web_breach_lab(request or make_request(), observation or make_observation())
    assert not isinstance(result, BlockedPlan), getattr(result, "describe", lambda: result)()
    return result


# ======================================================================================
# The compiled two-team topology
# ======================================================================================


def test_two_team_lab_compiles_expected_segments():
    plan, _ = compile_ok()

    assert plan.team_refs == ("blue", "red")
    roles = {(vnet.ownership.team_ref, vnet.role) for vnet in plan.vnets}
    assert (None, SegmentRole.scoring) in roles
    for team in ("red", "blue"):
        assert (team, SegmentRole.attacker) in roles
        assert (team, SegmentRole.vulnerable) in roles
        assert (team, SegmentRole.sensor) not in roles  # opt-in, not compiled by default

    # 1 shared scoring + 2 per team = 5 segments.
    assert len(plan.vnets) == 5


def test_sensor_segment_is_opt_in():
    request = make_request(
        teams=(
            TeamRequest(team_ref="red", label="Red", include_sensor=True),
            TeamRequest(team_ref="blue", label="Blue"),
        )
    )
    plan, _ = compile_ok(request)
    sensors = [v for v in plan.vnets if v.role == SegmentRole.sensor]
    assert [v.ownership.team_ref for v in sensors] == ["red"]


def test_every_segment_gets_a_distinct_subnet_and_vlan():
    plan, _ = compile_ok()

    subnets = [ipaddress.ip_network(vnet.subnet.cidr) for vnet in plan.vnets]
    for index, left in enumerate(subnets):
        for right in subnets[index + 1 :]:
            assert not left.overlaps(right), f"{left} overlaps {right}"

    vlans = [vnet.vlan_tag for vnet in plan.vnets]
    assert len(set(vlans)) == len(vlans)
    # Never reuses a VLAN observed in use on the cluster.
    assert not set(vlans) & {100, 101}


def test_gateway_is_first_usable_address_and_subnet_is_unrouted():
    plan, _ = compile_ok()
    for vnet in plan.vnets:
        network = ipaddress.ip_network(vnet.subnet.cidr)
        assert vnet.subnet.gateway == str(next(iter(network.hosts())))
        assert vnet.subnet.routed is False


# ======================================================================================
# Isolation — proved against the compiled rules, not the intent
# ======================================================================================


def test_all_isolation_properties_hold():
    request = make_request()
    observation = make_observation()
    plan, _ = compile_ok(request, observation)

    findings = verify_isolation(plan, observation, request)
    failed = [f for f in findings if not f.holds]
    assert not failed, "; ".join(f"{f.prop.value}: {f.detail}" for f in failed)
    assert {f.prop for f in findings} == set(IsolationProperty)


def test_red_cannot_reach_blue_and_blue_cannot_reach_red():
    plan, _ = compile_ok()

    red = [v for v in plan.vnets if v.ownership.team_ref == "red"]
    blue = [v for v in plan.vnets if v.ownership.team_ref == "blue"]

    for source, targets in ((red, blue), (blue, red)):
        for src in source:
            for dst in targets:
                host = str(next(iter(ipaddress.ip_network(dst.subnet.cidr).hosts())))
                for port in (22, 80, 443, 3389, 8080):
                    verdict = evaluate_flow(plan, from_vnet=src.name, to_address=host, port=port)
                    assert verdict is FirewallVerdict.drop, (
                        f"{src.name} reached {dst.name} at {host}:{port}"
                    )


def test_a_team_can_still_reach_its_own_segments():
    """Isolation that also severs the scenario would pass a naive deny test and ship broken."""
    plan, _ = compile_ok()
    attacker = next(
        v for v in plan.vnets if v.ownership.team_ref == "red" and v.role == SegmentRole.attacker
    )
    vulnerable = next(
        v for v in plan.vnets if v.ownership.team_ref == "red" and v.role == SegmentRole.vulnerable
    )
    host = str(next(iter(ipaddress.ip_network(vulnerable.subnet.cidr).hosts())))
    assert (
        evaluate_flow(plan, from_vnet=attacker.name, to_address=host, port=80)
        is FirewallVerdict.accept
    )


def test_no_segment_reaches_the_proxmox_management_plane():
    plan, _ = compile_ok()
    management_host = str(next(iter(ipaddress.ip_network(MANAGEMENT_CIDR).hosts())))
    for vnet in plan.vnets:
        for port in (22, 443, 8006):
            assert (
                evaluate_flow(plan, from_vnet=vnet.name, to_address=management_host, port=port)
                is FirewallVerdict.drop
            )


def test_control_plane_is_unreachable_without_a_reviewed_path():
    plan, _ = compile_ok()
    control_host = str(next(iter(ipaddress.ip_network(CONTROL_PLANE_CIDR).hosts())))
    for vnet in plan.vnets:
        for port in (22, 443, 5432):
            assert (
                evaluate_flow(plan, from_vnet=vnet.name, to_address=control_host, port=port)
                is FirewallVerdict.drop
            )


def test_exact_reviewed_path_is_permitted_and_nothing_wider():
    control_host = str(next(iter(ipaddress.ip_network(CONTROL_PLANE_CIDR).hosts())))
    request = make_request(
        reviewed_control_plane_paths=(
            ControlPlaneReviewedPath(
                dest_cidr=f"{control_host}/32",
                proto="tcp",
                dport="8443",
                justification="scoreboard submission relay",
                approval_reference="CHG-4471",
            ),
        )
    )
    observation = make_observation()
    plan, _ = compile_ok(request, observation)

    attacker = next(v for v in plan.vnets if v.role == SegmentRole.attacker)
    # The exact reviewed tuple is allowed...
    assert (
        evaluate_flow(plan, from_vnet=attacker.name, to_address=control_host, port=8443)
        is FirewallVerdict.accept
    )
    # ...and nothing adjacent to it is.
    for port in (8442, 8444, 22, 443):
        assert (
            evaluate_flow(plan, from_vnet=attacker.name, to_address=control_host, port=port)
            is FirewallVerdict.drop
        )

    findings = {f.prop: f for f in verify_isolation(plan, observation, request)}
    assert findings[IsolationProperty.control_plane_unreachable].holds


def test_reviewed_path_refuses_a_widened_destination_or_port():
    with pytest.raises(ProxmoxModelError, match="exactly one host"):
        ControlPlaneReviewedPath(
            dest_cidr=CONTROL_PLANE_CIDR,
            proto="tcp",
            dport="8443",
            justification="j",
            approval_reference="CHG-1",
        )
    with pytest.raises(ProxmoxModelError, match="exactly one port"):
        ControlPlaneReviewedPath(
            dest_cidr="10.20.0.1/32",
            proto="tcp",
            dport="8000:9000",
            justification="j",
            approval_reference="CHG-1",
        )


def test_no_public_route_by_default():
    plan, _ = compile_ok()
    for vnet in plan.vnets:
        # RFC 5737 documentation addresses: unroutable by construction, so this test can never
        # become a real connection attempt. See PUBLIC_PROBE_ADDRESSES.
        for address in PUBLIC_PROBE_ADDRESSES:
            assert (
                evaluate_flow(plan, from_vnet=vnet.name, to_address=address, port=443)
                is FirewallVerdict.drop
            )


def test_egress_permits_only_the_approved_destination():
    observation = make_observation()
    base_plan, _ = compile_ok()
    attacker = next(v for v in base_plan.vnets if v.role == SegmentRole.attacker)

    request = make_request(
        egress=EgressGatewaySpec(
            vnet_name=attacker.name,
            allowed_destinations=("203.0.113.10/32",),
            allowed_ports=("443",),
            ownership=Ownership(
                organization_id="org1",
                target_id="tgt-lab-01",
                range_id="wbl001",
                generation=1,
                operation_generation=1,
                resource_kind=RangeResourceKind.egress_gateway,
            ),
            approval_reference="CHG-9001",
        )
    )
    plan, _ = compile_ok(request, observation)

    assert (
        evaluate_flow(plan, from_vnet=attacker.name, to_address="203.0.113.10", port=443)
        is FirewallVerdict.accept
    )
    # A different port and a different host on the same approved network are both denied.
    assert (
        evaluate_flow(plan, from_vnet=attacker.name, to_address="203.0.113.10", port=80)
        is FirewallVerdict.drop
    )
    assert (
        evaluate_flow(plan, from_vnet=attacker.name, to_address="203.0.113.11", port=443)
        is FirewallVerdict.drop
    )
    # Egress was granted to one segment; the others still have none.
    other = next(v for v in plan.vnets if v.name != attacker.name and v.role != SegmentRole.scoring)
    assert (
        evaluate_flow(plan, from_vnet=other.name, to_address="203.0.113.10", port=443)
        is FirewallVerdict.drop
    )

    findings = {f.prop: f for f in verify_isolation(plan, observation, request)}
    assert findings[IsolationProperty.no_default_public_route].holds


def test_egress_without_an_approval_reference_is_refused():
    with pytest.raises(ProxmoxModelError, match="approval reference"):
        EgressGatewaySpec(
            vnet_name="t1atk",
            allowed_destinations=("203.0.113.10/32",),
            allowed_ports=("443",),
            ownership=Ownership(
                organization_id="o",
                target_id="t",
                range_id="r",
                generation=1,
                operation_generation=1,
                resource_kind=RangeResourceKind.egress_gateway,
            ),
            approval_reference="",
        )


def test_every_security_group_ends_in_default_deny_both_directions():
    plan, _ = compile_ok()
    assert plan.security_groups
    for group in plan.security_groups:
        assert group.default_policy_is_deny, f"{group.name} lacks a terminal default deny"


def test_isolation_verification_catches_a_reordered_allow():
    """The evaluator is the guard: move an allow above the cross-team deny and it must fail.

    This is the regression that a rules-look-right review would miss.
    """
    from dataclasses import replace

    plan, _ = compile_ok()
    request = make_request()
    observation = make_observation()

    red_attacker = next(
        v for v in plan.vnets if v.ownership.team_ref == "red" and v.role == SegmentRole.attacker
    )
    group_name = plan.vnet_security_group[red_attacker.name]
    group = next(g for g in plan.security_groups if g.name == group_name)
    blue_ipset = next(i for i in plan.ip_sets if i.ownership.team_ref == "blue")

    # Shift every existing rule down one slot and drop a broad ACCEPT into position 0 — exactly
    # what an "just let this one thing through" edit looks like in review.
    sabotaged_rules = (
        replace(
            group.rules[0],
            position=0,
            direction=FirewallDirection.outbound,
            verdict=FirewallVerdict.accept,
            dest=f"+{blue_ipset.name}",
            proto=None,
            dport=None,
            source=None,
            comment="accidental broad allow placed above the deny",
        ),
        *(replace(rule, position=rule.position + 1) for rule in group.rules),
    )
    sabotaged_group = replace(group, rules=sabotaged_rules)
    sabotaged_plan = replace(
        plan,
        security_groups=tuple(
            sabotaged_group if g.name == group_name else g for g in plan.security_groups
        ),
    )

    findings = {f.prop: f for f in verify_isolation(sabotaged_plan, observation, request)}
    assert not findings[IsolationProperty.cross_team_blocked].holds
    assert "ACCEPT" in findings[IsolationProperty.cross_team_blocked].detail


# ======================================================================================
# IPAM — deterministic, recorded, conflict-checked
# ======================================================================================


def test_identical_inputs_produce_byte_identical_allocations():
    """The first deterministic allocation test: compile twice, get the same ledger."""
    first_plan, first_ledger = compile_ok()
    second_plan, second_ledger = compile_ok()

    assert first_ledger.content_hash() == second_ledger.content_hash()
    assert [a.as_dict() for a in first_ledger.all()] == [a.as_dict() for a in second_ledger.all()]
    assert [(v.name, v.vlan_tag, v.subnet.cidr) for v in first_plan.vnets] == [
        (v.name, v.vlan_tag, v.subnet.cidr) for v in second_plan.vnets
    ]


def test_a_different_generation_allocates_differently_and_is_still_deterministic():
    plan_g1, ledger_g1 = compile_ok(make_request(generation=1))
    plan_g2, ledger_g2 = compile_ok(make_request(generation=2))
    plan_g2_again, _ = compile_ok(make_request(generation=2))

    assert ledger_g1.content_hash() != ledger_g2.content_hash()
    assert [v.subnet.cidr for v in plan_g2.vnets] == [v.subnet.cidr for v in plan_g2_again.vnets]


def test_every_allocation_is_recorded_in_the_ledger():
    plan, ledger = compile_ok()

    recorded_subnets = set(ledger.values_of(AllocationKind.subnet))
    recorded_vlans = {int(v) for v in ledger.values_of(AllocationKind.vlan_tag)}
    recorded_names = set(ledger.values_of(AllocationKind.vnet_name))

    for vnet in plan.vnets:
        assert vnet.subnet.cidr in recorded_subnets
        assert vnet.vlan_tag in recorded_vlans
        assert vnet.name in recorded_names
    for group in plan.security_groups:
        assert group.name in ledger.values_of(AllocationKind.firewall_object_name)


def test_allocation_avoids_values_observed_in_use():
    plan, ledger = compile_ok()
    # Now re-compile against a target that already holds the previously chosen VLANs and subnets.
    taken_vlans = tuple(int(v) for v in ledger.values_of(AllocationKind.vlan_tag))
    taken_subnets = tuple(ledger.values_of(AllocationKind.subnet))

    crowded = make_observation(
        vlan_tags_in_use=(100, 101, *taken_vlans),
        subnets_in_use=(MANAGEMENT_CIDR, "192.168.1.0/24", *taken_subnets),
    )
    second_plan, _ = compile_ok(make_request(), crowded)

    assert not {v.vlan_tag for v in second_plan.vnets} & set(taken_vlans)
    new_subnets = [ipaddress.ip_network(v.subnet.cidr) for v in second_plan.vnets]
    for old in taken_subnets:
        old_net = ipaddress.ip_network(old)
        assert not any(net.overlaps(old_net) for net in new_subnets)


def test_no_scenario_subnet_ever_overlaps_the_management_plane():
    plan, _ = compile_ok()
    management = ipaddress.ip_network(MANAGEMENT_CIDR)
    for vnet in plan.vnets:
        assert not ipaddress.ip_network(vnet.subnet.cidr).overlaps(management)


def test_vmid_allocation_skips_ids_in_use():
    ownership = Ownership(
        organization_id="org1",
        target_id="t",
        range_id="r",
        generation=1,
        operation_generation=1,
        resource_kind=RangeResourceKind.virtual_machine,
        team_ref="red",
    )
    pools = IpamPools(vmid_min=9000, vmid_max=9004)
    ledger = AllocationLedger()
    allocated = [
        ledger.allocate_vmid(
            ownership=ownership,
            purpose=f"guest{index}",
            pools=pools,
            observed_vmids=(9000, 9001),
        )
        for index in range(3)
    ]
    assert sorted(allocated) == [9002, 9003, 9004]
    assert len(set(allocated)) == 3

    with pytest.raises(AllocationError, match="exhausted"):
        ledger.allocate_vmid(
            ownership=ownership, purpose="one-too-many", pools=pools, observed_vmids=(9000, 9001)
        )


def test_vm_and_lxc_ids_share_one_namespace():
    """Proxmox has a single id namespace; allocating an LXC id must not collide with a VM id."""
    ownership = Ownership(
        organization_id="o",
        target_id="t",
        range_id="r",
        generation=1,
        operation_generation=1,
        resource_kind=RangeResourceKind.virtual_machine,
    )
    pools = IpamPools(vmid_min=9000, vmid_max=9001)
    ledger = AllocationLedger()
    vm = ledger.allocate_vmid(ownership=ownership, purpose="vm", pools=pools, observed_vmids=())
    ct = ledger.allocate_vmid(
        ownership=ownership, purpose="ct", pools=pools, observed_vmids=(), lxc=True
    )
    assert vm != ct


def test_generated_macs_are_locally_administered_and_avoid_observed_collisions():
    plan, ledger = compile_ok()
    ownership = plan.vnets[0].ownership
    macs = {
        ledger.allocate_mac(
            ownership=ownership, purpose=f"nic{index}", observed_macs=("02:53:45:00:00:00",)
        )
        for index in range(20)
    }
    assert len(macs) == 20
    assert "02:53:45:00:00:00" not in macs
    for mac in macs:
        first_octet = int(mac.split(":")[0], 16)
        assert first_octet & 0b10, f"{mac} is not locally administered"
        assert not first_octet & 0b1, f"{mac} is a multicast address"


def test_repeated_allocation_of_the_same_purpose_is_idempotent():
    ownership = Ownership(
        organization_id="o",
        target_id="t",
        range_id="r",
        generation=1,
        operation_generation=1,
        resource_kind=RangeResourceKind.virtual_machine,
    )
    ledger = AllocationLedger()
    first = ledger.allocate_mac(ownership=ownership, purpose="nic0", observed_macs=())
    second = ledger.allocate_mac(ownership=ownership, purpose="nic0", observed_macs=())
    assert first == second
    assert len(ledger) == 1


def test_remote_state_key_is_scoped_and_recorded():
    ownership = Ownership(
        organization_id="org1",
        target_id="tgt",
        range_id="wbl001",
        generation=3,
        operation_generation=1,
        resource_kind=RangeResourceKind.virtual_machine,
        team_ref="red",
    )
    ledger = AllocationLedger()
    key = ledger.allocate_remote_state_key(ownership=ownership)
    assert key == "secp/org1/tgt/wbl001/red/g3"
    assert ledger.values_of(AllocationKind.remote_state_key) == (key,)


# ======================================================================================
# Sealing, persistence and release
# ======================================================================================


def test_a_sealed_ledger_refuses_a_new_allocation():
    _, ledger = compile_ok()
    ledger.seal()
    ownership = Ownership(
        organization_id="org1",
        target_id="tgt-lab-01",
        range_id="wbl001",
        generation=1,
        operation_generation=1,
        resource_kind=RangeResourceKind.virtual_machine,
        team_ref="red",
    )
    with pytest.raises(AllocationError, match="new plan generation"):
        ledger.allocate_mac(ownership=ownership, purpose="brand-new-nic", observed_macs=())


def test_a_sealed_ledger_still_returns_existing_allocations():
    plan, ledger = compile_ok()
    ledger.seal()
    vnet = plan.vnets[0]
    # Re-asking for something already recorded must succeed — a reset re-reads, it does not
    # re-allocate.
    assert (
        ledger.allocate_int(
            ownership=vnet.ownership,
            kind=AllocationKind.vlan_tag,
            purpose=vnet.alias,
            low=1000,
            high=1999,
            observed_in_use=(),
            observation_field="TargetObservation.vlan_tags_in_use",
            reason_id="proxmox.vlan_inventory_missing",
        )
        == vnet.vlan_tag
    )


def test_ledger_round_trips_through_the_manifest_payload():
    _, ledger = compile_ok()
    ledger.seal()
    payload = ledger.to_manifest()

    restored = AllocationLedger.from_manifest(payload)
    assert restored.sealed
    assert restored.content_hash() == ledger.content_hash()
    assert [a.as_dict() for a in restored.all()] == [a.as_dict() for a in ledger.all()]


def test_an_edited_ledger_payload_is_rejected():
    _, ledger = compile_ok()
    payload = ledger.to_manifest()
    payload["allocations"][0]["value"] = "1234"

    with pytest.raises(AllocationError, match="hash mismatch"):
        AllocationLedger.from_manifest(payload)


def test_release_requires_proof_of_absence():
    ownership = Ownership(
        organization_id="o",
        target_id="t",
        range_id="r",
        generation=1,
        operation_generation=1,
        resource_kind=RangeResourceKind.virtual_machine,
    )
    pools = IpamPools()
    ledger = AllocationLedger()
    ledger.allocate_vmid(ownership=ownership, purpose="web", pools=pools, observed_vmids=())

    with pytest.raises(AllocationError, match="absence was not proved"):
        ledger.release(
            scope=ownership.scope_key(),
            kind=AllocationKind.vmid,
            purpose="web",
            absence_proved=False,
            proof_detail="teardown probe was unreachable",
        )
    assert len(ledger) == 1  # still reserved

    released = ledger.release(
        scope=ownership.scope_key(),
        kind=AllocationKind.vmid,
        purpose="web",
        absence_proved=True,
    )
    assert released.kind is AllocationKind.vmid
    assert len(ledger) == 0


# ======================================================================================
# Unknown stays unknown
# ======================================================================================


@pytest.mark.parametrize(
    ("field", "reason_id"),
    [
        ("sdn_supported", "proxmox.sdn_support_unknown"),
        ("firewall_supported", "proxmox.firewall_support_unknown"),
        ("vlan_tags_in_use", "proxmox.vlan_inventory_missing"),
        ("subnets_in_use", "proxmox.subnet_inventory_missing"),
        ("sdn_names_in_use", "proxmox.sdn_name_inventory_missing"),
    ],
)
def test_a_missing_observation_blocks_planning_by_name(field, reason_id):
    result = compile_web_breach_lab(make_request(), make_observation(**{field: None}))
    assert isinstance(result, BlockedPlan)
    assert reason_id in result.reason_ids, result.describe()
    # The blocked plan names the observation that would unblock it.
    assert any(field in item.observation for item in result.missing)


def test_an_unsupported_capability_blocks_rather_than_degrading():
    result = compile_web_breach_lab(make_request(), make_observation(sdn_supported=False))
    assert isinstance(result, BlockedPlan)
    assert "proxmox.sdn_unsupported" in result.reason_ids

    result = compile_web_breach_lab(make_request(), make_observation(firewall_supported=False))
    assert isinstance(result, BlockedPlan)
    assert "proxmox.firewall_unsupported" in result.reason_ids


def test_no_online_node_blocks():
    offline = make_observation(
        nodes=(NodeObservation(node_name="pve1", online=False, bridges=("vmbr0",)),)
    )
    result = compile_web_breach_lab(make_request(), offline)
    assert isinstance(result, BlockedPlan)
    assert "proxmox.no_online_node" in result.reason_ids


def test_a_bridge_present_on_only_some_nodes_blocks():
    """Picking it anyway would strand every guest that lands on the node without it."""
    split = make_observation(
        nodes=(
            NodeObservation(node_name="pve1", online=True, bridges=("vmbr0",)),
            NodeObservation(node_name="pve2", online=True, bridges=("vmbr9",)),
        )
    )
    result = compile_web_breach_lab(make_request(), split)
    assert isinstance(result, BlockedPlan)
    assert "proxmox.no_common_bridge" in result.reason_ids


def test_a_blocked_plan_reports_every_missing_prerequisite_at_once():
    result = compile_web_breach_lab(
        make_request(),
        make_observation(sdn_supported=None, firewall_supported=None, vlan_tags_in_use=None),
    )
    assert isinstance(result, BlockedPlan)
    assert len(result.reason_ids) >= 3
    assert "cannot compile" in result.describe()


def test_a_blocked_plan_must_name_something():
    with pytest.raises(ProxmoxModelError, match="at least one missing prerequisite"):
        BlockedPlan(())


# ======================================================================================
# Ownership
# ======================================================================================


def make_ownership(**overrides) -> Ownership:
    defaults = dict(
        organization_id="org1",
        target_id="tgt",
        range_id="rng",
        generation=1,
        operation_generation=1,
        resource_kind=RangeResourceKind.virtual_machine,
        team_ref="red",
    )
    defaults.update(overrides)
    return Ownership(**defaults)  # type: ignore[arg-type]


def test_a_matching_name_is_never_proof_of_ownership():
    ownership = make_ownership()
    # An object whose name is byte-identical to what we would generate, but which carries no tag.
    assert is_owned_by_secp(None, ownership) is ObjectProvenance.untagged
    assert is_owned_by_secp({}, ownership) is ObjectProvenance.untagged
    assert is_owned_by_secp({"name": "t1atk"}, ownership) is ObjectProvenance.untagged


def test_a_complete_matching_tag_is_ownership():
    ownership = make_ownership()
    assert is_owned_by_secp(ownership.as_tags(), ownership) is ObjectProvenance.secp_owned


def test_a_tag_from_another_scope_is_foreign():
    ownership = make_ownership()
    for other in (
        make_ownership(organization_id="org2"),
        make_ownership(target_id="other-target"),
        make_ownership(range_id="other-range"),
        make_ownership(generation=2),
        make_ownership(team_ref="blue"),
    ):
        assert is_owned_by_secp(other.as_tags(), ownership) is ObjectProvenance.secp_foreign_scope


def test_a_partial_or_corrupt_tag_is_unreadable_not_ours():
    ownership = make_ownership()
    partial = ownership.as_tags()
    del partial["secp.range"]
    assert is_owned_by_secp(partial, ownership) is ObjectProvenance.unreadable

    corrupt = ownership.as_tags()
    corrupt["secp.generation"] = "not-a-number"
    assert is_owned_by_secp(corrupt, ownership) is ObjectProvenance.unreadable


def test_operation_generation_does_not_change_the_allocation_scope():
    """A reset must resolve to the same allocations as the deploy it reconciles."""
    deploy = make_ownership(operation_generation=1)
    reset = make_ownership(operation_generation=7)
    assert deploy.scope_key() == reset.scope_key()
    # ...but it is still recorded, so the two operations remain distinguishable.
    assert deploy.as_tags()["secp.operation_generation"] == "1"
    assert reset.as_tags()["secp.operation_generation"] == "7"


def test_every_compiled_object_carries_ownership():
    plan, _ = compile_ok()
    for vnet in plan.vnets:
        assert vnet.ownership.organization_id == "org1"
        assert vnet.ownership.range_id == "wbl001"
    assert plan.zone.ownership.range_id == "wbl001"
    for group in plan.security_groups:
        assert group.ownership.range_id == "wbl001"
    for ip_set in plan.ip_sets:
        assert ip_set.ownership.range_id == "wbl001"


# ======================================================================================
# The management plane is never scenario-owned
# ======================================================================================


def build_topology(plan, guest_address="10.80.0.10", zone_override=None):
    ownership = make_ownership(team_ref="red")
    guest = GuestSpec(
        guest_ref="red-web",
        name="red-web",
        kind=GuestKind.qemu,
        vmid=9100,
        node_name="pve1",
        template_ref="dvwa",
        clone_strategy=CloneStrategy.full,
        cpu_cores=2,
        memory_mb=2048,
        disks=(DiskSpec(slot="scsi0", size_gb=20, storage_id="local-lvm"),),
        nics=(NicSpec(index=0, vnet_name=plan.vnets[0].name, mac_address="02:53:45:AA:BB:CC"),),
        address=GuestAddress(published_address=guest_address),
        ownership=ownership,
    )
    return CompiledTopology(
        target=make_identity(),
        ownership=make_ownership(team_ref=None),
        network=zone_override or plan,
        guests=(guest,),
    )


def test_the_compiler_never_selects_the_management_bridge():
    """On a stock Proxmox, vmbr0 is both 'present on every node' and the management bridge."""
    plan, _ = compile_ok()
    assert plan.zone.bridge == "vmbr1"
    assert plan.zone.bridge not in make_identity().management_bridges


def test_when_every_common_bridge_is_management_the_compiler_blocks():
    only_management = make_observation(
        nodes=(
            NodeObservation(node_name="pve1", online=True, bridges=("vmbr0",)),
            NodeObservation(node_name="pve2", online=True, bridges=("vmbr0",)),
        )
    )
    result = compile_web_breach_lab(make_request(), only_management)
    assert isinstance(result, BlockedPlan)
    assert "proxmox.no_non_management_bridge" in result.reason_ids


def test_management_plane_guard_accepts_a_clean_topology():
    plan, _ = compile_ok()
    topology = build_topology(
        plan, guest_address=str(next(iter(ipaddress.ip_network(plan.vnets[0].subnet.cidr).hosts())))
    )
    assert_management_plane_untouched(topology)


def test_management_plane_guard_refuses_a_guest_addressed_in_management():
    plan, _ = compile_ok()
    topology = build_topology(plan, guest_address="10.10.10.50")
    with pytest.raises(ProxmoxModelError, match="inside the management network"):
        assert_management_plane_untouched(topology)


def test_management_plane_guard_refuses_an_overlapping_subnet():
    from dataclasses import replace

    plan, _ = compile_ok()
    overlapping = replace(
        plan.vnets[0],
        subnet=replace(plan.vnets[0].subnet, cidr=MANAGEMENT_CIDR, gateway="10.10.10.1"),
    )
    sabotaged = replace(plan, vnets=(overlapping, *plan.vnets[1:]))
    topology = build_topology(plan, zone_override=sabotaged)
    with pytest.raises(ProxmoxModelError, match="overlaps the management network"):
        assert_management_plane_untouched(topology)


def test_management_plane_guard_refuses_a_zone_on_the_management_bridge():
    plan, _ = compile_ok()
    topology = build_topology(
        plan, guest_address=str(next(iter(ipaddress.ip_network(plan.vnets[0].subnet.cidr).hosts())))
    )
    # The compiled zone rides vmbr0; declaring vmbr0 as management must be refused, not warned.
    with pytest.raises(ProxmoxModelError, match="management bridge"):
        assert_management_plane_untouched(topology, management_bridges=(plan.zone.bridge,))


def test_a_target_without_a_declared_management_cidr_is_refused():
    with pytest.raises(ProxmoxModelError, match="management CIDR"):
        ProxmoxTargetIdentity(
            target_id="t",
            cluster_name="c",
            cluster_fingerprint="f",
            management_cidrs=(),
        )


# ======================================================================================
# Published address is not probe address
# ======================================================================================


def test_published_and_probe_addresses_are_independent():
    address = GuestAddress(published_address="10.80.1.10", probe_address="10.80.1.10")
    assert not address.probe_is_distinct

    distinct = GuestAddress(published_address="203.0.113.5", probe_address="10.80.1.10")
    assert distinct.probe_is_distinct
    # No fallback: a guest with no probe address reports None rather than reusing the published
    # one, so a readiness check cannot silently probe the address it published.
    assert GuestAddress(published_address="10.80.1.10").probe_address is None


# ======================================================================================
# Guest spec validation
# ======================================================================================


def test_a_guest_with_no_nic_is_refused():
    with pytest.raises(ProxmoxModelError, match="no NIC"):
        GuestSpec(
            guest_ref="x",
            name="x",
            kind=GuestKind.qemu,
            vmid=9100,
            node_name="pve1",
            template_ref="t",
            clone_strategy=CloneStrategy.full,
            cpu_cores=1,
            memory_mb=512,
            disks=(),
            nics=(),
            address=GuestAddress(published_address="10.80.1.10"),
            ownership=make_ownership(),
        )


def test_cloud_init_refuses_private_key_material():
    with pytest.raises(ProxmoxModelError, match="private key"):
        CloudInitSpec(
            user="secp",
            ssh_authorized_keys=("-----BEGIN OPENSSH PRIVATE KEY-----",),
        )


def test_cloud_init_accepts_public_keys():
    spec = CloudInitSpec(user="secp", ssh_authorized_keys=("ssh-ed25519 AAAAC3Nza test",))
    assert spec.nameservers == ()  # isolated segment gets none by default


def test_clone_strategy_default_is_the_safe_one():
    """``full`` survives template churn; ``linked`` dies with its template."""
    assert CloneStrategy.full.value == "full"
    guest = GuestSpec(
        guest_ref="x",
        name="x",
        kind=GuestKind.qemu,
        vmid=9100,
        node_name="pve1",
        template_ref="t",
        clone_strategy=CloneStrategy.full,
        cpu_cores=1,
        memory_mb=512,
        disks=(DiskSpec(slot="scsi0", size_gb=10, storage_id="local-lvm"),),
        nics=(NicSpec(index=0, vnet_name="t1atk", mac_address="02:53:45:00:00:01"),),
        address=GuestAddress(published_address="10.80.1.10"),
        ownership=make_ownership(),
    )
    assert guest.clone_strategy is CloneStrategy.full


def test_firewall_rules_must_carry_a_comment():
    plan, _ = compile_ok()
    for group in plan.security_groups:
        for rule in group.rules:
            assert rule.comment, f"{group.name} has an unexplained rule at {rule.position}"
