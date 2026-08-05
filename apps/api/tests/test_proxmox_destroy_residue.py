"""Tests for the destroy gate and the zero-residue proof.

Three properties are pinned, and each one is a thing this program has either paid for or refuses to
pay for again.

**An apply approval never authorizes a destroy.** Enforced twice and tested twice: the type cannot
be constructed from a non-destroy approval, and the gate separately refuses a plan whose own kind
is not ``destroy``. Every refusal code is exercised by a parametrized scenario keyed on the enum,
so a code added without a test fails collection rather than shipping untested.

**A foreign resource is never deleted for resembling an expected one.** Ownership comes from tags
via ``is_owned_by_secp``. The tests put an object with a perfectly matching NAME at one of our own
allocated vmids and prove it lands in ``protected``, that its reservation is retained, and that the
range cannot then be called clean.

**Unknown is never clean.** Every probe domain gets a test where its health flag is False and the
findings come back ``unproven`` rather than ``removed`` — because the false ``clean`` this
repository already shipped came from exactly that: a removal and an existence check sharing a
failure mode, and "nothing found" being read as "nothing there".
"""

from __future__ import annotations

import pytest
from secp_api.range_enums import RangeResourceKind, ResidueVerdict
from secp_api.range_providers.base import TeardownResourceOutcome
from secp_api.range_providers.proxmox_ipam import (
    Allocation,
    AllocationError,
    AllocationKind,
    AllocationLedger,
)
from secp_api.range_providers.proxmox_model import ObjectProvenance, Ownership
from secp_worker.provisioning.proxmox_apply_gate import WorkerIdentity
from secp_worker.provisioning.proxmox_destroy_gate import (
    DESTROY_OPERATION_KIND,
    DestroyApproval,
    DestroyApprovalError,
    DestroyPreconditions,
    DestroyRefusalCode,
    DestroyRefused,
    RegeneratedDestroyPlan,
    deletion_set_hash,
    evaluate_destroy_gate,
)
from secp_worker.provisioning.proxmox_residue import (
    CLASS_PROBE_DOMAIN,
    RESERVATION_ALLOCATION_KIND,
    ArtifactProbe,
    OwnedResource,
    ProbeDomain,
    RemoteStateProbe,
    ResidueClass,
    SupplementalObservation,
    bound_deletion_set,
    releasable_allocations,
    release_proved_allocations,
    reservation_findings,
    residue_verdict,
    uncovered_classes,
    verify_absence,
    zero_residue_proof,
)
from secp_worker.provisioning.proxmox_verification import ObservedGuest, ObservedInfrastructure

CONTROLLED_LIVE_QUEUE = "secp.controlled-live"
SCOPE = ("org1", "tgt-lab-01", "wbl001", "red", 1)


# --------------------------------------------------------------------------------------
# Destroy gate fixtures
# --------------------------------------------------------------------------------------


DELETION_ADDRESSES = (
    "proxmox_virtual_environment_vm.red_dvwa",
    "proxmox_virtual_environment_vm.red_juice",
    "proxmox_virtual_environment_vnet.t1vul",
)


def make_worker(**overrides) -> WorkerIdentity:
    defaults = dict(
        worker_id="wrk-01",
        role="infrastructure_operator",
        release="2026.08.1",
        queue=CONTROLLED_LIVE_QUEUE,
    )
    defaults.update(overrides)
    return WorkerIdentity(**defaults)  # type: ignore[arg-type]


def make_approval(**overrides) -> DestroyApproval:
    defaults = dict(
        operation_kind=DESTROY_OPERATION_KIND,
        change_set_hash="cs-destroy-1",
        deletion_set_hash=deletion_set_hash(DELETION_ADDRESSES),
        plan_document_hash="doc-1",
        ownership_scope=("org1", "tgt-lab-01", "wbl001", 1),
        target_id="tgt-lab-01",
        cluster_fingerprint="fp-lab-01",
        worker_id="wrk-01",
        worker_release="2026.08.1",
        approval_id="apr-destroy-1",
    )
    defaults.update(overrides)
    return DestroyApproval(**defaults)  # type: ignore[arg-type]


def make_plan(**overrides) -> RegeneratedDestroyPlan:
    defaults = dict(
        kind=DESTROY_OPERATION_KIND,
        change_set_hash="cs-destroy-1",
        deletion_set_hash=deletion_set_hash(DELETION_ADDRESSES),
        deletion_addresses=DELETION_ADDRESSES,
        ownership_scope=("org1", "tgt-lab-01", "wbl001", 1),
        target_id="tgt-lab-01",
        cluster_fingerprint="fp-lab-01",
        binary_plan_present=True,
    )
    defaults.update(overrides)
    return RegeneratedDestroyPlan(**defaults)  # type: ignore[arg-type]


def make_preconditions(**overrides) -> DestroyPreconditions:
    defaults = dict(
        ownership_verified=True,
        discovery_fresh=True,
        remote_state_lock_held=True,
        credential_resolved=True,
        approval_already_consumed=False,
    )
    defaults.update(overrides)
    return DestroyPreconditions(**defaults)  # type: ignore[arg-type]


def run_gate(**overrides):
    kwargs = dict(
        worker=make_worker(),
        approval=make_approval(),
        regenerated=make_plan(),
        preconditions=make_preconditions(),
        controlled_live_queue=CONTROLLED_LIVE_QUEUE,
    )
    kwargs.update(overrides)
    return evaluate_destroy_gate(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# Apply approval must never authorize a destroy
# --------------------------------------------------------------------------------------


def test_an_apply_approval_cannot_even_be_constructed_as_a_destroy_approval():
    """Structural, not procedural: there is no constructor that accepts an apply approval."""
    for kind in ("apply", "reset", "dry_run", ""):
        with pytest.raises(DestroyApprovalError, match="can never authorize a destroy"):
            make_approval(operation_kind=kind)


def test_a_destroy_approval_with_no_id_is_refused_because_it_could_be_replayed():
    with pytest.raises(DestroyApprovalError, match="replayed"):
        make_approval(approval_id="")


def test_a_valid_destroy_approval_cannot_authorize_a_plan_that_creates():
    """The second, independent binding: the APPROVAL is a destroy, the PLAN is not."""
    with pytest.raises(DestroyRefused) as excinfo:
        run_gate(regenerated=make_plan(kind="apply"))
    assert excinfo.value.code is DestroyRefusalCode.prepared_plan_is_not_a_destroy_plan
    assert "does not authorize a plan that creates" in excinfo.value.detail


def test_the_happy_path_authorizes_and_names_every_check_it_passed():
    authorization = run_gate()
    assert authorization.change_set_hash == "cs-destroy-1"
    assert authorization.approval_id == "apr-destroy-1"
    assert authorization.checks_passed == (
        "authority",
        "destroy_approval",
        "worker_identity",
        "freshness",
        "exclusive_access",
        "change_set_binding",
        "deletion_set_binding",
        "ownership_and_target",
    )


# --------------------------------------------------------------------------------------
# Every refusal code, keyed on the enum so an untested code fails collection
# --------------------------------------------------------------------------------------


REFUSAL_SCENARIOS: dict[DestroyRefusalCode, dict] = {
    DestroyRefusalCode.ordinary_worker_on_controlled_live_path: {
        "worker": make_worker(role="range_worker")
    },
    DestroyRefusalCode.no_destroy_approval: {"approval": None},
    DestroyRefusalCode.approval_is_not_for_destroy: {
        # A record mutated or deserialized around the constructor.
        "approval": object.__new__(DestroyApproval)
    },
    DestroyRefusalCode.approval_already_consumed: {
        "preconditions": make_preconditions(approval_already_consumed=True)
    },
    DestroyRefusalCode.worker_identity_mismatch: {"worker": make_worker(worker_id="wrk-99")},
    DestroyRefusalCode.worker_release_mismatch: {"worker": make_worker(release="2026.07.9")},
    DestroyRefusalCode.ownership_not_verified: {
        "preconditions": make_preconditions(ownership_verified=None)
    },
    DestroyRefusalCode.discovery_stale: {
        "preconditions": make_preconditions(discovery_fresh=False)
    },
    DestroyRefusalCode.remote_state_lock_unavailable: {
        "preconditions": make_preconditions(remote_state_lock_held=None)
    },
    DestroyRefusalCode.credential_unresolvable: {
        "preconditions": make_preconditions(credential_resolved=False)
    },
    DestroyRefusalCode.prepared_plan_is_not_a_destroy_plan: {"regenerated": None},
    DestroyRefusalCode.stale_binary_destroy_plan: {
        "regenerated": make_plan(binary_plan_present=False)
    },
    DestroyRefusalCode.destroy_change_set_hash_mismatch: {
        "regenerated": make_plan(change_set_hash="cs-something-else")
    },
    DestroyRefusalCode.deletion_set_mismatch: {
        "regenerated": make_plan(
            deletion_set_hash=deletion_set_hash((*DELETION_ADDRESSES, "extra.resource")),
            deletion_addresses=(*DELETION_ADDRESSES, "extra.resource"),
        )
    },
    DestroyRefusalCode.ownership_scope_mismatch: {
        "regenerated": make_plan(ownership_scope=("org1", "tgt-lab-01", "other-range", 1))
    },
    DestroyRefusalCode.target_mismatch: {"regenerated": make_plan(target_id="tgt-other")},
}


@pytest.mark.parametrize("code", sorted(DestroyRefusalCode, key=lambda c: c.value))
def test_every_destroy_refusal_code_is_produced_by_its_own_condition(code):
    """A refusal nobody can trigger is a refusal nobody can build recovery guidance on."""
    scenario = REFUSAL_SCENARIOS[code]
    if code is DestroyRefusalCode.approval_is_not_for_destroy:
        # Bypassing __post_init__ deliberately: this is the record-mutated-around-the-constructor
        # case the gate's own check exists for.
        approval = scenario["approval"]
        for name, value in make_approval().__dict__.items():
            object.__setattr__(approval, name, value)
        object.__setattr__(approval, "operation_kind", "apply")
        scenario = {"approval": approval}
    with pytest.raises(DestroyRefused) as excinfo:
        run_gate(**scenario)
    assert excinfo.value.code is code


def test_a_stale_cluster_fingerprint_is_a_target_mismatch():
    with pytest.raises(DestroyRefused) as excinfo:
        run_gate(regenerated=make_plan(cluster_fingerprint="fp-other-cluster"))
    assert excinfo.value.code is DestroyRefusalCode.target_mismatch
    assert "different cluster" in excinfo.value.detail


def test_freshness_refuses_an_unmade_check_exactly_as_it_refuses_a_failed_one():
    """``None`` is not "probably fine" — a destroy against unknown facts deletes the wrong thing."""
    for value in (None, False):
        with pytest.raises(DestroyRefused) as excinfo:
            run_gate(preconditions=make_preconditions(ownership_verified=value))
        assert excinfo.value.code is DestroyRefusalCode.ownership_not_verified
        with pytest.raises(DestroyRefused) as excinfo:
            run_gate(preconditions=make_preconditions(discovery_fresh=value))
        assert excinfo.value.code is DestroyRefusalCode.discovery_stale


def test_authority_is_refused_before_anything_about_the_plan_is_examined():
    """An unauthorized caller must learn nothing about what would be deleted."""
    with pytest.raises(DestroyRefused) as excinfo:
        run_gate(
            worker=make_worker(role="range_worker"),
            regenerated=make_plan(deletion_addresses=("secret.resource.name",)),
        )
    assert excinfo.value.code is DestroyRefusalCode.ordinary_worker_on_controlled_live_path
    assert "secret.resource.name" not in str(excinfo.value)


# --------------------------------------------------------------------------------------
# The deletion-set hash binds WHAT, not just how many
# --------------------------------------------------------------------------------------


def test_the_deletion_set_hash_describes_a_set_not_an_order():
    assert deletion_set_hash(DELETION_ADDRESSES) == deletion_set_hash(
        tuple(reversed(DELETION_ADDRESSES))
    )
    assert deletion_set_hash(DELETION_ADDRESSES) == deletion_set_hash(
        (*DELETION_ADDRESSES, DELETION_ADDRESSES[0])
    )


def test_one_extra_resource_changes_the_deletion_set_hash():
    assert deletion_set_hash(DELETION_ADDRESSES) != deletion_set_hash(
        (*DELETION_ADDRESSES, "proxmox_virtual_environment_vm.someone_else")
    )


def test_a_matching_change_set_hash_does_not_excuse_a_different_deletion_set():
    """The binding that makes "approve this destroy" mean "delete exactly these resources"."""
    swapped = ("proxmox_virtual_environment_vm.blue_dvwa", *DELETION_ADDRESSES[1:])
    with pytest.raises(DestroyRefused) as excinfo:
        run_gate(
            regenerated=make_plan(
                change_set_hash="cs-destroy-1",  # unchanged
                deletion_set_hash=deletion_set_hash(swapped),
                deletion_addresses=swapped,
            )
        )
    assert excinfo.value.code is DestroyRefusalCode.deletion_set_mismatch


# --------------------------------------------------------------------------------------
# Residue coverage
# --------------------------------------------------------------------------------------


def ownership(team_ref: str = "red", range_id: str = "wbl001") -> Ownership:
    return Ownership(
        organization_id="org1",
        target_id="tgt-lab-01",
        range_id=range_id,
        generation=1,
        operation_generation=2,
        resource_kind=RangeResourceKind.virtual_machine,
        team_ref=team_ref,
    )


def tags_for(own: Ownership) -> dict[str, str]:
    return dict(own.as_tags())


def test_every_residue_class_has_a_probe_domain():
    """A class with no domain is a class nothing ever probes."""
    assert set(CLASS_PROBE_DOMAIN) == set(ResidueClass)
    assert set(CLASS_PROBE_DOMAIN.values()) == set(ProbeDomain)


def test_every_reservation_class_maps_to_at_least_one_allocation_kind():
    ledger_classes = {c for c, d in CLASS_PROBE_DOMAIN.items() if d is ProbeDomain.ledger}
    assert set(RESERVATION_ALLOCATION_KIND) == ledger_classes
    assert all(kinds for kinds in RESERVATION_ALLOCATION_KIND.values())


def test_the_residue_classes_cover_everything_a_proxmox_range_owns():
    """The coverage contract, stated as a test so a removal is a failure rather than a gap."""
    required = {
        "qemu_vm",
        "lxc_container",
        "disk_volume",
        "nic",
        "sdn_zone",
        "vnet",
        "bridge",
        "subnet",
        "vlan_assignment",
        "firewall_group",
        "firewall_rule",
        "ip_set",
        "firewall_alias",
        "vmid_reservation",
        "mac_reservation",
        "ip_reservation",
        "subnet_reservation",
        "vlan_reservation",
        "remote_state_key_reservation",
        "cloud_init_snippet",
        "bootstrap_object",
        "transient_workspace",
        "binary_plan_file",
        "temporary_credential_file",
        "remote_state_object",
    }
    assert required <= {member.value for member in ResidueClass}


# --------------------------------------------------------------------------------------
# Ownership-bounded deletion
# --------------------------------------------------------------------------------------


def vm_resource(vmid: int = 9001, **overrides) -> OwnedResource:
    defaults = dict(
        residue_class=ResidueClass.qemu_vm,
        identifier=str(vmid),
        address=f"proxmox_virtual_environment_vm.guest{vmid}",
        expected_ownership=ownership(),
        allocation_key=(SCOPE, AllocationKind.vmid, "red/dvwa"),
    )
    defaults.update(overrides)
    return OwnedResource(**defaults)  # type: ignore[arg-type]


def test_an_owned_guest_is_deletable():
    resource = vm_resource()
    observed = ObservedInfrastructure(
        reachable=True,
        guests=(ObservedGuest(vmid=9001, name="wbl001-red-dvwa", tags=tags_for(ownership())),),
    )
    result = bound_deletion_set((resource,), observed)
    assert result.deletable == (resource,)
    assert result.protected == ()
    assert result.may_proceed


def test_a_foreign_object_with_a_perfectly_matching_name_is_never_deleted():
    """The headline property. A matching name is not, and has never been, proof of ownership."""
    resource = vm_resource()
    impostor = ObservedGuest(
        vmid=9001,
        name="wbl001-red-dvwa",  # byte-identical to what we would have created
        node_name="pve1",
        tags={"owner": "another-team", "purpose": "production"},
    )
    result = bound_deletion_set(
        (resource,), ObservedInfrastructure(reachable=True, guests=(impostor,))
    )
    assert result.deletable == ()
    assert len(result.protected) == 1
    protected = result.protected[0]
    assert protected.provenance is ObjectProvenance.untagged
    assert "will not be removed" in protected.detail
    assert resource.address not in result.deletion_addresses


def test_a_partial_secp_tag_reads_as_unreadable_and_is_protected():
    """A truncated description or a namespace collision is never "probably ours"."""
    partial = dict(tags_for(ownership()))
    del partial["secp.range"]
    result = bound_deletion_set(
        (vm_resource(),),
        ObservedInfrastructure(reachable=True, guests=(ObservedGuest(vmid=9001, tags=partial),)),
    )
    assert result.deletable == ()
    assert result.protected[0].provenance is ObjectProvenance.unreadable


def test_an_object_belonging_to_a_different_range_is_protected():
    other = tags_for(ownership(range_id="some-other-range"))
    result = bound_deletion_set(
        (vm_resource(),),
        ObservedInfrastructure(reachable=True, guests=(ObservedGuest(vmid=9001, tags=other),)),
    )
    assert result.deletable == ()
    assert result.protected[0].provenance is ObjectProvenance.secp_foreign_scope


def test_an_object_whose_tags_were_never_read_is_undetermined_not_deletable():
    """Not protected either — we did not establish anything, and that is a third answer."""
    result = bound_deletion_set(
        (vm_resource(),),
        ObservedInfrastructure(reachable=True, guests=(ObservedGuest(vmid=9001, tags=None),)),
    )
    assert result.deletable == ()
    assert result.protected == ()
    assert len(result.undetermined) == 1
    assert not result.may_proceed


def test_a_guest_already_gone_is_already_absent_rather_than_deletable():
    result = bound_deletion_set((vm_resource(),), ObservedInfrastructure(reachable=True))
    assert result.already_absent == (vm_resource(),)
    assert result.deletable == ()


def test_an_unobservable_provider_makes_every_resource_undetermined_and_blocks_the_destroy():
    resources = (vm_resource(), OwnedResource(ResidueClass.vnet, "t1vul"))
    result = bound_deletion_set(resources, ObservedInfrastructure(reachable=False))
    assert len(result.undetermined) == 2
    assert result.deletable == ()
    assert not result.may_proceed


def test_an_uncollected_inventory_leaves_its_resource_undetermined():
    """Empty means not observed, never "there is nothing there"."""
    resource = OwnedResource(ResidueClass.disk_volume, "local-lvm:vm-9001-disk-0")
    result = bound_deletion_set(
        (resource,),
        ObservedInfrastructure(reachable=True),
        SupplementalObservation(disk_volume_ids=None),
    )
    assert result.undetermined == (resource,)


def test_the_deletion_addresses_are_exactly_what_would_be_deleted():
    owned_guest = ObservedGuest(vmid=9001, tags=tags_for(ownership()))
    impostor = ObservedGuest(vmid=9002, name="wbl001-red-juice", tags={"owner": "someone"})
    result = bound_deletion_set(
        (
            vm_resource(9001),
            vm_resource(9002, address="proxmox_virtual_environment_vm.guest9002"),
        ),
        ObservedInfrastructure(reachable=True, guests=(owned_guest, impostor)),
    )
    assert result.deletion_addresses == ("proxmox_virtual_environment_vm.guest9001",)


# --------------------------------------------------------------------------------------
# Absence verification: unknown is never clean
# --------------------------------------------------------------------------------------


def full_probe_set():
    return {
        "observed": ObservedInfrastructure(
            reachable=True, zones=(), vnets=(), security_groups=(), ip_sets=()
        ),
        "supplemental": SupplementalObservation(
            disk_volume_ids=(),
            nic_macs=(),
            bridges=(),
            subnet_cidrs=(),
            vlan_tags_in_use=(),
            firewall_rule_ids=(),
            firewall_aliases=(),
            cloud_init_snippet_ids=(),
            bootstrap_object_ids=(),
        ),
        "artifacts": ArtifactProbe(readable=True, present_paths=()),
        "remote_state": RemoteStateProbe(readable=True, present_keys=()),
    }


def every_class_resource() -> tuple[OwnedResource, ...]:
    """One resource per residue class, so a run exercises the whole coverage contract."""
    return (
        vm_resource(9001),
        OwnedResource(
            ResidueClass.lxc_container,
            "9002",
            expected_ownership=ownership(),
            allocation_key=(SCOPE, AllocationKind.lxc_id, "red/sensor"),
        ),
        OwnedResource(ResidueClass.disk_volume, "local-lvm:vm-9001-disk-0"),
        OwnedResource(
            ResidueClass.nic, "02:53:45:AB:CD:EF", allocation_key=(SCOPE, AllocationKind.mac, "n0")
        ),
        OwnedResource(ResidueClass.sdn_zone, "zwbl001"),
        OwnedResource(ResidueClass.vnet, "t1vul"),
        OwnedResource(ResidueClass.bridge, "vmbr9"),
        OwnedResource(
            ResidueClass.subnet, "10.80.4.0/24", allocation_key=(SCOPE, AllocationKind.subnet, "s0")
        ),
        OwnedResource(
            ResidueClass.vlan_assignment,
            "1042",
            allocation_key=(SCOPE, AllocationKind.vlan_tag, "v0"),
        ),
        OwnedResource(ResidueClass.firewall_group, "secp-t1vul"),
        OwnedResource(ResidueClass.firewall_rule, "secp-t1vul#0"),
        OwnedResource(ResidueClass.ip_set, "secp-mgmt"),
        OwnedResource(ResidueClass.firewall_alias, "secp-score"),
        OwnedResource(ResidueClass.cloud_init_snippet, "snippets:wbl001-red-dvwa.yml"),
        OwnedResource(ResidueClass.bootstrap_object, "wbl001/guest/red/dvwa/attestation"),
        OwnedResource(ResidueClass.transient_workspace, "/var/lib/secp/ws/op-1"),
        OwnedResource(ResidueClass.binary_plan_file, "/var/lib/secp/ws/op-1/tfplan"),
        OwnedResource(ResidueClass.temporary_credential_file, "/run/secp/op-1.cred"),
        OwnedResource(
            ResidueClass.remote_state_object,
            "org1/tgt-lab-01/wbl001/g1",
            allocation_key=(SCOPE, AllocationKind.remote_state_key, "state"),
        ),
        OwnedResource(
            ResidueClass.ip_reservation,
            "guest_address:red/dvwa/address",
            allocation_key=(SCOPE, AllocationKind.guest_address, "red/dvwa/address"),
        ),
    )


def test_a_clean_teardown_confirms_every_resource_absent():
    expected = every_class_resource()
    findings = verify_absence(expected, **full_probe_set())
    assert all(f.outcome is TeardownResourceOutcome.removed for f in findings)
    assert all(f.probe_healthy for f in findings)
    assert all(f.absence_proved for f in findings)


def test_an_unobservable_provider_makes_every_provider_finding_unproven():
    """The exact shape of the false ``clean`` this repository already shipped once."""
    probes = full_probe_set()
    probes["observed"] = ObservedInfrastructure(reachable=False)
    findings = verify_absence(every_class_resource(), **probes)
    provider = [f for f in findings if f.resource.domain is ProbeDomain.provider]
    assert provider
    assert all(f.outcome is TeardownResourceOutcome.unproven for f in provider)
    assert all(not f.probe_healthy for f in provider)
    assert all(not f.absence_proved for f in provider)
    assert all("not evidence of absence" in f.detail for f in provider)


def test_an_unreadable_filesystem_makes_the_artifact_findings_unproven():
    probes = full_probe_set()
    probes["artifacts"] = ArtifactProbe(readable=False)
    findings = verify_absence(every_class_resource(), **probes)
    artifacts = [f for f in findings if f.resource.domain is ProbeDomain.local_artifact]
    assert len(artifacts) == 3
    assert all(f.outcome is TeardownResourceOutcome.unproven for f in artifacts)
    # And the provider side is unaffected — the domains fail independently.
    provider = [f for f in findings if f.resource.domain is ProbeDomain.provider]
    assert all(f.outcome is TeardownResourceOutcome.removed for f in provider)


def test_an_unreadable_remote_state_backend_makes_its_finding_unproven():
    probes = full_probe_set()
    probes["remote_state"] = RemoteStateProbe(readable=False)
    findings = verify_absence(every_class_resource(), **probes)
    remote = [f for f in findings if f.resource.domain is ProbeDomain.remote_state]
    assert len(remote) == 1
    assert remote[0].outcome is TeardownResourceOutcome.unproven


def test_an_uncollected_inventory_is_unproven_rather_than_removed():
    probes = full_probe_set()
    probes["supplemental"] = SupplementalObservation()  # nothing collected
    findings = verify_absence(every_class_resource(), **probes)
    disks = [f for f in findings if f.resource.residue_class is ResidueClass.disk_volume]
    assert disks[0].outcome is TeardownResourceOutcome.unproven
    assert "never collected" in disks[0].detail


def test_a_resource_still_present_is_reported_present():
    probes = full_probe_set()
    probes["observed"] = ObservedInfrastructure(reachable=True, zones=("zwbl001",))
    findings = verify_absence((OwnedResource(ResidueClass.sdn_zone, "zwbl001"),), **probes)
    assert findings[0].outcome is TeardownResourceOutcome.present
    assert not findings[0].absence_proved


def test_a_leftover_workspace_or_plan_file_is_reported_present():
    probes = full_probe_set()
    probes["artifacts"] = ArtifactProbe(
        readable=True, present_paths=("/var/lib/secp/ws/op-1/tfplan",)
    )
    findings = verify_absence(every_class_resource(), **probes)
    plan_file = next(
        f for f in findings if f.resource.residue_class is ResidueClass.binary_plan_file
    )
    assert plan_file.outcome is TeardownResourceOutcome.present


def test_reservations_are_not_answered_by_the_provider_probe():
    """A reservation's fate follows the release, not an inventory listing."""
    findings = verify_absence(every_class_resource(), **full_probe_set())
    assert not any(f.resource.domain is ProbeDomain.ledger for f in findings)


# --------------------------------------------------------------------------------------
# Reservations release only on proved absence
# --------------------------------------------------------------------------------------


def seeded_ledger() -> AllocationLedger:
    return AllocationLedger(
        (
            Allocation(kind=AllocationKind.vmid, scope=SCOPE, purpose="red/dvwa", value="9001"),
            Allocation(
                kind=AllocationKind.mac, scope=SCOPE, purpose="n0", value="02:53:45:AB:CD:EF"
            ),
            Allocation(kind=AllocationKind.subnet, scope=SCOPE, purpose="s0", value="10.80.4.0/24"),
        )
    )


def test_only_proved_absence_releases_a_reservation():
    probes = full_probe_set()
    findings = verify_absence(every_class_resource(), **probes)
    decisions = releasable_allocations(findings)
    assert decisions
    assert all(decision.release for decision in decisions)
    assert all("proved by a working probe" in decision.reason for decision in decisions)


def test_an_unproven_probe_releases_nothing():
    probes = full_probe_set()
    probes["observed"] = ObservedInfrastructure(reachable=False)
    findings = verify_absence(every_class_resource(), **probes)
    decisions = releasable_allocations(findings)
    provider_decisions = [
        d
        for d in decisions
        if d.residue_class in (ResidueClass.vmid_reservation, ResidueClass.subnet_reservation)
    ]
    assert provider_decisions
    assert not any(decision.release for decision in provider_decisions)
    assert all("was not proved" in decision.reason for decision in provider_decisions)


def test_a_protected_object_keeps_its_reservation_held():
    """Handing on an id something else occupies is how the next range collides with a live VM."""
    resource = vm_resource()
    impostor = ObservedGuest(vmid=9001, name="wbl001-red-dvwa", tags={"owner": "another-team"})
    deletion_set = bound_deletion_set(
        (resource,), ObservedInfrastructure(reachable=True, guests=(impostor,))
    )
    probes = full_probe_set()
    # The impostor is still there after the destroy, because we never touched it.
    probes["observed"] = ObservedInfrastructure(reachable=True, guests=(impostor,))
    findings = verify_absence((resource,), **probes)
    decisions = releasable_allocations(findings, protected=deletion_set.protected)
    assert len(decisions) == 1
    assert not decisions[0].release
    assert "not ours" in decisions[0].reason


def test_releasing_removes_only_the_proved_allocations_from_the_ledger():
    ledger = seeded_ledger()
    findings = verify_absence(every_class_resource(), **full_probe_set())
    decisions = releasable_allocations(findings)
    held = tuple(d for d in decisions if ledger.get(*d.allocation_key) is not None)
    assert held, "the fixture must actually hold some of the allocations under test"
    released, retained, already = release_proved_allocations(ledger, decisions)
    assert {d.allocation_key for d in released} == {d.allocation_key for d in held}
    assert retained == ()
    # Everything the ledger genuinely held is gone; the rest was already free.
    assert len(ledger) == 0
    assert len(already) == len(decisions) - len(held)


def test_an_allocation_the_ledger_does_not_hold_is_already_released_rather_than_an_error():
    """A destroy interrupted partway through its release phase must be safe to re-run."""
    ledger = seeded_ledger()
    findings = verify_absence(every_class_resource(), **full_probe_set())
    decisions = releasable_allocations(findings)
    release_proved_allocations(ledger, decisions)
    # Second run over the same decisions: nothing held, nothing raised, nothing retained.
    released, retained, already = release_proved_allocations(ledger, decisions)
    assert released == ()
    assert retained == ()
    assert len(already) == len(decisions)


def test_a_retained_decision_never_touches_the_ledger():
    ledger = seeded_ledger()
    before = len(ledger)
    probes = full_probe_set()
    probes["observed"] = ObservedInfrastructure(reachable=False)
    findings = verify_absence(every_class_resource(), **probes)
    decisions = releasable_allocations(findings)
    provider_backed = tuple(d for d in decisions if ledger.get(*d.allocation_key) is not None)
    released, retained, _already = release_proved_allocations(ledger, provider_backed)
    assert released == ()
    assert len(retained) == len(provider_backed)
    assert len(ledger) == before


def test_the_ledger_itself_refuses_an_unproved_release():
    """The backstop. If the decision logic were ever wrong, this still raises."""
    ledger = seeded_ledger()
    with pytest.raises(AllocationError, match="absence was not proved"):
        ledger.release(
            scope=SCOPE,
            kind=AllocationKind.vmid,
            purpose="red/dvwa",
            absence_proved=False,
            proof_detail="the provider was unreachable",
        )
    assert len(ledger) == 3


def test_reservation_findings_grade_releases_like_every_other_class():
    probes = full_probe_set()
    findings = verify_absence(every_class_resource(), **probes)
    decisions = releasable_allocations(findings)
    released, _retained = decisions, ()
    reservations = reservation_findings(decisions, released)
    assert reservations
    assert all(f.outcome is TeardownResourceOutcome.removed for f in reservations)

    none_released = reservation_findings(decisions, ())
    assert all(f.outcome is TeardownResourceOutcome.unproven for f in none_released)
    assert all(not f.probe_healthy for f in none_released)


# --------------------------------------------------------------------------------------
# The verdict: nothing clean by omission
# --------------------------------------------------------------------------------------


def test_a_teardown_that_confirmed_everything_absent_is_clean():
    probed = tuple(r for r in every_class_resource() if r.domain is not ProbeDomain.ledger)
    findings = verify_absence(probed, **full_probe_set())
    assert residue_verdict(findings, expected=probed) is ResidueVerdict.clean


def test_a_reservation_graded_before_its_release_is_unproven_not_clean():
    """``residue_verdict`` is a primitive over what was answered; a reservation is answered later.

    Callers use :func:`zero_residue_proof`, which composes the reservation findings itself. This
    pins the primitive's honest behaviour underneath: handed a reservation nobody has graded, it
    says ``unproven`` rather than assuming.
    """
    expected = every_class_resource()
    findings = verify_absence(expected, **full_probe_set())
    assert residue_verdict(findings, expected=expected) is ResidueVerdict.unproven
    assert ResidueClass.ip_reservation in uncovered_classes(findings, expected)


def test_an_expected_resource_with_no_finding_at_all_is_unproven():
    """Silence is not absence. The verdict is graded against what was expected."""
    expected = tuple(r for r in every_class_resource() if r.domain is not ProbeDomain.ledger)
    findings = verify_absence(expected, **full_probe_set())
    thinned = tuple(f for f in findings if f.resource.residue_class is not ResidueClass.vnet)
    assert residue_verdict(thinned, expected=expected) is ResidueVerdict.unproven
    assert ResidueClass.vnet in uncovered_classes(thinned, expected)


def test_an_empty_finding_set_never_reads_as_a_clean_teardown():
    assert residue_verdict((), expected=every_class_resource()) is ResidueVerdict.unproven


def test_a_teardown_that_expected_nothing_proved_nothing():
    assert residue_verdict((), expected=()) is ResidueVerdict.unproven


def test_a_confirmed_leftover_outranks_an_unproven_sibling():
    expected = (
        OwnedResource(ResidueClass.sdn_zone, "zwbl001"),
        OwnedResource(ResidueClass.vnet, "t1vul"),
    )
    probes = full_probe_set()
    probes["observed"] = ObservedInfrastructure(reachable=True, zones=("zwbl001",))
    findings = verify_absence(expected, **probes)
    assert residue_verdict(findings, expected=expected) is ResidueVerdict.residue


def test_a_protected_object_means_the_range_can_never_be_called_clean():
    resource = vm_resource()
    impostor = ObservedGuest(vmid=9001, name="wbl001-red-dvwa", tags={"owner": "another-team"})
    deletion_set = bound_deletion_set(
        (resource,), ObservedInfrastructure(reachable=True, guests=(impostor,))
    )
    # Every OTHER resource came back confirmed absent; only the impostor's id is in question.
    other = OwnedResource(ResidueClass.vnet, "t1vul")
    findings = verify_absence((other,), **full_probe_set())
    verdict = residue_verdict(findings, expected=(other,), protected=deletion_set.protected)
    assert verdict is ResidueVerdict.unproven


def test_an_unhealthy_probe_cannot_produce_clean_even_where_the_outcome_says_removed():
    """Defensive: the health flag overrides the outcome, not the other way round."""
    from secp_worker.provisioning.proxmox_residue import AbsenceFinding

    resource = OwnedResource(ResidueClass.vnet, "t1vul")
    forged = AbsenceFinding(
        resource=resource,
        outcome=TeardownResourceOutcome.removed,
        probe_healthy=False,
        detail="a removed verdict from a probe that was not working",
    )
    assert not forged.absence_proved
    assert residue_verdict((forged,), expected=(resource,)) is ResidueVerdict.unproven


# --------------------------------------------------------------------------------------
# The proof record
# --------------------------------------------------------------------------------------


def test_the_zero_residue_proof_computes_its_own_verdict_and_counts_every_class():
    """The one entry point a caller uses, and it composes the reservation grading itself."""
    expected = tuple(r for r in every_class_resource() if r.domain is not ProbeDomain.ledger)
    findings = verify_absence(expected, **full_probe_set())
    decisions = releasable_allocations(findings)
    proof = zero_residue_proof(findings, expected=expected, decisions=decisions, released=decisions)
    assert proof.is_clean
    assert proof.verdict is ResidueVerdict.clean
    assert proof.still_present == 0
    assert proof.unproven == 0
    assert proof.uncovered == ()
    assert proof.released_reservations == len(decisions)
    # Reservations were graded too, so the count exceeds the probe findings alone.
    assert proof.confirmed_absent == len(findings) + len(decisions)
    assert "vmid_reservation" in proof.by_class


def test_the_proof_reports_unproven_when_the_provider_could_not_be_observed():
    expected = tuple(r for r in every_class_resource() if r.domain is not ProbeDomain.ledger)
    probes = full_probe_set()
    probes["observed"] = ObservedInfrastructure(reachable=False)
    findings = verify_absence(expected, **probes)
    decisions = releasable_allocations(findings)
    released, retained, _already = release_proved_allocations(seeded_ledger(), decisions)
    proof = zero_residue_proof(
        findings,
        expected=expected,
        decisions=decisions,
        released=released,
        retained=retained,
    )
    assert not proof.is_clean
    assert proof.verdict is ResidueVerdict.unproven
    assert proof.unproven > 0
    assert proof.released_reservations == 0
    assert proof.retained_reservations == len(retained)
    # Every retained reservation is graded unproven, never quietly dropped. Both the VM id and the
    # CT id land here: they share one Proxmox namespace and therefore one reservation class.
    assert proof.by_class["vmid_reservation"] == {"unproven": 2}


def test_the_proof_names_protected_objects_without_claiming_them_as_removed():
    resource = vm_resource()
    impostor = ObservedGuest(vmid=9001, name="wbl001-red-dvwa", tags={"owner": "another-team"})
    deletion_set = bound_deletion_set(
        (resource,), ObservedInfrastructure(reachable=True, guests=(impostor,))
    )
    other = OwnedResource(ResidueClass.vnet, "t1vul")
    findings = verify_absence((other,), **full_probe_set())
    proof = zero_residue_proof(findings, expected=(other,), protected=deletion_set.protected)
    assert proof.protected == ("qemu_vm:9001",)
    assert proof.verdict is ResidueVerdict.unproven
    assert proof.confirmed_absent == 1  # the vnet, and nothing claimed about the impostor


def test_the_proof_breaks_results_down_by_residue_class():
    expected = every_class_resource()
    findings = verify_absence(expected, **full_probe_set())
    proof = zero_residue_proof(findings, expected=expected)
    assert proof.by_class["qemu_vm"] == {"removed": 1}
    assert proof.by_class["binary_plan_file"] == {"removed": 1}
    assert proof.by_class["remote_state_object"] == {"removed": 1}
    assert "vmid_reservation" not in proof.by_class  # reservations are graded after release
