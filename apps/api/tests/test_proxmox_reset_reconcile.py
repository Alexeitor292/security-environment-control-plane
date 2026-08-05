"""Tests for Proxmox range reset and for reconciliation over an interrupted apply.

Reset is pinned from both directions. Everything it claims to PRESERVE is asserted to be byte-equal
across the reset — identifiers, segments, firewall objects, the sealed ledger — using the real
compiler and the real manifest payload rather than a hand-written fixture, so a change to any of
those three breaks these tests rather than silently changing what a reset means. And everything it
claims to be a refusal is exercised by its own test and asserted on the CODE.

Reconciliation is pinned on the property that matters and is easy to lose: it must never authorise
a re-apply over state it did not fully observe. Each way an observation can be incomplete gets its
own test, and every one of them asserts ``recovery_required`` and ``halt`` — including the case
where the observation looks perfect but the apply's own outcome was never established, which is the
one a reassuring observation is most likely to talk somebody out of.
"""

from __future__ import annotations

import copy

import pytest
from secp_api.range_catalog import WEB_BREACH_LAB
from secp_api.range_providers.proxmox_manifest import to_manifest_payload
from secp_api.range_providers.proxmox_model import BlockedPlan
from secp_api.range_providers.proxmox_network import (
    TeamRequest,
    WebBreachLabRequest,
    compile_web_breach_lab,
)
from secp_api.range_providers.proxmox_workload import (
    ATTACKER_WORKLOAD_KEY,
    BootstrapOperation,
    GuestProfile,
    WorkloadRequest,
    WorkloadRole,
    assert_no_durable_secrets,
    compile_workload,
)
from secp_worker.provisioning.proxmox_reconcile import (
    ProviderOutcome,
    ReconcileAction,
    ReconcileDecision,
    ReconcileReason,
    decide_reconciliation,
)
from secp_worker.provisioning.proxmox_reset import (
    REQUIRED_RESET_CHECKS,
    ResetDisposition,
    ResetRefusalCode,
    ResetRefused,
    ResetRequest,
    ResetSubject,
    evaluate_reset_verification,
    plan_reset,
    reset_evidence,
    restamp_operation_generation,
    topology_fingerprint,
)
from secp_worker.provisioning.proxmox_verification import (
    CheckFinding,
    ObservedGuest,
    ObservedInfrastructure,
    VerificationCheck,
    VerificationOutcome,
    VerificationReport,
)
from tests.test_proxmox_workload import (  # reuse the real fixtures, never a parallel copy
    make_images,
    make_observation,
)

MANAGEMENT_CIDR = "10.10.0.0/24"

#: Every flag value the shipped Web Breach Lab defines, so the reset artifacts can be proved clean
#: against the real thing rather than against a stand-in.
CATALOG_FLAGS: tuple[str, ...] = tuple(
    flag.value for challenge in WEB_BREACH_LAB.challenges for flag in challenge.flags
)


def build_range():
    """Compile a real two-team Web Breach Lab and return (payload, ledger_payload, plan)."""
    observation = make_observation()
    network_result = compile_web_breach_lab(
        WebBreachLabRequest(
            organization_id="org1",
            target_id="tgt-lab-01",
            range_id="wbl001",
            generation=1,
            operation_generation=1,
            teams=(
                TeamRequest(team_ref="red", label="Red"),
                TeamRequest(team_ref="blue", label="Blue"),
            ),
        ),
        observation,
    )
    assert not isinstance(network_result, BlockedPlan)
    network, ledger = network_result

    workload = compile_workload(
        WorkloadRequest(
            organization_id="org1",
            target_id="tgt-lab-01",
            range_id="wbl001",
            generation=1,
            operation_generation=1,
            template=WEB_BREACH_LAB,
            team_refs=("red", "blue"),
            images=make_images(),
            profiles={
                WorkloadRole.attacker: GuestProfile(cpu_cores=4, memory_mb=8192, disk_gb=60),
                WorkloadRole.target: GuestProfile(cpu_cores=2, memory_mb=4096, disk_gb=20),
            },
            bootstrap_operations=(
                BootstrapOperation(key="install", description="install", timeout_seconds=300),
            ),
        ),
        network,
        observation,
        ledger,
    )
    assert not isinstance(workload, BlockedPlan), workload.describe()
    ledger.seal()
    payload = to_manifest_payload(workload.topology, ledger)
    return payload, payload["allocation_ledger"], workload


APPROVED, APPROVED_LEDGER, WORKLOAD = build_range()


def approved() -> dict:
    return copy.deepcopy(APPROVED)


def approved_ledger() -> dict:
    return copy.deepcopy(APPROVED_LEDGER)


def make_reset_request(**overrides) -> ResetRequest:
    defaults = dict(range_id="wbl001", operation_generation=2)
    defaults.update(overrides)
    return ResetRequest(**defaults)  # type: ignore[arg-type]


def do_reset(**overrides):
    kwargs = dict(
        approved_desired_state=approved(),
        approved_ledger=approved_ledger(),
        current_ledger=approved_ledger(),
        proposed_desired_state=None,
        material_refs=tuple(m.ref for m in WORKLOAD.materials),
        request=make_reset_request(),
    )
    kwargs.update(overrides)
    return plan_reset(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# The fingerprint: the one comparison that decides "same topology"
# --------------------------------------------------------------------------------------


def test_the_fingerprint_ignores_the_operation_generation_and_nothing_else():
    original = approved()
    restamped = restamp_operation_generation(original, 7)
    assert topology_fingerprint(original) == topology_fingerprint(restamped)


def test_the_fingerprint_notices_a_moved_guest():
    moved = approved()
    moved["guests"][0]["node_name"] = (
        "pve2" if moved["guests"][0]["node_name"] == "pve1" else "pve1"
    )
    assert topology_fingerprint(moved) != topology_fingerprint(approved())


def test_the_fingerprint_notices_a_renumbered_guest_and_a_resized_disk():
    renumbered = approved()
    renumbered["guests"][0]["vmid"] += 1
    resized = approved()
    resized["guests"][0]["disks"][0]["size_gb"] += 10
    base = topology_fingerprint(approved())
    assert topology_fingerprint(renumbered) != base
    assert topology_fingerprint(resized) != base


def test_the_fingerprint_notices_a_reordered_firewall_rule():
    """Rule ORDER is the whole of firewall semantics; a reorder is a topology change."""
    reordered = approved()
    group = reordered["network"]["security_groups"][0]
    group["rules"][0], group["rules"][-1] = group["rules"][-1], group["rules"][0]
    assert topology_fingerprint(reordered) != topology_fingerprint(approved())


def test_restamping_advances_every_ownership_block_not_only_the_root():
    restamped = restamp_operation_generation(approved(), 5)
    assert restamped["ownership"]["operation_generation"] == 5
    assert all(g["ownership"]["operation_generation"] == 5 for g in restamped["guests"])
    assert all(v["ownership"]["operation_generation"] == 5 for v in restamped["network"]["vnets"])
    assert all(
        s["ownership"]["operation_generation"] == 5 for s in restamped["network"]["security_groups"]
    )
    assert all(i["ownership"]["operation_generation"] == 5 for i in restamped["network"]["ip_sets"])
    assert restamped["network"]["zone"]["ownership"]["operation_generation"] == 5


def test_restamping_leaves_the_desired_state_generation_alone():
    """The IPAM scope key contains ``generation``; moving it would renumber the whole range."""
    restamped = restamp_operation_generation(approved(), 9)
    assert restamped["ownership"]["generation"] == approved()["ownership"]["generation"]
    assert all(g["ownership"]["generation"] == 1 for g in restamped["guests"])


# --------------------------------------------------------------------------------------
# What a reset preserves and what it recreates
# --------------------------------------------------------------------------------------


def test_a_reset_has_an_explicit_disposition_for_every_subject():
    """A subject with no disposition is a subject nobody decided about."""
    plan = do_reset()
    assert {action.subject for action in plan.actions} == set(ResetSubject)


def test_a_reset_preserves_the_topology_and_recreates_only_the_guests():
    plan = do_reset()
    assert plan.disposition(ResetSubject.sdn_zone) is ResetDisposition.preserved
    assert plan.disposition(ResetSubject.vnets) is ResetDisposition.preserved
    assert plan.disposition(ResetSubject.subnets_and_vlans) is ResetDisposition.preserved
    assert plan.disposition(ResetSubject.firewall_objects) is ResetDisposition.preserved
    assert plan.disposition(ResetSubject.allocation_ledger) is ResetDisposition.preserved
    assert plan.disposition(ResetSubject.range_identity) is ResetDisposition.preserved
    assert plan.disposition(ResetSubject.guests) is ResetDisposition.recreated
    assert plan.disposition(ResetSubject.challenge_state) is ResetDisposition.restored


def test_a_reset_keeps_every_deterministic_identifier():
    plan = do_reset()
    before = {
        g["guest_ref"]: (
            g["vmid"],
            g["node_name"],
            g["nics"][0]["mac_address"],
            g["address"]["published_address"],
        )
        for g in approved()["guests"]
    }
    after = {
        g["guest_ref"]: (
            g["vmid"],
            g["node_name"],
            g["nics"][0]["mac_address"],
            g["address"]["published_address"],
        )
        for g in plan.desired_state["guests"]
    }
    assert before == after


def test_a_reset_keeps_every_segment_subnet_and_vlan_tag():
    plan = do_reset()
    before = {
        (v["name"], v["vlan_tag"], v["subnet"]["cidr"]) for v in approved()["network"]["vnets"]
    }
    after = {
        (v["name"], v["vlan_tag"], v["subnet"]["cidr"])
        for v in plan.desired_state["network"]["vnets"]
    }
    assert before == after


def test_a_reset_recreates_exactly_the_compiled_guest_set():
    plan = do_reset()
    assert set(plan.recreated_guest_refs) == {g["guest_ref"] for g in approved()["guests"]}
    assert len(plan.recreated_guest_refs) == 6
    assert any(ref.endswith(ATTACKER_WORKLOAD_KEY) for ref in plan.recreated_guest_refs)


def test_a_reset_replants_challenge_state_by_reference_and_never_by_value():
    plan = do_reset()
    for challenge in WEB_BREACH_LAB.challenges:
        assert f"wbl001/challenge/{challenge.key}" in plan.restored_material_refs
    assert_no_durable_secrets(list(plan.restored_material_refs), forbidden_values=CATALOG_FLAGS)


def test_team_membership_is_always_preserved_and_is_not_an_option():
    for clear in (True, False):
        plan = do_reset(request=make_reset_request(clear_scores=clear))
        assert plan.disposition(ResetSubject.team_membership) is ResetDisposition.preserved


def test_scores_survive_a_reset_unless_the_operator_explicitly_asks():
    default_plan = do_reset()
    assert default_plan.disposition(ResetSubject.scores) is ResetDisposition.preserved
    assert "never implied" in next(
        a.detail for a in default_plan.actions if a.subject is ResetSubject.scores
    )

    asked = do_reset(request=make_reset_request(clear_scores=True))
    assert asked.disposition(ResetSubject.scores) is ResetDisposition.cleared


def test_a_reset_declares_the_checks_it_must_re_prove():
    plan = do_reset()
    assert plan.required_checks == REQUIRED_RESET_CHECKS
    assert VerificationCheck.guest_readiness in plan.required_checks
    assert VerificationCheck.required_reachability in plan.required_checks
    assert VerificationCheck.cross_team_denial in plan.required_checks
    assert VerificationCheck.management_denial in plan.required_checks


# --------------------------------------------------------------------------------------
# Every reset refusal, asserted on its code
# --------------------------------------------------------------------------------------


def test_a_reset_with_no_approved_desired_state_is_refused():
    with pytest.raises(ResetRefused) as excinfo:
        do_reset(approved_desired_state=None)
    assert excinfo.value.code is ResetRefusalCode.no_approved_desired_state


def test_a_reset_that_would_change_the_topology_is_refused():
    changed = approved()
    changed["guests"][0]["memory_mb"] += 2048
    with pytest.raises(ResetRefused) as excinfo:
        do_reset(proposed_desired_state=changed)
    assert excinfo.value.code is ResetRefusalCode.topology_change_without_approval


def test_a_topology_change_proceeds_only_with_an_explicit_new_approval():
    changed = approved()
    changed["guests"][0]["memory_mb"] += 2048
    plan = do_reset(
        proposed_desired_state=changed,
        request=make_reset_request(new_topology_approved=True),
    )
    assert plan.desired_state["guests"][0]["memory_mb"] == changed["guests"][0]["memory_mb"]


def test_an_unsealed_ledger_is_refused():
    open_ledger = approved_ledger()
    open_ledger["sealed"] = False
    with pytest.raises(ResetRefused) as excinfo:
        do_reset(approved_ledger=open_ledger, current_ledger=open_ledger)
    assert excinfo.value.code is ResetRefusalCode.ledger_not_sealed
    assert "renumbered" in excinfo.value.detail


def test_a_ledger_that_no_longer_hashes_to_the_approved_one_is_refused():
    drifted = approved_ledger()
    drifted["ledger_hash"] = "0" * 64
    with pytest.raises(ResetRefused) as excinfo:
        do_reset(current_ledger=drifted)
    assert excinfo.value.code is ResetRefusalCode.allocation_ledger_drift


def test_a_missing_allocation_ledger_is_refused():
    with pytest.raises(ResetRefused) as excinfo:
        do_reset(approved_ledger={"version": 1, "allocations": [], "sealed": True})
    assert excinfo.value.code is ResetRefusalCode.allocation_ledger_drift


def test_an_operation_generation_that_does_not_advance_is_refused():
    for generation in (0, 1):
        with pytest.raises(ResetRefused) as excinfo:
            do_reset(request=make_reset_request(operation_generation=generation))
        assert excinfo.value.code is ResetRefusalCode.operation_generation_not_advanced


# --------------------------------------------------------------------------------------
# Re-verification after a reset
# --------------------------------------------------------------------------------------


def finding(check: VerificationCheck, *, observed: bool = True, ok: bool = True) -> CheckFinding:
    """``observed=False`` yields ``ok=None`` — an unobserved check has no verdict to carry."""
    if not observed:
        return CheckFinding.unobserved(check, "")
    return CheckFinding.observed_result(check, ok=ok, detail="")


def full_report(outcome=VerificationOutcome.verified, **overrides) -> VerificationReport:
    findings = []
    for check in sorted(REQUIRED_RESET_CHECKS, key=lambda c: c.value):
        kwargs = overrides.get(check, {})
        findings.append(finding(check, **kwargs))
    return VerificationReport(outcome=outcome, findings=tuple(findings))


def test_a_reset_is_restored_only_when_every_required_check_was_observed_and_passed():
    verdict = evaluate_reset_verification(full_report())
    assert verdict.restored
    assert verdict.outcome is VerificationOutcome.verified
    assert set(verdict.proved) == REQUIRED_RESET_CHECKS
    assert verdict.outstanding == ()


def test_a_required_check_that_could_not_be_run_leaves_the_reset_unproved():
    report = full_report(**{VerificationCheck.cross_team_denial: {"observed": False, "ok": False}})
    verdict = evaluate_reset_verification(report)
    assert not verdict.restored
    assert VerificationCheck.cross_team_denial in verdict.outstanding


def test_a_verified_report_that_never_contained_a_required_check_is_downgraded():
    """A green gate over an incomplete check set is the failure this codebase keeps re-learning."""
    partial = VerificationReport(
        outcome=VerificationOutcome.verified,
        findings=(finding(VerificationCheck.guest_readiness),),
    )
    verdict = evaluate_reset_verification(partial)
    assert verdict.outcome is VerificationOutcome.verification_failed
    assert not verdict.restored
    assert VerificationCheck.cross_team_denial in verdict.outstanding
    assert VerificationCheck.management_denial in verdict.outstanding


def test_an_observed_isolation_failure_survives_into_the_reset_verdict():
    report = VerificationReport(
        outcome=VerificationOutcome.isolation_failed,
        findings=tuple(
            finding(check, ok=check is not VerificationCheck.cross_team_denial)
            for check in sorted(REQUIRED_RESET_CHECKS, key=lambda c: c.value)
        ),
    )
    verdict = evaluate_reset_verification(report)
    assert verdict.outcome is VerificationOutcome.isolation_failed
    assert not verdict.restored


def test_an_empty_report_never_reads_as_a_restored_reset():
    verdict = evaluate_reset_verification(VerificationReport(outcome=VerificationOutcome.verified))
    assert not verdict.restored
    assert set(verdict.outstanding) == REQUIRED_RESET_CHECKS


def test_reset_evidence_records_the_outcome_and_carries_no_flag_value():
    plan = do_reset()
    verdict = evaluate_reset_verification(full_report())
    evidence = reset_evidence(plan, verdict, bootstrap={"all_ready": True, "guest_count": 6})
    assert evidence["restored"] is True
    assert evidence["topology_fingerprint"] == topology_fingerprint(approved())
    assert evidence["dispositions"]["scores"] == "preserved"
    assert evidence["dispositions"]["team_membership"] == "preserved"
    assert evidence["dispositions"]["guests"] == "recreated"
    assert len(evidence["recreated_guests"]) == 6
    assert_no_durable_secrets(evidence, forbidden_values=CATALOG_FLAGS)


# --------------------------------------------------------------------------------------
# Reconciliation
# --------------------------------------------------------------------------------------


def observed_from(payload: dict, **overrides) -> ObservedInfrastructure:
    """A COMPLETE observation of the range the payload describes."""
    guests = tuple(
        ObservedGuest(
            vmid=int(guest["vmid"]),
            name=guest["name"],
            node_name=guest["node_name"],
            powered_on=True,
            ready=True,
            tags={
                "secp.org": guest["ownership"]["organization_id"],
                "secp.target": guest["ownership"]["target_id"],
                "secp.range": guest["ownership"]["range_id"],
                "secp.generation": str(guest["ownership"]["generation"]),
                "secp.operation_generation": str(guest["ownership"]["operation_generation"]),
                "secp.kind": guest["ownership"]["resource_kind"],
                "secp.team": guest["ownership"]["team_ref"],
            },
        )
        for guest in payload["guests"]
    )
    addresses = tuple(f"proxmox_virtual_environment_vm.guest[{g.vmid}]" for g in guests)
    defaults = dict(
        reachable=True,
        guests=guests,
        tofu_state_addresses=addresses,
        observed_addresses=addresses,
    )
    defaults.update(overrides)
    return ObservedInfrastructure(**defaults)  # type: ignore[arg-type]


def reconcile(**overrides) -> ReconcileDecision:
    payload = overrides.pop("payload", None) or approved()
    kwargs = dict(
        desired_state=payload,
        ledger=approved_ledger(),
        observed=observed_from(payload),
        provider_outcome=ProviderOutcome.succeeded,
        verification=None,
    )
    kwargs.update(overrides)
    return decide_reconciliation(**kwargs)  # type: ignore[arg-type]


def test_a_fully_present_range_needs_no_action():
    decision = reconcile()
    assert decision.action is ReconcileAction.no_action
    assert decision.reason is ReconcileReason.converged
    assert decision.create_vmids == ()


def test_an_unknown_provider_outcome_halts_even_when_the_observation_looks_perfect():
    """The reassuring observation must not talk the decision into a retry."""
    decision = reconcile(provider_outcome=ProviderOutcome.unknown)
    assert decision.action is ReconcileAction.halt
    assert decision.outcome is VerificationOutcome.recovery_required
    assert decision.reason is ReconcileReason.provider_outcome_unknown


def test_an_unobservable_provider_halts_with_recovery_required():
    decision = reconcile(observed=ObservedInfrastructure(reachable=False))
    assert decision.action is ReconcileAction.halt
    assert decision.outcome is VerificationOutcome.recovery_required
    assert decision.reason is ReconcileReason.provider_unobservable


def test_an_observation_that_did_not_read_ownership_tags_is_partial_and_halts():
    payload = approved()
    complete = observed_from(payload)
    partial = ObservedInfrastructure(
        reachable=True,
        guests=(
            ObservedGuest(vmid=complete.guests[0].vmid, tags=None),
            *complete.guests[1:],
        ),
        tofu_state_addresses=complete.tofu_state_addresses,
        observed_addresses=complete.observed_addresses,
    )
    decision = reconcile(payload=payload, observed=partial)
    assert decision.action is ReconcileAction.halt
    assert decision.outcome is VerificationOutcome.recovery_required
    assert decision.reason is ReconcileReason.observation_incomplete


def test_an_observation_that_did_not_read_opentofu_state_is_partial_and_halts():
    payload = approved()
    decision = reconcile(
        payload=payload,
        observed=observed_from(payload, tofu_state_addresses=None),
    )
    assert decision.action is ReconcileAction.halt
    assert decision.reason is ReconcileReason.observation_incomplete


def test_an_observation_with_no_provider_derived_address_list_is_partial_and_halts():
    payload = approved()
    decision = reconcile(payload=payload, observed=observed_from(payload, observed_addresses=None))
    assert decision.action is ReconcileAction.halt
    assert decision.reason is ReconcileReason.observation_incomplete


def test_an_unsealed_ledger_halts_because_a_retry_could_mint_new_identities():
    open_ledger = approved_ledger()
    open_ledger["sealed"] = False
    decision = reconcile(ledger=open_ledger)
    assert decision.action is ReconcileAction.halt
    assert decision.reason is ReconcileReason.ledger_not_sealed
    assert decision.outcome is VerificationOutcome.recovery_required


def test_an_object_at_one_of_our_ids_that_is_not_ours_is_never_adopted():
    payload = approved()
    complete = observed_from(payload)
    foreign = ObservedInfrastructure(
        reachable=True,
        guests=(
            # Same vmid, same name — and no SECP tag. A matching name is never proof of ownership.
            ObservedGuest(
                vmid=complete.guests[0].vmid,
                name=complete.guests[0].name,
                tags={"owner": "someone-else"},
            ),
            *complete.guests[1:],
        ),
        tofu_state_addresses=complete.tofu_state_addresses,
        observed_addresses=complete.observed_addresses,
    )
    decision = reconcile(payload=payload, observed=foreign)
    assert decision.action is ReconcileAction.halt
    assert decision.outcome is VerificationOutcome.state_disagreement
    assert decision.reason is ReconcileReason.foreign_object_at_allocated_id


def test_a_secp_object_from_a_different_range_at_one_of_our_ids_also_halts():
    payload = approved()
    complete = observed_from(payload)
    stale_tags = dict(complete.guests[0].tags or {})
    stale_tags["secp.range"] = "some-other-range"
    foreign = ObservedInfrastructure(
        reachable=True,
        guests=(
            ObservedGuest(vmid=complete.guests[0].vmid, tags=stale_tags),
            *complete.guests[1:],
        ),
        tofu_state_addresses=complete.tofu_state_addresses,
        observed_addresses=complete.observed_addresses,
    )
    decision = reconcile(payload=payload, observed=foreign)
    assert decision.action is ReconcileAction.halt
    assert decision.reason is ReconcileReason.foreign_object_at_allocated_id


def test_state_claiming_a_resource_the_provider_does_not_have_halts():
    payload = approved()
    complete = observed_from(payload)
    disagreeing = ObservedInfrastructure(
        reachable=True,
        guests=complete.guests,
        tofu_state_addresses=(*(complete.tofu_state_addresses or ()), "phantom.resource"),
        observed_addresses=complete.observed_addresses,
    )
    decision = reconcile(payload=payload, observed=disagreeing)
    assert decision.action is ReconcileAction.halt
    assert decision.outcome is VerificationOutcome.state_disagreement
    assert decision.reason is ReconcileReason.state_claims_absent_resource


def test_an_observed_isolation_failure_halts_rather_than_reconciling_forward():
    payload = approved()
    report = VerificationReport(
        outcome=VerificationOutcome.isolation_failed,
        findings=(finding(VerificationCheck.cross_team_denial, ok=False),),
    )
    decision = reconcile(payload=payload, verification=report)
    assert decision.action is ReconcileAction.halt
    assert decision.outcome is VerificationOutcome.isolation_failed
    assert decision.reason is ReconcileReason.isolation_violation_observed


def test_guests_proved_absent_may_be_resumed_at_their_existing_identifiers():
    payload = approved()
    complete = observed_from(payload)
    missing = complete.guests[0]
    survivors = complete.guests[1:]
    addresses = tuple(f"proxmox_virtual_environment_vm.guest[{g.vmid}]" for g in survivors)
    partial_apply = ObservedInfrastructure(
        reachable=True,
        guests=survivors,
        tofu_state_addresses=addresses,
        observed_addresses=addresses,
    )
    decision = reconcile(payload=payload, observed=partial_apply)
    assert decision.action is ReconcileAction.resume_apply
    assert decision.reason is ReconcileReason.resources_proved_absent
    assert decision.create_vmids == (missing.vmid,)


def test_a_resume_never_proposes_creating_something_already_present():
    payload = approved()
    complete = observed_from(payload)
    survivors = complete.guests[2:]
    addresses = tuple(f"proxmox_virtual_environment_vm.guest[{g.vmid}]" for g in survivors)
    decision = reconcile(
        payload=payload,
        observed=ObservedInfrastructure(
            reachable=True,
            guests=survivors,
            tofu_state_addresses=addresses,
            observed_addresses=addresses,
        ),
    )
    assert decision.action is ReconcileAction.resume_apply
    present = {guest.vmid for guest in survivors}
    assert not (set(decision.create_vmids) & present)


def test_a_resume_only_ever_names_identifiers_the_sealed_ledger_recorded():
    payload = approved()
    complete = observed_from(payload)
    ledger_vmids = {
        int(record["value"])
        for record in approved_ledger()["allocations"]
        if record["kind"] in ("vmid", "lxc_id")
    }
    addresses = tuple(
        f"proxmox_virtual_environment_vm.guest[{g.vmid}]" for g in complete.guests[3:]
    )
    decision = reconcile(
        payload=payload,
        observed=ObservedInfrastructure(
            reachable=True,
            guests=complete.guests[3:],
            tofu_state_addresses=addresses,
            observed_addresses=addresses,
        ),
    )
    assert decision.action is ReconcileAction.resume_apply
    assert set(decision.create_vmids) <= ledger_vmids


def test_a_desired_guest_the_ledger_never_recorded_halts_rather_than_being_created():
    """A resume may only ever create what an approved allocation already covers."""
    unallocated = 424242  # outside the 9000-9999 pool entirely, so it cannot collide
    payload = approved()
    payload["guests"][0]["vmid"] = unallocated
    complete = observed_from(payload)
    addresses = tuple(
        f"proxmox_virtual_environment_vm.guest[{g.vmid}]" for g in complete.guests[1:]
    )
    decision = reconcile(
        payload=payload,
        observed=ObservedInfrastructure(
            reachable=True,
            guests=complete.guests[1:],
            tofu_state_addresses=addresses,
            observed_addresses=addresses,
        ),
    )
    assert decision.action is ReconcileAction.halt
    assert decision.reason is ReconcileReason.resource_not_in_sealed_ledger
    assert decision.outcome is VerificationOutcome.state_disagreement
    assert str(unallocated) in decision.detail
    assert decision.create_vmids == ()


def test_only_a_resume_decision_may_carry_resources_to_create():
    """Structural: a halt that smuggled a create list would be a retry wearing a halt's name."""
    with pytest.raises(ValueError, match="only a resume_apply"):
        ReconcileDecision(
            action=ReconcileAction.halt,
            outcome=VerificationOutcome.recovery_required,
            reason=ReconcileReason.provider_unobservable,
            detail="",
            create_vmids=(9001,),
        )


def test_every_halt_path_reports_a_closed_outcome_from_the_107_vocabulary():
    payload = approved()
    complete = observed_from(payload)
    open_ledger = approved_ledger()
    open_ledger["sealed"] = False
    halts = [
        reconcile(provider_outcome=ProviderOutcome.unknown),
        reconcile(observed=ObservedInfrastructure(reachable=False)),
        reconcile(payload=payload, observed=observed_from(payload, tofu_state_addresses=None)),
        reconcile(ledger=open_ledger),
        reconcile(
            payload=payload,
            observed=ObservedInfrastructure(
                reachable=True,
                guests=complete.guests,
                tofu_state_addresses=(*(complete.tofu_state_addresses or ()), "phantom"),
                observed_addresses=complete.observed_addresses,
            ),
        ),
    ]
    assert all(decision.action is ReconcileAction.halt for decision in halts)
    assert all(decision.outcome in set(VerificationOutcome) for decision in halts)
    assert all(decision.create_vmids == () for decision in halts)
    # Nothing halting ever reports success.
    assert all(decision.outcome is not VerificationOutcome.verified for decision in halts)


def test_the_reconciler_defines_no_outcome_of_its_own():
    """Outcomes are consumed from the #107 contract; actions are this module's addition."""
    reconcile_outcomes = {
        reconcile().outcome,
        reconcile(provider_outcome=ProviderOutcome.unknown).outcome,
    }
    assert reconcile_outcomes <= set(VerificationOutcome)
    assert {member.value for member in ReconcileAction} == {
        "no_action",
        "resume_apply",
        "halt",
    }
