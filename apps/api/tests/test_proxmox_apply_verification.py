"""Tests for the Proxmox apply gate and observed verification.

Two things are being pinned here. Every refusal the gate can produce is exercised by its own test
and asserted on its CODE, not its prose — a refusal whose code is untested is a refusal nobody can
build recovery guidance on. And the verification outcome matrix is driven from both directions:
each outcome is produced by the condition that should produce it, and ``verified`` is shown to be
unreachable when a check merely could not be run.
"""

from __future__ import annotations

import pytest
from secp_worker.provisioning.proxmox_apply_gate import (
    INFRASTRUCTURE_OPERATOR_ROLE,
    ApplyRefusalCode,
    ApplyRefused,
    ApprovedPlanBinding,
    AuthoritativeState,
    RegeneratedPlan,
    WorkerIdentity,
    allocations_fingerprint,
    evaluate_apply_gate,
)
from secp_worker.provisioning.proxmox_verification import (
    ISOLATION_CHECKS,
    CheckFinding,
    ObservedDisk,
    ObservedGuest,
    ObservedInfrastructure,
    ObservedVNet,
    ProbeVerdict,
    VerificationCheck,
    VerificationOutcome,
    decide_outcome,
    verify_deployment,
)
from tests.test_proxmox_plan_generation import payload_of

CONTROLLED_LIVE_QUEUE = "secp-controlled-live"
MANAGEMENT_CIDR = "10.10.10.0/24"
PROTECTED_CIDR = "10.20.0.0/24"
EXTERNAL_PROBES = ("192.0.2.53", "198.51.100.10")

ALLOCATIONS = {
    "vmid|org1|tgt|rng||1|web": "9100",
    "subnet|org1|tgt|rng|red|1|attacker": "10.80.0.0/24",
}
SCOPE = ("org1", "tgt", "rng", 1)


def worker(**overrides) -> WorkerIdentity:
    defaults = dict(
        worker_id="worker-1",
        role=INFRASTRUCTURE_OPERATOR_ROLE,
        release="1.4.0",
        queue=CONTROLLED_LIVE_QUEUE,
    )
    defaults.update(overrides)
    return WorkerIdentity(**defaults)  # type: ignore[arg-type]


def approved(**overrides) -> ApprovedPlanBinding:
    defaults = dict(
        change_set_hash="sha256:aa",
        desired_state_hash="sha256:bb",
        plan_document_hash="sha256:cc",
        allocations=dict(ALLOCATIONS),
        ownership_scope=SCOPE,
        target_id="tgt-lab-01",
        cluster_fingerprint="sha256:fingerprint",
        worker_id="worker-1",
        worker_release="1.4.0",
    )
    defaults.update(overrides)
    return ApprovedPlanBinding(**defaults)  # type: ignore[arg-type]


def regenerated(**overrides) -> RegeneratedPlan:
    defaults = dict(
        change_set_hash="sha256:aa",
        desired_state_hash="sha256:bb",
        allocations=dict(ALLOCATIONS),
        ownership_scope=SCOPE,
        target_id="tgt-lab-01",
        cluster_fingerprint="sha256:fingerprint",
        binary_plan_present=True,
    )
    defaults.update(overrides)
    return RegeneratedPlan(**defaults)  # type: ignore[arg-type]


def satisfied(**overrides) -> AuthoritativeState:
    defaults = dict(
        onboarding_current=True,
        eligibility_passing=True,
        discovery_fresh=True,
        reservations_persisted=True,
        remote_state_lock_held=True,
        credential_resolved=True,
    )
    defaults.update(overrides)
    return AuthoritativeState(**defaults)  # type: ignore[arg-type]


def run_gate(**overrides):
    kwargs = dict(
        worker=worker(),
        approved=approved(),
        regenerated=regenerated(),
        state=satisfied(),
        controlled_live_queue=CONTROLLED_LIVE_QUEUE,
    )
    kwargs.update(overrides)
    return evaluate_apply_gate(**kwargs)  # type: ignore[arg-type]


def assert_refuses(code: ApplyRefusalCode, **overrides) -> ApplyRefused:
    with pytest.raises(ApplyRefused) as excinfo:
        run_gate(**overrides)
    assert excinfo.value.code is code, f"expected {code.value}, got {excinfo.value.code.value}"
    return excinfo.value


# ======================================================================================
# The apply gate — one test per refusal code
# ======================================================================================


def test_a_fully_satisfied_apply_is_authorized():
    authorization = run_gate()
    assert authorization.change_set_hash == "sha256:aa"
    assert authorization.desired_state_hash == "sha256:bb"
    assert authorization.ownership_scope == SCOPE
    assert "allocation_identity" in authorization.checks_passed


def test_an_ordinary_worker_on_the_controlled_live_queue_is_refused():
    """The installer already refuses a second worker here; this is the in-process restatement."""
    assert_refuses(
        ApplyRefusalCode.ordinary_worker_on_controlled_live_path,
        worker=worker(role="ordinary_worker"),
    )


def test_authority_is_checked_before_anything_about_the_plan():
    """An unauthorized caller must learn nothing about the plan from its refusal."""
    refusal = assert_refuses(
        ApplyRefusalCode.ordinary_worker_on_controlled_live_path,
        worker=worker(role="ordinary_worker"),
        regenerated=regenerated(change_set_hash="sha256:completely-different"),
        state=satisfied(onboarding_current=False),
    )
    assert "sha256" not in refusal.detail


def test_worker_identity_mismatch_is_refused():
    assert_refuses(ApplyRefusalCode.worker_identity_mismatch, worker=worker(worker_id="worker-9"))


def test_worker_release_mismatch_is_refused():
    assert_refuses(ApplyRefusalCode.worker_release_mismatch, worker=worker(release="1.5.0"))


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("onboarding_current", ApplyRefusalCode.onboarding_not_current),
        ("eligibility_passing", ApplyRefusalCode.eligibility_not_current),
        ("discovery_fresh", ApplyRefusalCode.discovery_stale),
        ("reservations_persisted", ApplyRefusalCode.reservations_not_persisted),
    ],
)
def test_a_failed_prerequisite_is_refused(field, code):
    assert_refuses(code, state=satisfied(**{field: False}))


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("onboarding_current", ApplyRefusalCode.onboarding_not_current),
        ("eligibility_passing", ApplyRefusalCode.eligibility_not_current),
        ("discovery_fresh", ApplyRefusalCode.discovery_stale),
        ("reservations_persisted", ApplyRefusalCode.reservations_not_persisted),
        ("remote_state_lock_held", ApplyRefusalCode.remote_state_lock_unavailable),
        ("credential_resolved", ApplyRefusalCode.credential_unresolvable),
    ],
)
def test_an_unchecked_prerequisite_refuses_exactly_like_a_failed_one(field, code):
    """``None`` means the check never ran. Unknown is never treated as satisfied."""
    refusal = assert_refuses(code, state=satisfied(**{field: None}))
    assert (
        "unknown" in refusal.detail or "not held" in refusal.detail or "could not" in refusal.detail
    )


def test_remote_state_lock_unavailable_is_refused():
    assert_refuses(
        ApplyRefusalCode.remote_state_lock_unavailable,
        state=satisfied(remote_state_lock_held=False),
    )


def test_unresolvable_credential_is_refused():
    assert_refuses(
        ApplyRefusalCode.credential_unresolvable, state=satisfied(credential_resolved=False)
    )


def test_no_prepared_plan_is_refused():
    assert_refuses(ApplyRefusalCode.no_prepared_plan, regenerated=None)


def test_a_stale_binary_plan_is_refused():
    assert_refuses(
        ApplyRefusalCode.stale_binary_plan, regenerated=regenerated(binary_plan_present=False)
    )


def test_a_change_set_hash_mismatch_is_refused():
    assert_refuses(
        ApplyRefusalCode.change_set_hash_mismatch,
        regenerated=regenerated(change_set_hash="sha256:different"),
    )


def test_desired_state_drift_is_refused_even_when_the_change_set_matches():
    """The whole reason the plan document binds the desired state separately."""
    refusal = assert_refuses(
        ApplyRefusalCode.desired_state_drift,
        regenerated=regenerated(desired_state_hash="sha256:different"),
    )
    assert "change set matches" in refusal.detail


def test_a_second_plan_with_different_allocations_is_refused():
    drifted = dict(ALLOCATIONS)
    drifted["vmid|org1|tgt|rng||1|web"] = "9999"
    refusal = assert_refuses(
        ApplyRefusalCode.allocation_drift, regenerated=regenerated(allocations=drifted)
    )
    assert "new plan and a new approval" in refusal.detail


def test_an_added_allocation_is_also_drift():
    extra = dict(ALLOCATIONS)
    extra["mac|org1|tgt|rng|red|1|nic0"] = "02:53:45:00:00:01"
    assert_refuses(ApplyRefusalCode.allocation_drift, regenerated=regenerated(allocations=extra))


def test_ownership_scope_mismatch_is_refused():
    assert_refuses(
        ApplyRefusalCode.ownership_scope_mismatch,
        regenerated=regenerated(ownership_scope=("org1", "tgt", "rng", 2)),
    )


def test_a_different_target_is_refused():
    assert_refuses(ApplyRefusalCode.target_mismatch, regenerated=regenerated(target_id="tgt-other"))


def test_a_different_cluster_fingerprint_is_refused():
    refusal = assert_refuses(
        ApplyRefusalCode.target_mismatch,
        regenerated=regenerated(cluster_fingerprint="sha256:other"),
    )
    assert "different cluster" in refusal.detail


def test_every_refusal_code_is_covered_by_a_test():
    """A refusal nobody tested is a refusal nobody can rely on."""
    exercised = set()
    for code, kwargs in (
        (ApplyRefusalCode.ordinary_worker_on_controlled_live_path, {"worker": worker(role="x")}),
        (ApplyRefusalCode.worker_identity_mismatch, {"worker": worker(worker_id="z")}),
        (ApplyRefusalCode.worker_release_mismatch, {"worker": worker(release="9")}),
        (ApplyRefusalCode.onboarding_not_current, {"state": satisfied(onboarding_current=False)}),
        (ApplyRefusalCode.eligibility_not_current, {"state": satisfied(eligibility_passing=False)}),
        (ApplyRefusalCode.discovery_stale, {"state": satisfied(discovery_fresh=False)}),
        (
            ApplyRefusalCode.reservations_not_persisted,
            {"state": satisfied(reservations_persisted=False)},
        ),
        (
            ApplyRefusalCode.remote_state_lock_unavailable,
            {"state": satisfied(remote_state_lock_held=False)},
        ),
        (ApplyRefusalCode.credential_unresolvable, {"state": satisfied(credential_resolved=False)}),
        (ApplyRefusalCode.no_prepared_plan, {"regenerated": None}),
        (
            ApplyRefusalCode.stale_binary_plan,
            {"regenerated": regenerated(binary_plan_present=False)},
        ),
        (
            ApplyRefusalCode.change_set_hash_mismatch,
            {"regenerated": regenerated(change_set_hash="sha256:x")},
        ),
        (
            ApplyRefusalCode.desired_state_drift,
            {"regenerated": regenerated(desired_state_hash="sha256:x")},
        ),
        (ApplyRefusalCode.allocation_drift, {"regenerated": regenerated(allocations={})}),
        (
            ApplyRefusalCode.ownership_scope_mismatch,
            {"regenerated": regenerated(ownership_scope=("a", "b", "c", 9))},
        ),
        (ApplyRefusalCode.target_mismatch, {"regenerated": regenerated(target_id="other")}),
    ):
        with pytest.raises(ApplyRefused) as excinfo:
            run_gate(**kwargs)
        assert excinfo.value.code is code
        exercised.add(excinfo.value.code)

    assert exercised == set(ApplyRefusalCode), (
        f"untested refusal codes: {sorted(c.value for c in set(ApplyRefusalCode) - exercised)}"
    )


def test_allocations_fingerprint_is_keyed_on_purpose_not_position():
    payload = {
        "allocations": [
            {
                "kind": "vmid",
                "organization_id": "o",
                "target_id": "t",
                "range_id": "r",
                "team_ref": "red",
                "generation": 1,
                "purpose": "web",
                "value": "9100",
            },
            {
                "kind": "vmid",
                "organization_id": "o",
                "target_id": "t",
                "range_id": "r",
                "team_ref": "red",
                "generation": 1,
                "purpose": "db",
                "value": "9101",
            },
        ]
    }
    reversed_payload = {"allocations": list(reversed(payload["allocations"]))}
    assert allocations_fingerprint(payload) == allocations_fingerprint(reversed_payload)

    # Swapping two values between purposes IS drift, even though the value multiset is identical.
    swapped = {
        "allocations": [
            dict(payload["allocations"][0], value="9101"),
            dict(payload["allocations"][1], value="9100"),
        ]
    }
    assert allocations_fingerprint(payload) != allocations_fingerprint(swapped)


# ======================================================================================
# Verification — observation fixtures
# ======================================================================================


class ScriptedProber:
    """Blocks everything by default; ``allow`` and ``unknown`` override specific flows."""

    def __init__(
        self,
        allow: set[tuple[str, str, int]] | None = None,
        unknown: set[tuple[str, str, int]] | None = None,
        allow_all_from: set[str] | None = None,
    ) -> None:
        self.allow = allow or set()
        self.unknown = unknown or set()
        self.allow_all_from = allow_all_from or set()
        self.calls: list[tuple[str, str, int]] = []

    def probe(self, *, from_segment: str, to_address: str, port: int) -> ProbeVerdict:
        key = (from_segment, to_address, port)
        self.calls.append(key)
        if key in self.unknown:
            return ProbeVerdict.unknown
        if key in self.allow or from_segment in self.allow_all_from:
            return ProbeVerdict.reachable
        return ProbeVerdict.blocked


def observation_for(desired_state: dict, **overrides) -> ObservedInfrastructure:
    """A fully-observed, fully-conforming target."""
    guests = tuple(
        ObservedGuest(
            vmid=int(g["vmid"]),
            name=g["name"],
            node_name=g["node_name"],
            kind=g["kind"],
            powered_on=bool(g.get("start_on_deploy", True)),
            ready=True,
            disks=tuple(
                ObservedDisk(slot=d["slot"], size_gb=d["size_gb"], storage_id=d["storage_id"])
                for d in g["disks"]
            ),
            macs=tuple(n["mac_address"] for n in g["nics"]),
            bridges=tuple(n["vnet_name"] for n in g["nics"]),
            tags=dict((g.get("ownership") or {}).get("tags") or {}),
        )
        for g in desired_state["guests"]
    )
    addresses = tuple(f"guest.{g['vmid']}" for g in desired_state["guests"])
    defaults = dict(
        reachable=True,
        guests=guests,
        zones=(desired_state["network"]["zone"]["name"],),
        vnets=tuple(
            ObservedVNet(
                name=v["name"],
                zone=v["zone_name"],
                vlan_tag=v["vlan_tag"],
                cidr=v["subnet"]["cidr"],
            )
            for v in desired_state["network"]["vnets"]
        ),
        security_groups=tuple(g["name"] for g in desired_state["network"]["security_groups"]),
        ip_sets=tuple(i["name"] for i in desired_state["network"]["ip_sets"]),
        tofu_state_addresses=addresses,
        observed_addresses=addresses,
    )
    defaults.update(overrides)
    return ObservedInfrastructure(**defaults)  # type: ignore[arg-type]


def conforming_prober(desired_state: dict) -> ScriptedProber:
    """Allows exactly the required flows and blocks everything else."""
    allow: set[tuple[str, str, int]] = set()
    vnets = desired_state["network"]["vnets"]
    guest_addresses: dict[str, list[str]] = {}
    for guest in desired_state["guests"]:
        for nic in guest["nics"]:
            guest_addresses.setdefault(nic["vnet_name"], []).append(
                guest["address"]["published_address"]
            )
    teams: dict[str, list[dict]] = {}
    scoring = []
    for vnet in vnets:
        team = (vnet.get("ownership") or {}).get("team_ref")
        if vnet["role"] == "scoring":
            scoring.append(vnet)
        elif team:
            teams.setdefault(team, []).append(vnet)
    import ipaddress as _ip

    for _team, team_vnets in teams.items():
        attacker = next((v for v in team_vnets if v["role"] == "attacker"), None)
        target = next((v for v in team_vnets if v["role"] == "vulnerable"), None)
        if attacker and target:
            for address in guest_addresses.get(target["name"], []):
                allow.add((attacker["name"], address, 80))
        for scoring_vnet in scoring:
            source = attacker or team_vnets[0]
            host = str(next(iter(_ip.ip_network(scoring_vnet["subnet"]["cidr"]).hosts())))
            allow.add((source["name"], host, 443))
    return ScriptedProber(allow=allow)


def verify(desired_state: dict, observed=None, prober=None, **overrides):
    return verify_deployment(
        desired_state,
        observed if observed is not None else observation_for(desired_state),
        prober=prober,
        management_cidrs=(MANAGEMENT_CIDR,),
        protected_cidrs=(PROTECTED_CIDR,),
        external_probe_addresses=EXTERNAL_PROBES,
        **overrides,
    )


# ======================================================================================
# Verification — the outcome matrix
# ======================================================================================


def test_a_fully_conforming_deployment_verifies():
    desired_state = payload_of()
    report = verify(desired_state, prober=conforming_prober(desired_state))
    assert report.outcome is VerificationOutcome.verified, [
        (f.check.value, f.detail) for f in report.failures
    ]
    assert not report.failures
    assert {f.check for f in report.findings} == set(VerificationCheck)


def test_an_unreachable_provider_is_recovery_required():
    desired_state = payload_of()
    report = verify(
        desired_state,
        observed=ObservedInfrastructure(reachable=False),
        prober=conforming_prober(desired_state),
    )
    assert report.outcome is VerificationOutcome.recovery_required
    assert "may or may not exist" in report.findings[0].detail


def test_an_observed_cross_team_path_is_isolation_failed():
    """The failure the whole design exists to prevent, proved by probe rather than by config."""
    desired_state = payload_of()
    prober = conforming_prober(desired_state)
    red_attacker = next(
        v
        for v in desired_state["network"]["vnets"]
        if v["role"] == "attacker" and v["ownership"]["team_ref"] == "red"
    )
    blue_guest = next(g for g in desired_state["guests"] if g["ownership"]["team_ref"] == "blue")
    prober.allow.add((red_attacker["name"], blue_guest["address"]["published_address"], 80))

    report = verify(desired_state, prober=prober)
    assert report.outcome is VerificationOutcome.isolation_failed
    finding = report.finding(VerificationCheck.cross_team_denial)
    assert finding is not None and "REACHED" in finding.detail


def test_a_reachable_management_network_is_isolation_failed():
    desired_state = payload_of()
    prober = conforming_prober(desired_state)
    prober.allow.add((desired_state["network"]["vnets"][0]["name"], "10.10.10.1", 8006))
    report = verify(desired_state, prober=prober)
    assert report.outcome is VerificationOutcome.isolation_failed
    assert not report.finding(VerificationCheck.management_denial).ok


def test_reachable_external_space_is_isolation_failed():
    desired_state = payload_of()
    prober = conforming_prober(desired_state)
    prober.allow.add((desired_state["network"]["vnets"][0]["name"], EXTERNAL_PROBES[0], 443))
    report = verify(desired_state, prober=prober)
    assert report.outcome is VerificationOutcome.isolation_failed
    assert not report.finding(VerificationCheck.external_denial).ok


def test_state_and_provider_disagreement_is_state_disagreement():
    desired_state = payload_of()
    observed = observation_for(desired_state, tofu_state_addresses=("guest.ghost",))
    report = verify(desired_state, observed=observed, prober=conforming_prober(desired_state))
    assert report.outcome is VerificationOutcome.state_disagreement
    assert "in state only" in report.finding(VerificationCheck.state_agreement).detail


def test_a_missing_guest_is_verification_failed():
    desired_state = payload_of()
    full = observation_for(desired_state)
    observed = ObservedInfrastructure(
        reachable=True,
        guests=full.guests[1:],
        zones=full.zones,
        vnets=full.vnets,
        security_groups=full.security_groups,
        ip_sets=full.ip_sets,
        tofu_state_addresses=full.tofu_state_addresses[1:],
        observed_addresses=full.observed_addresses[1:],
    )
    report = verify(desired_state, observed=observed, prober=conforming_prober(desired_state))
    assert report.outcome is VerificationOutcome.verification_failed
    assert not report.finding(VerificationCheck.guest_inventory).ok


def test_a_guest_on_the_wrong_node_is_verification_failed():
    desired_state = payload_of()
    full = observation_for(desired_state)
    from dataclasses import replace

    observed = replace(
        full, guests=(replace(full.guests[0], node_name="pve-elsewhere"), *full.guests[1:])
    )
    report = verify(desired_state, observed=observed, prober=conforming_prober(desired_state))
    assert report.outcome is VerificationOutcome.verification_failed
    assert not report.finding(VerificationCheck.node_placement).ok


def test_a_missing_ownership_tag_is_verification_failed():
    """A guest with the right name but no ownership stamp is not ours."""
    desired_state = payload_of()
    full = observation_for(desired_state)
    from dataclasses import replace

    observed = replace(full, guests=(replace(full.guests[0], tags={}), *full.guests[1:]))
    report = verify(desired_state, observed=observed, prober=conforming_prober(desired_state))
    assert report.outcome is VerificationOutcome.verification_failed
    assert not report.finding(VerificationCheck.ownership_tags).ok


def test_a_guest_that_never_reported_readiness_is_not_verified():
    """ "We did not observe it responding" is not "it is ready"."""
    desired_state = payload_of()
    full = observation_for(desired_state)
    from dataclasses import replace

    observed = replace(full, guests=(replace(full.guests[0], ready=None), *full.guests[1:]))
    report = verify(desired_state, observed=observed, prober=conforming_prober(desired_state))
    assert report.outcome is VerificationOutcome.verification_failed
    finding = report.finding(VerificationCheck.guest_readiness)
    assert finding is not None and not finding.observed


def test_a_required_path_that_does_not_work_is_verification_failed_not_isolation_failed():
    """Isolation succeeding while the scenario is broken is still a failure, but a different one."""
    desired_state = payload_of()
    report = verify(desired_state, prober=ScriptedProber())  # blocks everything, including required
    assert report.outcome is VerificationOutcome.verification_failed
    assert not report.finding(VerificationCheck.required_reachability).ok
    for check in ISOLATION_CHECKS:
        assert report.finding(check).ok


# ======================================================================================
# Unknown stays unknown
# ======================================================================================


def test_without_a_prober_isolation_is_unobserved_and_the_range_is_not_verified():
    """Isolation is never inferred from configuration, however correct the rules look."""
    desired_state = payload_of()
    report = verify(desired_state, prober=None)

    assert report.outcome is not VerificationOutcome.verified
    assert report.outcome is VerificationOutcome.verification_failed
    for check in ISOLATION_CHECKS | {VerificationCheck.required_reachability}:
        finding = report.finding(check)
        assert finding is not None
        assert finding.observed is False
        assert finding.ok is False
        assert "never inferred from configuration" in finding.detail


def test_a_correct_firewall_object_set_does_not_by_itself_verify_isolation():
    desired_state = payload_of()
    report = verify(desired_state, prober=None)
    # The objects are all present...
    assert report.finding(VerificationCheck.firewall_objects).ok
    # ...and that buys exactly nothing toward the isolation verdict.
    assert report.outcome is VerificationOutcome.verification_failed


def test_an_unknown_probe_verdict_is_not_a_pass():
    desired_state = payload_of()
    prober = conforming_prober(desired_state)
    prober.unknown.add((desired_state["network"]["vnets"][0]["name"], "10.10.10.1", 22))
    report = verify(desired_state, prober=prober)
    finding = report.finding(VerificationCheck.management_denial)
    assert finding is not None and finding.observed is False
    assert report.outcome is VerificationOutcome.verification_failed


def test_uncollected_state_makes_agreement_unobserved_rather_than_agreed():
    desired_state = payload_of()
    observed = observation_for(desired_state, tofu_state_addresses=None)
    report = verify(desired_state, observed=observed, prober=conforming_prober(desired_state))
    finding = report.finding(VerificationCheck.state_agreement)
    assert finding is not None and finding.observed is False
    # Not state_disagreement: nothing was compared, so nothing disagreed.
    assert report.outcome is VerificationOutcome.verification_failed


# ======================================================================================
# Outcome precedence
# ======================================================================================


def finding(check: VerificationCheck, *, observed=True, ok=True) -> CheckFinding:
    return CheckFinding(check=check, observed=observed, ok=ok, detail="")


def test_outcome_precedence_ranks_isolation_above_state_disagreement():
    findings = (
        finding(VerificationCheck.cross_team_denial, ok=False),
        finding(VerificationCheck.state_agreement, ok=False),
    )
    assert decide_outcome(findings, provider_reachable=True) is VerificationOutcome.isolation_failed


def test_an_unreachable_provider_outranks_every_other_finding():
    findings = (finding(VerificationCheck.cross_team_denial, ok=False),)
    assert (
        decide_outcome(findings, provider_reachable=False) is VerificationOutcome.recovery_required
    )


def test_an_unobserved_isolation_check_is_not_an_isolation_failure():
    """Nothing was proved either way, so it is a verification failure, not a breach."""
    findings = (finding(VerificationCheck.cross_team_denial, observed=False, ok=False),)
    assert (
        decide_outcome(findings, provider_reachable=True) is VerificationOutcome.verification_failed
    )


def test_all_passing_findings_verify():
    findings = tuple(finding(check) for check in VerificationCheck)
    assert decide_outcome(findings, provider_reachable=True) is VerificationOutcome.verified
