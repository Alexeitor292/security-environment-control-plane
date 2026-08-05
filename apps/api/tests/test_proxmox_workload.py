"""Tests for the Web Breach Lab workload compiler and guest bootstrap accounting.

Three things are pinned here.

The compiler is shown to REFUSE rather than guess: every input that decides what software boots has
a test that removes it and asserts the specific ``reason_id``, because a compiler that quietly
defaults a template or a storage produces a plan that is wrong in a way nobody reads.

The compiler is shown to be DETERMINISTIC and to respect a sealed ledger, since that is the whole
mechanism behind "a reset restores this range rather than a renumbered one".

Bootstrap is shown to have no ambiguous verdict: each of the four closed states is produced by the
condition that should produce it, and — the load-bearing one — ``verified`` is proved unreachable
whenever a guest could not be observed, by running the real
:func:`~secp_worker.provisioning.proxmox_verification.decide_outcome` over the finding rather than
by asserting on the finding's fields alone.
"""

from __future__ import annotations

import pytest
from secp_api.range_catalog import WEB_BREACH_LAB
from secp_api.range_providers.proxmox_ipam import AllocationError, AllocationKind, AllocationLedger
from secp_api.range_providers.proxmox_manifest import to_manifest_payload
from secp_api.range_providers.proxmox_model import (
    BlockedPlan,
    CloudInitSpec,
    GuestKind,
    NodeObservation,
    ProxmoxModelError,
    ProxmoxTargetIdentity,
    SegmentRole,
    StorageObservation,
    TargetObservation,
    TemplateObservation,
    assert_management_plane_untouched,
)
from secp_api.range_providers.proxmox_network import (
    TeamRequest,
    WebBreachLabRequest,
    compile_web_breach_lab,
)
from secp_api.range_providers.proxmox_workload import (
    ATTACKER_WORKLOAD_KEY,
    MAX_BOOTSTRAP_OPERATIONS,
    BootstrapOperation,
    DurableSecretLeak,
    GuestProfile,
    MaterialScope,
    ReadinessFinding,
    ReadinessRequirement,
    ReviewedGuestImage,
    WorkloadError,
    WorkloadRequest,
    WorkloadRole,
    assert_no_durable_secrets,
    assess_competition_readiness,
    compile_workload,
    readiness_is_satisfied,
    unsearchable_values,
)
from secp_worker.provisioning.proxmox_bootstrap import (
    BOOTSTRAP_SUCCESS,
    BootstrapPhase,
    BootstrapState,
    ExpectedGuest,
    GuestBootstrapReport,
    ReportRejection,
    bootstrap_finding,
    bootstrap_summary,
    evaluate_bootstrap,
)
from secp_worker.provisioning.proxmox_verification import (
    VerificationCheck,
    VerificationOutcome,
    decide_outcome,
)
from secp_worker.provisioning.proxmox_verification import (
    _first_host as verification_first_host,
)

MANAGEMENT_CIDR = "10.10.0.0/24"
DIGEST = "sha256:" + "a" * 64


def make_identity() -> ProxmoxTargetIdentity:
    return ProxmoxTargetIdentity(
        target_id="tgt-lab-01",
        cluster_name="lab",
        cluster_fingerprint="fp-lab-01",
        management_cidrs=(MANAGEMENT_CIDR,),
        management_bridges=("vmbr0",),
    )


def make_observation(**overrides) -> TargetObservation:
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
                storages=(storage,),
                bridges=("vmbr0", "vmbr1"),
            ),
            NodeObservation(
                node_name="pve2",
                online=True,
                storages=(storage,),
                bridges=("vmbr0", "vmbr1"),
            ),
        ),
        templates=(
            TemplateObservation(
                template_ref="kali-2026", vmid=8000, node_name="pve1", guest_kind=GuestKind.qemu
            ),
            TemplateObservation(
                template_ref="dvwa-1.9", vmid=8001, node_name="pve1", guest_kind=GuestKind.qemu
            ),
            TemplateObservation(
                template_ref="juice-v17", vmid=8002, node_name="pve1", guest_kind=GuestKind.qemu
            ),
        ),
        sdn_supported=True,
        firewall_supported=True,
        vlan_tags_in_use=(100,),
        vmids_in_use=(100, 8000, 8001, 8002),
        macs_in_use=("BC:24:11:00:00:01",),
        subnets_in_use=(MANAGEMENT_CIDR,),
        sdn_names_in_use=("legacy",),
        firewall_names_in_use=("existing",),
    )
    defaults.update(overrides)
    return TargetObservation(**defaults)  # type: ignore[arg-type]


def make_network(observation: TargetObservation | None = None):
    """Compile the segregated network the workload lands on. Consumed, never re-implemented."""
    request = WebBreachLabRequest(
        organization_id="org1",
        target_id="tgt-lab-01",
        range_id="wbl001",
        generation=1,
        operation_generation=1,
        teams=(
            TeamRequest(team_ref="red", label="Red"),
            TeamRequest(team_ref="blue", label="Blue"),
        ),
        scoring_port=443,
    )
    result = compile_web_breach_lab(request, observation or make_observation())
    assert not isinstance(result, BlockedPlan), getattr(result, "describe", lambda: result)()
    return result


def make_images(**overrides) -> tuple[ReviewedGuestImage, ...]:
    images = {
        ATTACKER_WORKLOAD_KEY: ReviewedGuestImage(
            workload_key=ATTACKER_WORKLOAD_KEY,
            role=WorkloadRole.attacker,
            template_ref="kali-2026",
            workload_version="2026.1",
            image_digest=DIGEST,
            approval_reference="CAB-2026-11",
            service_port=22,
        ),
        "dvwa": ReviewedGuestImage(
            workload_key="dvwa",
            role=WorkloadRole.target,
            template_ref="dvwa-1.9",
            workload_version="1.9",
            image_digest=DIGEST,
            approval_reference="CAB-2026-12",
            service_port=80,
        ),
        "juice-shop": ReviewedGuestImage(
            workload_key="juice-shop",
            role=WorkloadRole.target,
            template_ref="juice-v17",
            workload_version="v17.1.0",
            image_digest=DIGEST,
            approval_reference="CAB-2026-13",
            service_port=3000,
        ),
    }
    images.update(overrides)
    return tuple(images[key] for key in sorted(images) if images[key] is not None)


def make_request(**overrides) -> WorkloadRequest:
    defaults = dict(
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
            BootstrapOperation(
                key="install-workload",
                description="Install the pinned workload",
                timeout_seconds=300,
            ),
            BootstrapOperation(
                key="seed-challenges", description="Seed challenge state", timeout_seconds=120
            ),
        ),
        scoring_port=443,
    )
    defaults.update(overrides)
    return WorkloadRequest(**defaults)  # type: ignore[arg-type]


def compile_ok(request=None, observation=None, ledger=None, network=None):
    observation = observation or make_observation()
    network = network or make_network(observation)[0]
    result = compile_workload(
        request or make_request(),
        network,
        observation,
        ledger if ledger is not None else AllocationLedger(),
    )
    assert not isinstance(result, BlockedPlan), result.describe()
    return result


def compile_blocked(**request_overrides) -> BlockedPlan:
    observation = request_overrides.pop("observation", None) or make_observation()
    network = make_network(observation)[0]
    result = compile_workload(
        make_request(**request_overrides), network, observation, AllocationLedger()
    )
    assert isinstance(result, BlockedPlan), "expected a blocked plan"
    return result


# --------------------------------------------------------------------------------------
# The happy path, and what it actually produced
# --------------------------------------------------------------------------------------


def test_two_teams_each_get_an_attacker_and_every_catalog_target():
    plan = compile_ok()
    assert len(plan.topology.guests) == 6  # 2 teams x (attacker + dvwa + juice-shop)
    for team in ("red", "blue"):
        keys = {c.workload_key for c in plan.bootstrap if c.team_ref == team}
        assert keys == {ATTACKER_WORKLOAD_KEY, "dvwa", "juice-shop"}


def test_each_guest_lands_on_the_segment_its_role_belongs_to():
    plan = compile_ok()
    network = plan.topology.network
    by_name = {vnet.name: vnet for vnet in network.vnets}
    for guest in plan.topology.guests:
        vnet = by_name[guest.nics[0].vnet_name]
        expected = (
            SegmentRole.attacker
            if guest.guest_ref.endswith(ATTACKER_WORKLOAD_KEY)
            else SegmentRole.vulnerable
        )
        assert vnet.role is expected
        assert vnet.ownership.team_ref == guest.ownership.team_ref


def test_the_compiled_topology_never_touches_the_management_plane():
    plan = compile_ok()
    # Raises if any segment, bridge or guest address lands on the management network.
    assert_management_plane_untouched(plan.topology, management_bridges=("vmbr0",))


def test_the_scoring_endpoint_is_the_same_address_verification_probes():
    """One derivation of the scoring address, not two.

    ``proxmox_verification`` derives the scoring address as the first host of the scoring subnet.
    If this compiler derived it any other way, a range would verify connectivity to an address
    nothing was told to listen on — and the check would pass or fail for reasons unrelated to the
    product working.
    """
    plan = compile_ok()
    scoring = next(v for v in plan.topology.network.vnets if v.role is SegmentRole.scoring)
    expected = verification_first_host(scoring.subnet.cidr)
    assert {address for _team, address, _port in plan.scoring_endpoints} == {expected}
    assert {c.report_address for c in plan.bootstrap} == {expected}


def test_guest_addresses_never_collide_with_their_segment_gateway():
    plan = compile_ok()
    gateways = {vnet.subnet.gateway for vnet in plan.topology.network.vnets}
    published = {guest.address.published_address for guest in plan.topology.guests}
    assert not (gateways & published)


def test_cloud_init_carries_no_gateway_or_resolver_on_an_unrouted_segment():
    plan = compile_ok()
    for guest in plan.topology.guests:
        assert guest.cloud_init is not None
        assert guest.cloud_init.gateway is None
        assert guest.cloud_init.nameservers == ()


def test_cloud_init_refuses_private_key_material_outright():
    with pytest.raises(ProxmoxModelError, match="private key material"):
        CloudInitSpec(user="secp", ssh_authorized_keys=("-----BEGIN OPENSSH PRIVATE KEY-----",))


def test_a_probe_address_is_offered_only_where_the_compiled_rules_permit_the_flow():
    """An isolated segment gets no pull-probe address, and that is the correct answer.

    Copying the published address into ``probe_address`` would produce a readiness check pointed at
    somewhere the vantage cannot reach — which passes or fails for the wrong reason. Readiness for
    those guests comes from their own outbound report instead.
    """
    plan = compile_ok()
    assert all(guest.address.probe_address is None for guest in plan.topology.guests)
    assert all(contract.probe_address is None for contract in plan.bootstrap)
    assert all(contract.probe_port is None for contract in plan.bootstrap)
    # The published address is still set on every guest — the two fields are independent, not a
    # fallback pair.
    assert all(guest.address.published_address for guest in plan.topology.guests)


def test_every_bootstrap_deadline_covers_the_work_it_bounds():
    plan = compile_ok()
    assert all(contract.deadline_covers_operations for contract in plan.bootstrap)


def test_the_compiled_topology_serializes_into_the_manifest_payload():
    """The workload must be expressible in the artifact the worker actually renders from."""
    plan = compile_ok()
    payload = to_manifest_payload(plan.topology)
    assert len(payload["guests"]) == 6
    assert {g["node_name"] for g in payload["guests"]} <= {"pve1", "pve2"}
    assert all(g["cloud_init"]["gateway"] is None for g in payload["guests"])


# --------------------------------------------------------------------------------------
# Determinism and the sealed ledger
# --------------------------------------------------------------------------------------


def _identifier_map(plan) -> dict[str, tuple]:
    return {
        guest.guest_ref: (
            guest.vmid,
            guest.node_name,
            guest.nics[0].mac_address,
            guest.address.published_address,
        )
        for guest in plan.topology.guests
    }


def test_compiling_the_same_request_twice_produces_identical_identifiers():
    first = compile_ok()
    second = compile_ok()
    assert _identifier_map(first) == _identifier_map(second)


def test_recompiling_against_the_same_ledger_is_a_no_op():
    ledger = AllocationLedger()
    observation = make_observation()
    network = make_network(observation)[0]
    first = compile_ok(observation=observation, network=network, ledger=ledger)
    size = len(ledger)
    second = compile_ok(observation=observation, network=network, ledger=ledger)
    assert _identifier_map(first) == _identifier_map(second)
    assert len(ledger) == size


def test_a_sealed_ledger_still_resolves_every_allocation_the_deploy_recorded():
    """This is the mechanism a reset rests on: same request, sealed ledger, same identifiers."""
    ledger = AllocationLedger()
    observation = make_observation()
    network = make_network(observation)[0]
    deployed = compile_ok(observation=observation, network=network, ledger=ledger)
    ledger.seal()
    reset = compile_ok(observation=observation, network=network, ledger=ledger)
    assert _identifier_map(deployed) == _identifier_map(reset)


def test_a_sealed_ledger_refuses_to_allocate_for_a_guest_it_never_recorded():
    """An approved plan cannot be widened after the fact — it can only fail and force a new one."""
    from dataclasses import replace

    from secp_api.range_catalog import CatalogComponent
    from secp_api.range_enums import ComponentRole

    ledger = AllocationLedger()
    observation = make_observation()
    network = make_network(observation)[0]
    compile_ok(observation=observation, network=network, ledger=ledger)
    ledger.seal()

    widened = replace(
        WEB_BREACH_LAB,
        components=(
            *WEB_BREACH_LAB.components,
            CatalogComponent(
                key="extra-target", name="Extra", role=ComponentRole.target, image="x:1"
            ),
        ),
    )
    images = (
        *make_images(),
        ReviewedGuestImage(
            workload_key="extra-target",
            role=WorkloadRole.target,
            template_ref="dvwa-1.9",
            workload_version="1.0",
            image_digest=DIGEST,
            approval_reference="CAB-99",
        ),
    )
    with pytest.raises(AllocationError, match="sealed"):
        compile_workload(
            make_request(template=widened, images=images), network, observation, ledger
        )


def test_vmids_come_from_the_declared_pool_and_avoid_observed_ids():
    plan = compile_ok()
    observed = set(make_observation().vmids_in_use or ())
    for guest in plan.topology.guests:
        assert 9000 <= guest.vmid <= 9999
        assert guest.vmid not in observed


def test_every_guest_identifier_is_recorded_in_the_ledger():
    ledger = AllocationLedger()
    observation = make_observation()
    plan = compile_ok(observation=observation, network=make_network(observation)[0], ledger=ledger)
    recorded_vmids = {int(v) for v in ledger.values_of(AllocationKind.vmid)}
    recorded_macs = set(ledger.values_of(AllocationKind.mac))
    assert {g.vmid for g in plan.topology.guests} <= recorded_vmids
    assert {g.nics[0].mac_address for g in plan.topology.guests} <= recorded_macs


# --------------------------------------------------------------------------------------
# What the compiler refuses to invent
# --------------------------------------------------------------------------------------


def test_a_workload_with_no_reviewed_template_blocks():
    blocked = compile_blocked(images=make_images(**{"juice-shop": None}))
    assert "proxmox.workload.image_not_reviewed" in blocked.reason_ids


def test_a_template_discovery_never_saw_blocks():
    images = make_images(
        **{
            "dvwa": ReviewedGuestImage(
                workload_key="dvwa",
                role=WorkloadRole.target,
                template_ref="dvwa-imagined",
                workload_version="1.9",
                image_digest=DIGEST,
                approval_reference="CAB-1",
            )
        }
    )
    blocked = compile_blocked(images=images)
    assert "proxmox.workload.template_not_observed" in blocked.reason_ids


def test_a_role_with_no_sizing_profile_blocks():
    blocked = compile_blocked(
        profiles={WorkloadRole.target: GuestProfile(cpu_cores=2, memory_mb=4096, disk_gb=20)}
    )
    assert "proxmox.workload.profile_missing" in blocked.reason_ids


def test_a_storage_whose_content_types_were_not_observed_is_not_a_candidate():
    """Empty content types mean NOT OBSERVED, never "accepts everything"."""
    unobserved = make_observation(
        nodes=(
            NodeObservation(
                node_name="pve1",
                online=True,
                storages=(StorageObservation(storage_id="local-lvm"),),
                bridges=("vmbr0", "vmbr1"),
            ),
        )
    )
    network = make_network()[0]
    result = compile_workload(make_request(), network, unobserved, AllocationLedger())
    assert isinstance(result, BlockedPlan)
    assert "proxmox.workload.no_eligible_node" in result.reason_ids


def test_placement_on_a_node_that_is_not_eligible_blocks():
    blocked = compile_blocked(placement={"red/dvwa": "pve9"})
    assert "proxmox.workload.placement_not_eligible" in blocked.reason_ids


def sensor_image() -> ReviewedGuestImage:
    return ReviewedGuestImage(
        workload_key="sensor",
        role=WorkloadRole.sensor,
        template_ref="kali-2026",
        workload_version="2026.1",
        image_digest=DIGEST,
        approval_reference="CAB-2026-14",
        service_port=4789,
    )


def sensor_network(observation: TargetObservation):
    """A network compiled WITH a sensor segment per team. Telemetry is opt-in on both sides."""
    result = compile_web_breach_lab(
        WebBreachLabRequest(
            organization_id="org1",
            target_id="tgt-lab-01",
            range_id="wbl001",
            generation=1,
            operation_generation=1,
            teams=(
                TeamRequest(team_ref="red", label="Red", include_sensor=True),
                TeamRequest(team_ref="blue", label="Blue", include_sensor=True),
            ),
        ),
        observation,
    )
    assert not isinstance(result, BlockedPlan), result.describe()
    return result[0]


def test_a_reviewed_sensor_image_is_compiled_onto_the_teams_sensor_segment():
    """Telemetry where available — and never silently dropped when it was asked for."""
    observation = make_observation()
    network = sensor_network(observation)
    request = make_request(
        images=(*make_images(), sensor_image()),
        profiles={
            WorkloadRole.attacker: GuestProfile(cpu_cores=4, memory_mb=8192, disk_gb=60),
            WorkloadRole.target: GuestProfile(cpu_cores=2, memory_mb=4096, disk_gb=20),
            WorkloadRole.sensor: GuestProfile(cpu_cores=2, memory_mb=2048, disk_gb=40),
        },
    )
    plan = compile_ok(request, observation=observation, network=network)
    assert len(plan.topology.guests) == 8  # 2 teams x (attacker + 2 targets + sensor)
    by_name = {vnet.name: vnet for vnet in network.vnets}
    sensors = [g for g in plan.topology.guests if g.guest_ref.endswith("/sensor")]
    assert len(sensors) == 2
    assert all(by_name[g.nics[0].vnet_name].role is SegmentRole.sensor for g in sensors)
    # The targets are still all there, so readiness is unaffected by the extra guest.
    assert readiness_is_satisfied(assess_competition_readiness(plan, request))


def test_a_sensor_image_with_no_sensor_segment_blocks_instead_of_being_dropped():
    request = make_request(
        images=(*make_images(), sensor_image()),
        profiles={
            WorkloadRole.attacker: GuestProfile(cpu_cores=4, memory_mb=8192, disk_gb=60),
            WorkloadRole.target: GuestProfile(cpu_cores=2, memory_mb=4096, disk_gb=20),
            WorkloadRole.sensor: GuestProfile(cpu_cores=2, memory_mb=2048, disk_gb=40),
        },
    )
    observation = make_observation()
    result = compile_workload(
        request, make_network(observation)[0], observation, AllocationLedger()
    )
    assert isinstance(result, BlockedPlan)
    assert "proxmox.workload.segment_missing" in result.reason_ids


def test_a_workload_team_set_that_does_not_match_the_network_blocks():
    observation = make_observation()
    network = make_network(observation)[0]
    result = compile_workload(
        make_request(team_refs=("red", "green")), network, observation, AllocationLedger()
    )
    assert isinstance(result, BlockedPlan)
    assert "proxmox.workload.team_set_mismatch" in result.reason_ids


def test_a_blocked_plan_names_every_blocker_at_once():
    blocked = compile_blocked(images=(), profiles={})
    # Three workloads with no reviewed image, and no profile for either role that would be needed.
    assert len(blocked.missing) >= 3


def test_a_floating_workload_version_is_refused_at_construction():
    for tag in ("latest", "main", "stable", ""):
        with pytest.raises(WorkloadError, match="floating tag"):
            ReviewedGuestImage(
                workload_key="dvwa",
                role=WorkloadRole.target,
                template_ref="dvwa-1.9",
                workload_version=tag,
                image_digest=DIGEST,
                approval_reference="CAB-1",
            )


def test_an_image_with_no_digest_is_refused():
    with pytest.raises(WorkloadError, match="immutable"):
        ReviewedGuestImage(
            workload_key="dvwa",
            role=WorkloadRole.target,
            template_ref="dvwa-1.9",
            workload_version="1.9",
            image_digest="",
            approval_reference="CAB-1",
        )


def test_an_unreviewed_template_is_refused():
    with pytest.raises(WorkloadError, match="approval reference"):
        ReviewedGuestImage(
            workload_key="dvwa",
            role=WorkloadRole.target,
            template_ref="dvwa-1.9",
            workload_version="1.9",
            image_digest=DIGEST,
            approval_reference="",
        )


def test_bootstrap_is_bounded():
    operations = tuple(
        BootstrapOperation(key=f"op{index}", description="x", timeout_seconds=10)
        for index in range(MAX_BOOTSTRAP_OPERATIONS + 1)
    )
    with pytest.raises(WorkloadError, match="deliberately bounded"):
        make_request(bootstrap_operations=operations)


def test_a_single_team_request_is_refused():
    with pytest.raises(WorkloadError, match="two-team"):
        make_request(team_refs=("red",))


# --------------------------------------------------------------------------------------
# Competition readiness — a property of the plan, and only of the plan
# --------------------------------------------------------------------------------------


def test_a_compiled_web_breach_lab_is_competition_ready():
    request = make_request()
    plan = compile_ok(request)
    findings = assess_competition_readiness(plan, request)
    unmet = [f.requirement.value for f in findings if not f.met]
    assert unmet == []
    assert readiness_is_satisfied(findings)


def test_readiness_covers_every_requirement_the_enum_declares():
    """A requirement with no finding is a requirement nobody checks."""
    request = make_request()
    findings = assess_competition_readiness(compile_ok(request), request)
    assert {f.requirement for f in findings} == set(ReadinessRequirement)


def test_an_empty_finding_set_is_not_satisfied():
    assert not readiness_is_satisfied(())


def test_a_challenge_whose_component_is_not_deployed_fails_readiness():
    """DVWA removed from the images: its three challenges have nothing to run against."""
    request = make_request(images=make_images(dvwa=None))
    observation = make_observation()
    network = make_network(observation)[0]
    result = compile_workload(request, network, observation, AllocationLedger())
    # The compiler blocks first, which is the stronger behaviour — a plan that cannot cover the
    # catalog is never produced at all.
    assert isinstance(result, BlockedPlan)
    assert "proxmox.workload.image_not_reviewed" in result.reason_ids


def test_readiness_reports_uncovered_challenges_when_the_template_outruns_the_workloads():
    """Readiness is checked against the CATALOG, so a template gaining a target is caught."""
    from dataclasses import replace

    from secp_api.range_catalog import CatalogChallenge, CatalogFlag

    extended = replace(
        WEB_BREACH_LAB,
        challenges=(
            *WEB_BREACH_LAB.challenges,
            CatalogChallenge(
                key="future-target",
                title="A challenge for a component nobody stood up",
                description="",
                category="misc",
                points=10,
                component_key="not-deployed",
                flags=(CatalogFlag(value="x"),),
            ),
        ),
    )
    request = make_request()
    plan = compile_ok(request)
    findings = assess_competition_readiness(plan, make_request(template=extended))
    covered = next(f for f in findings if f.requirement is ReadinessRequirement.challenges_covered)
    assert not covered.met
    assert "future-target" in covered.detail


def test_plan_readiness_and_observed_verification_do_not_share_a_vocabulary():
    """Readiness must never be mistakable for verification.

    The two answer different questions — "is this plan runnable?" and "is this deployed range
    isolated?" — and the second can only be answered by observation. Overlapping names would let a
    caller satisfy a verification requirement with a plan-level finding, which is the exact
    inference from configuration that the product forbids.
    """
    readiness_values = {member.value for member in ReadinessRequirement}
    verification_values = {member.value for member in VerificationCheck}
    assert not (readiness_values & verification_values)
    outcome_values = {member.value for member in VerificationOutcome}
    assert not (readiness_values & outcome_values)
    assert not hasattr(ReadinessFinding, "observed")


def test_the_scoring_readiness_finding_says_it_is_not_evidence():
    request = make_request()
    findings = assess_competition_readiness(compile_ok(request), request)
    scoring = next(
        f for f in findings if f.requirement is ReadinessRequirement.scoring_reachable_by_plan
    )
    assert scoring.met
    assert "NOT evidence" in scoring.detail


# --------------------------------------------------------------------------------------
# Secrets never reach OpenTofu state
# --------------------------------------------------------------------------------------


def test_every_dynamic_value_is_a_reference_with_no_value_field():
    plan = compile_ok()
    assert plan.materials
    for material in plan.materials:
        assert not hasattr(material, "value")
        assert material.channel == "secp.post-provisioning.v1"
    scopes = {material.scope for material in plan.materials}
    assert scopes == {MaterialScope.range, MaterialScope.team, MaterialScope.guest}


def test_every_catalog_flag_has_a_material_reference_and_no_flag_value_is_in_the_plan():
    request = make_request()
    plan = compile_ok(request)
    refs = {material.ref for material in plan.materials}
    for challenge in WEB_BREACH_LAB.challenges:
        assert f"{request.range_id}/challenge/{challenge.key}" in refs

    flag_values = tuple(
        flag.value for challenge in WEB_BREACH_LAB.challenges for flag in challenge.flags
    )
    payload = to_manifest_payload(plan.topology)
    assert_no_durable_secrets(payload, forbidden_values=flag_values)


def test_the_secret_guard_catches_a_flag_that_leaked_into_the_desired_state():
    payload = {"guests": [{"cloud_init": {"user": "secp", "notes": "flag=admin@juice-sh.op"}}]}
    with pytest.raises(DurableSecretLeak, match="post-provisioning channel"):
        assert_no_durable_secrets(payload, forbidden_values=("admin@juice-sh.op",))


def test_the_secret_guard_names_the_path_and_never_the_value():
    payload = {"guests": [{"cloud_init": {"user": "s3cr3t-token-value"}}]}
    with pytest.raises(DurableSecretLeak) as excinfo:
        assert_no_durable_secrets(payload, forbidden_values=("s3cr3t-token-value",))
    assert "/guests[0]/cloud_init/user" in str(excinfo.value)
    assert "s3cr3t-token-value" not in str(excinfo.value)


def test_the_secret_guard_keys_on_content_not_on_a_field_name():
    """A leak in an innocuously named field is still a leak, and is what actually happens."""
    payload = {"description": "provisioned by secp; motd=e99a18c428cb38d5f260853678922e03"}
    with pytest.raises(DurableSecretLeak):
        assert_no_durable_secrets(payload, forbidden_values=("e99a18c428cb38d5f260853678922e03",))


def test_the_secret_guard_catches_private_key_material_with_no_declared_values():
    payload = {"cloud_init": {"keys": ["-----BEGIN RSA PRIVATE KEY-----\nMIIE..."]}}
    with pytest.raises(DurableSecretLeak, match="private key material"):
        assert_no_durable_secrets(payload)


def test_the_secret_guard_ignores_values_too_short_to_be_evidence():
    """A one-character needle matches everywhere and would make the guard always raise."""
    assert_no_durable_secrets({"name": "red-dvwa"}, forbidden_values=("d", "a-", ""))


def test_the_shipped_dvwa_flag_is_reported_as_something_no_guard_can_protect():
    """A live example, not a hypothetical.

    DVWA's flag value is the word ``password``, which occurs inside the PUBLIC challenge key
    ``dvwa-sqli-password-hash``. Searching for it would fire on payloads containing nothing secret,
    so it is reported as unsearchable — which is the machine-readable form of what the catalog
    already says in prose about its static demo flags.
    """
    flags = tuple(flag.value for challenge in WEB_BREACH_LAB.challenges for flag in challenge.flags)
    unsearchable = unsearchable_values(flags)
    assert "password" in unsearchable
    # The rest carry punctuation or entropy and remain genuinely checkable.
    assert "admin@juice-sh.op" not in unsearchable
    assert "e99a18c428cb38d5f260853678922e03" not in unsearchable
    assert "uid=33(www-data)" not in unsearchable
    assert "acquisitions.md" not in unsearchable

    # And the guard does not fire on the challenge key that merely contains the word.
    assert_no_durable_secrets(
        {"ref": "wbl001/challenge/dvwa-sqli-password-hash"}, forbidden_values=flags
    )


def test_a_high_entropy_value_is_never_excused_as_unsearchable():
    """The exclusion must not widen to cover the material it exists to protect."""
    generated = "c7f3e9a1b45d2088ffab3312cc9910de"
    assert unsearchable_values((generated,)) == ()
    with pytest.raises(DurableSecretLeak):
        assert_no_durable_secrets({"note": generated}, forbidden_values=(generated,))


def test_public_ssh_keys_travel_but_private_material_cannot():
    request = make_request(ssh_authorized_keys=("ssh-ed25519 AAAAC3NzaC1lZDI1 operator",))
    plan = compile_ok(request)
    payload = to_manifest_payload(plan.topology)
    assert_no_durable_secrets(payload)
    assert all(
        guest.cloud_init is not None and guest.cloud_init.ssh_authorized_keys
        for guest in plan.topology.guests
    )


# --------------------------------------------------------------------------------------
# Guest bootstrap: four closed states, and no fifth
# --------------------------------------------------------------------------------------


def expected_guests(plan) -> tuple[ExpectedGuest, ...]:
    return tuple(
        ExpectedGuest(
            guest_ref=contract.guest_ref,
            vmid=contract.vmid,
            attestation_ref=contract.attestation_ref.ref,
            workload_version=contract.workload_version,
            image_digest=contract.image_digest,
            required_operations=tuple(op.key for op in contract.operations),
            deadline_seconds=contract.deadline_seconds,
        )
        for contract in plan.bootstrap
    )


def good_report(guest: ExpectedGuest, **overrides) -> GuestBootstrapReport:
    defaults = dict(
        guest_ref=guest.guest_ref,
        vmid=guest.vmid,
        attestation_ref=guest.attestation_ref,
        phase=BootstrapPhase.workload_serving,
        operations_succeeded=True,
        completed_operations=guest.required_operations,
        workload_version=guest.workload_version,
        image_digest=guest.image_digest,
        elapsed_seconds=120,
    )
    defaults.update(overrides)
    return GuestBootstrapReport(**defaults)  # type: ignore[arg-type]


def test_bootstrap_state_is_a_closed_set_of_four():
    assert {member.value for member in BootstrapState} == {
        "ready",
        "failed",
        "timed_out",
        "unobserved",
    }
    assert BOOTSTRAP_SUCCESS == frozenset({BootstrapState.ready})


def test_every_guest_reporting_correctly_verifies():
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        tuple(good_report(guest) for guest in guests),
        channel_reachable=True,
        elapsed_seconds=200,
    )
    assert {v.state for v in verdicts} == {BootstrapState.ready}
    finding = bootstrap_finding(verdicts)
    assert finding.observed and finding.ok
    assert decide_outcome((finding,), provider_reachable=True) is VerificationOutcome.verified


def test_an_unreachable_report_channel_makes_every_guest_unobserved_and_blocks_verified():
    """The load-bearing one: 'we could not look' can never resolve into a pass."""
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        tuple(good_report(guest) for guest in guests),
        channel_reachable=False,
        elapsed_seconds=10_000,
    )
    assert {v.state for v in verdicts} == {BootstrapState.unobserved}
    finding = bootstrap_finding(verdicts)
    assert not finding.observed
    assert not finding.ok
    assert decide_outcome((finding,), provider_reachable=True) is (
        VerificationOutcome.verification_failed
    )


def test_a_guest_running_the_wrong_workload_version_failed_not_ready():
    guests = expected_guests(compile_ok())
    reports = (good_report(guests[0], workload_version="1.8"),) + tuple(
        good_report(guest) for guest in guests[1:]
    )
    verdicts = evaluate_bootstrap(guests, reports, channel_reachable=True, elapsed_seconds=200)
    failed = next(v for v in verdicts if v.guest_ref == guests[0].guest_ref)
    assert failed.state is BootstrapState.failed
    assert "not the pinned" in failed.detail


def test_a_guest_whose_base_image_digest_does_not_match_is_a_failure():
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        (good_report(guests[0], image_digest="sha256:" + "b" * 64),),
        channel_reachable=True,
        elapsed_seconds=200,
    )
    assert verdicts[0].state is BootstrapState.failed or any(
        v.state is BootstrapState.failed for v in verdicts
    )
    reported = next(v for v in verdicts if v.guest_ref == guests[0].guest_ref)
    assert reported.state is BootstrapState.failed
    assert "digest" in reported.detail


def test_a_guest_that_did_not_finish_its_bounded_operations_is_a_failure():
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        (good_report(guests[0], completed_operations=("install-workload",)),),
        channel_reachable=True,
        elapsed_seconds=200,
    )
    reported = next(v for v in verdicts if v.guest_ref == guests[0].guest_ref)
    assert reported.state is BootstrapState.failed
    assert "seed-challenges" in reported.detail


def test_a_guest_that_only_reached_cloud_init_is_not_ready():
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        (good_report(guests[0], phase=BootstrapPhase.cloud_init_complete),),
        channel_reachable=True,
        elapsed_seconds=200,
    )
    reported = next(v for v in verdicts if v.guest_ref == guests[0].guest_ref)
    assert reported.state is BootstrapState.failed
    assert "reached only cloud_init_complete" in reported.detail


def test_a_report_with_the_wrong_attestation_is_not_evidence_in_either_direction():
    """A forged success must not pass, and must not be read as the guest failing either."""
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        (good_report(guests[0], attestation_ref="someone-elses-ref"),),
        channel_reachable=True,
        elapsed_seconds=10_000,
    )
    reported = next(v for v in verdicts if v.guest_ref == guests[0].guest_ref)
    assert reported.state is BootstrapState.timed_out
    assert reported.rejection is ReportRejection.attestation_mismatch


def test_a_report_whose_vmid_does_not_match_is_rejected():
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        (good_report(guests[0], vmid=guests[0].vmid + 1),),
        channel_reachable=True,
        elapsed_seconds=10_000,
    )
    reported = next(v for v in verdicts if v.guest_ref == guests[0].guest_ref)
    assert reported.rejection is ReportRejection.vmid_mismatch
    assert reported.state is not BootstrapState.ready


def test_two_reports_for_one_guest_mean_neither_is_trusted():
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        (good_report(guests[0]), good_report(guests[0])),
        channel_reachable=True,
        elapsed_seconds=10_000,
    )
    reported = next(v for v in verdicts if v.guest_ref == guests[0].guest_ref)
    assert reported.rejection is ReportRejection.duplicate_report
    assert reported.state is BootstrapState.timed_out


def test_no_report_before_the_deadline_is_unobserved_and_after_it_is_timed_out():
    guests = expected_guests(compile_ok())[:1]
    early = evaluate_bootstrap(guests, (), channel_reachable=True, elapsed_seconds=1)
    late = evaluate_bootstrap(
        guests, (), channel_reachable=True, elapsed_seconds=guests[0].deadline_seconds
    )
    assert early[0].state is BootstrapState.unobserved
    assert late[0].state is BootstrapState.timed_out
    # Neither is a pass, and neither can produce `verified`.
    for verdicts in (early, late):
        assert (
            decide_outcome((bootstrap_finding(verdicts),), provider_reachable=True)
            is not VerificationOutcome.verified
        )


def test_a_guest_reporting_beyond_its_own_bound_is_a_failure():
    guests = expected_guests(compile_ok())[:1]
    verdicts = evaluate_bootstrap(
        guests,
        (good_report(guests[0], elapsed_seconds=guests[0].deadline_seconds + 1),),
        channel_reachable=True,
        elapsed_seconds=200,
    )
    assert verdicts[0].state is BootstrapState.failed
    assert "bound" in verdicts[0].detail


def test_no_verdicts_at_all_is_unobserved_rather_than_vacuously_ok():
    finding = bootstrap_finding(())
    assert not finding.observed
    assert not finding.ok
    assert decide_outcome((finding,), provider_reachable=True) is (
        VerificationOutcome.verification_failed
    )


def test_the_bootstrap_summary_is_evidence_and_carries_no_guest_supplied_payload():
    guests = expected_guests(compile_ok())
    verdicts = evaluate_bootstrap(
        guests,
        tuple(good_report(guest, detail="whatever the guest wanted to say") for guest in guests),
        channel_reachable=True,
        elapsed_seconds=200,
    )
    summary = bootstrap_summary(verdicts)
    assert summary["all_ready"] is True
    assert summary["by_state"] == {"ready": sorted(g.guest_ref for g in guests)}
    assert "whatever the guest wanted to say" not in str(summary)


def test_an_empty_summary_is_not_all_ready():
    assert bootstrap_summary(())["all_ready"] is False
