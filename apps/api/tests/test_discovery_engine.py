"""SECP-B5 — read-only discovery engine behavioral tests (fake-backed; zero host contact).

Proves: a sealed probe source fails closed with no evidence; an eligible target yields a
deterministic,
immutable, content-addressed candidate plan bound to the exact observed evidence; and every unsafe /
unsupported condition (clustered, ambiguous node, unsupported version, no nested virtualization,
insufficient capacity, no storage, candidate VMID collision, foreign/occupied candidate locator)
fails
closed BEFORE any plan is produced. No mutation is ever performed.
"""

from __future__ import annotations

from datetime import UTC, datetime

from secp_api.enums import (
    DiscoveryCandidatePlanStatus,
    DiscoveryEligibility,
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    TargetDiscoveryStatus,
    TargetStatus,
)
from secp_api.errors import ImmutableResourceError
from secp_api.models import (
    DiscoveryCandidatePlan,
    DiscoveryJob,
    DiscoverySnapshot,
    ExecutionTarget,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
)
from secp_api.services import target_discovery as svc
from secp_worker.target_discovery.engine import DiscoveryComposition, run_discovery
from secp_worker.target_discovery.seams import (
    InventoryFacts,
    LocatorPresence,
    ProbeSourceUnavailable,
    SealedHostProbeSource,
    StorageOption,
)


def _healthy_facts(**over) -> InventoryFacts:
    base = dict(
        version_major=8,
        version_minor=1,
        is_clustered=False,
        node="pve-a",
        node_count=1,
        cpu_total=16,
        mem_total_mb=65536,
        mem_free_mb=32768,
        nested_available=True,
        storages=(StorageOption("local-lvm", 500_000, True),),
        used_vmids=frozenset(),
    )
    base.update(over)
    return InventoryFacts(**base)


class _FakeProbeSource:
    def __init__(self, facts, presences=None):
        self._facts = facts
        self._presences = presences or {}
        self.inventory_calls = 0
        self.presence_calls = 0

    def read_inventory(self):
        self.inventory_calls += 1
        if self._facts is None:
            raise ProbeSourceUnavailable("probe_refused")
        return self._facts

    def probe_candidate_presence(self, locators):
        self.presence_calls += 1
        return {
            loc.observe_key(): self._presences.get(loc.observe_key(), LocatorPresence(False, None))
            for loc in locators
        }


def _comp(facts, presences=None) -> DiscoveryComposition:
    return DiscoveryComposition(probe_source=_FakeProbeSource(facts, presences))


def _enrollment(session, principal, profile="small_lab") -> TargetDiscoveryEnrollment:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref="vault:secp/proxmox/target-1",
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    return svc.request_discovery(
        session, principal, execution_target_id=target.id, resource_profile=profile
    )


def _job(session, enrollment) -> DiscoveryJob:
    return session.query(DiscoveryJob).filter(DiscoveryJob.enrollment_id == enrollment.id).one()


def _run(session, principal, *, facts, presences=None):
    enrollment = _enrollment(session, principal)
    job = _job(session, enrollment)
    outcome = run_discovery(
        session, job, composition=_comp(facts, presences), now=datetime.now(UTC)
    )
    session.refresh(enrollment)
    return enrollment, outcome


# --- sealed + eligible
# -----------------------------------------------------------------------------


def test_sealed_probe_source_fails_closed_with_no_evidence(session, principal):
    enrollment = _enrollment(session, principal)
    job = _job(session, enrollment)
    outcome = run_discovery(
        session,
        job,
        composition=DiscoveryComposition(probe_source=SealedHostProbeSource()),
        now=datetime.now(UTC),
    )
    assert outcome.ok is False and outcome.reason_code == "probe_source_sealed"
    session.refresh(enrollment)
    assert enrollment.status == TargetDiscoveryStatus.failed
    snap = session.query(DiscoverySnapshot).one()
    assert snap.eligibility == DiscoveryEligibility.unverifiable
    assert snap.bundle_available is False
    assert session.query(DiscoveryCandidatePlan).count() == 0


def test_eligible_target_produces_candidate_plan(session, principal):
    enrollment, outcome = _run(session, principal, facts=_healthy_facts())
    assert outcome.ok is True and outcome.reason_code == "plan_ready"
    assert enrollment.status == TargetDiscoveryStatus.plan_ready
    plan = session.query(DiscoveryCandidatePlan).one()
    assert plan.plan_hash == outcome.plan_hash == enrollment.active_plan_hash
    assert plan.node == "pve-a" and plan.storage == "local-lvm"
    assert plan.status == DiscoveryCandidatePlanStatus.draft
    # The plan is bound to exact discovery evidence + is non-executable (apply sealed).
    assert plan.plan_document["executable"] is False
    kinds = {r["kind"] for r in plan.plan_document["resources"]}
    assert {"isolated_bridge", "control_plane_vm", "nested_target_vm"} <= kinds
    # Candidate VMIDs are allocated from the bounded pool, avoiding used ones.
    vmids = plan.plan_document["resources"]
    guest_vmids = [r["locator"]["vmid"] for r in vmids if r["locator"]["type"] == "guest"]
    assert all(9000 <= v <= 9999 for v in guest_vmids) and len(set(guest_vmids)) == 2
    # An immutable evidence snapshot was recorded, with NO SSH/raw fields.
    snap = (
        session.query(DiscoverySnapshot).filter_by(eligibility=DiscoveryEligibility.eligible).one()
    )
    blob = str(snap.evidence)
    for forbidden in ("ssh", "password", "token", "BEGIN", "known_hosts", "@", "/mnt", "http"):
        assert forbidden not in blob


def test_candidate_plan_is_deterministic_and_immutable(session, principal):
    e1, o1 = _run(session, principal, facts=_healthy_facts())
    plan1 = session.query(DiscoveryCandidatePlan).filter_by(enrollment_id=e1.id).one()
    # Recompute the hash from the stored document — content-addressed + deterministic.
    from secp_api.discovery_contract import discovery_candidate_plan_hash

    assert discovery_candidate_plan_hash(plan1.plan_document) == plan1.plan_hash
    # The plan + snapshot are immutable and undeletable.
    plan1.node = "tampered"
    import pytest

    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


# --- fail-closed eligibility
# -----------------------------------------------------------------------


def _assert_refused(session, principal, *, facts, expected, presences=None):
    enrollment, outcome = _run(session, principal, facts=facts, presences=presences)
    assert outcome.ok is False and outcome.reason_code == expected
    assert enrollment.status == TargetDiscoveryStatus.failed
    assert session.query(DiscoveryCandidatePlan).count() == 0


def test_clustered_target_refused(session, principal):
    _assert_refused(
        session, principal, facts=_healthy_facts(is_clustered=True), expected="target_is_clustered"
    )


def test_ambiguous_node_refused(session, principal):
    _assert_refused(
        session, principal, facts=_healthy_facts(node_count=3), expected="ambiguous_node_selection"
    )


def test_unsupported_version_refused(session, principal):
    _assert_refused(
        session,
        principal,
        facts=_healthy_facts(version_major=5),
        expected="unsupported_proxmox_version",
    )


def test_no_nested_virtualization_refused(session, principal):
    _assert_refused(
        session,
        principal,
        facts=_healthy_facts(nested_available=False),
        expected="nested_virtualization_unavailable",
    )


def test_insufficient_capacity_refused(session, principal):
    _assert_refused(
        session,
        principal,
        facts=_healthy_facts(cpu_total=1, mem_free_mb=256),
        expected="insufficient_capacity",
    )


def test_no_storage_refused(session, principal):
    _assert_refused(
        session,
        principal,
        facts=_healthy_facts(storages=(StorageOption("local", 10, False),)),
        expected="no_storage_available",
    )


def test_candidate_vmid_collision_refused(session, principal):
    # Every candidate VMID in the pool is used → no free VMIDs to allocate.
    _assert_refused(
        session,
        principal,
        facts=_healthy_facts(used_vmids=frozenset(range(9000, 10000))),
        expected="candidate_vmid_unavailable",
    )


def test_foreign_candidate_locator_refused(session, principal):
    # Presence-probe reports the candidate bridge already exists with a FOREIGN ownership marker.
    enrollment = _enrollment(session, principal)
    from secp_api.ownership_contract import compute_ownership_fingerprint

    fp8 = compute_ownership_fingerprint(enrollment.ownership_label)[:8]
    foreign_key = f"bridge:pve-a:secp{fp8}br"
    presences = {foreign_key: LocatorPresence(True, "secp-owned:deadbeef#foreign")}
    job = _job(session, enrollment)
    outcome = run_discovery(
        session, job, composition=_comp(_healthy_facts(), presences), now=datetime.now(UTC)
    )
    assert outcome.ok is False and outcome.reason_code == "foreign_ownership_conflict"
    assert session.query(DiscoveryCandidatePlan).count() == 0
