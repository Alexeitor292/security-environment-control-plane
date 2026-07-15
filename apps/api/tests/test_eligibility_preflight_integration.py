"""End-to-end integration over the ACTUAL selected Path B chain (B1B-PR3 amendment, gap 2).

This drives the REAL production components — ``run_real_eligibility_preflight`` →
``run_live_readonly_collection`` → the real ``LiveReadOnlyProxmoxCollector`` → the real
provider-neutral normalizer → the real eligibility policy → the real worker persistence recorder —
against the real, hardened, GET-only, allowlist-enforcing ``FakeProxmoxReadOnlyTransport`` and
fixture ORM records. Nothing real is contacted: no network, no Proxmox, no SSH, no subprocess.

NO FAKE COLLECTOR is substituted. The test therefore proves exactly what the actual collector can
prove through the currently reviewed GET allowlist, and documents the frontier:

  Through the reviewed allowlist the real collector emits ONLY nodes / storage / network segments /
  CIDR reservations. It deliberately does NOT infer isolation posture / no-route, VM-ID collision,
  quota capacity, or storage disposability (those require explicit, dedicated, approved
  observations the shipped collector does not supply). So for a fully-segregated first-lab boundary
  the real collector produces ``unverifiable`` — NEVER ``eligible`` — with the observable dimensions
  passing and the unobservable ones failing closed to ``unverifiable``. Reaching ``eligible`` is a
  documented deployment prerequisite (an authorized activation supplying those approved
  observations), not something the shipped read-only collector can fabricate.
"""

from __future__ import annotations

from secp_api.enums import EligibilityDimension, EligibilityOutcome, EvidenceStatus
from secp_api.models import TargetEvidenceRecord, TargetPreflight
from secp_plugin_proxmox.live_collector import LiveReadOnlyProxmoxCollector
from secp_plugin_proxmox.readonly_transport import FakeProxmoxReadOnlyTransport
from secp_worker.onboarding.eligibility_preflight import (
    EligibilityPreflightComposition,
    EligibilityPreflightGate,
    run_real_eligibility_preflight,
)
from secp_worker.onboarding.live_readonly import LiveReadCollectionGate
from tests._eligibility_fixtures import NOW, _build_chain  # type: ignore


class _Cred:
    def reveal_secret(self) -> str:
        return "transient-token"


class _Resolver:
    def resolve(self, secret_ref: str) -> _Cred:
        return _Cred()


class _AllowVerifier:
    def verify(self, binding, *, now) -> bool:
        return True


# Inventory the REAL collector can read through the reviewed GET allowlist for the BOUNDARY fixture
# (single node ``labnode``, storage ``labstore``, segment ``labseg``, CIDR ``10.9.0.0/24``).
_OBSERVABLE_INVENTORY = {
    "/nodes": [{"node": "labnode", "status": "online"}],
    "/cluster/sdn/vnets": [{"vnet": "labseg", "cidr": "10.9.0.0/24"}],
    "/nodes/labnode/storage": [{"storage": "labstore", "type": "dir"}],
}


def _real_composition(inventory: dict) -> EligibilityPreflightComposition:
    transport = FakeProxmoxReadOnlyTransport(inventory)
    return EligibilityPreflightComposition(
        gate=EligibilityPreflightGate(enabled=True),
        live_read_gate=LiveReadCollectionGate(enabled=True),
        secret_resolver=_Resolver(),
        transport_factory=lambda validated_config, token: transport,
        collector=LiveReadOnlyProxmoxCollector(),  # the ACTUAL production collector
        authorization_verifier=_AllowVerifier(),
    )


def _dimension_status(pf: TargetPreflight) -> dict:
    # preflight check status vocabulary: passed / warning(=unverifiable) / failed
    return {c["check"]: c["status"] for c in pf.checks}


def test_real_collector_complete_observable_inventory_is_unverifiable_not_eligible(
    session, principal
):
    """CASE A — actual collector + the most complete safely-observable fixture. The observable
    dimensions pass; isolation / VM-ID / quotas / disposability are unverifiable (never inferred),
    so the real policy's outcome is ``unverifiable`` — never ``eligible``."""
    chain = _build_chain(session)
    result = run_real_eligibility_preflight(
        session,
        request=chain.request(),
        composition=_real_composition(_OBSERVABLE_INVENTORY),
        now=NOW,
    )
    assert result.outcome == EligibilityOutcome.unverifiable.value
    assert result.outcome != EligibilityOutcome.eligible.value

    pf = session.get(TargetPreflight, result.preflight_id)
    assert pf.passed is False
    statuses = _dimension_status(pf)
    passed = EvidenceStatus.passed.value  # "pass" -> mapped to preflight "passed"
    # Observable dimensions the real collector can prove:
    assert statuses[EligibilityDimension.target_identity.value] == "passed"
    assert statuses[EligibilityDimension.node_boundary.value] == "passed"
    assert statuses[EligibilityDimension.network_segments.value] == "passed"
    assert statuses[EligibilityDimension.credential_read_capability.value] == "passed"
    # Dimensions the reviewed GET allowlist cannot prove — unverifiable (mapped to "warning"),
    # NEVER passed, and isolation is NEVER inferred to fully-segregated.
    assert statuses[EligibilityDimension.route_isolation.value] == "warning"
    assert statuses[EligibilityDimension.storage_boundary.value] == "warning"
    assert statuses[EligibilityDimension.vmid_range.value] == "warning"
    assert statuses[EligibilityDimension.quotas.value] == "warning"
    del passed

    # The persisted live evidence is real and immutable.
    record = session.get(TargetEvidenceRecord, pf.target_evidence_id)
    assert record.evidence_source == "live_readonly_proxmox"
    assert record.verification_level == "live_verified"


def test_real_collector_records_a_live_vmid_observation_from_cluster_resources(session, principal):
    """CASE A2 — the actual collector issues the allowlisted /cluster/resources GET and records the
    cluster's used VM-IDs as a LIVE observation (PR5A §6). The observation is genuinely collected
    and persisted (bare integer ids, redacted), yet the VM-ID dimension STILL stays unverifiable:
    the allocatable WINDOW is an approved dedicated observation the shipped collector never
    fabricates, so a live used-VM-ID list can prove collision but never makes the dimension pass."""
    inventory = {
        **_OBSERVABLE_INVENTORY,
        "/cluster/resources": [
            {"type": "qemu", "vmid": 105, "name": "existing-vm"},
            {"type": "lxc", "vmid": 210},
            {"type": "storage", "storage": "labstore"},  # non-VM rows are ignored
        ],
    }
    chain = _build_chain(session)
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=_real_composition(inventory), now=NOW
    )
    # Still not eligible: the VM-ID window is unobserved, so the dimension is unverifiable.
    assert result.outcome == EligibilityOutcome.unverifiable.value
    pf = session.get(TargetPreflight, result.preflight_id)
    assert _dimension_status(pf)[EligibilityDimension.vmid_range.value] == "warning"

    # But the LIVE VM-ID observation was genuinely collected and persisted (redacted to bare ids).
    record = session.get(TargetEvidenceRecord, pf.target_evidence_id)
    observed = record.evidence_payload["observed"]
    assert observed["vmid_range"]["used_vmids"] == [105, 210]
    # No VM name / node / status / config survived the normalizer's redaction.
    assert set(observed["vmid_range"]) == {"used_vmids"}


def test_real_collector_generic_inventory_is_ineligible_never_eligible_never_inferred(
    session, principal
):
    """CASE B — actual collector + generic/partial inventory that does NOT contain the declared
    boundary. The SDN endpoint is READ (the hardened transport returns an empty list for it), so the
    declared segment is genuinely NOT observed → ``network_segments`` FAILS → the outcome is
    ``ineligible`` (a real boundary violation), NEVER ``eligible``, isolation NEVER inferred to
    fully-segregated from generic inventory or a successful read."""
    partial = {"/nodes": [{"node": "labnode"}], "/nodes/labnode/storage": [{"storage": "labstore"}]}
    chain = _build_chain(session)
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=_real_composition(partial), now=NOW
    )
    assert result.outcome == EligibilityOutcome.ineligible.value
    assert result.outcome != EligibilityOutcome.eligible.value

    pf = session.get(TargetPreflight, result.preflight_id)
    assert pf.passed is False
    statuses = _dimension_status(pf)
    # The declared segment is genuinely not observed → failed (never a silent pass).
    assert statuses[EligibilityDimension.network_segments.value] == "failed"
    # Isolation is never inferred to fully-segregated from generic inventory / a successful read.
    assert statuses[EligibilityDimension.route_isolation.value] != "passed"


def test_real_collector_empty_target_is_never_eligible_and_never_inferred_segregated(
    session, principal
):
    """CASE C — actual collector + an empty target (no nodes). Nothing is proven; the outcome is
    non-eligible and isolation is never inferred to fully-segregated. Proves a bare successful read
    can never yield ``eligible`` or a false ``fully_segregated``."""
    chain = _build_chain(session)
    result = run_real_eligibility_preflight(
        session, request=chain.request(), composition=_real_composition({"/nodes": []}), now=NOW
    )
    assert result.outcome != EligibilityOutcome.eligible.value
    pf = session.get(TargetPreflight, result.preflight_id)
    assert pf.passed is False
    assert _dimension_status(pf)[EligibilityDimension.route_isolation.value] != "passed"


def test_real_collector_issues_only_gets_on_the_reviewed_allowlist(session, principal):
    """The actual chain issues ONLY allowlisted canonical GETs (proven by the hardened fake)."""
    transport = FakeProxmoxReadOnlyTransport(_OBSERVABLE_INVENTORY)
    composition = EligibilityPreflightComposition(
        gate=EligibilityPreflightGate(enabled=True),
        live_read_gate=LiveReadCollectionGate(enabled=True),
        secret_resolver=_Resolver(),
        transport_factory=lambda vc, tok: transport,
        collector=LiveReadOnlyProxmoxCollector(),
        authorization_verifier=_AllowVerifier(),
    )
    chain = _build_chain(session)
    run_real_eligibility_preflight(
        session, request=chain.request(), composition=composition, now=NOW
    )
    assert transport.calls, "the real collector must have issued reads"
    assert all(method == "GET" for method, _ in transport.calls)
    # Only cluster-scope + per-node storage reads were issued (no write/action endpoints). The
    # cluster-scope set now includes the allowlisted /cluster/resources VM-ID observation (PR5A §6).
    for _method, path in transport.calls:
        assert path in {
            "/nodes",
            "/cluster/sdn/vnets",
            "/cluster/resources",
            "/nodes/labnode/storage",
        }
