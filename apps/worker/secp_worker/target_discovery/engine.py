"""Worker-only READ-ONLY discovery engine (SECP-B5 §1/§3/§6).

Given a claimed durable discovery job, it re-verifies the enrollment + worker identity, runs the
CLOSED read-only probe set through an injected :class:`HostProbeSource` (sealed default refuses),
assembles a typed/bounded/secret-free evidence snapshot, applies fail-closed eligibility
(unsupported
version, clustered, ambiguous node, no nested virtualization, insufficient capacity, no storage,
candidate VMID collision, occupied/foreign candidate locator), and — only if eligible — derives an
exact, content-addressed candidate plan bound to the observed evidence. It NEVER mutates: it imports
no mutation executor/transport, host-helper installer, artifact pipeline, OpenBao handoff, or the
deployment apply engine, and the candidate plan it produces is explicitly non-executable (live apply
remains sealed). Fail-closed throughout; fully testable with an injected fake probe source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from secp_api.discovery_contract import (
    DISCOVERY_EVIDENCE_SCHEMA_VERSION,
    build_candidate_plan_document,
    candidate_resource_specs,
    compute_capacity_snapshot_hash,
    compute_evidence_hash,
    discovery_candidate_plan_hash,
)
from secp_api.enums import (
    DiscoveryCandidatePlanStatus,
    DiscoveryDecisionCode,
    DiscoveryEligibility,
    DiscoveryFailureCode,
    OnboardingStatus,
    TargetDiscoveryStatus,
    WorkerIdentityStatus,
)
from secp_api.models import (
    DiscoveryCandidatePlan,
    DiscoverySnapshot,
    TargetDiscoveryEnrollment,
    TargetOnboarding,
    WorkerIdentityRegistration,
)
from secp_api.ownership_contract import compute_resource_marker
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_worker.deployment.locators import (
    BridgeLocator,
    FirewallGroupLocator,
    GuestLocator,
    ResourceLocator,
    ServiceIdentityLocator,
)
from secp_worker.target_discovery.binding import (
    BundleAnchorSource,
    DiscoveryBindingRefused,
    authorize_discovery_bundle,
)
from secp_worker.target_discovery.seams import (
    HostProbeSource,
    InventoryFacts,
    ProbeSourceUnavailable,
    SealedHostProbeSource,
)

# Closed mapping from a ``read_inventory`` refusal reason to a truthful, secret-free execution
# contact-state signal (SECP-B6 F-AUDIT). ``bundle_available`` is True only once a live bundle was
# actually acquired (host-key stage or later).
_PROBE_CONTACT_STATE: dict[str, tuple[str, bool]] = {
    "probe_source_sealed": ("sealed", False),
    "bootstrap_unavailable": ("bundle_unavailable", False),
    "host_key_binding_unverified": ("host_key_refused", True),
    "probe_timeout": ("contacted", True),
    "probe_refused": ("contacted", True),
    "malformed_probe_output": ("contacted", True),
}

# App-owned bounded policy (NOT host values): supported version floor, capacity requirements per
# profile, candidate VMID allocation pool, and candidate-plan validity window.
_MIN_PVE_MAJOR = 7
_CANDIDATE_VMID_START = 9000
_CANDIDATE_VMID_END = 9999
_PLAN_TTL = timedelta(hours=12)
_PROFILE_REQUIREMENTS: dict[str, dict[str, int]] = {
    "small_lab": {"cpu": 4, "mem_free_mb": 4096, "storage_avail_mb": 40 * 1024, "vmids": 2},
    "medium_lab": {"cpu": 8, "mem_free_mb": 8192, "storage_avail_mb": 80 * 1024, "vmids": 2},
}
_DEFAULT_ARTIFACT_MANIFEST = "secp-b4/artifact-catalog/v1"


@dataclass(frozen=True)
class DiscoveryComposition:
    """The reviewed set of injected seams for discovery. The shipped default (see
    :func:`sealed_discovery_composition`) uses a sealed probe source, so discovery refuses before
    any
    network/SSH contact. Constructed only out of band on the isolated worker with a bundle
    mounted.

    ``bundle_binding`` is present ONLY on the live controlled-integration composition; when set, the
    engine enforces the mandatory approved-worker-identity gate and the bundle-to-job authorization
    binding BEFORE any host contact. A sealed/test composition leaves it ``None`` and contacts
    nothing."""

    probe_source: HostProbeSource
    bundle_binding: BundleAnchorSource | None = None


def sealed_discovery_composition() -> DiscoveryComposition:
    """The shipped, sealed composition: the probe source refuses. Nothing is contacted."""
    return DiscoveryComposition(probe_source=SealedHostProbeSource(), bundle_binding=None)


@dataclass(frozen=True)
class DiscoveryOutcome:
    ok: bool
    reason_code: str
    plan_hash: str | None = None
    # SECP-B6 F-AUDIT: truthful, secret-free execution signals threaded into the completion audit.
    bundle_available: bool = False
    contact_state: str = "sealed"


def _approved_registrations(session: Session, org_id: object) -> list[WorkerIdentityRegistration]:
    """All approved worker-identity registrations for the org (0, 1, or ambiguous >1). Never raises
    on multiplicity — the caller decides fail-closed policy (SECP-B6 F-IDENTITY)."""
    return list(
        session.execute(
            select(WorkerIdentityRegistration).where(
                WorkerIdentityRegistration.organization_id == org_id,
                WorkerIdentityRegistration.status == WorkerIdentityStatus.approved,
            )
        )
        .scalars()
        .all()
    )


def _active_onboarding(session: Session, target_id: object) -> TargetOnboarding | None:
    return session.execute(
        select(TargetOnboarding).where(
            TargetOnboarding.execution_target_id == target_id,
            TargetOnboarding.status == OnboardingStatus.active,
        )
    ).scalar_one_or_none()


def _candidate_locators(label: str, node: str, cp_vmid: int, nt_vmid: int) -> list[ResourceLocator]:
    """Build the exact candidate locators the presence probe will read (from generated names +
    discovered node/vmids). Mirrors :func:`candidate_resource_specs`."""
    from secp_api.ownership_contract import compute_ownership_fingerprint

    fp8 = compute_ownership_fingerprint(label)[:8]
    return [
        ServiceIdentityLocator(f"secp{fp8}@pam"),
        BridgeLocator(node, f"secp{fp8}br"),
        FirewallGroupLocator(f"secp{fp8}fw"),
        GuestLocator(node, cp_vmid),
        GuestLocator(node, nt_vmid),
    ]


def _select_vmids(used: frozenset[int], count: int) -> list[int] | None:
    free = [v for v in range(_CANDIDATE_VMID_START, _CANDIDATE_VMID_END + 1) if v not in used]
    return free[:count] if len(free) >= count else None


def _select_storage(facts: InventoryFacts, required_mb: int) -> tuple[str, int] | None:
    usable = [s for s in facts.storages if s.usable and s.avail_mb >= required_mb]
    if not usable:
        return None
    best = max(usable, key=lambda s: s.avail_mb)
    return best.storage, best.avail_mb


def _assess(facts: InventoryFacts, profile: str) -> str | None:
    """Return a closed failure code if the target is ineligible, else None. Fail closed."""
    req = _PROFILE_REQUIREMENTS.get(profile)
    if req is None:
        return DiscoveryFailureCode.internal_error.value
    if facts.version_major < _MIN_PVE_MAJOR:
        return DiscoveryFailureCode.unsupported_proxmox_version.value
    if facts.is_clustered:
        return DiscoveryFailureCode.target_is_clustered.value
    if facts.node_count != 1:
        return DiscoveryFailureCode.ambiguous_node_selection.value
    if not facts.nested_available:
        return DiscoveryFailureCode.nested_virtualization_unavailable.value
    if facts.cpu_total < req["cpu"] or facts.mem_free_mb < req["mem_free_mb"]:
        return DiscoveryFailureCode.insufficient_capacity.value
    if _select_storage(facts, req["storage_avail_mb"]) is None:
        return DiscoveryFailureCode.no_storage_available.value
    return None


def _evidence_dict(
    facts: InventoryFacts,
    *,
    selected_storage: str | None,
    candidate_vmids: list[int],
    presence: dict,
) -> dict:
    return {
        "schema_version": DISCOVERY_EVIDENCE_SCHEMA_VERSION,
        "version_major": facts.version_major,
        "version_minor": facts.version_minor,
        "is_clustered": facts.is_clustered,
        "node": facts.node,
        "node_count": facts.node_count,
        "cpu_total": facts.cpu_total,
        "mem_total_mb": facts.mem_total_mb,
        "mem_free_mb": facts.mem_free_mb,
        "nested_available": facts.nested_available,
        "storages": [
            {"storage": s.storage, "avail_mb": s.avail_mb, "usable": s.usable}
            for s in facts.storages
        ],
        "used_vmid_count": len(facts.used_vmids),
        "selected_storage": selected_storage,
        "candidate_vmids": candidate_vmids,
        "candidate_presence": presence,
    }


def _fail(
    session: Session,
    enrollment: TargetDiscoveryEnrollment,
    job_status_evidence: dict | None,
    *,
    reason: str,
    facts: InventoryFacts | None,
    job,
    worker_identity_version: int,
    bundle_available: bool,
    now: datetime,
    contact_state: str = "unverifiable",
) -> DiscoveryOutcome:
    """Persist an (immutable) snapshot capturing the fail-closed outcome and mark the enrollment
    failed. The snapshot records eligibility=ineligible/unverifiable with a closed reason."""
    eligibility = (
        DiscoveryEligibility.ineligible if facts is not None else DiscoveryEligibility.unverifiable
    )
    evidence = job_status_evidence or {"schema_version": DISCOVERY_EVIDENCE_SCHEMA_VERSION}
    session.add(
        DiscoverySnapshot(
            enrollment_id=enrollment.id,
            organization_id=enrollment.organization_id,
            job_id=job.id,
            enrollment_version=job.enrollment_version,
            evidence=evidence,
            evidence_hash=compute_evidence_hash(evidence),
            capacity_snapshot_hash=_capacity_hash(facts, evidence),
            eligibility=eligibility,
            reason_code=reason,
            worker_identity_version=worker_identity_version,
            bundle_available=bundle_available,
        )
    )
    enrollment.status = TargetDiscoveryStatus.failed
    enrollment.failure_code = reason
    enrollment.revision = enrollment.revision + 1
    session.flush()
    return DiscoveryOutcome(
        False, reason, bundle_available=bundle_available, contact_state=contact_state
    )


def _refuse_pre_probe(
    session: Session,
    enrollment: TargetDiscoveryEnrollment,
    *,
    reason: str,
    contact_state: str,
) -> DiscoveryOutcome:
    """Fail closed BEFORE any host contact for a mandatory pre-probe gate (worker identity or
    bundle-to-job binding). No evidence snapshot is written — the job never matched a usable,
    authorized bundle, so there is no host observation to record (SECP-B6 F-IDENTITY / F-BIND)."""
    enrollment.status = TargetDiscoveryStatus.failed
    enrollment.failure_code = reason
    enrollment.revision = enrollment.revision + 1
    session.flush()
    return DiscoveryOutcome(False, reason, bundle_available=False, contact_state=contact_state)


def _capacity_hash(facts: InventoryFacts | None, evidence: dict) -> str:
    if facts is None:
        return compute_capacity_snapshot_hash(
            cpu_total=0, mem_total_mb=0, mem_free_mb=0, storage="", storage_avail_mb=0
        )
    return compute_capacity_snapshot_hash(
        cpu_total=facts.cpu_total,
        mem_total_mb=facts.mem_total_mb,
        mem_free_mb=facts.mem_free_mb,
        storage=str(evidence.get("selected_storage") or ""),
        storage_avail_mb=int(_selected_avail(facts, evidence)),
    )


def _selected_avail(facts: InventoryFacts, evidence: dict) -> int:
    sel = evidence.get("selected_storage")
    for s in facts.storages:
        if s.storage == sel:
            return s.avail_mb
    return 0


def run_discovery(
    session: Session,
    job,
    *,
    composition: DiscoveryComposition,
    now: datetime,
) -> DiscoveryOutcome:
    """Fail-at-first read-only discovery: reverify → probe (sealed refuses) → assess eligibility →
    presence-check candidates → persist immutable evidence + candidate plan. No mutation, ever."""
    enrollment = session.get(TargetDiscoveryEnrollment, job.enrollment_id)
    if enrollment is None:
        return DiscoveryOutcome(
            False,
            DiscoveryFailureCode.internal_error.value,
            bundle_available=False,
            contact_state="internal_error",
        )

    # ``live`` == the controlled-integration composition that can contact a host. The mandatory
    # worker-identity gate and the bundle-to-job binding gate below are enforced ONLY on this path;
    # the sealed/test compositions contact nothing, so they need neither.
    live = composition.bundle_binding is not None

    # SECP-B6 F-IDENTITY: an approved worker identity is MANDATORY before any live host contact.
    # Exactly one approved registration must exist; zero or ambiguous fails closed BEFORE probing.
    registrations = _approved_registrations(session, enrollment.organization_id)
    identity = registrations[0] if len(registrations) == 1 else None
    if live and len(registrations) != 1:
        reason = (
            DiscoveryFailureCode.worker_identity_unapproved.value
            if not registrations
            else DiscoveryFailureCode.worker_identity_ambiguous.value
        )
        return _refuse_pre_probe(
            session, enrollment, reason=reason, contact_state="identity_refused"
        )
    worker_identity_version = identity.identity_version if identity is not None else 0
    worker_registration_id = identity.id if identity is not None else None

    # Enrollment drift: the job must still match the current active enrollment version + onboarding.
    if enrollment.enrollment_version != job.enrollment_version:
        return _fail(
            session,
            enrollment,
            None,
            reason=DiscoveryFailureCode.enrollment_changed.value,
            facts=None,
            job=job,
            worker_identity_version=worker_identity_version,
            bundle_available=False,
            now=now,
            contact_state="drift",
        )
    onboarding = _active_onboarding(session, enrollment.execution_target_id)
    if onboarding is None or onboarding.id != enrollment.onboarding_id:
        return _fail(
            session,
            enrollment,
            None,
            reason=DiscoveryFailureCode.enrollment_changed.value,
            facts=None,
            job=job,
            worker_identity_version=worker_identity_version,
            bundle_available=False,
            now=now,
            contact_state="drift",
        )

    # SECP-B6 F-BIND: the mounted bundle must be authorized for THIS exact job (organization /
    # target / onboarding / enrollment + a current approved live-read authorization) BEFORE any SSH.
    # A bundle mounted for another org/target can never be used here, and no snapshot is written.
    if live:
        assert composition.bundle_binding is not None
        try:
            authorize_discovery_bundle(session, enrollment, composition.bundle_binding, now=now)
        except DiscoveryBindingRefused as exc:
            return _refuse_pre_probe(
                session, enrollment, reason=exc.reason_code, contact_state="binding_refused"
            )

    enrollment.status = TargetDiscoveryStatus.discovering
    enrollment.revision = enrollment.revision + 1
    session.flush()

    # 1. Read-only inventory probes (sealed source → fail closed, bundle unavailable).
    try:
        facts = composition.probe_source.read_inventory()
    except ProbeSourceUnavailable as exc:
        contact_state, bundle_available = _PROBE_CONTACT_STATE.get(
            exc.reason_code, ("contacted", True)
        )
        return _fail(
            session,
            enrollment,
            None,
            reason=exc.reason_code,
            facts=None,
            job=job,
            worker_identity_version=worker_identity_version,
            bundle_available=bundle_available,
            now=now,
            contact_state=contact_state,
        )

    # 2. Eligibility (fail closed on any unsupported/unsafe condition).
    ineligible = _assess(facts, enrollment.resource_profile)
    req = _PROFILE_REQUIREMENTS[enrollment.resource_profile]
    if ineligible is not None:
        evidence = _evidence_dict(facts, selected_storage=None, candidate_vmids=[], presence={})
        return _fail(
            session,
            enrollment,
            evidence,
            reason=ineligible,
            facts=facts,
            job=job,
            worker_identity_version=worker_identity_version,
            bundle_available=True,
            now=now,
            contact_state="contacted",
        )

    # 3. Allocate candidate VMIDs + storage from the observed inventory.
    storage_sel = _select_storage(facts, req["storage_avail_mb"])
    vmids = _select_vmids(facts.used_vmids, req["vmids"])
    if storage_sel is None:
        evidence = _evidence_dict(facts, selected_storage=None, candidate_vmids=[], presence={})
        return _fail(
            session,
            enrollment,
            evidence,
            reason=DiscoveryFailureCode.no_storage_available.value,
            facts=facts,
            job=job,
            worker_identity_version=worker_identity_version,
            bundle_available=True,
            now=now,
            contact_state="contacted",
        )
    if vmids is None:
        evidence = _evidence_dict(
            facts, selected_storage=storage_sel[0], candidate_vmids=[], presence={}
        )
        return _fail(
            session,
            enrollment,
            evidence,
            reason=DiscoveryFailureCode.candidate_vmid_unavailable.value,
            facts=facts,
            job=job,
            worker_identity_version=worker_identity_version,
            bundle_available=True,
            now=now,
            contact_state="contacted",
        )
    cp_vmid, nt_vmid = vmids[0], vmids[1]
    storage, storage_avail = storage_sel

    # 4. Presence-probe the EXACT candidate locators; a present-and-not-ours object refuses.
    locators = _candidate_locators(enrollment.ownership_label, facts.node, cp_vmid, nt_vmid)
    try:
        presences = composition.probe_source.probe_candidate_presence(tuple(locators))
    except ProbeSourceUnavailable as exc:
        contact_state, bundle_available = _PROBE_CONTACT_STATE.get(
            exc.reason_code, ("contacted", True)
        )
        return _fail(
            session,
            enrollment,
            None,
            reason=exc.reason_code,
            facts=facts,
            job=job,
            worker_identity_version=worker_identity_version,
            bundle_available=bundle_available,
            now=now,
            contact_state=contact_state,
        )
    presence_summary: dict[str, dict] = {}
    specs = candidate_resource_specs(
        ownership_label=enrollment.ownership_label,
        node=facts.node,
        control_plane_vmid=cp_vmid,
        nested_target_vmid=nt_vmid,
    )
    for locator, spec in zip(locators, specs, strict=True):
        seen = presences.get(locator.observe_key())
        present = bool(seen and seen.present)
        owned = bool(seen and seen.present and seen.owner_marker == spec["ownership_marker"])
        presence_summary[spec["kind"]] = {"present": present, "owned": owned}
        if present and not owned:
            evidence = _evidence_dict(
                facts,
                selected_storage=storage,
                candidate_vmids=[cp_vmid, nt_vmid],
                presence=presence_summary,
            )
            reason = (
                DiscoveryFailureCode.foreign_ownership_conflict.value
                if seen and seen.owner_marker
                else DiscoveryFailureCode.candidate_locator_occupied.value
            )
            return _fail(
                session,
                enrollment,
                evidence,
                reason=reason,
                facts=facts,
                job=job,
                worker_identity_version=worker_identity_version,
                bundle_available=True,
                now=now,
                contact_state="contacted",
            )
        # A candidate VMID observed as present-but-ours is fine (idempotent re-discovery); a foreign
        # VMID would have been caught above. Also guard the raw VMID collision explicitly.
        marker = compute_resource_marker(enrollment.ownership_label, spec["kind"], 0)
        assert marker == spec["ownership_marker"]  # contract self-check

    # SECP-B6 F-IDENTITY: re-verify the approved worker identity did not change DURING probing.
    # A revocation or identity-version bump mid-discovery must not mint an approvable plan.
    if live:
        current = _approved_registrations(session, enrollment.organization_id)
        if (
            len(current) != 1
            or current[0].id != worker_registration_id
            or current[0].identity_version != worker_identity_version
        ):
            evidence = _evidence_dict(
                facts,
                selected_storage=storage,
                candidate_vmids=[cp_vmid, nt_vmid],
                presence=presence_summary,
            )
            return _fail(
                session,
                enrollment,
                evidence,
                reason=DiscoveryFailureCode.worker_identity_changed.value,
                facts=facts,
                job=job,
                worker_identity_version=worker_identity_version,
                bundle_available=True,
                now=now,
                contact_state="contacted",
            )

    # 5. Persist the immutable evidence snapshot + the content-addressed candidate plan.
    evidence = _evidence_dict(
        facts,
        selected_storage=storage,
        candidate_vmids=[cp_vmid, nt_vmid],
        presence=presence_summary,
    )
    evidence_hash = compute_evidence_hash(evidence)
    capacity_hash = compute_capacity_snapshot_hash(
        cpu_total=facts.cpu_total,
        mem_total_mb=facts.mem_total_mb,
        mem_free_mb=facts.mem_free_mb,
        storage=storage,
        storage_avail_mb=storage_avail,
    )
    snapshot = DiscoverySnapshot(
        enrollment_id=enrollment.id,
        organization_id=enrollment.organization_id,
        job_id=job.id,
        enrollment_version=job.enrollment_version,
        evidence=evidence,
        evidence_hash=evidence_hash,
        capacity_snapshot_hash=capacity_hash,
        eligibility=DiscoveryEligibility.eligible,
        reason_code=None,
        worker_identity_version=worker_identity_version,
        bundle_available=True,
    )
    session.add(snapshot)
    session.flush()

    expires_at = now + _PLAN_TTL
    plan_document = build_candidate_plan_document(
        ownership_label=enrollment.ownership_label,
        organization_id=enrollment.organization_id,
        enrollment_id=enrollment.id,
        worker_registration_id=worker_registration_id,
        resource_profile=enrollment.resource_profile,
        node=facts.node,
        storage=storage,
        control_plane_vmid=cp_vmid,
        nested_target_vmid=nt_vmid,
        capacity_snapshot_hash=capacity_hash,
        evidence_hash=evidence_hash,
        worker_identity_version=worker_identity_version,
        artifact_manifest_id=f"{_DEFAULT_ARTIFACT_MANIFEST}/{enrollment.resource_profile}",
        enrollment_version=enrollment.enrollment_version,
        expires_at=expires_at,
    )
    plan_hash = discovery_candidate_plan_hash(plan_document)
    session.add(
        DiscoveryCandidatePlan(
            enrollment_id=enrollment.id,
            organization_id=enrollment.organization_id,
            snapshot_id=snapshot.id,
            plan_version=1,
            plan_hash=plan_hash,
            plan_document=plan_document,
            node=facts.node,
            storage=storage,
            ownership_tag=plan_document["ownership_tag"],
            capacity_snapshot_hash=capacity_hash,
            evidence_hash=evidence_hash,
            worker_identity_version=worker_identity_version,
            enrollment_version=enrollment.enrollment_version,
            expires_at=expires_at,
            status=DiscoveryCandidatePlanStatus.draft,
        )
    )
    enrollment.status = TargetDiscoveryStatus.plan_ready
    enrollment.decision_code = DiscoveryDecisionCode.pending
    enrollment.active_plan_hash = plan_hash
    enrollment.failure_code = None
    enrollment.revision = enrollment.revision + 1
    session.flush()
    return DiscoveryOutcome(
        True, "plan_ready", plan_hash, bundle_available=True, contact_state="contacted"
    )
