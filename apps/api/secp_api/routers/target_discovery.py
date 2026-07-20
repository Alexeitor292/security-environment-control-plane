"""Worker-owned read-only target-discovery routes (SECP-B5 §4, control plane only).

The API creates a discovery enrollment desired state and ENQUEUES a durable read-only discovery job
—
it NEVER runs a probe, contacts a host, or imports worker/SSH/Proxmox/subprocess code. It exposes
the
safe capability/eligibility outcome, the discovery-derived candidate plan (safe categories + node/
storage labels + generated ownership-safe identifiers), and drives the exact-plan approval. It
accepts
NO SSH material, Proxmox endpoint/token, raw output, arbitrary node/storage/VMID entry, free-form
command, or provider option. Live deployment apply of any plan remains sealed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import current_principal, db_session
from secp_api.schemas_target_discovery import (
    CandidatePlanOut,
    CandidatePlanResourceOut,
    DiscoveryApprove,
    DiscoveryBootstrapAvailabilityOut,
    DiscoveryEvidenceOut,
    DiscoveryRequest,
    EnrollmentOut,
    SealedApplyNoticeOut,
)
from secp_api.services import target_discovery as svc

router = APIRouter(prefix="/api/v1", tags=["target-discovery"])

# Every control here queues durable read-only work only. No host is contacted, and live apply is
# sealed: the discovery-derived plan is not executable in this PR.
READ_ONLY_NOTICE = "Read-only discovery. Live deployment remains sealed pending integration."


@router.post("/target-discovery", response_model=EnrollmentOut, status_code=201)
def request_discovery(
    body: DiscoveryRequest,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentOut:
    row = svc.request_discovery(
        session,
        principal,
        execution_target_id=body.execution_target_id,
        resource_profile=body.resource_profile,
        logical_name=body.logical_name,
    )
    return EnrollmentOut.model_validate(row)


@router.get("/target-discovery", response_model=list[EnrollmentOut])
def list_enrollments(
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> list[EnrollmentOut]:
    return [EnrollmentOut.model_validate(r) for r in svc.list_enrollments(session, principal)]


@router.get("/target-discovery/{enrollment_id}", response_model=EnrollmentOut)
def get_enrollment(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentOut:
    return EnrollmentOut.model_validate(svc.get_enrollment(session, principal, enrollment_id))


@router.get("/target-discovery/{enrollment_id}/evidence", response_model=DiscoveryEvidenceOut)
def get_evidence(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DiscoveryEvidenceOut:
    """The safe capability/eligibility outcome from the latest immutable discovery snapshot."""
    snap = svc.get_latest_snapshot(session, principal, enrollment_id)
    if snap is None:
        # No snapshot yet (job queued/running) — report unverifiable with an empty safe outcome.
        return DiscoveryEvidenceOut(
            eligibility="unverifiable",
            reason_code=None,
            version_major=None,
            version_minor=None,
            is_clustered=None,
            node=None,
            node_count=None,
            cpu_total=None,
            mem_total_mb=None,
            mem_free_mb=None,
            nested_available=None,
            selected_storage=None,
            storage_count=0,
            candidate_vmids=[],
            evidence_hash="",
            bundle_available=False,
            contact_state="unverifiable",
            created_at=datetime.now(UTC),
        )
    ev = snap.evidence if isinstance(snap.evidence, dict) else {}
    return DiscoveryEvidenceOut(
        eligibility=snap.eligibility.value
        if hasattr(snap.eligibility, "value")
        else str(snap.eligibility),
        reason_code=snap.reason_code,
        version_major=ev.get("version_major"),
        version_minor=ev.get("version_minor"),
        is_clustered=ev.get("is_clustered"),
        node=ev.get("node"),
        node_count=ev.get("node_count"),
        cpu_total=ev.get("cpu_total"),
        mem_total_mb=ev.get("mem_total_mb"),
        mem_free_mb=ev.get("mem_free_mb"),
        nested_available=ev.get("nested_available"),
        selected_storage=ev.get("selected_storage"),
        storage_count=len(ev.get("storages", []) or []),
        candidate_vmids=list(ev.get("candidate_vmids", []) or []),
        evidence_hash=snap.evidence_hash,
        bundle_available=bool(snap.bundle_available),
        contact_state=(
            snap.contact_state.value
            if hasattr(snap.contact_state, "value")
            else str(snap.contact_state)
        ),
        created_at=snap.created_at,
    )


@router.get("/target-discovery/{enrollment_id}/candidate-plan", response_model=CandidatePlanOut)
def get_candidate_plan(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> CandidatePlanOut:
    plan = svc.get_active_candidate_plan(session, principal, enrollment_id)
    doc = plan.plan_document if isinstance(plan.plan_document, dict) else {}
    resources = [
        CandidatePlanResourceOut(
            kind=str(r.get("kind", "")),
            resource_ref=str(r.get("resource_ref", "")),
            ownership_marker=str(r.get("ownership_marker", "")),
        )
        for r in doc.get("resources", [])
    ]
    return CandidatePlanOut(
        plan_version=plan.plan_version,
        plan_hash=plan.plan_hash,
        ownership_tag=plan.ownership_tag,
        resource_profile=str(doc.get("resource_profile", "")),
        node=plan.node,
        storage=plan.storage,
        capacity_snapshot_hash=plan.capacity_snapshot_hash,
        evidence_hash=plan.evidence_hash,
        worker_identity_version=plan.worker_identity_version,
        enrollment_version=plan.enrollment_version,
        expires_at=plan.expires_at,
        executable=bool(doc.get("executable", False)),
        status=plan.status.value if hasattr(plan.status, "value") else str(plan.status),
        resources=resources,
    )


@router.get(
    "/target-discovery/{enrollment_id}/bootstrap-availability",
    response_model=DiscoveryBootstrapAvailabilityOut,
)
def get_bootstrap_availability(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> DiscoveryBootstrapAvailabilityOut:
    """A SAFE boolean + closed reason only. The worker-local read-only SSH authority is
    worker-mounted
    and the API cannot read it, so it is always reported unavailable here (never its location)."""
    svc.get_enrollment(session, principal, enrollment_id)  # authorize + 404
    return DiscoveryBootstrapAvailabilityOut()


@router.get("/target-discovery/{enrollment_id}/apply-status", response_model=SealedApplyNoticeOut)
def get_apply_status(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> SealedApplyNoticeOut:
    svc.get_enrollment(session, principal, enrollment_id)  # authorize + 404
    return SealedApplyNoticeOut()


@router.post("/target-discovery/{enrollment_id}/rerun", response_model=EnrollmentOut)
def rerun_discovery(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentOut:
    return EnrollmentOut.model_validate(svc.rerun_discovery(session, principal, enrollment_id))


@router.post("/target-discovery/{enrollment_id}/approve", response_model=EnrollmentOut)
def approve_candidate_plan(
    enrollment_id: uuid.UUID,
    body: DiscoveryApprove,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentOut:
    """Approve the EXACT candidate plan. Grants NO execution — live apply remains sealed."""
    return EnrollmentOut.model_validate(
        svc.approve_candidate_plan(
            session, principal, enrollment_id, expected_plan_hash=body.expected_plan_hash
        )
    )


@router.post("/target-discovery/{enrollment_id}/reject", response_model=EnrollmentOut)
def reject_candidate_plan(
    enrollment_id: uuid.UUID,
    session: Session = Depends(db_session),
    principal: Principal = Depends(current_principal),
) -> EnrollmentOut:
    return EnrollmentOut.model_validate(
        svc.reject_candidate_plan(session, principal, enrollment_id)
    )
