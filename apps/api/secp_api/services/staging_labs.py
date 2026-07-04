"""Declarative disposable staging-lab lifecycle services (SECP-002B-1B-9).

Control-plane only and fake-only. The API owns the desired state, immutable plan, and approval,
and it *enqueues durable work items* for simulation/teardown — it NEVER executes them. This
module NEVER imports worker/provider/transport/secret/subprocess code, never lazy-imports worker
orchestration, never contacts infrastructure, and never creates a real target or a
:class:`LiveReadAuthorization`.

Only a worker (see :mod:`secp_worker.staging_lab.consumer`) may claim a committed work item and
write simulated observations or completion state. A staging-lab approval is permission to enqueue
*fake simulation only*; it is separate from, and never a substitute for, the SECP-002B-1B-6
live-read authorization required for any future real read-only collection.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    Permission,
    StagingBootstrapArtifactProfile,
    StagingLabDecisionCode,
    StagingLabProfile,
    StagingLabStatus,
    StagingNetworkIntent,
    StagingResourceClass,
    StagingRollbackPolicy,
    StagingSubstrateEligibilityStatus,
    StagingWorkOperation,
    StagingWorkStatus,
    TargetStatus,
)
from secp_api.errors import DomainError, NotFoundError, ValidationFailedError
from secp_api.models import (
    ExecutionTarget,
    StagingLab,
    StagingLabWorkItem,
    StagingSubstrateEligibility,
)
from secp_api.staging_lab import (
    StagingLabPlanError,
    StagingLabSpec,
    compile_staging_plan,
    staging_plan_hash,
)

# Provider/plugin the staging substrate must be.
STAGING_SUBSTRATE_PLUGIN = "proxmox"

# A strict allowlist for the ONLY caller-supplied string (optional logical name). Everything
# else is a controlled enum, a UUID, or a server-generated slug. Kebab-case, bounded length.
_LOGICAL_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{1,38}[a-z0-9])$")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def assert_safe_logical_name(value: str) -> str:
    """Strict allowlist validation for the optional caller-supplied logical name.

    Rejects anything that is not a short kebab-case slug — which structurally excludes URLs,
    hosts, IPs, paths, ports, bridge/VNet/VLAN/VMID/storage identifiers, certificates, hashes,
    secrets, credentials, tokens, and env/vault references.
    """
    candidate = (value or "").strip()
    # Strict allowlist — no normalization. Uppercase, spaces, dots, slashes, colons, ports, '@',
    # '=', '://', and over-length inputs all fail closed here. The error NEVER echoes the rejected
    # input; it returns only a generic, safe code.
    if not _LOGICAL_NAME_RE.fullmatch(candidate):
        raise ValidationFailedError(
            "invalid_staging_lab_input", errors=["invalid_staging_lab_input"]
        )
    return candidate


def operation_fingerprint(
    lab_id: uuid.UUID, operation: StagingWorkOperation, plan_hash: str, plan_version: int
) -> str:
    """Deterministic, canonical server-generated work identity.

    A SHA-256 over the canonical immutable tuple ``(lab_id, operation, plan_hash, plan_version)``.
    It contains no user-provided text, target display text, or infrastructure value, and is stable
    across processes so an identical operation on an identical plan resolves to the same key.
    """
    canonical = f"{lab_id}|{operation.value}|{plan_hash}|{plan_version}"
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ownership_label(lab_id: uuid.UUID) -> str:
    """Server-generated, immutable ownership label derived only from the lab identity."""
    return f"secp-lab-{lab_id.hex[:12]}"


def _display_name(lab_id: uuid.UUID, logical_name: str | None) -> str:
    if logical_name:
        return f"staging-lab-{logical_name}"
    return f"staging-lab-{lab_id.hex[:8]}"


def _safe_audit(lab: StagingLab, **extra: object) -> dict:
    payload: dict[str, object] = {
        "execution_target_id": str(lab.execution_target_id),
        "ownership_label": lab.ownership_label,
        "status": lab.status.value,
        "plan_version": lab.plan_version,
        "plan_hash": lab.plan_hash,
        "revision": lab.revision,
    }
    payload.update(extra)
    return payload


def _get_lab(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    lab = session.get(StagingLab, lab_id)
    if lab is None:
        raise NotFoundError(f"staging lab {lab_id} not found")
    actor.require_org(lab.organization_id)
    return lab


def _cas_transition(
    session: Session,
    lab: StagingLab,
    *,
    expected_status: StagingLabStatus,
    new_status: StagingLabStatus,
    extra: dict | None = None,
) -> bool:
    """Compare-and-swap lab lifecycle at the DB layer.

    Conditionally updates the row only when (status, revision) still match what this caller
    read, bumping ``revision``. Returns True on success; on a lost race the UPDATE affects zero
    rows and this returns False (fail-closed). Refreshes the in-session object on success.
    """
    values: dict = {"status": new_status, "revision": lab.revision + 1}
    if extra:
        values.update(extra)
    result = session.execute(
        update(StagingLab)
        .where(
            StagingLab.id == lab.id,
            StagingLab.status == expected_status,
            StagingLab.revision == lab.revision,
        )
        .values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        return False
    session.refresh(lab)
    return True


# --- Substrate eligibility (target-admin only; NO lab-creator endpoint) -------


def grant_substrate_eligibility(
    session: Session, actor: Principal, *, execution_target_id: uuid.UUID
) -> StagingSubstrateEligibility:
    """Mark a Proxmox target eligible as a disposable staging substrate.

    Requires ``staging_substrate:manage`` (a target-admin capability, deliberately distinct from
    ``staging_lab:manage``). No API router exposes this — a normal lab creator cannot grant it.
    """
    actor.require(Permission.staging_substrate_manage)
    target = session.get(ExecutionTarget, execution_target_id)
    if target is None:
        raise NotFoundError(f"execution target {execution_target_id} not found")
    actor.require_org(target.organization_id)
    if target.plugin_name != STAGING_SUBSTRATE_PLUGIN:
        raise DomainError("only proxmox targets may be staging substrates")
    record = StagingSubstrateEligibility(
        organization_id=target.organization_id,
        execution_target_id=target.id,
        plugin_type=STAGING_SUBSTRATE_PLUGIN,
        allowed_profile=StagingLabProfile.nested_proxmox,
        status=StagingSubstrateEligibilityStatus.active,
        issued_by=actor.user_id,
        issued_at=_utcnow(),
    )
    session.add(record)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DomainError("target already has active staging eligibility") from exc
    audit.record(
        session,
        action=AuditAction.staging_substrate_eligibility_granted,
        resource_type="staging_substrate_eligibility",
        resource_id=record.id,
        organization_id=record.organization_id,
        actor=str(actor.user_id),
        data={"execution_target_id": str(target.id), "plugin_type": STAGING_SUBSTRATE_PLUGIN},
    )
    return record


def _active_eligibility(
    session: Session, target_id: uuid.UUID
) -> StagingSubstrateEligibility | None:
    return (
        session.execute(
            select(StagingSubstrateEligibility).where(
                StagingSubstrateEligibility.execution_target_id == target_id,
                StagingSubstrateEligibility.status == StagingSubstrateEligibilityStatus.active,
            )
        )
        .scalars()
        .first()
    )


def _substrate_has_active_onboarding(session: Session, target: ExecutionTarget) -> bool:
    from secp_api.services.onboarding import active_onboarding_for_target

    if target.status != TargetStatus.active:
        return False
    try:
        return active_onboarding_for_target(session, target.id) is not None
    except DomainError:
        return False


def _substrate_is_eligible(session: Session, target: ExecutionTarget) -> bool:
    elig = _active_eligibility(session, target.id)
    return (
        elig is not None
        and target.plugin_name == STAGING_SUBSTRATE_PLUGIN
        and elig.allowed_profile == StagingLabProfile.nested_proxmox
    )


def list_eligible_substrates(session: Session, actor: Principal) -> list[dict]:
    """Safe substrate list for the UI: only same-org, active, Proxmox, eligible, onboarded targets.

    Returns a server-generated logical alias per target — never raw target display text.
    """
    rows = (
        session.execute(
            select(ExecutionTarget)
            .join(
                StagingSubstrateEligibility,
                StagingSubstrateEligibility.execution_target_id == ExecutionTarget.id,
            )
            .where(
                ExecutionTarget.organization_id == actor.organization_id,
                ExecutionTarget.status == TargetStatus.active,
                ExecutionTarget.plugin_name == STAGING_SUBSTRATE_PLUGIN,
                StagingSubstrateEligibility.status == StagingSubstrateEligibilityStatus.active,
            )
            .order_by(ExecutionTarget.created_at)
        )
        .scalars()
        .all()
    )
    out: list[dict] = []
    for target in rows:
        if _substrate_has_active_onboarding(session, target):
            out.append({"id": target.id, "alias": f"substrate-{target.id.hex[:10]}"})
    return out


# --- Lab lifecycle (API: create/plan/submit/approve; queue only) --------------


def create_staging_lab(
    session: Session,
    actor: Principal,
    *,
    execution_target_id: uuid.UUID,
    resource_class: StagingResourceClass = StagingResourceClass.small_lab,
    rollback_policy: StagingRollbackPolicy = StagingRollbackPolicy.revert_to_known_clean_checkpoint,
    bootstrap_artifact_profile: StagingBootstrapArtifactProfile = (
        StagingBootstrapArtifactProfile.nested_proxmox_offline_base
    ),
    logical_name: str | None = None,
) -> StagingLab:
    """Create a draft staging lab bound to an eligible substrate. All labels are server-owned."""
    actor.require(Permission.staging_lab_manage)
    target = session.get(ExecutionTarget, execution_target_id)
    if target is None:
        raise NotFoundError(f"execution target {execution_target_id} not found")
    actor.require_org(target.organization_id)
    safe_name = assert_safe_logical_name(logical_name) if logical_name else None
    if not _substrate_is_eligible(session, target):
        raise DomainError("execution target is not an eligible staging substrate")

    # Generate the immutable id up front so the server-owned labels are derived from it and set
    # once at construction — no caller label is ever accepted, and no post-insert relabeling.
    lab_id = uuid.uuid4()
    lab = StagingLab(
        id=lab_id,
        organization_id=target.organization_id,
        execution_target_id=target.id,
        display_name=_display_name(lab_id, safe_name),
        ownership_label=_ownership_label(lab_id),
        profile=StagingLabProfile.nested_proxmox,
        network_intent=StagingNetworkIntent.host_only_no_uplink,
        resource_class=resource_class,
        rollback_policy=rollback_policy,
        bootstrap_artifact_profile=bootstrap_artifact_profile,
        status=StagingLabStatus.draft,
        revision=0,
        plan_version=0,
        plan_hash="",
        created_by=actor.user_id,
    )
    session.add(lab)
    session.flush()
    audit.record(
        session,
        action=AuditAction.staging_lab_created,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    return lab


def generate_plan(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Compile the immutable logical plan for a draft lab (draft -> planned)."""
    actor.require(Permission.staging_lab_manage)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.draft:
        raise DomainError(f"staging lab is '{lab.status.value}'; only 'draft' can be planned")
    target = session.get(ExecutionTarget, lab.execution_target_id)
    if target is None:
        raise NotFoundError("execution target no longer exists")

    spec = StagingLabSpec(
        ownership_label=lab.ownership_label,
        profile=lab.profile,
        network_intent=lab.network_intent,
        resource_class=lab.resource_class,
        rollback_policy=lab.rollback_policy,
        bootstrap_artifact_profile=lab.bootstrap_artifact_profile,
        substrate_approved=_substrate_has_active_onboarding(session, target),
        substrate_eligible=_substrate_is_eligible(session, target),
    )
    try:
        plan = compile_staging_plan(spec)
    except StagingLabPlanError as exc:
        audit.record(
            session,
            action=AuditAction.staging_lab_refused,
            resource_type="staging_lab",
            resource_id=lab.id,
            organization_id=lab.organization_id,
            actor=str(actor.user_id),
            outcome="denied",
            data=_safe_audit(lab, reason_code=exc.reason_code),
        )
        raise DomainError(f"staging-lab plan refused: {exc.reason_code}") from exc

    # Write the immutable plan atomically inside the compare-and-swap transition so a stale
    # writer cannot land a plan against a lab that changed underneath it.
    if not _cas_transition(
        session,
        lab,
        expected_status=StagingLabStatus.draft,
        new_status=StagingLabStatus.planned,
        extra={
            "desired_state": plan,
            "plan_hash": staging_plan_hash(plan),
            "plan_version": 1,
        },
    ):
        raise DomainError("staging lab changed concurrently; retry planning")
    audit.record(
        session,
        action=AuditAction.staging_lab_planned,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    return lab


def submit_for_approval(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Move a planned lab into the approval queue (planned -> awaiting_approval)."""
    actor.require(Permission.staging_lab_manage)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.planned:
        raise DomainError(f"staging lab is '{lab.status.value}'; only 'planned' can be submitted")
    if not _cas_transition(
        session,
        lab,
        expected_status=StagingLabStatus.planned,
        new_status=StagingLabStatus.awaiting_approval,
    ):
        raise DomainError("staging lab changed concurrently; retry submission")
    audit.record(
        session,
        action=AuditAction.staging_lab_submitted,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    return lab


def approve_staging_lab(
    session: Session,
    actor: Principal,
    lab_id: uuid.UUID,
    *,
    expected_plan_hash: str,
) -> StagingLab:
    """Approve the exact reviewed plan (awaiting_approval -> approved), concurrency-safe.

    Binds lab id, the immutable plan hash/version, the substrate id, lifecycle state, approver,
    and time via a DB compare-and-swap on (status, revision): exactly one competing approval for
    the same plan can win; the loser fails closed. Records the closed decision code ``approved``
    (no free text). This is NOT a live-read authorization.
    """
    actor.require(Permission.staging_lab_approve)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.awaiting_approval:
        raise DomainError(
            f"staging lab is '{lab.status.value}'; only 'awaiting_approval' can be approved"
        )
    if not lab.plan_hash or lab.desired_state is None:
        raise DomainError("staging lab has no generated plan to approve")
    if staging_plan_hash(lab.desired_state) != lab.plan_hash:
        raise DomainError("staging-lab plan integrity check failed (hash mismatch)")
    if (expected_plan_hash or "").strip() != lab.plan_hash:
        raise DomainError(
            "the plan changed since review; re-review the current plan hash before approving"
        )
    if not _cas_transition(
        session,
        lab,
        expected_status=StagingLabStatus.awaiting_approval,
        new_status=StagingLabStatus.approved,
        extra={
            "approved_by": actor.user_id,
            "approved_at": _utcnow(),
            "approved_plan_hash": lab.plan_hash,
            "approved_plan_version": lab.plan_version,
            "decision_code": StagingLabDecisionCode.approved,
        },
    ):
        raise DomainError("a competing approval already changed this lab; approval refused")
    audit.record(
        session,
        action=AuditAction.staging_lab_approved,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(
            lab,
            approved_plan_hash=lab.approved_plan_hash,
            approved_plan_version=lab.approved_plan_version,
            authorizes="fake_simulation_only",
            live_read_authorization=False,
        ),
    )
    return lab


def reject_staging_lab(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Reject a lab awaiting approval. Records the closed decision code ``rejected_policy``."""
    actor.require(Permission.staging_lab_approve)
    lab = _get_lab(session, actor, lab_id)
    if lab.status != StagingLabStatus.awaiting_approval:
        raise DomainError(
            f"staging lab is '{lab.status.value}'; only 'awaiting_approval' can be rejected"
        )
    if not _cas_transition(
        session,
        lab,
        expected_status=StagingLabStatus.awaiting_approval,
        new_status=StagingLabStatus.failed,
        extra={"decision_code": StagingLabDecisionCode.rejected_policy},
    ):
        raise DomainError("staging lab changed concurrently; rejection refused")
    audit.record(
        session,
        action=AuditAction.staging_lab_rejected,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab),
    )
    return lab


# --- Queueing durable work (API enqueues; worker executes) --------------------


def _existing_by_fingerprint(session: Session, fingerprint: str) -> StagingLabWorkItem | None:
    return (
        session.execute(
            select(StagingLabWorkItem).where(
                StagingLabWorkItem.operation_fingerprint == fingerprint
            )
        )
        .scalars()
        .first()
    )


def _enqueue_work(
    session: Session,
    lab: StagingLab,
    *,
    operation: StagingWorkOperation,
    fingerprint: str,
) -> StagingLabWorkItem:
    item = StagingLabWorkItem(
        organization_id=lab.organization_id,
        staging_lab_id=lab.id,
        operation_kind=operation,
        plan_hash=lab.plan_hash,
        plan_version=lab.plan_version,
        operation_fingerprint=fingerprint,
        status=StagingWorkStatus.queued,
        revision=0,
        created_by=lab.created_by,
    )
    session.add(item)
    try:
        session.flush()
    except IntegrityError as exc:
        # The fingerprint/scope unique constraint or the partial-unique active index fired:
        # an item for this exact (lab, operation, plan) or another active item already exists.
        session.rollback()
        raise DomainError("an active work item already exists for this lab/operation") from exc
    return item


def _queue_operation(
    session: Session,
    actor: Principal,
    lab_id: uuid.UUID,
    *,
    operation: StagingWorkOperation,
    allowed_statuses: tuple[StagingLabStatus, ...],
    queued_status: StagingLabStatus,
    audit_action: AuditAction,
) -> StagingLab:
    """Shared enqueue path. The API only commits queued work — it never executes it.

    Idempotency is by a server-generated fingerprint over (lab, operation, plan_hash,
    plan_version): a retry for the identical operation and plan resolves to the original work
    item; a different operation/plan/stale-plan/lifecycle-conflict fails closed.
    """
    actor.require(Permission.staging_lab_manage)
    lab = _get_lab(session, actor, lab_id)
    if not lab.plan_hash:
        raise DomainError(f"staging lab is '{lab.status.value}'; it has no approved plan to queue")
    fingerprint = operation_fingerprint(lab.id, operation, lab.plan_hash, lab.plan_version)
    existing = _existing_by_fingerprint(session, fingerprint)
    if existing is not None:
        # Idempotent replay of the identical operation+plan: return the original, unchanged.
        return lab
    if lab.status not in allowed_statuses:
        raise DomainError(
            f"staging lab is '{lab.status.value}'; it cannot be queued for {operation.value}"
        )
    if lab.approved_plan_hash != lab.plan_hash:
        raise DomainError("approved plan hash does not match the current plan; re-approve")
    item = _enqueue_work(session, lab, operation=operation, fingerprint=fingerprint)
    if not _cas_transition(session, lab, expected_status=lab.status, new_status=queued_status):
        raise DomainError("staging lab changed concurrently; work not queued")
    audit.record(
        session,
        action=audit_action,
        resource_type="staging_lab",
        resource_id=lab.id,
        organization_id=lab.organization_id,
        actor=str(actor.user_id),
        data=_safe_audit(lab, work_item_id=str(item.id), simulation_only=True),
    )
    return lab


def queue_simulation(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Enqueue a durable simulate_provision work item (approved/simulated_ready -> queued)."""
    return _queue_operation(
        session,
        actor,
        lab_id,
        operation=StagingWorkOperation.simulate_provision,
        allowed_statuses=(StagingLabStatus.approved, StagingLabStatus.simulated_ready),
        queued_status=StagingLabStatus.simulation_queued,
        audit_action=AuditAction.staging_lab_simulation_queued,
    )


def queue_teardown(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    """Enqueue a durable simulate_teardown work item (-> teardown_queued). Nothing real exists."""
    return _queue_operation(
        session,
        actor,
        lab_id,
        operation=StagingWorkOperation.simulate_teardown,
        allowed_statuses=(StagingLabStatus.simulated_ready, StagingLabStatus.approved),
        queued_status=StagingLabStatus.teardown_queued,
        audit_action=AuditAction.staging_lab_teardown_queued,
    )


# --- Reads --------------------------------------------------------------------


def get_staging_lab(session: Session, actor: Principal, lab_id: uuid.UUID) -> StagingLab:
    return _get_lab(session, actor, lab_id)


def list_staging_labs(session: Session, actor: Principal) -> list[StagingLab]:
    return list(
        session.execute(
            select(StagingLab)
            .where(StagingLab.organization_id == actor.organization_id)
            .order_by(StagingLab.created_at.desc())
        )
        .scalars()
        .all()
    )


def list_work_items(
    session: Session, actor: Principal, lab_id: uuid.UUID
) -> list[StagingLabWorkItem]:
    lab = _get_lab(session, actor, lab_id)
    return list(
        session.execute(
            select(StagingLabWorkItem)
            .where(StagingLabWorkItem.staging_lab_id == lab.id)
            .order_by(StagingLabWorkItem.created_at)
        )
        .scalars()
        .all()
    )
