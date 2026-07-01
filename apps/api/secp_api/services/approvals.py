"""Provisioning change-set approval services (SECP-002B-1A, ADR-013).

A durable, auditable human approval of an *exact* dry-run change-set hash. Apply and
destroy on the real OpenTofu path are permitted only when a freshly regenerated dry run
reproduces the approved hash AND every binding still matches.

Control-plane only: this module records approvals and applies the approve/reject/consume
decisions. It NEVER imports a runner, process executor, adapter, OpenTofu, or
process-execution code. The worker produces change-set hashes and calls ``record_change_set`` /
``find_approved_change_set`` / ``mark_consumed``; humans call ``approve_change_set``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from secp_scenario_schema import content_hash
from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import (
    AuditAction,
    ChangeSetApprovalStatus,
    Permission,
    ProvisioningOperationKind,
)
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import (
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    ToolchainProfile,
)

# Only these operation kinds can be authorized by an approval.
_AUTHORIZABLE = (ProvisioningOperationKind.apply, ProvisioningOperationKind.destroy)


def reservations_hash(manifest: ProvisioningManifest) -> str:
    """Canonical SHA-256 over the manifest's finalized reservation set (secret-free)."""
    reservations = sorted(
        ((r["team_ref"], r["cidr"]) for r in manifest.content.get("reservations", [])),
    )
    return content_hash({"reservations": reservations})


def record_change_set(
    session: Session,
    manifest: ProvisioningManifest,
    toolchain_profile: ToolchainProfile,
    *,
    authorizes_kind: ProvisioningOperationKind,
    change_set_hash: str,
    rendered_workspace_hash: str,
    summary: dict,
    created_by: uuid.UUID | None = None,
) -> ProvisioningChangeSetApproval:
    """Idempotently record a pending change-set approval (worker-driven).

    Keyed on (manifest, authorizes_kind, change_set_hash): a deterministic re-run
    returns the existing row; a *different* hash (drift) creates a new pending row so a
    previously approved hash can never authorize a changed plan.
    """
    if authorizes_kind not in _AUTHORIZABLE:
        raise DomainError(f"change set cannot authorize kind '{authorizes_kind.value}'")

    existing = (
        session.execute(
            select(ProvisioningChangeSetApproval).where(
                ProvisioningChangeSetApproval.manifest_id == manifest.id,
                ProvisioningChangeSetApproval.authorizes_kind == authorizes_kind,
                ProvisioningChangeSetApproval.change_set_hash == change_set_hash,
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return existing

    profile_content = toolchain_profile.content or {}
    approval = ProvisioningChangeSetApproval(
        organization_id=manifest.organization_id,
        manifest_id=manifest.id,
        toolchain_profile_id=toolchain_profile.id,
        authorizes_kind=authorizes_kind,
        change_set_hash=change_set_hash,
        rendered_workspace_hash=rendered_workspace_hash,
        manifest_content_hash=manifest.content_hash,
        toolchain_profile_hash=toolchain_profile.content_hash,
        target_scope_policy_hash=manifest.target_scope_policy_hash or "",
        reservations_hash=reservations_hash(manifest),
        renderer_version=str(profile_content.get("renderer_version", "")),
        module_bundle_hash=str(profile_content.get("module_bundle_hash", "")),
        summary=summary,
        status=ChangeSetApprovalStatus.pending,
        created_by=created_by,
    )
    session.add(approval)
    session.flush()
    audit.record(
        session,
        action=AuditAction.change_set_recorded,
        resource_type="provisioning_change_set_approval",
        resource_id=approval.id,
        organization_id=manifest.organization_id,
        actor="worker",
        data={
            "authorizes_kind": authorizes_kind.value,
            "change_set_hash": change_set_hash,
            "summary": summary,
        },
    )
    return approval


def get_change_set_approval(
    session: Session, actor: Principal, approval_id: uuid.UUID
) -> ProvisioningChangeSetApproval:
    actor.require(Permission.provisioning_read)
    approval = session.get(ProvisioningChangeSetApproval, approval_id)
    if approval is None:
        raise NotFoundError(f"change-set approval {approval_id} not found")
    actor.require_org(approval.organization_id)
    return approval


def list_change_set_approvals(
    session: Session, actor: Principal, manifest_id: uuid.UUID
) -> list[ProvisioningChangeSetApproval]:
    actor.require(Permission.provisioning_read)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise NotFoundError(f"manifest {manifest_id} not found")
    actor.require_org(manifest.organization_id)
    return list(
        session.execute(
            select(ProvisioningChangeSetApproval)
            .where(ProvisioningChangeSetApproval.manifest_id == manifest_id)
            .order_by(ProvisioningChangeSetApproval.created_at)
        )
        .scalars()
        .all()
    )


def approve_change_set(
    session: Session, actor: Principal, approval_id: uuid.UUID, reason: str = ""
) -> ProvisioningChangeSetApproval:
    """Explicit human approval of an exact dry-run change set (Charter Invariant 5).

    No AI approval, no environment-variable bypass — a human with the
    ``provisioning:approve`` permission is required.
    """
    actor.require(Permission.provisioning_approve)
    approval = get_change_set_approval(session, actor, approval_id)
    if approval.status != ChangeSetApprovalStatus.pending:
        raise DomainError(
            f"change-set approval is '{approval.status.value}', only 'pending' can be approved"
        )
    approval.status = ChangeSetApprovalStatus.approved
    approval.decided_by = actor.user_id
    approval.decided_at = datetime.now(UTC)
    approval.decision_reason = reason
    audit.record(
        session,
        action=AuditAction.change_set_approved,
        resource_type="provisioning_change_set_approval",
        resource_id=approval.id,
        organization_id=approval.organization_id,
        actor=str(actor.user_id),
        data={
            "authorizes_kind": approval.authorizes_kind.value,
            "change_set_hash": approval.change_set_hash,
            "reason": reason,
        },
    )
    return approval


def reject_change_set(
    session: Session, actor: Principal, approval_id: uuid.UUID, reason: str = ""
) -> ProvisioningChangeSetApproval:
    actor.require(Permission.provisioning_approve)
    approval = get_change_set_approval(session, actor, approval_id)
    if approval.status != ChangeSetApprovalStatus.pending:
        raise DomainError(
            f"change-set approval is '{approval.status.value}', only 'pending' can be rejected"
        )
    approval.status = ChangeSetApprovalStatus.rejected
    approval.decided_by = actor.user_id
    approval.decided_at = datetime.now(UTC)
    approval.decision_reason = reason
    audit.record(
        session,
        action=AuditAction.change_set_rejected,
        resource_type="provisioning_change_set_approval",
        resource_id=approval.id,
        organization_id=approval.organization_id,
        actor=str(actor.user_id),
        data={"reason": reason},
    )
    return approval


def find_approved_change_set(
    session: Session,
    manifest_id: uuid.UUID,
    authorizes_kind: ProvisioningOperationKind,
    change_set_hash: str,
) -> ProvisioningChangeSetApproval | None:
    """Return the APPROVED approval for the exact (manifest, kind, hash), else None."""
    return (
        session.execute(
            select(ProvisioningChangeSetApproval).where(
                ProvisioningChangeSetApproval.manifest_id == manifest_id,
                ProvisioningChangeSetApproval.authorizes_kind == authorizes_kind,
                ProvisioningChangeSetApproval.change_set_hash == change_set_hash,
                ProvisioningChangeSetApproval.status == ChangeSetApprovalStatus.approved,
            )
        )
        .scalars()
        .first()
    )


def mark_consumed(
    session: Session, approval: ProvisioningChangeSetApproval
) -> ProvisioningChangeSetApproval:
    """Mark an approved change set as consumed after a successful apply/destroy."""
    if approval.status == ChangeSetApprovalStatus.approved:
        approval.status = ChangeSetApprovalStatus.consumed
        session.flush()
    return approval
