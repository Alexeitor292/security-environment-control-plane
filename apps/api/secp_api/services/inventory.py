"""Provider inventory snapshot services (ADR-008).

Snapshots are organization-scoped and immutable after completion. The API queues a
discovery request; the WORKER performs the discovery and finalizes the snapshot.
Secrets never appear in snapshots, resources, audit events, or errors.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.db import session_scope
from secp_api.enums import AuditAction, Permission, SnapshotStatus, TargetStatus
from secp_api.errors import DomainError, NotFoundError
from secp_api.models import (
    ExecutionTarget,
    ProviderInventoryResource,
    ProviderInventorySnapshot,
)
from secp_api.services.targets import get_target


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _audit_provider_refusal(actor: Principal, target: ExecutionTarget, reason: str) -> None:
    """Persist a provider-operation refusal in its own transaction (survives raise)."""
    with session_scope() as s:
        audit.record(
            s,
            action=AuditAction.provider_operation_refused,
            resource_type="execution_target",
            resource_id=target.id,
            organization_id=target.organization_id,
            actor=str(actor.user_id),
            outcome="denied",
            data={"reason": reason},
        )


# --- API-side: request discovery (queue) -------------------------------------


def request_discovery(
    session: Session, actor: Principal, target_id: uuid.UUID, dispatcher=None
) -> ProviderInventorySnapshot:
    """Queue a read-only discovery for a target. The worker performs it (ADR-010).

    The API never calls the provider plugin and never resolves the secret ref.
    Discovery requires the Temporal worker path; an inline dispatcher is refused
    up front (and audited) before any snapshot is created.
    """
    actor.require(Permission.inventory_discover)
    target = get_target(session, actor, target_id)
    if target.status != TargetStatus.active:
        raise DomainError(
            f"execution target is '{target.status.value}'; discovery requires 'active'"
        )

    if dispatcher is not None and getattr(dispatcher, "mode", None) == "inline":
        from secp_api.safety import InlineExecutionForbidden

        reason = (
            "provider discovery requires the Temporal worker path; "
            "set SECP_WORKFLOW_DISPATCH_MODE=temporal"
        )
        _audit_provider_refusal(actor, target, reason)
        raise InlineExecutionForbidden(reason)

    snapshot = ProviderInventorySnapshot(
        organization_id=actor.organization_id,
        execution_target_id=target.id,
        plugin_name=target.plugin_name,
        target_config_hash=target.config_hash,
        status=SnapshotStatus.queued,
        requested_by=actor.user_id,
        requested_at=_utcnow(),
    )
    session.add(snapshot)
    session.flush()
    audit.record(
        session,
        action=AuditAction.discovery_requested,
        resource_type="provider_inventory_snapshot",
        resource_id=snapshot.id,
        organization_id=actor.organization_id,
        actor=str(actor.user_id),
        data={"target_id": str(target.id), "plugin": target.plugin_name},
    )

    if dispatcher is not None:
        # Dispatch to the worker boundary; inline refuses non-simulator providers.
        run = dispatcher.dispatch_discovery(session, snapshot.id)
        snapshot.workflow_run_id = run.id
        session.flush()
    return snapshot


# --- worker-side: lifecycle (called by the discovery workflow) ---------------


def _get_snapshot(session: Session, snapshot_id: uuid.UUID) -> ProviderInventorySnapshot:
    snap = session.get(ProviderInventorySnapshot, snapshot_id)
    if snap is None:
        raise NotFoundError(f"snapshot {snapshot_id} not found")
    return snap


def mark_running(session: Session, snapshot_id: uuid.UUID) -> ProviderInventorySnapshot:
    snap = _get_snapshot(session, snapshot_id)
    snap.status = SnapshotStatus.running
    audit.record(
        session,
        action=AuditAction.discovery_started,
        resource_type="provider_inventory_snapshot",
        resource_id=snap.id,
        organization_id=snap.organization_id,
        actor="worker",
    )
    return snap


def complete_snapshot(
    session: Session,
    snapshot_id: uuid.UUID,
    *,
    resources: list[dict],
    summary: dict,
    plugin_version: str = "",
) -> ProviderInventorySnapshot:
    """Persist normalized resources and finalize the snapshot (immutable after)."""
    snap = _get_snapshot(session, snapshot_id)
    for r in resources:
        session.add(
            ProviderInventoryResource(
                snapshot_id=snap.id,
                organization_id=snap.organization_id,
                resource_type=str(r["resource_type"]),
                provider_external_id=str(r["provider_external_id"]),
                display_name=str(r.get("display_name", "")),
                parent_ref=r.get("parent_ref"),
                status=str(r.get("status", "unknown")),
                attributes=dict(r.get("attributes", {})),
            )
        )
    snap.status = SnapshotStatus.completed
    snap.summary = summary
    snap.plugin_version = plugin_version
    snap.completed_at = _utcnow()
    snap.finalized = True
    audit.record(
        session,
        action=AuditAction.discovery_completed,
        resource_type="provider_inventory_snapshot",
        resource_id=snap.id,
        organization_id=snap.organization_id,
        actor="worker",
        data={"summary": summary},
    )
    return snap


def fail_snapshot(
    session: Session, snapshot_id: uuid.UUID, *, error: str
) -> ProviderInventorySnapshot:
    """Finalize a snapshot as failed. ``error`` must already be redacted."""
    snap = _get_snapshot(session, snapshot_id)
    snap.status = SnapshotStatus.failed
    snap.error = error
    snap.completed_at = _utcnow()
    snap.finalized = True
    audit.record(
        session,
        action=AuditAction.discovery_failed,
        resource_type="provider_inventory_snapshot",
        resource_id=snap.id,
        organization_id=snap.organization_id,
        actor="worker",
        outcome="failed",
        data={"error": error},
    )
    return snap


# --- read access (org-scoped) -------------------------------------------------


def get_snapshot(
    session: Session, actor: Principal, snapshot_id: uuid.UUID
) -> ProviderInventorySnapshot:
    actor.require(Permission.inventory_read)
    snap = _get_snapshot(session, snapshot_id)
    actor.require_org(snap.organization_id)
    return snap


def list_snapshots(
    session: Session, actor: Principal, target_id: uuid.UUID
) -> list[ProviderInventorySnapshot]:
    actor.require(Permission.inventory_read)
    get_target(session, actor, target_id)
    return list(
        session.execute(
            select(ProviderInventorySnapshot)
            .where(ProviderInventorySnapshot.execution_target_id == target_id)
            .order_by(ProviderInventorySnapshot.requested_at.desc())
        )
        .scalars()
        .all()
    )


def list_snapshot_resources(
    session: Session, actor: Principal, snapshot_id: uuid.UUID
) -> list[ProviderInventoryResource]:
    snap = get_snapshot(session, actor, snapshot_id)
    return list(
        session.execute(
            select(ProviderInventoryResource)
            .where(ProviderInventoryResource.snapshot_id == snap.id)
            .order_by(
                ProviderInventoryResource.resource_type, ProviderInventoryResource.display_name
            )
        )
        .scalars()
        .all()
    )
