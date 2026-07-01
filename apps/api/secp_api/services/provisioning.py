"""Control-plane provisioning-operation service (SECP-002B-0).

Records and reads durable provisioning operations and applies audited state
transitions. This module NEVER imports a runner, OpenTofu, or a provider client —
the worker drives the runner and calls these helpers to persist state.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secp_api import audit
from secp_api.auth import Principal
from secp_api.enums import AuditAction, Permission, ProvisioningStatus
from secp_api.errors import NotFoundError
from secp_api.models import ProvisioningManifest, ProvisioningOperation
from secp_api.provisioning_lifecycle import transition


def _utcnow() -> datetime:
    return datetime.now(UTC)


def get_operation(
    session: Session, actor: Principal, operation_id: uuid.UUID
) -> ProvisioningOperation:
    actor.require(Permission.provisioning_read)
    op = session.get(ProvisioningOperation, operation_id)
    if op is None:
        raise NotFoundError(f"provisioning operation {operation_id} not found")
    actor.require_org(op.organization_id)
    return op


def operation_for_manifest(
    session: Session, manifest_id: uuid.UUID
) -> ProvisioningOperation | None:
    return (
        session.execute(
            select(ProvisioningOperation).where(ProvisioningOperation.manifest_id == manifest_id)
        )
        .scalars()
        .first()
    )


def list_operations(
    session: Session, actor: Principal, manifest_id: uuid.UUID
) -> list[ProvisioningOperation]:
    actor.require(Permission.provisioning_read)
    manifest = session.get(ProvisioningManifest, manifest_id)
    if manifest is None:
        raise NotFoundError(f"manifest {manifest_id} not found")
    actor.require_org(manifest.organization_id)
    return list(
        session.execute(
            select(ProvisioningOperation)
            .where(ProvisioningOperation.manifest_id == manifest_id)
            .order_by(ProvisioningOperation.created_at)
        )
        .scalars()
        .all()
    )


# --- state transitions (called by the worker execution) ----------------------


def advance(
    session: Session,
    operation: ProvisioningOperation,
    target: ProvisioningStatus,
    *,
    action: AuditAction,
    data: dict | None = None,
    finished: bool = False,
) -> ProvisioningOperation:
    """Apply an audited, validated lifecycle transition."""
    operation.status = transition(operation.status, target)
    if finished:
        operation.finished_at = _utcnow()
    audit.record(
        session,
        action=action,
        resource_type="provisioning_operation",
        resource_id=operation.id,
        organization_id=operation.organization_id,
        actor="worker",
        data=data or {},
    )
    session.flush()
    return operation


def mark_failed(
    session: Session, operation: ProvisioningOperation, *, error: str
) -> ProvisioningOperation:
    """Finalize an operation as failed with a redacted error."""
    operation.status = transition(operation.status, ProvisioningStatus.failed)
    operation.error = error
    operation.finished_at = _utcnow()
    audit.record(
        session,
        action=AuditAction.provisioning_failed,
        resource_type="provisioning_operation",
        resource_id=operation.id,
        organization_id=operation.organization_id,
        actor="worker",
        outcome="failed",
        data={"error": error},
    )
    session.flush()
    return operation
