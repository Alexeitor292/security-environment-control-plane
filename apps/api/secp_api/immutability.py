"""ORM-level immutability guards (Charter Invariants 2, 10; ADR-002, ADR-006/008).

These are the portable (SQLite + PostgreSQL) enforcement layer. The dev/prod
PostgreSQL migration additionally installs database triggers for the strongest
cases (environment_version, audit_event). The service layer provides no update
path for protected fields. Defense in depth.
"""

from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from secp_api.errors import ImmutableResourceError
from secp_api.models import (
    AuditEvent,
    DeploymentPlan,
    EnvironmentVersion,
    ExecutionTarget,
    ProviderInventorySnapshot,
    ProvisioningManifest,
)

_VERSION_PROTECTED = ("spec", "content_hash", "version_number", "api_version")
_TARGET_PROTECTED = ("config", "config_hash", "plugin_name")
# Binding fields that plan approval covers — mutable lifecycle fields (status,
# approved_content_hash, decided_by, decided_at, decision_reason) are excluded.
_PLAN_PROTECTED = (
    "organization_id",
    "exercise_id",
    "environment_version_id",
    "version_content_hash",
    "execution_target_id",
    "target_config_hash",
    "target_scope_policy_hash",
    "plan",
    "summary",
    "generated_by",
)
_MANIFEST_PROTECTED = (
    "content",
    "content_hash",
    "deployment_plan_id",
    "execution_target_id",
    "target_config_hash",
    "target_scope_policy_hash",
)


def _attr_changed(obj: object, attr: str) -> bool:
    state = inspect(obj)
    assert state is not None  # ORM-mapped instances always have inspection state
    return state.attrs[attr].history.has_changes()


def _previous_value(obj: object, attr: str) -> object:
    """Return the previously-committed value of an attribute (before this flush)."""
    state = inspect(obj)
    assert state is not None
    hist = state.attrs[attr].history
    if hist.deleted:
        return hist.deleted[0]
    if hist.unchanged:
        return hist.unchanged[0]
    return None


@event.listens_for(Session, "before_flush")
def _block_immutable_mutations(session: Session, _flush_context, _instances) -> None:
    for obj in session.dirty:
        # EnvironmentVersion: spec/hash/number/api_version are immutable.
        if isinstance(obj, EnvironmentVersion):
            changed = [a for a in _VERSION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    f"EnvironmentVersion is immutable after creation; attempted to change {changed}"
                )
        # ExecutionTarget: config/config_hash/plugin_name are immutable (ADR-006).
        if isinstance(obj, ExecutionTarget):
            changed = [a for a in _TARGET_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "ExecutionTarget configuration is immutable after creation; "
                    f"attempted to change {changed}. Register a new target instead."
                )
        # DeploymentPlan: binding fields are immutable after creation (SECP-002B-0).
        # Lifecycle fields (status, decided_by, decided_at, etc.) remain mutable.
        if isinstance(obj, DeploymentPlan):
            changed = [a for a in _PLAN_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "DeploymentPlan binding fields are immutable after creation; "
                    f"attempted to change {changed}"
                )
        # ProviderInventorySnapshot: immutable once finalized (ADR-008).
        if isinstance(obj, ProviderInventorySnapshot):
            if bool(_previous_value(obj, "finalized")):
                raise ImmutableResourceError(
                    "ProviderInventorySnapshot is immutable after completion"
                )
        # ProvisioningManifest: content/hash/bindings immutable after creation (ADR-011).
        if isinstance(obj, ProvisioningManifest):
            changed = [a for a in _MANIFEST_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "ProvisioningManifest is immutable after generation; "
                    f"attempted to change {changed}"
                )
        # AuditEvent: append-only.
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records are immutable")

    for obj in session.deleted:
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records cannot be deleted")


def install_guards() -> None:
    """Idempotent import hook. Importing this module registers the listeners."""
    return None
