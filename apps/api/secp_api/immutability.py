"""ORM-level immutability guards (Charter Invariants 2, 10; ADR-002, ADR-006/008).

These are the portable (SQLite + PostgreSQL) enforcement layer. The dev/prod
PostgreSQL migration additionally installs database triggers for the strongest
cases (environment_version, audit_event). The service layer provides no update
path for protected fields. Defense in depth.
"""

from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from secp_api.enums import LiveReadAuthorizationStatus
from secp_api.errors import ImmutableResourceError
from secp_api.models import (
    AuditEvent,
    DeploymentPlan,
    EnvironmentVersion,
    ExecutionTarget,
    LiveReadAuthorization,
    ProviderInventorySnapshot,
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    TargetEvidenceRecord,
    TargetOnboarding,
    TargetPreflight,
    ToolchainProfile,
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
    "toolchain_profile_id",
    "toolchain_profile_hash",
    "target_onboarding_id",
    "onboarding_boundary_hash",
    "approved_preflight_id",
    "approved_preflight_evidence_hash",
    "onboarding_verification_level",
    "effective_boundary",
    "effective_boundary_hash",
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
    "toolchain_profile_id",
    "toolchain_profile_hash",
    "target_onboarding_id",
    "onboarding_boundary_hash",
    "approved_preflight_id",
    "approved_preflight_evidence_hash",
    "onboarding_verification_level",
    "effective_boundary",
    "effective_boundary_hash",
)
_TOOLCHAIN_PROFILE_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "version",
    "runner_kind",
    "activation_class",
    "renderer_version",
    "content",
    "content_hash",
)
# A change-set approval's bindings are immutable; only the decision fields
# (status, decided_by, decided_at, decision_reason) may change.
_CHANGE_SET_APPROVAL_PROTECTED = (
    "organization_id",
    "manifest_id",
    "toolchain_profile_id",
    "authorizes_kind",
    "change_set_hash",
    "rendered_workspace_hash",
    "manifest_content_hash",
    "toolchain_profile_hash",
    "target_scope_policy_hash",
    "reservations_hash",
    "renderer_version",
    "module_bundle_hash",
)
# An onboarding's identity + declared boundary are immutable; the lifecycle/decision
# fields (status, decided_by/at, decision_reason, approved_*_hash, activated_at) change.
_ONBOARDING_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "onboarding_mode",
    "isolation_model",
    "declared_boundary",
    "boundary_hash",
)
# Preflight evidence is append-only: immutable once recorded (incl. provenance + level).
_PREFLIGHT_PROTECTED = (
    "organization_id",
    "onboarding_id",
    "collector",
    "verification_level",
    "collector_kind",
    "collector_identity",
    "evidence_version",
    "target_config_hash",
    "scope_policy_hash",
    "boundary_hash",
    "toolchain_profile_id",
    "toolchain_profile_hash",
    "passed",
    "checks",
    "evidence_hash",
    "target_evidence_id",
    "target_evidence_hash",
)
_TARGET_EVIDENCE_PROTECTED = (
    "organization_id",
    "onboarding_id",
    "execution_target_id",
    "evidence_source",
    "verification_level",
    "status",
    "evidence_payload",
    "findings",
    "collected_at",
    "evidence_hash",
)
_LIVE_READ_AUTHORIZATION_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "onboarding_id",
    "connection_hash",
    "boundary_hash",
    "authorization_version",
    "authorization_expiry",
    "collector_contract_version",
    "endpoint_allowlist_version",
    "evidence_source",
    "verification_level",
    "created_by",
)
_LIVE_READ_AUTHORIZATION_SET_ONCE = (
    "approved_by",
    "approved_at",
    "revoked_by",
    "revoked_at",
    "revocation_reason_code",
)
_LIVE_READ_AUTHORIZATION_ALLOWED_TRANSITIONS = {
    (LiveReadAuthorizationStatus.draft, LiveReadAuthorizationStatus.approved),
    (LiveReadAuthorizationStatus.draft, LiveReadAuthorizationStatus.expired),
    (LiveReadAuthorizationStatus.approved, LiveReadAuthorizationStatus.revoked),
    (LiveReadAuthorizationStatus.approved, LiveReadAuthorizationStatus.expired),
}


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
        # ToolchainProfile: provenance is immutable after creation (ADR-013).
        if isinstance(obj, ToolchainProfile):
            changed = [a for a in _TOOLCHAIN_PROFILE_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "ToolchainProfile provenance is immutable after creation; "
                    f"attempted to change {changed}. Register a new profile version instead."
                )
        # ProvisioningChangeSetApproval: bindings/hashes immutable; only the decision
        # fields (status, decided_by, decided_at, decision_reason) may change (ADR-013).
        if isinstance(obj, ProvisioningChangeSetApproval):
            changed = [a for a in _CHANGE_SET_APPROVAL_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "ProvisioningChangeSetApproval bindings are immutable after creation; "
                    f"attempted to change {changed}"
                )
        # TargetOnboarding: identity + declared boundary immutable; lifecycle mutable (ADR-014).
        if isinstance(obj, TargetOnboarding):
            changed = [a for a in _ONBOARDING_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "TargetOnboarding identity/declared-boundary is immutable after creation; "
                    f"attempted to change {changed}. Create a new onboarding record instead."
                )
        # TargetPreflight: append-only, immutable once recorded (ADR-014).
        if isinstance(obj, TargetPreflight):
            changed = [a for a in _PREFLIGHT_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "TargetPreflight evidence is immutable after recording; "
                    f"attempted to change {changed}"
                )
        # TargetEvidenceRecord: append-only, immutable once recorded (SECP-002B-1B-1).
        if isinstance(obj, TargetEvidenceRecord):
            changed = [a for a in _TARGET_EVIDENCE_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "TargetEvidenceRecord is immutable after recording; "
                    f"attempted to change {changed}"
                )
        # LiveReadAuthorization: binding facts are immutable. Approval/revocation metadata may
        # be set once through explicit lifecycle transitions, preserving approval history.
        if isinstance(obj, LiveReadAuthorization):
            changed = [a for a in _LIVE_READ_AUTHORIZATION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "LiveReadAuthorization binding fields are immutable; "
                    f"attempted to change {changed}"
                )
            repeated = [
                a
                for a in _LIVE_READ_AUTHORIZATION_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    "LiveReadAuthorization approval/revocation metadata is set-once; "
                    f"attempted to change {repeated}"
                )
            if _attr_changed(obj, "status"):
                previous = _previous_value(obj, "status")
                transition = (previous, obj.status)
                if (
                    previous is not None
                    and transition not in _LIVE_READ_AUTHORIZATION_ALLOWED_TRANSITIONS
                ):
                    raise ImmutableResourceError(
                        "LiveReadAuthorization status transition is not allowed: "
                        f"{getattr(previous, 'value', previous)!r} -> "
                        f"{getattr(obj.status, 'value', obj.status)!r}"
                    )
                if obj.status == LiveReadAuthorizationStatus.approved and (
                    obj.approved_by is None or obj.approved_at is None
                ):
                    raise ImmutableResourceError(
                        "LiveReadAuthorization approval requires approved_by and approved_at"
                    )
                if obj.status == LiveReadAuthorizationStatus.revoked and (
                    obj.revoked_by is None
                    or obj.revoked_at is None
                    or not obj.revocation_reason_code
                    or obj.approved_by is None
                    or obj.approved_at is None
                ):
                    raise ImmutableResourceError(
                        "LiveReadAuthorization revocation requires preserved approval and "
                        "explicit revocation metadata"
                    )
        # AuditEvent: append-only.
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records are immutable")

    for obj in session.deleted:
        if isinstance(obj, LiveReadAuthorization):
            raise ImmutableResourceError("LiveReadAuthorization records cannot be deleted")
        if isinstance(obj, TargetEvidenceRecord):
            raise ImmutableResourceError("TargetEvidenceRecord records cannot be deleted")
        if isinstance(obj, TargetPreflight):
            raise ImmutableResourceError("TargetPreflight records cannot be deleted")
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records cannot be deleted")


def install_guards() -> None:
    """Idempotent import hook. Importing this module registers the listeners."""
    return None
