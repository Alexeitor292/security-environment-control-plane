"""ORM-level immutability guards (Charter Invariants 2, 10; ADR-002, ADR-006/008).

These are the portable (SQLite + PostgreSQL) enforcement layer. The dev/prod
PostgreSQL migration additionally installs database triggers for the strongest
cases (environment_version, audit_event). The service layer provides no update
path for protected fields. Defense in depth.
"""

from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from secp_api.enums import (
    LiveReadAuthorizationStatus,
    ResolverActivationStatus,
    WorkerIdentityStatus,
)
from secp_api.errors import ImmutableResourceError
from secp_api.models import (
    AuditEvent,
    DeploymentPlan,
    EnvironmentVersion,
    ExecutionTarget,
    LivePreflightEvidence,
    LiveReadAuthorization,
    ProviderInventorySnapshot,
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    ReadonlyStagingPreflight,
    ResolverActivationAuthorization,
    ResolverActivationEvidence,
    StagingDeploymentApproval,
    StagingDeploymentPlan,
    StagingDeploymentVerification,
    StagingLab,
    StagingLabWorkItem,
    StagingSubstrateEligibility,
    TargetEvidenceRecord,
    TargetOnboarding,
    TargetPreflight,
    ToolchainProfile,
    WorkerIdentityEvidence,
    WorkerIdentityRegistration,
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
# StagingLab (SECP-002B-1B-9): identity + substrate + the immutable desired-state plan are
# immutable from creation/plan-generation; approval binding and the plan are set once. The
# simulated observed-state and lifecycle status are mutable through the service layer.
_STAGING_LAB_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "ownership_label",
    "purpose",
    "profile",
    "network_intent",
    "resource_class",
    "rollback_policy",
    "bootstrap_artifact_profile",
    "created_by",
)
_STAGING_LAB_SET_ONCE = (
    "plan_hash",
    "desired_state",
    "approved_by",
    "approved_at",
    "approved_plan_hash",
)
# StagingLabWorkItem: the work definition (identity + immutable plan binding + operation) is
# immutable; only lifecycle (status/revision/timestamps/failure_code) may change.
_STAGING_WORK_PROTECTED = (
    "organization_id",
    "staging_lab_id",
    "operation_kind",
    "plan_hash",
    "plan_version",
    "operation_fingerprint",
    "created_by",
)
# StagingSubstrateEligibility: issuance facts immutable; only revocation metadata is set once.
_STAGING_ELIGIBILITY_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "plugin_type",
    "allowed_profile",
    "issued_by",
    "issued_at",
)
_STAGING_ELIGIBILITY_SET_ONCE = ("revoked_by", "revoked_at")
# ReadonlyStagingPreflight (SECP-B2-0): the immutable binding is fixed at creation; only lifecycle
# (status/revision/outcome/facts/timestamps) may change (worker-only, via the service/consumer).
_READONLY_PREFLIGHT_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "onboarding_id",
    "live_read_authorization_id",
    "authorization_version",
    "collector_contract_version",
    "endpoint_allowlist_version",
    "operation_fingerprint",
    "created_by",
)
# ResolverActivationAuthorization (SECP-B2-4.1): binding facts are immutable after creation; the
# approval/revocation metadata + evidence fingerprint are set-once; and only the closed lifecycle
# transitions are allowed. The service mutates via Core CAS (which bypasses this ORM guard), so the
# amended migration installs a PostgreSQL trigger for the raw/Core path — this guard is the portable
# (SQLite + PostgreSQL) ORM-path layer + defense in depth.
_RESOLVER_ACTIVATION_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "onboarding_id",
    "live_read_authorization_id",
    "live_read_authorization_version",
    "preflight_id",
    "operation_fingerprint",
    "resolver_adapter_contract_version",
    "purpose",
    "authorization_expiry",
    "authorization_version",
    "created_by",
    "created_at",
)
_RESOLVER_ACTIVATION_SET_ONCE = (
    "evidence_fingerprint",
    "approved_by",
    "approved_at",
    "revoked_by",
    "revoked_at",
    "revocation_reason_code",
)
_RESOLVER_ACTIVATION_ALLOWED_TRANSITIONS = {
    (ResolverActivationStatus.draft, ResolverActivationStatus.approved),
    (ResolverActivationStatus.draft, ResolverActivationStatus.revoked),
    (ResolverActivationStatus.draft, ResolverActivationStatus.expired),
    (ResolverActivationStatus.approved, ResolverActivationStatus.revoked),
    (ResolverActivationStatus.approved, ResolverActivationStatus.expired),
}


def _resolver_activation_parent_status(
    session: Session, evidence: ResolverActivationEvidence
) -> ResolverActivationStatus | None:
    """The lifecycle status of an evidence row's parent authorization (identity-map first)."""
    parent = session.get(ResolverActivationAuthorization, evidence.authorization_id)
    if parent is None:
        parent = evidence.authorization  # fall back to the relationship (unflushed insert)
    return None if parent is None else parent.status


def _guard_resolver_evidence(
    session: Session, evidence: ResolverActivationEvidence, verb: str
) -> None:
    status = _resolver_activation_parent_status(session, evidence)
    if status is not None and status != ResolverActivationStatus.draft:
        raise ImmutableResourceError(
            f"ResolverActivationEvidence may not be {verb} once the authorization is "
            f"{getattr(status, 'value', status)!r}; evidence is managed only while draft"
        )


# WorkerIdentityRegistration (SECP-B2-4.3): binding facts immutable after creation; approval /
# revocation metadata + evidence fingerprint set-once; only the closed lifecycle transitions are
# allowed. The service mutates via Core CAS (which bypasses this ORM guard), so the migration
# installs a PostgreSQL trigger for the raw/Core path — this guard is the portable (SQLite +
# PostgreSQL) ORM-path layer + defense in depth.
_WORKER_IDENTITY_PROTECTED = (
    "organization_id",
    "mechanism",
    "identity_label",
    "deployment_binding",
    "verification_anchor_fingerprint",
    "identity_version",
    "expiry",
    "created_by",
    "created_at",
)
_WORKER_IDENTITY_SET_ONCE = (
    "evidence_fingerprint",
    "approved_by",
    "approved_at",
    "revoked_by",
    "revoked_at",
    "revocation_reason_code",
)
_WORKER_IDENTITY_ALLOWED_TRANSITIONS = {
    (WorkerIdentityStatus.draft, WorkerIdentityStatus.approved),
    (WorkerIdentityStatus.draft, WorkerIdentityStatus.revoked),
    (WorkerIdentityStatus.draft, WorkerIdentityStatus.expired),
    (WorkerIdentityStatus.approved, WorkerIdentityStatus.revoked),
    (WorkerIdentityStatus.approved, WorkerIdentityStatus.expired),
}


def _worker_identity_parent_status(
    session: Session, evidence: WorkerIdentityEvidence
) -> WorkerIdentityStatus | None:
    """The lifecycle status of an evidence row's parent registration (identity-map first)."""
    parent = session.get(WorkerIdentityRegistration, evidence.registration_id)
    if parent is None:
        parent = evidence.registration  # fall back to the relationship (unflushed insert)
    return None if parent is None else parent.status


def _guard_worker_identity_evidence(
    session: Session, evidence: WorkerIdentityEvidence, verb: str
) -> None:
    status = _worker_identity_parent_status(session, evidence)
    if status is not None and status != WorkerIdentityStatus.draft:
        raise ImmutableResourceError(
            f"WorkerIdentityEvidence may not be {verb} once the registration is "
            f"{getattr(status, 'value', status)!r}; evidence is managed only while draft"
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
        # StagingLab (SECP-002B-1B-9): identity/substrate immutable; the desired-state plan and
        # approval binding are set-once. Lifecycle status + simulated observed-state stay mutable.
        if isinstance(obj, StagingLab):
            changed = [a for a in _STAGING_LAB_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "StagingLab identity/substrate fields are immutable after creation; "
                    f"attempted to change {changed}"
                )
            repeated = [
                a
                for a in _STAGING_LAB_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    f"StagingLab plan/approval fields are set-once; attempted to change {repeated}"
                )
        # StagingLabWorkItem (SECP-002B-1B-9): the work definition is immutable; only lifecycle
        # (status/revision/timestamps/failure_code) may change.
        if isinstance(obj, StagingLabWorkItem):
            changed = [a for a in _STAGING_WORK_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    f"StagingLabWorkItem definition is immutable; attempted to change {changed}"
                )
        # StagingSubstrateEligibility (SECP-002B-1B-9): issuance immutable; revocation set-once.
        if isinstance(obj, StagingSubstrateEligibility):
            changed = [a for a in _STAGING_ELIGIBILITY_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "StagingSubstrateEligibility issuance fields are immutable; "
                    f"attempted to change {changed}"
                )
            repeated = [
                a
                for a in _STAGING_ELIGIBILITY_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    "StagingSubstrateEligibility revocation metadata is set-once; "
                    f"attempted to change {repeated}"
                )
        # ReadonlyStagingPreflight (SECP-B2-0): the binding is immutable; lifecycle stays mutable.
        if isinstance(obj, ReadonlyStagingPreflight):
            changed = [a for a in _READONLY_PREFLIGHT_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    f"ReadonlyStagingPreflight binding is immutable; attempted to change {changed}"
                )
        # ResolverActivationAuthorization (SECP-B2-4.1): binding facts immutable; approval /
        # revocation facts + evidence fingerprint set-once; only closed transitions allowed.
        if isinstance(obj, ResolverActivationAuthorization):
            changed = [a for a in _RESOLVER_ACTIVATION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "ResolverActivationAuthorization binding facts are immutable after creation; "
                    f"attempted to change {changed}"
                )
            repeated = [
                a
                for a in _RESOLVER_ACTIVATION_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    "ResolverActivationAuthorization approval/revocation facts are set-once; "
                    f"attempted to change {repeated}"
                )
            if _attr_changed(obj, "status"):
                previous = _previous_value(obj, "status")
                if (
                    previous is not None
                    and (previous, obj.status) not in _RESOLVER_ACTIVATION_ALLOWED_TRANSITIONS
                ):
                    raise ImmutableResourceError(
                        "ResolverActivationAuthorization status transition is not allowed: "
                        f"{getattr(previous, 'value', previous)!r} -> "
                        f"{getattr(obj.status, 'value', obj.status)!r}"
                    )
        # ResolverActivationEvidence: managed (changed) only while the authorization is draft.
        if isinstance(obj, ResolverActivationEvidence):
            _guard_resolver_evidence(session, obj, "changed")
        # WorkerIdentityRegistration (SECP-B2-4.3): binding facts immutable; approval / revocation
        # facts + evidence fingerprint set-once; only closed transitions allowed.
        if isinstance(obj, WorkerIdentityRegistration):
            changed = [a for a in _WORKER_IDENTITY_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "WorkerIdentityRegistration binding facts are immutable after creation; "
                    f"attempted to change {changed}"
                )
            repeated = [
                a
                for a in _WORKER_IDENTITY_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    "WorkerIdentityRegistration approval/revocation facts are set-once; "
                    f"attempted to change {repeated}"
                )
            if _attr_changed(obj, "status"):
                previous = _previous_value(obj, "status")
                if (
                    previous is not None
                    and (previous, obj.status) not in _WORKER_IDENTITY_ALLOWED_TRANSITIONS
                ):
                    raise ImmutableResourceError(
                        "WorkerIdentityRegistration status transition is not allowed: "
                        f"{getattr(previous, 'value', previous)!r} -> "
                        f"{getattr(obj.status, 'value', obj.status)!r}"
                    )
        # WorkerIdentityEvidence: managed (changed) only while the registration is draft.
        if isinstance(obj, WorkerIdentityEvidence):
            _guard_worker_identity_evidence(session, obj, "changed")
        # LivePreflightEvidence (SECP-B2-4.5): fully immutable after insert — no field may change.
        if isinstance(obj, LivePreflightEvidence):
            raise ImmutableResourceError("LivePreflightEvidence records are immutable after insert")
        # SECP-B4: content-addressed plans, approvals, and verification results are immutable.
        if isinstance(
            obj,
            StagingDeploymentPlan | StagingDeploymentApproval | StagingDeploymentVerification,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records are immutable after insert")
        # AuditEvent: append-only.
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records are immutable")

    for obj in session.new:
        # ResolverActivationEvidence: cannot be inserted once the authorization leaves draft.
        if isinstance(obj, ResolverActivationEvidence):
            _guard_resolver_evidence(session, obj, "inserted")
        # WorkerIdentityEvidence: cannot be inserted once the registration leaves draft.
        if isinstance(obj, WorkerIdentityEvidence):
            _guard_worker_identity_evidence(session, obj, "inserted")

    for obj in session.deleted:
        if isinstance(obj, StagingLab):
            raise ImmutableResourceError("StagingLab records cannot be deleted")
        if isinstance(obj, StagingLabWorkItem):
            raise ImmutableResourceError("StagingLabWorkItem records cannot be deleted")
        if isinstance(obj, StagingSubstrateEligibility):
            raise ImmutableResourceError("StagingSubstrateEligibility records cannot be deleted")
        if isinstance(obj, ReadonlyStagingPreflight):
            raise ImmutableResourceError("ReadonlyStagingPreflight records cannot be deleted")
        if isinstance(obj, LiveReadAuthorization):
            raise ImmutableResourceError("LiveReadAuthorization records cannot be deleted")
        if isinstance(obj, TargetEvidenceRecord):
            raise ImmutableResourceError("TargetEvidenceRecord records cannot be deleted")
        if isinstance(obj, TargetPreflight):
            raise ImmutableResourceError("TargetPreflight records cannot be deleted")
        if isinstance(obj, ResolverActivationAuthorization):
            raise ImmutableResourceError(
                "ResolverActivationAuthorization records cannot be deleted"
            )
        if isinstance(obj, ResolverActivationEvidence):
            _guard_resolver_evidence(session, obj, "deleted")
        if isinstance(obj, WorkerIdentityRegistration):
            raise ImmutableResourceError("WorkerIdentityRegistration records cannot be deleted")
        if isinstance(obj, WorkerIdentityEvidence):
            _guard_worker_identity_evidence(session, obj, "deleted")
        if isinstance(obj, LivePreflightEvidence):
            raise ImmutableResourceError("LivePreflightEvidence records cannot be deleted")
        # SECP-B4: content-addressed plans, approvals, and verification results cannot be deleted
        # outside an explicit governed archival path (none exists yet), preserving the audit chain.
        if isinstance(
            obj,
            StagingDeploymentPlan | StagingDeploymentApproval | StagingDeploymentVerification,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records cannot be deleted")
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records cannot be deleted")


def install_guards() -> None:
    """Idempotent import hook. Importing this module registers the listeners."""
    return None
