"""ORM-level immutability guards (Charter Invariants 2, 10; ADR-002, ADR-006/008).

These are the portable (SQLite + PostgreSQL) enforcement layer. The dev/prod
PostgreSQL migration additionally installs database triggers for the strongest
cases (environment_version, audit_event). The service layer provides no update
path for protected fields. Defense in depth.
"""

from __future__ import annotations

from secp_scenario_schema.v1alpha2.models import API_VERSION as _V1ALPHA2
from secp_scenario_schema.v1alpha2.models import (
    PUBLICATION_CONTRACT_VERSION as _PUBLICATION_CONTRACT_VERSION,
)
from sqlalchemy import event, inspect, text
from sqlalchemy.orm import Session

from secp_api.enums import (
    LiveReadAuthorizationStatus,
    PlanSecretAuthorizationStatus,
    ResolverActivationStatus,
    TopologyRevisionStatus,
    WorkerDiscoveryAdmissionStatus,
    WorkerIdentityStatus,
)
from secp_api.errors import ImmutableResourceError
from secp_api.models import (
    AuditEvent,
    CredentialBinding,
    DeploymentPlan,
    DiscoveryCandidatePlan,
    DiscoveryCandidatePlanApproval,
    DiscoverySnapshot,
    EnvironmentVersion,
    ExecutionTarget,
    LivePreflightEvidence,
    LiveReadAuthorization,
    PlanSecretReadinessAuthorization,
    PlanSecretReadinessEvidence,
    PlanSecretReadinessRecord,
    ProviderInventorySnapshot,
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    ReadonlyStagingPreflight,
    RemoteStateReadinessRecord,
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
    ToolchainAttestationRecord,
    ToolchainProfile,
    WorkerDiscoveryAdmission,
    WorkerIdentityEvidence,
    WorkerIdentityRegistration,
)
from secp_api.topology_authoring_models import (
    TopologyRevision,
    TopologyValidationResult,
)

# SECP-B9: a topology revision's content/hash/binding are immutable; only its
# lifecycle ``status`` and set-once decision metadata may change.
_TOPOLOGY_REVISION_PROTECTED = (
    "organization_id",
    "document_id",
    "revision_number",
    "parent_revision_id",
    "schema_version",
    "document_content",
    "content_hash",
    "source_environment_version_id",
    "change_note",
    "created_by",
)
_TOPOLOGY_REVISION_SET_ONCE = ("decided_by", "decided_at", "decision_reason")
# SECP-B9: the only legal revision status moves (defense-in-depth; the service
# never attempts others). Terminal states (approved/rejected/superseded) admit
# no further transition.
_TOPOLOGY_REVISION_ALLOWED_TRANSITIONS = frozenset(
    {
        (TopologyRevisionStatus.draft, TopologyRevisionStatus.validated),
        (TopologyRevisionStatus.draft, TopologyRevisionStatus.superseded),
        (TopologyRevisionStatus.validated, TopologyRevisionStatus.submitted),
        (TopologyRevisionStatus.validated, TopologyRevisionStatus.superseded),
        (TopologyRevisionStatus.submitted, TopologyRevisionStatus.approved),
        (TopologyRevisionStatus.submitted, TopologyRevisionStatus.rejected),
    }
)
# SECP-B9: a validation result is append-only; EVERY field (incl. detail) is
# immutable once recorded, matching the Postgres trigger.
_TOPOLOGY_VALIDATION_PROTECTED = (
    "organization_id",
    "document_id",
    "revision_id",
    "content_hash",
    "status",
    "error_count",
    "warning_count",
    "findings",
    "result_hash",
    "validated_by",
    "validated_at",
    "detail",
)

# EnvironmentVersion: identity, spec/hash, created_by, and every publication binding column are
# immutable after creation (SECP-B10 / ADR-016). The migration-installed PostgreSQL trigger guards
# the same set on UPDATE (created_by included); this ORM guard is the portable layer.
_VERSION_PROTECTED = (
    "organization_id",
    "template_id",
    "version_number",
    "api_version",
    "spec",
    "content_hash",
    "created_by",
    "source_topology_document_id",
    "source_topology_revision_id",
    "topology_content_hash",
    "topology_validation_result_id",
    "topology_validation_result_hash",
    "base_environment_version_id",
    "publication_contract_version",
    "publication_fingerprint",
)
_V1ALPHA1 = "controlplane.security/v1alpha1"
# Required-non-null publication columns for a published v1alpha2 row (base stays nullable).
_VERSION_PUBLICATION_REQUIRED = (
    "source_topology_document_id",
    "source_topology_revision_id",
    "topology_content_hash",
    "topology_validation_result_id",
    "topology_validation_result_hash",
    "publication_contract_version",
    "publication_fingerprint",
)
_VERSION_PUBLICATION_COLUMNS = (*_VERSION_PUBLICATION_REQUIRED, "base_environment_version_id")
# EnvironmentVersion column -> its mirrored spec.publicationProvenance key (server-owned
# provenance; publication_fingerprint is intentionally NOT embedded in the spec).
_VERSION_PROVENANCE_MIRROR = {
    "source_topology_document_id": "topology_document_id",
    "source_topology_revision_id": "topology_revision_id",
    "topology_content_hash": "topology_content_hash",
    "topology_validation_result_id": "topology_validation_result_id",
    "topology_validation_result_hash": "topology_validation_result_hash",
    "base_environment_version_id": "base_environment_version_id",
    "publication_contract_version": "publication_contract_version",
}


def _mirror_str(value: object) -> str | None:
    """Canonical string form for mirror comparison (UUID/str -> str; None -> None)."""
    return None if value is None else str(value)


def _guard_version_insert(obj: EnvironmentVersion) -> None:
    """Insertion-coherence gate for a NEW EnvironmentVersion (SECP-B10 / ADR-016).

    A caller must not persist a fabricated, partial, mismatched, or unpublished-v1alpha2 row
    directly through the ORM (the publication service is the only legitimate v1alpha2 producer).
    This mirrors the migration-installed PostgreSQL BEFORE INSERT trigger and rejects mismatches
    with the repository's immutable-resource exception convention. It never repairs values.
    """
    spec = obj.spec
    if not isinstance(spec, dict) or spec.get("apiVersion") != obj.api_version:
        raise ImmutableResourceError("EnvironmentVersion spec.apiVersion must equal api_version")
    if obj.api_version == _V1ALPHA1:
        present = [c for c in _VERSION_PUBLICATION_COLUMNS if getattr(obj, c) is not None]
        if present:
            raise ImmutableResourceError(
                f"v1alpha1 EnvironmentVersion must carry no publication columns; got {present}"
            )
        return
    if obj.api_version != _V1ALPHA2:
        raise ImmutableResourceError(
            f"EnvironmentVersion has unsupported api_version {obj.api_version!r}"
        )
    missing = [c for c in _VERSION_PUBLICATION_REQUIRED if getattr(obj, c) is None]
    if missing:
        raise ImmutableResourceError(
            f"published EnvironmentVersion requires publication columns {missing}"
        )
    if obj.publication_contract_version != _PUBLICATION_CONTRACT_VERSION:
        raise ImmutableResourceError(
            "EnvironmentVersion publication_contract_version must be "
            f"{_PUBLICATION_CONTRACT_VERSION!r}"
        )
    fingerprint = obj.publication_fingerprint
    if not isinstance(fingerprint, str) or not fingerprint.startswith("sha256:"):
        raise ImmutableResourceError(
            "EnvironmentVersion publication_fingerprint must be a sha256 digest"
        )
    inner = spec.get("spec")
    provenance = inner.get("publicationProvenance") if isinstance(inner, dict) else None
    if not isinstance(provenance, dict):
        raise ImmutableResourceError(
            "published EnvironmentVersion spec is missing publicationProvenance"
        )
    mismatched = [
        column
        for column, key in _VERSION_PROVENANCE_MIRROR.items()
        if _mirror_str(getattr(obj, column)) != provenance.get(key)
    ]
    if mismatched:
        raise ImmutableResourceError(
            "EnvironmentVersion publication columns must mirror spec.publicationProvenance; "
            f"mismatched {mismatched}"
        )


_TARGET_PROTECTED = ("config", "config_hash", "plugin_name")
# B1B-PR4 amendment: the OPAQUE credential binding's identity is immutable; only its lifecycle
# (status + rotated_at) may transition. It holds no reference, no hash of one, and no secret.
_CREDENTIAL_BINDING_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "purpose_class",
    "binding_version",
    "binding_source",
    "created_at",
)
# Per-session key: set on the flush in which the SUPPORTED ORM rotation path announced itself to
# PostgreSQL. It lives in ``Session.info`` — NEVER a module global — so a second, concurrent session
# can never clear this session's announcement and leave ``secp.credential_rotation = 'on'`` stuck on
# for a later raw UPDATE in this transaction (which would silently suppress the rotation trigger).
_ROTATION_ANNOUNCED_KEY = "secp_credential_rotation_announced"
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
    # SECP-002B-1B B1B-PR3: the live read-only eligibility bindings are immutable once recorded.
    "operation_fingerprint",
    "eligibility_outcome",
    "eligibility_policy_version",
    "evidence_expires_at",
    "live_read_authorization_id",
    "live_read_authorization_version",
    "worker_identity_registration_id",
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
    "endpoint_binding_hash",  # SECP-B6 MB-2: immutable SSH endpoint binding digest
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
# WorkerDiscoveryAdmission (SECP-B6 MB-1): every binding fact is immutable; the admitted/consumed
# timestamps are set once; status only advances along the one-time admission lifecycle.
_WORKER_DISCOVERY_ADMISSION_PROTECTED = (
    "organization_id",
    "worker_registration_id",
    "identity_version",
    "discovery_job_id",
    "enrollment_id",
    "execution_target_id",
    "onboarding_id",
    "live_read_authorization_id",
    "authorization_version",
    "endpoint_binding_hash",
    "purpose",
    "nonce",
    "issued_at",
    "expires_at",
)
_WORKER_DISCOVERY_ADMISSION_SET_ONCE = ("admitted_at", "consumed_at")
_WORKER_DISCOVERY_ADMISSION_ALLOWED_TRANSITIONS = {
    (WorkerDiscoveryAdmissionStatus.challenged, WorkerDiscoveryAdmissionStatus.admitted),
    (WorkerDiscoveryAdmissionStatus.challenged, WorkerDiscoveryAdmissionStatus.refused),
    (WorkerDiscoveryAdmissionStatus.challenged, WorkerDiscoveryAdmissionStatus.expired),
    (WorkerDiscoveryAdmissionStatus.admitted, WorkerDiscoveryAdmissionStatus.consumed),
    (WorkerDiscoveryAdmissionStatus.admitted, WorkerDiscoveryAdmissionStatus.refused),
    (WorkerDiscoveryAdmissionStatus.admitted, WorkerDiscoveryAdmissionStatus.expired),
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


# PlanSecretReadinessAuthorization (SECP-002B-1B B1B-PR4 / ADR-021 §G): every bound fact is
# immutable after creation; the approval/revocation metadata + evidence fingerprint are set-once;
# only the closed lifecycle transitions are allowed. The service mutates via Core CAS (which
# bypasses this ORM guard), so the migration installs a PostgreSQL trigger for the raw/Core path —
# this guard is the portable (SQLite + PostgreSQL) ORM-path layer + defence in depth.
_PLAN_SECRET_AUTHORIZATION_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "target_onboarding_id",
    "deployment_plan_id",
    "provisioning_manifest_id",
    "toolchain_profile_id",
    "eligibility_preflight_id",
    "remote_state_readiness_id",
    "toolchain_attestation_id",
    "credential_binding_id",
    "credential_binding_version",
    "worker_identity_registration_id",
    "worker_identity_version",
    "provisioning_manifest_content_hash",
    "target_config_hash",
    "onboarding_boundary_hash",
    "eligibility_evidence_hash",
    "toolchain_profile_hash",
    "toolchain_attestation_hash",
    "remote_state_evidence_hash",
    "activation_dossier_hash",
    "purpose",
    "credential_reference_scheme",
    "resolver_contract_version",
    "readiness_policy_version",
    "operation_fingerprint",
    "authorization_expiry",
    "authorization_version",
    "created_by",
    "created_at",
)
_PLAN_SECRET_AUTHORIZATION_SET_ONCE = (
    "evidence_fingerprint",
    "approved_by",
    "approved_at",
    "revoked_by",
    "revoked_at",
    "revocation_reason_code",
)
_PLAN_SECRET_AUTHORIZATION_ALLOWED_TRANSITIONS = {
    (PlanSecretAuthorizationStatus.draft, PlanSecretAuthorizationStatus.approved),
    (PlanSecretAuthorizationStatus.draft, PlanSecretAuthorizationStatus.revoked),
    (PlanSecretAuthorizationStatus.draft, PlanSecretAuthorizationStatus.expired),
    (PlanSecretAuthorizationStatus.approved, PlanSecretAuthorizationStatus.revoked),
    (PlanSecretAuthorizationStatus.approved, PlanSecretAuthorizationStatus.expired),
}


# B1B-PR5A (ADR-022): the activation dossier + plan-generation authorization bind facts immutably;
# approval/revocation/supersession metadata + the evidence fingerprint are set-once; only the closed
# lifecycle transitions are allowed. Services mutate via Core CAS (which the migration guards with a
# PostgreSQL trigger); this ORM guard is the portable defence-in-depth layer.
_ACTIVATION_DOSSIER_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "target_onboarding_id",
    "deployment_plan_id",
    "environment_version_id",
    "provisioning_manifest_id",
    "toolchain_profile_id",
    "toolchain_attestation_id",
    "worker_identity_registration_id",
    "worker_identity_version",
    "provider_credential_binding_id",
    "provider_credential_binding_version",
    "state_credential_binding_id",
    "state_credential_binding_version",
    "environment_version_content_hash",
    "deployment_plan_content_hash",
    "provisioning_manifest_content_hash",
    "target_config_hash",
    "onboarding_boundary_hash",
    "toolchain_profile_hash",
    "toolchain_attestation_hash",
    "state_namespace_hash",
    "recovery_owner_proof",
    "emergency_stop_owner_proof",
    "operation_kind",
    "dossier_revision",
    "dossier_hash",
    "authorization_expiry",
    "created_by",
    "created_at",
)
_ACTIVATION_DOSSIER_SET_ONCE = (
    "evidence_fingerprint",
    "approved_by",
    "approved_at",
    "revoked_by",
    "revoked_at",
    "superseded_by",
    "superseded_at",
    "revocation_reason_code",
)
_PLAN_GENERATION_AUTHORIZATION_PROTECTED = (
    "organization_id",
    "execution_target_id",
    "target_onboarding_id",
    "deployment_plan_id",
    "provisioning_manifest_id",
    "toolchain_profile_id",
    "activation_dossier_id",
    "eligibility_preflight_id",
    "toolchain_attestation_id",
    "remote_state_readiness_id",
    "plan_secret_readiness_id",
    "provider_credential_binding_id",
    "provider_credential_binding_version",
    "state_credential_binding_id",
    "state_credential_binding_version",
    "worker_identity_registration_id",
    "worker_identity_version",
    "provisioning_manifest_content_hash",
    "target_config_hash",
    "onboarding_boundary_hash",
    "eligibility_evidence_hash",
    "toolchain_profile_hash",
    "toolchain_attestation_hash",
    "remote_state_evidence_hash",
    "plan_secret_evidence_hash",
    "activation_dossier_hash",
    "dossier_evidence_fingerprint",
    "purpose",
    "plan_only_capability_contract_version",
    "readiness_policy_version",
    "operation_fingerprint",
    "authorization_expiry",
    "authorization_version",
    "created_by",
    "created_at",
)
_PLAN_GENERATION_AUTHORIZATION_SET_ONCE = (
    "evidence_fingerprint",
    "approved_by",
    "approved_at",
    "revoked_by",
    "revoked_at",
    "consumed_by",
    "consumed_at",
    "revocation_reason_code",
)


def _dossier_parent_status(session: Session, evidence):  # noqa: ANN001, ANN202
    from secp_api.plan_activation_models import RealLabActivationDossier

    parent = session.get(RealLabActivationDossier, evidence.dossier_id)
    if parent is None:
        parent = getattr(evidence, "dossier", None)
    return None if parent is None else parent.status


def _guard_dossier_evidence(session: Session, evidence, verb: str) -> None:  # noqa: ANN001
    from secp_api.enums import ActivationDossierStatus

    status = _dossier_parent_status(session, evidence)
    if status is not None and status != ActivationDossierStatus.draft:
        raise ImmutableResourceError(
            f"RealLabActivationDossierEvidence may not be {verb} once the dossier is "
            f"{getattr(status, 'value', status)!r}; evidence is managed only while draft"
        )


def _guard_plan_activation_mutation(session: Session, obj: object) -> None:
    """B1B-PR5A dirty-mutation guard for the dossier, its evidence, and the plan-gen auth."""
    from secp_api.enums import (
        ActivationDossierStatus,
        PlanExecutionLeaseStatus,
        PlanGenerationAttemptStatus,
        PlanGenerationAuthorizationStatus,
    )
    from secp_api.plan_activation_models import (
        PlanGenerationExecutionLease,
        RealLabActivationDossier,
        RealLabActivationDossierEvidence,
        RealPlanGenerationAttempt,
        RealPlanGenerationAuthorization,
        RealPlanGenerationResult,
    )

    _dossier_transitions = {
        (ActivationDossierStatus.draft, ActivationDossierStatus.approved),
        (ActivationDossierStatus.draft, ActivationDossierStatus.revoked),
        (ActivationDossierStatus.draft, ActivationDossierStatus.expired),
        (ActivationDossierStatus.draft, ActivationDossierStatus.superseded),
        (ActivationDossierStatus.approved, ActivationDossierStatus.revoked),
        (ActivationDossierStatus.approved, ActivationDossierStatus.expired),
        (ActivationDossierStatus.approved, ActivationDossierStatus.superseded),
    }
    _authz_transitions = {
        (PlanGenerationAuthorizationStatus.draft, PlanGenerationAuthorizationStatus.approved),
        (PlanGenerationAuthorizationStatus.draft, PlanGenerationAuthorizationStatus.revoked),
        (PlanGenerationAuthorizationStatus.draft, PlanGenerationAuthorizationStatus.expired),
        (PlanGenerationAuthorizationStatus.approved, PlanGenerationAuthorizationStatus.consumed),
        (PlanGenerationAuthorizationStatus.approved, PlanGenerationAuthorizationStatus.revoked),
        (PlanGenerationAuthorizationStatus.approved, PlanGenerationAuthorizationStatus.expired),
    }

    def _immutable(name, protected, set_once, transitions):  # noqa: ANN001, ANN202
        changed = [a for a in protected if _attr_changed(obj, a)]
        if changed:
            raise ImmutableResourceError(
                f"{name} binding facts are immutable after creation; attempted to change {changed}"
            )
        repeated = [
            a
            for a in set_once
            if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
        ]
        if repeated:
            raise ImmutableResourceError(
                f"{name} approval/lifecycle facts are set-once; attempted to change {repeated}"
            )
        if _attr_changed(obj, "status"):
            previous = _previous_value(obj, "status")
            current = getattr(obj, "status", None)
            if previous is not None and (previous, current) not in transitions:
                raise ImmutableResourceError(
                    f"{name} status transition is not allowed: "
                    f"{getattr(previous, 'value', previous)!r} -> "
                    f"{getattr(current, 'value', current)!r}"
                )

    def _revocation_reason_only_on_revoke(name: str) -> None:
        # B1B-PR5A amendment §4: the revocation reason may become non-empty ONLY on the transition
        # to 'revoked' (the DB CHECK already forbids any value outside the closed set). This mirrors
        # the PostgreSQL trigger on the portable/SQLite layer.
        if _attr_changed(obj, "revocation_reason_code"):
            previous = _previous_value(obj, "revocation_reason_code")
            current = getattr(obj, "revocation_reason_code", "")
            _status = getattr(obj, "status", None)
            status_value = getattr(_status, "value", _status)
            if previous in (None, "") and current not in (None, "") and status_value != "revoked":
                raise ImmutableResourceError(
                    f"{name} revocation_reason_code may be set only when revoking"
                )

    if isinstance(obj, RealLabActivationDossier):
        _immutable(
            "RealLabActivationDossier",
            _ACTIVATION_DOSSIER_PROTECTED,
            _ACTIVATION_DOSSIER_SET_ONCE,
            _dossier_transitions,
        )
        _revocation_reason_only_on_revoke("RealLabActivationDossier")
    elif isinstance(obj, RealPlanGenerationAuthorization):
        _immutable(
            "RealPlanGenerationAuthorization",
            _PLAN_GENERATION_AUTHORIZATION_PROTECTED,
            _PLAN_GENERATION_AUTHORIZATION_SET_ONCE,
            _authz_transitions,
        )
        _revocation_reason_only_on_revoke("RealPlanGenerationAuthorization")
    elif isinstance(obj, RealLabActivationDossierEvidence):
        _guard_dossier_evidence(session, obj, "changed")
    elif isinstance(obj, RealPlanGenerationAttempt):
        # B1B-PR5B: the attempt carries the execution lifecycle with a TIGHT transition guard (the
        # ORM counterpart to the ``secp_real_plan_generation_attempt_transition`` PG trigger).
        # Binding facts stay immutable; only the allowed status edges are permitted.
        _attempt_protected = (
            "organization_id",
            "authorization_id",
            "authorization_version",
            "execution_target_id",
            "deployment_plan_id",
            "provisioning_manifest_id",
            "target_onboarding_id",
            "activation_dossier_id",
            "operation_fingerprint",
            "collected_at",
        )
        _S = PlanGenerationAttemptStatus
        _attempt_transitions = {
            (_S.requested, _S.running),
            (_S.requested, _S.refused),
            (_S.requested, _S.failed),
            (_S.requested, _S.recovery_required),
            (_S.running, _S.completed),
            (_S.running, _S.failed),
            (_S.running, _S.recovery_required),
        }
        _immutable("RealPlanGenerationAttempt", _attempt_protected, (), _attempt_transitions)
    elif isinstance(obj, RealPlanGenerationResult):
        # B1B-PR5B: the durable result is fully immutable (append-only) — no field may change.
        raise ImmutableResourceError(
            "RealPlanGenerationResult records are immutable after insert (append-only)"
        )
    elif isinstance(obj, PlanGenerationExecutionLease):
        # B1B-PR5B: the lease binding facts are immutable; only the guarded control transitions are
        # permitted (the ORM counterpart to the ``secp_plan_generation_execution_lease_guard``
        # PostgreSQL trigger). ``attempts_used`` is monotonic non-decreasing.
        _lease_protected = (
            "organization_id",
            "authorization_id",
            "authorization_version",
            "authorization_expiry",
            "provisioning_manifest_id",
            "provisioning_manifest_content_hash",
            "deployment_plan_id",
            "environment_version_id",
            "execution_target_id",
            "target_config_hash",
            "target_onboarding_id",
            "onboarding_boundary_hash",
            "activation_dossier_id",
            "activation_dossier_hash",
            "activation_dossier_revision",
            "eligibility_preflight_id",
            "eligibility_evidence_hash",
            "toolchain_profile_id",
            "toolchain_profile_hash",
            "toolchain_attestation_id",
            "toolchain_attestation_hash",
            "worker_identity_registration_id",
            "worker_identity_version",
            "provider_credential_binding_id",
            "provider_credential_binding_version",
            "state_credential_binding_id",
            "state_credential_binding_version",
            "remote_state_readiness_id",
            "remote_state_evidence_hash",
            "plan_secret_readiness_id",
            "plan_secret_evidence_hash",
            "operation_fingerprint",
            "lease_epoch",
            "attempt_budget",
            "acquired_at",
        )
        _L = PlanExecutionLeaseStatus
        _lease_transitions = {
            (_L.active, _L.consumed),
            (_L.active, _L.expired),
            (_L.active, _L.recovery_required),
        }
        _immutable(
            "PlanGenerationExecutionLease",
            _lease_protected,
            ("result_id", "consumed_at", "recovery_reason_code"),
            _lease_transitions,
        )
        if _attr_changed(obj, "attempts_used"):
            prev = _previous_value(obj, "attempts_used")
            current_used = int(getattr(obj, "attempts_used", 0) or 0)
            if isinstance(prev, int) and current_used < prev:
                raise ImmutableResourceError(
                    "PlanGenerationExecutionLease attempts_used cannot decrease"
                )


def _plan_secret_parent_status(
    session: Session, evidence: PlanSecretReadinessEvidence
) -> PlanSecretAuthorizationStatus | None:
    """The lifecycle status of an evidence row's parent authorization (identity-map first)."""
    parent = session.get(PlanSecretReadinessAuthorization, evidence.authorization_id)
    if parent is None:
        parent = evidence.authorization  # fall back to the relationship (unflushed insert)
    return None if parent is None else parent.status


def _guard_plan_secret_evidence(
    session: Session, evidence: PlanSecretReadinessEvidence, verb: str
) -> None:
    status = _plan_secret_parent_status(session, evidence)
    if status is not None and status != PlanSecretAuthorizationStatus.draft:
        raise ImmutableResourceError(
            f"PlanSecretReadinessEvidence may not be {verb} once the authorization is "
            f"{getattr(status, 'value', status)!r}; evidence is managed only while draft"
        )


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
        # TopologyRevision (SECP-B9): content/hash/binding immutable; only status
        # and set-once decision metadata may change. A new edit is a new revision.
        if isinstance(obj, TopologyRevision):
            changed = [a for a in _TOPOLOGY_REVISION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "TopologyRevision content is immutable after creation; "
                    f"attempted to change {changed}. Create a new revision instead."
                )
            repeated = [
                a
                for a in _TOPOLOGY_REVISION_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    "TopologyRevision decision metadata is set-once; "
                    f"attempted to change {repeated}"
                )
            if _attr_changed(obj, "status"):
                previous = _previous_value(obj, "status")
                if (
                    previous is not None
                    and (previous, obj.status) not in _TOPOLOGY_REVISION_ALLOWED_TRANSITIONS
                ):
                    raise ImmutableResourceError(
                        "TopologyRevision status transition is not allowed: "
                        f"{getattr(previous, 'value', previous)!r} -> "
                        f"{getattr(obj.status, 'value', obj.status)!r}"
                    )
        # TopologyValidationResult (SECP-B9): append-only, fully immutable.
        if isinstance(obj, TopologyValidationResult):
            changed = [a for a in _TOPOLOGY_VALIDATION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "TopologyValidationResult is immutable after recording; "
                    f"attempted to change {changed}"
                )
        # WorkerDiscoveryAdmission (SECP-B6 MB-1): binding facts immutable; admitted/consumed
        # timestamps set once; status advances only along the one-time admission lifecycle.
        if isinstance(obj, WorkerDiscoveryAdmission):
            changed = [a for a in _WORKER_DISCOVERY_ADMISSION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "WorkerDiscoveryAdmission binding fields are immutable; "
                    f"attempted to change {changed}"
                )
            repeated = [
                a
                for a in _WORKER_DISCOVERY_ADMISSION_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    "WorkerDiscoveryAdmission admitted/consumed timestamps are set-once; "
                    f"attempted to change {repeated}"
                )
            if _attr_changed(obj, "status"):
                previous = _previous_value(obj, "status")
                admission_transition = (previous, obj.status)
                if (
                    previous is not None
                    and admission_transition not in _WORKER_DISCOVERY_ADMISSION_ALLOWED_TRANSITIONS
                ):
                    raise ImmutableResourceError(
                        "WorkerDiscoveryAdmission status transition is not allowed: "
                        f"{getattr(previous, 'value', previous)!r} -> "
                        f"{getattr(obj.status, 'value', obj.status)!r}"
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
        # B1B-PR4: readiness EVIDENCE (incl. the durable toolchain attestation) is fully immutable
        # after insert. A prior successful record is NEVER mutated into failure by later drift or
        # expiry — validity is DERIVED, and a new attempt creates a new immutable record under a new
        # operation fingerprint (ADR-021 §N).
        if isinstance(
            obj,
            RemoteStateReadinessRecord | PlanSecretReadinessRecord | ToolchainAttestationRecord,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records are immutable after insert")
        # B1B-PR4/PR5A: an ExecutionTarget whose credential reference changes MUST rotate the
        # MATCHING opaque credential binding. This is the portable (SQLite + PostgreSQL) ORM layer;
        # the migration additionally installs a PostgreSQL trigger for the raw/Core path. Rotation
        # is
        # not a caller decision — a credential replacement can never be invisible.
        #
        # B1B-PR5A amendment §1 — rotate ONLY the matching binding, and ONLY when its OWN source
        # reference actually changes:
        #   * provider_plan_read rotates when the DEDICATED ``provider_plan_secret_ref`` changes
        #     (which may flip the binding's source class dedicated<->legacy), OR when the generic
        #     ``secret_ref`` changes WHILE no dedicated reference is set (so the resolved fallback
        #     reference changed). A ``secret_ref`` change while a dedicated reference is present
        #     does NOT rotate the (dedicated, real-plan) binding — a legacy ref cannot refresh it.
        #   * state_backend_plan rotates ONLY when ``state_backend_secret_ref`` changes.
        if isinstance(obj, ExecutionTarget):
            from secp_api.credential_binding import rotate_credential_binding
            from secp_api.enums import CredentialPurposeClass as _CPC

            provider_dedicated_changed = _attr_changed(obj, "provider_plan_secret_ref")
            secret_ref_changed = _attr_changed(obj, "secret_ref")
            has_dedicated_provider = obj.provider_plan_secret_ref is not None
            if provider_dedicated_changed or (secret_ref_changed and not has_dedicated_provider):
                session.info[_ROTATION_ANNOUNCED_KEY] = True
                rotate_credential_binding(session, obj, _CPC.provider_plan_read)
            if _attr_changed(obj, "state_backend_secret_ref"):
                session.info[_ROTATION_ANNOUNCED_KEY] = True
                rotate_credential_binding(session, obj, _CPC.state_backend_plan)
        # B1B-PR4 amendment: a credential binding's OPAQUE identity is immutable; only the
        # lifecycle transition active -> rotated/revoked (+ rotated_at) may change.
        if isinstance(obj, CredentialBinding):
            changed = [a for a in _CREDENTIAL_BINDING_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "CredentialBinding identity is immutable after creation; "
                    f"attempted to change {changed}"
                )
        # PlanSecretReadinessAuthorization (B1B-PR4): binding facts immutable; approval/revocation
        # facts + evidence fingerprint set-once; only closed transitions allowed.
        if isinstance(obj, PlanSecretReadinessAuthorization):
            changed = [a for a in _PLAN_SECRET_AUTHORIZATION_PROTECTED if _attr_changed(obj, a)]
            if changed:
                raise ImmutableResourceError(
                    "PlanSecretReadinessAuthorization binding facts are immutable after creation; "
                    f"attempted to change {changed}"
                )
            repeated = [
                a
                for a in _PLAN_SECRET_AUTHORIZATION_SET_ONCE
                if _attr_changed(obj, a) and _previous_value(obj, a) not in (None, "")
            ]
            if repeated:
                raise ImmutableResourceError(
                    "PlanSecretReadinessAuthorization approval/revocation facts are set-once; "
                    f"attempted to change {repeated}"
                )
            if _attr_changed(obj, "status"):
                previous = _previous_value(obj, "status")
                if (
                    previous is not None
                    and (previous, obj.status) not in _PLAN_SECRET_AUTHORIZATION_ALLOWED_TRANSITIONS
                ):
                    raise ImmutableResourceError(
                        "PlanSecretReadinessAuthorization status transition is not allowed: "
                        f"{getattr(previous, 'value', previous)!r} -> "
                        f"{getattr(obj.status, 'value', obj.status)!r}"
                    )
        # PlanSecretReadinessEvidence: managed (changed) only while the authorization is draft.
        if isinstance(obj, PlanSecretReadinessEvidence):
            _guard_plan_secret_evidence(session, obj, "changed")
        # B1B-PR5A: activation dossier + plan-generation authorization binding facts, set-once
        # metadata, closed transitions; evidence managed only while draft; attempts append-only.
        _guard_plan_activation_mutation(session, obj)
        # SECP-B4: content-addressed plans, approvals, and verification results are immutable.
        if isinstance(
            obj,
            StagingDeploymentPlan | StagingDeploymentApproval | StagingDeploymentVerification,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records are immutable after insert")
        # SECP-B5: discovery evidence snapshots, candidate plans, and approvals are immutable.
        if isinstance(
            obj,
            DiscoverySnapshot | DiscoveryCandidatePlan | DiscoveryCandidatePlanApproval,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records are immutable after insert")
        # AuditEvent: append-only.
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records are immutable")

    for obj in session.new:
        # EnvironmentVersion: a new row must be a coherent v1alpha1 legacy row or a fully
        # server-mirrored v1alpha2 published row (SECP-B10 / ADR-016). No fabricated bypass.
        if isinstance(obj, EnvironmentVersion):
            _guard_version_insert(obj)
        # ResolverActivationEvidence: cannot be inserted once the authorization leaves draft.
        if isinstance(obj, ResolverActivationEvidence):
            _guard_resolver_evidence(session, obj, "inserted")
        # WorkerIdentityEvidence: cannot be inserted once the registration leaves draft.
        if isinstance(obj, WorkerIdentityEvidence):
            _guard_worker_identity_evidence(session, obj, "inserted")
        # PlanSecretReadinessEvidence: cannot be inserted once the authorization leaves draft.
        if isinstance(obj, PlanSecretReadinessEvidence):
            _guard_plan_secret_evidence(session, obj, "inserted")
        # B1B-PR5A: dossier evidence cannot be inserted once the dossier leaves draft.
        from secp_api.plan_activation_models import RealLabActivationDossierEvidence as _RLADE

        if isinstance(obj, _RLADE):
            _guard_dossier_evidence(session, obj, "inserted")

    for obj in session.deleted:
        # B1B-PR5A: activation dossier + plan-generation authorization + attempts cannot be deleted;
        # dossier evidence cannot be deleted once the dossier leaves draft.
        from secp_api.plan_activation_models import (
            PlanGenerationExecutionLease as _PGEL,
        )
        from secp_api.plan_activation_models import (
            RealLabActivationDossier as _RLAD,
        )
        from secp_api.plan_activation_models import (
            RealLabActivationDossierEvidence as _RLADE2,
        )
        from secp_api.plan_activation_models import (
            RealPlanGenerationAttempt as _RPGA,
        )
        from secp_api.plan_activation_models import (
            RealPlanGenerationAuthorization as _RPGAuthz,
        )
        from secp_api.plan_activation_models import (
            RealPlanGenerationResult as _RPGRes,
        )

        if isinstance(obj, _RLAD | _RPGAuthz | _RPGA | _RPGRes | _PGEL):
            raise ImmutableResourceError(f"{type(obj).__name__} records cannot be deleted")
        if isinstance(obj, _RLADE2):
            _guard_dossier_evidence(session, obj, "deleted")
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
        if isinstance(obj, WorkerDiscoveryAdmission):
            raise ImmutableResourceError("WorkerDiscoveryAdmission records cannot be deleted")
        if isinstance(obj, WorkerIdentityEvidence):
            _guard_worker_identity_evidence(session, obj, "deleted")
        if isinstance(obj, LivePreflightEvidence):
            raise ImmutableResourceError("LivePreflightEvidence records cannot be deleted")
        # B1B-PR4: readiness evidence + the plan-secret authorization are append-only evidence.
        if isinstance(
            obj,
            RemoteStateReadinessRecord | PlanSecretReadinessRecord | ToolchainAttestationRecord,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records cannot be deleted")
        if isinstance(obj, CredentialBinding):
            raise ImmutableResourceError("CredentialBinding records cannot be deleted")
        if isinstance(obj, PlanSecretReadinessAuthorization):
            raise ImmutableResourceError(
                "PlanSecretReadinessAuthorization records cannot be deleted"
            )
        if isinstance(obj, PlanSecretReadinessEvidence):
            _guard_plan_secret_evidence(session, obj, "deleted")
        # SECP-B4: content-addressed plans, approvals, and verification results cannot be deleted
        # outside an explicit governed archival path (none exists yet), preserving the audit chain.
        if isinstance(
            obj,
            StagingDeploymentPlan | StagingDeploymentApproval | StagingDeploymentVerification,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records cannot be deleted")
        # SECP-B5: discovery snapshots/candidate plans/approvals cannot be deleted outside a
        # governed
        # archival path (none exists yet), preserving the discovery evidence + approval chain.
        if isinstance(
            obj,
            DiscoverySnapshot | DiscoveryCandidatePlan | DiscoveryCandidatePlanApproval,
        ):
            raise ImmutableResourceError(f"{type(obj).__name__} records cannot be deleted")
        if isinstance(obj, AuditEvent):
            raise ImmutableResourceError("AuditEvent records cannot be deleted")
        # SECP-B9: topology revisions and validation results are append-only evidence.
        if isinstance(obj, TopologyRevision | TopologyValidationResult):
            raise ImmutableResourceError(f"{type(obj).__name__} records cannot be deleted")


@event.listens_for(Session, "after_flush")
def _clear_credential_rotation_flag(session: Session, _flush_context) -> None:
    """Retire the transaction-scoped ``secp.credential_rotation`` announcement (B1B-PR4 §2).

    ``rotate_credential_binding`` sets it so the PostgreSQL ``execution_target`` trigger knows the
    SUPPORTED ORM path already rotated, and does not rotate a second time. Clearing it immediately
    after the flush means a LATER raw/Core ``UPDATE`` in the same transaction is still caught and
    auto-rotated by the trigger: the announcement covers exactly one flush and nothing more.

    The announcement lives in THIS session's ``info`` — never a module global — so a concurrent
    session can never clear it out from under us and leave ``secp.credential_rotation`` stuck on.
    """
    if not session.info.pop(_ROTATION_ANNOUNCED_KEY, False):
        return
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    session.execute(text("SET LOCAL secp.credential_rotation = 'off'"))


def install_guards() -> None:
    """Idempotent import hook. Importing this module registers the listeners."""
    return None
