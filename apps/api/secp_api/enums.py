"""Shared enumerations: lifecycle states, plan/workflow status, audit actions."""

from __future__ import annotations

from enum import Enum


class LifecycleState(str, Enum):
    """The authoritative environment/exercise lifecycle (Charter §6, design §7/§9)."""

    draft = "draft"
    validated = "validated"
    planned = "planned"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    deploying = "deploying"
    running = "running"
    resetting = "resetting"
    destroying = "destroying"
    destroyed = "destroyed"
    failed = "failed"


class PlanStatus(str, Enum):
    generated = "generated"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    rejected = "rejected"
    applied = "applied"


class TargetStatus(str, Enum):
    """Lifecycle status of an ExecutionTarget (ADR-006)."""

    active = "active"
    disabled = "disabled"
    discovery_failed = "discovery_failed"


class ReservationStatus(str, Enum):
    """Status of a network address-space reservation (ADR-009)."""

    reserved = "reserved"
    released = "released"


class SnapshotStatus(str, Enum):
    """Status of a provider inventory snapshot (ADR-008)."""

    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ProvisioningOperationKind(str, Enum):
    """The kind of provisioning operation (SECP-002B-0/1A, ADR-012/013).

    ``dry_run`` previews an apply; ``destroy_dry_run`` previews a destroy. Apply and
    destroy each require a human-approved change set produced by the matching dry run
    (SECP-002B-1A).
    """

    dry_run = "dry_run"
    apply = "apply"
    destroy = "destroy"
    destroy_dry_run = "destroy_dry_run"


class ProvisioningStatus(str, Enum):
    """Durable provisioning-operation lifecycle (SECP-002B-0/1A, ADR-011/012/013)."""

    manifest_generated = "manifest_generated"
    pending_approval = "pending_approval"
    queued = "queued"
    dry_run_completed = "dry_run_completed"
    destroy_dry_run_completed = "destroy_dry_run_completed"
    awaiting_change_set_approval = "awaiting_change_set_approval"
    applying = "applying"
    applied = "applied"
    failed = "failed"
    destroy_queued = "destroy_queued"
    destroyed = "destroyed"


class ToolchainProfileStatus(str, Enum):
    """Lifecycle status of an immutable toolchain profile (SECP-002B-1A, ADR-013)."""

    active = "active"
    disabled = "disabled"


class ChangeSetApprovalStatus(str, Enum):
    """Lifecycle of a human approval of an exact dry-run change set (SECP-002B-1A)."""

    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    consumed = "consumed"


class OnboardingMode(str, Enum):
    """How a target is brought under SECP management (SECP-002B-1B-0, ADR-014).

    ``clean_server`` — the user brings a new/empty eligible server; SECP guides safe
    setup and then creates scenario infrastructure automatically.
    ``existing_environment`` — the user selects an existing node/cluster and declares an
    explicit, enforceable boundary; SECP deploys only inside it.
    """

    clean_server = "clean_server"
    existing_environment = "existing_environment"


class IsolationModel(str, Enum):
    """Target isolation model (SECP-002B-1B-0, ADR-014).

    ``physical`` — a dedicated host/cluster (recommended secure preset).
    ``logical`` — a shared environment with an explicitly declared, enforceable,
    auditable, independently verifiable logical isolation boundary.
    """

    physical = "physical"
    logical = "logical"


class OnboardingStatus(str, Enum):
    """Target onboarding lifecycle (SECP-002B-1B-0, ADR-014).

    A target may only be cleared for real provisioning once its onboarding reaches
    ``active`` (approved + activated with no config/scope drift).
    """

    draft = "draft"
    preflight_pending = "preflight_pending"
    ready_for_review = "ready_for_review"
    approved = "approved"
    active = "active"
    rejected = "rejected"
    retired = "retired"


class NetworkApproach(str, Enum):
    """How the lab network segment is provided for an onboarding (SECP-002B-1B-0.1).

    ``use_approved_existing_segment`` — the operator constrains the boundary to the target's
    already-approved network segments (no network is created). ``secp_managed_dedicated_segment``
    — SECP is *intended* to create a dedicated bridge/VNet later; in this release it is a durable
    declaration only (activation pending — **no** bridge/VNet is created and nothing real is
    contacted). Provider-neutral.
    """

    use_approved_existing_segment = "use_approved_existing_segment"
    secp_managed_dedicated_segment = "secp_managed_dedicated_segment"


class IsolationProfile(str, Enum):
    """Network isolation posture declared for an onboarding boundary (SECP-002B-1B-0.1).

    Only ``fully_segregated`` is available in this release: no Internet, no default route, and
    no path to management/home/corporate/storage/public networks. The remaining profiles are
    declared for the roadmap but are **rejected server-side** (not merely disabled in the UI)
    until a separately reviewed change enables them. No NAT/gateway/firewall/egress behaviour
    is introduced here.
    """

    fully_segregated = "fully_segregated"
    internet_egress_only = "internet_egress_only"
    controlled_service_access = "controlled_service_access"
    advanced_custom_policy = "advanced_custom_policy"


class PreflightCheckStatus(str, Enum):
    """Outcome of a single onboarding preflight check (SECP-002B-1B-0)."""

    passed = "passed"
    failed = "failed"
    warning = "warning"
    skipped = "skipped"


class VerificationLevel(str, Enum):
    """Trust level of preflight evidence (SECP-002B-1B-0, ADR-014).

    ``simulated`` — deterministically derived from the declared boundary; useful for
    onboarding UX/review but **never** proof of live infrastructure and never sufficient
    for live real provisioning. ``live_verified`` — collected by a trusted worker-only
    provider collector against a real (reviewed disposable) target (future B1-B).
    """

    simulated = "simulated"
    live_verified = "live_verified"


class CollectorKind(str, Enum):
    """Which collector produced preflight evidence (SECP-002B-1B-0, ADR-014).

    ``fake_declared_boundary`` derives simulated evidence from the declared boundary and
    inspects nothing real. ``provider_worker`` is the future trusted worker-only collector
    that produces ``live_verified`` evidence. Arbitrary/caller-supplied kinds are refused.
    """

    fake_declared_boundary = "fake_declared_boundary"
    provider_worker = "provider_worker"


class EvidenceStatus(str, Enum):
    """Summary status for provider-neutral read-only target evidence (SECP-002B-1B-1)."""

    passed = "pass"
    failed = "fail"
    unverifiable = "unverifiable"


class LiveReadAuthorizationStatus(str, Enum):
    """Durable live-read authorization lifecycle (SECP-002B-1B-6).

    This is an authorization contract only. It does not enable collection, configure a
    target, or resolve any secret.
    """

    draft = "draft"
    approved = "approved"
    revoked = "revoked"
    expired = "expired"


class StagingLabPurpose(str, Enum):
    """Why a disposable staging lab exists (SECP-002B-1B-9).

    Only ``disposable_readonly_staging`` is available: a bounded, reversible lab used to
    functionally validate the read-only control plane. It is not for running workloads.
    """

    disposable_readonly_staging = "disposable_readonly_staging"


class StagingLabProfile(str, Enum):
    """Provider-neutral substrate profile for a staging lab (SECP-002B-1B-9).

    Only ``nested_proxmox`` is available: a disposable nested Proxmox target on an approved
    substrate. It is a functional test substrate, never a hardware/hypervisor isolation boundary.
    """

    nested_proxmox = "nested_proxmox"


class StagingNetworkIntent(str, Enum):
    """Logical network intent for a staging lab (SECP-002B-1B-9).

    ``host_only_no_uplink`` is the only accepted intent: an internal, host-only segment with no
    physical uplink, no gateway, and no DNS. ``shared_or_production`` names a disallowed intent
    that the compiler rejects fail-closed (it is never emitted into a plan).
    """

    host_only_no_uplink = "host_only_no_uplink"
    shared_or_production = "shared_or_production"


class StagingResourceClass(str, Enum):
    """Bounded logical resource class for a staging lab (SECP-002B-1B-9).

    Safe, coarse logical sizes only — never raw host CPU/RAM/disk values. Real sizing against
    verified host headroom happens out of band; SECP stores only the chosen logical class.
    """

    small_lab = "small_lab"
    medium_lab = "medium_lab"


class StagingBootstrapArtifactProfile(str, Enum):
    """Backend catalog of approved offline bootstrap-artifact profiles (SECP-002B-1B-9).

    A closed server-owned enum — never a caller-supplied artifact id, path, URL, or checksum.
    Each value names an operator-approved, pre-staged offline artifact set resolved out of band.
    """

    nested_proxmox_offline_base = "nested_proxmox_offline_base"


class StagingWorkOperation(str, Enum):
    """Durable staging-lab work-item operation kind (SECP-002B-1B-9, fake-only)."""

    simulate_provision = "simulate_provision"
    simulate_teardown = "simulate_teardown"


class StagingWorkStatus(str, Enum):
    """Durable staging-lab work-item lifecycle (SECP-002B-1B-9).

    The API may only create ``queued`` items. Only the worker may move an item to ``claimed`` and
    then ``completed`` / ``failed`` / ``refused``.
    """

    queued = "queued"
    claimed = "claimed"
    completed = "completed"
    failed = "failed"
    refused = "refused"


class StagingSubstrateEligibilityStatus(str, Enum):
    """Durable staging-substrate eligibility lifecycle (SECP-002B-1B-9)."""

    active = "active"
    revoked = "revoked"


class StagingLabDecisionCode(str, Enum):
    """Closed set of staging-lab decision/outcome codes (SECP-002B-1B-9).

    Replaces all free-text approval/rejection reasons. Never caller-supplied arbitrary text.
    """

    pending = "pending"
    approved = "approved"
    rejected_plan_drift = "rejected_plan_drift"
    rejected_lifecycle = "rejected_lifecycle"
    rejected_policy = "rejected_policy"
    refused_ownership = "refused_ownership"
    refused_concurrency = "refused_concurrency"
    failed_internal = "failed_internal"


class StagingWorkFailureCode(str, Enum):
    """Closed set of durable work-item failure/refusal codes (SECP-002B-1B-9).

    Never an arbitrary string — every refusal maps to one of these safe codes.
    """

    lab_missing = "lab_missing"
    cross_org = "cross_org"
    plan_drift = "plan_drift"
    approval_mismatch = "approval_mismatch"
    ownership_mismatch = "ownership_mismatch"
    stale_lifecycle = "stale_lifecycle"
    lifecycle_raced = "lifecycle_raced"
    blast_radius = "blast_radius"
    stale_completion = "stale_completion"
    internal = "internal"


class StagingRollbackPolicy(str, Enum):
    """How a staging lab is returned to a known-clean state (SECP-002B-1B-9)."""

    revert_to_known_clean_checkpoint = "revert_to_known_clean_checkpoint"
    destroy_and_rebuild = "destroy_and_rebuild"


class StagingLabStatus(str, Enum):
    """Application-owned disposable staging-lab lifecycle (SECP-002B-1B-9).

    Fake-only. Reaching ``simulated_ready`` means a labeled simulation completed; it creates no
    infrastructure and is never live read-only collection. ``approved`` is permission to enter
    fake simulation only — it is NOT a :class:`LiveReadAuthorizationStatus` grant.
    """

    draft = "draft"
    planned = "planned"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    simulation_queued = "simulation_queued"
    simulating = "simulating"
    simulated_ready = "simulated_ready"
    teardown_queued = "teardown_queued"
    tearing_down = "tearing_down"
    destroyed = "destroyed"
    failed = "failed"


class ProvisioningApplicationMode(str, Enum):
    """Which provisioning path a request targets (SECP-002B-1A, ADR-013).

    ``simulator`` is the unchanged default. ``isolated_lab`` is the only mode eligible
    for the real, worker-only OpenTofu path, and only behind the full activation gate.
    """

    simulator = "simulator"
    isolated_lab = "isolated_lab"


class WorkflowKind(str, Enum):
    deploy = "deploy"
    reset = "reset"
    destroy = "destroy"
    discover = "discover"  # provider inventory discovery (read-only)


class WorkflowStatus(str, Enum):
    queued = "queued"  # created by the API, awaiting worker execution (ADR-010)
    running = "running"
    completed = "completed"
    failed = "failed"


class Permission(str, Enum):
    """Coarse RBAC permissions gating sensitive control-plane actions."""

    template_author = "template:author"
    version_create = "version:create"
    exercise_operate = "exercise:operate"
    plan_generate = "plan:generate"
    plan_approve = "plan:approve"
    exercise_apply = "exercise:apply"
    exercise_reset = "exercise:reset"
    exercise_destroy = "exercise:destroy"
    audit_read = "audit:read"
    # SECP-002A — provider targets and read-only discovery.
    target_manage = "target:manage"
    inventory_discover = "inventory:discover"
    inventory_read = "inventory:read"
    # SECP-002B-0 — provisioning safety harness (manifests + fake runner).
    provisioning_manage = "provisioning:manage"
    provisioning_read = "provisioning:read"
    # SECP-002B-1A — sealed OpenTofu runner, toolchain profiles, change-set approval.
    toolchain_manage = "toolchain:manage"
    provisioning_approve = "provisioning:approve"
    # SECP-002B-1B-0 — target onboarding and automated deployment contract.
    onboarding_manage = "onboarding:manage"
    onboarding_approve = "onboarding:approve"
    # SECP-002B-1B-9 — declarative disposable staging-lab workflow (fake-only).
    staging_lab_manage = "staging_lab:manage"
    staging_lab_approve = "staging_lab:approve"
    # Granting a target staging-substrate eligibility is a target-admin action, NOT a
    # lab-creator action — deliberately separate from staging_lab:manage.
    staging_substrate_manage = "staging_substrate:manage"
    # SECP-B2-0 — app-owned read-only staging preflight (admin action). Requesting a preflight
    # is deliberately distinct from staging-lab management and from onboarding approval.
    staging_preflight_manage = "staging_preflight:manage"
    # SECP-B2-4.1 — durable resolver-activation authorization. Creating/revoking is an admin action;
    # APPROVING is a DELIBERATELY SEPARATE permission that cannot be inferred from any other
    # (onboarding, staging-lab, live-read). It never grants infrastructure execution or resolution.
    resolver_activation_manage = "resolver_activation:manage"
    resolver_activation_approve = "resolver_activation:approve"
    # SECP-B2-4.3 — durable worker-identity trust anchor. Registering/revoking is an admin action;
    # APPROVING is a DELIBERATELY SEPARATE permission that can never be inferred from
    # worker_identity:manage (or any other approval). It authenticates no worker, enables nothing.
    worker_identity_manage = "worker_identity:manage"
    worker_identity_approve = "worker_identity:approve"


class ReadonlyPreflightStatus(str, Enum):
    """App-owned read-only staging-preflight lifecycle (SECP-B2-0).

    The API may only create durable ``queued`` intent. Only the worker may move a preflight to
    ``claimed`` / ``running`` and then to a terminal state, recording a closed outcome code.
    """

    queued = "queued"
    claimed = "claimed"
    running = "running"
    completed = "completed"
    failed = "failed"
    refused = "refused"


class ReadonlyPreflightOutcome(str, Enum):
    """Closed set of safe preflight outcome codes (SECP-B2-0).

    Never free text. A successful ``ready`` proves only the specific readiness facts collected —
    it never asserts the host is isolated or production-safe beyond that evidence.
    """

    ready = "ready"
    not_ready = "not_ready"
    authorization_expired = "authorization_expired"
    authorization_revoked = "authorization_revoked"
    authorization_invalid = "authorization_invalid"
    credential_unavailable = "credential_unavailable"
    tls_or_policy_refused = "tls_or_policy_refused"
    worker_internal_failure = "worker_internal_failure"


class ReadonlyPreflightErrorCode(str, Enum):
    """Closed catalog of read-only preflight API error codes (SECP-B2-0).

    Every read-only-preflight service refusal maps to exactly one of these safe codes. No
    free-form backend message is ever serialized for this feature.
    """

    not_found = "readonly_preflight_not_found"
    forbidden = "readonly_preflight_forbidden"
    substrate_ineligible = "readonly_preflight_substrate_ineligible"
    authorization_invalid = "readonly_preflight_authorization_invalid"
    lifecycle_conflict = "readonly_preflight_lifecycle_conflict"
    queue_conflict = "readonly_preflight_queue_conflict"
    internal_failure = "readonly_preflight_internal_failure"


class ResolverActivationStatus(str, Enum):
    """Closed lifecycle of a durable resolver-activation authorization (SECP-B2-4.1).

    ``draft`` — created, gathering evidence; ``approved`` — separately approved against a complete
    evidence fingerprint; ``revoked`` — terminated immediately (approval facts preserved);
    ``expired`` — past its canonical UTC expiry. Only the worker verifier consumes an ``approved``,
    unexpired, unrevoked record — and even then produces no resolution in shipped runtime.
    """

    draft = "draft"
    approved = "approved"
    revoked = "revoked"
    expired = "expired"


class ResolverActivationEvidenceKind(str, Enum):
    """Closed set of provider-neutral, secret-free activation-evidence items (B2-4.1 / B2-2).

    Each item is proof METADATA only — never an endpoint, backend config, vault path, reference,
    worker credential, token, policy, or secret. Approval requires every kind present + verified.
    """

    isolated_staging_identity = "isolated_staging_identity"
    worker_only_network_path = "worker_only_network_path"
    backend_access_policy_review = "backend_access_policy_review"
    reference_grammar_review = "reference_grammar_review"
    redaction_log_audit_verification = "redaction_log_audit_verification"
    transport_get_only_canonical = "transport_get_only_canonical"
    no_production_or_shared_target = "no_production_or_shared_target"
    rollback_kill_switch_drill = "rollback_kill_switch_drill"
    independent_adversarial_review = "independent_adversarial_review"


class ResolverActivationEvidenceStatus(str, Enum):
    """Closed status of one evidence item. Only ``verified`` counts toward approval completeness."""

    pending = "pending"
    verified = "verified"
    failed = "failed"


class ResolverActivationErrorCode(str, Enum):
    """Closed catalog of resolver-activation API error codes (SECP-B2-4.1). No free-form message."""

    not_found = "resolver_activation_not_found"
    forbidden = "resolver_activation_forbidden"
    invalid_state = "resolver_activation_invalid_state"
    substrate_ineligible = "resolver_activation_substrate_ineligible"
    evidence_incomplete = "resolver_activation_evidence_incomplete"
    evidence_invalid = "resolver_activation_evidence_invalid"
    lifecycle_conflict = "resolver_activation_lifecycle_conflict"
    internal_failure = "resolver_activation_internal_failure"


class WorkerIdentityMechanism(str, Enum):
    """Closed set of worker-identity mechanisms (SECP-B2-4.3). Initially only mTLS workload id.

    A label only — it stores/authorizes no certificate, key, CSR, CA, endpoint, or secret. This PR
    performs NO real mTLS and constructs no attestation; it records only which mechanism a future
    isolated staging worker will use.
    """

    mtls_workload_identity = "mtls_workload_identity"


class WorkerIdentityStatus(str, Enum):
    """Closed lifecycle of a durable worker-identity registration (SECP-B2-4.3).

    ``draft`` — registered, gathering evidence; ``approved`` — separately approved against complete
    evidence fingerprint; ``revoked`` — terminated immediately (approval facts preserved);
    ``expired`` — past its canonical UTC expiry. An ``approved``, unexpired, unrevoked record is the
    ONLY one a worker verifier may consult — and even then it authenticates no real worker.
    """

    draft = "draft"
    approved = "approved"
    revoked = "revoked"
    expired = "expired"


class WorkerIdentityEvidenceKind(str, Enum):
    """Closed set of secret-free worker-identity evidence items (SECP-B2-4.3).

    Each item is proof METADATA only — never a certificate, key, CSR, CA name, endpoint, token, or
    secret. Approval requires every kind present + verified.
    """

    deployment_binding_review = "deployment_binding_review"
    verification_anchor_review = "verification_anchor_review"
    rotation_revocation_review = "rotation_revocation_review"


class WorkerIdentityEvidenceStatus(str, Enum):
    """Closed status of one worker-identity evidence item. Only ``verified`` counts for approval."""

    pending = "pending"
    verified = "verified"
    failed = "failed"


class WorkerIdentityErrorCode(str, Enum):
    """Closed catalog of worker-identity API error codes (SECP-B2-4.3). No free-form message."""

    not_found = "worker_identity_not_found"
    forbidden = "worker_identity_forbidden"
    invalid_state = "worker_identity_invalid_state"
    invalid_metadata = "worker_identity_invalid_metadata"
    evidence_incomplete = "worker_identity_evidence_incomplete"
    lifecycle_conflict = "worker_identity_lifecycle_conflict"
    internal_failure = "worker_identity_internal_failure"


class AuditAction(str, Enum):
    organization_created = "organization.created"
    user_created = "user.created"
    team_created = "team.created"
    template_created = "template.created"
    version_created = "version.created"
    version_mutation_rejected = "version.mutation_rejected"
    exercise_created = "exercise.created"
    exercise_validated = "exercise.validated"
    plan_generated = "plan.generated"
    plan_submitted = "plan.submitted"
    plan_approved = "plan.approved"
    plan_rejected = "plan.rejected"
    apply_refused = "apply.refused"
    execution_refused = "execution.refused"
    deploy_started = "deploy.started"
    deploy_completed = "deploy.completed"
    instance_created = "instance.created"
    reset_started = "reset.started"
    reset_completed = "reset.completed"
    destroy_started = "destroy.started"
    destroy_completed = "destroy.completed"
    lifecycle_transition = "lifecycle.transition"
    authorization_denied = "authorization.denied"
    # SECP-002A — execution targets, discovery, reservations, secret resolution.
    target_created = "target.created"
    target_disabled = "target.disabled"
    discovery_requested = "discovery.requested"
    discovery_started = "discovery.started"
    discovery_completed = "discovery.completed"
    discovery_failed = "discovery.failed"
    secret_resolution_failed = "secret.resolution_failed"
    provider_operation_refused = "provider.operation_refused"
    reservation_created = "reservation.created"
    reservation_released = "reservation.released"
    # SECP-002A plan target-pinning.
    plan_target_bound = "plan.target_bound"
    target_deploy_refused = "deploy.target_refused"
    # SECP-002B-0 — provisioning manifests and fake-runner operations.
    manifest_generated = "manifest.generated"
    manifest_validated = "manifest.validated"
    manifest_generation_refused = "manifest.generation_refused"
    provisioning_operation_created = "provisioning.operation_created"
    provisioning_dry_run_completed = "provisioning.dry_run_completed"
    provisioning_apply_started = "provisioning.apply_started"
    provisioning_applied = "provisioning.applied"
    provisioning_failed = "provisioning.failed"
    provisioning_destroy_queued = "provisioning.destroy_queued"
    provisioning_destroyed = "provisioning.destroyed"
    provisioning_refused = "provisioning.refused"
    # SECP-002B-1A — toolchain profiles, change-set approval, real-lab activation.
    toolchain_profile_created = "toolchain.profile_created"
    toolchain_profile_disabled = "toolchain.profile_disabled"
    toolchain_profile_refused = "toolchain.profile_refused"
    change_set_recorded = "provisioning.change_set_recorded"
    change_set_approved = "provisioning.change_set_approved"
    change_set_rejected = "provisioning.change_set_rejected"
    real_provisioning_refused = "provisioning.real_refused"
    workspace_rendered = "provisioning.workspace_rendered"
    # SECP-002B-1B-0 — target onboarding + automated deployment contract.
    onboarding_created = "onboarding.created"
    onboarding_boundary_declared = "onboarding.boundary_declared"
    onboarding_preflight_recorded = "onboarding.preflight_recorded"
    onboarding_submitted = "onboarding.submitted"
    onboarding_approved = "onboarding.approved"
    onboarding_rejected = "onboarding.rejected"
    onboarding_activated = "onboarding.activated"
    onboarding_retired = "onboarding.retired"
    onboarding_refused = "onboarding.refused"
    onboarding_preflight_requested = "onboarding.preflight_requested"
    target_evidence_collected = "target_evidence.collected"
    target_evidence_compared = "target_evidence.compared"
    # SECP-002B-1B-6 — dormant live-read authorization contract.
    live_read_authorization_created = "live_read.authorization_created"
    live_read_authorization_approved = "live_read.authorization_approved"
    live_read_authorization_revoked = "live_read.authorization_revoked"
    live_read_authorization_validation_refused = "live_read.authorization_validation_refused"
    # SECP-002B-1B-9 — declarative disposable staging-lab workflow (fake-only).
    staging_lab_created = "staging_lab.created"
    staging_lab_planned = "staging_lab.planned"
    staging_lab_submitted = "staging_lab.submitted"
    staging_lab_approved = "staging_lab.approved"
    staging_lab_rejected = "staging_lab.rejected"
    staging_lab_simulation_queued = "staging_lab.simulation_queued"
    staging_lab_simulation_started = "staging_lab.simulation_started"
    staging_lab_simulated_ready = "staging_lab.simulated_ready"
    staging_lab_simulation_failed = "staging_lab.simulation_failed"
    staging_lab_teardown_queued = "staging_lab.teardown_queued"
    staging_lab_teardown_started = "staging_lab.teardown_started"
    staging_lab_destroyed = "staging_lab.destroyed"
    staging_lab_refused = "staging_lab.refused"
    # Durable work items + substrate eligibility (SECP-002B-1B-9).
    staging_work_claimed = "staging_lab.work_claimed"
    staging_work_completed = "staging_lab.work_completed"
    staging_work_failed = "staging_lab.work_failed"
    staging_work_refused = "staging_lab.work_refused"
    staging_substrate_eligibility_granted = "staging_lab.substrate_eligibility_granted"
    staging_substrate_eligibility_revoked = "staging_lab.substrate_eligibility_revoked"
    # SECP-B2-0 — app-owned read-only staging preflight.
    readonly_preflight_created = "readonly_preflight.created"
    readonly_preflight_queued = "readonly_preflight.queued"
    readonly_preflight_claimed = "readonly_preflight.claimed"
    readonly_preflight_completed = "readonly_preflight.completed"
    readonly_preflight_refused = "readonly_preflight.refused"
    readonly_preflight_failed = "readonly_preflight.failed"
    # SECP-B2-3 — durable resolution-lease transitions (worker-only, secret-free).
    resolution_lease_acquired = "resolution_lease.acquired"
    resolution_lease_attempt_started = "resolution_lease.attempt_started"
    resolution_lease_refused = "resolution_lease.refused"
    resolution_lease_consumed = "resolution_lease.consumed"
    # SECP-B2-4.1 — durable resolver-activation authorization lifecycle (secret-free).
    resolver_activation_created = "resolver_activation.created"
    resolver_activation_evidence_recorded = "resolver_activation.evidence_recorded"
    resolver_activation_approved = "resolver_activation.approved"
    resolver_activation_revoked = "resolver_activation.revoked"
    resolver_activation_expired = "resolver_activation.expired"
    resolver_activation_activation_refused = "resolver_activation.activation_refused"
    # SECP-B2-4.3 — durable worker-identity trust anchor lifecycle (secret-free).
    worker_identity_registered = "worker_identity.registered"
    worker_identity_evidence_recorded = "worker_identity.evidence_recorded"
    worker_identity_approved = "worker_identity.approved"
    worker_identity_revoked = "worker_identity.revoked"
    worker_identity_expired = "worker_identity.expired"
    worker_identity_verification_refused = "worker_identity.verification_refused"


class ResolutionLeaseStatus(str, Enum):
    """Durable state of one read-only-preflight resolution operation (SECP-B2-3).

    The row is keyed by the global operation uniqueness boundary
    ``(authorization_id, authorization_version, operation_fingerprint)`` and persists the durable
    attempt budget across every lease instance and worker identity. It never stores a credential,
    reference, endpoint, target configuration, certificate, secret, or hash of any of those.
    """

    # A currently valid pre-success lease is held (exactly one per operation key at a time).
    active = "active"
    # A resolution succeeded for this operation: globally single-use; further attempts are replay.
    consumed = "consumed"
    # The durable retry budget (N=3) is exhausted for this operation key; terminal until a new
    # authorization_version creates a distinct operation key with a fresh budget.
    exhausted = "exhausted"


class ResolutionLeaseReason(str, Enum):
    """Closed catalog of secret-free resolution-lease refusal/transition codes (SECP-B2-3)."""

    # Fail-closed refusals recorded durably (never free text, never a secret/reference value).
    replay_refused = "replay_refused"
    retry_bound_exceeded = "retry_bound_exceeded"
    lease_held = "lease_held"
    authorization_expired = "authorization_expired"
    reference_mismatch = "reference_mismatch"
    worker_identity_untrusted = "worker_identity_untrusted"
    resolution_activation_disabled = "resolution_activation_disabled"
