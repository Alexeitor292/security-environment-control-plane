// Types mirroring the control-plane API responses (apps/api/secp_api/schemas.py).

export type LifecycleState =
  | "draft"
  | "validated"
  | "planned"
  | "awaiting_approval"
  | "approved"
  | "deploying"
  | "running"
  | "resetting"
  | "destroying"
  | "destroyed"
  | "failed";

export type PlanStatus =
  | "generated"
  | "awaiting_approval"
  | "approved"
  | "rejected"
  | "applied";

export interface Principal {
  user_id: string;
  organization_id: string;
  email: string;
  permissions: string[];
  is_dev_fallback: boolean;
}

export interface Template {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  display_name: string;
  description: string;
  created_at: string;
}

export interface Version {
  id: string;
  template_id: string;
  version_number: number;
  api_version: string;
  content_hash: string;
  spec: Record<string, unknown>;
  created_at: string;
}

export interface Exercise {
  id: string;
  organization_id: string;
  template_id: string;
  environment_version_id: string;
  name: string;
  lifecycle_state: LifecycleState;
  team_count: number;
  created_at: string;
}

export interface Instance {
  id: string;
  exercise_id: string;
  team_index: number;
  team_ref: string;
  instance_ref: string;
  lifecycle_state: LifecycleState;
  provider: string;
}

export interface PlanSummaryTeam {
  team_ref: string;
  networks: { name: string; cidr: string }[];
  nodes: { name: string; role: string; kind: string; ip: string }[];
}

export interface PlanSummary {
  plugin: string;
  teams: number;
  isolation: string;
  total_networks: number;
  total_nodes: number;
  per_team: PlanSummaryTeam[];
}

export interface DeploymentPlan {
  id: string;
  exercise_id: string;
  environment_version_id: string;
  version_content_hash: string;
  status: PlanStatus;
  summary: PlanSummary;
  approved_content_hash: string | null;
  decided_at: string | null;
  created_at: string;
}

export interface WorkflowRun {
  id: string;
  exercise_id: string;
  kind: string;
  status: string;
  dispatch_mode: string;
  correlation_id: string;
  target_instance_id: string | null;
  detail: Record<string, unknown>;
  created_at: string;
  finished_at: string | null;
}

export interface AuditEvent {
  id: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  data: Record<string, unknown>;
  created_at: string;
}

export interface PluginInfo {
  name: string;
  version: string;
  contract_version: string;
  healthy: boolean;
  simulated: boolean;
  capabilities: string[];
}

export interface TopologyNode {
  id: string;
  type: string;
  data: {
    label: string;
    kind: string;
    role?: string;
    image?: string;
    ip?: string;
    cidr?: string;
    status?: string;
    network?: string;
    isolated?: boolean;
  };
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  data: { kind: string };
}

export interface TeamTopology {
  instance_id: string;
  team_ref: string;
  team_index: number;
  lifecycle_state: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export interface ApiError {
  error: { code: string; message: string; details?: string[] };
}

// --- Provider Targets (SECP-002A) ---

export interface ProviderCapabilities {
  milestone: string;
  provisioning_enabled: boolean;
  discovery: string;
  note: string;
}

export interface ExecutionTarget {
  id: string;
  organization_id: string;
  display_name: string;
  plugin_name: string;
  config: Record<string, unknown>;
  config_hash: string;
  secret_ref: string | null;
  status: string;
  scope_policy: Record<string, unknown>;
  created_at: string;
}

export interface TargetCreate {
  display_name: string;
  plugin_name: string;
  config: Record<string, unknown>;
  secret_ref?: string | null;
  scope_policy?: Record<string, unknown>;
  address_spaces?: { cidr_block: string; subnet_prefix: number }[];
}

export interface InventorySnapshot {
  id: string;
  execution_target_id: string;
  plugin_name: string;
  plugin_version: string;
  target_config_hash: string;
  status: string;
  workflow_run_id: string | null;
  requested_at: string;
  completed_at: string | null;
  summary: Record<string, unknown>;
  error: string | null;
}

export interface InventoryResource {
  id: string;
  resource_type: string;
  provider_external_id: string;
  display_name: string;
  parent_ref: string | null;
  status: string;
  attributes: Record<string, unknown>;
}

// --- Target Onboarding (SECP-002B-1B-0 / 0.1) ---

export type OnboardingMode = "clean_server" | "existing_environment";
export type IsolationModelName = "physical" | "logical";
export type NetworkApproach =
  | "use_approved_existing_segment"
  | "secp_managed_dedicated_segment";
export type IsolationProfile =
  | "fully_segregated"
  | "internet_egress_only"
  | "controlled_service_access"
  | "advanced_custom_policy";
export type OnboardingStatus =
  | "draft"
  | "preflight_pending"
  | "ready_for_review"
  | "approved"
  | "active"
  | "rejected"
  | "retired";

export interface OnboardingBoundary {
  nodes: string[];
  storage: string[];
  network_segments: string[];
  cidrs: string[];
  vmid_range: { start: number; end: number };
  quotas: {
    max_teams: number;
    max_vms: number;
    max_containers: number;
    max_total_vcpu: number;
    max_total_memory_mb: number;
    max_total_disk_gb: number;
  };
  external_connectivity: { policy: "deny" };
  credential_scope: string;
  network_approach?: NetworkApproach;
  isolation_profile?: IsolationProfile;
}

export interface Onboarding {
  id: string;
  organization_id: string;
  execution_target_id: string;
  onboarding_mode: OnboardingMode;
  isolation_model: IsolationModelName;
  status: OnboardingStatus;
  declared_boundary: OnboardingBoundary;
  boundary_hash: string;
  network_approach: NetworkApproach;
  isolation_profile: IsolationProfile;
  approved_verification_level: string | null;
  activated_at: string | null;
  created_at: string;
}

export interface PreflightCheck {
  check: string;
  status: string;
  detail: string;
}

export interface Preflight {
  id: string;
  onboarding_id: string;
  collector: string;
  verification_level: string;
  collector_kind: string;
  collector_identity: string;
  evidence_version: number;
  passed: boolean;
  checks: PreflightCheck[];
  evidence_hash: string;
  target_evidence_id: string | null;
  target_evidence_hash: string | null;
  created_at: string;
}

export interface TargetEvidenceFinding {
  check: string;
  status: "pass" | "fail" | "unverifiable" | string;
  detail: string;
}

export interface TargetEvidence {
  id: string;
  onboarding_id: string;
  execution_target_id: string;
  evidence_source: string;
  verification_level: string;
  status: "pass" | "fail" | "unverifiable" | string;
  findings: TargetEvidenceFinding[];
  collected_at: string;
  evidence_hash: string;
  created_at: string;
}

export interface OnboardingCreate {
  onboarding_mode: OnboardingMode;
  isolation_model: IsolationModelName;
  declared_boundary: OnboardingBoundary;
}

// --- Declarative Disposable Staging Lab (SECP-002B-1B-9, fake-only) ---

export type StagingLabStatus =
  | "draft"
  | "planned"
  | "awaiting_approval"
  | "approved"
  | "simulation_queued"
  | "simulating"
  | "simulated_ready"
  | "teardown_queued"
  | "tearing_down"
  | "destroyed"
  | "failed";

export type StagingLabProfile = "nested_proxmox";
export type StagingNetworkIntent = "host_only_no_uplink";
export type StagingResourceClass = "small_lab" | "medium_lab";
export type StagingBootstrapArtifactProfile = "nested_proxmox_offline_base";
export type StagingRollbackPolicy =
  | "revert_to_known_clean_checkpoint"
  | "destroy_and_rebuild";

export interface StagingLab {
  id: string;
  organization_id: string;
  execution_target_id: string;
  display_name: string;
  ownership_label: string;
  purpose: string;
  profile: string;
  network_intent: string;
  resource_class: string;
  rollback_policy: string;
  bootstrap_artifact_profile: string;
  status: StagingLabStatus;
  revision: number;
  plan_version: number;
  plan_hash: string;
  desired_state: Record<string, unknown> | null;
  simulated_observed_state: Record<string, unknown> | null;
  approved_plan_hash: string;
  approved_plan_version: number;
  approved_at: string | null;
  decision_code: string;
  created_at: string;
}

export interface StagingLabCreate {
  execution_target_id: string;
  resource_class?: StagingResourceClass;
  bootstrap_artifact_profile?: StagingBootstrapArtifactProfile;
  rollback_policy?: StagingRollbackPolicy;
  logical_name?: string | null;
}

export interface EligibleSubstrate {
  id: string;
  alias: string;
}

// --- Real App-Owned Isolated Staging Lab Deployment (SECP-B4) ---
//
// The control plane owns every label; this surface accepts only a substrate id, a closed resource
// profile, and one optional strict logical name. It NEVER carries an SSH key, API token, host,
// endpoint, command, bridge/storage name, VMID, network range, path, or provider option.

export type StagingDeploymentStatus =
  | "draft"
  | "planned"
  | "awaiting_approval"
  | "approved"
  | "bootstrap_pending"
  | "applying"
  | "verifying"
  | "ready"
  | "failed"
  | "rollback_required"
  | "rolling_back"
  | "rolled_back"
  | "teardown_requested"
  | "tearing_down"
  | "destroyed";

export type DeploymentResourceProfile = "small_lab" | "medium_lab";

export interface StagingDeployment {
  id: string;
  organization_id: string;
  execution_target_id: string;
  display_name: string;
  ownership_label: string;
  resource_profile: string;
  status: StagingDeploymentStatus;
  decision_code: string;
  revision: number;
  plan_version: number;
  plan_hash: string;
  approved_plan_hash: string;
  approved_at: string | null;
  failure_code: string | null;
  created_at: string;
}

export interface StagingDeploymentCreate {
  execution_target_id: string;
  resource_profile?: DeploymentResourceProfile;
  logical_name?: string | null;
}

export interface PlannedResource {
  kind: string;
  count: number;
  resource_ref: string;
}

export interface StagingDeploymentPlan {
  plan_version: number;
  plan_hash: string;
  ownership_tag: string;
  capacity_assessment_hash: string;
  artifact_manifest_id: string;
  resources: PlannedResource[];
}

export interface StagingDeploymentResourceRecord {
  resource_kind: string;
  ownership_tag: string;
  resource_ref: string;
  inverse_op: string;
  state: string;
}

export interface StagingDeploymentVerificationRecord {
  check_code: string;
  status: string;
}

export interface BootstrapAvailability {
  available: boolean;
  reason_code: string;
}

// --- Worker-owned read-only target enrollment + discovery (SECP-B5) ---
//
// The control plane owns every label; this surface accepts only a substrate id, a closed resource
// profile, and one optional strict logical name. It NEVER carries an SSH host/account/port/key path/
// known_hosts/fingerprint, Proxmox endpoint/token, raw output, node/storage/VMID entry, or command.

export type TargetDiscoveryStatus =
  | "requested"
  | "discovering"
  | "discovered"
  | "plan_ready"
  | "approved"
  | "failed";

export type DiscoveryResourceProfile = "small_lab" | "medium_lab";

export interface DiscoveryEnrollment {
  id: string;
  organization_id: string;
  execution_target_id: string;
  display_name: string;
  ownership_label: string;
  resource_profile: string;
  status: TargetDiscoveryStatus;
  decision_code: string;
  enrollment_version: number;
  revision: number;
  active_plan_hash: string;
  approved_plan_hash: string;
  approved_at: string | null;
  failure_code: string | null;
  created_at: string;
}

export interface DiscoveryRequest {
  execution_target_id: string;
  resource_profile?: DiscoveryResourceProfile;
  logical_name?: string | null;
}

export interface DiscoveryCandidatePlanResource {
  kind: string;
  resource_ref: string;
  ownership_marker: string;
}

export interface DiscoveryCandidatePlan {
  plan_version: number;
  plan_hash: string;
  ownership_tag: string;
  resource_profile: string;
  node: string;
  storage: string;
  capacity_snapshot_hash: string;
  evidence_hash: string;
  enrollment_version: number;
  expires_at: string;
  executable: boolean;
  status: string;
  resources: DiscoveryCandidatePlanResource[];
}

export interface DiscoveryEvidence {
  eligibility: string;
  reason_code: string | null;
  version_major: number | null;
  version_minor: number | null;
  is_clustered: boolean | null;
  node: string | null;
  node_count: number | null;
  cpu_total: number | null;
  mem_total_mb: number | null;
  mem_free_mb: number | null;
  nested_available: boolean | null;
  selected_storage: string | null;
  storage_count: number;
  candidate_vmids: number[];
  evidence_hash: string;
  bundle_available: boolean;
  created_at: string;
}

export interface DiscoveryApplyNotice {
  live_apply_sealed: boolean;
  message: string;
}

// --- App-owned read-only staging preflight (SECP-B2-0) ---

export type ReadonlyPreflightStatus =
  | "queued"
  | "claimed"
  | "running"
  | "completed"
  | "failed"
  | "refused";

export type ReadonlyPreflightOutcome =
  | "ready"
  | "not_ready"
  | "authorization_expired"
  | "authorization_revoked"
  | "authorization_invalid"
  | "credential_unavailable"
  | "tls_or_policy_refused"
  | "worker_internal_failure";

export interface PreflightSubstrate {
  id: string;
  alias: string;
}

export interface PreflightAuthorization {
  id: string;
  organization_id: string;
  execution_target_id: string;
  onboarding_id: string;
  authorization_version: number;
  status: string;
  authorization_expiry: string;
  created_at: string;
  approved_at: string | null;
  revoked_at: string | null;
}

export interface ReadonlyPreflight {
  id: string;
  organization_id: string;
  execution_target_id: string;
  onboarding_id: string;
  live_read_authorization_id: string;
  authorization_version: number;
  status: ReadonlyPreflightStatus;
  revision: number;
  outcome_code: ReadonlyPreflightOutcome | null;
  readiness_facts: Record<string, number | boolean> | null;
  created_at: string;
  completed_at: string | null;
}

// SECP-B2-4.1 — resolver-activation authorization (secret-free; closed states + safe hashes only).
export interface ResolverActivationEvidence {
  kind: string;
  status: string;
  proof_id: string;
  issuer: string;
  verified_at: string | null;
}

export interface ResolverActivation {
  id: string;
  organization_id: string;
  execution_target_id: string;
  onboarding_id: string;
  live_read_authorization_id: string;
  live_read_authorization_version: number;
  preflight_id: string;
  operation_fingerprint: string;
  resolver_adapter_contract_version: string;
  purpose: string;
  authorization_expiry: string;
  evidence_fingerprint: string;
  status: string;
  authorization_version: number;
  revision: number;
  approved_at: string | null;
  revoked_at: string | null;
  created_at: string;
  evidence: ResolverActivationEvidence[];
}
