// Types for the Proxmox range provider, transcribed from the BACKEND SCHEMAS.
//
// Every declaration below names the module and dataclass it mirrors. That matters more here than
// usual: none of these cross the wire today, so there is no response body to check a guess
// against, and a prose contract document has lagged the code in this repo before. The source of
// truth is:
//
//   secp_api.range_providers.proxmox_model      — ownership, guests, network specs, topology
//   secp_api.range_providers.proxmox_network    — segregated network compiler, isolation findings
//   secp_api.range_providers.proxmox_ipam       — allocation ledger and pools
//   secp_api.range_providers.proxmox_workload   — workload plan, bootstrap, readiness
//   secp_worker.provisioning.plan_document      — plan document envelope, EXECUTION STATUS
//   secp_worker.provisioning.proxmox_apply_gate — apply authorization and refusal codes
//   secp_worker.provisioning.proxmox_verification — observed verification report
//   secp_worker.provisioning.proxmox_reset      — reset plan and verdict
//   secp_worker.provisioning.proxmox_reconcile  — reconciliation decision
//   secp_worker.provisioning.proxmox_destroy_gate — destroy authorization and refusal codes
//   secp_worker.provisioning.proxmox_residue    — deletion set, absence findings, zero-residue
//
// Enums are `as const` arrays with types derived from them, matching `range-types.ts`. A bare
// union is erased at build time and can prove nothing at runtime; the arrays let the tone maps be
// checked exhaustive and let the fixtures be checked against the contract they claim to model.
//
// Naming follows the backend exactly (snake_case fields, backend spellings for enum members) so a
// reader can diff a screen against a Python dataclass without a translation table in between.

// --- ownership (proxmox_model.Ownership / ObjectProvenance) ------------------------------------

export const GUEST_KINDS = ["qemu", "lxc"] as const;
export type GuestKind = (typeof GUEST_KINDS)[number];

export const CLONE_STRATEGIES = ["full", "linked"] as const;
export type CloneStrategy = (typeof CLONE_STRATEGIES)[number];

export const SEGMENT_ROLES = ["scoring", "attacker", "vulnerable", "sensor"] as const;
export type SegmentRole = (typeof SEGMENT_ROLES)[number];

export const FIREWALL_VERDICTS = ["ACCEPT", "DROP", "REJECT"] as const;
export type FirewallVerdict = (typeof FIREWALL_VERDICTS)[number];

export const FIREWALL_DIRECTIONS = ["IN", "OUT"] as const;
export type FirewallDirection = (typeof FIREWALL_DIRECTIONS)[number];

/**
 * How an object on the cluster was classified. `untagged` and `unreadable` are the two that must
 * never be treated as "ours": an object we cannot read is not an object we may delete.
 */
export const OBJECT_PROVENANCES = [
  "secp_owned",
  "secp_foreign_scope",
  "untagged",
  "unreadable",
] as const;
export type ObjectProvenance = (typeof OBJECT_PROVENANCES)[number];

/** `proxmox_model.Ownership` — the identity stamped on every object SECP creates. */
export interface Ownership {
  organization_id: string;
  target_id: string;
  range_id: string;
  generation: number;
  operation_generation: number;
  /** `RangeResourceKind` on the backend; kept as a string, which is what it serialises to. */
  resource_kind: string;
  team_ref: string | null;
}

/** `proxmox_model.ProxmoxTargetIdentity`. */
export interface ProxmoxTargetIdentity {
  target_id: string;
  cluster_name: string;
  cluster_fingerprint: string;
  management_cidrs: string[];
  management_bridges: string[];
}

// --- network design (proxmox_model network specs) ----------------------------------------------

/** `proxmox_model.SubnetSpec`. */
export interface SubnetSpec {
  cidr: string;
  gateway: string;
  routed: boolean;
}

/** `proxmox_model.SdnZoneSpec`. */
export interface SdnZoneSpec {
  name: string;
  bridge: string;
  nodes: string[];
  ownership: Ownership;
  mtu: number | null;
}

/** `proxmox_model.VNetSpec`. */
export interface VNetSpec {
  name: string;
  zone_name: string;
  vlan_tag: number;
  subnet: SubnetSpec;
  role: SegmentRole;
  ownership: Ownership;
  alias: string;
}

/** `proxmox_model.NicSpec`. */
export interface NicSpec {
  index: number;
  vnet_name: string;
  mac_address: string;
  model: string;
  firewall: boolean;
}

/**
 * `proxmox_model.GuestAddress`.
 *
 * The two addresses are deliberately separate and are rendered separately. `published_address` is
 * what the guest is told to report to; `probe_address` is what the worker can actually reach.
 * Collapsing them is the defect fixed by #103 — the worker probed the address it published.
 */
export interface GuestAddress {
  published_address: string;
  probe_address: string | null;
}

/** `proxmox_model.DiskSpec`. */
export interface DiskSpec {
  slot: string;
  size_gb: number;
  storage_id: string;
  discard: boolean;
  ssd_emulation: boolean;
}

/** `proxmox_model.GuestSpec` — one VM or container in the desired state. */
export interface GuestSpec {
  guest_ref: string;
  name: string;
  kind: GuestKind;
  vmid: number;
  node_name: string;
  template_ref: string;
  clone_strategy: CloneStrategy;
  cpu_cores: number;
  memory_mb: number;
  disks: DiskSpec[];
  nics: NicSpec[];
  address: GuestAddress;
  ownership: Ownership;
  start_on_deploy: boolean;
  readiness_timeout_seconds: number;
}

/** `proxmox_model.FirewallRuleSpec`. */
export interface FirewallRuleSpec {
  position: number;
  direction: FirewallDirection;
  verdict: FirewallVerdict;
  comment: string;
  source: string | null;
  dest: string | null;
  proto: string | null;
  dport: string | null;
  enabled: boolean;
}

/** `proxmox_model.SecurityGroupSpec`. */
export interface SecurityGroupSpec {
  name: string;
  rules: FirewallRuleSpec[];
  ownership: Ownership;
  comment: string;
}

/** `proxmox_model.IpSetSpec`. */
export interface IpSetSpec {
  name: string;
  cidrs: string[];
  ownership: Ownership;
  comment: string;
}

/** `proxmox_model.EgressGatewaySpec` — absent unless egress was explicitly approved. */
export interface EgressGatewaySpec {
  vnet_name: string;
  allowed_destinations: string[];
  allowed_ports: string[];
  ownership: Ownership;
  approval_reference: string;
}

/** `proxmox_model.SegregatedNetworkPlan`. */
export interface SegregatedNetworkPlan {
  zone: SdnZoneSpec;
  vnets: VNetSpec[];
  security_groups: SecurityGroupSpec[];
  ip_sets: IpSetSpec[];
  /** vnet name -> security group name. */
  vnet_security_group: Record<string, string>;
  egress: EgressGatewaySpec | null;
}

/** `proxmox_model.CompiledTopology`. */
export interface CompiledTopology {
  target: ProxmoxTargetIdentity;
  ownership: Ownership;
  network: SegregatedNetworkPlan;
  guests: GuestSpec[];
}

/** `proxmox_network.IsolationProperty`. */
export const ISOLATION_PROPERTIES = [
  "cross_team_blocked",
  "management_plane_unreachable",
  "control_plane_unreachable",
  "no_default_public_route",
  "default_deny_present",
  "scoring_reachable",
] as const;
export type IsolationProperty = (typeof ISOLATION_PROPERTIES)[number];

/** `proxmox_network.IsolationFinding` — a property of the COMPILED PLAN, not of a live cluster. */
export interface IsolationFinding {
  prop: IsolationProperty;
  holds: boolean;
  detail: string;
}

/** `proxmox_model.MissingPrerequisite` inside a `BlockedPlan`. */
export interface MissingPrerequisite {
  reason_id: string;
  observation: string;
  detail: string;
}

// --- allocations (proxmox_ipam) ----------------------------------------------------------------

export const ALLOCATION_KINDS = [
  "vmid",
  "lxc_id",
  "mac",
  "subnet",
  "guest_address",
  "gateway_address",
  "vlan_tag",
  "vnet_name",
  "zone_name",
  "resource_name",
  "firewall_object_name",
  "remote_state_key",
] as const;
export type AllocationKind = (typeof ALLOCATION_KINDS)[number];

/** `proxmox_ipam.Allocation`. `scope` is the 5-tuple; rendered as its parts. */
export interface Allocation {
  kind: AllocationKind;
  purpose: string;
  value: string;
}

/** `proxmox_ipam.IpamPools` — the bounds every allocation was drawn from. */
export interface IpamPools {
  vmid_min: number;
  vmid_max: number;
  supernet: string;
  segment_prefix: number;
  vlan_min: number;
  vlan_max: number;
}

// --- workload (proxmox_workload) ---------------------------------------------------------------

export const WORKLOAD_ROLES = ["attacker", "target", "sensor"] as const;
export type WorkloadRole = (typeof WORKLOAD_ROLES)[number];

/** `proxmox_workload.ReviewedGuestImage` — the pinned, approved source template. */
export interface ReviewedGuestImage {
  workload_key: string;
  role: WorkloadRole;
  template_ref: string;
  workload_version: string;
  image_digest: string;
  approval_reference: string;
  guest_kind: GuestKind;
  clone_strategy: CloneStrategy;
  service_port: number;
}

export const READINESS_REQUIREMENTS = [
  "two_teams_present",
  "attacker_per_team",
  "targets_per_team",
  "challenges_covered",
  "scoring_reachable_by_plan",
  "flags_delivered_out_of_band",
  "bootstrap_bounded_and_observable",
  "workload_versions_pinned",
] as const;
export type ReadinessRequirement = (typeof READINESS_REQUIREMENTS)[number];

/** `proxmox_workload.ReadinessFinding`. */
export interface ReadinessFinding {
  requirement: ReadinessRequirement;
  met: boolean;
  detail: string;
}

// --- plan document (plan_document) -------------------------------------------------------------

/** `plan_document.EXECUTION_STATUS_NOT_APPLIED`. Rendered verbatim, never softened. */
export const EXECUTION_STATUS_NOT_APPLIED = "NOT APPLIED";

/** `plan_document.PLAN_DOCUMENT_VERSION`. */
export const PLAN_DOCUMENT_VERSION = "secp-proxmox/plan-document/v1";

/**
 * The plan document envelope. A plan is a DESCRIPTION of intended change that has not run.
 *
 * `execution_status` is carried as its own field rather than inferred from a lifecycle state,
 * because the operator's question at plan review is exactly "has this run?" and the answer must
 * come from the document itself.
 */
export interface PlanDocument {
  version: string;
  execution_status: string;
  change_set_hash: string;
  desired_state_hash: string;
  plan_document_hash: string;
  create_addresses: string[];
  update_addresses: string[];
  delete_addresses: string[];
  generated_at: string;
}

// --- apply gate (proxmox_apply_gate) -----------------------------------------------------------

/** `proxmox_apply_gate.ApplyRefusalCode`. Every value is prefixed `proxmox.apply.`. */
export const APPLY_REFUSAL_CODES = [
  "proxmox.apply.no_prepared_plan",
  "proxmox.apply.change_set_hash_mismatch",
  "proxmox.apply.stale_binary_plan",
  "proxmox.apply.allocation_drift",
  "proxmox.apply.desired_state_drift",
  "proxmox.apply.ownership_scope_mismatch",
  "proxmox.apply.worker_identity_mismatch",
  "proxmox.apply.worker_release_mismatch",
  "proxmox.apply.target_mismatch",
  "proxmox.apply.remote_state_lock_unavailable",
  "proxmox.apply.credential_unresolvable",
  "proxmox.apply.ordinary_worker_on_controlled_live_path",
  "proxmox.apply.discovery_stale",
  "proxmox.apply.onboarding_not_current",
  "proxmox.apply.eligibility_not_current",
  "proxmox.apply.reservations_not_persisted",
] as const;
export type ApplyRefusalCode = (typeof APPLY_REFUSAL_CODES)[number];

/** `proxmox_apply_gate.WorkerIdentity`. */
export interface WorkerIdentity {
  worker_id: string;
  role: string;
  release: string;
  queue: string;
}

/** `proxmox_apply_gate.INFRASTRUCTURE_OPERATOR_ROLE`. */
export const INFRASTRUCTURE_OPERATOR_ROLE = "infrastructure_operator";

/**
 * `proxmox_apply_gate.AuthoritativeState` — the preconditions the gate reads.
 *
 * Every field is a THREE-VALUED boolean: `null` means the control plane did not state it, which
 * the gate treats as not-satisfied. It is rendered as "not stated", never as false, because
 * "nobody said" and "the answer is no" are different facts and only one of them is a finding.
 */
export interface AuthoritativeState {
  onboarding_current: boolean | null;
  eligibility_passing: boolean | null;
  discovery_fresh: boolean | null;
  reservations_persisted: boolean | null;
  remote_state_lock_held: boolean | null;
  credential_resolved: boolean | null;
}

/**
 * `proxmox_apply_gate.ApplyAuthorization` — what the gate EMITS when it does not refuse.
 *
 * Its existence means apply is permitted to start. It does not mean apply started, and nothing on
 * these screens may imply that it did.
 */
export interface ApplyAuthorization {
  change_set_hash: string;
  desired_state_hash: string;
  ownership_scope: [string, string, string, number];
  checks_passed: string[];
}

/** The apply-authorization state as an operator sees it. Not a backend enum: a UI projection. */
export const APPLY_AUTHORIZATION_STATES = [
  "not_requested",
  "plan_awaiting_review",
  "plan_approved_apply_not_authorized",
  "apply_authorized",
  "apply_refused",
] as const;
export type ApplyAuthorizationState = (typeof APPLY_AUTHORIZATION_STATES)[number];

/** Plan-approval state, separate from apply authorization by construction. */
export const PLAN_APPROVAL_STATES = ["draft", "approved", "rejected", "superseded"] as const;
export type PlanApprovalState = (typeof PLAN_APPROVAL_STATES)[number];

// --- verification (proxmox_verification) -------------------------------------------------------

/**
 * `proxmox_verification.VerificationOutcome`.
 *
 * Five members, and the last three are NOT failure synonyms. `state_disagreement` means recorded
 * state and observation disagree; `recovery_required` means the cluster could not be observed at
 * all. Neither is evidence the deployment is broken, and neither is evidence it is fine.
 */
export const VERIFICATION_OUTCOMES = [
  "verified",
  "verification_failed",
  "isolation_failed",
  "state_disagreement",
  "recovery_required",
] as const;
export type VerificationOutcome = (typeof VERIFICATION_OUTCOMES)[number];

/** `proxmox_verification.VerificationCheck`. */
export const VERIFICATION_CHECKS = [
  "guest_inventory",
  "guest_names",
  "node_placement",
  "disks_and_storage",
  "nics_and_macs",
  "network_objects",
  "firewall_objects",
  "ownership_tags",
  "power_state",
  "guest_readiness",
  "required_reachability",
  "cross_team_denial",
  "management_denial",
  "protected_denial",
  "external_denial",
  "state_agreement",
] as const;
export type VerificationCheck = (typeof VERIFICATION_CHECKS)[number];

/** `proxmox_verification.ISOLATION_CHECKS` — the subset whose failure means isolation_failed. */
export const ISOLATION_CHECK_KEYS: readonly VerificationCheck[] = [
  "cross_team_denial",
  "management_denial",
  "protected_denial",
  "external_denial",
];

/** `proxmox_verification.ProbeVerdict`. `unknown` is the third outcome, not a soft "blocked". */
export const PROBE_VERDICTS = ["reachable", "blocked", "unknown"] as const;
export type ProbeVerdict = (typeof PROBE_VERDICTS)[number];

/**
 * `proxmox_verification.CheckFinding`.
 *
 * `observed` and `ok` are two independent booleans and the pair is the whole point: `observed:
 * false` means the check could not be run, and `ok` carries no meaning in that case. A renderer
 * that reads only `ok` reports an unobserved check as a failure.
 */
export interface CheckFinding {
  check: VerificationCheck;
  observed: boolean;
  ok: boolean;
  detail: string;
}

/** `proxmox_verification.VerificationReport`. */
export interface VerificationReport {
  outcome: VerificationOutcome;
  findings: CheckFinding[];
}

// --- reset and reconcile (proxmox_reset / proxmox_reconcile) -----------------------------------

export const RESET_DISPOSITIONS = ["preserved", "recreated", "restored", "cleared"] as const;
export type ResetDisposition = (typeof RESET_DISPOSITIONS)[number];

export const RESET_SUBJECTS = [
  "range_identity",
  "sdn_zone",
  "vnets",
  "subnets_and_vlans",
  "firewall_objects",
  "allocation_ledger",
  "guests",
  "challenge_state",
  "team_membership",
  "scores",
] as const;
export type ResetSubject = (typeof RESET_SUBJECTS)[number];

/** `proxmox_reset.ResetAction`. */
export interface ResetAction {
  subject: ResetSubject;
  disposition: ResetDisposition;
  detail: string;
}

/** `proxmox_reset.ResetPlan` (the fields an operator reviews). */
export interface ResetPlan {
  range_id: string;
  operation_generation: number;
  actions: ResetAction[];
  recreated_guest_refs: string[];
  topology_fingerprint: string;
}

export const RECONCILE_ACTIONS = ["no_action", "resume_apply", "halt"] as const;
export type ReconcileAction = (typeof RECONCILE_ACTIONS)[number];

export const PROVIDER_OUTCOMES = ["succeeded", "failed", "unknown"] as const;
export type ProviderOutcome = (typeof PROVIDER_OUTCOMES)[number];

/** `proxmox_reconcile.ReconcileDecision`. */
export interface ReconcileDecision {
  action: ReconcileAction;
  outcome: VerificationOutcome;
  /** `ReconcileReason`, e.g. `proxmox.reconcile.provider_outcome_unknown`. */
  reason: string;
  detail: string;
  create_vmids: number[];
}

// --- destroy gate (proxmox_destroy_gate) -------------------------------------------------------

/**
 * `proxmox_destroy_gate.DestroyRefusalCode`. Prefixed `proxmox.destroy.` — a DIFFERENT namespace
 * from the apply codes, which is the machine-readable form of the same separation the UI enforces.
 */
export const DESTROY_REFUSAL_CODES = [
  "proxmox.destroy.approval_is_not_for_destroy",
  "proxmox.destroy.no_destroy_approval",
  "proxmox.destroy.approval_already_consumed",
  "proxmox.destroy.change_set_hash_mismatch",
  "proxmox.destroy.prepared_plan_is_not_a_destroy_plan",
  "proxmox.destroy.stale_binary_destroy_plan",
  "proxmox.destroy.deletion_set_mismatch",
  "proxmox.destroy.ownership_not_verified",
  "proxmox.destroy.discovery_stale",
  "proxmox.destroy.ownership_scope_mismatch",
  "proxmox.destroy.worker_identity_mismatch",
  "proxmox.destroy.worker_release_mismatch",
  "proxmox.destroy.target_mismatch",
  "proxmox.destroy.remote_state_lock_unavailable",
  "proxmox.destroy.credential_unresolvable",
  "proxmox.destroy.ordinary_worker_on_controlled_live_path",
] as const;
export type DestroyRefusalCode = (typeof DESTROY_REFUSAL_CODES)[number];

/** `proxmox_destroy_gate.DESTROY_OPERATION_KIND`. */
export const DESTROY_OPERATION_KIND = "destroy";

/**
 * `proxmox_destroy_gate.DestroyApproval`.
 *
 * `operation_kind` exists so an apply approval cannot be replayed as a destroy approval — the gate
 * refuses with `approval_is_not_for_destroy` when it is anything but `"destroy"`. The field is
 * rendered for the same reason it exists.
 */
export interface DestroyApproval {
  operation_kind: string;
  change_set_hash: string;
  deletion_set_hash: string;
  plan_document_hash: string;
  ownership_scope: [string, string, string, number];
  target_id: string;
  cluster_fingerprint: string;
  worker_id: string;
  worker_release: string;
  approval_id: string;
}

/** `proxmox_destroy_gate.DestroyPreconditions`. Same three-valued booleans as the apply gate. */
export interface DestroyPreconditions {
  ownership_verified: boolean | null;
  discovery_fresh: boolean | null;
  remote_state_lock_held: boolean | null;
  credential_resolved: boolean | null;
  approval_already_consumed: boolean;
}

/** `proxmox_destroy_gate.DestroyAuthorization`. */
export interface DestroyAuthorization {
  change_set_hash: string;
  deletion_set_hash: string;
  ownership_scope: [string, string, string, number];
  approval_id: string;
  checks_passed: string[];
}

/** The destroy-authorization state as an operator sees it. A UI projection, like its apply twin. */
export const DESTROY_AUTHORIZATION_STATES = [
  "not_requested",
  "destroy_plan_awaiting_review",
  "destroy_plan_approved_not_authorized",
  "destroy_authorized",
  "destroy_refused",
] as const;
export type DestroyAuthorizationState = (typeof DESTROY_AUTHORIZATION_STATES)[number];

// --- residue (proxmox_residue) -----------------------------------------------------------------

export const RESIDUE_CLASSES = [
  "qemu_vm",
  "lxc_container",
  "disk_volume",
  "nic",
  "sdn_zone",
  "vnet",
  "bridge",
  "subnet",
  "vlan_assignment",
  "firewall_group",
  "firewall_rule",
  "ip_set",
  "firewall_alias",
  "cloud_init_snippet",
  "bootstrap_object",
  "vmid_reservation",
  "mac_reservation",
  "ip_reservation",
  "subnet_reservation",
  "vlan_reservation",
  "remote_state_key_reservation",
  "transient_workspace",
  "binary_plan_file",
  "temporary_credential_file",
  "remote_state_object",
] as const;
export type ResidueClass = (typeof RESIDUE_CLASSES)[number];

export const PROBE_DOMAINS = ["provider", "local_artifact", "remote_state", "ledger"] as const;
export type ProbeDomain = (typeof PROBE_DOMAINS)[number];

/** `proxmox_residue.OwnedResource`. */
export interface OwnedResource {
  residue_class: ResidueClass;
  identifier: string;
  address: string | null;
}

/** `proxmox_residue.ProtectedResource` — refused for deletion because it is not provably ours. */
export interface ProtectedResource {
  resource: OwnedResource;
  provenance: ObjectProvenance;
  detail: string;
}

/**
 * `proxmox_residue.DeletionSet`.
 *
 * `undetermined` is a FOURTH bucket beside deletable/protected/already_absent. It is rendered as
 * its own group, never folded into either neighbour.
 */
export interface DeletionSet {
  deletable: OwnedResource[];
  protected: ProtectedResource[];
  already_absent: OwnedResource[];
  undetermined: OwnedResource[];
}

/** `base.TeardownResourceOutcome` — the same three the range API already emits. */
export const TEARDOWN_OUTCOMES = ["removed", "present", "unproven"] as const;
export type TeardownOutcome = (typeof TEARDOWN_OUTCOMES)[number];

/**
 * `proxmox_residue.AbsenceFinding`.
 *
 * `probe_healthy: false` with `outcome: "removed"` is a contradiction the backend does not emit —
 * a probe that was not working cannot prove absence — so the UI treats the pair as the unit it is.
 */
export interface AbsenceFinding {
  resource: OwnedResource;
  outcome: TeardownOutcome;
  probe_healthy: boolean;
  detail: string;
}

/** `proxmox_residue.ZeroResidueProof`. */
export interface ZeroResidueProof {
  /** `clean` | `residue` | `unproven`. */
  verdict: string;
  expected_count: number;
  confirmed_absent: number;
  still_present: number;
  unproven: number;
  protected: string[];
  uncovered: ResidueClass[];
  released_reservations: number;
  retained_reservations: number;
}
