// Shapes of the RECORDED WORKER DOCUMENTS that the API carries as opaque JSON.
//
// READ THIS BEFORE ADDING ANYTHING HERE.
//
// Everything the control-plane API types is generated into `./generated/openapi.ts` from
// `contracts/openapi/openapi.json`. This file is the deliberate remainder: seven members of the
// Proxmox response models are declared `dict[str, Any]` / `list[dict[str, Any]]` in
// `secp_api.schemas_proxmox`, so OpenAPI publishes them as `{ [key: string]: unknown }` and the
// generator can only emit that. They are:
//
//   ProxmoxVerificationOut.infrastructure_checks   ProxmoxVerificationOut.isolation_checks
//   ProxmoxResetDispositionsOut.dispositions       ProxmoxResidueOut.resources
//   ProxmoxDestroyPlanOut.deletion_set             ProxmoxTopologyOut.topology
//   ProxmoxPlanOut.document
//
// They are opaque ON PURPOSE. `secp_api.proxmox_projection` copies them VERBATIM out of what the
// worker recorded (`_maybe_list(recorded.get("infrastructure_checks"))`), so declaring a Pydantic
// model for them would make the API drop any key the model did not know — silently discarding
// evidence the worker went to the trouble of recording. The API is right to pass them through.
//
// What is NOT acceptable is a client that therefore treats them as untyped soup. The declarations
// below say what the worker writes, and `./recorded.ts` NARROWS the opaque values at runtime
// against them. Nothing here is a contract: it is a reader's expectation, checked before use, and
// a value that does not match is reported as unreadable rather than coerced.
//
// Backend sources, module by module:
//
//   secp_api.range_providers.proxmox_model      — ownership, guests, network specs, topology
//   secp_api.range_providers.proxmox_network    — segregated network compiler
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
import type { CheckFindingOut } from "./generated/openapi";

// Enums are `as const` arrays with types derived from them. A bare union is erased at build time
// and can prove nothing at runtime; the arrays let the tone maps be checked exhaustive AND let the
// narrowing functions in `./recorded.ts` validate a recorded value against the real member set.

// --- ownership and object classification (proxmox_model) ---------------------------------------

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

/**
 * `proxmox_model.Ownership` — the identity stamped on every object SECP creates.
 *
 * NOT the same shape as the generated `OwnershipClassOut`, which is what `/proxmox/ownership`
 * returns. That one adds the tag set and the acts-on / never-touches provenance lists and drops
 * `resource_kind` and `team_ref`, because the endpoint describes the RANGE's stamping rule while
 * this describes ONE object's stamp. Read the endpoint's type for the rule and this one for an
 * object inside a compiled topology.
 */
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
 * TWO fields here, THREE on the wire. The generated `ProxmoxGuestAddressOut` additionally carries
 * `observed_address`, `observed` and `probe_is_distinct`, because the endpoint can report what the
 * provider actually reported after apply and the compiled document cannot — it is a plan, and a
 * plan has observed nothing. Do not add an `observed_address` here: a compiled topology that
 * appeared to carry one would be claiming an observation nobody made.
 *
 * `published_address` is what the guest is told to report to; `probe_address` is what the worker
 * can actually reach. Collapsing them is the defect fixed by #103 — the worker probed the address
 * it published.
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

/**
 * `proxmox_model.GuestSpec` — one VM or container in the desired state.
 *
 * A SUPERSET of the generated `ProxmoxGuestOut`. The endpoint publishes the identity and placement
 * of each guest; this is the full compiled spec, and it exists only inside
 * `ProxmoxTopologyOut.topology`. Sizing (`cpu_cores`, `memory_mb`, `disks`) and the per-NIC detail
 * are here and not on the typed endpoint — see the delta note in `./recorded.ts`.
 */
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

/** `proxmox_model.CompiledTopology` — the document inside `ProxmoxTopologyOut.topology`. */
export interface CompiledTopology {
  target: ProxmoxTargetIdentity;
  ownership: Ownership;
  network: SegregatedNetworkPlan;
  guests: GuestSpec[];
}

/** `proxmox_network.IsolationProperty` — the member set behind `IsolationFindingOut.property`. */
export const ISOLATION_PROPERTIES = [
  "cross_team_blocked",
  "management_plane_unreachable",
  "control_plane_unreachable",
  "no_default_public_route",
  "default_deny_present",
  "scoring_reachable",
] as const;
export type IsolationProperty = (typeof ISOLATION_PROPERTIES)[number];

// --- allocations (proxmox_ipam) ----------------------------------------------------------------

/** The member set behind the generated `ProxmoxAllocationOut.kind`, which is typed `string`. */
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

/** The member set behind the generated `ReadinessFindingOut.requirement`, typed `string`. */
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

// --- plan document (plan_document) -------------------------------------------------------------

/** `plan_document.EXECUTION_STATUS_NOT_APPLIED`. Rendered verbatim, never softened. */
export const EXECUTION_STATUS_NOT_APPLIED = "NOT APPLIED";

/**
 * `plan_document.PLAN_DOCUMENT_VERSION` — the WORKER's OpenTofu plan document.
 *
 * NOT the same document as `ProxmoxPlanOut.document_version`, which is
 * `secp-proxmox/desired-state-document/v1`: the desired state this API compiled. This one
 * describes what `tofu plan` computed against real remote state and is produced only inside the
 * privileged worker. A screen that labels one with the other's version is claiming a plan ran.
 */
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
 * `proxmox_verification.VerificationReport`.
 *
 * `findings` is the GENERATED `CheckFindingOut`, not a hand-written twin. The pair used to be
 * transcribed here because the wire published an opaque dict; it is typed on the contract now, so
 * a second declaration would be exactly the divergent copy this file exists to avoid.
 */
export interface VerificationReport {
  outcome: VerificationOutcome;
  findings: CheckFindingOut[];
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

/** `proxmox_reset.ResetAction` — the shape inside `ProxmoxResetDispositionsOut.dispositions`. */
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

/**
 * `proxmox_reconcile.ReconcileDecision`.
 *
 * NO HTTP SURFACE. Nothing under `/api/v1/ranges/{id}/proxmox/*` returns a reconcile decision,
 * typed or opaque — see the delta note in `./recorded.ts`. Kept because the tone map for
 * `halt` encodes a product rule (stopping to ask is correct behaviour, not an error) that the
 * endpoint will need the day it lands.
 */
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
 * from the apply codes, which is the machine-readable form of the same separation the API enforces
 * by giving apply and destroy authorization requests non-interchangeable body shapes.
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
 * `proxmox_destroy_gate.DestroyApproval` — the WORKER-side approval the destroy gate consumes.
 *
 * Not the same record as the generated `ApprovalOut`, which is what the API publishes for a
 * recorded approval. Both carry the operation kind for the same reason: an apply approval must be
 * structurally unable to authorize a destroy. `ApprovalOut.operation_kind` is a four-member enum
 * (`plan_approval` | `apply_authorization` | `destroy_plan_approval` | `destroy_authorization`);
 * this one is the gate's own `"destroy"` marker.
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
 * `proxmox_residue.DeletionSet` — the document inside `ProxmoxDestroyPlanOut.deletion_set`.
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
 * `proxmox_residue.AbsenceFinding` — the shape inside `ProxmoxResidueOut.resources`.
 *
 * `probe_healthy: false` with `outcome: "removed"` is a contradiction the backend does not emit —
 * a probe that was not working cannot prove absence — so a reader treats the pair as the unit it
 * is, exactly as `CheckFinding` treats `(observed, ok)`.
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
