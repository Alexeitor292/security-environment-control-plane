// Pure view-model for the Proxmox range surfaces. No React, no fetching.
//
// The rules this module exists to hold:
//
//  1. THREE OUTCOMES, NOT TWO. `unproven`, `undetermined`, `unknown`, `state_disagreement` and
//     `recovery_required` each get a tone that is neither the success tone nor the failure tone.
//     An unprovable outcome shown as either is the defect the whole programme exists to prevent.
//  2. A PLAN HAS NOT RUN. Plan review renders `EXECUTION STATUS: NOT APPLIED` from the document,
//     and approving a plan is never described as starting anything.
//  3. APPLY AND DESTROY ARE TWO AUTHORIZATIONS. They have separate states, separate hashes and
//     separate copy here, and `assertSeparateAuthorizations` refuses to let a screen show one
//     hash under the other's label.
//  4. THE BROWSER IS NOT THE BOUNDARY. `mutationAvailability` returns a reason, and the reason is
//     rendered next to the control — the server-side gate is what refuses, and the copy says so.

import type {
  AbsenceFinding,
  ApplyAuthorizationState,
  AuthoritativeState,
  CheckFinding,
  DeletionSet,
  DestroyAuthorizationState,
  DestroyPreconditions,
  GuestSpec,
  IsolationFinding,
  PlanApprovalState,
  PlanDocument,
  ReadinessFinding,
  ReconcileAction,
  ResetDisposition,
  SegregatedNetworkPlan,
  VerificationCheck,
  VerificationOutcome,
  VerificationReport,
  VNetSpec,
} from "./proxmox-types";
import { EXECUTION_STATUS_NOT_APPLIED, ISOLATION_CHECK_KEYS } from "./proxmox-types";
import type { StatusTone } from "../../../components/ui";

// ------------------------------------------------------------------------------------- copy

export const PROXMOX_SURFACE_NOTE =
  "Proxmox ranges run on a cluster this control plane does not own. Every object SECP creates carries an ownership stamp, and nothing without that stamp is ever modified or deleted.";

/**
 * The single most important sentence on the plan review screen. A plan is a description of
 * intended change. Reading one changes nothing; approving one still changes nothing.
 */
export const PLAN_NOT_APPLIED_NOTE =
  `The plan below has not run. Its execution status is ${EXECUTION_STATUS_NOT_APPLIED}: no resource has been created, changed or deleted on the cluster, and nothing on this screen starts apply.`;

export const APPLY_APPROVAL_IS_NOT_APPLY_NOTE =
  "Approving a plan records a decision. It does not start apply. Apply begins only when a worker claims the operation and the server-side apply gate authorizes it against the plan hash, the allocation ledger, the worker identity and the target — any of which can still refuse after this approval is recorded.";

export const APPLY_AND_DESTROY_ARE_SEPARATE_NOTE =
  "Destroy authorization is a separate decision from apply authorization, taken against a separate plan with its own hash. An apply approval is never a destroy approval: the destroy gate refuses an approval whose operation kind is not \"destroy\" (proxmox.destroy.approval_is_not_for_destroy).";

export const DESTROY_PLAN_NOTE =
  "This is a destroy plan. It lists the objects the worker intends to delete and the deletion-set hash the destroy gate will check them against. It is not the apply plan and does not share its hash.";

export const AUTHORIZATION_IS_SERVER_SIDE_NOTE =
  "Controls on this page are enabled from the recorded lifecycle state as a convenience only. They are not the security boundary: every mutation is authorized server-side, and a request the server does not authorize is refused whether or not a control was offered for it.";

export const UNPROVEN_IS_NOT_CLEAN_NOTE =
  "An unproven result is not a clean result. It means the check could not be run — commonly because the cluster was unreachable, which makes the removal and the \"is it gone?\" check fail for the same reason. Nobody has proved these objects are gone.";

export const OWNERSHIP_NOTE =
  "Objects are matched by ownership TAGS, never by name. An object that is untagged, unreadable, or tagged for another scope is protected: it is neither deleted nor counted as ours.";

export const PROBE_ADDRESS_NOTE =
  "The published address is what a guest is told to report to. The probe address is what the worker can actually reach. They are shown separately because assuming they are the same is a defect this codebase has already fixed once.";

export const SCORES_ARE_SERVER_SIDE_NOTE =
  "Scores are computed and held by the server. Nothing in this browser derives, sums or adjusts a total.";

// ------------------------------------------------------------------------------- tone maps

/**
 * `VerificationOutcome` — five members, four distinct tones.
 *
 * `verification_failed` and `isolation_failed` are both red because both are findings: the worker
 * looked and did not like what it saw. `state_disagreement` is amber because recorded state and
 * observation disagreeing is not itself proof either one is wrong. `recovery_required` is amber
 * because nothing was observed at all — and it must never share the green of `verified` or the red
 * of the two failures, because it is not a claim in either direction.
 */
export const VERIFICATION_OUTCOME_TONE: Record<VerificationOutcome, StatusTone> = {
  verified: "ok",
  verification_failed: "danger",
  isolation_failed: "danger",
  state_disagreement: "warn",
  recovery_required: "warn",
};

export const VERIFICATION_OUTCOME_LABEL: Record<VerificationOutcome, string> = {
  verified: "Verified",
  verification_failed: "Verification failed",
  isolation_failed: "Isolation failed",
  state_disagreement: "State disagreement",
  recovery_required: "Recovery required",
};

export const VERIFICATION_OUTCOME_HELP: Record<VerificationOutcome, string> = {
  verified: "Every required check was observed and passed.",
  verification_failed: "A required check was observed and did not pass. The deployment is not as planned.",
  isolation_failed: "A segmentation check was observed and did not pass. Traffic that must be denied was not denied.",
  state_disagreement: "Recorded state and observed infrastructure disagree. Neither is yet known to be the wrong one.",
  recovery_required: "The cluster could not be observed, so nothing was proved either way. A human has to look.",
};

/** `ProbeVerdict`. `unknown` is amber: the probe did not run, so it found neither. */
export const PROBE_VERDICT_TONE: Record<string, StatusTone> = {
  reachable: "ok",
  blocked: "ok",
  unknown: "warn",
};

/**
 * Per-check status, derived from the `(observed, ok)` pair rather than from `ok` alone.
 *
 * `observed: false` means the check could not be run and `ok` carries no information. Reading only
 * `ok` renders an unobservable check as a failure, which claims a finding nobody made.
 */
export type CheckStatus = "passed" | "failed" | "not_observed";

export const CHECK_STATUS_TONE: Record<CheckStatus, StatusTone> = {
  passed: "ok",
  failed: "danger",
  not_observed: "warn",
};

export const CHECK_STATUS_LABEL: Record<CheckStatus, string> = {
  passed: "passed",
  failed: "failed",
  not_observed: "not observed",
};

export function checkStatus(finding: CheckFinding): CheckStatus {
  if (!finding.observed) return "not_observed";
  return finding.ok ? "passed" : "failed";
}

/** `ObjectProvenance`. Only `secp_owned` is ours; the other three are protected, not failures. */
export const OBJECT_PROVENANCE_TONE: Record<string, StatusTone> = {
  secp_owned: "ok",
  secp_foreign_scope: "warn",
  untagged: "warn",
  unreadable: "warn",
};

export const OBJECT_PROVENANCE_LABEL: Record<string, string> = {
  secp_owned: "SECP-owned (this scope)",
  secp_foreign_scope: "SECP-tagged, another scope",
  untagged: "Untagged — not ours",
  unreadable: "Unreadable — cannot classify",
};

/** `TeardownResourceOutcome`, matching the range contract's existing three. */
export const TEARDOWN_OUTCOME_TONE: Record<string, StatusTone> = {
  removed: "ok",
  present: "danger",
  unproven: "warn",
};

/** `ResetDisposition`. All four are intended outcomes; none is an error. */
export const RESET_DISPOSITION_TONE: Record<ResetDisposition, StatusTone> = {
  preserved: "ok",
  recreated: "accent",
  restored: "accent",
  cleared: "warn",
};

/** `ReconcileAction`. `halt` is amber, not red: stopping to ask is correct behaviour. */
export const RECONCILE_ACTION_TONE: Record<ReconcileAction, StatusTone> = {
  no_action: "ok",
  resume_apply: "accent",
  halt: "warn",
};

export const RECONCILE_ACTION_LABEL: Record<ReconcileAction, string> = {
  no_action: "No action",
  resume_apply: "Resume apply",
  halt: "Halt — human decision required",
};

export const PLAN_APPROVAL_TONE: Record<PlanApprovalState, StatusTone> = {
  draft: "warn",
  approved: "ok",
  rejected: "danger",
  superseded: "pending",
};

export const PLAN_APPROVAL_LABEL: Record<PlanApprovalState, string> = {
  draft: "Awaiting review",
  approved: "Approved",
  rejected: "Rejected",
  superseded: "Superseded",
};

/**
 * Apply authorization, as its own state with its own tones.
 *
 * `plan_approved_apply_not_authorized` is deliberately NOT green. A recorded approval is not an
 * authorization: the gate still evaluates hashes, drift, worker identity and target at claim time.
 * Painting an approved plan green invites exactly the reading "approval started apply".
 */
export const APPLY_AUTHORIZATION_TONE: Record<ApplyAuthorizationState, StatusTone> = {
  not_requested: "pending",
  plan_awaiting_review: "warn",
  plan_approved_apply_not_authorized: "accent",
  apply_authorized: "ok",
  apply_refused: "danger",
};

export const APPLY_AUTHORIZATION_LABEL: Record<ApplyAuthorizationState, string> = {
  not_requested: "No plan requested",
  plan_awaiting_review: "Plan awaiting review",
  plan_approved_apply_not_authorized: "Plan approved — apply NOT authorized",
  apply_authorized: "Apply authorized by the server gate",
  apply_refused: "Apply refused by the server gate",
};

export const APPLY_AUTHORIZATION_HELP: Record<ApplyAuthorizationState, string> = {
  not_requested: "No OpenTofu plan has been generated for this range yet.",
  plan_awaiting_review: "A plan exists and has not been reviewed. Nothing has run.",
  plan_approved_apply_not_authorized:
    "An operator approved the plan. The apply gate has not authorized apply, and may still refuse it.",
  apply_authorized:
    "The apply gate evaluated the plan hash, allocations, ownership scope, worker identity and target, and authorized apply to start.",
  apply_refused: "The apply gate refused. The refusal code says which precondition was not met.",
};

/** Destroy authorization. A parallel state, never a continuation of the apply one. */
export const DESTROY_AUTHORIZATION_TONE: Record<DestroyAuthorizationState, StatusTone> = {
  not_requested: "pending",
  destroy_plan_awaiting_review: "warn",
  destroy_plan_approved_not_authorized: "accent",
  destroy_authorized: "ok",
  destroy_refused: "danger",
};

export const DESTROY_AUTHORIZATION_LABEL: Record<DestroyAuthorizationState, string> = {
  not_requested: "No destroy plan requested",
  destroy_plan_awaiting_review: "Destroy plan awaiting review",
  destroy_plan_approved_not_authorized: "Destroy plan approved — destroy NOT authorized",
  destroy_authorized: "Destroy authorized by the server gate",
  destroy_refused: "Destroy refused by the server gate",
};

export const DESTROY_AUTHORIZATION_HELP: Record<DestroyAuthorizationState, string> = {
  not_requested: "No destroy plan has been generated for this range.",
  destroy_plan_awaiting_review:
    "A destroy plan exists and has not been reviewed. No object has been deleted.",
  destroy_plan_approved_not_authorized:
    "An operator approved the destroy plan. The destroy gate has not authorized destroy, and may still refuse it.",
  destroy_authorized:
    "The destroy gate matched the destroy approval to a destroy plan, checked the deletion-set hash and confirmed ownership, and authorized deletion to start.",
  destroy_refused: "The destroy gate refused. The refusal code says which precondition was not met.",
};

/** `ReadinessRequirement` and `IsolationProperty` findings share a shape: met/holds + detail. */
export const FINDING_TONE: Record<"met" | "unmet", StatusTone> = {
  met: "ok",
  unmet: "danger",
};

// -------------------------------------------------------------- three-valued precondition

export type TriState = "yes" | "no" | "not_stated";

export const TRISTATE_TONE: Record<TriState, StatusTone> = {
  yes: "ok",
  no: "danger",
  not_stated: "warn",
};

export const TRISTATE_LABEL: Record<TriState, string> = {
  yes: "yes",
  no: "no",
  not_stated: "not stated",
};

/**
 * `bool | None` from the gate's precondition dataclasses.
 *
 * `null` is `not_stated`, NOT `no`. The gate treats an unstated precondition as unsatisfied and
 * refuses, which is correct — but "the control plane did not tell us" and "the control plane told
 * us no" are different facts, and only the second is a finding about the cluster.
 */
export function triState(value: boolean | null | undefined): TriState {
  if (value === true) return "yes";
  if (value === false) return "no";
  return "not_stated";
}

export interface PreconditionRow {
  key: string;
  label: string;
  state: TriState;
}

const APPLY_PRECONDITION_LABELS: Record<keyof AuthoritativeState, string> = {
  onboarding_current: "Target onboarding current",
  eligibility_passing: "Eligibility passing",
  discovery_fresh: "Discovery fresh",
  reservations_persisted: "Reservations persisted",
  remote_state_lock_held: "Remote state lock held",
  credential_resolved: "Credential resolved",
};

export function applyPreconditionRows(state: AuthoritativeState): PreconditionRow[] {
  return (Object.keys(APPLY_PRECONDITION_LABELS) as (keyof AuthoritativeState)[]).map((key) => ({
    key,
    label: APPLY_PRECONDITION_LABELS[key],
    state: triState(state[key]),
  }));
}

const DESTROY_PRECONDITION_LABELS: Record<
  Exclude<keyof DestroyPreconditions, "approval_already_consumed">,
  string
> = {
  ownership_verified: "Ownership verified on the cluster",
  discovery_fresh: "Discovery fresh",
  remote_state_lock_held: "Remote state lock held",
  credential_resolved: "Credential resolved",
};

export function destroyPreconditionRows(state: DestroyPreconditions): PreconditionRow[] {
  const rows: PreconditionRow[] = (
    Object.keys(DESTROY_PRECONDITION_LABELS) as (keyof typeof DESTROY_PRECONDITION_LABELS)[]
  ).map((key) => ({ key, label: DESTROY_PRECONDITION_LABELS[key], state: triState(state[key]) }));
  // Consumption is a plain boolean on the backend, and its SAFE value is false: an approval that
  // has already been used must not be replayed. It is inverted here so the column reads the same
  // direction as every other row — "yes" is always the good answer.
  rows.push({
    key: "approval_not_consumed",
    label: "Approval not already consumed",
    state: state.approval_already_consumed ? "no" : "yes",
  });
  return rows;
}

// ---------------------------------------------------------------------- plan and hashes

export interface PlanHashRow {
  key: string;
  label: string;
  hash: string;
}

/**
 * The hashes an operator checks at plan review, in the order the gate checks them.
 *
 * They are separate rows with separate labels rather than one "plan hash", because the apply gate
 * refuses on each of them independently (`change_set_hash_mismatch`, `desired_state_drift`,
 * `stale_binary_plan`) and an operator comparing a mismatch needs to know which one moved.
 */
export function planHashRows(doc: PlanDocument): PlanHashRow[] {
  return [
    { key: "plan_document_hash", label: "Plan document hash", hash: doc.plan_document_hash },
    { key: "change_set_hash", label: "Change-set hash", hash: doc.change_set_hash },
    { key: "desired_state_hash", label: "Desired-state hash", hash: doc.desired_state_hash },
  ];
}

export interface ChangeCounts {
  create: number;
  update: number;
  destroy: number;
}

export function changeCounts(doc: PlanDocument): ChangeCounts {
  return {
    create: doc.create_addresses.length,
    update: doc.update_addresses.length,
    destroy: doc.delete_addresses.length,
  };
}

/** True only when the document itself says it has not run. Never inferred from a lifecycle state. */
export function planIsUnapplied(doc: PlanDocument): boolean {
  return doc.execution_status === EXECUTION_STATUS_NOT_APPLIED;
}

/**
 * Guard against the one presentation error that would undo the whole separation: showing the apply
 * plan hash under a destroy label, or the reverse.
 *
 * Thrown rather than logged. A screen that cannot tell the two authorizations apart must not
 * render at all — a silently mislabelled hash is worse than a blank panel, because an operator
 * would approve a destroy against a hash they believe they already reviewed.
 */
export function assertSeparateAuthorizations(
  applyChangeSetHash: string,
  destroyChangeSetHash: string,
): void {
  if (applyChangeSetHash !== "" && applyChangeSetHash === destroyChangeSetHash) {
    throw new Error(
      "apply and destroy change-set hashes are identical; a destroy plan must be a distinct plan with a distinct hash",
    );
  }
}

// ------------------------------------------------------------------------ mutation availability

export interface MutationAvailability {
  /** Whether the control is offered. NOT a security decision — see the reason copy. */
  enabled: boolean;
  /** Why, rendered beside the control in both directions. */
  reason: string;
}

/**
 * Whether to OFFER a control, and why.
 *
 * The reason is rendered whether the control is offered or not, which is the point: an operator
 * must never be left to infer a security property from a missing button. Hiding a control is a
 * convenience — the server refuses the request regardless, and the copy attached to every one of
 * these says so.
 */
export function mutationAvailability(
  recordedState: string,
  allowedStates: readonly string[],
  action: string,
): MutationAvailability {
  if (allowedStates.includes(recordedState)) {
    return {
      enabled: true,
      reason: `The control plane records this range as "${recordedState}". ${action} is offered here; the server still authorizes it independently.`,
    };
  }
  return {
    enabled: false,
    reason: `The control plane records this range as "${recordedState}", and ${action.toLowerCase()} is not offered in that state. This is a convenience, not the boundary: the request would be refused server-side.`,
  };
}

// ------------------------------------------------------------------------------ projections

export interface GuestRow {
  guestRef: string;
  name: string;
  kind: string;
  vmid: number;
  node: string;
  template: string;
  cloneStrategy: string;
  cpuCores: number;
  memoryMb: number;
  /** Rendered as `scsi0 40 GB on local-lvm`, one per disk. */
  disks: string[];
  totalDiskGb: number;
  storageIds: string[];
  macs: string[];
  vnets: string[];
  publishedAddress: string;
  probeAddress: string | null;
  teamRef: string | null;
  ownershipLine: string;
}

/** `Ownership` as one identifier line. Ownership is what makes an object ours; it is always shown. */
export function ownershipLine(o: GuestSpec["ownership"]): string {
  const team = o.team_ref === null ? "" : ` team=${o.team_ref}`;
  return `org=${o.organization_id} target=${o.target_id} range=${o.range_id} gen=${o.generation}/${o.operation_generation}${team}`;
}

export function guestRows(guests: readonly GuestSpec[]): GuestRow[] {
  return guests.map((g) => ({
    guestRef: g.guest_ref,
    name: g.name,
    kind: g.kind,
    vmid: g.vmid,
    node: g.node_name,
    template: g.template_ref,
    cloneStrategy: g.clone_strategy,
    cpuCores: g.cpu_cores,
    memoryMb: g.memory_mb,
    disks: g.disks.map((d) => `${d.slot} ${d.size_gb} GB on ${d.storage_id}`),
    totalDiskGb: g.disks.reduce((sum, d) => sum + d.size_gb, 0),
    storageIds: [...new Set(g.disks.map((d) => d.storage_id))],
    macs: g.nics.map((n) => n.mac_address),
    vnets: g.nics.map((n) => n.vnet_name),
    publishedAddress: g.address.published_address,
    probeAddress: g.address.probe_address,
    teamRef: g.ownership.team_ref,
    ownershipLine: ownershipLine(g.ownership),
  }));
}

export interface SegmentRow {
  vnet: string;
  zone: string;
  vlanTag: number;
  cidr: string;
  gateway: string;
  routed: boolean;
  role: string;
  teamRef: string | null;
  securityGroup: string | null;
  alias: string;
}

export function segmentRows(plan: SegregatedNetworkPlan): SegmentRow[] {
  return plan.vnets.map((v: VNetSpec) => ({
    vnet: v.name,
    zone: v.zone_name,
    vlanTag: v.vlan_tag,
    cidr: v.subnet.cidr,
    gateway: v.subnet.gateway,
    routed: v.subnet.routed,
    role: v.role,
    teamRef: v.ownership.team_ref,
    securityGroup: plan.vnet_security_group[v.name] ?? null,
    alias: v.alias,
  }));
}

/** Team topology: which segments and guests belong to each team ref. */
export interface TeamTopologyRow {
  teamRef: string;
  segments: SegmentRow[];
  guests: GuestRow[];
}

export function teamTopology(
  plan: SegregatedNetworkPlan,
  guests: readonly GuestSpec[],
): TeamTopologyRow[] {
  const segments = segmentRows(plan);
  const rows = guestRows(guests);
  const refs: string[] = [];
  for (const s of segments) if (s.teamRef !== null && !refs.includes(s.teamRef)) refs.push(s.teamRef);
  for (const g of rows) if (g.teamRef !== null && !refs.includes(g.teamRef)) refs.push(g.teamRef);
  return refs.map((teamRef) => ({
    teamRef,
    segments: segments.filter((s) => s.teamRef === teamRef),
    guests: rows.filter((g) => g.teamRef === teamRef),
  }));
}

/** Shared segments — those with no team ref, e.g. the scoring segment. */
export function sharedSegments(plan: SegregatedNetworkPlan): SegmentRow[] {
  return segmentRows(plan).filter((s) => s.teamRef === null);
}

export interface VerificationSummary {
  outcome: VerificationOutcome;
  passed: number;
  failed: number;
  notObserved: number;
  /** Isolation checks that were not observed. Called out separately: unproved segmentation. */
  isolationNotObserved: VerificationCheck[];
}

export function verificationSummary(report: VerificationReport): VerificationSummary {
  let passed = 0;
  let failed = 0;
  let notObserved = 0;
  const isolationNotObserved: VerificationCheck[] = [];
  for (const f of report.findings) {
    const status = checkStatus(f);
    if (status === "passed") passed += 1;
    else if (status === "failed") failed += 1;
    else {
      notObserved += 1;
      if (ISOLATION_CHECK_KEYS.includes(f.check)) isolationNotObserved.push(f.check);
    }
  }
  return { outcome: report.outcome, passed, failed, notObserved, isolationNotObserved };
}

export interface ResidueSummary {
  deletable: number;
  protected: number;
  alreadyAbsent: number;
  undetermined: number;
  confirmedAbsent: number;
  stillPresent: number;
  unproven: number;
  /**
   * True when every finding is `removed` AND every probe that produced one was healthy. A removed
   * verdict from an unhealthy probe proves nothing, so it does not count toward a clean result.
   */
  provedClean: boolean;
}

export function residueSummary(
  set: DeletionSet,
  findings: readonly AbsenceFinding[],
): ResidueSummary {
  const confirmedAbsent = findings.filter((f) => f.outcome === "removed" && f.probe_healthy).length;
  const stillPresent = findings.filter((f) => f.outcome === "present").length;
  const unproven = findings.filter((f) => f.outcome === "unproven" || !f.probe_healthy).length;
  return {
    deletable: set.deletable.length,
    protected: set.protected.length,
    alreadyAbsent: set.already_absent.length,
    undetermined: set.undetermined.length,
    confirmedAbsent,
    stillPresent,
    unproven,
    provedClean:
      findings.length > 0 && stillPresent === 0 && unproven === 0 && set.undetermined.length === 0,
  };
}

export function isolationHolds(findings: readonly IsolationFinding[]): boolean {
  return findings.length > 0 && findings.every((f) => f.holds);
}

export function readinessSatisfied(findings: readonly ReadinessFinding[]): boolean {
  return findings.length > 0 && findings.every((f) => f.met);
}

// ---------------------------------------------------------------------- provider applicability

/**
 * Provider names that mean "this range runs on Proxmox".
 *
 * A list rather than one string because the range catalog's `provider` field is free-form text on
 * the template row, and the first Proxmox template could plausibly land under any of these.
 */
export const PROXMOX_PROVIDER_NAMES: readonly string[] = ["proxmox", "proxmox_ve", "proxmox-ve"];

export function isProxmoxProvider(provider: string): boolean {
  return PROXMOX_PROVIDER_NAMES.includes(provider.trim().toLowerCase());
}

export interface ProviderApplicability {
  applies: boolean;
  note: string;
}

/**
 * Whether the Proxmox surfaces describe THIS range.
 *
 * They are reachable on every range rather than hidden behind a provider match, because no range
 * template on main declares a Proxmox provider — the shipped catalog is `local_docker` only. Gating
 * the tabs on the provider would make them unreachable and therefore unreviewable, and quietly
 * showing Proxmox screens over a Docker range would be worse still. So they are shown, and each one
 * says which case it is in.
 *
 * When a Proxmox template lands, `applies` becomes true for those ranges with no change here.
 */
export function providerApplicability(provider: string): ProviderApplicability {
  if (isProxmoxProvider(provider)) {
    return {
      applies: true,
      note: `This range is recorded against provider "${provider}". These surfaces describe how it is placed, planned, verified and torn down.`,
    };
  }
  return {
    applies: false,
    note: `This range is recorded against provider "${provider}", not Proxmox. Nothing on these Proxmox tabs describes this range, and no control here acts on it. They are reachable so the Proxmox operator surfaces can be reviewed before a Proxmox range template exists — the shipped range catalog declares only local_docker.`,
  };
}

/** Human label for an enum member: `cross_team_denial` -> `cross team denial`. */
export function humanize(value: string): string {
  return value.replace(/_/g, " ");
}

/** Strip the `proxmox.apply.` / `proxmox.destroy.` namespace for display, keeping the full code in a title. */
export function refusalCodeLabel(code: string): string {
  const tail = code.startsWith("proxmox.") ? code.split(".").slice(2).join(".") : code;
  return humanize(tail);
}
