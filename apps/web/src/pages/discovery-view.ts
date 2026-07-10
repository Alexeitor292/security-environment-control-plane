// Presentation view-models for Worker-Owned Read-Only Target Discovery (SECP-B5)
// and the discovery-derived candidate-plan review.
//
// This module composes the pinned target-discovery.ts contract — it never
// reinterprets a status predicate or safety constant, and it renders no
// endpoint, host, key, or secret material. Discovery request / queue / worker
// execution / evidence / eligibility / plan approval / apply are independent:
// an earlier state passing never implies a later one.

import type {
  DiscoveryCandidatePlan,
  DiscoveryEnrollment,
  DiscoveryEvidence,
  TargetDiscoveryStatus,
} from "../api/types";
import type { StepRailItem } from "../components/ui/StepRail";

/**
 * Closed codes the discovery surface actually surfaces, mapped to fixed copy.
 * Reason/failure codes are evidence a gate refused or a probe failed — shown,
 * never hidden. The shared resolveClosedCodeCopy guards malformed and
 * prototype-key codes and falls back to generic copy; a backend message is
 * never used as display text.
 */
export const DISCOVERY_ERROR_TEXT: Record<string, string> = {
  // generic (services raise these)
  domain_error: "That action is not allowed in the current state.",
  invalid_transition: "That action is not allowed in the current lifecycle state.",
  validation_failed: "The request was rejected by the server's validation.",
  forbidden: "You are not permitted to perform this action.",
  unauthenticated: "Your session is not authenticated.",
  not_found: "The requested discovery record was not found.",
  queue_conflict: "A discovery job is already in flight for this enrollment.",
  // worker / gate refusals (surfaced as reason codes)
  probe_source_sealed:
    "The worker's read-only probe source is sealed. A worker-side prerequisite is not enabled; the control plane cannot observe it.",
  bootstrap_unavailable:
    "The read-only bootstrap is not available for this target yet.",
  worker_identity_missing: "No worker identity is available to run discovery.",
  worker_identity_unapproved: "The worker identity has not been approved.",
  authorization_invalid: "The live-read authorization is not valid for this action.",
  authorization_expired: "The live-read authorization has expired.",
  authorization_revoked: "The live-read authorization was revoked.",
  authorization_missing: "No live-read authorization exists for this endpoint.",
  authorization_not_approved: "The live-read authorization has not been approved.",
  endpoint_binding_mismatch:
    "The endpoint binding no longer matches; re-bind before discovery.",
  bootstrap_host_key_mismatch:
    "The host key does not match the bound endpoint; re-confirm the bootstrap.",
  bundle_not_ready: "The worker's discovery bundle is not prepared yet.",
  bundle_not_prepared: "The worker's discovery bundle is not prepared yet.",
  credential_unavailable:
    "Credential resolution failed closed; no transport was constructed.",
  // capability outcomes (recorded as reason codes on an ineligible result)
  nested_virtualization_unavailable:
    "The host does not expose nested virtualization, which this profile requires.",
  insufficient_capacity: "The host does not have enough spare capacity for this profile.",
  capacity_insufficient: "The host does not have enough spare capacity for this profile.",
  no_storage_available: "No eligible storage was found on the host.",
  target_is_clustered:
    "The target is part of a Proxmox cluster; single-node discovery only.",
  ambiguous_node_selection: "The node selection is ambiguous; more than one node matched.",
  unsupported_proxmox_version: "The host's Proxmox version is not supported.",
};

// ------------------------------------------------------- lifecycle rail

/** Ordered happy-path discovery states (from TargetDiscoveryStatus). The
 *  worker-owned states are explicit; failure is off-rail. */
export const DISCOVERY_STEPS: { status: TargetDiscoveryStatus; label: string }[] = [
  { status: "requested", label: "Requested (queued for worker)" },
  { status: "discovering", label: "Discovering (worker probing)" },
  { status: "discovered", label: "Evidence recorded" },
  { status: "plan_ready", label: "Candidate plan ready" },
  { status: "approved", label: "Approved (apply sealed)" },
];

export function discoveryIndex(status: TargetDiscoveryStatus): number {
  return DISCOVERY_STEPS.findIndex((s) => s.status === status);
}

/** True for statuses not on the happy-path rail (failed). */
export function isOffRail(status: TargetDiscoveryStatus): boolean {
  return discoveryIndex(status) === -1;
}

/** Non-interactive rail: steps before the current status are complete, the
 *  current status is current, later steps blocked. A failed enrollment yields
 *  an all-blocked rail (the page shows the failure state separately) — skipped
 *  states are never marked complete. */
export function discoveryRailItems(status: TargetDiscoveryStatus): StepRailItem[] {
  const currentIndex = discoveryIndex(status);
  return DISCOVERY_STEPS.map((step, i) => ({
    id: step.status,
    label: step.label,
    state:
      currentIndex === -1
        ? "blocked"
        : i < currentIndex
          ? "complete"
          : i === currentIndex
            ? "current"
            : "blocked",
  }));
}

export const REQUEST_ENQUEUE_NOTICE =
  "Requesting discovery enqueues a durable worker job — it does not start discovery, and the app contacts no host. A worker claims the job and runs the read-only probes.";

export const WORKER_QUEUED_NOTICE =
  "Read-only discovery job queued — a worker will claim it and run the probes. Queued is not running; running is not completed.";

export const WORKER_RUNNING_NOTICE =
  "A worker has claimed this job and is running the read-only probes. Running is not completed; no candidate plan exists until evidence is recorded.";

// ---------------------------------------------------- worker posture

export interface WorkerPostureRow {
  key: string;
  value: string;
  mono?: boolean;
}

/** Worker-owned execution posture from real enrollment fields only. Ownership
 *  identity is server-owned; API enqueue is distinct from worker claim. */
export function workerPostureRows(e: DiscoveryEnrollment): WorkerPostureRow[] {
  const rows: WorkerPostureRow[] = [
    { key: "Ownership identity", value: e.ownership_label, mono: true },
    { key: "Enrollment version", value: String(e.enrollment_version) },
    { key: "Revision", value: String(e.revision) },
  ];
  if (e.approved_at) rows.push({ key: "Approved", value: e.approved_at });
  return rows;
}

// ---------------------------------------------------- eligibility

export type EligibilityState =
  | "eligible"
  | "ineligible"
  | "unverifiable"
  | "pending";

export interface EligibilityView {
  state: EligibilityState;
  label: string;
  /** The recorded reason code, if any — shown verbatim for operators. */
  reasonCode: string | null;
  /** Whether this is a not-yet-recorded state (evidence absent). */
  recorded: boolean;
}

const ELIGIBILITY_LABEL: Record<string, string> = {
  eligible: "Eligible (read-only capability facts recorded)",
  ineligible: "Ineligible",
  unverifiable: "Unverifiable (neither pass nor fail — a probe could not confirm)",
};

/** Eligibility outcome from durably recorded evidence. Absent evidence is
 *  "pending", never a false ineligible/eligible. */
export function eligibilityView(ev: DiscoveryEvidence | null): EligibilityView {
  if (!ev) {
    return { state: "pending", label: "Not yet recorded", reasonCode: null, recorded: false };
  }
  const raw = ev.eligibility;
  const state: EligibilityState =
    raw === "eligible" || raw === "ineligible" || raw === "unverifiable" ? raw : "pending";
  return {
    state,
    label: ELIGIBILITY_LABEL[raw] ?? "Unknown",
    reasonCode: ev.reason_code ?? null,
    recorded: true,
  };
}

/** Eligibility → StatusBadge domain/state. eligible=ok, ineligible=danger,
 *  unverifiable=pending (neither), pending=pending. */
export function eligibilityTone(state: EligibilityState): string {
  return state; // authorization domain maps these; see mapping in the page
}

// ---------------------------------------------------- evidence facts

export interface EvidenceFact {
  key: string;
  label: string;
  value: string;
}

/**
 * Allowlisted, durably-recorded evidence facts. Unknown keys are never
 * rendered. Values are booleans/counts/short identifiers only — never raw
 * output. A fact's presence is a recorded read-only observation, not a
 * broader safety claim.
 */
export function evidenceFacts(ev: DiscoveryEvidence | null): EvidenceFact[] {
  if (!ev) return [];
  const facts: EvidenceFact[] = [];
  const push = (key: string, label: string, value: string | null) => {
    if (value !== null && value !== "") facts.push({ key, label, value });
  };
  const bool = (v: boolean | null): string | null =>
    v === null ? null : v ? "yes" : "no";
  const num = (v: number | null): string | null => (v === null ? null : String(v));

  push(
    "proxmox_version",
    "Proxmox version",
    ev.version_major !== null ? `${ev.version_major}.${ev.version_minor ?? 0}` : null,
  );
  push("is_clustered", "Clustered", bool(ev.is_clustered));
  push("node", "Node", ev.node);
  push("node_count", "Node count", num(ev.node_count));
  push("cpu_total", "CPU total", num(ev.cpu_total));
  push("mem_total_mb", "Memory total (MB)", num(ev.mem_total_mb));
  push("mem_free_mb", "Memory free (MB)", num(ev.mem_free_mb));
  push("nested_available", "Nested virtualization", bool(ev.nested_available));
  push("selected_storage", "Selected storage", ev.selected_storage);
  push("storage_count", "Storage count", num(ev.storage_count));
  push(
    "candidate_vmids",
    "Candidate VM-IDs",
    ev.candidate_vmids.length ? ev.candidate_vmids.join(", ") : null,
  );
  push("bundle_available", "Worker bundle available", bool(ev.bundle_available));
  return facts;
}

// ---------------------------------------------------- candidate plan

export const PLAN_APPROVAL_DECISION_NOTICE =
  "Approval records a decision. Apply/provisioning remains sealed.";

export const PLAN_NON_EXECUTABLE_NOTICE =
  "This candidate plan is discovery-derived and non-executable. Approval is pinned to the exact plan hash; any change requires a new approval. Live apply remains sealed.";

export const CANDIDATE_PLAN_STALE_HINT =
  "The candidate plan changed (drift or supersede). Re-run discovery to review the current plan before approving.";

export interface CandidatePlanRow {
  key: string;
  value: string;
  mono?: boolean;
}

/** Candidate-plan summary rows from real plan fields only. */
export function candidatePlanRows(plan: DiscoveryCandidatePlan): CandidatePlanRow[] {
  return [
    { key: "Plan version", value: String(plan.plan_version) },
    { key: "Enrollment version", value: String(plan.enrollment_version) },
    { key: "Resource profile", value: plan.resource_profile, mono: true },
    { key: "Node", value: plan.node, mono: true },
    { key: "Storage", value: plan.storage, mono: true },
    { key: "Ownership tag", value: plan.ownership_tag, mono: true },
    { key: "Status", value: plan.status, mono: true },
    { key: "Expires", value: plan.expires_at.slice(0, 19).replace("T", " ") + " UTC" },
  ];
}

/** A candidate plan is stale for approval if its hash differs from the
 *  enrollment's active plan hash (drift/supersede), or it is not draft. */
export function planIsApprovable(
  plan: DiscoveryCandidatePlan | null,
  enrollment: DiscoveryEnrollment,
): boolean {
  if (!plan) return false;
  if (plan.status !== "draft") return false;
  return plan.plan_hash === enrollment.active_plan_hash;
}
