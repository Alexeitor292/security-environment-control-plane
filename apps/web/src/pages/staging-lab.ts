// Pure, framework-free logic for the Disposable Staging Lab workflow (SECP-002B-1B-9).
//
// Kept separate from the React component so it is unit-testable and free of DOM concerns.
// Provider-neutral; contains NO real infrastructure values (no endpoint, host, IP, bridge/VNet
// name, VMID, storage id, certificate, credential, token, secret ref, or artifact URL/checksum).
// The server owns all labels, re-validates every input, and only a worker records completion.

import type {
  EligibleSubstrate,
  StagingBootstrapArtifactProfile,
  StagingLab,
  StagingLabStatus,
  StagingResourceClass,
  StagingRollbackPolicy,
} from "../api/types";

/** Mandatory label shown on every execution control in this PR. */
export const SIMULATION_ONLY_LABEL =
  "Simulation only — no infrastructure will be created.";

/** Shown after queueing: the worker, not the API, performs and completes the simulation. */
export const QUEUED_NOTICE =
  "Simulation queued — a worker will process it. No infrastructure will be created.";

/** Fixed safety constraints shown on the review screen (mirrors the server contract). */
export const SAFETY_CONSTRAINTS: string[] = [
  "Self-contained staging control plane: staging API + database + worker inside one isolated VM.",
  "No production control-plane or production-database dependency.",
  "One isolated host-only network with no uplink, no gateway, and no DNS.",
  "Exactly one disposable nested Proxmox target.",
  "Exactly one target-facing connection: staging worker → nested target read-only API.",
  "Offline bootstrap: operator-approved pre-staged artifacts; no post-isolation internet.",
  "Approval permits fake simulation only — it is NOT a live-read authorization.",
];

export interface Option<T> {
  value: T;
  label: string;
  help: string;
}

/** Bounded, safe logical resource classes — never raw host CPU/RAM/disk values. */
export const RESOURCE_CLASSES: Option<StagingResourceClass>[] = [
  {
    value: "small_lab",
    label: "Small lab",
    help: "Minimal bounded footprint. Requires verified spare host headroom (checked out of band).",
  },
  {
    value: "medium_lab",
    label: "Medium lab",
    help: "Modest bounded footprint. Requires verified spare host headroom (checked out of band).",
  },
];

/** Approved offline bootstrap-artifact profiles — a closed backend catalog, never free text. */
export const BOOTSTRAP_PROFILES: Option<StagingBootstrapArtifactProfile>[] = [
  {
    value: "nested_proxmox_offline_base",
    label: "Nested Proxmox offline base",
    help: "Operator-approved, pre-staged offline artifact set. No post-isolation internet.",
  },
];

export const ROLLBACK_POLICIES: Option<StagingRollbackPolicy>[] = [
  {
    value: "revert_to_known_clean_checkpoint",
    label: "Revert to known-clean checkpoint",
    help: "Roll the disposable target back to a verified known-clean snapshot.",
  },
  {
    value: "destroy_and_rebuild",
    label: "Destroy and rebuild",
    help: "Tear down and rebuild the disposable target from documented automation.",
  },
];

/** Ordered lifecycle steps for the progress UI (explicit queued states). */
export const LIFECYCLE_STEPS: { status: StagingLabStatus; label: string }[] = [
  { status: "draft", label: "Draft" },
  { status: "planned", label: "Plan generated" },
  { status: "awaiting_approval", label: "Awaiting approval" },
  { status: "approved", label: "Approved (sim only)" },
  { status: "simulation_queued", label: "Simulation queued" },
  { status: "simulated_ready", label: "Simulated ready" },
  { status: "destroyed", label: "Torn down" },
];

export function lifecycleIndex(status: StagingLabStatus): number {
  return LIFECYCLE_STEPS.findIndex((s) => s.status === status);
}

export function isFailed(status: StagingLabStatus): boolean {
  return status === "failed";
}

/** True while a worker still owes completion — the UI must not present results as ready. */
export function isQueuedOrRunning(status: StagingLabStatus): boolean {
  return (
    status === "simulation_queued" ||
    status === "simulating" ||
    status === "teardown_queued" ||
    status === "tearing_down"
  );
}

export function planHashPrefix(hash: string | null | undefined): string {
  if (!hash) return "pending";
  return hash.replace(/^sha256:/, "").slice(0, 12);
}

export function substrateOptions(
  substrates: EligibleSubstrate[],
): { id: string; label: string }[] {
  return substrates.map((s) => ({ id: s.id, label: s.alias }));
}

export interface StagingLabDraft {
  executionTargetId: string;
  logicalName: string;
  resourceClass: StagingResourceClass;
  bootstrapArtifactProfile: StagingBootstrapArtifactProfile;
  rollbackPolicy: StagingRollbackPolicy;
}

export function emptyDraft(): StagingLabDraft {
  return {
    executionTargetId: "",
    logicalName: "",
    resourceClass: "small_lab",
    bootstrapArtifactProfile: "nested_proxmox_offline_base",
    rollbackPolicy: "revert_to_known_clean_checkpoint",
  };
}

// The optional logical name is the ONLY free-text field; it must be a strict kebab-case slug.
// (The server re-validates authoritatively and rejects anything else.)
const LOGICAL_NAME_RE = /^[a-z0-9]([a-z0-9-]{1,38}[a-z0-9])$/;

export interface DraftValidation {
  ok: boolean;
  errors: string[];
}

export function validateDraft(draft: StagingLabDraft): DraftValidation {
  const errors: string[] = [];
  if (!draft.executionTargetId) errors.push("Select an eligible substrate.");
  if (draft.logicalName.trim().length > 0 && !LOGICAL_NAME_RE.test(draft.logicalName.trim())) {
    errors.push(
      "Optional name must be a short lowercase kebab-case slug (a-z, 0-9, '-'), or left blank.",
    );
  }
  return { ok: errors.length === 0, errors };
}

export function canCreate(busy: boolean, draft: StagingLabDraft): boolean {
  return !busy && validateDraft(draft).ok;
}

export function canPlan(lab: StagingLab | null): boolean {
  return lab?.status === "draft";
}

export function canSubmit(lab: StagingLab | null): boolean {
  return lab?.status === "planned";
}

export function canApprove(lab: StagingLab | null): boolean {
  return lab?.status === "awaiting_approval";
}

export function canQueueSimulation(lab: StagingLab | null): boolean {
  return lab?.status === "approved" || lab?.status === "simulated_ready";
}

export function canQueueTeardown(lab: StagingLab | null): boolean {
  return lab?.status === "simulated_ready" || lab?.status === "approved";
}

/** Extract the logical resource kinds from a compiled plan for display (safe strings only). */
export function planResourceKinds(lab: StagingLab | null): string[] {
  const resources = (lab?.desired_state?.resources as { kind?: string }[] | undefined) ?? [];
  return resources.map((r) => String(r.kind ?? "")).filter((k) => k.length > 0);
}

/**
 * Simulated observed resources (fake) for display — ONLY when the worker has recorded
 * completion (status simulated_ready or destroyed). Never presented while queued/running.
 */
export function observedResources(
  lab: StagingLab | null,
): { kind: string; owner: string; phase: string }[] {
  if (!lab || (lab.status !== "simulated_ready" && lab.status !== "destroyed")) return [];
  const resources =
    (lab.simulated_observed_state?.resources as
      | { kind?: string; owner?: string; observed_phase?: string }[]
      | undefined) ?? [];
  return resources.map((r) => ({
    kind: String(r.kind ?? ""),
    owner: String(r.owner ?? ""),
    phase: String(r.observed_phase ?? ""),
  }));
}

export function rollbackPosture(lab: StagingLab | null): string {
  if (!lab) return "unknown";
  return lab.rollback_policy;
}

export function statusLabel(status: StagingLabStatus): string {
  if (status === "simulation_queued") return "Simulation queued (worker will process)";
  if (status === "simulating") return "Simulating (worker running)";
  if (status === "teardown_queued") return "Teardown queued (worker will process)";
  if (status === "tearing_down") return "Teardown in progress (worker running)";
  if (status === "destroyed") return "Torn down (simulated)";
  if (status === "simulated_ready") return "Simulated ready";
  return status;
}
