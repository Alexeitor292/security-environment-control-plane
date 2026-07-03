// Pure, framework-free logic for the Disposable Staging Lab workflow (SECP-002B-1B-9).
//
// Kept separate from the React component so it is unit-testable and free of DOM concerns.
// Provider-neutral; contains NO real infrastructure values (no endpoint, host, IP, bridge/VNet
// name, VMID, storage id, certificate, credential, token, secret ref, or artifact URL/checksum).
// The server re-validates, re-compiles, and re-hashes everything; this only guides the operator.

import type {
  ExecutionTarget,
  StagingLab,
  StagingLabStatus,
  StagingResourceClass,
  StagingRollbackPolicy,
} from "../api/types";

/** Mandatory label shown on every execution control in this PR. */
export const SIMULATION_ONLY_LABEL =
  "Simulation only — no infrastructure will be created.";

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

/** Ordered lifecycle steps for the progress UI. */
export const LIFECYCLE_STEPS: { status: StagingLabStatus; label: string }[] = [
  { status: "draft", label: "Draft" },
  { status: "planned", label: "Plan generated" },
  { status: "awaiting_approval", label: "Awaiting approval" },
  { status: "approved", label: "Approved (sim only)" },
  { status: "simulated_ready", label: "Simulated ready" },
  { status: "destroyed", label: "Torn down" },
];

export function lifecycleIndex(status: StagingLabStatus): number {
  return LIFECYCLE_STEPS.findIndex((s) => s.status === status);
}

export function isFailed(status: StagingLabStatus): boolean {
  return status === "failed";
}

export function planHashPrefix(hash: string | null | undefined): string {
  if (!hash) return "pending";
  return hash.replace(/^sha256:/, "").slice(0, 12);
}

/** Approved substrate targets a lab may be built on (safe display names only). */
export function substrateOptions(targets: ExecutionTarget[]): { id: string; label: string }[] {
  return targets
    .filter((t) => t.status === "active")
    .map((t) => ({ id: t.id, label: t.display_name }));
}

export interface StagingLabDraft {
  executionTargetId: string;
  displayName: string;
  ownershipLabel: string;
  resourceClass: StagingResourceClass;
  rollbackPolicy: StagingRollbackPolicy;
  bootstrapArtifactProfileId: string;
}

export function emptyDraft(): StagingLabDraft {
  return {
    executionTargetId: "",
    displayName: "",
    ownershipLabel: "",
    resourceClass: "small_lab",
    rollbackPolicy: "revert_to_known_clean_checkpoint",
    bootstrapArtifactProfileId: "",
  };
}

const LABEL_RE = /^[a-z0-9][a-z0-9-]{1,118}[a-z0-9]$/;
// A bootstrap-artifact PROFILE id is an opaque logical label — never a path/URL/checksum.
const PROFILE_ID_RE = /^[a-z0-9][a-z0-9-]{1,118}[a-z0-9]$/;

export interface DraftValidation {
  ok: boolean;
  errors: string[];
}

export function validateDraft(draft: StagingLabDraft): DraftValidation {
  const errors: string[] = [];
  if (!draft.executionTargetId) errors.push("Select an approved substrate target.");
  if (draft.displayName.trim().length === 0) errors.push("A display name is required.");
  if (!LABEL_RE.test(draft.ownershipLabel.trim())) {
    errors.push("Ownership label must be a lowercase kebab-case identity (e.g. secp-lab-alpha).");
  }
  if (!PROFILE_ID_RE.test(draft.bootstrapArtifactProfileId.trim())) {
    errors.push(
      "Bootstrap artifact profile must be an approved logical id (no path, URL, or checksum).",
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

export function canSimulate(lab: StagingLab | null): boolean {
  return lab?.status === "approved" || lab?.status === "simulated_ready";
}

export function canTeardown(lab: StagingLab | null): boolean {
  return (
    lab?.status === "simulated_ready" ||
    lab?.status === "approved" ||
    lab?.status === "failed"
  );
}

/** Extract the logical resource kinds from a compiled plan for display (safe strings only). */
export function planResourceKinds(lab: StagingLab | null): string[] {
  const resources = (lab?.desired_state?.resources as { kind?: string }[] | undefined) ?? [];
  return resources.map((r) => String(r.kind ?? "")).filter((k) => k.length > 0);
}

/** Simulated observed resources (fake) for display. */
export function observedResources(
  lab: StagingLab | null,
): { kind: string; owner: string; phase: string }[] {
  const resources =
    (lab?.simulated_observed_state?.resources as
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

export function teardownStatusLabel(status: StagingLabStatus): string {
  if (status === "tearing_down") return "Teardown in progress (simulated)";
  if (status === "destroyed") return "Torn down (simulated)";
  return "Not torn down";
}
