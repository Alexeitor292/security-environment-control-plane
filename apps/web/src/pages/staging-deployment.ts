// Pure, framework-free logic for the Real App-Owned Isolated Staging Lab Deployment (SECP-B4).
//
// Kept separate from the React component so it is unit-testable and free of DOM concerns.
// Provider-neutral; contains NO real infrastructure values (no endpoint, host, IP, bridge/VNet
// name, VMID, storage id, certificate, credential, token, secret ref, SSH material, command, or
// artifact URL/checksum). The server owns all labels and re-validates every input; only a worker
// performs a real host action, and only after an exact plan is approved and re-verified.

import type {
  BootstrapAvailability,
  DeploymentResourceProfile,
  StagingDeployment,
  StagingDeploymentPlan,
  StagingDeploymentStatus,
} from "../api/types";

/** Mandatory notice: the API never contacts infrastructure; the worker holds sealed execution. */
export const CONTROL_PLANE_ONLY_LABEL =
  "Control plane only — the app durably orchestrates plan/approval and enqueues work; it contacts no infrastructure.";

/** Shown after deploy is enqueued. */
export const DEPLOY_ENQUEUED_NOTICE =
  "Apply enqueued — the worker claims it, re-verifies every binding, and refuses at the sealed execution boundary until the real integration seams are supplied on the isolated worker.";

/** Fixed safety constraints shown on the review screen (mirrors the server contract). */
export const SAFETY_CONSTRAINTS: string[] = [
  "Durable app-owned orchestration: the app owns the immutable plan, exact-plan approval, and the durable worker job — it never executes them.",
  "Execution is a sealed, fail-closed worker contract. Real host action requires merged code, a mounted worker-local bootstrap bundle, and integration-validated provider/host/OpenBao seams (not yet enabled).",
  "When enabled, the app (not the operator) creates every resource: SECP-owned bridge, default-deny firewall, control-plane VM, nested target VM, artifact stage, scoped credential, and service identity.",
  "Every mutation is gated by a fresh observed-ownership proof of the exact provider object; foreign/uncertain resources are never touched.",
  "Approval binds ONE exact plan hash plus every drift anchor; later drift fails closed before any mutation.",
  "The one-time SSH bootstrap authority is worker-local and deployment-mounted — never entered here.",
];

export interface Option<T> {
  value: T;
  label: string;
  help: string;
}

/** Bounded, safe resource profiles — never raw host CPU/RAM/disk values. */
export const RESOURCE_PROFILES: Option<DeploymentResourceProfile>[] = [
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

/** Ordered lifecycle steps for the progress UI. */
export const LIFECYCLE_STEPS: { status: StagingDeploymentStatus; label: string }[] = [
  { status: "draft", label: "Draft" },
  { status: "planned", label: "Plan generated" },
  { status: "awaiting_approval", label: "Awaiting approval" },
  { status: "approved", label: "Approved" },
  { status: "bootstrap_pending", label: "Bootstrap pending" },
  { status: "applying", label: "Applying" },
  { status: "verifying", label: "Verifying" },
  { status: "ready", label: "Ready" },
];

/** Terminal/failure/rollback statuses shown distinctly. */
export const FAILURE_STATUSES: StagingDeploymentStatus[] = [
  "failed",
  "rollback_required",
  "rolling_back",
  "rolled_back",
];

export function lifecycleIndex(status: StagingDeploymentStatus): number {
  return LIFECYCLE_STEPS.findIndex((s) => s.status === status);
}

export function isFailureState(status: StagingDeploymentStatus): boolean {
  return FAILURE_STATUSES.includes(status);
}

/** True while a worker still owes progress — the UI must not present the lab as ready. */
export function isInFlight(status: StagingDeploymentStatus): boolean {
  return (
    status === "bootstrap_pending" ||
    status === "applying" ||
    status === "verifying" ||
    status === "rolling_back" ||
    status === "tearing_down"
  );
}

export function planHashPrefix(hash: string | null | undefined): string {
  if (!hash) return "pending";
  return hash.replace(/^sha256:/, "").slice(0, 12);
}

export interface DeploymentDraft {
  executionTargetId: string;
  logicalName: string;
  resourceProfile: DeploymentResourceProfile;
}

export function emptyDraft(): DeploymentDraft {
  return { executionTargetId: "", logicalName: "", resourceProfile: "small_lab" };
}

// The optional logical name is the ONLY free-text field; it must be a strict kebab-case slug.
// (The server re-validates authoritatively and rejects anything else.)
const LOGICAL_NAME_RE = /^[a-z0-9]([a-z0-9-]{1,38}[a-z0-9])$/;

export interface DraftValidation {
  ok: boolean;
  errors: string[];
}

export function validateDraft(draft: DeploymentDraft): DraftValidation {
  const errors: string[] = [];
  if (!draft.executionTargetId) errors.push("Select an eligible substrate.");
  if (draft.logicalName.trim().length > 0 && !LOGICAL_NAME_RE.test(draft.logicalName.trim())) {
    errors.push(
      "Optional name must be a short lowercase kebab-case slug (a-z, 0-9, '-'), or left blank.",
    );
  }
  return { ok: errors.length === 0, errors };
}

export function canCreate(busy: boolean, draft: DeploymentDraft): boolean {
  return !busy && validateDraft(draft).ok;
}

export function canPlan(dep: StagingDeployment | null): boolean {
  return dep?.status === "draft" || dep?.status === "planned";
}

export function canSubmit(dep: StagingDeployment | null): boolean {
  return dep?.status === "planned";
}

export function canApprove(dep: StagingDeployment | null): boolean {
  return dep?.status === "awaiting_approval";
}

export function canDeploy(dep: StagingDeployment | null): boolean {
  return dep?.status === "approved";
}

export function canTeardown(dep: StagingDeployment | null): boolean {
  return (
    dep?.status === "ready" || dep?.status === "failed" || dep?.status === "rolled_back"
  );
}

/** Extract the planned resource categories for display (safe strings only). */
export function planResourceKinds(plan: StagingDeploymentPlan | null): string[] {
  return (plan?.resources ?? []).map((r) => String(r.kind ?? "")).filter((k) => k.length > 0);
}

/** Human-safe rendering of the bootstrap-availability boolean (never a location/contents). */
export function bootstrapAvailabilityLabel(avail: BootstrapAvailability | null): string {
  if (!avail) return "Unknown";
  return avail.available
    ? "Worker-local bootstrap authority present"
    : "Worker-local bootstrap authority not mounted (worker-only; not settable here)";
}

export function statusLabel(status: StagingDeploymentStatus): string {
  const found = LIFECYCLE_STEPS.find((s) => s.status === status);
  if (found) return found.label;
  const map: Record<string, string> = {
    failed: "Failed",
    rollback_required: "Rollback required",
    rolling_back: "Rolling back (worker running)",
    rolled_back: "Rolled back",
    teardown_requested: "Teardown requested",
    tearing_down: "Tearing down (worker running)",
    destroyed: "Destroyed",
  };
  return map[status] ?? status;
}
