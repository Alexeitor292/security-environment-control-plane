// Pure, framework-free logic for Worker-Owned Read-Only Target Discovery (SECP-B5).
//
// Kept separate from the React component so it is unit-testable and free of DOM concerns.
// Provider-neutral; contains NO SSH host/account/port/key path/known_hosts/fingerprint, Proxmox
// endpoint/token, raw command output, node/storage/VMID entry field, free-form command, or credential.
// The server owns all labels; the worker runs read-only probes; live deployment apply remains sealed.

import type {
  DiscoveryCandidatePlan,
  DiscoveryEnrollment,
  DiscoveryEvidence,
  DiscoveryResourceProfile,
  TargetDiscoveryStatus,
} from "../api/types";

/** Mandatory notice on the discovery surface. */
export const READ_ONLY_LABEL =
  "Read-only discovery — the app enqueues a durable read-only probe job and contacts no host; the worker runs the probes.";

/** The fixed sealed-apply notice shown after discovery completes. */
export const SEALED_APPLY_MESSAGE =
  "Read-only discovery complete. Live deployment remains sealed until controlled integration enablement.";

/** Fixed safety constraints (mirror the server contract). */
export const SAFETY_CONSTRAINTS: string[] = [
  "Discovery is strictly read-only: a closed set of Proxmox read probes (version, cluster status, node, storage, capacity, nested-virtualization, candidate presence). No write is representable.",
  "It cannot create, modify, delete, reload, restart, install, upload, or download anything on the host.",
  "Only typed, bounded, secret-free evidence is persisted — never SSH host/account/key material, endpoints, tokens, or raw output.",
  "The candidate plan binds the exact discovered node/storage/VMIDs + generated ownership names; approval binds the whole plan hash and invalidates on any drift or expiry.",
  "The worker-local read-only SSH authority is worker-mounted — never entered here.",
  "Live deployment apply of the plan remains sealed pending controlled integration enablement.",
];

export interface Option<T> {
  value: T;
  label: string;
  help: string;
}

export const RESOURCE_PROFILES: Option<DiscoveryResourceProfile>[] = [
  {
    value: "small_lab",
    label: "Small lab",
    help: "Minimal bounded footprint. Discovery verifies the host can host it.",
  },
  {
    value: "medium_lab",
    label: "Medium lab",
    help: "Modest bounded footprint. Discovery verifies the host can host it.",
  },
];

export interface DiscoveryDraft {
  executionTargetId: string;
  logicalName: string;
  resourceProfile: DiscoveryResourceProfile;
}

export function emptyDraft(): DiscoveryDraft {
  return { executionTargetId: "", logicalName: "", resourceProfile: "small_lab" };
}

const LOGICAL_NAME_RE = /^[a-z0-9]([a-z0-9-]{1,38}[a-z0-9])$/;

export interface DraftValidation {
  ok: boolean;
  errors: string[];
}

export function validateDraft(draft: DiscoveryDraft): DraftValidation {
  const errors: string[] = [];
  if (!draft.executionTargetId) errors.push("Select an eligible substrate.");
  if (draft.logicalName.trim().length > 0 && !LOGICAL_NAME_RE.test(draft.logicalName.trim())) {
    errors.push(
      "Optional name must be a short lowercase kebab-case slug (a-z, 0-9, '-'), or left blank.",
    );
  }
  return { ok: errors.length === 0, errors };
}

export function canRequest(busy: boolean, draft: DiscoveryDraft): boolean {
  return !busy && validateDraft(draft).ok;
}

export function canApprove(e: DiscoveryEnrollment | null): boolean {
  return e?.status === "plan_ready";
}

export function canRerun(e: DiscoveryEnrollment | null): boolean {
  return (
    e?.status === "plan_ready" || e?.status === "failed" || e?.status === "approved"
  );
}

export function isInFlight(status: TargetDiscoveryStatus): boolean {
  return status === "requested" || status === "discovering";
}

export function statusLabel(status: TargetDiscoveryStatus): string {
  const map: Record<TargetDiscoveryStatus, string> = {
    requested: "Requested (queued for worker)",
    discovering: "Discovering (read-only probes running)",
    discovered: "Discovered",
    plan_ready: "Candidate plan ready for review",
    approved: "Approved (apply still sealed)",
    failed: "Failed / ineligible",
  };
  return map[status] ?? status;
}

export function planHashPrefix(hash: string | null | undefined): string {
  if (!hash) return "pending";
  return hash.replace(/^sha256:/, "").slice(0, 12);
}

export function planResourceKinds(plan: DiscoveryCandidatePlan | null): string[] {
  return (plan?.resources ?? []).map((r) => String(r.kind ?? "")).filter((k) => k.length > 0);
}

/** A short, safe summary of the capability/eligibility outcome (never raw output). */
export function evidenceSummary(ev: DiscoveryEvidence | null): string[] {
  if (!ev) return [];
  const lines: string[] = [`Eligibility: ${ev.eligibility}`];
  if (ev.reason_code) lines.push(`Reason: ${ev.reason_code}`);
  if (ev.node) lines.push(`Node: ${ev.node}`);
  if (ev.version_major !== null)
    lines.push(`Proxmox: ${ev.version_major}.${ev.version_minor ?? 0}`);
  if (ev.nested_available !== null)
    lines.push(`Nested virtualization: ${ev.nested_available ? "available" : "unavailable"}`);
  if (ev.cpu_total !== null) lines.push(`CPU: ${ev.cpu_total}`);
  if (ev.mem_free_mb !== null) lines.push(`Free memory: ${ev.mem_free_mb} MB`);
  if (ev.selected_storage) lines.push(`Selected storage: ${ev.selected_storage}`);
  if (ev.candidate_vmids.length) lines.push(`Candidate VMIDs: ${ev.candidate_vmids.join(", ")}`);
  return lines;
}
