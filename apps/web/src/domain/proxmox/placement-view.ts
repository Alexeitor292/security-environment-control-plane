// Pure view-model for Proxmox placement: target, worker, enrollment, discovery freshness.
//
// Everything here projects LIVE server records. There is no fixture in this module, which is why
// it is separate from `proxmox-view.ts`: the placement surface is the one Proxmox surface that is
// wired end to end today, and keeping its projection apart makes that boundary legible.

import type {
  DiscoveryEnrollment,
  EnrollmentStatus,
  ExecutionTarget,
  InventorySnapshot,
  WorkerDiscoveryNode,
} from "../../api/types";

export const PROXMOX_PLUGIN_NAME = "proxmox";

/** Targets are matched on the plugin the server recorded, never on the display name. */
export function proxmoxTargets(targets: readonly ExecutionTarget[]): ExecutionTarget[] {
  return targets.filter((t) => t.plugin_name === PROXMOX_PLUGIN_NAME);
}

export interface TargetRow {
  id: string;
  displayName: string;
  status: string;
  configHash: string;
  /** True when the server holds a credential reference. The reference itself is opaque. */
  hasCredentialRef: boolean;
  createdAt: string;
}

export function targetRows(targets: readonly ExecutionTarget[]): TargetRow[] {
  return proxmoxTargets(targets).map((t) => ({
    id: t.id,
    displayName: t.display_name,
    status: t.status,
    configHash: t.config_hash,
    hasCredentialRef: t.secret_ref !== null && t.secret_ref !== "",
    createdAt: t.created_at,
  }));
}

/**
 * Discovery freshness.
 *
 * Age is computed against a caller-supplied `now` rather than read from the clock inside the
 * function, so the value is testable and so a component cannot accidentally re-render a moving
 * number as though the server had re-stated it.
 *
 * `completedAt === null` is NOT stale — it is "never completed", a different fact, and the two are
 * reported separately because a discovery that has not finished is not evidence of anything.
 */
export type DiscoveryFreshness = "fresh" | "aging" | "stale" | "never_completed" | "failed";

export const FRESHNESS_TONE: Record<DiscoveryFreshness, "ok" | "warn" | "danger" | "pending"> = {
  fresh: "ok",
  aging: "warn",
  stale: "danger",
  never_completed: "pending",
  failed: "danger",
};

export const FRESHNESS_LABEL: Record<DiscoveryFreshness, string> = {
  fresh: "fresh",
  aging: "aging",
  stale: "stale",
  never_completed: "never completed",
  failed: "failed",
};

/** Thresholds are UI-side presentation only. The apply gate holds the authoritative one. */
export const DISCOVERY_AGING_SECONDS = 60 * 60;
export const DISCOVERY_STALE_SECONDS = 24 * 60 * 60;

export const DISCOVERY_FRESHNESS_NOTE =
  "Freshness here is a display threshold, not the gate. The apply gate applies its own rule and refuses with proxmox.apply.discovery_stale independently of what this column says.";

export interface DiscoveryRow {
  snapshotId: string;
  status: string;
  requestedAt: string;
  completedAt: string | null;
  ageSeconds: number | null;
  freshness: DiscoveryFreshness;
  error: string | null;
  pluginVersion: string;
}

export function discoveryRow(snapshot: InventorySnapshot, nowIso: string): DiscoveryRow {
  const completedAt = snapshot.completed_at;
  const failed = snapshot.error !== null && snapshot.error !== "";
  let ageSeconds: number | null = null;
  let freshness: DiscoveryFreshness;

  if (failed) {
    freshness = "failed";
  } else if (completedAt === null || completedAt === "") {
    freshness = "never_completed";
  } else {
    const completed = Date.parse(completedAt);
    const now = Date.parse(nowIso);
    if (Number.isNaN(completed) || Number.isNaN(now)) {
      // An unparseable timestamp is not a fresh one. Refuse to guess.
      freshness = "never_completed";
    } else {
      ageSeconds = Math.max(0, Math.round((now - completed) / 1000));
      freshness =
        ageSeconds >= DISCOVERY_STALE_SECONDS
          ? "stale"
          : ageSeconds >= DISCOVERY_AGING_SECONDS
            ? "aging"
            : "fresh";
    }
  }

  return {
    snapshotId: snapshot.id,
    status: snapshot.status,
    requestedAt: snapshot.requested_at,
    completedAt: completedAt === "" ? null : completedAt,
    ageSeconds,
    freshness,
    error: snapshot.error,
    pluginVersion: snapshot.plugin_version,
  };
}

/** Newest completed snapshot first; a target with none returns null rather than an empty shape. */
export function latestDiscovery(
  snapshots: readonly InventorySnapshot[],
  nowIso: string,
): DiscoveryRow | null {
  if (snapshots.length === 0) return null;
  const sorted = [...snapshots].sort((a, b) => b.requested_at.localeCompare(a.requested_at));
  return discoveryRow(sorted[0], nowIso);
}

export function formatAge(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

/** Eligibility as the discovery enrollment records it. Approval is a decision, not an observation. */
export interface EligibilityRow {
  enrollmentId: string;
  targetId: string;
  displayName: string;
  status: string;
  decisionCode: string;
  activePlanHash: string;
  approvedPlanHash: string;
  approvedAt: string | null;
  failureCode: string | null;
  /** True when the approved plan hash no longer matches the active one — a re-review is due. */
  planHashDiverged: boolean;
}

export function eligibilityRows(enrollments: readonly DiscoveryEnrollment[]): EligibilityRow[] {
  return enrollments.map((e) => ({
    enrollmentId: e.id,
    targetId: e.execution_target_id,
    displayName: e.display_name,
    status: e.status,
    decisionCode: e.decision_code,
    activePlanHash: e.active_plan_hash,
    approvedPlanHash: e.approved_plan_hash,
    approvedAt: e.approved_at,
    failureCode: e.failure_code,
    planHashDiverged:
      e.approved_plan_hash !== "" &&
      e.active_plan_hash !== "" &&
      e.approved_plan_hash !== e.active_plan_hash,
  }));
}

/**
 * Worker rows, joined from the two live sources that describe one worker between them.
 *
 * The enrollment record carries the lifecycle state and the release fingerprint; the discovery
 * node record carries the published key material. They are joined on the worker installation id
 * where both exist, and a row is emitted for a worker present in only one of them — an enrolled
 * worker that never published keys, or published keys with no enrollment, are both real states and
 * neither may be silently dropped.
 */
export interface WorkerRow {
  key: string;
  workerInstallationId: string | null;
  nodeLabel: string | null;
  /** Enrollment lifecycle state, e.g. `healthy`, `recovery_required`. Empty when not enrolled. */
  enrollmentState: string | null;
  enrollmentId: string | null;
  releaseFingerprint: string | null;
  workerKeyFingerprint: string | null;
  sshKeyFingerprint: string | null;
  siteLabel: string | null;
  identityRegistrationId: string | null;
  refusalReason: string | null;
  updatedAt: string | null;
}

export function workerRows(
  enrollments: readonly EnrollmentStatus[],
  nodes: readonly WorkerDiscoveryNode[],
): WorkerRow[] {
  const rows: WorkerRow[] = enrollments.map((e) => ({
    key: `enr:${e.enrollment_id}`,
    workerInstallationId: e.worker_installation_id === "" ? null : e.worker_installation_id,
    nodeLabel: null,
    enrollmentState: e.state,
    enrollmentId: e.enrollment_id,
    releaseFingerprint: e.release_fingerprint === "" ? null : e.release_fingerprint,
    workerKeyFingerprint: e.worker_key_fingerprint === "" ? null : e.worker_key_fingerprint,
    sshKeyFingerprint: null,
    // Tolerated as absent: a controller built before the projection change omits the key entirely.
    siteLabel:
      typeof e.deployment_site_label === "string" && e.deployment_site_label !== ""
        ? e.deployment_site_label
        : null,
    identityRegistrationId: null,
    refusalReason: e.refusal_reason === "" ? null : e.refusal_reason,
    updatedAt: e.updated_at === "" ? null : e.updated_at,
  }));

  for (const n of nodes) {
    const match = rows.find(
      (r) =>
        r.workerKeyFingerprint !== null &&
        (r.workerKeyFingerprint === n.ssh_public_key_fingerprint ||
          r.workerKeyFingerprint === n.admission_anchor_fingerprint),
    );
    if (match) {
      match.nodeLabel = n.node_label;
      match.sshKeyFingerprint = n.ssh_public_key_fingerprint;
      match.identityRegistrationId = n.worker_identity_registration_id;
      continue;
    }
    rows.push({
      key: `node:${n.id}`,
      workerInstallationId: null,
      nodeLabel: n.node_label,
      // Not enrolled, as far as the enrollment list shows. Rendered as its own state, never as a
      // failure and never as healthy.
      enrollmentState: null,
      enrollmentId: null,
      releaseFingerprint: null,
      workerKeyFingerprint: null,
      sshKeyFingerprint: n.ssh_public_key_fingerprint,
      siteLabel: null,
      identityRegistrationId: n.worker_identity_registration_id,
      refusalReason: null,
      updatedAt: n.updated_at,
    });
  }
  return rows;
}

/** Only a `healthy` enrollment describes a worker that can currently take work. */
export function healthyWorkers(rows: readonly WorkerRow[]): WorkerRow[] {
  return rows.filter((r) => r.enrollmentState === "healthy");
}

export const PLACEMENT_INTRO =
  "Where this range would run: the registered Proxmox target, the enrolled worker that would execute against it, and how recently the control plane observed either.";

export const NO_BINDING_NOTE =
  "The range create contract (`RangeCreate`: template_slug, name) carries no target or worker field, so nothing on this page pins a range to a target. Placement is decided server-side. This page reports what the control plane knows about the available targets and workers; it does not choose between them.";

export const WORKER_IDENTITY_NOTE =
  "A worker's identity is its installation id and key fingerprints. The apply gate binds a plan to exactly one of these and refuses with proxmox.apply.worker_identity_mismatch if a different worker claims it.";
