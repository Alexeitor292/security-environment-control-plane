// Pure view-model for the RANGE surfaces: catalog, create, deployment progress, overview and
// access, event timeline, and the reset/destroy confirmation.
//
// No React, no fetching. Every function is a total function of server-supplied records.
//
// Truth rules enforced here:
// - A template is a DEFINITION. Choosing one deploys nothing.
// - `reachable` is only ever the server's observed value. Nothing here infers reachability from
//   "the container exists".
// - "Dispatched" is not "done". Lifecycle mutations return 202 and the work happens on the worker;
//   the recorded state is the only thing that says an operation finished.
// - NOT-YET-KNOWN IS NOT ZERO, and it is not empty. `total_steps: 0` before the worker plans the
//   operation means the plan does not exist yet — rendered as indeterminate, never as 0%.
// - `unproven` is a third outcome. A teardown that could not observe the provider proves nothing,
//   and is never reported as clean.
// - Scores are never computed here. See `scoreboard-view.ts`.

import type {
  Range,
  RangeAccessTarget,
  RangeOperation,
  RangeOperationSummary,
  RangeResource,
  RangeTemplate,
  TeardownEvidence,
} from "../../api/range-types";
import { rangeLifecycle, type RangeLifecycle } from "./range-lifecycle";

// ------------------------------------------------------------------------------------- copy

export const CATALOG_INTRO =
  "Vulnerable range blueprints available to your organization. A blueprint is a definition — choosing one does not deploy anything.";

/**
 * What the range surface actually does. Unlike the exercise surface (whose shipped provider is the
 * simulator and contacts nothing), a range deploys real local infrastructure through its provider.
 * That is worth stating plainly in the opposite direction too: this really does start containers.
 */
export const EXECUTION_POSTURE_NOTE =
  "Deploying a range starts real infrastructure through its provider. Containers are created on the host running the worker, and the targets are intentionally vulnerable software.";

export const VULNERABLE_SOFTWARE_NOTE =
  "These ranges run intentionally vulnerable software. Keep them on an isolated local host and never expose them to an untrusted network.";

export const ACCESS_IS_OBSERVED_NOTE =
  "Access details come from the server. A target is marked reachable only where an actual response was observed — never inferred from the container having been created.";

export const RESET_IS_DISPATCHED_NOTE =
  "Reset recreates the target containers and clears competition scores and submissions. Teams and challenges survive. Requested is not complete — the recorded state is authoritative.";

export const DESTROY_IS_IRREVERSIBLE_NOTE =
  "Destroy removes every resource this range owns and nothing else. It cannot be undone, and a destroyed range cannot be redeployed — create a new one from the blueprint.";

/**
 * The `recovery_required` explanation. This copy must not be softened: the phase does NOT mean the
 * range broke, and it does NOT mean the range is gone. It means nothing observed the outcome, so
 * neither claim can be made.
 */
export const RECOVERY_REQUIRED_NOTE =
  "This range could not be observed to completion. That is not the same as a failure and not the same as a clean teardown: nobody has proved what is left. Resources this range created may still exist. Check the provider directly before assuming anything is gone.";

export const UNPROVEN_NOTE =
  "Unproven means the provider could not be observed — the answer is unknown, not good and not bad. It is never rolled up into a success or a failure count.";

/** Closed-code copy for range surfaces. Raw backend messages never render. */
export const RANGE_ERROR_TEXT: Record<string, string> = {
  range_not_found: "The range was not found, or you cannot access it.",
  range_invalid_transition: "That action is not allowed in the range's current state.",
  range_provider_unavailable:
    "The range provider could not be reached. Nothing was changed — check that the worker and its provider are running.",
  // Hit whenever the control plane is running WITHOUT a worker, which is the common local setup.
  // The generic fallback ("backend details are not shown by design") is true but useless here, and
  // this is a refusal with an exact, actionable cause: range operations run only on the durable
  // worker path, so the API refuses to execute one itself.
  inline_execution_forbidden:
    "Range operations run on the durable worker, never inside the API. Nothing was changed. Start a worker with access to its provider (for local_docker, the Docker socket) and try again.",
  competition_not_open: "The competition is not running.",
  submission_rejected: "The server rejected that submission.",
  forbidden: "You do not have permission for that action.",
  not_found: "The requested record was not found.",
  validation_failed: "The server rejected the request's contents.",
  conflict: "The request conflicts with the range's current recorded state.",
};

// -------------------------------------------------------------------------------- catalog

export interface RangeBlueprint {
  slug: string;
  name: string;
  summary: string;
  description: string;
  provider: string;
  difficulty: string;
  estimatedDeploySeconds: number;
  warning: string;
  targetCount: number;
  componentNames: string[];
  challengeCount: number;
  totalPoints: number;
}

export function rangeBlueprints(templates: readonly RangeTemplate[]): RangeBlueprint[] {
  return [...templates]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((t) => ({
      slug: t.slug,
      name: t.name,
      summary: t.summary,
      description: t.description,
      provider: t.provider,
      difficulty: t.difficulty,
      estimatedDeploySeconds: t.estimated_deploy_seconds,
      warning: t.warning,
      // Only `target` components are things a competitor attacks; scoring/support are plumbing.
      targetCount: t.components.filter((c) => c.role === "target").length,
      componentNames: t.components.map((c) => c.name),
      challengeCount: t.challenge_count,
      totalPoints: t.total_points,
    }));
}

export function filterBlueprints(
  blueprints: readonly RangeBlueprint[],
  query: string,
): RangeBlueprint[] {
  const q = query.trim().toLowerCase();
  if (!q) return [...blueprints];
  return blueprints.filter((b) =>
    `${b.name} ${b.slug} ${b.summary} ${b.difficulty}`.toLowerCase().includes(q),
  );
}

/** Human duration for an estimate. Deliberately coarse — it is an estimate, not a promise. */
export function estimatedDuration(seconds: number): string {
  if (seconds <= 0) return "unknown";
  if (seconds < 90) return `about ${seconds}s`;
  return `about ${Math.round(seconds / 60)} min`;
}

// ------------------------------------------------------------------------- deployed ranges

export interface RangeSummary {
  id: string;
  name: string;
  templateSlug: string;
  templateName: string;
  provider: string;
  lifecycle: RangeLifecycle;
  stateReason: string | null;
  createdAt: string;
  hasCompetition: boolean;
  reachableCount: number;
  accessCount: number;
}

export function rangeSummaries(ranges: readonly Range[]): RangeSummary[] {
  return [...ranges]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .map(rangeSummary);
}

export function rangeSummary(range: Range): RangeSummary {
  return {
    id: range.id,
    name: range.name,
    templateSlug: range.template_slug,
    templateName: range.template_name,
    provider: range.provider,
    lifecycle: rangeLifecycle(range.state),
    stateReason: range.state_reason,
    createdAt: range.created_at,
    hasCompetition: range.competition_id !== null,
    reachableCount: range.access.filter((a) => a.reachable).length,
    accessCount: range.access.length,
  };
}

// --------------------------------------------------------------------- operation progress

export type ProgressKind = "none" | "indeterminate" | "determinate";

export interface OperationProgress {
  kind: ProgressKind;
  /** null when the amount of work is not yet known. Never a fabricated 0. */
  percent: number | null;
  completedSteps: number;
  /** null when the worker has not planned the operation yet. */
  totalSteps: number | null;
  label: string;
}

/**
 * Progress for the current operation, WITHOUT ever dividing by `total_steps`.
 *
 * The API no longer plans an operation's steps — asking a provider what it intends to do means
 * holding one, and the API is not permitted to. So between the 202 and the worker picking the
 * operation up, `total_steps` is 0. That is three distinct facts away from what it looks like:
 *
 *   total_steps: 0, in flight -> the plan DOES NOT EXIST YET    (indeterminate)
 *   total_steps: 0, settled   -> the operation planned nothing  (determinate)
 *   total_steps: N            -> a real plan                    (determinate)
 *
 * Only the first is the common case, and rendering it as "0%" would state that no work has been
 * done when the truth is that nobody knows yet how much work there is. `percent` comes from the
 * server, which clamps it in that window; this never computes it.
 */
export function operationProgress(
  operation: RangeOperationSummary | null,
): OperationProgress {
  if (operation === null) {
    return {
      kind: "none",
      percent: null,
      completedSteps: 0,
      totalSteps: null,
      label: "No operation has run against this range yet.",
    };
  }
  const settled =
    operation.status === "succeeded" ||
    operation.status === "failed" ||
    operation.status === "unproven";

  if (operation.total_steps === 0 && !settled) {
    return {
      kind: "indeterminate",
      percent: null,
      completedSteps: 0,
      totalSteps: null,
      label: "Waiting for the worker to pick this up and plan the steps.",
    };
  }
  return {
    kind: "determinate",
    percent: operation.percent,
    completedSteps: operation.completed_steps,
    totalSteps: operation.total_steps,
    label:
      operation.total_steps === 0
        ? "This operation planned no steps."
        : `${operation.completed_steps} of ${operation.total_steps} steps`,
  };
}

/** Whether the client should keep polling, decided from the operation rather than a caller flag. */
export function operationInFlight(operation: RangeOperationSummary | null): boolean {
  return operation !== null && (operation.status === "pending" || operation.status === "running");
}

export const OPERATION_KIND_LABEL: Record<string, string> = {
  deploy: "Deploy",
  reset: "Reset",
  destroy: "Destroy",
};

/** Copy for a finished operation. `unproven` is neither success nor failure. */
export function operationOutcomeText(operation: RangeOperation | null): string | null {
  if (operation === null) return null;
  switch (operation.status) {
    case "failed":
      return operation.failure_code === null
        ? "This operation failed."
        : `This operation failed (${operation.failure_code}).`;
    case "unproven":
      return "This operation could not be observed to completion. What happened on the provider is unknown — it did not necessarily fail, and it did not necessarily succeed.";
    default:
      return null;
  }
}

// -------------------------------------------------------------------------- access targets

export interface AccessRow {
  componentKey: string;
  name: string;
  url: string;
  host: string;
  port: number;
  protocol: string;
  reachable: boolean;
  observedAt: string | null;
}

/**
 * Access rows for a range, ordered by name so reloads are stable.
 *
 * `reachable` is passed through verbatim. `observedAt` is kept alongside it so the UI can tell
 * "we checked and it did not answer" apart from "we never checked" — see `reachabilityText`.
 */
export function accessRows(range: Pick<Range, "access">): AccessRow[] {
  return [...range.access]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((a: RangeAccessTarget) => ({
      componentKey: a.component_key,
      name: a.name,
      url: a.url,
      host: a.host,
      port: a.port,
      protocol: a.protocol,
      reachable: a.reachable,
      observedAt: a.observed_at,
    }));
}

/** Reachability wording that keeps "did not respond" and "never checked" apart. */
export function reachabilityText(row: Pick<AccessRow, "reachable" | "observedAt">): string {
  if (row.observedAt === null) return "not checked";
  return row.reachable ? "responded" : "did not respond";
}

// -------------------------------------------------------------------------------- resources

export interface ResourceRow {
  id: string;
  kind: string;
  name: string;
  componentKey: string | null;
  state: string;
  image: string | null;
  imageDigest: string | null;
  externalId: string | null;
  hostPort: number | null;
  removedAt: string | null;
}

export function resourceRows(resources: readonly RangeResource[]): ResourceRow[] {
  return [...resources]
    .sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name))
    .map((r) => ({
      id: r.id,
      kind: r.kind,
      name: r.name,
      componentKey: r.component_key,
      state: r.state,
      image: r.image,
      imageDigest: r.image_digest,
      externalId: r.external_id,
      hostPort: r.host_port,
      removedAt: r.removed_at,
    }));
}

/** Resources that still exist as far as the server knows — the destroy blast radius. */
export function liveResources(resources: readonly RangeResource[]): RangeResource[] {
  return resources.filter((r) => r.removed_at === null && r.state !== "removed");
}

// -------------------------------------------------------------- destroy confirmation

export interface BlastRadius {
  resourceCount: number;
  containerCount: number;
  networkCount: number;
  /** One line per resource: "container secp-range-0f2c-juice-shop (verified)". */
  lines: string[];
  /** Every host port that will stop answering. */
  ports: number[];
  /** False when the resource list could not be read, so the enumeration may be short. */
  complete: boolean;
  incompleteReason: string | null;
}

/**
 * What a destroy will tear down, enumerated from the server's own resource records.
 *
 * A confirmation that cannot state its own blast radius is a button with a warning label. So this
 * reports what was READ and reports gaps as gaps: a resource list that could not be loaded makes
 * `complete` false and the UI says the list may be short rather than presenting it as the whole
 * story. Under-stating a blast radius is the failure mode that matters.
 */
export function blastRadius(resources: readonly RangeResource[] | null): BlastRadius {
  if (resources === null) {
    return {
      resourceCount: 0,
      containerCount: 0,
      networkCount: 0,
      lines: [],
      ports: [],
      complete: false,
      incompleteReason:
        "The resource list could not be read, so this enumeration is incomplete. Treat it as a minimum, not an inventory.",
    };
  }
  const live = liveResources(resources);
  return {
    resourceCount: live.length,
    containerCount: live.filter((r) => r.kind === "container").length,
    networkCount: live.filter((r) => r.kind === "network").length,
    lines: live.map((r) => `${r.kind} ${r.name} (${r.state})`).sort((a, b) => a.localeCompare(b)),
    ports: live
      .map((r) => r.host_port)
      .filter((p): p is number => p !== null)
      .sort((a, b) => a - b),
    complete: true,
    incompleteReason: null,
  };
}

/**
 * Whether a typed confirmation matches the range name.
 *
 * Exact match after trimming — deliberately NOT case-insensitive and not fuzzy. The point of the
 * control is that the operator reads the specific name of the specific range they are destroying.
 */
export function destroyConfirmationMatches(typed: string, rangeName: string): boolean {
  return typed.trim() === rangeName.trim() && rangeName.trim() !== "";
}

// ------------------------------------------------------------------------ teardown evidence

export interface TeardownSummary {
  verdict: string;
  /** True only for a `clean` verdict from a REACHABLE probe. */
  provedClean: boolean;
  headline: string;
  detail: string;
  expected: number;
  removedConfirmed: number;
  stillPresent: number;
  unprovenCount: number;
  observedAt: string;
  resources: { name: string; kind: string; verdict: string; detail: string | null }[];
}

/**
 * Summarize one teardown-evidence record.
 *
 * `provedClean` requires BOTH a `clean` verdict AND a reachable probe. When the probe could not
 * run, the removal and the "is it gone?" check share a failure mode, so absence was never proved —
 * and the summary says exactly that rather than reporting zero residue as a clean result.
 */
export function teardownSummary(evidence: TeardownEvidence): TeardownSummary {
  const provedClean = evidence.verdict === "clean" && evidence.probe_reachable;
  const headline =
    evidence.verdict === "clean"
      ? provedClean
        ? "Teardown verified clean"
        : "Reported clean, but the probe could not run"
      : evidence.verdict === "residue"
        ? "Resources are still present"
        : "Teardown could not be verified";
  const detail =
    evidence.reason !== null
      ? evidence.reason
      : provedClean
        ? "Every resource this range owned was confirmed removed."
        : evidence.verdict === "residue"
          ? "The provider still reports resources belonging to this range."
          : "The provider could not be observed, so nothing was proved either way.";
  return {
    verdict: evidence.verdict,
    provedClean,
    headline,
    detail,
    expected: evidence.expected_count,
    removedConfirmed: evidence.removed_confirmed,
    stillPresent: evidence.still_present,
    unprovenCount: evidence.unproven_count,
    observedAt: evidence.observed_at,
    resources: evidence.resources.map((r) => ({
      name: r.name,
      kind: r.kind,
      verdict: r.verdict,
      detail: r.detail,
    })),
  };
}
