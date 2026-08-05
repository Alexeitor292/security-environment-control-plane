// Pure view-model for the RANGE surfaces: catalog, create, deployment progress, overview, access,
// timeline, and the reset/destroy confirmation.
//
// No React, no fetching. Every function here is a total function of server-supplied records, so the
// pages stay thin and the behaviour that matters is testable without a DOM.
//
// Truth rules enforced here, in the spirit of environments-view.ts:
// - A blueprint is a DEFINITION. It is not a deployed range and cannot be reached.
// - Deploying is APPROVAL-GATED. The gate is the server's; this module only reports which step the
//   operator is actually on so the UI never offers a button whose sole outcome is a refusal.
// - "Dispatched" is not "done". A reset or destroy that has been requested is reported as
//   requested until the recorded state says otherwise.
// - Access details render only from RECORDED plan/topology data. Nothing here probes a host, and
//   no reachability is asserted that the control plane did not record.
// - Scores are NEVER computed here. See `scoreboard-view.ts` for why that module refuses to.

import type {
  AuditEvent,
  DeploymentPlan,
  Exercise,
  Instance,
  TeamTopology,
  Template,
  Version,
} from "../../api/types";
import { rangeLifecycle, type RangeLifecycle } from "./range-lifecycle";

// ------------------------------------------------------------------------------------- copy

export const CATALOG_INTRO =
  "Vulnerable range blueprints available to your organization. A blueprint is an immutable definition — choosing one does not deploy anything.";

/**
 * The single honest statement about what deployment actually does in this build. The control-plane
 * API, the workflow records and the lifecycle transitions are all real; the provider that
 * materializes hosts is the simulation provider that ships with the control plane. Saying "deployed"
 * without this line would claim reachable infrastructure that does not exist.
 */
export const EXECUTION_POSTURE_NOTE =
  "Execution runs through the control plane's configured provider. The shipped default provider is simulated — lifecycle, workflows and topology are real records, but no external infrastructure is contacted.";

export const DEPLOY_IS_GATED_NOTE =
  "Deployment is approval-gated: a range must be validated, planned, submitted and approved before it can be deployed. The server enforces every step.";

export const ACCESS_IS_DECLARED_NOTE =
  "Access details come from the recorded plan and topology. They are declared addresses — nothing here probes a host or proves reachability.";

export const RESET_IS_DISPATCHED_NOTE =
  "Reset dispatches work per team instance. Requested is not complete — the lifecycle reflects the recorded state only.";

export const DESTROY_IS_IRREVERSIBLE_NOTE =
  "Destroy tears down every team instance in this range. It cannot be undone, and a destroyed range cannot be redeployed — create a new one from the blueprint.";

/** Closed-code copy for range surfaces. Raw backend messages never render. */
export const RANGE_ERROR_TEXT: Record<string, string> = {
  domain_error: "That action is not allowed in the range's current state.",
  not_found: "The range was not found, or you cannot access it.",
  validation_failed: "The server rejected the request's contents.",
  forbidden: "You do not have permission for that action.",
  conflict: "The request conflicts with the range's current recorded state.",
  approval_required: "This range needs an approved plan before it can be deployed.",
  plan_stale: "The plan no longer matches the definition. Generate a new plan.",
  execution_refused: "The execution boundary refused this action.",
};

// -------------------------------------------------------------------------------- catalog

export interface RangeBlueprint {
  templateId: string;
  name: string;
  slug: string;
  description: string;
  versionCount: number;
  latestVersionId: string | null;
  latestVersionNumber: number | null;
  latestContentHash: string | null;
  /** A blueprint with no immutable version cannot be instantiated. */
  deployable: boolean;
  /** Present only when `deployable` is false — always says what is missing. */
  unavailableReason: string | null;
}

/**
 * Build catalog entries from templates and their versions.
 *
 * `versionsByTemplate` is keyed by template id; a template MISSING from the map is not the same as
 * a template with zero versions. A missing key means "versions were not loaded for this template",
 * and it reports `versionCount: 0` with a reason that says exactly that, rather than claiming the
 * blueprint has no versions. That distinction is the difference between "nothing to deploy" and
 * "we did not look".
 */
export function rangeBlueprints(
  templates: readonly Template[],
  versionsByTemplate: ReadonlyMap<string, readonly Version[]>,
): RangeBlueprint[] {
  return [...templates]
    .sort((a, b) => displayName(a).localeCompare(displayName(b)))
    .map((t) => {
      const loaded = versionsByTemplate.has(t.id);
      const versions = versionsByTemplate.get(t.id) ?? [];
      // Highest version_number wins. Never "the last element" — list order is the server's, and
      // depending on it would silently pick the wrong version if that order ever changed.
      const latest = versions.reduce<Version | null>(
        (best, v) => (best === null || v.version_number > best.version_number ? v : best),
        null,
      );
      return {
        templateId: t.id,
        name: displayName(t),
        slug: t.slug,
        description: t.description,
        versionCount: versions.length,
        latestVersionId: latest?.id ?? null,
        latestVersionNumber: latest?.version_number ?? null,
        latestContentHash: latest?.content_hash ?? null,
        deployable: latest !== null,
        unavailableReason:
          latest !== null
            ? null
            : loaded
              ? "No immutable version has been published for this blueprint yet."
              : "Versions for this blueprint could not be loaded.",
      };
    });
}

function displayName(t: Template): string {
  return t.display_name || t.name;
}

/** Case-insensitive substring filter over the fields an operator would search by. */
export function filterBlueprints(
  blueprints: readonly RangeBlueprint[],
  query: string,
): RangeBlueprint[] {
  const q = query.trim().toLowerCase();
  if (!q) return [...blueprints];
  return blueprints.filter((b) =>
    `${b.name} ${b.slug} ${b.description}`.toLowerCase().includes(q),
  );
}

// ------------------------------------------------------------------------ deployed ranges

export interface RangeSummary {
  id: string;
  name: string;
  lifecycle: RangeLifecycle;
  teamCount: number;
  environmentVersionId: string;
  templateId: string;
  createdAt: string;
}

export function rangeSummaries(exercises: readonly Exercise[]): RangeSummary[] {
  return [...exercises]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .map(rangeSummary);
}

export function rangeSummary(exercise: Exercise): RangeSummary {
  return {
    id: exercise.id,
    name: exercise.name,
    lifecycle: rangeLifecycle(exercise.lifecycle_state),
    teamCount: exercise.team_count,
    environmentVersionId: exercise.environment_version_id,
    templateId: exercise.template_id,
    createdAt: exercise.created_at,
  };
}

// ------------------------------------------------------------------------- the deploy gate

/**
 * The steps between a created range and a deployed one. These are the SERVER's gate, mirrored here
 * only so the UI can show the operator where they are and offer exactly one next action.
 */
export type GateStep =
  | "validate"
  | "generate-plan"
  | "submit-plan"
  | "approve-plan"
  | "deploy"
  | "none";

export interface DeployGate {
  /** The one action available now, or "none". */
  next: GateStep;
  label: string;
  help: string;
  /** Steps already satisfied, in order, for a progress rail. */
  completed: readonly GateStep[];
  /** Set when no action is available AND that is not because deployment finished. */
  blockedReason: string | null;
}

const GATE_ORDER: readonly GateStep[] = [
  "validate",
  "generate-plan",
  "submit-plan",
  "approve-plan",
  "deploy",
];

export const GATE_LABEL: Record<GateStep, string> = {
  validate: "Validate definition",
  "generate-plan": "Generate deployment plan",
  "submit-plan": "Submit plan for approval",
  "approve-plan": "Approve plan",
  deploy: "Deploy range",
  none: "No action available",
};

/**
 * Resolve the operator's next step from the RECORDED exercise state and the plan (if one exists).
 *
 * Driven by the recorded lifecycle state, not by the plan alone: a plan can be approved while the
 * exercise has already moved on, and in that case the next step is deploy, not approve. `plan` is
 * null when no plan has been generated — distinct from a plan that exists in `generated` status.
 */
export function deployGate(
  exercise: Pick<Exercise, "lifecycle_state">,
  plan: Pick<DeploymentPlan, "status"> | null,
): DeployGate {
  const state = exercise.lifecycle_state;
  const step = (next: GateStep, help: string): DeployGate => ({
    next,
    label: GATE_LABEL[next],
    help,
    completed: GATE_ORDER.slice(0, GATE_ORDER.indexOf(next)),
    blockedReason: null,
  });

  switch (state) {
    case "draft":
      return step("validate", "Check the definition parses against the schema.");
    case "validated":
      return step("generate-plan", "Produce a deterministic plan pinned to this version's content hash.");
    case "planned":
      // `planned` means a plan exists. Which step comes next depends on the PLAN's own status.
      if (plan === null) {
        return {
          next: "generate-plan",
          label: GATE_LABEL["generate-plan"],
          help: "The range is planned but the plan could not be read. Generate a new one.",
          completed: GATE_ORDER.slice(0, 1),
          blockedReason: null,
        };
      }
      if (plan.status === "generated") {
        return step("submit-plan", "Send the plan for an approval decision.");
      }
      if (plan.status === "awaiting_approval") {
        return step("approve-plan", "Record an approval decision pinned to this plan hash.");
      }
      if (plan.status === "rejected") {
        return {
          next: "generate-plan",
          label: GATE_LABEL["generate-plan"],
          help: "The plan was rejected. Generate a new plan to continue.",
          completed: GATE_ORDER.slice(0, 1),
          blockedReason: null,
        };
      }
      return step("deploy", "Dispatch deployment work for every team.");
    case "awaiting_approval":
      return step("approve-plan", "Record an approval decision pinned to this plan hash.");
    case "approved":
      return step("deploy", "Dispatch deployment work for every team.");
    default:
      return {
        next: "none",
        label: GATE_LABEL.none,
        help: "",
        completed: GATE_ORDER,
        blockedReason: gateBlockedReason(state),
      };
  }
}

function gateBlockedReason(state: string): string | null {
  switch (state) {
    case "deploying":
      return "Deployment is already in progress.";
    case "running":
      return null; // Deployment finished — not blocked, just done.
    case "resetting":
      return "A reset is in progress.";
    case "destroying":
      return "The range is being destroyed.";
    case "destroyed":
      return "This range has been destroyed. Create a new one from the blueprint.";
    case "failed":
      return "The last operation failed. Inspect the timeline before acting.";
    default:
      return `The range is in an unrecognized state (${state}).`;
  }
}

// -------------------------------------------------------------------------- access targets

export interface AccessTarget {
  instanceId: string;
  teamRef: string;
  teamIndex: number;
  nodeId: string;
  label: string;
  kind: string;
  role: string | null;
  /** Declared address from the plan. null when the plan declares none. */
  ip: string | null;
  network: string | null;
  isolated: boolean | null;
}

/**
 * Flatten per-team topologies into the list of things an operator would connect to.
 *
 * Network nodes are excluded — they are segments, not targets. Ordering is by team index then node
 * label so the list is stable across reloads regardless of server ordering.
 */
export function accessTargets(topologies: readonly TeamTopology[]): AccessTarget[] {
  const rows: AccessTarget[] = [];
  for (const topo of topologies) {
    for (const node of topo.nodes) {
      if (node.data.kind === "network") continue;
      rows.push({
        instanceId: topo.instance_id,
        teamRef: topo.team_ref,
        teamIndex: topo.team_index,
        nodeId: node.id,
        label: node.data.label,
        kind: node.data.kind,
        role: node.data.role ?? null,
        ip: node.data.ip ?? null,
        network: node.data.network ?? null,
        isolated: node.data.isolated ?? null,
      });
    }
  }
  return rows.sort(
    (a, b) => a.teamIndex - b.teamIndex || a.label.localeCompare(b.label),
  );
}

/** Per-team instance rows for the overview, joined with their recorded lifecycle. */
export interface TeamInstanceRow {
  instanceId: string;
  teamRef: string;
  teamIndex: number;
  instanceRef: string;
  provider: string;
  lifecycle: RangeLifecycle;
  targetCount: number;
}

export function teamInstanceRows(
  instances: readonly Instance[],
  topologies: readonly TeamTopology[],
): TeamInstanceRow[] {
  const targetsByInstance = new Map<string, number>();
  for (const t of accessTargets(topologies)) {
    targetsByInstance.set(t.instanceId, (targetsByInstance.get(t.instanceId) ?? 0) + 1);
  }
  return [...instances]
    .sort((a, b) => a.team_index - b.team_index)
    .map((i) => ({
      instanceId: i.id,
      teamRef: i.team_ref,
      teamIndex: i.team_index,
      instanceRef: i.instance_ref,
      provider: i.provider,
      lifecycle: rangeLifecycle(i.lifecycle_state),
      targetCount: targetsByInstance.get(i.id) ?? 0,
    }));
}

/** Whether an individual team instance can be reset. The server re-checks. */
export function canResetInstance(row: Pick<TeamInstanceRow, "lifecycle">): boolean {
  return row.lifecycle.known && row.lifecycle.phase === "ready";
}

// -------------------------------------------------------------------------------- timeline

export interface TimelineEntry {
  id: string;
  at: string;
  actor: string;
  action: string;
  outcome: string;
  resourceType: string;
  resourceId: string | null;
  /** True for anything that is not a plain success — surfaced prominently. */
  flagged: boolean;
}

/**
 * Range event timeline, newest first.
 *
 * The events are the server's audit ledger scoped to this range. Nothing is synthesized: if the
 * ledger has no entry for a transition, the timeline shows no entry for it, rather than inferring
 * one from the current lifecycle state.
 */
export function timelineEntries(events: readonly AuditEvent[]): TimelineEntry[] {
  return [...events]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .map((e) => ({
      id: e.id,
      at: e.created_at,
      actor: e.actor,
      action: e.action,
      outcome: e.outcome,
      resourceType: e.resource_type,
      resourceId: e.resource_id,
      flagged: e.outcome !== "success",
    }));
}

/** Counts for the timeline header strip. Derived only from loaded events. */
export function timelineTally(entries: readonly TimelineEntry[]): {
  total: number;
  flagged: number;
} {
  return {
    total: entries.length,
    flagged: entries.filter((e) => e.flagged).length,
  };
}

// -------------------------------------------------------------- destroy confirmation

/**
 * Whether a typed confirmation matches the range name.
 *
 * Exact match after trimming — deliberately NOT case-insensitive and not a fuzzy match. The point
 * of the control is that the operator reads the specific name of the specific range they are about
 * to destroy; anything looser defeats it.
 */
export function destroyConfirmationMatches(typed: string, rangeName: string): boolean {
  return typed.trim() === rangeName.trim() && rangeName.trim() !== "";
}
