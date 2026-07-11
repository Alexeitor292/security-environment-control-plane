import { ApiClientError } from "../api/client";
import type {
  DeploymentPlan,
  Exercise,
  Instance,
  LifecycleState,
  TeamTopology,
} from "../api/types";

// Pure view-model for the ENVIRONMENTS surfaces: template library, definition
// editor, exercise lifecycle/plan review, and the read-only topology preview.
//
// Truth boundary rules enforced here:
// - A template is a definition, not a running environment; a valid definition
//   is not an approved plan; an approved plan is not deployed infrastructure.
// - Queueing/dispatching work is distinct from a worker running it; simulated
//   ready is never production ready; destroy requested is not destroyed.
// - The topology preview is a declarative plan view — never observed traffic.
// - Definition content renders only through explicit allowlists with bounded
//   lengths; backend free-form error messages never render (closed codes).

// ------------------------------------------------------------------ copy

export const LIBRARY_INTRO =
  "Catalog of declarative environment definitions. A template is a definition only — it is not a running environment and is not deployable to a real target from here.";

export const TEMPLATE_IS_DEFINITION_NOTE =
  "Definitions are immutable per version. Validation success means the definition parses against the schema — it is not approval and not deployment.";

export const EDITOR_INTRO =
  "Declarative environment definition. Edit the YAML; the structured view and validation update from the same content that will be persisted.";

export const EDITOR_REVISION_NOTE =
  "Creating a version records an immutable revision of exactly this content. A saved revision still requires exercise validation, plan generation, and an explicit approval before any simulated deployment.";

export const VALIDATION_IS_NOT_APPROVAL_NOTE =
  "A valid definition is not an approved plan, and an approved plan is not deployed infrastructure.";

export const PLAN_PINNED_NOTE =
  "Deterministic plan pinned to the immutable version content hash. Any definition change produces a new version, a new plan, and a new decision.";

export const APPROVAL_RECORDS_ONLY_NOTE =
  "Approval records a decision pinned to this exact plan hash. It does not deploy anything — deployment is a separate action that dispatches simulated work.";

export const DEPLOY_DISPATCH_NOTE =
  "Deploy dispatches simulated deployment work for each team. Dispatching is not running; running is simulated execution only — never production infrastructure.";

export const DESTROY_DISPATCH_NOTE =
  "Destroy dispatches teardown work. Requested is not destroyed — the lifecycle reflects the recorded state only.";

export const TOPOLOGY_DECLARATIVE_NOTE =
  "Declarative plan view: the planned per-team shape from the approved plan. It is not observed infrastructure and shows no live traffic.";

export const SIMULATED_POSTURE_NOTE =
  "Simulated execution only — no real infrastructure is contacted.";

// ------------------------------------------------------------ closed codes

export const ENVIRONMENTS_ERROR_TEXT: Record<string, string> = {
  domain_error: "That action is not allowed in the current state.",
  not_found: "The requested record was not found.",
  validation_failed: "The request was rejected by the server's validation.",
  forbidden: "You do not have permission for that action.",
  conflict: "The request conflicts with the current recorded state.",
  plan_stale: "The plan no longer matches the current version. Generate a new plan.",
  approval_required: "A recorded approval is required before this action.",
};

/** For optional-record fetches: only a not_found legitimately means "no
 *  record"; every other failure must surface as unavailable, never as a
 *  claim of absence. */
export function onlyNotFoundAsNull(e: unknown): null {
  if (e instanceof ApiClientError && (e.status === 404 || e.code === "not_found")) {
    return null;
  }
  throw e;
}

// -------------------------------------------------- definition summary

export interface DefinitionNetwork {
  name: string;
  cidrStrategy: string;
  baseCidr: string;
  isolated: boolean | null;
}

export interface DefinitionRole {
  name: string;
  kind: string;
  image: string;
  network: string;
}

export interface DefinitionSummary {
  name: string;
  displayName: string;
  apiVersion: string;
  kind: string;
  teamCount: number | null;
  isolationPolicy: string;
  networks: DefinitionNetwork[];
  roles: DefinitionRole[];
  vulnerabilityPacks: string[];
  telemetryProviders: string[];
  validationProvider: string;
  objectiveCount: number | null;
  requiredPlugins: string[];
  /** Count of top-level spec keys that the allowlist did not surface. */
  unrecognizedSpecKeys: number;
}

const MAX_STR = 120;
const MAX_LIST = 32;

function str(v: unknown): string {
  return typeof v === "string" ? v.slice(0, MAX_STR) : "";
}

function strList(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((x): x is string => typeof x === "string")
    .slice(0, MAX_LIST)
    .map((x) => x.slice(0, MAX_STR));
}

const KNOWN_SPEC_KEYS = new Set([
  "teams",
  "networks",
  "roles",
  "vulnerabilityPacks",
  "telemetry",
  "validation",
  "requiredPlugins",
]);

/**
 * Allowlisted, bounded extraction from a parsed definition. Never renders
 * arbitrary nested content: unknown keys are counted, unknown value shapes
 * are dropped, strings are length-capped, lists are size-capped.
 */
export function definitionSummary(parsed: unknown): DefinitionSummary | null {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  const root = parsed as Record<string, unknown>;
  const metadata = (root.metadata ?? {}) as Record<string, unknown>;
  const spec =
    root.spec !== null && typeof root.spec === "object" && !Array.isArray(root.spec)
      ? (root.spec as Record<string, unknown>)
      : {};

  const teams = (spec.teams ?? {}) as Record<string, unknown>;
  const telemetry = (spec.telemetry ?? {}) as Record<string, unknown>;
  const validation = (spec.validation ?? {}) as Record<string, unknown>;

  const networks: DefinitionNetwork[] = Array.isArray(spec.networks)
    ? spec.networks
        .filter((n): n is Record<string, unknown> => n !== null && typeof n === "object")
        .slice(0, MAX_LIST)
        .map((n) => ({
          name: str(n.name),
          cidrStrategy: str(n.cidrStrategy),
          baseCidr: str(n.baseCidr),
          isolated: typeof n.isolated === "boolean" ? n.isolated : null,
        }))
    : [];

  const roles: DefinitionRole[] = Array.isArray(spec.roles)
    ? spec.roles
        .filter((r): r is Record<string, unknown> => r !== null && typeof r === "object")
        .slice(0, MAX_LIST)
        .map((r) => ({
          name: str(r.name),
          kind: str(r.kind),
          image: str(r.image),
          network: str(r.network),
        }))
    : [];

  const packs = Array.isArray(spec.vulnerabilityPacks)
    ? spec.vulnerabilityPacks
        .filter((p): p is Record<string, unknown> => p !== null && typeof p === "object")
        .slice(0, MAX_LIST)
        .map((p) => `${str(p.ref)}@${str(p.version)}`)
    : [];

  const objectives = Array.isArray(validation.objectives)
    ? validation.objectives.length
    : null;

  return {
    name: str(metadata.name),
    displayName: str(metadata.displayName) || str(metadata.name),
    apiVersion: str(root.apiVersion),
    kind: str(root.kind),
    teamCount: typeof teams.count === "number" ? teams.count : null,
    isolationPolicy: str(teams.isolationPolicy),
    networks,
    roles,
    vulnerabilityPacks: packs,
    telemetryProviders: strList(telemetry.providers),
    validationProvider: str(validation.provider),
    objectiveCount: objectives,
    requiredPlugins: strList(spec.requiredPlugins),
    unrecognizedSpecKeys: Object.keys(spec).filter((k) => !KNOWN_SPEC_KEYS.has(k))
      .length,
  };
}

// --------------------------------------------------------- validation view

export type ValidationState = "not-run" | "valid" | "valid-with-warnings" | "invalid" | "stale";

export interface ValidationView {
  state: ValidationState;
  label: string;
  /** Bounded validator findings — product content of the validation endpoint,
   *  never transport/backend internals. */
  errors: string[];
  warnings: string[];
  droppedFindings: number;
}

const MAX_FINDINGS = 20;
const MAX_FINDING_LEN = 300;

function boundFindings(list: string[]): { shown: string[]; dropped: number } {
  const strings = list.filter((f): f is string => typeof f === "string");
  return {
    shown: strings.slice(0, MAX_FINDINGS).map((f) => f.slice(0, MAX_FINDING_LEN)),
    dropped: Math.max(0, strings.length - MAX_FINDINGS),
  };
}

/**
 * Structured view of a definition-validation result. Not-run is never a
 * failure; warnings are never success; `stale` marks a result whose source
 * text has changed since validation ran.
 */
export function validationView(
  result: { ok: boolean; errors: string[]; warnings: string[] } | null,
  stale = false,
): ValidationView {
  if (result === null) {
    return {
      state: "not-run",
      label: "Validation not run",
      errors: [],
      warnings: [],
      droppedFindings: 0,
    };
  }
  const errs = boundFindings(result.errors ?? []);
  const warns = boundFindings(result.warnings ?? []);
  if (stale) {
    return {
      state: "stale",
      label: "Definition changed since validation — re-run",
      errors: errs.shown,
      warnings: warns.shown,
      droppedFindings: errs.dropped + warns.dropped,
    };
  }
  if (!result.ok) {
    return {
      state: "invalid",
      label: "Invalid definition",
      errors: errs.shown,
      warnings: warns.shown,
      droppedFindings: errs.dropped + warns.dropped,
    };
  }
  if (warns.shown.length > 0) {
    return {
      state: "valid-with-warnings",
      label: "Valid — with warnings",
      errors: [],
      warnings: warns.shown,
      droppedFindings: errs.dropped + warns.dropped,
    };
  }
  return {
    state: "valid",
    label: "Valid (schema only — not approval)",
    errors: [],
    warnings: [],
    droppedFindings: 0,
  };
}

// ------------------------------------------------------ exercise lifecycle

/** Truthful lifecycle labels. Simulated execution is labeled as such; a
 *  dispatched action is labeled as dispatched, never as done. */
export const EXERCISE_STATUS_LABEL: Record<LifecycleState, string> = {
  draft: "Draft",
  validated: "Validated (not planned)",
  planned: "Plan generated (not approved)",
  awaiting_approval: "Awaiting approval",
  approved: "Approved (not deployed)",
  deploying: "Deploying (dispatched work)",
  running: "Running (simulated)",
  resetting: "Resetting (dispatched work)",
  destroying: "Destroying (dispatched work)",
  destroyed: "Destroyed",
  failed: "Failed",
};

export function exerciseStatusLabel(state: string): string {
  return (EXERCISE_STATUS_LABEL as Record<string, string>)[state] ?? state;
}

export interface RailItem {
  /** StepRail-compatible shape (presentational when no onSelect is given). */
  id: string;
  label: string;
  state: "complete" | "current" | "blocked";
}

const EXERCISE_RAIL: { key: LifecycleState; title: string }[] = [
  { key: "draft", title: "Draft" },
  { key: "validated", title: "Validated" },
  { key: "planned", title: "Plan generated" },
  { key: "awaiting_approval", title: "Awaiting approval" },
  { key: "approved", title: "Approved (decision recorded)" },
  { key: "deploying", title: "Deploying (worker-dispatched)" },
  { key: "running", title: "Running (simulated)" },
];

const OFF_RAIL: ReadonlySet<string> = new Set([
  "failed",
  "resetting",
  "destroying",
  "destroyed",
]);

export function isExerciseOffRail(state: string): boolean {
  return OFF_RAIL.has(state);
}

/** Rail items for the on-rail lifecycle. Off-rail states (failed, destroy
 *  family) block every step — a skipped or aborted stage never reads as
 *  complete. */
export function exerciseRailItems(state: string): RailItem[] {
  const idx = EXERCISE_RAIL.findIndex((s) => s.key === state);
  return EXERCISE_RAIL.map((s, i) => ({
    id: s.key,
    label: s.title,
    state:
      idx === -1
        ? "blocked"
        : i < idx
          ? "complete"
          : i === idx
            ? "current"
            : "blocked",
  }));
}

// Predicates — EXACTLY the pre-redesign gating conditions, moved out of JSX.
export function canValidateExercise(state: string): boolean {
  return state === "draft";
}
export function canGeneratePlan(state: string): boolean {
  return state === "validated";
}
export function canDeployExercise(state: string): boolean {
  return state === "approved";
}
export function canDestroyExercise(state: string): boolean {
  return state === "running" || state === "failed";
}
export function canResetInstance(instance: Pick<Instance, "lifecycle_state">): boolean {
  return instance.lifecycle_state === "running";
}

// ------------------------------------------------------------- plan review

// Predicates — exactly the pre-redesign conditions.
export function canSubmitPlan(plan: Pick<DeploymentPlan, "status">): boolean {
  return plan.status === "generated";
}
export function canDecidePlan(plan: Pick<DeploymentPlan, "status">): boolean {
  return plan.status === "awaiting_approval";
}

export const PLAN_STATUS_LABEL: Record<string, string> = {
  generated: "Generated (not submitted)",
  awaiting_approval: "Awaiting approval",
  approved: "Approved (decision recorded — not deployed)",
  rejected: "Rejected",
  applied: "Applied (simulated)",
};

export function planStatusLabel(status: string): string {
  return PLAN_STATUS_LABEL[status] ?? status;
}

// --------------------------------------------------------------- inventory

export interface ExerciseRow {
  id: string;
  name: string;
  lifecycle: string;
  label: string;
  teamCount: number;
  versionRef: string;
  createdAt: string;
}

export function exerciseRows(exercises: Exercise[]): ExerciseRow[] {
  return [...exercises]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .map((e) => ({
      id: e.id,
      name: e.name,
      lifecycle: e.lifecycle_state,
      label: exerciseStatusLabel(e.lifecycle_state),
      teamCount: e.team_count,
      versionRef: e.environment_version_id,
      createdAt: e.created_at,
    }));
}

/** Naive-UTC recorded timestamps format by string slicing (see audit-view). */
export function recordedDate(createdAt: string): string {
  return createdAt.slice(0, 10);
}

// ----------------------------------------------------------- topology view

export interface TopologyNodeVM {
  id: string;
  kind: string;
  label: string;
  role: string | null;
  ip: string | null;
  cidr: string | null;
  x: number;
  y: number;
}

export interface TopologyEdgeVM {
  id: string;
  source: string;
  target: string;
  kind: string;
}

const KNOWN_NODE_KINDS = new Set(["attacker", "target", "sensor", "network"]);

/** Icon name (PR-10 registry) per topology node kind. Unknown kinds get the
 *  neutral topology glyph — never a misleading specific type. */
export function nodeIconName(
  kind: string,
): "vm" | "target" | "evidence" | "network-segment" | "topology" {
  switch (kind) {
    case "attacker":
      return "vm";
    case "target":
      return "target";
    case "sensor":
      return "evidence";
    case "network":
      return "network-segment";
    default:
      return "topology";
  }
}

export function nodeKindClass(kind: string): string {
  return KNOWN_NODE_KINDS.has(kind) ? kind : "unknown";
}

/**
 * Deterministic declarative layout (hosts top lane, networks bottom lane) as
 * pure data. Edges carry their declared relationship kind and are NEVER
 * animated — this is a plan preview, not observed traffic.
 */
export function topologyGraph(topo: TeamTopology): {
  nodes: TopologyNodeVM[];
  edges: TopologyEdgeVM[];
} {
  const networks = topo.nodes.filter((n) => n.data.kind === "network");
  const hosts = topo.nodes.filter((n) => n.data.kind !== "network");

  const nodes: TopologyNodeVM[] = [
    ...hosts.map((n, i) => ({
      id: n.id,
      kind: n.data.kind,
      label: n.data.label,
      role: n.data.role ?? null,
      ip: n.data.ip ?? null,
      cidr: n.data.cidr ?? null,
      x: 40 + i * 230,
      y: 40,
    })),
    ...networks.map((n, i) => ({
      id: n.id,
      kind: n.data.kind,
      label: n.data.label,
      role: n.data.role ?? null,
      ip: n.data.ip ?? null,
      cidr: n.data.cidr ?? null,
      x: 160 + i * 330,
      y: 260,
    })),
  ];

  const edges: TopologyEdgeVM[] = topo.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    kind: e.data.kind,
  }));

  return { nodes, edges };
}

/** Accessible textual summary of one team's planned topology. */
export function topologySummaryText(topo: TeamTopology): string {
  const networks = topo.nodes.filter((n) => n.data.kind === "network");
  const hosts = topo.nodes.filter((n) => n.data.kind !== "network");
  const hostText = hosts
    .map((h) => `${h.data.label} (${h.data.kind}${h.data.ip ? `, ${h.data.ip}` : ""})`)
    .join("; ");
  const netText = networks
    .map((n) => `${n.data.label}${n.data.cidr ? ` (${n.data.cidr})` : ""}`)
    .join("; ");
  return (
    `${topo.team_ref}: planned topology with ${hosts.length} host${hosts.length === 1 ? "" : "s"}` +
    ` and ${networks.length} network${networks.length === 1 ? "" : "s"}, ${topo.edges.length} declared link${topo.edges.length === 1 ? "" : "s"}.` +
    (hostText ? ` Hosts: ${hostText}.` : "") +
    (netText ? ` Networks: ${netText}.` : "")
  );
}

export const TOPOLOGY_EDGE_LEGEND: Record<string, string> = {
  attached: "attached to network (declared)",
  monitors: "monitoring relationship (declared)",
};

export function edgeLegendLabel(kind: string): string {
  return TOPOLOGY_EDGE_LEGEND[kind] ?? `${kind} (declared)`;
}
