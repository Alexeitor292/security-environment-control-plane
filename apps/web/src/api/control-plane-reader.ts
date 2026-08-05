// The transport half of the spatial frontend's data layer: real reads, typed by the CONTRACT.
//
// WHAT THIS IS NOT. It is not an implementation of the spatial `ControlPlaneAdapter`. That
// interface returns product models — `InfraTarget`, `EventItem`, `Team` — and most of their fields
// have no source on the wire (`Team.color`, `Team.subnet`, `Deployment.drift`,
// `Deployment.costToDate`, `InfraTarget.capacity`). An adapter satisfying it literally would have
// to invent them, and an adapter that invents is worse than none: the page cannot tell the
// invention from the reading. `adapter-endpoint-map.ts` names every unsourced field, method by
// method, so the presentation layer can render "not available from the control plane" instead.
//
// So the split is: this module reads, and returns exactly what the API published; the presentation
// layer decides how to show it, and what to say where there is nothing to show.
//
// WHY THE RETURN TYPES COME FROM `./generated/openapi`. They are generated from
// `contracts/openapi/openapi.json`, which is exported from the live FastAPI app and held in step
// by CI. Typing the reads against them makes this module a drift detector as well as a client:
// `apps/web/src/api/types.ts` is a hand-written transcription of the same surface, and where the
// two disagree, `tsc` says so here rather than a component saying so at runtime.
//
// SIGNATURES DIFFER FROM THE ADAPTER'S, DELIBERATELY. `listTeams(rangeId)` takes a REQUIRED range
// id because the route is range-scoped; the adapter declares `listTeams(eventId?)` with the
// argument optional, and no route serves that. Papering over it with a default or a silent empty
// array would turn a contract gap into an empty screen with no explanation. The mismatch is
// recorded in the map and surfaced here as a type error at the call site, which is where somebody
// can do something about it.

import { api } from "./client";
import { workerRows, type WorkerRow } from "../domain/proxmox/placement-view";
import type {
  AuditEventOut,
  CompetitionOut,
  PluginOut,
  RangeEventOut,
  RangeOperationOut,
  RangeOut,
  RangeResourceOut,
  RangeTemplateOut,
  ScoreboardOut,
  TargetOut,
  TeamOut,
  TeardownEvidenceOut,
} from "./generated/openapi";

/**
 * Where a reader's rows came from.
 *
 * Mirrors `AdapterProvenance` in the spatial tree deliberately — same two values, same spelling —
 * so the presentation layer's `ProvenanceBoundary` can consume a reader directly.
 */
export type ReaderProvenance = "live" | "fixture";

/**
 * A reader cannot exist without declaring where its data came from.
 *
 * Required, not optional. An optional field would be omitted by exactly the implementation that
 * most needs it — a fixture reader written in a hurry, which then renders as though it had
 * contacted a server.
 */
export interface ProvenanceDeclaring {
  readonly provenance: ReaderProvenance;
}

/**
 * One deployment, read from the two routes that describe it between them.
 *
 * `RangeOut` alone has no resource list; `/ranges/{id}/resources` has no lifecycle state. Both are
 * returned rather than merged, because `RangeResourceOut.removed_at` distinguishes a resource that
 * WAS in this deployment from one that still is — a distinction any flattening drops, after which
 * a torn-down resource is indistinguishable from a live one.
 */
export interface DeploymentReading {
  readonly range: RangeOut;
  readonly resources: readonly RangeResourceOut[];
}

/**
 * The reads the control plane actually serves today, in contract terms.
 *
 * Every method here has a registered route. The seven adapter methods with no route
 * (`listEvents`, `listAccessProfiles`, `listApprovals`, `listAlerts`, `listReports`, `listUsers`,
 * `listSecretRefs`) are ABSENT from this interface rather than present and returning `[]`. An
 * empty array is a claim — "the control plane looked and found none" — and it is the wrong claim
 * when nothing was asked. A method that cannot be served should fail to compile at the call site.
 */
export interface ControlPlaneReader extends ProvenanceDeclaring {
  /** `GET /api/v1/targets`. `secret_ref` is an opaque reference: presence, never material. */
  listTargets(): Promise<readonly TargetOut[]>;

  /** `GET /api/v1/audit`. */
  listAuditEvents(): Promise<readonly AuditEventOut[]>;

  /**
   * The JOIN of `/target-discovery/read-only-bootstrap/worker-nodes` and `/enrollment`.
   *
   * Two records describe one worker: the node carries published key material, the enrollment
   * carries lifecycle state and release fingerprint. A row is emitted for a worker present in only
   * ONE of them — enrolled but never published keys, and published keys with no enrollment, are
   * both real states and neither may be silently dropped.
   */
  listWorkers(): Promise<readonly WorkerRow[]>;

  /** `GET /api/v1/range-templates`. The catalogue, not a versioned scenario — there is no history. */
  listScenarios(): Promise<readonly RangeTemplateOut[]>;
  getScenario(slug: string): Promise<RangeTemplateOut>;

  /** `GET /api/v1/ranges`. `state` is NINE members; see `RANGE_STATES_ARE_NOT_BINARY`. */
  listDeployments(): Promise<readonly RangeOut[]>;
  getDeployment(rangeId: string): Promise<DeploymentReading>;

  /** Range-scoped, and the id is required — the adapter's optional `eventId` has no route. */
  listTeams(rangeId: string): Promise<readonly TeamOut[]>;

  /** `GET /api/v1/plugins`. `simulated: true` is not "implemented"; do not map it to one. */
  listIntegrations(): Promise<readonly PluginOut[]>;

  /** `GET /api/v1/ranges/{id}/operations`. Carries `stale`, which is neither running nor failed. */
  listWorkflowRuns(rangeId: string): Promise<readonly RangeOperationOut[]>;

  /** `GET /api/v1/ranges/{id}/teardown-evidence`. Carries `unproven_count`; see the note there. */
  listEvidence(rangeId: string): Promise<readonly TeardownEvidenceOut[]>;

  /** `GET /api/v1/ranges/{id}/scoreboard`. One total per team — no score components exist. */
  listScores(rangeId: string): Promise<ScoreboardOut>;

  /** `GET /api/v1/ranges/{id}/competition`. The nearest thing to a domain "event". */
  getEvent(rangeId: string): Promise<CompetitionOut>;

  /**
   * `GET /api/v1/ranges/{id}/events` — the append-only LOG, and named for what it is.
   *
   * Deliberately NOT called `listEvents`. A `RangeEventOut` is a log line (kind, level, message,
   * sequence); the domain `EventItem` is a scheduled competition. The route name makes the wrong
   * wiring look right, so the method name here refuses to help.
   */
  listRangeLog(rangeId: string, afterSequence?: number): Promise<readonly RangeEventOut[]>;
}

/**
 * The nine range states, and why a boolean is not enough.
 *
 * `recovery_required` means the range could not be OBSERVED. It is not running and it is not
 * failed, and mapping it to either claims knowledge nobody has. Exported so a presentation layer
 * can be checked exhaustive against it rather than falling through to a default.
 */
export const RANGE_STATES_ARE_NOT_BINARY = [
  "draft",
  "deploying",
  "ready",
  "active",
  "resetting",
  "recovery_required",
  "failed",
  "destroying",
  "destroyed",
] as const;

export type RangeStateName = (typeof RANGE_STATES_ARE_NOT_BINARY)[number];

/**
 * The live reader: every method is a real request to the control plane.
 *
 * `api` supplies the transport — base-URL resolution, the bearer token, and the closed error
 * mapping. Nothing is transformed on the way out; the generated types are the response shapes, so
 * "preserving the distinctions" is achieved by not touching them rather than by remembering to.
 */
export const liveReader: ControlPlaneReader = {
  provenance: "live",

  listTargets: () => api.listTargets(),
  listAuditEvents: () => api.audit(),

  async listWorkers() {
    // Both sides, always. Requesting one and falling back to the other would drop exactly the
    // workers the join exists to surface.
    const [enrollments, nodes] = await Promise.all([api.listEnrollments(), api.listWorkerNodes()]);
    return workerRows(enrollments.items, nodes);
  },

  listScenarios: () => api.listRangeTemplates(),
  getScenario: (slug: string) => api.getRangeTemplate(slug),

  listDeployments: () => api.listRanges(),
  async getDeployment(rangeId: string) {
    const [range, resources] = await Promise.all([
      api.getRange(rangeId),
      api.listRangeResources(rangeId),
    ]);
    return { range, resources };
  },

  listTeams: (rangeId: string) => api.listTeams(rangeId),
  listIntegrations: () => api.plugins(),
  listWorkflowRuns: (rangeId: string) => api.listRangeOperations(rangeId),
  listEvidence: (rangeId: string) => api.listTeardownEvidence(rangeId),
  listScores: (rangeId: string) => api.getScoreboard(rangeId),
  getEvent: (rangeId: string) => api.getCompetition(rangeId),
  listRangeLog: (rangeId: string, afterSequence?: number) =>
    api.listRangeEvents(rangeId, afterSequence),
};

/**
 * Build a reader over supplied rows, for tests and for offline development.
 *
 * `provenance` is fixed to `"fixture"` and is not a parameter, so there is no call that produces
 * fixture data wearing a live label. That is the whole reason this exists as a factory rather than
 * as an object literal a caller assembles.
 */
export function fixtureReader(rows: {
  targets?: readonly TargetOut[];
  auditEvents?: readonly AuditEventOut[];
  workers?: readonly WorkerRow[];
  scenarios?: readonly RangeTemplateOut[];
  deployments?: readonly RangeOut[];
  resources?: readonly RangeResourceOut[];
  teams?: readonly TeamOut[];
  integrations?: readonly PluginOut[];
  workflowRuns?: readonly RangeOperationOut[];
  evidence?: readonly TeardownEvidenceOut[];
  scoreboard?: ScoreboardOut;
  competition?: CompetitionOut;
  rangeLog?: readonly RangeEventOut[];
}): ControlPlaneReader {
  const missing = (what: string) => (): never => {
    // Not an empty array. A fixture that was never supplied has not been "found to be empty", and
    // a screen rendering "none" over an unsupplied fixture is stating a fact nobody established.
    throw new Error(`fixtureReader was not given ${what}`);
  };
  return {
    provenance: "fixture",
    listTargets: async () => rows.targets ?? missing("targets")(),
    listAuditEvents: async () => rows.auditEvents ?? missing("auditEvents")(),
    listWorkers: async () => rows.workers ?? missing("workers")(),
    listScenarios: async () => rows.scenarios ?? missing("scenarios")(),
    getScenario: async (slug) => {
      const found = (rows.scenarios ?? missing("scenarios")()).find((s) => s.slug === slug);
      if (!found) throw new Error(`no fixture scenario with slug ${slug}`);
      return found;
    },
    listDeployments: async () => rows.deployments ?? missing("deployments")(),
    getDeployment: async (rangeId) => {
      const range = (rows.deployments ?? missing("deployments")()).find((r) => r.id === rangeId);
      if (!range) throw new Error(`no fixture deployment with id ${rangeId}`);
      return { range, resources: rows.resources ?? [] };
    },
    listTeams: async () => rows.teams ?? missing("teams")(),
    listIntegrations: async () => rows.integrations ?? missing("integrations")(),
    listWorkflowRuns: async () => rows.workflowRuns ?? missing("workflowRuns")(),
    listEvidence: async () => rows.evidence ?? missing("evidence")(),
    listScores: async () => rows.scoreboard ?? missing("scoreboard")(),
    getEvent: async () => rows.competition ?? missing("competition")(),
    listRangeLog: async () => rows.rangeLog ?? missing("rangeLog")(),
  };
}

/** True when a reader's rows are fixture data. Mirrors `isFixture` in the spatial tree. */
export function isFixtureReader(reader: ProvenanceDeclaring): boolean {
  return reader.provenance === "fixture";
}
