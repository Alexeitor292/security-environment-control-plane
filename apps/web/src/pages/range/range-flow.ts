// The range vertical slice, as an executable definition.
//
// This is the flow the product exists to deliver — choose a blueprint, create a range, deploy it,
// reach the targets, reset it, destroy it — written ONCE so it can be executed against two
// substrates without the two drifting apart:
//
//   1. `range-flow.test.ts`      — runs in the Frontend gate on every PR, against a fetch-level
//                                  fake implementing the range API. ALWAYS runs. Proves the client
//                                  drives a conforming server correctly: right calls, right order,
//                                  right reads, right handling of an operation that has no plan
//                                  yet. It proves NOTHING about a real container.
//   2. `range-flow.live-test.ts` — runs on demand against a REAL control plane, which for ranges
//                                  means a running worker with a Docker socket. This is the only
//                                  half that touches infrastructure.
//
// Both execute the REAL `api` client. The only difference is what is on the other end of `fetch`.
//
// The driver POLLS rather than awaits: every lifecycle mutation returns 202 and the work happens on
// the worker, so "the call returned" is never "the work finished". Waiting for the recorded state
// is the only correct way to observe completion, and it is what the pages do too.

import { api as realApi } from "../../api/client";
import type { Range, RangeState } from "../../api/range-types";
import { rangeLifecycle, type RangePhase } from "./range-lifecycle";
import { accessRows, blastRadius, operationProgress } from "./range-view";

/** The exact client surface the flow needs. The real `api` object satisfies it structurally. */
export type RangeFlowApi = Pick<
  typeof realApi,
  | "listRangeTemplates"
  | "createRange"
  | "getRange"
  | "deployRange"
  | "resetRange"
  | "destroyRange"
  | "listRangeResources"
  | "listRangeEvents"
  | "listTeardownEvidence"
>;

/** One recorded observation, captured after a step settles. */
export interface FlowObservation {
  step: string;
  /** The state the SERVER recorded — the ground truth for every assertion. */
  recorded: RangeState | string;
  phase: RangePhase;
  /** Step-specific facts worth asserting on. */
  detail: Record<string, unknown>;
}

export interface FlowResult {
  rangeId: string;
  observations: FlowObservation[];
  /** Every event kind the server recorded, in sequence order. */
  eventKinds: string[];
  /** The teardown verdict, or null when the range was never destroyed. */
  teardownVerdict: string | null;
}

export interface FlowOptions {
  rangeName: string;
  /** Blueprint slug. Defaults to the first in the catalog. */
  templateSlug?: string;
  onStep?: (observation: FlowObservation) => void;
  /** How long to wait for one operation to settle. */
  operationTimeoutMs?: number;
  pollIntervalMs?: number;
  /** Injected so the in-gate run does not actually sleep. */
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_TIMEOUT_MS = 180_000;
const DEFAULT_POLL_MS = 500;

/** States from which nothing further happens without an operator. */
function settled(state: string): boolean {
  return (
    state === "draft" ||
    state === "ready" ||
    state === "active" ||
    state === "failed" ||
    state === "destroyed" ||
    state === "recovery_required"
  );
}

/**
 * Drive the whole slice and report what the server recorded at each step.
 *
 * The driver ASSERTS NOTHING — it reports, and the callers assert over the transcript. The moment a
 * flow driver contains its own expectations, the fake and the live server need different drivers
 * and the single definition this file exists to provide is gone.
 */
export async function runRangeFlow(
  api: RangeFlowApi,
  opts: FlowOptions,
): Promise<FlowResult> {
  const observations: FlowObservation[] = [];
  const timeoutMs = opts.operationTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = opts.pollIntervalMs ?? DEFAULT_POLL_MS;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

  const templates = await api.listRangeTemplates();
  if (templates.length === 0) throw new Error("flow: the range catalog is empty");
  const template =
    opts.templateSlug === undefined
      ? templates[0]
      : templates.find((t) => t.slug === opts.templateSlug);
  if (template === undefined) {
    throw new Error(`flow: no blueprint with slug ${String(opts.templateSlug)}`);
  }

  const created = await api.createRange({
    template_slug: template.slug,
    name: opts.rangeName,
  });
  const rangeId = created.id;

  const observe = (step: string, range: Range, detail: Record<string, unknown> = {}) => {
    const observation: FlowObservation = {
      step,
      recorded: range.state,
      phase: rangeLifecycle(range.state).phase,
      detail,
    };
    observations.push(observation);
    opts.onStep?.(observation);
    return observation;
  };

  /**
   * Poll `GET /ranges/{id}` until the range settles.
   *
   * Deliberately waits on the RANGE STATE, not on the operation: an operation can finish while the
   * range is still transitioning, and the range's state is what every surface renders. Times out
   * loudly rather than looping forever — a hung worker must look like a hung worker.
   */
  const waitForSettled = async (what: string): Promise<Range> => {
    const deadline = Date.now() + timeoutMs;
    let last = await api.getRange(rangeId);
    while (!settled(last.state)) {
      if (Date.now() > deadline) {
        throw new Error(
          `flow: ${what} did not settle within ${timeoutMs}ms (last state: ${last.state}). ` +
            `For a live run this usually means the worker is not running or cannot reach its provider.`,
        );
      }
      await sleep(pollMs);
      last = await api.getRange(rangeId);
    }
    return last;
  };

  observe("created", created, { rangeId, templateSlug: template.slug });

  // Deploy: 202 + background work. Capture the pre-plan window, which is the one an obvious
  // implementation gets wrong by dividing by `total_steps`.
  const deployOp = await api.deployRange(rangeId);
  const justDispatched = await api.getRange(rangeId);
  const dispatchProgress = operationProgress(justDispatched.current_operation);
  observe("deploy-dispatched", justDispatched, {
    operationId: deployOp.id,
    operationStatus: deployOp.status,
    // `true` here is the contract's pre-plan window: the worker has not planned the steps yet.
    progressKind: dispatchProgress.kind,
    totalSteps: dispatchProgress.totalSteps,
  });

  const deployed = await waitForSettled("deploy");
  const access = accessRows(deployed);
  observe("deployed", deployed, {
    accessCount: access.length,
    reachableCount: access.filter((a) => a.reachable).length,
    observedCount: access.filter((a) => a.observedAt !== null).length,
  });

  const resources = await api.listRangeResources(rangeId);
  const radius = blastRadius(resources);
  observe("inspected", deployed, {
    resourceCount: radius.resourceCount,
    containerCount: radius.containerCount,
    networkCount: radius.networkCount,
    blastRadiusComplete: radius.complete,
  });

  await api.resetRange(rangeId);
  const afterReset = await waitForSettled("reset");
  observe("reset", afterReset);

  await api.destroyRange(rangeId);
  const afterDestroy = await waitForSettled("destroy");
  observe("destroyed", afterDestroy, { residueVerdict: afterDestroy.residue_verdict });

  const events = await api.listRangeEvents(rangeId);
  const evidence = await api.listTeardownEvidence(rangeId).catch(() => []);

  return {
    rangeId,
    observations,
    eventKinds: [...events].sort((a, b) => a.sequence - b.sequence).map((e) => e.kind),
    teardownVerdict: evidence.length === 0 ? null : evidence[0].verdict,
  };
}

/** The steps `runRangeFlow` emits, in order. */
export const FLOW_STEPS: readonly string[] = [
  "created",
  "deploy-dispatched",
  "deployed",
  "inspected",
  "reset",
  "destroyed",
];

/**
 * Range event `kind` values for a complete happy-path run, in order.
 *
 * CAPTURED FROM A REAL CONTROL PLANE on 2026-08-05, not invented. An earlier version of this list
 * held `deploy_started` / `reset_started` / `destroy_started`, which were names the TEST FAKE made
 * up; the live run failed against the real server and that is how the drift was found. The fake now
 * emits these same values, so the in-gate suite is checked against observed reality rather than
 * against its own invention.
 *
 * `range_ready` legitimately appears twice — once after deploy, once after reset — and
 * `firstMissingInOrder` matches repeats separately, so the duplication is meaningful rather than a
 * transcription slip.
 */
export const EXPECTED_EVENT_KIND_ORDER: readonly string[] = [
  "range_created",
  "deploy_requested",
  "range_ready",
  "reset_requested",
  "range_ready",
  "destroy_requested",
  "range_destroyed",
];

/**
 * Check that `expected` appears within `actual` in order (extra entries between are fine).
 * Returns the first expected entry that could not be found, or null when all matched.
 */
export function firstMissingInOrder(
  actual: readonly string[],
  expected: readonly string[],
): string | null {
  let cursor = 0;
  for (const want of expected) {
    const at = actual.indexOf(want, cursor);
    if (at === -1) return want;
    cursor = at + 1;
  }
  return null;
}
