// The range vertical slice, as an executable definition.
//
// This is the flow the product exists to deliver — choose a blueprint, create a range, walk the
// approval gate, deploy it, read the targets, reset a team, destroy it — written ONCE so that it
// can be executed against two different substrates without the two drifting apart:
//
//   1. `range-flow.test.ts`      — runs in the Frontend gate on every PR, against a fetch-level
//                                  fake that implements the control plane's recorded lifecycle.
//                                  ALWAYS runs. Proves the client drives a conforming server
//                                  correctly, in the right order, with the right state reads.
//   2. `range-flow.live-test.ts` — runs on demand against a REAL control plane. Proves the same
//                                  steps work against the actual server rather than a model of it.
//
// Both execute the REAL `api` client from src/api/client.ts. The only difference between them is
// what is on the other end of `fetch`, which is exactly the difference that should exist.
//
// WHAT EACH ONE IS WORTH, stated plainly because it is easy to overclaim: the in-gate run cannot
// discover that the server changed, because the fake IS this repo's belief about the server. Only
// the live run can do that. The in-gate run catches the client breaking — a call dropped, a step
// reordered, a state misprojected, a mutation that stops refreshing what it changed — which is the
// class of regression a UI PR actually introduces.

import { api as realApi } from "../../api/client";
import { rangeLifecycle, type RangePhase } from "./range-lifecycle";
import { blastRadius, deployGate, accessTargets, type GateStep } from "./range-view";

/** The exact client surface the flow needs. The real `api` object satisfies it structurally. */
export type RangeFlowApi = Pick<
  typeof realApi,
  | "listTemplates"
  | "listVersions"
  | "createExercise"
  | "getExercise"
  | "validateExercise"
  | "generatePlan"
  | "latestPlan"
  | "submitPlan"
  | "approvePlan"
  | "deployExercise"
  | "listInstances"
  | "exerciseTopology"
  | "resetInstance"
  | "destroyExercise"
  | "audit"
>;

/** One recorded observation, captured after a step completes. */
export interface FlowObservation {
  step: string;
  /** The state the SERVER recorded — the ground truth for every assertion. */
  recorded: string;
  /** The product phase this build projects that state onto. */
  phase: RangePhase;
  /** The next action the deploy gate offers from here. */
  gateNext: GateStep;
  /** Step-specific facts worth asserting on. */
  detail: Record<string, unknown>;
}

export interface FlowResult {
  rangeId: string;
  observations: FlowObservation[];
  /** Every audit action recorded against the range, oldest first. */
  auditActions: string[];
}

export interface FlowOptions {
  rangeName: string;
  /** Blueprint slug to use. Defaults to the first blueprint that has a version. */
  templateSlug?: string;
  /** Called after each step — lets the live runner print progress. */
  onStep?: (observation: FlowObservation) => void;
}

/**
 * Drive the whole slice and return what the server recorded at each step.
 *
 * The driver ASSERTS NOTHING. It reports, and the two callers assert over the transcript. That
 * split is deliberate: the moment a flow driver contains its own expectations, the fake and the
 * live server need different drivers, and the single definition this file exists to provide is
 * gone.
 *
 * Every step reads the range back from the server rather than assuming the mutation's return value
 * is the new truth — which is also exactly what the pages do.
 */
export async function runRangeFlow(
  api: RangeFlowApi,
  opts: FlowOptions,
): Promise<FlowResult> {
  const observations: FlowObservation[] = [];

  // Resolve the blueprint and its newest immutable version from the live catalog.
  const templates = await api.listTemplates();
  if (templates.length === 0) throw new Error("flow: no blueprints in the catalog");
  const template =
    opts.templateSlug === undefined
      ? templates[0]
      : templates.find((t) => t.slug === opts.templateSlug);
  if (template === undefined) {
    throw new Error(`flow: no blueprint with slug ${String(opts.templateSlug)}`);
  }
  const versions = await api.listVersions(template.id);
  if (versions.length === 0) throw new Error("flow: blueprint has no immutable version");
  const version = versions.reduce((best, v) =>
    v.version_number > best.version_number ? v : best,
  );

  const range = await api.createExercise({
    template_id: template.id,
    version_id: version.id,
    name: opts.rangeName,
  });
  const rangeId = range.id;

  // Read the range and the plan back from the server, then record one observation.
  const observe = async (step: string, detail: Record<string, unknown> = {}) => {
    const current = await api.getExercise(rangeId);
    const plan = await api.latestPlan(rangeId).catch(() => null);
    const lifecycle = rangeLifecycle(current.lifecycle_state);
    const observation: FlowObservation = {
      step,
      recorded: current.lifecycle_state,
      phase: lifecycle.phase,
      gateNext: deployGate(current, plan).next,
      detail,
    };
    observations.push(observation);
    opts.onStep?.(observation);
    return observation;
  };

  await observe("created", { rangeId, templateSlug: template.slug, teamCount: range.team_count });

  await api.validateExercise(rangeId);
  await observe("validated");

  const plan = await api.generatePlan(rangeId);
  await observe("plan-generated", { planId: plan.id });

  await api.submitPlan(plan.id);
  await observe("plan-submitted");

  await api.approvePlan(plan.id, "Approved by the range flow acceptance run.");
  await observe("plan-approved");

  await api.deployExercise(rangeId);
  await observe("deployed");

  // The payoff of deploying: per-team instances, and targets an operator could reach.
  const instances = await api.listInstances(rangeId);
  const topologies = await api.exerciseTopology(rangeId).catch(() => []);
  const targets = accessTargets(topologies);
  const radius = blastRadius(instances, topologies);
  await observe("inspected", {
    instanceCount: instances.length,
    targetCount: targets.length,
    addressCount: radius.addresses.length,
    blastRadiusComplete: radius.complete,
  });

  if (instances.length === 0) throw new Error("flow: deploy produced no team instances");
  await api.resetInstance(rangeId, instances[0].id);
  await observe("reset", { resetInstanceId: instances[0].id });

  await api.destroyExercise(rangeId);
  await observe("destroyed");

  const events = await api.audit(rangeId);
  return {
    rangeId,
    observations,
    auditActions: [...events]
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .map((e) => e.action),
  };
}

/** The steps `runRangeFlow` emits, in order. Callers assert against this rather than a literal. */
export const FLOW_STEPS: readonly string[] = [
  "created",
  "validated",
  "plan-generated",
  "plan-submitted",
  "plan-approved",
  "deployed",
  "inspected",
  "reset",
  "destroyed",
];

/**
 * The audit actions the control plane records for a complete run, in order.
 *
 * Asserting on the SERVER'S ledger rather than on the UI's own state is the point: it is the only
 * evidence that the flow actually happened rather than that the client believes it did.
 *
 * `instance.created` repeats once per team, so the check is containment-and-order, not equality —
 * see `assertLedgerOrder`.
 */
export const EXPECTED_LEDGER_ORDER: readonly string[] = [
  "exercise.created",
  "exercise.validated",
  "plan.generated",
  "plan.submitted",
  "plan.approved",
  "deploy.started",
  "instance.created",
  "deploy.completed",
  "reset.started",
  "reset.completed",
  "destroy.started",
  "destroy.completed",
];

/**
 * Check that `expected` appears within `actual` in order (allowing extra entries between).
 * Returns the first expected action that could not be found, or null when all matched.
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
