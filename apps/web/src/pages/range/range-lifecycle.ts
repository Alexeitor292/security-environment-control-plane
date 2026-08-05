// The product-level range lifecycle.
//
// The nine phases below are the vocabulary the range product speaks: a range is a draft, it is
// deploying, it is ready to use, a competition is active on it, it is resetting, it needs recovery,
// it failed, it is being destroyed, or it is destroyed.
//
// TWO backends produce these phases, and `rangeLifecycle` is the single place both are read.
//
// 1. The RANGE API (`RangeState` in the frozen range contract) emits these exact nine values. For
//    it the projection is IDENTITY — the value passes through untouched.
//
// 2. The legacy EXERCISE API emits `LifecycleState` (api/types.ts): eleven values with a different
//    shape — five distinct pre-deployment states the product calls one thing, and no
//    `recovery_required` at all. Those are projected by the table below.
//
// Everything else in the range UI reads a phase and never a raw state, so a page does not know or
// care which backend it came from.
//
// The projection never reports a phase the recorded state cannot support. Two consequences worth
// naming, because both were got wrong first time:
//
//  - `running` projects to `active`, NOT to `ready` (lead ruling, 2026-08-04). In the range
//    contract `ready` specifically means "deployed AND OBSERVED REACHABLE". The exercise surface
//    observes nothing, so it cannot produce `ready`; claiming it would assert a probe that never
//    ran.
//  - `recovery_required` is NOT a flavour of `failed`. It means an operation could not be OBSERVED
//    to completion — canonically, teardown could not prove the residue is gone. "It broke" and "we
//    cannot prove what happened" are different facts and are rendered differently everywhere.
//
// `recorded` is carried alongside every phase so the UI can always show the precise server-recorded
// state next to the product phase.

import type { LifecycleState, RangePhase } from "../../api/types";
import { RANGE_TONE } from "../../components/ui";

export type { RangePhase };

/** Narrative order. Index is used for progress, never for permission decisions. */
export const RANGE_PHASE_ORDER: readonly RangePhase[] = [
  "draft",
  "deploying",
  "ready",
  "active",
  "resetting",
  "recovery_required",
  "failed",
  "destroying",
  "destroyed",
];

export const RANGE_PHASE_LABEL: Record<RangePhase, string> = {
  draft: "Draft",
  deploying: "Deploying",
  ready: "Ready",
  // "Active", not "Competition active" (lead ruling). Two backends land here: the range API, where
  // `active` does mean a competition is running, and the exercise API, whose `running` projects
  // here with no competition anywhere in the system. A label naming a competition would be a false
  // claim on every exercise-backed range.
  active: "Active",
  resetting: "Resetting",
  recovery_required: "Recovery required",
  failed: "Failed",
  destroying: "Destroying",
  destroyed: "Destroyed",
};

/** Re-exported from the shared badge tone map so the badge and any other consumer can never drift
 *  apart — there is one tone per phase, defined once, in status-tone.ts with every other domain. */
export const RANGE_PHASE_TONE = RANGE_TONE;

/** One-line explanation of what the phase means for the operator. */
export const RANGE_PHASE_HELP: Record<RangePhase, string> = {
  draft: "Defined but not deployed. No infrastructure exists yet.",
  deploying: "Infrastructure is being created. Targets are not reachable yet.",
  ready: "Deployed and observed reachable. No competition is running.",
  // Deliberately does not assert a competition — see the label comment above.
  active: "Deployed and in use. A competition, if one exists, runs in this phase.",
  resetting: "Targets are being returned to their initial state.",
  recovery_required: "Automatic progress stopped. An operator has to intervene.",
  failed: "The last operation failed. Inspect the timeline before retrying.",
  destroying: "Infrastructure is being torn down.",
  destroyed: "Torn down. Nothing remains to access.",
};

/**
 * Exhaustive projection from the recorded control-plane state to a product phase.
 *
 * A `Record<LifecycleState, RangePhase>` rather than a switch so the compiler rejects the map the
 * day the backend adds a state — an unmapped state must be a build failure, never a silent fall
 * through to `draft`, which would render a live range as "no infrastructure exists yet".
 */
const PHASE_BY_RECORDED_STATE: Record<LifecycleState, RangePhase> = {
  // The five pre-deployment states are ONE product phase. They differ in approval progress, not in
  // what exists: in every one of them no infrastructure has been created.
  draft: "draft",
  validated: "draft",
  planned: "draft",
  awaiting_approval: "draft",
  approved: "draft",

  deploying: "deploying",
  // `running` IS `active` (lead ruling, 2026-08-04), and the range contract agrees: `RangeState`
  // has BOTH `ready` and `active` as distinct values, where `ready` means "deployed AND observed
  // reachable, competition not started". The legacy exercise surface never observes reachability,
  // so it cannot produce `ready` — it can only say the workflow reached its running state. Mapping
  // `running` to `ready` would therefore have claimed an observation nothing performed.
  running: "active",
  resetting: "resetting",
  destroying: "destroying",
  destroyed: "destroyed",
  failed: "failed",
};

export interface RangeLifecycle {
  /** The product phase. */
  phase: RangePhase;
  /** The exact state the server recorded, always shown alongside the phase. */
  recorded: string;
  /** false when the server sent a state this build does not know. */
  known: boolean;
}

/** Own-property membership test for the nine product phases. */
function isRangePhase(value: string): value is RangePhase {
  return (RANGE_PHASE_ORDER as readonly string[]).includes(value);
}

/**
 * Project a server-recorded lifecycle state onto a product phase.
 *
 * A value that is ALREADY one of the nine phases passes straight through — that is the range API's
 * `RangeState`, and re-mapping it would be a chance to corrupt it. The legacy exercise states go
 * through the table. The native check runs FIRST, so once the range backend lands, `ready` and
 * `recovery_required` are honoured verbatim rather than falling into the unknown branch.
 *
 * The two vocabularies overlap on six names (`draft`, `deploying`, `resetting`, `destroying`,
 * `destroyed`, `failed`) and agree on all six, so the precedence is safe. They differ only on
 * `running`, which exists solely in the legacy enum and is handled by the table.
 *
 * An unrecognized state does NOT guess. It reports `recovery_required` — "automatic progress
 * stopped, a human has to look" — because that is exactly the situation, and because every other
 * phase would assert something specific about infrastructure that this build cannot know.
 * `known:false` lets the UI say so plainly rather than dressing it up.
 */
export function rangeLifecycle(recorded: string): RangeLifecycle {
  if (isRangePhase(recorded)) return { phase: recorded, recorded, known: true };
  if (Object.prototype.hasOwnProperty.call(PHASE_BY_RECORDED_STATE, recorded)) {
    const phase = PHASE_BY_RECORDED_STATE[recorded as LifecycleState];
    if (typeof phase === "string") return { phase, recorded, known: true };
  }
  return { phase: "recovery_required", recorded, known: false };
}

/**
 * Phases where the server is mid-operation and the client should keep polling. Nothing else in the
 * UI decides to poll; a page asks this so "when do we refresh" has one answer.
 */
export function isInFlight(phase: RangePhase): boolean {
  return phase === "deploying" || phase === "resetting" || phase === "destroying";
}

/** Phases from which no further transition happens on its own. */
export function isTerminal(phase: RangePhase): boolean {
  return phase === "destroyed";
}

/** Whether the range has infrastructure an operator could reach right now. */
export function hasLiveInfrastructure(phase: RangePhase): boolean {
  return phase === "ready" || phase === "active" || phase === "resetting";
}

export type RangeAction = "deploy" | "reset" | "destroy";

/**
 * Which lifecycle actions the phase permits.
 *
 * This is a CLIENT-SIDE AFFORDANCE, not an authorization decision. The server re-checks every one
 * of these and is authoritative; this exists so the UI does not offer a button whose only possible
 * outcome is a refusal. A phase this build does not understand permits nothing — an unknown state
 * is the worst moment to offer a destroy button.
 */
export function permittedActions(lifecycle: RangeLifecycle): readonly RangeAction[] {
  if (!lifecycle.known) return [];
  switch (lifecycle.phase) {
    case "draft":
      return ["deploy"];
    case "ready":
    case "active":
      return ["reset", "destroy"];
    // A failed range still has whatever the failed operation left behind, so tearing it down is
    // exactly what an operator needs. Re-deploying over the wreckage is not offered.
    case "failed":
    case "recovery_required":
      return ["destroy"];
    case "deploying":
    case "resetting":
    case "destroying":
    case "destroyed":
      return [];
  }
}

/** The steps the deployment progress page walks through, in order. */
export const DEPLOYMENT_STEPS: readonly RangePhase[] = [
  "draft",
  "deploying",
  "ready",
];

export type StepStatus = "done" | "current" | "upcoming" | "failed";

/**
 * Status of one deployment step given the phase the range is actually in.
 *
 * A failure marks the step that was in flight as `failed` rather than quietly leaving the rail
 * frozen mid-progress — a stalled rail and a failed deployment must not look the same.
 */
export function deploymentStepStatus(
  step: RangePhase,
  lifecycle: RangeLifecycle,
): StepStatus {
  const { phase } = lifecycle;
  if (phase === "failed" || phase === "recovery_required") {
    // Everything before `deploying` completed; `deploying` is where a deploy failure lands.
    return step === "draft" ? "done" : step === "deploying" ? "failed" : "upcoming";
  }
  // Past deployment (a competition is on, or it is being reset/torn down) every step is done.
  if (phase === "active" || phase === "resetting" || phase === "destroying" || phase === "destroyed") {
    return "done";
  }
  const current = RANGE_PHASE_ORDER.indexOf(phase);
  const at = RANGE_PHASE_ORDER.indexOf(step);
  if (at < current) return "done";
  if (at === current) return phase === "ready" ? "done" : "current";
  return "upcoming";
}

/**
 * Fraction of the deployment walk completed, 0..1, for a progress meter.
 * `failed` deliberately does not report 1 — a failed deploy has not finished.
 */
export function deploymentProgress(lifecycle: RangeLifecycle): number {
  const done = DEPLOYMENT_STEPS.filter(
    (s) => deploymentStepStatus(s, lifecycle) === "done",
  ).length;
  return done / DEPLOYMENT_STEPS.length;
}
