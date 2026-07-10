// Presentation view-models shared by the Staging Labs and Staging Deployments
// surfaces. This module composes the pinned staging-lab.ts / staging-deployment.ts
// contracts — it never reinterprets lifecycle status: rails are built from each
// module's exported LIFECYCLE_STEPS + lifecycleIndex, and off-rail statuses
// (worker-running, teardown, rollback, failure) surface through the modules'
// own statusLabel wording.

import type { StepRailItem } from "../components/ui/StepRail";

/** Closed staging action codes → fixed copy. Backend free-form messages and
 *  detail arrays are never rendered; the code stays visible for operators. */
export const STAGING_ERROR_TEXT: Record<string, string> = {
  validation_failed:
    "The request was rejected by the server's validation. Adjust the values and try again.",
  invalid_transition: "That action is not allowed in the current lifecycle state.",
  approval_required: "That action requires an approval that has not been recorded.",
  forbidden: "You are not permitted to perform this staging action.",
  not_found: "The requested staging record was not found.",
  immutable_resource: "That record is immutable and cannot be changed.",
};

interface LifecycleRailOptions<T extends string> {
  /** Off-rail callers can pass durable completed milestones so progress is not
   *  erased while still keeping the module status label as the current state. */
  completedStatuses?: readonly T[];
  /** Use when the current status is itself an on-rail terminal state but the
   *  completed milestones are not simply every earlier item. */
  currentStatus?: T;
  pendingReason?: string;
}

/** Non-interactive lifecycle rail from a module's exported ordered steps.
 *  complete = the lifecycle moved PAST a step; current = the recorded status;
 *  blocked = not reached yet. Off-rail statuses can pass durable completed
 *  milestones; the page still renders the module's statusLabel separately. */
export function lifecycleRailItems<T extends string>(
  steps: { status: T; label: string }[],
  currentIndex: number,
  options: LifecycleRailOptions<T> = {},
): StepRailItem[] {
  const completed = options.completedStatuses
    ? new Set<T>(options.completedStatuses)
    : null;
  const pendingReason = options.pendingReason ?? "Not reached yet";
  return steps.map((step, i) => ({
    id: step.status,
    label: step.label,
    ...((): Pick<StepRailItem, "state" | "blockedReason"> => {
      const state = completed
        ? options.currentStatus === step.status
          ? "current"
          : completed.has(step.status)
            ? "complete"
            : "blocked"
        : currentIndex === -1
          ? "blocked"
          : i < currentIndex
            ? "complete"
            : i === currentIndex
              ? "current"
              : "blocked";
      return {
        state,
        blockedReason: state === "blocked" ? pendingReason : undefined,
      };
    })(),
  }));
}

/** True when the recorded status is not on the happy-path rail. */
export function isOffRail(currentIndex: number): boolean {
  return currentIndex === -1;
}

/** Plan-pinning truth copy (mirrors the exact-hash approval calls the pages
 *  already make: approve*(id, plan_hash)). */
export const PLAN_PIN_NOTICE =
  "Approval is pinned to this exact plan hash. Any change produces a new plan version that must be re-approved.";

export const LAB_APPROVAL_SCOPE_NOTICE =
  "Approval permits queueing one labeled fake simulation only. It is not a live-read authorization, it does not activate a resolver or collector, and it creates no real infrastructure.";

export const DEPLOYMENT_APPROVAL_SCOPE_NOTICE =
  "Approval binds one exact plan hash plus its drift anchors. The apply remains a sealed, fail-closed worker contract — approval does not grant live-read authorization, does not activate a resolver or collector, and no real host action occurs unless the worker's sealed execution seams are enabled and durably record it.";

/** Fixed observation empty states (worker-owned results only). */
export const OBSERVATIONS_EMPTY_TITLE = "Nothing recorded yet";
export const OBSERVATIONS_QUEUED_BODY =
  "Observations appear once the worker records completion.";
export const OBSERVATIONS_IDLE_BODY =
  "Observations appear only after a worker records completion. Queueing a simulation does not create them.";
