import type { LifecycleState, PlanStatus } from "../api/types";

const LIFECYCLE_TONE: Record<LifecycleState, string> = {
  draft: "pending",
  validated: "accent",
  planned: "accent",
  awaiting_approval: "warn",
  approved: "accent",
  deploying: "warn",
  running: "ok",
  resetting: "warn",
  destroying: "warn",
  destroyed: "danger",
  failed: "danger",
};

const PLAN_TONE: Record<PlanStatus, string> = {
  generated: "pending",
  awaiting_approval: "warn",
  approved: "ok",
  rejected: "danger",
  applied: "accent",
};

export function StatusBadge({ state }: { state: string }) {
  const tone =
    LIFECYCLE_TONE[state as LifecycleState] ??
    PLAN_TONE[state as PlanStatus] ??
    "pending";
  return <span className={`badge ${tone}`}>{state.replace(/_/g, " ")}</span>;
}
