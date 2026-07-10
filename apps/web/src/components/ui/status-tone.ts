// Status → badge tone resolution for the unified StatusBadge.
//
// Every known status union from src/api/types.ts has an explicit, exhaustive
// tone map (Record<Union, Tone> — the compiler rejects a missing member).
// Unknown statuses resolve to the visually distinct "unknown" tone; they are
// never silently rendered as "pending".

import type {
  BootstrapStatus,
  LifecycleState,
  OnboardingStatus,
  PlanStatus,
  ReadonlyPreflightOutcome,
  ReadonlyPreflightStatus,
  StagingDeploymentStatus,
  StagingLabStatus,
  TargetDiscoveryStatus,
} from "../../api/types";

/** Badge tones. All but "unknown" bind to the pre-existing .badge.* classes. */
export type StatusTone =
  | "ok"
  | "warn"
  | "danger"
  | "accent"
  | "pending"
  | "unknown";

export type StatusDomain =
  | "lifecycle"
  | "plan"
  | "onboarding"
  | "staging-lab"
  | "staging-deployment"
  | "discovery"
  | "bootstrap"
  | "preflight"
  | "preflight-outcome"
  | "evidence"
  | "verification"
  | "authorization"
  | "target"
  | "audit";

export const LIFECYCLE_TONE: Record<LifecycleState, StatusTone> = {
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

export const PLAN_TONE: Record<PlanStatus, StatusTone> = {
  generated: "pending",
  awaiting_approval: "warn",
  approved: "ok",
  rejected: "danger",
  applied: "accent",
};

export const ONBOARDING_TONE: Record<OnboardingStatus, StatusTone> = {
  draft: "pending",
  preflight_pending: "warn",
  ready_for_review: "warn",
  approved: "accent",
  active: "ok",
  rejected: "danger",
  retired: "pending",
};

export const STAGING_LAB_TONE: Record<StagingLabStatus, StatusTone> = {
  draft: "pending",
  planned: "accent",
  awaiting_approval: "warn",
  approved: "accent",
  simulation_queued: "warn",
  simulating: "warn",
  simulated_ready: "ok",
  teardown_queued: "warn",
  tearing_down: "warn",
  destroyed: "danger",
  failed: "danger",
};

export const STAGING_DEPLOYMENT_TONE: Record<StagingDeploymentStatus, StatusTone> = {
  draft: "pending",
  planned: "accent",
  awaiting_approval: "warn",
  approved: "accent",
  bootstrap_pending: "warn",
  applying: "warn",
  verifying: "warn",
  ready: "ok",
  failed: "danger",
  rollback_required: "danger",
  rolling_back: "warn",
  rolled_back: "pending",
  teardown_requested: "warn",
  tearing_down: "warn",
  destroyed: "danger",
};

export const DISCOVERY_TONE: Record<TargetDiscoveryStatus, StatusTone> = {
  requested: "warn",
  discovering: "warn",
  discovered: "accent",
  plan_ready: "warn",
  approved: "accent",
  failed: "danger",
};

export const BOOTSTRAP_TONE: Record<BootstrapStatus, StatusTone> = {
  pending: "warn",
  completed: "accent",
  bound: "ok",
  refused: "danger",
};

export const PREFLIGHT_TONE: Record<ReadonlyPreflightStatus, StatusTone> = {
  queued: "warn",
  claimed: "warn",
  running: "warn",
  completed: "ok",
  failed: "danger",
  refused: "danger",
};

export const PREFLIGHT_OUTCOME_TONE: Record<ReadonlyPreflightOutcome, StatusTone> = {
  ready: "ok",
  not_ready: "warn",
  // Expected result while the resolver is sealed — honest, not alarming.
  credential_unavailable: "warn",
  authorization_expired: "danger",
  authorization_revoked: "danger",
  authorization_invalid: "danger",
  tls_or_policy_refused: "danger",
  worker_internal_failure: "danger",
};

/** TargetEvidence / finding statuses ("pass" | "fail" | "unverifiable"). */
export const EVIDENCE_TONE: Record<string, StatusTone> = {
  pass: "ok",
  fail: "danger",
  unverifiable: "pending",
};

/** StagingDeploymentVerification.status values. These are distinct from the
 *  evidence map: the backend emits "passed", not "pass". */
export const VERIFICATION_TONE: Record<string, StatusTone> = {
  passed: "ok",
  failed: "danger",
  unverifiable: "pending",
};

/** ExecutionTarget.status (backend TargetStatus enum — plain string in
 *  types.ts): active | disabled | discovery_failed. Disabled is a routine
 *  operator-initiated state, not an anomaly. */
export const TARGET_TONE: Record<string, StatusTone> = {
  active: "ok",
  disabled: "pending",
  discovery_failed: "danger",
};

/** Plain-string authorization statuses used by PreflightAuthorization and
 *  ResolverActivation (not closed unions in types.ts). */
export const AUTHORIZATION_TONE: Record<string, StatusTone> = {
  draft: "pending",
  requested: "warn",
  approved: "ok",
  active: "ok",
  registered: "ok",
  expired: "danger",
  revoked: "danger",
  // Sealed is the safe shipped default; the reference renders it red to mean
  // "no access exists", not "something is wrong".
  sealed: "danger",
};

/** AuditEvent.outcome values (plain string in types.ts). */
export const AUDIT_TONE: Record<string, StatusTone> = {
  success: "ok",
  denied: "danger",
  refused: "danger",
  failed: "danger",
  error: "danger",
};

const DOMAIN_MAPS: Record<StatusDomain, Record<string, StatusTone>> = {
  lifecycle: LIFECYCLE_TONE,
  plan: PLAN_TONE,
  onboarding: ONBOARDING_TONE,
  "staging-lab": STAGING_LAB_TONE,
  "staging-deployment": STAGING_DEPLOYMENT_TONE,
  discovery: DISCOVERY_TONE,
  bootstrap: BOOTSTRAP_TONE,
  preflight: PREFLIGHT_TONE,
  "preflight-outcome": PREFLIGHT_OUTCOME_TONE,
  evidence: EVIDENCE_TONE,
  verification: VERIFICATION_TONE,
  authorization: AUTHORIZATION_TONE,
  target: TARGET_TONE,
  audit: AUDIT_TONE,
};

/** Resolution order for domain-less lookups. Lifecycle then plan first, which
 *  keeps every previously EXPLICITLY mapped state rendering exactly as before
 *  (e.g. domain-less "approved" stays accent). States that previously fell
 *  through to the silent "pending" fallback now resolve to an explicit tone;
 *  where a key exists in several maps, the earlier map shadows the later one
 *  until the call site passes `domain`. */
const DEFAULT_ORDER: StatusDomain[] = [
  "lifecycle",
  "plan",
  "onboarding",
  "staging-lab",
  "staging-deployment",
  "discovery",
  "bootstrap",
  "preflight",
  "preflight-outcome",
  "evidence",
  "verification",
  "authorization",
  "target",
  "audit",
];

export interface ResolvedStatus {
  tone: StatusTone;
  /** false means the status matched no known map — rendered distinctly, never
   *  silently as "pending". */
  known: boolean;
}

/** Own-property, string-only lookup — inherited Object.prototype members
 *  (e.g. state "constructor") must resolve as unknown, not as a tone. */
function ownTone(
  map: Record<string, StatusTone>,
  state: string,
): StatusTone | undefined {
  if (!Object.prototype.hasOwnProperty.call(map, state)) return undefined;
  const tone = map[state];
  return typeof tone === "string" ? tone : undefined;
}

export function resolveStatusTone(
  state: string,
  domain?: StatusDomain,
): ResolvedStatus {
  if (domain) {
    const tone = ownTone(DOMAIN_MAPS[domain], state);
    return tone ? { tone, known: true } : { tone: "unknown", known: false };
  }
  for (const d of DEFAULT_ORDER) {
    const tone = ownTone(DOMAIN_MAPS[d], state);
    if (tone) return { tone, known: true };
  }
  return { tone: "unknown", known: false };
}

/** Display transform shared by all badges: underscores to spaces. */
export function statusDisplayLabel(state: string): string {
  return state.replace(/_/g, " ");
}
