// Pure application-state to visual-state mapping for the SECP motion system.
//
// This module is the truth boundary between real page state and decorative
// animation. Every mapping is total and defensive: an unrecognized input
// resolves to a NEUTRAL/STATIC visual state, never to a more-operational one.
// The visual vocabulary deliberately keeps sealed, authorized, active,
// running, completed, eligible, approved, and executed as SEPARATE states —
// animation supplements status text and never invents activity.
//
// No backend free-form string is ever passed unchecked into a Rive input;
// callers map through these functions first.

/** Motion preference resolved from the environment, threaded so callers can
 *  force static in tests and honor prefers-reduced-motion at runtime. */
export type MotionPreference = "auto" | "reduced" | "static";

export function resolveMotion(
  requested: MotionPreference,
  prefersReducedMotion: boolean,
): "animate" | "static" {
  if (requested === "static") return "static";
  if (requested === "reduced") return "static";
  return prefersReducedMotion ? "static" : "animate";
}

// ---------------------------------------------------------------- lock

/** Sealed lock: sealed is the shipped default; authorization is a recorded
 *  decision, NOT activity; active only when a real active flag is supplied. */
export type LockVisual = "sealed" | "authorized" | "active" | "refused";

export interface LockInputs {
  sealed: boolean;
  authorized: boolean;
  active: boolean;
  refused: boolean;
}

/** Precedence enforces the truth ordering: refused and sealed dominate;
 *  authorized never implies active; active requires the explicit flag. */
export function lockVisual(inputs: Partial<LockInputs>): LockVisual {
  if (inputs.refused) return "refused";
  // active is only reachable when explicitly driven AND not sealed.
  if (inputs.active && !inputs.sealed) return "active";
  if (inputs.sealed) return "sealed";
  if (inputs.authorized) return "authorized";
  return "sealed";
}

// -------------------------------------------------------- authorization

/** Authorization pulse states — a decision lifecycle, never execution. */
export type AuthorizationVisual =
  | "draft"
  | "pending"
  | "approved"
  | "expired"
  | "revoked"
  | "refused";

const AUTHORIZATION_MAP: Record<string, AuthorizationVisual> = {
  draft: "draft",
  requested: "pending",
  pending: "pending",
  ready_for_review: "pending",
  awaiting_approval: "pending",
  approved: "approved",
  active: "approved",
  expired: "expired",
  revoked: "revoked",
  refused: "refused",
  rejected: "refused",
  denied: "refused",
};

/** Unknown status → neutral "draft" (least-operational), never approved. */
export function authorizationVisual(status: string): AuthorizationVisual {
  return AUTHORIZATION_MAP[status] ?? "draft";
}

// -------------------------------------------------------------- packet flow

/** Packet flow: sealed shows NO traffic; denied is not a success path;
 *  read-only is visually distinct from write/apply (which never animates
 *  here — apply is sealed platform-wide). */
export type FlowVisual = "sealed" | "read-only" | "denied" | "idle";

export interface FlowInputs {
  running: boolean;
  readOnly: boolean;
  denied: boolean;
  sealed: boolean;
}

export function flowVisual(inputs: Partial<FlowInputs>): FlowVisual {
  if (inputs.sealed) return "sealed";
  if (inputs.denied) return "denied";
  if (inputs.running && inputs.readOnly) return "read-only";
  return "idle";
}

// ------------------------------------------------------------ topology node

/** Topology node state — never conveyed by color alone (each has a distinct
 *  glyph treatment in the fallback). */
export type NodeVisual =
  | "default"
  | "selected"
  | "isolated"
  | "compromised"
  | "sealed";

export interface NodeInputs {
  selected: boolean;
  isolated: boolean;
  compromised: boolean;
  sealed: boolean;
}

export function nodeVisual(inputs: Partial<NodeInputs>): NodeVisual {
  if (inputs.compromised) return "compromised";
  if (inputs.sealed) return "sealed";
  if (inputs.isolated) return "isolated";
  if (inputs.selected) return "selected";
  return "default";
}

// ------------------------------------------------------------ approval stamp

/** Approval stamp: approved communicates a RECORDED DECISION, not execution. */
export type ApprovalVisual = "pending" | "approved" | "rejected" | "stale";

const APPROVAL_MAP: Record<string, ApprovalVisual> = {
  pending: "pending",
  draft: "pending",
  awaiting_approval: "pending",
  plan_ready: "pending",
  approved: "approved",
  rejected: "rejected",
  refused: "rejected",
  denied: "rejected",
  expired: "stale",
  superseded: "stale",
  invalidated_drift: "stale",
};

export function approvalVisual(status: string): ApprovalVisual {
  return APPROVAL_MAP[status] ?? "pending";
}

// ------------------------------------------------------------ worker bundle

/** Worker bundle: "ready" means the bundle is PREPARED — not that discovery
 *  ran or completed. */
export type BundleVisual = "preparing" | "ready" | "failed" | "sealed";

export interface BundleInputs {
  preparing: boolean;
  ready: boolean;
  failed: boolean;
  sealed: boolean;
}

export function bundleVisual(inputs: Partial<BundleInputs>): BundleVisual {
  if (inputs.failed) return "failed";
  if (inputs.sealed) return "sealed";
  if (inputs.ready) return "ready";
  if (inputs.preparing) return "preparing";
  return "sealed";
}

// ------------------------------------------------------------ discovery scan

/** Discovery scan: queued must NOT animate like running; completed must NOT
 *  imply eligible (eligibility is a separate recorded outcome). */
export type DiscoveryVisual = "queued" | "running" | "completed" | "failed";

const DISCOVERY_MAP: Record<string, DiscoveryVisual> = {
  requested: "queued",
  queued: "queued",
  discovering: "running",
  running: "running",
  discovered: "completed",
  plan_ready: "completed",
  approved: "completed",
  completed: "completed",
  failed: "failed",
};

/** Unknown status → "queued" (least-active), never running/completed. */
export function discoveryVisual(status: string): DiscoveryVisual {
  return DISCOVERY_MAP[status] ?? "queued";
}

// ------------------------------------------------------- globe hero state

/** Holographic globe posture — decorative, driven only by real state.
 *  ambient/sealed are non-operational; active animates only when supplied. */
export type GlobeVisual = "ambient" | "sealed" | "authorized" | "active" | "degraded";

const GLOBE_STATES: readonly GlobeVisual[] = [
  "ambient",
  "sealed",
  "authorized",
  "active",
  "degraded",
];

/** Unknown state → "ambient" (purely decorative), never "active". */
export function globeVisual(state: string): GlobeVisual {
  return (GLOBE_STATES as readonly string[]).includes(state)
    ? (state as GlobeVisual)
    : "ambient";
}
