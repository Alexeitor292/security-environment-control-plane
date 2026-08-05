// Types for the range API (`/api/v1/range-templates`, `/api/v1/ranges`).
//
// Mirrors `apps/api/secp_api/schemas_range.py` and `range_enums.py` on the range backend branch.
// Read from the SCHEMAS rather than transcribed from the contract document, because the document
// has already lagged the code once (`total_steps` became 0 on the first poll after range execution
// moved behind the worker boundary).
//
// Two omissions in the backend schemas are load-bearing and are preserved here by simply having no
// field to hold them:
//   - no schema anywhere carries a FLAG VALUE, so there is no path by which a solution reaches the
//     browser;
//   - no schema accepts an `organization_id`; tenancy comes from the authenticated principal.

// The enums are declared as runtime `as const` arrays with the TYPES DERIVED FROM THEM, rather
// than as bare type unions. That is deliberate: a bare union is erased at build time and cannot be
// checked against anything at runtime, so nothing could verify that the test fake — a second
// implementation of this contract — still emits values the contract allows. With the arrays
// present, `range-contract.test.ts` pins the fake, and the badge tone maps are proved exhaustive.
// Adding a value the backend introduced is then a single edit here that the compiler propagates.

/** `RangeState` — the range lifecycle, emitted natively by the range API. Same nine as `RangePhase`. */
export const RANGE_STATES = [
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
export type RangeState = (typeof RANGE_STATES)[number];

export const RANGE_OPERATION_KINDS = ["deploy", "reset", "destroy"] as const;
export type RangeOperationKind = (typeof RANGE_OPERATION_KINDS)[number];

/**
 * `unproven` is a real third outcome on all of these: the provider could not be observed, so the
 * answer is unknown. It is never a synonym for success or for failure.
 */
export const RANGE_OPERATION_STATUSES = [
  "pending",
  "running",
  "succeeded",
  "failed",
  "unproven",
] as const;
export type RangeOperationStatus = (typeof RANGE_OPERATION_STATUSES)[number];

/** `RangeStepStatus` has the same members as the operation status. */
export const RANGE_STEP_STATUSES = RANGE_OPERATION_STATUSES;
export type RangeStepStatus = RangeOperationStatus;

export const RANGE_RESOURCE_KINDS = ["network", "container"] as const;
export type RangeResourceKind = (typeof RANGE_RESOURCE_KINDS)[number];

export const RANGE_RESOURCE_STATES = [
  "pending",
  "creating",
  "created",
  "verified",
  "removing",
  "removed",
  "unproven",
  "failed",
] as const;
export type RangeResourceState = (typeof RANGE_RESOURCE_STATES)[number];

export const RESIDUE_VERDICTS = ["clean", "residue", "unproven"] as const;
export type ResidueVerdict = (typeof RESIDUE_VERDICTS)[number];

/** Per-resource verdict inside teardown evidence. Distinct from `ResidueVerdict`. */
export const TEARDOWN_RESOURCE_VERDICTS = ["removed", "present", "unproven"] as const;
export type TeardownResourceVerdict = (typeof TEARDOWN_RESOURCE_VERDICTS)[number];

export const RANGE_EVENT_LEVELS = ["info", "warning", "error"] as const;
export type RangeEventLevel = (typeof RANGE_EVENT_LEVELS)[number];

// --- catalog ---------------------------------------------------------------------------------

export interface RangeComponent {
  key: string;
  name: string;
  /** "target" | "scoring" | "support". */
  role: string;
  image: string;
  /** null for components with no HTTP surface. */
  container_port: number | null;
  protocol: string;
  path: string;
}

export interface RangeTemplate {
  slug: string;
  name: string;
  summary: string;
  description: string;
  provider: string;
  difficulty: string;
  estimated_deploy_seconds: number;
  /** Intentionally-vulnerable software warning. Always rendered, never suppressed. */
  warning: string;
  components: RangeComponent[];
  challenge_count: number;
  total_points: number;
}

// --- lifecycle -------------------------------------------------------------------------------

export interface RangeOperationStep {
  key: string;
  label: string;
  status: RangeStepStatus;
  detail: string | null;
  at: string | null;
}

export interface RangeOperationSummary {
  id: string;
  kind: RangeOperationKind;
  status: RangeOperationStatus;
  phase: string | null;
  completed_steps: number;
  /**
   * ZERO until the worker picks the operation up and plans the steps — the API no longer plans
   * them, because asking a provider what it intends to do means holding one, which the API is not
   * permitted to. `total_steps: 0` with `status: "pending"` means THE PLAN DOES NOT EXIST YET; it
   * does not mean an empty plan or a zero-length deployment. Never divide by it.
   */
  total_steps: number;
  /** Server-computed and already clamped in the pre-plan window. Prefer this over dividing. */
  percent: number;
}

export interface RangeOperation extends RangeOperationSummary {
  range_id: string;
  failure_code: string | null;
  failure_message: string | null;
  started_at: string;
  finished_at: string | null;
  steps: RangeOperationStep[];
}

export interface RangeAccessTarget {
  component_key: string;
  name: string;
  url: string;
  host: string;
  port: number;
  protocol: string;
  /** True ONLY where an actual response was observed. Never inferred from "container created". */
  reachable: boolean;
  observed_at: string | null;
}

export interface Range {
  id: string;
  name: string;
  template_slug: string;
  template_name: string;
  provider: string;
  state: RangeState;
  state_reason: string | null;
  created_at: string;
  updated_at: string;
  deployed_at: string | null;
  destroyed_at: string | null;
  competition_id: string | null;
  /** null before the first operation. */
  current_operation: RangeOperationSummary | null;
  residue_verdict: ResidueVerdict | null;
  /** `[]` unless the range is `ready` or `active`. */
  access: RangeAccessTarget[];
}

export interface RangeResource {
  id: string;
  kind: RangeResourceKind;
  provider: string;
  component_key: string | null;
  name: string;
  external_id: string | null;
  image: string | null;
  image_digest: string | null;
  state: RangeResourceState;
  host_port: number | null;
  created_at: string;
  removed_at: string | null;
  detail: Record<string, unknown>;
}

export interface RangeEvent {
  id: string;
  range_id: string;
  sequence: number;
  kind: string;
  level: RangeEventLevel;
  /** Render this. `kind` is a stable machine string, not display copy. */
  message: string;
  data: Record<string, unknown>;
  occurred_at: string;
}

export interface TeardownResource {
  kind: string;
  name: string;
  external_id: string | null;
  /** "removed" | "present" | "unproven". */
  verdict: string;
  detail: string | null;
}

export interface TeardownEvidence {
  id: string;
  range_id: string;
  operation_id: string | null;
  verdict: ResidueVerdict;
  /** false means the removal and the existence check share a failure mode — absence NOT proved. */
  probe_reachable: boolean;
  expected_count: number;
  removed_confirmed: number;
  still_present: number;
  unproven_count: number;
  reason: string | null;
  observed_at: string;
  resources: TeardownResource[];
}

// --- requests --------------------------------------------------------------------------------

export interface RangeCreate {
  template_slug: string;
  /** Optional; defaults to the template name server-side. */
  name?: string;
}
