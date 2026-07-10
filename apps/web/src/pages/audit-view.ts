import type { AuditEvent } from "../api/types";

// Pure view-model for the governance surfaces: the append-only audit ledger
// and the aggregate approvals queue's recorded-decision rail.
//
// Truth rules enforced here:
// - The ledger is evidence, not telemetry: rows render only recorded fields.
// - Refusals are first-class: refusal DECISIONS are classified by the action
//   verb (a `plan.rejected` event records outcome "success" because the
//   RECORDING succeeded — the verb carries the refusal, not the outcome).
// - Event detail is operator-safe: an allowlist of known recorded keys with
//   value guards; free-form backend internals (error/summary/message/...)
//   are never displayed; unknown or unsafe fields are counted, not shown.
// - Approval records a decision; nothing executes from these surfaces.

// ------------------------------------------------------------------ copy

/** Existing charter copy, preserved verbatim from the previous ledger page. */
export const LEDGER_INTRO =
  "Immutable, append-only record. Every mutation and authorization decision is captured (Charter Invariant 10).";

/** Closed unavailability copy — the backend error text is never rendered. */
export const LEDGER_UNAVAILABLE = "Audit log unavailable.";

export const QUEUE_INTRO =
  "Aggregated from each surface's own review state — the same predicates each surface uses. Decisions are made on the owning surface; this queue only navigates.";

export const QUEUE_EXECUTES_NOTHING =
  "Approval records a decision. Nothing is executed from this queue — live apply and provisioning remain sealed.";

export const REFUSAL_FIRST_NOTE =
  "Refusals are first-class evidence: every refusal, denial, and revocation is recorded with the same fidelity as approvals.";

export const OPERATOR_SAFE_NOTE =
  "Operator-safe view: only allowlisted recorded fields are displayed. Free-form backend internals and anything secret-shaped are withheld.";

// ------------------------------------------------------------- structure

/** The backend records naive-UTC ISO strings (no timezone suffix). Format by
 *  string slicing — never via `new Date(...)`, which would parse a naive
 *  string as LOCAL time and shift the displayed value by the viewer's offset. */
export function ledgerTimestamp(createdAt: string): string {
  return createdAt.slice(0, 19).replace("T", " ");
}

const CATEGORY_RE = /^[a-z0-9_]{1,32}$/;

/** Category token before the first "." of an action (e.g. "onboarding" from
 *  "onboarding.approved"). Malformed actions group under "other". */
export function actionCategory(action: string): string {
  const head = action.split(".", 1)[0] ?? "";
  return CATEGORY_RE.test(head) && head !== action ? head : "other";
}

/** Verb after the last "." of an action ("approved" from "onboarding.approved"). */
export function actionVerb(action: string): string {
  const i = action.lastIndexOf(".");
  return i >= 0 ? action.slice(i + 1) : action;
}

/** Distinct categories present in the loaded events, sorted. Derived from real
 *  data only — never a hardcoded list that could claim absent categories. */
export function ledgerCategories(events: AuditEvent[]): string[] {
  return [...new Set(events.map((e) => actionCategory(e.action)))].sort();
}

// -------------------------------------------------------------- filtering

export type OutcomeFilter = "all" | "flagged" | "success";

export interface LedgerFilter {
  outcome: OutcomeFilter;
  category: string; // "all" or an exact category token
  query: string;
}

export const EMPTY_LEDGER_FILTER: LedgerFilter = {
  outcome: "all",
  category: "all",
  query: "",
};

/** True for any recorded outcome other than plain success. */
export function isFlaggedOutcome(outcome: string): boolean {
  return outcome !== "success";
}

export function filterLedger(
  events: AuditEvent[],
  filter: LedgerFilter,
): AuditEvent[] {
  const q = filter.query.trim().toLowerCase();
  return events.filter((e) => {
    if (filter.outcome === "flagged" && !isFlaggedOutcome(e.outcome)) return false;
    if (filter.outcome === "success" && e.outcome !== "success") return false;
    if (filter.category !== "all" && actionCategory(e.action) !== filter.category)
      return false;
    if (q) {
      const hay = [
        e.action,
        e.resource_type,
        e.resource_id ?? "",
        e.actor,
        e.outcome,
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

/** Counts for the refusal-first strip. Computed only from loaded events. */
export function ledgerTally(events: AuditEvent[]): {
  total: number;
  flagged: number;
  decisions: number;
} {
  return {
    total: events.length,
    flagged: events.filter((e) => isFlaggedOutcome(e.outcome)).length,
    decisions: events.filter((e) => isDecisionAction(e.action)).length,
  };
}

// ------------------------------------------------------ decision records

const DECISION_VERBS = ["approved", "rejected", "refused", "revoked", "denied"];

/** True when the action records a governance decision (approve/reject/refuse/
 *  revoke/deny), matched on the verb — including compound verbs such as
 *  "authorization_validation_refused". */
export function isDecisionAction(action: string): boolean {
  const verb = actionVerb(action);
  return DECISION_VERBS.some((v) => verb === v || verb.endsWith(`_${v}`));
}

/** True when the recorded decision is a refusal-shaped decision. Keyed on the
 *  VERB: a `plan.rejected` event carries outcome "success" (the recording
 *  succeeded) yet is a refusal decision. Non-success outcomes also count. */
export function isRefusalDecision(event: AuditEvent): boolean {
  const verb = actionVerb(event.action);
  const refusalVerb = ["rejected", "refused", "revoked", "denied"].some(
    (v) => verb === v || verb.endsWith(`_${v}`),
  );
  return refusalVerb || isFlaggedOutcome(event.outcome);
}

export interface DecisionRecord {
  id: string;
  action: string;
  category: string;
  verb: string;
  outcome: string;
  createdAt: string;
  resourceType: string;
  resourceId: string | null;
  /** Grammar-guarded machine code from the recorded data, if present. */
  reasonCode: string | null;
}

const CODE_RE = /^[a-z0-9_.:-]{1,64}$/;

function recordedCode(data: Record<string, unknown>, key: string): string | null {
  if (!Object.prototype.hasOwnProperty.call(data, key)) return null;
  const v = data[key];
  return typeof v === "string" && CODE_RE.test(v) ? v : null;
}

/** Immutable decision records from the ledger, newest first, split with
 *  refusals FIRST — refusal evidence outranks approvals in placement. */
export function decisionRecords(events: AuditEvent[]): {
  refusals: DecisionRecord[];
  approvals: DecisionRecord[];
} {
  const toRecord = (e: AuditEvent): DecisionRecord => ({
    id: e.id,
    action: e.action,
    category: actionCategory(e.action),
    verb: actionVerb(e.action),
    outcome: e.outcome,
    createdAt: e.created_at,
    resourceType: e.resource_type,
    resourceId: e.resource_id,
    reasonCode:
      recordedCode(e.data ?? {}, "reason_code") ??
      recordedCode(e.data ?? {}, "decision_code"),
  });
  const decisions = events.filter((e) => isDecisionAction(e.action));
  const byNewest = (a: DecisionRecord, b: DecisionRecord) =>
    b.createdAt.localeCompare(a.createdAt);
  return {
    refusals: decisions.filter(isRefusalDecision).map(toRecord).sort(byNewest),
    approvals: decisions
      .filter((e) => !isRefusalDecision(e))
      .map(toRecord)
      .sort(byNewest),
  };
}

// --------------------------------------------------- operator-safe detail

export interface DetailField {
  key: string;
  label: string;
  value: string;
  mono: boolean;
  /** Content-address values render as truncating hash chips. */
  hash: boolean;
}

/** Recorded keys that may be displayed, with human labels. Order matters:
 *  refusal evidence (reason codes, reasons) leads. */
const DETAIL_ALLOWLIST: [string, string][] = [
  ["reason_code", "Reason code"],
  ["decision_code", "Decision code"],
  ["reason", "Recorded reason"],
  ["status", "Status"],
  ["kind", "Kind"],
  ["slug", "Slug"],
  ["label", "Label"],
  ["node_label", "Node label"],
  ["ownership_label", "Ownership label"],
  ["verification_level", "Verification level"],
  ["plan_version", "Plan version"],
  ["enrollment_version", "Enrollment version"],
  ["authorization_version", "Authorization version"],
  ["identity_version", "Identity version"],
  ["revision", "Revision"],
  ["team_count", "Team count"],
  ["teams", "Teams"],
  ["ttl_seconds", "TTL (seconds)"],
  ["cidr", "CIDR"],
  ["plugin", "Plugin"],
  ["plugin_name", "Plugin"],
  ["approved_by", "Approved by"],
  ["approved_at", "Approved at"],
  ["plan_hash", "Plan hash"],
  ["approved_plan_hash", "Approved plan hash"],
  ["boundary_hash", "Boundary hash"],
  ["effective_boundary_hash", "Effective boundary hash"],
  ["evidence_hash", "Evidence hash"],
  ["approved_preflight_evidence_hash", "Approved preflight evidence hash"],
  ["content_hash", "Content hash"],
  ["approved_content_hash", "Approved content hash"],
  ["endpoint_binding_hash", "Endpoint binding hash"],
  ["execution_target_id", "Execution target"],
  ["target_id", "Execution target"],
  ["onboarding_id", "Onboarding"],
  ["enrollment_id", "Enrollment"],
  ["authorization_id", "Authorization"],
  ["admission_id", "Admission"],
  ["worker_registration_id", "Worker registration"],
  ["approved_preflight_id", "Approved preflight"],
  ["version_id", "Version"],
  ["exercise_id", "Exercise"],
  ["organization_id", "Organization"],
];

/** Free-form backend internals — recorded, but never displayed. */
const DETAIL_BLOCKED = new Set([
  "error",
  "summary",
  "message",
  "detail",
  "details",
  "traceback",
  "stack",
]);

const SECRETISH_KEY_RE = /(secret|token|password|credential|private|api_key|apikey|ssh)/i;
const PEM_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
/** Secret-shaped VALUE heuristics for free-form fields: known credential
 *  prefixes (JWTs, AWS access keys, GitHub/Slack/OpenAI/GitLab tokens, SSH
 *  keys) and long unbroken base64/hex runs. Hash fields are exempt (content
 *  addresses are long hex by design and render as chips). */
const SECRET_VALUE_RE =
  /\b(eyJ[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{15,}|xox[abps]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|ssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]+)/;
const LONG_UNBROKEN_RUN_RE = /[A-Za-z0-9+/=_-]{64,}/;
const MAX_VALUE_LEN = 160;

function isSafePrimitive(v: unknown): v is string | number | boolean {
  return (
    typeof v === "number" || typeof v === "boolean" || typeof v === "string"
  );
}

/**
 * Operator-safe field list for one event. Only allowlisted keys with primitive,
 * guard-passing values render; everything else is counted into `hiddenCount`
 * so the withholding itself is visible and honest.
 */
export function detailFields(event: AuditEvent): {
  fields: DetailField[];
  hiddenCount: number;
} {
  const data = event.data ?? {};
  const keys = Object.keys(data);
  const fields: DetailField[] = [];
  const shown = new Set<string>();

  for (const [key, label] of DETAIL_ALLOWLIST) {
    if (!Object.prototype.hasOwnProperty.call(data, key)) continue;
    // Defense in depth: even if a blocked or secret-shaped key were ever added
    // to the allowlist, it still would not render.
    if (DETAIL_BLOCKED.has(key) || SECRETISH_KEY_RE.test(key)) continue;
    const raw = data[key];
    if (!isSafePrimitive(raw)) continue;
    let value = String(raw);
    if (PEM_RE.test(value)) continue;
    const isHash = key.endsWith("_hash");
    // Secret-shaped values in free-form fields are withheld (they still count
    // into hiddenCount below, keeping the withholding visible).
    if (!isHash && (SECRET_VALUE_RE.test(value) || LONG_UNBROKEN_RUN_RE.test(value)))
      continue;
    if (!isHash && value.length > MAX_VALUE_LEN) {
      value = `${value.slice(0, MAX_VALUE_LEN)}…`;
    }
    fields.push({
      key,
      label,
      value,
      mono: isHash || key.endsWith("_id") || key.endsWith("_code") || key === "cidr" || key === "slug",
      hash: isHash,
    });
    shown.add(key);
  }

  const hiddenCount = keys.filter((k) => !shown.has(k)).length;
  return { fields, hiddenCount };
}

export function hiddenFieldsNote(hiddenCount: number): string {
  return `${hiddenCount} recorded field${hiddenCount === 1 ? "" : "s"} not displayed (operator-safe view).`;
}
