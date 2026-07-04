// Pure, framework-free logic for the Read-Only Staging Preflight (SECP-B2-0).
//
// Kept separate from the React component so it is unit-testable and DOM-free. It renders ONLY safe
// aliases, closed lifecycle/outcome codes, and boolean/count readiness facts — never an endpoint,
// host, IP, port, path, VMID, storage id, certificate, token, credential, secret ref, or config.
// The server re-verifies and re-authorizes everything; the UI only guides the operator.

import type {
  PreflightAuthorization,
  ReadonlyPreflight,
  ReadonlyPreflightOutcome,
  ReadonlyPreflightStatus,
} from "../api/types";

/** Shown on every preflight control: this verifies readiness only and mutates nothing. */
export const READONLY_ONLY_LABEL =
  "Read-only readiness verification only — creates, alters, starts, or stops nothing.";

/** Shown while a worker still owes an outcome. */
export const QUEUED_NOTICE =
  "Preflight queued — a worker will verify authorization and run only approved GET-only reads.";

/** The preflight authorization is explicit and separate from staging-lab approval. */
export const AUTHORIZATION_SEPARATION_NOTICE =
  "This short-lived read-only authorization is created and approved explicitly here — it is " +
  "separate from staging-lab approval and is never created automatically from a staging-lab plan.";

/** Human-safe labels for closed outcome codes (no infrastructure detail). */
export const OUTCOME_LABELS: Record<ReadonlyPreflightOutcome, string> = {
  ready: "Ready",
  not_ready: "Not ready",
  authorization_expired: "Authorization expired",
  authorization_revoked: "Authorization revoked",
  authorization_invalid: "Authorization invalid",
  credential_unavailable: "Credential unavailable",
  tls_or_policy_refused: "TLS / policy refused",
  worker_internal_failure: "Worker failure",
};

export function outcomeLabel(code: ReadonlyPreflightOutcome | null | undefined): string {
  if (!code) return "Pending";
  return OUTCOME_LABELS[code] ?? "Pending";
}

/** A ready result proves only the collected readiness facts — never isolation/production-safety. */
export const READY_SCOPE_NOTICE =
  "A ready result proves only the specific readiness facts listed below. It does not claim the " +
  "host is isolated or production-safe.";

// Closed backend error codes (SECP-B2-0) mapped to FIXED safe UI text. The UI NEVER renders a
// backend `message`; an unknown/absent code maps to the generic fallback.
export const API_ERROR_TEXT: Record<string, string> = {
  readonly_preflight_not_found: "That preflight or authorization was not found.",
  readonly_preflight_forbidden: "You are not permitted to perform this action.",
  readonly_preflight_substrate_ineligible:
    "This substrate is not eligible for a read-only preflight.",
  readonly_preflight_authorization_invalid:
    "The read-only authorization is not valid for this action.",
  readonly_preflight_lifecycle_conflict: "The request conflicts with the current state.",
  readonly_preflight_queue_conflict: "A preflight is already active for this authorization.",
  readonly_preflight_internal_failure: "The request could not be completed.",
  invalid_readonly_preflight_input: "The request was rejected as invalid.",
};

export const GENERIC_API_ERROR_TEXT = "The request could not be completed.";

/** Map a closed error code to fixed safe UI text; unknown/absent -> generic fallback. */
export function apiErrorText(code: string | null | undefined): string {
  if (!code) return GENERIC_API_ERROR_TEXT;
  return API_ERROR_TEXT[code] ?? GENERIC_API_ERROR_TEXT;
}

// Client-side readiness-fact allowlist — MUST match the worker allowlist. Unknown keys dropped.
export const SAFE_FACT_KEYS = [
  "api_reachable",
  "readonly_policy_enforced",
  "node_count",
  "storage_count",
  "network_segment_count",
  "tls_verified",
] as const;

export function isQueuedOrRunning(status: ReadonlyPreflightStatus): boolean {
  return status === "queued" || status === "claimed" || status === "running";
}

export function isTerminal(status: ReadonlyPreflightStatus): boolean {
  return status === "completed" || status === "failed" || status === "refused";
}

export function isReady(pf: ReadonlyPreflight | null): boolean {
  return pf?.outcome_code === "ready";
}

/** Readiness facts (safe booleans/counts) for display; empty until a ready outcome exists.
 * Client-side allowlist: only SAFE_FACT_KEYS render — an unexpected key is dropped defensively. */
export function readinessFactRows(
  pf: ReadonlyPreflight | null,
): { key: string; value: string }[] {
  if (!pf || pf.outcome_code !== "ready" || !pf.readiness_facts) return [];
  const allowed = new Set<string>(SAFE_FACT_KEYS);
  return Object.entries(pf.readiness_facts)
    .filter(([key]) => allowed.has(key))
    .map(([key, value]) => ({
      key,
      value: typeof value === "boolean" ? (value ? "yes" : "no") : String(value),
    }));
}

export function authorizationIsApprovedAndCurrent(
  auth: PreflightAuthorization,
  now: Date = new Date(),
): boolean {
  return auth.status === "approved" && new Date(auth.authorization_expiry) > now;
}

/** The most recent approved+unexpired authorization for a substrate, or null. */
export function usableAuthorization(
  authorizations: PreflightAuthorization[],
  now: Date = new Date(),
): PreflightAuthorization | null {
  const usable = authorizations
    .filter((a) => authorizationIsApprovedAndCurrent(a, now))
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  return usable[0] ?? null;
}

export function canQueuePreflight(auth: PreflightAuthorization | null): boolean {
  return auth !== null;
}

export function substrateAliasOnly(alias: string): string {
  // Defensive: the UI only ever shows the server alias; never a raw endpoint/host.
  return alias;
}
