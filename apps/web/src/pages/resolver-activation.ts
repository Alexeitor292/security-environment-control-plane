// SECP-B2-4.1 — resolver-activation authorization UI logic (secret-free, no backend detail).
//
// This surface displays only closed states, safe hashes, and evidence metadata. It never collects,
// transmits, displays, or re-displays a secret, endpoint, backend endpoint, credential, worker
// identity, vault path, or reference, and it never implies a real backend is connected.

import type { ResolverActivation } from "../api/types";

// Shown prominently wherever an activation authorization appears. An APPROVED authorization is NOT
// an active resolver.
export const RESOLVER_ACTIVATION_SEALED_NOTICE =
  "Authorization exists, but resolver activation remains sealed until separate staging trust " +
  "evidence and worker-side activation are completed. Approving here connects no backend and " +
  "resolves no secret.";

export const RESOLVER_ACTIVATION_SCOPE_NOTICE =
  "This authorization does not grant infrastructure execution, does not substitute for collector " +
  "or OpenTofu activation gates, and is separate from live-read and staging-lab approvals.";

// Closed error codes -> fixed local text. Unknown codes fall back to the generic message; a backend
// message is never rendered.
export const API_ERROR_TEXT: Record<string, string> = {
  resolver_activation_not_found: "That resolver-activation authorization was not found.",
  resolver_activation_forbidden: "You do not have permission for that action.",
  resolver_activation_invalid_state: "That action is not allowed in the current state.",
  resolver_activation_substrate_ineligible: "The bound work item is not eligible.",
  resolver_activation_evidence_incomplete:
    "Approval requires every activation-evidence item to be verified first.",
  resolver_activation_evidence_invalid: "The evidence metadata was rejected.",
  resolver_activation_lifecycle_conflict: "The authorization changed concurrently; reload and retry.",
  resolver_activation_internal_failure: "The request could not be completed.",
  invalid_resolver_activation_input: "The submitted values were rejected.",
};

export const GENERIC_API_ERROR_TEXT = "The request could not be completed.";

export function apiErrorText(code: string | null | undefined): string {
  if (!code) return GENERIC_API_ERROR_TEXT;
  return API_ERROR_TEXT[code] ?? GENERIC_API_ERROR_TEXT;
}

export const STATUS_LABELS: Record<string, string> = {
  draft: "Draft — gathering evidence",
  approved: "Approved — sealed (not active)",
  revoked: "Revoked",
  expired: "Expired",
};

export function statusLabel(status: string): string {
  return STATUS_LABELS[status] ?? status;
}

// An authorization is ALWAYS sealed from the UI's perspective — even an approved one never becomes
// an active resolver here (worker-side activation + staging trust evidence are required elsewhere).
export function isSealed(authorization: ResolverActivation): boolean {
  return Boolean(authorization);
}

export function evidenceSummary(a: ResolverActivation): { verified: number; total: number } {
  const items = a.evidence ?? [];
  return { verified: items.filter((e) => e.status === "verified").length, total: items.length };
}
