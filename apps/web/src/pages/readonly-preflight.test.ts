import { describe, expect, it } from "vitest";

import type { PreflightAuthorization, ReadonlyPreflight } from "../api/types";
import {
  API_ERROR_TEXT,
  AUTHORIZATION_SEPARATION_NOTICE,
  GENERIC_API_ERROR_TEXT,
  OUTCOME_LABELS,
  QUEUED_NOTICE,
  READONLY_ONLY_LABEL,
  READY_SCOPE_NOTICE,
  apiErrorText,
  authorizationIsApprovedAndCurrent,
  canQueuePreflight,
  isQueuedOrRunning,
  isReady,
  isTerminal,
  outcomeLabel,
  readinessFactRows,
  usableAuthorization,
} from "./readonly-preflight";

function auth(over: Partial<PreflightAuthorization> = {}): PreflightAuthorization {
  return {
    id: "a1",
    organization_id: "o1",
    execution_target_id: "t1",
    onboarding_id: "ob1",
    authorization_version: 1,
    status: "approved",
    authorization_expiry: "2999-01-01T00:00:00Z",
    created_at: "2026-07-04T00:00:00Z",
    approved_at: "2026-07-04T00:00:00Z",
    revoked_at: null,
    ...over,
  };
}

function pf(over: Partial<ReadonlyPreflight> = {}): ReadonlyPreflight {
  return {
    id: "p1",
    organization_id: "o1",
    execution_target_id: "t1",
    onboarding_id: "ob1",
    live_read_authorization_id: "a1",
    authorization_version: 1,
    status: "queued",
    revision: 0,
    outcome_code: null,
    readiness_facts: null,
    created_at: "2026-07-04T00:00:00Z",
    completed_at: null,
    ...over,
  };
}

describe("Read-only preflight UI logic", () => {
  it("labels controls read-only and states the authorization separation + ready scope", () => {
    expect(READONLY_ONLY_LABEL).toContain("Read-only");
    expect(READONLY_ONLY_LABEL.toLowerCase()).toContain("creates, alters, starts, or stops nothing");
    expect(AUTHORIZATION_SEPARATION_NOTICE.toLowerCase()).toContain("separate from staging-lab");
    expect(AUTHORIZATION_SEPARATION_NOTICE.toLowerCase()).toContain("never created automatically");
    expect(READY_SCOPE_NOTICE.toLowerCase()).toContain("does not claim the host is isolated");
    expect(QUEUED_NOTICE.toLowerCase()).toContain("worker");
  });

  it("maps every closed outcome to a human-safe label", () => {
    for (const code of Object.keys(OUTCOME_LABELS) as (keyof typeof OUTCOME_LABELS)[]) {
      expect(outcomeLabel(code).length).toBeGreaterThan(0);
    }
    expect(outcomeLabel(null)).toBe("Pending");
  });

  it("tracks lifecycle state", () => {
    expect(isQueuedOrRunning(pf({ status: "queued" }).status)).toBe(true);
    expect(isQueuedOrRunning(pf({ status: "running" }).status)).toBe(true);
    expect(isTerminal(pf({ status: "completed" }).status)).toBe(true);
    expect(isReady(pf({ outcome_code: "ready" }))).toBe(true);
    expect(isReady(pf({ outcome_code: "credential_unavailable" }))).toBe(false);
  });

  it("only surfaces an approved + unexpired authorization for queueing", () => {
    expect(authorizationIsApprovedAndCurrent(auth())).toBe(true);
    expect(authorizationIsApprovedAndCurrent(auth({ status: "draft" }))).toBe(false);
    expect(authorizationIsApprovedAndCurrent(auth({ status: "revoked" }))).toBe(false);
    expect(
      authorizationIsApprovedAndCurrent(auth({ authorization_expiry: "2000-01-01T00:00:00Z" })),
    ).toBe(false);
    expect(usableAuthorization([auth({ status: "draft" })])).toBeNull();
    expect(canQueuePreflight(usableAuthorization([auth()]))).toBe(true);
    expect(canQueuePreflight(usableAuthorization([]))).toBe(false);
  });

  it("shows readiness facts only for a ready outcome, and drops unknown (non-allowlisted) keys", () => {
    expect(readinessFactRows(pf({ status: "completed", outcome_code: "credential_unavailable" }))).toEqual(
      [],
    );
    const ready = pf({
      status: "completed",
      outcome_code: "ready",
      // A stray non-allowlisted key must be dropped client-side, matching the worker allowlist.
      readiness_facts: { api_reachable: true, node_count: 3, endpoint: 1 as unknown as number },
    });
    const rows = readinessFactRows(ready);
    expect(rows).toContainEqual({ key: "api_reachable", value: "yes" });
    expect(rows).toContainEqual({ key: "node_count", value: "3" });
    expect(rows.find((r) => r.key === "endpoint")).toBeUndefined();
  });

  it("maps closed error codes to fixed safe text and unknown codes to the generic fallback", () => {
    for (const code of Object.keys(API_ERROR_TEXT)) {
      expect(apiErrorText(code).length).toBeGreaterThan(0);
    }
    expect(apiErrorText("readonly_preflight_forbidden")).toBe(
      API_ERROR_TEXT.readonly_preflight_forbidden,
    );
    // Unknown code, null, and empty all fall back to the fixed generic text.
    expect(apiErrorText("some_unknown_backend_code")).toBe(GENERIC_API_ERROR_TEXT);
    expect(apiErrorText(null)).toBe(GENERIC_API_ERROR_TEXT);
    expect(apiErrorText("")).toBe(GENERIC_API_ERROR_TEXT);
    // Error text is fixed and never contains raw backend detail.
    const allText = Object.values(API_ERROR_TEXT).join(" ").toLowerCase();
    for (const needle of ["://", "traceback", "sqlalchemy", "secret", "env:"]) {
      expect(allText.includes(needle)).toBe(false);
    }
  });

  it("exposes no endpoint/secret tokens in its safe-label surface", () => {
    const surface = [
      READONLY_ONLY_LABEL,
      QUEUED_NOTICE,
      AUTHORIZATION_SEPARATION_NOTICE,
      READY_SCOPE_NOTICE,
      JSON.stringify(OUTCOME_LABELS),
    ]
      .join(" ")
      .toLowerCase();
    for (const needle of ["http://", "https://", "://", "8006", "vmbr", "token=", "secret="]) {
      expect(surface.includes(needle)).toBe(false);
    }
  });
});
