import { describe, expect, it } from "vitest";

import type { ResolverActivation } from "../api/types";
import {
  API_ERROR_TEXT,
  GENERIC_API_ERROR_TEXT,
  RESOLVER_ACTIVATION_SCOPE_NOTICE,
  RESOLVER_ACTIVATION_SEALED_NOTICE,
  apiErrorText,
  evidenceSummary,
  isSealed,
  statusLabel,
} from "./resolver-activation";

function auth(over: Partial<ResolverActivation> = {}): ResolverActivation {
  return {
    id: "a1",
    organization_id: "o1",
    execution_target_id: "t1",
    onboarding_id: "ob1",
    live_read_authorization_id: "lr1",
    live_read_authorization_version: 1,
    preflight_id: "pf1",
    operation_fingerprint: "sha256:ab",
    resolver_adapter_contract_version: "secp-b2-4/openbao-worker-resolver/v1",
    purpose: "readonly_staging_preflight",
    authorization_expiry: "2999-01-01T00:00:00Z",
    evidence_fingerprint: "sha256:cd",
    status: "approved",
    authorization_version: 1,
    revision: 1,
    approved_at: "2026-07-04T00:00:00Z",
    revoked_at: null,
    created_at: "2026-07-04T00:00:00Z",
    evidence: [
      { kind: "isolated_staging_identity", status: "verified", proof_id: "TKT-1", issuer: "rev", verified_at: null },
      { kind: "worker_only_network_path", status: "pending", proof_id: "TKT-2", issuer: "rev", verified_at: null },
    ],
    ...over,
  };
}

describe("Resolver activation UI logic", () => {
  it("states that an approved authorization is sealed and connects no backend", () => {
    const notice = RESOLVER_ACTIVATION_SEALED_NOTICE.toLowerCase();
    expect(notice).toContain("authorization exists");
    expect(notice).toContain("resolver activation remains sealed");
    expect(notice).toContain("worker-side activation");
    expect(notice).toContain("connects no backend");
    expect(RESOLVER_ACTIVATION_SCOPE_NOTICE.toLowerCase()).toContain(
      "does not grant infrastructure execution",
    );
  });

  it("treats an approved authorization as sealed (never active)", () => {
    expect(isSealed(auth({ status: "approved" }))).toBe(true);
  });

  it("maps closed codes to fixed text and unknown/null to the generic fallback", () => {
    for (const code of Object.keys(API_ERROR_TEXT)) {
      expect(apiErrorText(code).length).toBeGreaterThan(0);
    }
    expect(apiErrorText("resolver_activation_forbidden")).toBe(
      API_ERROR_TEXT.resolver_activation_forbidden,
    );
    expect(apiErrorText("some_unknown_code")).toBe(GENERIC_API_ERROR_TEXT);
    expect(apiErrorText(null)).toBe(GENERIC_API_ERROR_TEXT);
    // Error text is fixed and never contains raw backend/reference detail.
    const allText = Object.values(API_ERROR_TEXT).join(" ").toLowerCase();
    for (const needle of ["://", "vault:", "env:", "token", "secret", "endpoint", "traceback"]) {
      expect(allText.includes(needle)).toBe(false);
    }
  });

  it("summarizes evidence and labels states without exposing sensitive values", () => {
    expect(evidenceSummary(auth())).toEqual({ verified: 1, total: 2 });
    expect(statusLabel("approved").toLowerCase()).toContain("sealed");
    const surface = [
      RESOLVER_ACTIVATION_SEALED_NOTICE,
      RESOLVER_ACTIVATION_SCOPE_NOTICE,
      Object.values(API_ERROR_TEXT).join(" "),
    ]
      .join(" ")
      .toLowerCase();
    for (const needle of ["http://", "https://", "vault:", "env:", "token=", "secret="]) {
      expect(surface.includes(needle)).toBe(false);
    }
  });
});
