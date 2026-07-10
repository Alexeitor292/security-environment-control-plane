import {
  AUDIT_TONE,
  AUTHORIZATION_TONE,
  BOOTSTRAP_TONE,
  ELIGIBILITY_TONE,
  PLAN_DECISION_TONE,
  TARGET_TONE,
  DISCOVERY_TONE,
  EVIDENCE_TONE,
  LIFECYCLE_TONE,
  ONBOARDING_TONE,
  PLAN_TONE,
  PREFLIGHT_OUTCOME_TONE,
  PREFLIGHT_TONE,
  STAGING_DEPLOYMENT_TONE,
  STAGING_LAB_TONE,
  VERIFICATION_TONE,
  resolveStatusTone,
  statusDisplayLabel,
} from "./status-tone";

const ALL_MAPS = {
  LIFECYCLE_TONE,
  PLAN_TONE,
  ONBOARDING_TONE,
  STAGING_LAB_TONE,
  STAGING_DEPLOYMENT_TONE,
  DISCOVERY_TONE,
  BOOTSTRAP_TONE,
  PREFLIGHT_TONE,
  PREFLIGHT_OUTCOME_TONE,
  EVIDENCE_TONE,
  VERIFICATION_TONE,
  AUTHORIZATION_TONE,
  TARGET_TONE,
  AUDIT_TONE,
  ELIGIBILITY_TONE,
  PLAN_DECISION_TONE,
};

describe("status tone maps", () => {
  it("every mapped status resolves to a real tone, never 'unknown'", () => {
    for (const [name, map] of Object.entries(ALL_MAPS)) {
      for (const [state, tone] of Object.entries(map)) {
        expect(tone, `${name}.${state}`).not.toBe("unknown");
        expect(["ok", "warn", "danger", "accent", "pending"]).toContain(tone);
      }
    }
  });

  it("every union member resolves as known via domain lookup", () => {
    const domains = {
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
    } as const;
    for (const [domain, map] of Object.entries(domains)) {
      for (const state of Object.keys(map)) {
        const resolved = resolveStatusTone(
          state,
          domain as keyof typeof domains,
        );
        expect(resolved.known, `${domain}:${state}`).toBe(true);
      }
    }
  });

  it("preserves the legacy resolution order: lifecycle wins over plan without a domain", () => {
    // Pre-unification behavior: LIFECYCLE_TONE was checked before PLAN_TONE,
    // so a domain-less "approved" renders accent, not the plan map's ok.
    expect(resolveStatusTone("approved")).toEqual({ tone: "accent", known: true });
    expect(resolveStatusTone("approved", "plan")).toEqual({ tone: "ok", known: true });
    expect(resolveStatusTone("generated")).toEqual({ tone: "pending", known: true });
  });

  it("statuses that silently fell back to 'pending' before are now explicit", () => {
    expect(resolveStatusTone("simulated_ready", "staging-lab").tone).toBe("ok");
    expect(resolveStatusTone("bootstrap_pending", "staging-deployment").tone).toBe("warn");
    expect(resolveStatusTone("plan_ready", "discovery").tone).toBe("warn");
    expect(resolveStatusTone("bound", "bootstrap").tone).toBe("ok");
    expect(resolveStatusTone("credential_unavailable", "preflight-outcome").tone).toBe("warn");
    expect(resolveStatusTone("unverifiable", "evidence").tone).toBe("pending");
    expect(resolveStatusTone("passed", "verification").tone).toBe("ok");
    expect(resolveStatusTone("failed", "verification").tone).toBe("danger");
  });

  it("unknown statuses resolve to the distinct 'unknown' tone, not 'pending'", () => {
    expect(resolveStatusTone("no_such_status")).toEqual({
      tone: "unknown",
      known: false,
    });
    expect(resolveStatusTone("simulated_ready", "plan")).toEqual({
      tone: "unknown",
      known: false,
    });
    expect(resolveStatusTone("")).toEqual({ tone: "unknown", known: false });
  });

  it("covers the backend TargetStatus enum so routine target states never render as unknown", () => {
    expect(resolveStatusTone("active", "target").tone).toBe("ok");
    expect(resolveStatusTone("disabled", "target").tone).toBe("pending");
    expect(resolveStatusTone("discovery_failed", "target").tone).toBe("danger");
    // Domain-less resolution (today's ProviderTargets call site) also works.
    expect(resolveStatusTone("disabled").known).toBe(true);
    expect(resolveStatusTone("discovery_failed").tone).toBe("danger");
  });

  it("covers every backend audit outcome, including revoked and expired", () => {
    for (const outcome of ["denied", "refused", "failed", "revoked", "expired"]) {
      expect(resolveStatusTone(outcome, "audit").tone, outcome).toBe("danger");
    }
    expect(resolveStatusTone("success", "audit").tone).toBe("ok");
  });

  it("treats Object.prototype keys as unknown, never as a tone", () => {
    for (const state of ["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__"]) {
      expect(resolveStatusTone(state)).toEqual({ tone: "unknown", known: false });
      expect(resolveStatusTone(state, "lifecycle")).toEqual({
        tone: "unknown",
        known: false,
      });
    }
  });

  it("formats display labels by replacing underscores", () => {
    expect(statusDisplayLabel("awaiting_approval")).toBe("awaiting approval");
    expect(statusDisplayLabel("running")).toBe("running");
  });
});
