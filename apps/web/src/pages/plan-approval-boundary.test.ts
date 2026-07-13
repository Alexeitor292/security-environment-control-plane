import { describe, expect, it } from "vitest";

import VIEW from "./environments-view.ts?raw";
import PAGE from "./PlanApproval.tsx?raw";

// Static architecture/security boundary tests for the plan review surface (ADR-016 PR E).
// The plan review is control-plane read + plan-lifecycle only: it never imports
// worker/provider/transport/infra code, never deploys or dispatches, and reads the version
// origin/provenance SOLELY from plan.environment_version_binding — never from plan.summary,
// the version spec, a workspace, a URL, or a topology-authoring row.

const FORBIDDEN_IMPORT =
  /from\s+["'][^"']*(worker|provider|transport|opentofu|terraform|socket|subprocess|secret-resolver)[^"']*["']/i;

describe("plan review import boundary", () => {
  it("imports no worker/provider/transport/infra module", () => {
    expect(FORBIDDEN_IMPORT.test(PAGE)).toBe(false);
    expect(FORBIDDEN_IMPORT.test(VIEW)).toBe(false);
  });

  it("calls only read + plan-lifecycle APIs — never deploy/dispatch/destroy", () => {
    const forbiddenCalls = [
      "deployExercise",
      "destroyExercise",
      "resetInstance",
      "createStagingDeployment",
      "deployStagingDeployment",
      "requestTargetDiscovery",
      "publishEnvironmentVersion",
      "dispatch",
    ];
    for (const call of forbiddenCalls) {
      expect(PAGE.includes(`api.${call}`)).toBe(false);
    }
    // the ONLY mutations are the plan-lifecycle transitions
    for (const allowed of ["api.submitPlan", "api.approvePlan", "api.rejectPlan"]) {
      expect(PAGE).toContain(allowed);
    }
  });
});

describe("plan review provenance source boundary", () => {
  it("reads origin/provenance ONLY from the plan binding, never from summary/spec/topology rows", () => {
    // The published/legacy decision + provenance flow through planBindingView(binding).
    expect(PAGE).toContain("planBindingView");
    expect(PAGE).toContain("environment_version_binding");
    // Never reconstruct provenance from other plan fields or from topology-authoring reads.
    expect(PAGE).not.toContain("summary.publication");
    expect(PAGE).not.toContain("getTopologyDocument");
    expect(PAGE).not.toContain("getTopologyRevision");
    expect(PAGE).not.toContain("getTopologyValidation");
  });

  it("planBindingView derives isPublished solely from publication_provenance presence", () => {
    // No apiVersion-string sniffing to decide published vs legacy — provenance presence is the
    // single source of truth, so a legacy version can never masquerade as published.
    const block = VIEW.slice(VIEW.indexOf("export function planBindingView"));
    const body = block.slice(0, block.indexOf("\n}"));
    expect(body).toContain("binding.publication_provenance");
    expect(body).not.toContain("api_version ===");
    expect(body).not.toContain("plan.summary");
  });
});
