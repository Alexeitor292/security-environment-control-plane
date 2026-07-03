import { describe, expect, it } from "vitest";

import type { ExecutionTarget, StagingLab } from "../api/types";
import {
  LIFECYCLE_STEPS,
  RESOURCE_CLASSES,
  ROLLBACK_POLICIES,
  SAFETY_CONSTRAINTS,
  SIMULATION_ONLY_LABEL,
  canApprove,
  canCreate,
  canPlan,
  canSimulate,
  canSubmit,
  canTeardown,
  emptyDraft,
  lifecycleIndex,
  observedResources,
  planHashPrefix,
  planResourceKinds,
  substrateOptions,
  teardownStatusLabel,
  validateDraft,
} from "./staging-lab";

const SOURCE = [
  emptyDraft.toString(),
  validateDraft.toString(),
  substrateOptions.toString(),
  planResourceKinds.toString(),
  observedResources.toString(),
  JSON.stringify(RESOURCE_CLASSES),
  JSON.stringify(ROLLBACK_POLICIES),
  JSON.stringify(SAFETY_CONSTRAINTS),
  JSON.stringify(LIFECYCLE_STEPS),
  SIMULATION_ONLY_LABEL,
].join("\n");

function lab(over: Partial<StagingLab> = {}): StagingLab {
  return {
    id: "lab-1",
    organization_id: "org-1",
    execution_target_id: "t-1",
    display_name: "Alpha",
    ownership_label: "secp-lab-alpha",
    purpose: "disposable_readonly_staging",
    profile: "nested_proxmox",
    network_intent: "host_only_no_uplink",
    resource_class: "small_lab",
    rollback_policy: "revert_to_known_clean_checkpoint",
    bootstrap_artifact_profile_id: "approved-offline-profile-a",
    status: "draft",
    plan_version: 0,
    plan_hash: "",
    desired_state: null,
    simulated_observed_state: null,
    approved_plan_hash: "",
    approved_plan_version: 0,
    approved_at: null,
    decision_reason: "",
    created_at: "2026-07-03T00:00:00Z",
    ...over,
  };
}

describe("Staging lab UI logic", () => {
  it("labels every execution control as simulation-only", () => {
    expect(SIMULATION_ONLY_LABEL).toContain("Simulation only");
    expect(SIMULATION_ONLY_LABEL).toContain("no infrastructure will be created");
  });

  it("states the self-contained control-plane and single-target safety constraints", () => {
    const joined = SAFETY_CONSTRAINTS.join(" ").toLowerCase();
    expect(joined).toContain("staging api + database + worker");
    expect(joined).toContain("no production control-plane");
    expect(joined).toContain("one disposable nested proxmox target");
    expect(joined).toContain("not a live-read authorization");
  });

  it("validates a good draft and rejects unsafe artifact ids", () => {
    const good = {
      executionTargetId: "t-1",
      displayName: "Alpha",
      ownershipLabel: "secp-lab-alpha",
      resourceClass: "small_lab" as const,
      rollbackPolicy: "revert_to_known_clean_checkpoint" as const,
      bootstrapArtifactProfileId: "approved-offline-profile-a",
    };
    expect(validateDraft(good).ok).toBe(true);
    expect(validateDraft({ ...good, bootstrapArtifactProfileId: "https://x/y.iso" }).ok).toBe(false);
    expect(validateDraft({ ...good, bootstrapArtifactProfileId: "path/to/iso" }).ok).toBe(false);
    expect(validateDraft({ ...good, ownershipLabel: "Bad Label!" }).ok).toBe(false);
    expect(validateDraft({ ...good, executionTargetId: "" }).ok).toBe(false);
  });

  it("only offers active substrate targets by display name", () => {
    const targets = [
      { id: "a", display_name: "Active One", status: "active" },
      { id: "b", display_name: "Disabled", status: "disabled" },
    ] as ExecutionTarget[];
    const options = substrateOptions(targets);
    expect(options).toEqual([{ id: "a", label: "Active One" }]);
  });

  it("gates lifecycle actions by status", () => {
    expect(canPlan(lab({ status: "draft" }))).toBe(true);
    expect(canSubmit(lab({ status: "planned" }))).toBe(true);
    expect(canApprove(lab({ status: "awaiting_approval" }))).toBe(true);
    expect(canSimulate(lab({ status: "approved" }))).toBe(true);
    expect(canSimulate(lab({ status: "simulated_ready" }))).toBe(true);
    expect(canTeardown(lab({ status: "simulated_ready" }))).toBe(true);
    expect(canCreate(false, { ...emptyDraft(), executionTargetId: "" })).toBe(false);
  });

  it("summarizes plan and observed resources for display", () => {
    const planned = lab({
      status: "planned",
      plan_hash: "sha256:abcdef0123456789",
      desired_state: { resources: [{ kind: "disposable_nested_proxmox_target" }] },
    });
    expect(planHashPrefix(planned.plan_hash)).toBe("abcdef012345");
    expect(planResourceKinds(planned)).toContain("disposable_nested_proxmox_target");

    const simulated = lab({
      status: "simulated_ready",
      simulated_observed_state: {
        resources: [
          { kind: "isolated_target_facing_network", owner: "secp-lab-alpha", observed_phase: "simulated_provisioned" },
        ],
      },
    });
    expect(observedResources(simulated)[0].phase).toBe("simulated_provisioned");
    expect(teardownStatusLabel("destroyed")).toContain("Torn down");
  });

  it("tracks lifecycle order", () => {
    expect(lifecycleIndex("draft")).toBe(0);
    expect(lifecycleIndex("simulated_ready")).toBeGreaterThan(lifecycleIndex("approved"));
  });

  it("exposes no real infrastructure or secret fields in its option/config surface", () => {
    const forbidden = ["http://", "https://", "://", "8006", "vlan", "vmid", "token", "secret", "password", "credential"];
    const haystack = SOURCE.toLowerCase();
    for (const needle of forbidden) {
      expect(haystack.includes(needle)).toBe(false);
    }
  });
});
