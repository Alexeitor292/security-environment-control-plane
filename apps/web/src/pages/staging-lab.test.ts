import { describe, expect, it } from "vitest";

import type { EligibleSubstrate, StagingLab } from "../api/types";
import {
  BOOTSTRAP_PROFILES,
  LIFECYCLE_STEPS,
  QUEUED_NOTICE,
  RESOURCE_CLASSES,
  ROLLBACK_POLICIES,
  SAFETY_CONSTRAINTS,
  SIMULATION_ONLY_LABEL,
  canApprove,
  canCreate,
  canPlan,
  canQueueSimulation,
  canQueueTeardown,
  canSubmit,
  emptyDraft,
  isQueuedOrRunning,
  lifecycleIndex,
  observedResources,
  planHashPrefix,
  planResourceKinds,
  statusLabel,
  substrateOptions,
  validateDraft,
} from "./staging-lab";

const SOURCE = [
  emptyDraft.toString(),
  validateDraft.toString(),
  substrateOptions.toString(),
  planResourceKinds.toString(),
  observedResources.toString(),
  JSON.stringify(RESOURCE_CLASSES),
  JSON.stringify(BOOTSTRAP_PROFILES),
  JSON.stringify(ROLLBACK_POLICIES),
  JSON.stringify(SAFETY_CONSTRAINTS),
  JSON.stringify(LIFECYCLE_STEPS),
  SIMULATION_ONLY_LABEL,
  QUEUED_NOTICE,
].join("\n");

function lab(over: Partial<StagingLab> = {}): StagingLab {
  return {
    id: "lab-1",
    organization_id: "org-1",
    execution_target_id: "t-1",
    display_name: "staging-lab-alpha",
    ownership_label: "secp-lab-abc123",
    purpose: "disposable_readonly_staging",
    profile: "nested_proxmox",
    network_intent: "host_only_no_uplink",
    resource_class: "small_lab",
    rollback_policy: "revert_to_known_clean_checkpoint",
    bootstrap_artifact_profile: "nested_proxmox_offline_base",
    status: "draft",
    revision: 0,
    plan_version: 0,
    plan_hash: "",
    desired_state: null,
    simulated_observed_state: null,
    approved_plan_hash: "",
    approved_plan_version: 0,
    approved_at: null,
    decision_code: "pending",
    created_at: "2026-07-03T00:00:00Z",
    ...over,
  };
}

describe("Staging lab UI logic", () => {
  it("labels every execution control as simulation-only and marks queued work", () => {
    expect(SIMULATION_ONLY_LABEL).toContain("Simulation only");
    expect(SIMULATION_ONLY_LABEL).toContain("no infrastructure will be created");
    expect(QUEUED_NOTICE).toContain("queued");
  });

  it("states the self-contained control-plane and single-target safety constraints", () => {
    const joined = SAFETY_CONSTRAINTS.join(" ").toLowerCase();
    expect(joined).toContain("staging api + database + worker");
    expect(joined).toContain("no production control-plane");
    expect(joined).toContain("one disposable nested proxmox target");
    expect(joined).toContain("not a live-read authorization");
  });

  it("validates a good draft and rejects unsafe logical names", () => {
    const good = {
      executionTargetId: "t-1",
      logicalName: "alpha-01",
      resourceClass: "small_lab" as const,
      bootstrapArtifactProfile: "nested_proxmox_offline_base" as const,
      rollbackPolicy: "revert_to_known_clean_checkpoint" as const,
    };
    expect(validateDraft(good).ok).toBe(true);
    expect(validateDraft({ ...good, logicalName: "https://x/y" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "10.0.0.1" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "pve:8006" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "Has Space" }).ok).toBe(false);
    expect(validateDraft({ ...good, executionTargetId: "" }).ok).toBe(false);
    // Optional name may be blank.
    expect(validateDraft({ ...good, logicalName: "" }).ok).toBe(true);
  });

  it("offers substrates by server alias only (never raw target text)", () => {
    const substrates: EligibleSubstrate[] = [
      { id: "a", alias: "substrate-aaaa111111" },
      { id: "b", alias: "substrate-bbbb222222" },
    ];
    expect(substrateOptions(substrates)).toEqual([
      { id: "a", label: "substrate-aaaa111111" },
      { id: "b", label: "substrate-bbbb222222" },
    ]);
  });

  it("gates lifecycle actions by status (queue-only for simulation/teardown)", () => {
    expect(canPlan(lab({ status: "draft" }))).toBe(true);
    expect(canSubmit(lab({ status: "planned" }))).toBe(true);
    expect(canApprove(lab({ status: "awaiting_approval" }))).toBe(true);
    expect(canQueueSimulation(lab({ status: "approved" }))).toBe(true);
    expect(canQueueSimulation(lab({ status: "simulated_ready" }))).toBe(true);
    expect(canQueueTeardown(lab({ status: "simulated_ready" }))).toBe(true);
    expect(canCreate(false, { ...emptyDraft(), executionTargetId: "" })).toBe(false);
  });

  it("treats queued/running states as not-yet-ready", () => {
    for (const s of ["simulation_queued", "simulating", "teardown_queued", "tearing_down"] as const) {
      expect(isQueuedOrRunning(lab({ status: s }).status)).toBe(true);
    }
    expect(isQueuedOrRunning("simulated_ready")).toBe(false);
  });

  it("does NOT present observations until the worker records completion", () => {
    // Queued, even if a stray observed-state blob exists, must show nothing.
    const queued = lab({
      status: "simulation_queued",
      simulated_observed_state: { resources: [{ kind: "x", owner: "y", observed_phase: "z" }] },
    });
    expect(observedResources(queued)).toEqual([]);
    // Simulating: still nothing.
    expect(observedResources(lab({ status: "simulating" }))).toEqual([]);
    // Only once simulated_ready does the worker-recorded observation appear.
    const ready = lab({
      status: "simulated_ready",
      simulated_observed_state: {
        resources: [
          { kind: "isolated_target_facing_network", owner: "secp-lab-abc123", observed_phase: "simulated_provisioned" },
        ],
      },
    });
    expect(observedResources(ready)[0].phase).toBe("simulated_provisioned");
  });

  it("summarizes plan for display and tracks lifecycle order", () => {
    const planned = lab({
      status: "planned",
      plan_hash: "sha256:abcdef0123456789",
      desired_state: { resources: [{ kind: "disposable_nested_proxmox_target" }] },
    });
    expect(planHashPrefix(planned.plan_hash)).toBe("abcdef012345");
    expect(planResourceKinds(planned)).toContain("disposable_nested_proxmox_target");
    expect(statusLabel("simulation_queued")).toContain("queued");
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
