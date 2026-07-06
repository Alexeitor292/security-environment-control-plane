import { describe, expect, it } from "vitest";

import type { StagingDeployment, StagingDeploymentPlan } from "../api/types";
import {
  CONTROL_PLANE_ONLY_LABEL,
  DEPLOY_ENQUEUED_NOTICE,
  RESOURCE_PROFILES,
  SAFETY_CONSTRAINTS,
  bootstrapAvailabilityLabel,
  canApprove,
  canCreate,
  canDeploy,
  canPlan,
  canSubmit,
  canTeardown,
  emptyDraft,
  isFailureState,
  isInFlight,
  lifecycleIndex,
  planHashPrefix,
  planResourceKinds,
  statusLabel,
  validateDraft,
} from "./staging-deployment";

// Only the caller-facing OPTION/CONFIG/INPUT surface — never the descriptive safety prose.
const CONFIG_SURFACE = [
  emptyDraft.toString(),
  validateDraft.toString(),
  planResourceKinds.toString(),
  JSON.stringify(RESOURCE_PROFILES),
  CONTROL_PLANE_ONLY_LABEL,
  DEPLOY_ENQUEUED_NOTICE,
].join("\n");

function dep(over: Partial<StagingDeployment> = {}): StagingDeployment {
  return {
    id: "dep-1",
    organization_id: "org-1",
    execution_target_id: "t-1",
    display_name: "staging-deploy-alpha",
    ownership_label: "secp-deploy-abc123def456",
    resource_profile: "small_lab",
    status: "draft",
    decision_code: "pending",
    revision: 0,
    plan_version: 0,
    plan_hash: "",
    approved_plan_hash: "",
    approved_at: null,
    failure_code: null,
    created_at: "2026-07-05T00:00:00Z",
    ...over,
  };
}

function plan(): StagingDeploymentPlan {
  return {
    plan_version: 1,
    plan_hash: "sha256:abcdef0123456789",
    ownership_tag: "secp-owned:0011223344556677",
    capacity_assessment_hash: "sha256:cd",
    artifact_manifest_id: "secp-b4/artifact-catalog/v1/small_lab",
    resources: [
      { kind: "isolated_bridge", count: 1, resource_ref: "secp00-bridge-0" },
      { kind: "control_plane_vm", count: 1, resource_ref: "secp00-cpvm-0" },
      { kind: "nested_target_vm", count: 1, resource_ref: "secp00-tgt-0" },
    ],
  };
}

describe("Staging deployment UI logic", () => {
  it("labels the surface as control-plane-only and describes enqueue semantics", () => {
    expect(CONTROL_PLANE_ONLY_LABEL).toContain("Control plane only");
    expect(CONTROL_PLANE_ONLY_LABEL).toContain("contacts no infrastructure");
    expect(DEPLOY_ENQUEUED_NOTICE).toContain("enqueued");
    expect(DEPLOY_ENQUEUED_NOTICE.toLowerCase()).toContain("worker");
  });

  it("states the app-creates-everything and owned-only rollback safety constraints", () => {
    const joined = SAFETY_CONSTRAINTS.join(" ").toLowerCase();
    expect(joined).toContain("the app creates every resource");
    expect(joined).toContain("no uplink");
    expect(joined).toContain("offline artifacts");
    expect(joined).toContain("exact plan hash");
    expect(joined).toContain("worker-local");
    expect(joined).toContain("only resources proven owned by this exact lab");
  });

  it("validates a good draft and rejects unsafe logical names", () => {
    const good = {
      executionTargetId: "t-1",
      logicalName: "alpha-01",
      resourceProfile: "small_lab" as const,
    };
    expect(validateDraft(good).ok).toBe(true);
    expect(validateDraft({ ...good, logicalName: "https://x/y" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "10.0.0.1" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "pve:8006" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "Has Space" }).ok).toBe(false);
    expect(validateDraft({ ...good, executionTargetId: "" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "" }).ok).toBe(true);
  });

  it("gates lifecycle actions by status", () => {
    expect(canPlan(dep({ status: "draft" }))).toBe(true);
    expect(canSubmit(dep({ status: "planned" }))).toBe(true);
    expect(canApprove(dep({ status: "awaiting_approval" }))).toBe(true);
    expect(canDeploy(dep({ status: "approved" }))).toBe(true);
    expect(canTeardown(dep({ status: "ready" }))).toBe(true);
    expect(canTeardown(dep({ status: "rolled_back" }))).toBe(true);
    // Deploy is gated strictly to 'approved' — never before.
    expect(canDeploy(dep({ status: "awaiting_approval" }))).toBe(false);
    expect(canCreate(false, { ...emptyDraft(), executionTargetId: "" })).toBe(false);
  });

  it("treats in-flight worker states as not-yet-ready", () => {
    for (const s of ["bootstrap_pending", "applying", "verifying", "rolling_back", "tearing_down"] as const) {
      expect(isInFlight(dep({ status: s }).status)).toBe(true);
    }
    expect(isInFlight("ready")).toBe(false);
    expect(isFailureState("rollback_required")).toBe(true);
    expect(isFailureState("ready")).toBe(false);
  });

  it("summarizes plan categories for display and tracks lifecycle order", () => {
    expect(planHashPrefix(plan().plan_hash)).toBe("abcdef012345");
    expect(planResourceKinds(plan())).toContain("isolated_bridge");
    expect(planResourceKinds(plan())).toContain("control_plane_vm");
    expect(planResourceKinds(null)).toEqual([]);
    expect(lifecycleIndex("ready")).toBeGreaterThan(lifecycleIndex("approved"));
    expect(statusLabel("bootstrap_pending")).toBe("Bootstrap pending");
    expect(statusLabel("rolled_back")).toBe("Rolled back");
  });

  it("renders bootstrap availability as a safe boolean, never a location", () => {
    const unavailable = bootstrapAvailabilityLabel({
      available: false,
      reason_code: "deployment_local_bootstrap_not_mounted",
    });
    expect(unavailable.toLowerCase()).toContain("not mounted");
    expect(unavailable).not.toContain("/"); // no filesystem path leaks
    expect(bootstrapAvailabilityLabel(null)).toBe("Unknown");
  });

  it("exposes no real infrastructure or secret fields in its option/config surface", () => {
    const forbidden = [
      "http://",
      "https://",
      "://",
      "8006",
      "vlan",
      "vmid",
      "token",
      "secret",
      "password",
      "pveapitoken",
      "begin openssh",
    ];
    const haystack = CONFIG_SURFACE.toLowerCase();
    for (const needle of forbidden) {
      expect(haystack.includes(needle)).toBe(false);
    }
  });
});
