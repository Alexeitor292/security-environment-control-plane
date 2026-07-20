import { describe, expect, it } from "vitest";

import type { DiscoveryCandidatePlan, DiscoveryEnrollment, DiscoveryEvidence } from "../api/types";
import {
  READ_ONLY_LABEL,
  RESOURCE_PROFILES,
  SAFETY_CONSTRAINTS,
  SEALED_APPLY_MESSAGE,
  canApprove,
  canRequest,
  canRerun,
  emptyDraft,
  evidenceSummary,
  isInFlight,
  planHashPrefix,
  planResourceKinds,
  statusLabel,
  validateDraft,
} from "./target-discovery";

const CONFIG_SURFACE = [
  emptyDraft.toString(),
  validateDraft.toString(),
  JSON.stringify(RESOURCE_PROFILES),
  READ_ONLY_LABEL,
  SEALED_APPLY_MESSAGE,
].join("\n");

function enr(over: Partial<DiscoveryEnrollment> = {}): DiscoveryEnrollment {
  return {
    id: "e-1",
    organization_id: "o-1",
    execution_target_id: "t-1",
    display_name: "target-discovery-alpha",
    ownership_label: "secp-discover-abc123def456",
    resource_profile: "small_lab",
    status: "plan_ready",
    decision_code: "pending",
    enrollment_version: 1,
    revision: 3,
    active_plan_hash: "sha256:abcdef0123456789",
    approved_plan_hash: "",
    approved_at: null,
    failure_code: null,
    created_at: "2026-07-06T00:00:00Z",
    ...over,
  };
}

function plan(): DiscoveryCandidatePlan {
  return {
    plan_version: 1,
    plan_hash: "sha256:abcdef0123456789",
    ownership_tag: "secp-owned:0011",
    resource_profile: "small_lab",
    node: "pve-a",
    storage: "local-lvm",
    capacity_snapshot_hash: "sha256:cc",
    evidence_hash: "sha256:ee",
    enrollment_version: 1,
    expires_at: "2026-07-06T12:00:00Z",
    executable: false,
    status: "draft",
    resources: [
      { kind: "isolated_bridge", resource_ref: "secp00-isolated_bridge-0", ownership_marker: "m" },
      { kind: "control_plane_vm", resource_ref: "secp00-control_plane_vm-0", ownership_marker: "m" },
    ],
  };
}

describe("Target discovery UI logic", () => {
  it("labels the surface read-only and states the sealed-apply notice", () => {
    expect(READ_ONLY_LABEL.toLowerCase()).toContain("read-only");
    expect(READ_ONLY_LABEL.toLowerCase()).toContain("contacts no host");
    expect(SEALED_APPLY_MESSAGE.toLowerCase()).toContain("live deployment remains sealed");
  });

  it("states the no-mutation + no-secret + apply-sealed safety constraints", () => {
    const joined = SAFETY_CONSTRAINTS.join(" ").toLowerCase();
    expect(joined).toContain("strictly read-only");
    expect(joined).toContain("cannot create, modify, delete");
    expect(joined).toContain("never ssh host");
    expect(joined).toContain("approval binds the whole plan hash");
    expect(joined).toContain("live deployment apply of the plan remains sealed");
  });

  it("validates a good draft and rejects unsafe logical names", () => {
    const good = { executionTargetId: "t-1", logicalName: "alpha-01", resourceProfile: "small_lab" as const };
    expect(validateDraft(good).ok).toBe(true);
    expect(validateDraft({ ...good, logicalName: "https://x" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "10.0.0.1" }).ok).toBe(false);
    expect(validateDraft({ ...good, logicalName: "pve:8006" }).ok).toBe(false);
    expect(validateDraft({ ...good, executionTargetId: "" }).ok).toBe(false);
    expect(canRequest(false, { ...emptyDraft(), executionTargetId: "" })).toBe(false);
  });

  it("gates approve/rerun and tracks in-flight status", () => {
    expect(canApprove(enr({ status: "plan_ready" }))).toBe(true);
    expect(canApprove(enr({ status: "requested" }))).toBe(false);
    expect(canRerun(enr({ status: "failed" }))).toBe(true);
    expect(isInFlight("discovering")).toBe(true);
    expect(isInFlight("plan_ready")).toBe(false);
    expect(statusLabel("approved")).toContain("apply still sealed");
  });

  it("summarizes the candidate plan + evidence with safe values only", () => {
    expect(planHashPrefix(plan().plan_hash)).toBe("abcdef012345");
    expect(planResourceKinds(plan())).toContain("isolated_bridge");
    const ev: DiscoveryEvidence = {
      eligibility: "eligible",
      reason_code: null,
      version_major: 8,
      version_minor: 1,
      is_clustered: false,
      node: "pve-a",
      node_count: 1,
      cpu_total: 16,
      mem_total_mb: 65536,
      mem_free_mb: 32768,
      nested_available: true,
      selected_storage: "local-lvm",
      storage_count: 1,
      candidate_vmids: [9000, 9001],
      evidence_hash: "sha256:ee",
      bundle_available: false,
      contact_state: "sealed",
      created_at: "2026-07-06T00:00:00Z",
    };
    const summary = evidenceSummary(ev).join(" ");
    expect(summary).toContain("eligible");
    expect(summary).toContain("pve-a");
    expect(summary).toContain("9000");
  });

  it("exposes no SSH/endpoint/secret material in its config surface", () => {
    const forbidden = [
      "http://",
      "https://",
      "://",
      "8006",
      "token",
      "secret",
      "password",
      "known_hosts",
      "fingerprint",
      "private_key",
      "pveapitoken",
    ];
    const haystack = CONFIG_SURFACE.toLowerCase();
    for (const needle of forbidden) {
      expect(haystack.includes(needle)).toBe(false);
    }
  });
});
