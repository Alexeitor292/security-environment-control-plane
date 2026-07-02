import { describe, expect, it } from "vitest";

import {
  DEFAULT_ISOLATION_PROFILE,
  DEFAULT_NETWORK_APPROACH,
  ISOLATION_PROFILES,
  LIFECYCLE_STEPS,
  REVIEW_STATEMENT,
  buildBoundary,
  draftFromScope,
  emptyDraft,
  isTerminalRejected,
  isolationProfileAvailable,
  lifecycleIndex,
  parseList,
  type BoundaryDraft,
} from "./onboarding-wizard";

function validDraft(overrides: Partial<BoundaryDraft> = {}): BoundaryDraft {
  return {
    ...emptyDraft(),
    nodes: "pve-node-1, pve-node-2",
    storage: "local-lvm",
    networkSegments: "vmbr0",
    cidrs: "10.60.0.0/16",
    vmidStart: "9000",
    vmidEnd: "9100",
    maxTeams: "4",
    maxVms: "20",
    maxContainers: "10",
    maxVcpu: "64",
    maxMemoryMb: "131072",
    maxDiskGb: "2048",
    credentialScope: "least_privilege",
    ...overrides,
  };
}

describe("defaults", () => {
  it("defaults the isolation profile to fully_segregated", () => {
    expect(DEFAULT_ISOLATION_PROFILE).toBe("fully_segregated");
    expect(emptyDraft().isolationProfile).toBe("fully_segregated");
  });

  it("defaults the network approach to using an approved existing segment", () => {
    expect(DEFAULT_NETWORK_APPROACH).toBe("use_approved_existing_segment");
  });
});

describe("isolation profiles", () => {
  it("enables only fully_segregated and marks it recommended", () => {
    const available = ISOLATION_PROFILES.filter((p) => p.available);
    expect(available).toHaveLength(1);
    expect(available[0].value).toBe("fully_segregated");
    expect(available[0].recommended).toBe(true);
  });

  it("marks the roadmap profiles as unavailable (planned, not available yet)", () => {
    for (const value of [
      "internet_egress_only",
      "controlled_service_access",
      "advanced_custom_policy",
    ] as const) {
      expect(isolationProfileAvailable(value)).toBe(false);
    }
    expect(isolationProfileAvailable("fully_segregated")).toBe(true);
  });
});

describe("review statement", () => {
  it("states SECP creates resources and manual pre-creation is not required", () => {
    expect(REVIEW_STATEMENT).toContain("SECP will automatically allocate IDs and addresses");
    expect(REVIEW_STATEMENT).toContain(
      "Manual per-scenario VM, container, network, disk, or address creation is not required",
    );
  });
});

describe("lifecycle rendering", () => {
  it("orders the lifecycle steps draft -> preflight -> review -> approval -> active", () => {
    expect(LIFECYCLE_STEPS.map((s) => s.status)).toEqual([
      "draft",
      "preflight_pending",
      "ready_for_review",
      "approved",
      "active",
    ]);
    expect(LIFECYCLE_STEPS[1].label).toBe("Simulated preflight");
  });

  it("maps a status to its ordered index and flags terminal states", () => {
    expect(lifecycleIndex("draft")).toBe(0);
    expect(lifecycleIndex("active")).toBe(4);
    expect(lifecycleIndex("rejected")).toBe(-1);
    expect(isTerminalRejected("retired")).toBe(true);
    expect(isTerminalRejected("active")).toBe(false);
  });
});

describe("parseList", () => {
  it("splits on commas/whitespace and drops empties", () => {
    expect(parseList("a, b  c,,\nd")).toEqual(["a", "b", "c", "d"]);
    expect(parseList("   ")).toEqual([]);
  });
});

describe("draftFromScope", () => {
  it("prefills allowlists and quotas from a provisioning scope policy", () => {
    const draft = draftFromScope({
      provisioning: {
        allowed_nodes: ["pve-node-1"],
        allowed_storage: ["local-lvm"],
        allowed_bridges: ["vmbr0"],
        allowed_cidr_reservations: ["10.60.0.0/16"],
        vmid_range: { start: 9000, end: 9100 },
        max_vms: 20,
      },
    });
    expect(draft.nodes).toBe("pve-node-1");
    expect(draft.networkSegments).toBe("vmbr0");
    expect(draft.vmidStart).toBe("9000");
    expect(draft.maxVms).toBe("20");
    expect(draft.isolationProfile).toBe("fully_segregated");
  });
});

describe("buildBoundary", () => {
  it("builds a deny-external, fully-segregated boundary from a valid draft", () => {
    const res = buildBoundary(validDraft(), ["vmbr0"]);
    expect(res.ok).toBe(true);
    expect(res.boundary?.external_connectivity.policy).toBe("deny");
    expect(res.boundary?.network_segments).toEqual(["vmbr0"]);
    expect(res.boundary?.isolation_profile).toBe("fully_segregated");
    expect(res.boundary?.network_approach).toBe("use_approved_existing_segment");
    expect(res.boundary?.vmid_range).toEqual({ start: 9000, end: 9100 });
  });

  it("reports missing allowlists and an inverted VM-ID range", () => {
    const res = buildBoundary(
      validDraft({ nodes: "", vmidStart: "9100", vmidEnd: "9000" }),
      ["vmbr0"],
    );
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes("allowed node"))).toBe(true);
    expect(res.errors.some((e) => e.includes("end must be greater"))).toBe(true);
  });

  it("rejects a roadmap isolation profile server-side-consistently", () => {
    const res = buildBoundary(
      validDraft({ isolationProfile: "internet_egress_only" }),
      ["vmbr0"],
    );
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes("not available yet"))).toBe(true);
  });

  it("refuses a network segment outside the target's approved segments", () => {
    const res = buildBoundary(
      validDraft({ networkSegments: "vmbr0, vmbr9" }),
      ["vmbr0"],
    );
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes("vmbr9"))).toBe(true);
  });

  it("still constrains a SECP-managed segment to the approved set", () => {
    const res = buildBoundary(
      validDraft({ networkApproach: "secp_managed_dedicated_segment", networkSegments: "vmbr9" }),
      ["vmbr0"],
    );
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes("vmbr9"))).toBe(true);
  });

  it("rejects an invalid CIDR", () => {
    const res = buildBoundary(validDraft({ cidrs: "not-a-cidr" }), ["vmbr0"]);
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes("Invalid CIDR"))).toBe(true);
  });
});
