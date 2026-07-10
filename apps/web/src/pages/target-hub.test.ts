import type {
  Onboarding,
  PreflightAuthorization,
  ResolverActivation,
  TargetEvidence,
} from "../api/types";
import {
  DEFAULT_PROVISIONING_BOUNDARY,
  buildScopePolicyFromBoundary,
} from "./provider-targets";
import {
  COLLECTOR_GATE_STATEMENT,
  MILESTONE_NOTICE,
  SECRET_REF_CAPTION,
  UNAVAILABLE_CELL,
  boundarySummaryFromScope,
  buildAccessChain,
  evidenceCellView,
  liveAccessCellView,
} from "./target-hub";

const NOW = new Date("2026-07-09T12:00:00Z");

const auth = (
  status: string,
  expiry: string,
  created = "2026-07-09T10:00:00Z",
  version = 2,
): PreflightAuthorization =>
  ({
    id: `a-${status}-${created}`,
    status,
    authorization_expiry: expiry,
    created_at: created,
    authorization_version: version,
  }) as PreflightAuthorization;

const onboarding = (status: string): Onboarding =>
  ({
    id: `o-${status}`,
    status,
    boundary_hash: "5f8823bc11d0aabb",
    created_at: "2026-07-01T10:00:00Z",
  }) as Onboarding;

const evidence = (
  status: string,
  collected: string,
  source = "simulated",
): TargetEvidence =>
  ({
    id: `e-${collected}`,
    status,
    collected_at: collected,
    evidence_source: source,
  }) as TargetEvidence;

describe("boundarySummaryFromScope", () => {
  it("summarizes the real scope-policy shape produced by registration", () => {
    const built = buildScopePolicyFromBoundary(DEFAULT_PROVISIONING_BOUNDARY);
    expect(built.ok).toBe(true);
    const summary = boundarySummaryFromScope(built.value!.scopePolicy);
    expect(summary).not.toBeNull();
    expect(summary!.counts).toBe("1 node · 1 segment");
    expect(summary!.detail).toBe("10.60.0.0/16 · VMID 9000–9100");
    const keys = summary!.rows.map((r) => r.key);
    expect(keys).toContain("External connectivity");
    expect(
      summary!.rows.find((r) => r.key === "External connectivity")!.value,
    ).toContain("deny (fixed)");
    expect(summary!.rows.find((r) => r.key === "Quotas")!.value).toBe(
      "4 teams · 20 VMs · 10 CT · 64 vCPU · 131072 MB · 2048 GB",
    );
  });

  it("returns null for absent or malformed scope policies", () => {
    expect(boundarySummaryFromScope(null)).toBeNull();
    expect(boundarySummaryFromScope({})).toBeNull();
    expect(boundarySummaryFromScope({ provisioning: "bogus" })).toBeNull();
  });
});

describe("inventory cells", () => {
  it("renders unavailable sources as an explicit dash", () => {
    expect(evidenceCellView(null)).toEqual(UNAVAILABLE_CELL);
    expect(liveAccessCellView(null, NOW)).toEqual(UNAVAILABLE_CELL);
  });

  it("shows the newest evidence verdict with source and date", () => {
    const view = evidenceCellView([
      evidence("fail", "2026-07-01T10:00:00Z"),
      evidence("pass", "2026-07-03T09:51:00Z"),
    ]);
    expect(view).toEqual({
      label: "pass",
      tone: "ok",
      meta: "simulated · 2026-07-03",
    });
    expect(evidenceCellView([]).label).toBe("none recorded");
  });

  it("claims Authorized only for an approved, unexpired authorization", () => {
    const active = liveAccessCellView(
      [auth("approved", "2026-07-09T12:26:00Z")],
      NOW,
    );
    expect(active.label).toBe("Authorized");
    expect(active.meta).toBe("GET-only · resolver sealed");
    const expired = liveAccessCellView(
      [auth("approved", "2026-07-09T11:00:00Z")],
      NOW,
    );
    expect(expired.label).toBe("Sealed");
    expect(liveAccessCellView([], NOW).label).toBe("Sealed");
  });
});

describe("buildAccessChain", () => {
  it("derives link states from real records without overclaiming", () => {
    const links = buildAccessChain({
      onboardings: [onboarding("active")],
      authorizations: [auth("approved", "2026-07-09T12:26:00Z")],
      resolverActivations: [],
      now: NOW,
    });
    expect(links.map((l) => l.id)).toEqual([
      "boundary",
      "authorization",
      "resolver",
      "collector",
    ]);
    expect(links[0].state).toBe("complete");
    expect(links[0].status).toContain("boundary 5f8823bc");
    expect(links[1].state).toBe("active");
    expect(links[1].status).toBe("v2 · approved · expires in 26m");
    // No activation record: the sealed shipped default, stated as contract.
    expect(links[2].state).toBe("sealed");
    expect(links[2].status).toContain("sealed shipped default");
    expect(links[3].state).toBe("sealed");
    expect(links[3].body).toBe(COLLECTOR_GATE_STATEMENT);
  });

  it("an approved-but-expired authorization never renders as active", () => {
    const links = buildAccessChain({
      onboardings: [],
      authorizations: [auth("approved", "2026-07-09T11:59:00Z")],
      resolverActivations: null,
      now: NOW,
    });
    expect(links[0].status).toBe("not established");
    expect(links[1].state).toBe("pending");
    expect(links[1].status).toBe("approved · expired");
    expect(links[2].status).toContain("unavailable");
  });

  it("an approved resolver activation still renders sealed", () => {
    const activation = {
      id: "ra1",
      status: "approved",
      created_at: "2026-07-09T09:00:00Z",
      evidence: [
        { kind: "x", status: "verified", proof_id: "p", issuer: "i", verified_at: null },
      ],
    } as unknown as ResolverActivation;
    const links = buildAccessChain({
      onboardings: [onboarding("approved")],
      authorizations: [],
      resolverActivations: [activation],
      now: NOW,
    });
    expect(links[0].state).toBe("active");
    expect(links[0].status).toContain("not yet activated");
    expect(links[2].state).toBe("sealed");
    expect(links[2].status).toContain("Approved — sealed (not active)");
    expect(links[2].status).toContain("evidence 1/1");
  });

  it("keeps safety copy free of endpoints and secrets", () => {
    for (const text of [MILESTONE_NOTICE, SECRET_REF_CAPTION, COLLECTOR_GATE_STATEMENT]) {
      expect(text).not.toMatch(/:\/\//);
      expect(text).not.toMatch(/:\d{4,5}\b/);
      expect(text.toLowerCase()).not.toContain("password");
    }
  });
});
