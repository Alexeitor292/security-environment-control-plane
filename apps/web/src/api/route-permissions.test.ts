// The permission table is read, not transcribed — and `null` never means "needs nothing".

import { describe, expect, it } from "vitest";

import { knownRoutes, requirementFor } from "./route-permissions";

describe("permissions come from the call graph", () => {
  it("knows the three answers no route path would suggest", () => {
    // Same pins as tests/test_route_permissions.py, asserted on the client side too: the artifact
    // is the seam between them, and a seam checked from only one end is checked once.
    expect(requirementFor("GET /api/v1/ranges")).toEqual({
      state: "requires",
      permissions: ["exercise_operate"],
    });
    expect(
      requirementFor("GET /api/v1/target-discovery/read-only-bootstrap/worker-nodes"),
    ).toEqual({ state: "requires", permissions: ["target_discovery_manage"] });
    expect(requirementFor("GET /api/v1/enrollment")).toEqual({
      state: "requires",
      permissions: ["enrollment_read"],
    });
  });

  it("distinguishes a VERIFIED open route from one it could not resolve", () => {
    // The pair that must not merge. Both were read by hand and found to enforce nothing beyond
    // authentication, so they are `open` — a positive claim. Everything unresolved stays
    // `unknown`, and a page must render those differently: `open` shows the control to everyone,
    // `unknown` is the state a BROKEN WALK produces for every route at once.
    expect(requirementFor("GET /api/v1/targets")).toEqual({ state: "open" });
    expect(requirementFor("GET /api/v1/plugins")).toEqual({ state: "open" });
  });

  it("treats a route it has never heard of as unknown, never as open", () => {
    expect(requirementFor("GET /api/v1/not-a-route")).toEqual({ state: "unknown" });
  });

  it("never reports `requires` with an empty permission list", () => {
    // A third way the two could collapse: `{state:"requires", permissions:[]}` renders as a
    // requirement nobody can hold, which is indistinguishable from a locked surface.
    for (const route of knownRoutes()) {
      const requirement = requirementFor(route);
      if (requirement.state === "requires") expect(requirement.permissions.length).toBeGreaterThan(0);
    }
  });

  it("covers the whole registered surface, so a missing entry is a real absence", () => {
    // If the artifact were truncated, every lookup would return null and every surface would
    // decide it knows nothing about permissions — quietly, and in the direction that looks safe.
    expect(knownRoutes().length).toBeGreaterThan(200);
  });
});
