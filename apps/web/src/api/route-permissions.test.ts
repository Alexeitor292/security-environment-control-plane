// The permission table is read, not transcribed — and `null` never means "needs nothing".

import { describe, expect, it } from "vitest";

import { knownRoutes, permissionsFor } from "./route-permissions";

describe("permissions come from the call graph", () => {
  it("knows the three answers no route path would suggest", () => {
    // Same pins as tests/test_route_permissions.py, asserted on the client side too: the artifact
    // is the seam between them, and a seam checked from only one end is checked once.
    expect(permissionsFor("GET /api/v1/ranges")).toEqual(["exercise_operate"]);
    expect(
      permissionsFor("GET /api/v1/target-discovery/read-only-bootstrap/worker-nodes"),
    ).toEqual(["target_discovery_manage"]);
    expect(permissionsFor("GET /api/v1/enrollment")).toEqual(["enrollment_read"]);
  });

  it("returns null for a route with no resolved gate, and null is not 'open'", () => {
    // `GET /api/v1/targets` genuinely enforces nothing beyond authentication — verified by
    // reading `services/targets.py`. It still returns null here, because this module cannot tell
    // that case from a walk that lost the thread, and rendering "no permission needed" over the
    // second one shows a control to everyone.
    expect(permissionsFor("GET /api/v1/targets")).toBeNull();
  });

  it("returns null for a route it has never heard of", () => {
    expect(permissionsFor("GET /api/v1/not-a-route")).toBeNull();
  });

  it("covers the whole registered surface, so a missing entry is a real absence", () => {
    // If the artifact were truncated, every lookup would return null and every surface would
    // decide it knows nothing about permissions — quietly, and in the direction that looks safe.
    expect(knownRoutes().length).toBeGreaterThan(200);
  });
});
