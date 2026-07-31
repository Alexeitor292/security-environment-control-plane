import {
  DEV_DISCLOSURE,
  NAV_GROUPS,
  navPermissionReason,
  resolveNavItem,
  type NavItem,
} from "./nav";

/** Static routes registered in main.tsx (excluding parameterized ones). */
const KNOWN_ROUTES = [
  "/",
  "/templates",
  "/templates/new",
  "/provider-targets",
  "/onboarding",
  "/staging-labs",
  "/staging-deployments",
  "/read-only-bootstrap",
  "/target-discovery",
  "/readonly-preflight",
  "/resolver-activation",
  "/approvals",
  "/exercises",
  "/worker-enrollment",
  "/audit",
];

/** Every route the previous sidebar linked to — nothing may become unreachable.
 *  Frozen at the pre-approvals-queue set; /approvals is a new route, not a
 *  previously navigable one. */
const PREVIOUS_NAV_ROUTES = KNOWN_ROUTES.filter(
  (r) => r !== "/approvals" && r !== "/exercises",
);

const allItems = NAV_GROUPS.flatMap((g) => g.items);

describe("shell navigation model", () => {
  it("links every previously navigable route (nothing becomes unreachable)", () => {
    const hrefs = allItems.map((i) => i.href).filter(Boolean);
    for (const route of PREVIOUS_NAV_ROUTES) {
      expect(hrefs, `route ${route} lost from the sidebar`).toContain(route);
    }
  });

  it("links the new approvals queue", () => {
    expect(allItems.map((i) => i.href)).toContain("/approvals");
  });

  it("links the new exercise inventory", () => {
    expect(allItems.map((i) => i.href)).toContain("/exercises");
  });

  it("only links routes that exist in the router", () => {
    for (const item of allItems) {
      if (item.href) {
        expect(KNOWN_ROUTES, `${item.id} links unknown ${item.href}`).toContain(
          item.href,
        );
      }
    }
  });

  // Deliberately UNCHANGED by the permission-gating work. `requiresAnyPermission` is orthogonal
  // metadata, not a third alternative: a gated item still declares an href and nothing else, so
  // this invariant was never weakened to accommodate it. The resolved form is held to the same
  // rule below.
  it("gives every item exactly one of href or unavailableReason", () => {
    for (const item of allItems) {
      const hasHref = item.href !== undefined;
      const hasReason =
        item.unavailableReason !== undefined && item.unavailableReason.length > 0;
      expect(hasHref !== hasReason, item.id).toBe(true);
    }
  });

  it("has globally unique item ids and unique hrefs", () => {
    const ids = allItems.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
    const hrefs = allItems.map((i) => i.href).filter(Boolean);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });

  it("contains the mandated group structure", () => {
    const labels = NAV_GROUPS.map((g) => g.label);
    for (const required of [
      "Environments",
      "Infrastructure",
      "Governance",
      "Workflows",
      "System",
    ]) {
      expect(labels).toContain(required);
    }
  });

  it("preserves the development disclosure truth language verbatim", () => {
    expect(DEV_DISCLOSURE).toBe(
      "Local development. Simulated execution only — no real infrastructure.",
    );
  });

  it("keeps unavailable-item copy free of fake-status language", () => {
    for (const item of allItems) {
      if (item.unavailableReason) {
        expect(item.unavailableReason.toLowerCase()).not.toContain("coming soon");
        expect(item.unavailableReason).not.toMatch(/\d+ pending/);
      }
    }
  });
});

describe("permission-gated navigation", () => {
  const gated = allItems.filter((i) => i.requiresAnyPermission !== undefined);
  const enrollment = allItems.find((i) => i.id === "worker-enrollment") as NavItem;

  it("links the worker-enrollment surface, in Infrastructure", () => {
    expect(enrollment).toBeDefined();
    expect(enrollment.href).toBe("/worker-enrollment");
    const group = NAV_GROUPS.find((g) => g.items.some((i) => i.id === "worker-enrollment"));
    expect(group?.label).toBe("Infrastructure");
  });

  /**
   * THE BUG THIS TEST EXISTS FOR. Gating on enrollment:read alone would hide the page from an
   * operator holding only enrollment:manage — who can create AND revoke invitations, which is the
   * entire hand-off flow, and is refused only status look-ups. The page has dedicated copy
   * (MANAGE_WITHOUT_READ_NOTICE) warning that principal up front, so it was built for them.
   *
   * ANY, never ALL. This is the assertion that fails if anyone "tightens" it later.
   */
  it("shows the enrollment surface to a manage-only principal", () => {
    const resolved = resolveNavItem(enrollment, ["enrollment:manage"]);
    expect(resolved.href).toBe("/worker-enrollment");
    expect(resolved.unavailableReason).toBeUndefined();
  });

  it("shows it to a read-only principal too", () => {
    const resolved = resolveNavItem(enrollment, ["enrollment:read"]);
    expect(resolved.href).toBe("/worker-enrollment");
  });

  it("disables it — with a reason, never hidden — for a principal holding neither", () => {
    for (const permissions of [[], ["exercise:read"], null, undefined]) {
      const resolved = resolveNavItem(enrollment, permissions);
      expect(resolved.href, JSON.stringify(permissions)).toBeUndefined();
      expect(resolved.unavailableReason, JSON.stringify(permissions)).toBeTruthy();
      // Still rendered: an entry that vanishes leaves the operator with nothing to ask for.
      expect(resolved.id).toBe("worker-enrollment");
      expect(resolved.label).toBe("Worker Enrollment");
    }
  });

  it("names the permissions to request rather than saying only 'unavailable'", () => {
    const reason = resolveNavItem(enrollment, []).unavailableReason ?? "";
    expect(reason).toContain("enrollment:read");
    expect(reason).toContain("enrollment:manage");
    expect(reason).toContain("or"); // either one suffices, and the copy says so
    expect(reason.toLowerCase()).not.toContain("coming soon");
    expect(reason).not.toMatch(/\d+ pending/);
  });

  it("never infers the permission from a neighbouring capability", () => {
    for (const near of ["enrollment", "enrollment:progress", "worker:read", "enrollment:write"]) {
      expect(resolveNavItem(enrollment, [near]).href, near).toBeUndefined();
    }
  });

  // The resolved item is held to the same exactly-one rule as the static model, in BOTH
  // outcomes — so gating can never emit an item that is simultaneously live and explained, or
  // neither.
  it("keeps the exactly-one invariant after resolution", () => {
    const cases = [
      ["enrollment:read", "enrollment:manage"],
      ["enrollment:manage"],
      [],
    ];
    for (const item of allItems) {
      for (const permissions of cases) {
        const r = resolveNavItem(item, permissions);
        const hasHref = r.href !== undefined;
        const hasReason = r.unavailableReason !== undefined && r.unavailableReason.length > 0;
        expect(hasHref !== hasReason, `${item.id} @ ${JSON.stringify(permissions)}`).toBe(true);
      }
    }
  });

  it("leaves every ungated item exactly as it was", () => {
    for (const item of allItems.filter((i) => i.requiresAnyPermission === undefined)) {
      expect(resolveNavItem(item, []), item.id).toBe(item);
      expect(resolveNavItem(item, ["anything"]), item.id).toBe(item);
    }
  });

  // Anti-vacuity: if gating were dropped from the model, every assertion above would still pass
  // against an empty set. Pin that exactly one item is gated, and which.
  it("gates exactly the surfaces that need it", () => {
    expect(gated.map((i) => i.id)).toEqual(["worker-enrollment"]);
    expect(enrollment.requiresAnyPermission).toEqual([
      "enrollment:read",
      "enrollment:manage",
    ]);
  });

  it("builds the reason from whatever permissions it is given", () => {
    expect(navPermissionReason(["a:b"])).toContain("a:b");
    expect(navPermissionReason(["a:b", "c:d"])).toContain("a:b or c:d");
  });
});
