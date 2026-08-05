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
  "/enrollment-inventory",
  "/audit",
  "/ranges",
  "/ranges/new",
];

/** Every route the previous sidebar linked to — nothing may become unreachable.
 *  Frozen at the pre-approvals-queue set; /approvals is a new route, not a
 *  previously navigable one, and neither are the range surfaces. */
const PREVIOUS_NAV_ROUTES = KNOWN_ROUTES.filter(
  (r) =>
    r !== "/approvals" &&
    r !== "/exercises" &&
    r !== "/enrollment-inventory" &&
    !r.startsWith("/ranges"),
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

  it("links the range catalog and range creation", () => {
    const hrefs = allItems.map((i) => i.href);
    expect(hrefs).toContain("/ranges");
    expect(hrefs).toContain("/ranges/new");
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
    // The JOINED form, not a bare "or". `toContain("or")` was passing on the "or" inside
    // "administrator", so switching the joiner to " and " — which would misstate the rule as
    // requiring both — left it green. Asserting the whole phrase is what makes it falsifiable.
    expect(reason).toContain("enrollment:read or enrollment:manage");
    expect(reason).not.toContain("enrollment:read and enrollment:manage");
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
    // The permission cases are DERIVED per item, not a hardcoded list. A fixed list only ever
    // exercised the granted branch for items whose permissions happened to appear in it — gate a
    // future item on settings:read and every case would land in the denied branch, so the
    // granted branch would go unchecked and this test would pass without covering it.
    const everyPermission = allItems.flatMap((i) => i.requiresAnyPermission ?? []);
    for (const item of allItems) {
      const required = item.requiresAnyPermission ?? [];
      const cases: string[][] = [
        [], // denied (or ungated)
        [...everyPermission], // granted, if the item is gated at all
        ...required.map((p) => [p]), // granted by each individual permission, one at a time
      ];
      for (const permissions of cases) {
        const r = resolveNavItem(item, permissions);
        const hasHref = r.href !== undefined;
        const hasReason = r.unavailableReason !== undefined && r.unavailableReason.length > 0;
        expect(hasHref !== hasReason, `${item.id} @ ${JSON.stringify(permissions)}`).toBe(true);
      }
    }
  });

  // Directly pins what the derived cases above make reachable: the granted branch must preserve
  // whatever the item declared, rather than rebuilding it from a fixed field list. A rebuild that
  // omits unavailableReason yields an item with NEITHER — legal input, invalid output.
  it("returns a permitted item unchanged rather than rebuilding it", () => {
    const declaredReason: NavItem = {
      id: "hypothetical",
      label: "Hypothetical",
      unavailableReason: "Not available in this milestone.",
      requiresAnyPermission: ["some:permission"],
    };
    const granted = resolveNavItem(declaredReason, ["some:permission"]);
    expect(granted.unavailableReason).toBe("Not available in this milestone.");
    expect(granted.href).toBeUndefined();
    const hasHref = granted.href !== undefined;
    const hasReason = (granted.unavailableReason ?? "").length > 0;
    expect(hasHref !== hasReason).toBe(true);
  });

  it("leaves every ungated item exactly as it was", () => {
    for (const item of allItems.filter((i) => i.requiresAnyPermission === undefined)) {
      expect(resolveNavItem(item, []), item.id).toBe(item);
      expect(resolveNavItem(item, ["anything"]), item.id).toBe(item);
    }
  });

  // Anti-vacuity: if gating were dropped from the model, every assertion above would still pass
  // against an empty set. Pin exactly which items are gated, and on what.
  it("gates exactly the surfaces that need it", () => {
    expect(gated.map((i) => i.id)).toEqual([
      "worker-enrollment",
      "enrollment-inventory",
    ]);
    expect(enrollment.requiresAnyPermission).toEqual([
      "enrollment:read",
      "enrollment:manage",
    ]);
  });

  /**
   * The two enrollment entries are gated DIFFERENTLY, and the difference is the pinned backend
   * decision that enrollment:manage does not imply enrollment:read.
   *
   * The hand-off surface takes read OR manage, because a manage-only principal can still run the
   * whole create-and-hand-over flow. The inventory takes read ALONE, because the list route
   * requires read and a manage-only principal opening it could only ever be refused. Collapsing
   * them onto one rule would either hide a usable surface or advertise an unusable one.
   */
  it("gates the inventory on read alone, unlike the hand-off surface", () => {
    const inventory = allItems.find((i) => i.id === "enrollment-inventory") as NavItem;
    expect(inventory.requiresAnyPermission).toEqual(["enrollment:read"]);
    expect(resolveNavItem(inventory, ["enrollment:read"]).href).toBe(
      "/enrollment-inventory",
    );
    // manage alone must NOT open it
    const manageOnly = resolveNavItem(inventory, ["enrollment:manage"]);
    expect(manageOnly.href).toBeUndefined();
    expect(manageOnly.unavailableReason).toContain("enrollment:read");
    // ...while the hand-off surface stays reachable on manage alone.
    expect(resolveNavItem(enrollment, ["enrollment:manage"]).href).toBe(
      "/worker-enrollment",
    );
  });

  it("builds the reason from whatever permissions it is given", () => {
    expect(navPermissionReason(["a:b"])).toContain("a:b");
    expect(navPermissionReason(["a:b", "c:d"])).toContain("a:b or c:d");
  });
});
