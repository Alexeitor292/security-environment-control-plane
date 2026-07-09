import { DEV_DISCLOSURE, NAV_GROUPS } from "./nav";

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
  "/audit",
];

/** Every route the previous sidebar linked to — nothing may become unreachable. */
const PREVIOUS_NAV_ROUTES = KNOWN_ROUTES;

const allItems = NAV_GROUPS.flatMap((g) => g.items);

describe("shell navigation model", () => {
  it("links every previously navigable route (nothing becomes unreachable)", () => {
    const hrefs = allItems.map((i) => i.href).filter(Boolean);
    for (const route of PREVIOUS_NAV_ROUTES) {
      expect(hrefs, `route ${route} lost from the sidebar`).toContain(route);
    }
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
