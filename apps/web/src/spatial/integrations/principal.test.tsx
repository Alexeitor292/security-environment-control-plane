// The permission gate must fail CLOSED, and must not hide what it withholds.
//
// Both properties produce output that looks fine when broken: a gate that fails
// open renders the content (indistinguishable from a permitted user), and a gate
// that renders `null` looks like a page with fewer panels. So each is asserted
// differentially — permitted vs denied must DIFFER, and the denied case must say
// something rather than nothing.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { holdsAny, PermissionGate, SpatialPrincipalProvider } from "./principal";

const GATED = "audit-table-content";

function render(permissions: readonly string[] | null | undefined, requires: string[]): string {
  return renderToStaticMarkup(
    createElement(SpatialPrincipalProvider, {
      permissions,
      children: createElement(PermissionGate, {
        requires,
        surface: "The audit log",
        children: createElement("p", null, GATED),
      }),
    }),
  );
}

/** With NO provider at all — the harness case, and any future forgotten mount. */
function renderWithoutProvider(requires: string[]): string {
  return renderToStaticMarkup(
    createElement(PermissionGate, {
      requires,
      surface: "The audit log",
      children: createElement("p", null, GATED),
    }),
  );
}

describe("permission gate", () => {
  it("renders the surface for a principal holding the permission", () => {
    expect(render(["audit:read"], ["audit:read"])).toContain(GATED);
  });

  it("withholds it from a principal without the permission", () => {
    // The differential. The first assertion alone would pass on a gate that
    // always renders; the second alone on a gate that never does.
    const denied = render(["target:manage"], ["audit:read"]);
    expect(denied).not.toContain(GATED);
    expect(denied).toContain("not available to you");
  });

  it("FAILS CLOSED with no principal", () => {
    expect(render(null, ["audit:read"])).not.toContain(GATED);
    expect(render(undefined, ["audit:read"])).not.toContain(GATED);
    expect(render([], ["audit:read"])).not.toContain(GATED);
  });

  it("FAILS CLOSED with no provider at all", () => {
    // The harness mounts the shell outside `AuthProvider`, and a future mount
    // could forget it. Treating "no principal" as "unrestricted" would make both
    // silently open; the default context is empty precisely so it cannot.
    const out = renderWithoutProvider(["audit:read"]);
    expect(out).not.toContain(GATED);
    expect(out).toContain("not available to you");
  });

  it("names the permission it needs rather than vanishing", () => {
    // A surface that disappears reads as a missing feature or a broken page.
    const denied = render([], ["audit:read"]);
    expect(denied).toContain("audit:read");
    expect(denied.length).toBeGreaterThan(0);
  });

  it("does not claim to be an authorization boundary", () => {
    // The copy has to say the server decides, because an operator who reads this
    // as enforcement will draw the wrong conclusion from its absence.
    expect(render([], ["audit:read"])).toContain("does not decide it");
  });

  it("holdsAny requires ANY, not ALL — matching resolveNavItem", () => {
    // A surface offered by the sidebar and refused by its own page would be
    // worse than either rule alone, so the two must use the same rule.
    expect(holdsAny(["a"], ["a", "b"])).toBe(true);
    expect(holdsAny(["b"], ["a", "b"])).toBe(true);
    expect(holdsAny(["c"], ["a", "b"])).toBe(false);
    // No requirement means no gate.
    expect(holdsAny([], [])).toBe(true);
  });
});
