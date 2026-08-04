// Sidebar wiring for permission-gated navigation.
//
// nav.test.ts proves the RULE (`resolveNavItem`); this proves the sidebar actually applies it.
// Those are different failures: the resolver could be perfect while the component renders the raw
// item and links a route the principal cannot use. Only rendering catches that.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import type { Principal } from "../../api/types";
import { Sidebar } from "./Sidebar";

function principal(permissions: string[]): Principal {
  return {
    user_id: "u-1",
    organization_id: "org-1",
    email: "operator@example.test",
    permissions,
    is_dev_fallback: false,
  };
}

function html(permissions: string[] | null): string {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(Sidebar, {
        principal: permissions === null ? null : principal(permissions),
        collapsed: false,
      }),
    ),
  );
}

/** The href appears only inside a real link. A disabled entry renders as a <span>, so matching the
 *  path alone would pass on an entry that navigates nowhere. */
function linksTo(out: string, path: string): boolean {
  return out.includes(`href="${path}"`);
}

describe("Sidebar — permission-gated entries", () => {
  it("links worker enrollment for a principal holding either permission", () => {
    for (const permissions of [
      ["enrollment:read"],
      ["enrollment:manage"],
      ["enrollment:read", "enrollment:manage"],
    ]) {
      const out = html(permissions);
      expect(linksTo(out, "/worker-enrollment"), permissions.join("+")).toBe(true);
      expect(out, permissions.join("+")).toContain("Worker Enrollment");
    }
  });

  // The near-miss this whole gate exists to avoid: manage-without-read can create and revoke
  // invitations — the entire hand-off flow — so hiding the entry from them would remove the
  // surface from the operator it was built for.
  it("links it for a manage-only principal, who can still use most of the page", () => {
    expect(linksTo(html(["enrollment:manage"]), "/worker-enrollment")).toBe(true);
  });

  it("disables rather than hides it when the principal holds neither", () => {
    for (const permissions of [[], ["exercise:read"], null]) {
      const out = html(permissions);
      // Still present, so the operator can see the surface exists...
      expect(out, JSON.stringify(permissions)).toContain("Worker Enrollment");
      // ...but it navigates nowhere...
      expect(linksTo(out, "/worker-enrollment"), JSON.stringify(permissions)).toBe(false);
      // ...and says what to ask for.
      expect(out, JSON.stringify(permissions)).toContain("enrollment:read");
      expect(out, JSON.stringify(permissions)).toContain("enrollment:manage");
      expect(out, JSON.stringify(permissions)).toContain("organization administrator");
    }
  });

  it("exposes the reason to assistive technology, not only as a hover title", () => {
    const out = html([]);
    expect(out).toContain("shell-nav__item--unavailable");
    expect(out).toContain("shell-sr-only");
  });

  it("leaves ungated entries reachable regardless of permissions", () => {
    for (const permissions of [[], ["enrollment:read"], null]) {
      const out = html(permissions);
      for (const route of ["/", "/templates", "/exercises", "/audit", "/approvals"]) {
        expect(linksTo(out, route), `${route} @ ${JSON.stringify(permissions)}`).toBe(true);
      }
    }
  });

  // Anti-vacuity: `linksTo` must be able to return both answers, or the assertions above prove
  // nothing. The same call reports true for a route that is linked and false for one that is not.
  it("uses a link check that can distinguish linked from unlinked", () => {
    const out = html([]);
    expect(linksTo(out, "/audit")).toBe(true);
    expect(linksTo(out, "/worker-enrollment")).toBe(false);
    expect(linksTo(out, "/not-a-route-at-all")).toBe(false);
  });
});
