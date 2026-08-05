// No page may assert a security property it does not observe.
//
// THE INCIDENT THIS ENCODES. `ProvidersPage` shipped a hand-written table
// stating that for Proxmox every mutating operation -- plan, apply, reset,
// destroy -- was `refused`, that discovery was GET-only, and that refusals were
// audited. Nothing verified any of it. By the time it was migrated it was
// already false: the Proxmox apply, destroy, verification and residue-proof
// paths had shipped, so the page was telling operators that operations were
// refused while the endpoints to perform them existed.
//
// WHY THE OBVIOUS FIX WAS REJECTED. Sourcing the table from
// `GET /api/v1/providers/capabilities` looks like the correct repair and is
// worse. That endpoint returns a hardcoded constant (`PROVISIONING_ENABLED =
// False`) and is stale in the same way. Wiring the page to it would relocate the
// false claim from the frontend to the backend and make it look OBSERVED,
// because a claim sourced from an API reads as verified. Hardening a lie is
// worse than leaving it visibly hand-written.
//
// THE RULE THIS ENFORCES. A fixture label is an adequate caveat for a deployment
// count. It is NOT adequate for "every mutating operation is refused", because
// an operator may act on that, and the error runs in the direction where someone
// gets hurt. Under-claiming is recoverable; over-claiming safety is not. So
// security properties are a distinct class: they may render as UNKNOWN, never as
// a comforting default.
//
// WHY A STRING SCAN IS LEGITIMATE HERE. Normally "assert the copy" is the
// self-restating anti-pattern this codebase avoids. This is the inverse: it
// asserts the ABSENCE of a class of claim across every page, including pages
// nobody has written yet. It cannot pass by restating itself, because it owns
// none of the text it inspects. `src/auth/boundary.test.ts` establishes the same
// shape for forbidden storage APIs.

import { describe, expect, it } from "vitest";

const PAGE_SOURCES = import.meta.glob("./apps/**/features/**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const PROVIDERS_PAGE = "./apps/prototype-suite/core/features/infrastructure/ProvidersPage.tsx";

/** Comments legitimately explain what must not be claimed; only real output counts. */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/**
 * Assertions about enforcement that no page can observe.
 *
 * Each is phrased to catch a claim, not a discussion. "permits or refuses" in a
 * sentence explaining that the page does not know is fine; "is refused" is not.
 */
const FORBIDDEN_CLAIMS: { pattern: RegExp; why: string }[] = [
  { pattern: /\bis refused\b/i, why: "asserts an operation is refused" },
  { pattern: /\bare refused\b/i, why: "asserts operations are refused" },
  { pattern: /every mutating operation/i, why: "asserts blanket refusal of mutations" },
  { pattern: /refusal is audited|audited refusal/i, why: "asserts refusals are audited" },
  { pattern: /never attempted/i, why: "asserts an operation is never attempted" },
  { pattern: /\bGET-only\b/i, why: "asserts a request-method restriction is enforced" },
  { pattern: /hard-sealed|provisioning sealed/i, why: "asserts provisioning cannot occur" },
  {
    pattern: /not real infrastructure/i,
    why: "asserts no real infrastructure is touched -- the exact claim that stayed green for months after it became false",
  },
];

describe("security-property claims", () => {
  it("scans a real set of pages (guard is not vacuous)", () => {
    // A glob that matched nothing would make every assertion below pass while
    // inspecting no files at all.
    expect(Object.keys(PAGE_SOURCES).length).toBeGreaterThan(30);
    expect(Object.keys(PAGE_SOURCES)).toContain(PROVIDERS_PAGE);
  });

  it("asserts no unobserved enforcement claim on any page", () => {
    const violations: string[] = [];

    for (const [path, src] of Object.entries(PAGE_SOURCES)) {
      const body = code(src);
      for (const { pattern, why } of FORBIDDEN_CLAIMS) {
        if (pattern.test(body)) violations.push(`${path}: ${why} (/${pattern.source}/)`);
      }
    }

    expect(violations, `Unobserved security claims found:\n${violations.join("\n")}`).toEqual([]);
  });

  it("renders provider capability as not-determined, in the unknown tone", () => {
    // The behavioural half. The scan above proves the page stopped SAYING the
    // wrong thing; this proves it says the right thing in the right register --
    // `unknown`, never `ok` (which reads as permitted) and never `error` (which
    // reads as refused). Both of those would be assertions the page cannot make.
    const src = PAGE_SOURCES[PROVIDERS_PAGE];

    expect(src).toMatch(/unverified:\s*\{\s*tone:\s*['"]unknown['"]/);
    expect(code(src)).not.toMatch(/tone:\s*['"]ok['"]/);
    expect(code(src)).not.toMatch(/tone:\s*['"]error['"]/);
  });
});
