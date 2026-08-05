// The spatial workspace must never be reachable without authentication.
//
// WHY A SOURCE SCAN. The invariant is a property of the ROUTE TABLE, not of any
// component: `AuthBoundary` is already responsible for rendering children only
// when `status === "authenticated"`, and that behaviour is its own to test. The
// failure this file exists to catch is different and purely structural --
// someone adds a second route for the spatial shell, or moves the existing one,
// and mounts it without the guard. No component test can see that, because the
// defect is in the composition rather than in any component. `src/auth/
// boundary.test.ts` establishes this `?raw` scanning idiom in this codebase for
// exactly this class of invariant.
//
// The assertion is deliberately phrased as a CLOSURE over the file rather than
// as "the route I wrote is guarded". Checking the known route would pass while a
// second, unguarded mount sat next to it. So instead: *every* place the spatial
// workspace is mounted must be inside a guard, however many there turn out to be.

import { describe, expect, it } from "vitest";

import RAW_MAIN from "../main.tsx?raw";

/** Comments legitimately discuss auth; the invariant is about real JSX. */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

const MAIN = code(RAW_MAIN);

/**
 * Extract every `element: ( ... )` block with balanced parentheses.
 *
 * A regex cannot do this correctly -- these blocks nest -- and getting it wrong
 * would silently under-report, which for a security guard means passing when it
 * should fail.
 */
function elementBlocks(src: string): string[] {
  const blocks: string[] = [];
  const marker = "element:";

  for (let i = src.indexOf(marker); i !== -1; i = src.indexOf(marker, i + 1)) {
    let j = i + marker.length;
    while (j < src.length && /\s/.test(src[j])) j += 1;
    if (src[j] !== "(") continue; // single-element form, e.g. `element: <Dashboard />`

    let depth = 0;
    const start = j;
    for (; j < src.length; j += 1) {
      if (src[j] === "(") depth += 1;
      else if (src[j] === ")") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    blocks.push(src.slice(start, j + 1));
  }

  return blocks;
}

/** Mounts of the spatial shell, in whatever form they appear. */
function mountsSpatial(block: string): boolean {
  return /<\s*SpatialWorkspace[\s/>]/.test(block);
}

describe("spatial workspace route guarding", () => {
  it("mounts the spatial workspace at least once (guard is not vacuous)", () => {
    // Without this, every assertion below would pass trivially on a file that
    // stopped mounting the workspace at all -- a green test proving nothing.
    // This is the clause that makes the rest of this file meaningful.
    const mounts = elementBlocks(MAIN).filter(mountsSpatial);
    expect(mounts.length).toBeGreaterThan(0);
  });

  it("wraps EVERY spatial mount in the auth boundary", () => {
    for (const block of elementBlocks(MAIN).filter(mountsSpatial)) {
      expect(block).toMatch(/<\s*AuthBoundary[\s>]/);
    }
  });

  it("finds no spatial mount anywhere outside a guarded route element", () => {
    // Counts mounts in the whole file against mounts inside guarded blocks. If
    // someone renders the workspace outside the route table entirely -- say
    // directly into the root render call -- the totals diverge and this fails.
    const everywhere = MAIN.match(/<\s*SpatialWorkspace[\s/>]/g) ?? [];
    const guarded = elementBlocks(MAIN)
      .filter(mountsSpatial)
      .filter((b) => /<\s*AuthBoundary[\s>]/.test(b))
      .reduce((n, b) => n + (b.match(/<\s*SpatialWorkspace[\s/>]/g) ?? []).length, 0);

    expect(everywhere.length).toBe(guarded);
  });

  it("keeps the auth boundary between the router and the workspace, not inside it", () => {
    // `AuthBoundary` uses `useLocation`/`useNavigate`, so it must sit under the
    // RouterProvider. If it were hoisted above the router this would still look
    // guarded but would throw at runtime -- a guard that fails open.
    expect(MAIN).toMatch(/<RouterProvider/);
    const routerIndex = MAIN.indexOf("createBrowserRouter");
    const spatialIndex = MAIN.search(/<\s*SpatialWorkspace[\s/>]/);
    expect(routerIndex).toBeGreaterThanOrEqual(0);
    expect(spatialIndex).toBeGreaterThan(routerIndex);
  });
});
