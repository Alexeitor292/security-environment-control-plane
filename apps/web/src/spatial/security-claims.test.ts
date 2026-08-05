// No page may assert a security property it does not observe.
//
// THE INCIDENT THIS ENCODES. `ProvidersPage` shipped a hand-written table
// stating that for Proxmox every mutating operation was `refused`, that
// discovery was GET-only, and that refusals were audited. Nothing verified any
// of it, and by the time it was migrated it was already false: the Proxmox
// apply, destroy, verification and residue-proof paths had shipped.
//
// WHY THE OBVIOUS FIX WAS REJECTED. Sourcing the table from
// `GET /api/v1/providers/capabilities` looks like the repair and is worse: that
// endpoint returns a hardcoded constant and is stale in the same way. Wiring
// them together would relocate the false claim into an API response, where it
// reads as OBSERVED rather than hand-written. That is a harder lie to catch.
//
// THE RULE. A fixture label is an adequate caveat for a deployment count. It is
// NOT adequate for "every mutating operation is refused", because an operator
// may act on that and the error runs in the direction where someone gets hurt.
// Security properties may render as UNKNOWN; never as a comforting default.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE IS BUILT THE WAY IT IS
//
// Its first version was a list of forbidden phrases. That version missed
// "no secret manager has ever been contacted" -- a claim of exactly the class it
// existed to catch -- because the phrase was not on the list. An include list
// cannot see what nobody thought of, and a guard that reads as comprehensive
// while being partial is worse than no guard.
//
// So the classification is INVERTED, the same way the authorization guard is:
// key on the CLASS OF CLAIM rather than on phrasing. Every absolute assertion in
// user-facing copy must be either removed or entered in ACKNOWLEDGED below with
// a written justification. A new absolute claim therefore fails BY DEFAULT,
// which is the property a pattern list can never have.
//
// SCOPE, AND WHAT IS DELIBERATELY LEFT OUT. `only` and `read-only` are absolute
// quantifiers too, and they are NOT enforced here. Measured against the migrated
// tree they produce 84 hits, overwhelmingly legitimate scoping description
// ("worker-only", "Simulator-only", "read-only inventory"). Requiring a written
// justification for each would produce a list nobody reads, and a rubber-stamped
// list is worse than no list because it looks like review. The enforced class is
// the one where being wrong is dangerous: assertions that something CANNOT
// happen or has NEVER happened. That narrowing is a judgement, and it is stated
// here rather than left implicit so it can be argued with.

import { describe, expect, it } from "vitest";

const PAGE_SOURCES = import.meta.glob("../**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

// Raw glob key: Vite shortens keys for files under this directory to "./...".
const PROVIDERS_PAGE = "./apps/prototype-suite/core/features/infrastructure/ProvidersPage.tsx";

/** Comments legitimately explain what must not be claimed; only real output counts. */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/** String literals -- an approximation of user-facing copy, and a good one here. */
const STRING_LITERAL = /'([^'\n]{12,})'|"([^"\n]{12,})"|`([^`]{12,}?)`/g;

/**
 * Absolute assertions: claims that something CANNOT happen, or has NEVER
 * happened. Being wrong about one of these is dangerous in the direction that
 * matters, which is what earns them a default-deny.
 */
const ABSOLUTE_CLAIM =
  /\b(never|always|no real|has ever|cannot|impossible|hard-sealed|is refused|are refused|by construction|sealed)\b/gi;

/**
 * Claims reviewed and kept, with the reason. `[file, phrase, count]`.
 *
 * The COUNT is part of the key on purpose: adding a second absolute claim to a
 * file that already has one acknowledged would otherwise pass silently. A
 * changed count fails and has to be re-justified.
 */
const ACKNOWLEDGED: [file: string, phrase: string, count: number][] = [
  // "sealed enclave" is the NAME of a network segment in a cyber-range scenario
  // fixture, not an assertion about the platform's own enforcement.
  ["spatial/apps/deployments/prototype/mocks/deployments.ts", "sealed", 1],
  ["spatial/apps/deployments/prototype/mocks/events.ts", "sealed", 2],
  ["spatial/apps/prototype-suite/core/mocks/deployments.ts", "sealed", 1],
  ["spatial/apps/prototype-suite/core/mocks/events.ts", "sealed", 2],
  ["spatial/apps/prototype-suite/core/features/events/NewEventWizardPage.tsx", "sealed", 1],

  // The fixture banner itself. "no real infrastructure" here is the honest
  // provenance label, not a safety guarantee about a live system -- it is the
  // one place the phrase is doing the right job.
  ["spatial/apps/prototype-suite/core/components/prototype/PrototypeBanner.tsx", "no real", 1],

  // A statement about the SIMULATOR, whose entire purpose is to not provision.
  ["spatial/apps/prototype-suite/core/features/scenarios/ScenarioOverviewPage.tsx", "no real", 1],

  // Product rules about this application's own behaviour, which it can observe:
  // a wizard's validation rule, a placement policy, a role definition, and the
  // immutability of a content-hashed version.
  ["spatial/apps/prototype-suite/core/features/events/NewEventWizardPage.tsx", "cannot", 1],
  ["spatial/apps/prototype-suite/core/features/events/NewEventWizardPage.tsx", "never", 1],
  ["spatial/apps/prototype-suite/core/features/infrastructure/PlacementPage.tsx", "never", 2],
  ["spatial/apps/prototype-suite/core/features/platform/IdentityPage.tsx", "never", 2],
  ["spatial/apps/prototype-suite/core/features/scenarios/ScenarioVersionsPage.tsx", "never", 1],
];

/**
 * Absolute claims that already existed OUTSIDE the migrated tree when this guard
 * was widened to cover all of `src`.
 *
 * THESE ARE PINNED, NOT REVIEWED. P7-C did not audit 66 entries of other
 * streams' copy and will not pretend otherwise -- writing 66 justifications for
 * code this slice does not own is the rubber stamp this guard exists to avoid.
 * What the pin buys is the property that matters: the counts cannot GROW
 * silently, so a NEW absolute claim anywhere in `src` fails by default, even in
 * a file nobody has reviewed and even in one nobody remembered existed.
 *
 * Several are certainly correct as written -- `domain/proxmox/proxmox-view.ts`
 * carries deliberate safety copy, and `pages/` states real product rules. The
 * honest position is that they are unexamined by this slice, not endorsed by it.
 * Working this list down, entry by entry with reasons, belongs to whoever owns
 * those files.
 */
const PRE_EXISTING: [file: string, phrase: string, count: number][] = [
  ["api/client.ts", "cannot", 1],
  ["components/rive/wrappers.tsx", "sealed", 2],
  ["components/ui/closed-code-error.ts", "cannot", 1],
  ["domain/proxmox/placement-view.ts", "never", 1],
  ["domain/proxmox/proxmox-fixtures.ts", "always", 1],
  ["domain/proxmox/proxmox-fixtures.ts", "cannot", 1],
  ["domain/proxmox/proxmox-fixtures.ts", "never", 4],
  ["domain/proxmox/proxmox-fixtures.ts", "sealed", 1],
  ["domain/proxmox/proxmox-view.ts", "cannot", 1],
  ["domain/proxmox/proxmox-view.ts", "is refused", 1],
  ["domain/proxmox/proxmox-view.ts", "never", 2],
  ["pages/AuditLog.tsx", "never", 2],
  ["pages/EnrollmentInventory.tsx", "cannot", 1],
  ["pages/ReadOnlyBootstrap.tsx", "is refused", 1],
  ["pages/ReadOnlyBootstrap.tsx", "never", 1],
  ["pages/ResolverActivation.tsx", "never", 1],
  ["pages/TopologyAuthoring.tsx", "never", 1],
  ["pages/TopologyPersistencePanel.tsx", "never", 1],
  ["pages/TopologyWorkspace.tsx", "never", 1],
  ["pages/audit-view.ts", "sealed", 1],
  ["pages/discovery-view.ts", "cannot", 1],
  ["pages/discovery-view.ts", "sealed", 4],
  ["pages/enrollment-inventory.ts", "cannot", 6],
  ["pages/enrollment-inventory.ts", "never", 1],
  ["pages/environment-publication.ts", "cannot", 2],
  ["pages/environment-publication.ts", "never", 2],
  ["pages/environments-view.ts", "never", 1],
  ["pages/environments-view.ts", "no real", 1],
  ["pages/onboarding-wizard-view.ts", "never", 1],
  ["pages/overview.ts", "never", 1],
  ["pages/range/range-flow.live-test.ts", "are refused", 1],
  ["pages/range/range-flow.ts", "cannot", 1],
  ["pages/range/range-view.ts", "cannot", 3],
  ["pages/range/range-view.ts", "never", 4],
  ["pages/range/scoreboard-view.ts", "are refused", 1],
  ["pages/range/scoreboard-view.ts", "cannot", 1],
  ["pages/range/scoreboard-view.ts", "never", 3],
  ["pages/read-only-bootstrap.ts", "cannot", 1],
  ["pages/read-only-bootstrap.ts", "never", 5],
  ["pages/read-only-bootstrap.ts", "sealed", 1],
  ["pages/readonly-ops.ts", "cannot", 2],
  ["pages/readonly-ops.ts", "never", 5],
  ["pages/readonly-ops.ts", "sealed", 3],
  ["pages/readonly-preflight.ts", "never", 1],
  ["pages/resolver-activation.ts", "sealed", 2],
  ["pages/staging-deployment.ts", "never", 3],
  ["pages/staging-deployment.ts", "sealed", 2],
  ["pages/staging-view.ts", "cannot", 1],
  ["pages/staging-view.ts", "no real", 2],
  ["pages/staging-view.ts", "sealed", 2],
  ["pages/target-discovery.ts", "cannot", 1],
  ["pages/target-discovery.ts", "never", 2],
  ["pages/target-discovery.ts", "sealed", 3],
  ["pages/target-hub.ts", "cannot", 1],
  ["pages/target-hub.ts", "is refused", 1],
  ["pages/target-hub.ts", "never", 3],
  ["pages/target-hub.ts", "no real", 1],
  ["pages/target-hub.ts", "sealed", 4],
  ["pages/topology-persistence.ts", "cannot", 3],
  ["pages/topology-persistence.ts", "never", 1],
  ["pages/topology-workspace.ts", "cannot", 1],
  ["pages/topology-workspace.ts", "never", 2],
  ["pages/worker-enrollment.ts", "cannot", 6],
  ["pages/worker-enrollment.ts", "never", 10],
  ["pages/worker-enrollment.ts", "sealed", 1],
  ["testing/fake-control-plane.ts", "cannot", 1],
];

/**
 * P7-H retires `src/pages/` wholesale. 54 of the 66 `PRE_EXISTING` entries live
 * there, and they are resolved by that DELETION rather than by review -- which
 * is why they were never audited.
 *
 * Pinning the number turns the retirement into a checked event instead of an
 * assumed one: when `pages/` goes, the count must fall by exactly 54. If it
 * falls by less, a claim MOVED rather than died -- carried into the spatial tree
 * by someone porting a page, which is exactly how false claims reached the
 * fixtures in the first place. A count that fails to drop is a signal no diff
 * review produces, because the claim looks like ordinary ported copy in the
 * diff that carries it.
 *
 * Relocation is caught from the other side too: a claim ported into `spatial/`
 * arrives unacknowledged and fails the main assertion above. This pin is what
 * catches the case where it lands somewhere else in `src` entirely.
 */
const PAGES_ENTRIES_AT_PIN = 54;

function acknowledgedCount(file: string, phrase: string): number | undefined {
  return [...ACKNOWLEDGED, ...PRE_EXISTING].find(([f, p]) => f === file && p === phrase)?.[2];
}

/** Absolute claims per (file, phrase), across the migrated tree. */
function absoluteClaims(): Map<string, number> {
  const found = new Map<string, number>();

  for (const [path, src] of Object.entries(PAGE_SOURCES)) {
    if (path.includes(".test.")) continue;
    // Vite normalises glob keys to their shortest relative form, so this glob
    // yields a MIX: "./apps/x" for files under `spatial/`, "../pages/x" for the
    // rest. Both are resolved to one src-relative form so the lists below can be
    // written in a single vocabulary.
    const rel = path.startsWith("../")
      ? path.slice(3)
      : `spatial/${path.replace(/^\.\//, "")}`;
    const body = code(src);

    for (const lit of body.matchAll(STRING_LITERAL)) {
      const text = lit[1] ?? lit[2] ?? lit[3] ?? "";
      for (const m of text.matchAll(ABSOLUTE_CLAIM)) {
        // "|" cannot occur in a path or a phrase, so the key is unambiguous;
        // a space separator split "no real" in the middle.
        const key = `${rel}|${m[0].toLowerCase()}`;
        found.set(key, (found.get(key) ?? 0) + 1);
      }
    }
  }

  return found;
}

describe("security-property claims", () => {
  it("scans a real set of sources (guard is not vacuous)", () => {
    expect(Object.keys(PAGE_SOURCES).length).toBeGreaterThan(350);
    expect(Object.keys(PAGE_SOURCES)).toContain(PROVIDERS_PAGE);
  });

  it("requires every absolute claim to be acknowledged with a reason", () => {
    // THE LOAD-BEARING ASSERTION. A newly written "nothing can ever reach the
    // host" is unacknowledged by construction and fails here. The message tells
    // whoever trips it what the choice is, because they will not have read the
    // header.
    const unacknowledged: string[] = [];

    for (const [key, count] of absoluteClaims()) {
      const [file, phrase] = key.split("|");
      const allowed = acknowledgedCount(file, phrase);
      if (allowed === undefined) {
        unacknowledged.push(`${file}: new absolute claim "${phrase}" (${count}x)`);
      } else if (allowed !== count) {
        unacknowledged.push(
          `${file}: "${phrase}" count changed ${allowed} -> ${count}; re-justify or revert`,
        );
      }
    }

    expect(
      unacknowledged,
      `Unacknowledged absolute claim(s):\n${unacknowledged.join("\n")}\n\n` +
        "An absolute claim in user-facing copy must be either removed or entered in " +
        "ACKNOWLEDGED with a written reason. If it is a claim about ENFORCEMENT that this " +
        "application cannot observe -- what a provider refuses, what cannot reach a host, " +
        "what has never been contacted -- remove it and render the state as unknown. " +
        "A fixture label does not make a false security claim safe.",
    ).toEqual([]);
  });

  it("keeps the acknowledgement list free of stale entries", () => {
    // An entry left behind after the copy changed would silently pre-authorize a
    // future claim in that file.
    const live = absoluteClaims();
    const stale = [...ACKNOWLEDGED, ...PRE_EXISTING]
      .filter(([f, p]) => !live.has(`${f}|${p}`))
      .map(
      ([f, p]) => `${f}: "${p}"`,
    );
    expect(stale, `Stale acknowledgements:\n${stale.join("\n")}`).toEqual([]);
  });

  it("tracks the pages/ retirement: 54 entries must die, not move", () => {
    // `pages/` is obsolete and scheduled for wholesale removal in P7-H.
    const pagesTreeLive = Object.keys(PAGE_SOURCES).some((k) => k.startsWith("../pages/"));
    const pagesEntries = PRE_EXISTING.filter(([f]) => f.startsWith("pages/"));

    if (pagesTreeLive) {
      expect(
        pagesEntries.length,
        "The pages/ baseline changed while pages/ still exists. If a claim was removed, " +
          "drop its entry and lower PAGES_ENTRIES_AT_PIN in the same change; if one was " +
          "added, it is a new absolute claim and needs removing, not pinning.",
      ).toBe(PAGES_ENTRIES_AT_PIN);
    } else {
      expect(
        pagesEntries,
        "pages/ has been retired but its PRE_EXISTING entries remain. Every one of the 54 " +
          "must be deleted from this list. If a claim survived the retirement it was PORTED, " +
          "not resolved -- find where it landed and remove the claim itself.",
      ).toEqual([]);
    }
  });

  it("renders provider capability as not-determined, in the unknown tone", () => {
    // The behavioural half: the page says the right thing in the right register
    // -- `unknown`, never `ok` (reads as permitted), never `error` (reads as
    // refused). Both would be assertions the page cannot make.
    const src = PAGE_SOURCES[PROVIDERS_PAGE];

    expect(src).toMatch(/unverified:\s*\{\s*tone:\s*['"]unknown['"]/);
    expect(code(src)).not.toMatch(/tone:\s*['"]ok['"]/);
    expect(code(src)).not.toMatch(/tone:\s*['"]error['"]/);
  });
});
