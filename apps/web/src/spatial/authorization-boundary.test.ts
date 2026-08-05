// No mutating adapter method may be reachable without an authorization check.
//
// WHY THIS IS A GUARD AND NOT A NOTE IN A DOC. The migrated spatial UI contains
// no authorization logic of any kind -- no permission check, no capability gate,
// no principal-aware rendering. That is survivable only for as long as the
// adapter is read-only, which it is today: all 22 methods are `list*`/`get*`.
// The moment somebody adds `approvePlan()` or `destroyRange()` and wires a
// button to it, an unprivileged operator gets a working mutation button and
// nothing in the codebase objects. A remembered rule does not survive that; a
// failing test does.
//
// THE DESIGN CONSTRAINT THAT SHAPED THIS FILE. A guard that only checks "the
// mutating methods we know about are gated" is useless here, because there are
// currently NO mutating methods -- it would pass vacuously forever and go red
// only if someone removed a gate that does not exist yet. So the classification
// is INVERTED: every method on the live interface must be explicitly
// acknowledged as read-only, and anything not acknowledged is treated as
// mutating and must be gated. Adding a method is therefore what turns this red.
//
// That inversion is the same lesson this codebase learned from closed-set
// guards elsewhere: enumerate from the LIVE artifact and require each item to be
// approved, rather than enumerating the approved items and hoping the live set
// matches.
//
// WHAT THIS DELIBERATELY DOES NOT DO. It does not treat a hidden or disabled
// control as an authorization boundary, and neither should any code it guards.
// Hiding a button is a UX courtesy; the server refusing the request is the
// boundary. `DangerousOperationDialog` is a confirmation step, not a permission
// check, and must never be the only thing between an operator and a mutation.

import { describe, expect, it } from "vitest";

import RAW_ADAPTER from "./apps/prototype-suite/core/integrations/adapter.ts?raw";

/** Page sources, where any call site would live. */
const PAGE_SOURCES = import.meta.glob("./apps/**/features/**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/**
 * Methods on `ControlPlaneAdapter` that only READ.
 *
 * This list is an explicit acknowledgement, not a description. A method absent
 * from it is treated as mutating by default -- the safe direction -- so adding
 * an adapter method without thinking about authorization fails the first test
 * below. Adding a name here is a deliberate act with a visible diff, which is
 * the point: it forces the question to be answered by a person rather than
 * skipped by omission.
 */
const ACKNOWLEDGED_READ_ONLY = new Set([
  "listEvents",
  "getEvent",
  "listScenarios",
  "getScenario",
  "listDeployments",
  "getDeployment",
  "listTeams",
  "listParticipants",
  "listAccessProfiles",
  "listTargets",
  "listWorkers",
  "listIntegrations",
  "listWorkflowRuns",
  "listApprovals",
  "listAlerts",
  "listAuditEvents",
  "listEvidence",
  "listScores",
  "listReports",
  "listUsers",
  "listSecretRefs",
  "getTopology",
]);

/**
 * Every method declared on the interface, read from the live source.
 *
 * Matches `name(args): ReturnType` inside the interface body, which excludes
 * property declarations such as `readonly provenance: AdapterProvenance`.
 */
function declaredMethods(source: string): string[] {
  const body = /export interface ControlPlaneAdapter[^{]*\{([\s\S]*?)\n\}/.exec(source)?.[1] ?? "";
  const stripped = body.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  return [...stripped.matchAll(/^\s*(\w+)\s*\(/gm)].map((m) => m[1]);
}

/** Signals that a call site sits behind some authorization decision. */
const AUTHORIZATION_SIGNAL =
  /permission|can[A-Z]\w*|useAuth|principal|authoriz|capabilit(y|ies)Gate|requirePermission/;

const METHODS = declaredMethods(RAW_ADAPTER);
const MUTATING = METHODS.filter((m) => !ACKNOWLEDGED_READ_ONLY.has(m));

describe("adapter authorization boundary", () => {
  it("parses the live interface (guard is not vacuous)", () => {
    // Without this, a regex that stopped matching would empty METHODS and make
    // every assertion below pass while inspecting nothing.
    expect(METHODS.length).toBeGreaterThanOrEqual(22);
    expect(METHODS).toContain("listTargets");
  });

  it("classifies every method on the live interface", () => {
    // THE LOAD-BEARING ASSERTION. A newly added adapter method is unacknowledged
    // by construction, so this fails the moment one appears. The failure message
    // names it and says what to do, because the person who trips this will not
    // have read the comment at the top of this file.
    expect(
      MUTATING,
      `Unacknowledged adapter method(s): ${MUTATING.join(", ")}. ` +
        "Every method must be classified. If it only reads, add it to " +
        "ACKNOWLEDGED_READ_ONLY. If it mutates, it needs an authorization gate " +
        "at every call site, landing in the SAME change that adds the method -- " +
        "and note that hiding or disabling a control is not an authorization " +
        "boundary; the server refuses, the UI merely reflects.",
    ).toEqual([]);
  });

  it("keeps the acknowledgement list free of stale entries", () => {
    // A name left behind after a method is removed would silently widen the
    // allowlist for any future method that happened to reuse it.
    const declared = new Set(METHODS);
    const stale = [...ACKNOWLEDGED_READ_ONLY].filter((m) => !declared.has(m));
    expect(stale, `Stale entries no longer on the interface: ${stale.join(", ")}`).toEqual([]);
  });

  it("gates every call site of every mutating method", () => {
    // Currently a no-op over an empty set, by design: the machinery is in place
    // so that the FIRST mutating method is covered automatically, rather than
    // relying on whoever adds it to also remember to write this test. It is
    // mutation-verified against a synthetic mutating method.
    expect(Object.keys(PAGE_SOURCES).length).toBeGreaterThan(30);

    for (const method of MUTATING) {
      for (const [path, src] of Object.entries(PAGE_SOURCES)) {
        if (!new RegExp(`\\.${method}\\s*\\(`).test(src)) continue;
        expect(
          AUTHORIZATION_SIGNAL.test(src),
          `${path} calls mutating adapter method ${method}() with no authorization check`,
        ).toBe(true);
      }
    }
  });
});
