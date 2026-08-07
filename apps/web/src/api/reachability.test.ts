// The reachability analysis, pinned against facts established by hand.
//
// This module answers a question that decides whether a backend route gets built, so its output is
// checked against cases whose answer was worked out from the contract directly — not against
// whatever it happened to produce. Three of these were WRONG in earlier versions of the analysis,
// each for a different reason, and each is kept as a regression:
//
//   plans        was reported unreachable because `/api/v1/plans` has no collection route. It is
//                reachable in two hops via exercises. Reachability is a graph, not a lookup.
//   manifests    was reported reachable, three separate times, by three different bugs: a
//                parameter-name collision, a schema with a bare `id` matching every space, and a
//                route producing the space it consumes.
//   audit        `GET /api/v1/audit` once appeared to unlock the entire API on its own.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ReachabilityUnmeasurable,
  analyseReachability,
  REASON_OWNER,
  type ContractDocument,
} from "./reachability";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const document = JSON.parse(
  readFileSync(join(REPO_ROOT, "contracts", "openapi", "openapi.json"), "utf8"),
) as ContractDocument;
const reachability = analyseReachability(document);

describe("the facts this analysis exists to get right", () => {
  it("finds plans through exercises, not through a /plans collection", () => {
    // `/api/v1/plans` has no GET. `GET /api/v1/exercises/{exercise_id}/plan` returns `PlanOut`,
    // which carries `id`, and exercises are enumerable. Two hops.
    expect(reachability.producedBy.get("api/v1/plans")).toBe(
      "GET /api/v1/exercises/{exercise_id}/plan",
    );
  });

  it("finds ranges directly, and range-templates by their slug", () => {
    expect(reachability.producedBy.get("api/v1/ranges")).toBe("GET /api/v1/ranges");
    // Slug-keyed, not id-keyed: the item schema carries `slug`, which is the space's key field.
    expect(reachability.producedBy.get("api/v1/range-templates")).toBe(
      "GET /api/v1/range-templates",
    );
  });

  it("reaches manifests now that a collection route exists, and still not provisioning-operations", () => {
    // This assertion USED to be the one real break: every GET yielding a manifest id needed a
    // manifest, a change-set or a provisioning-operation id, and those three formed a closed
    // cycle, so the only way in was `POST /api/v1/plans/{plan_id}/manifest` — creating, not
    // reading. `GET /api/v1/manifests` closed it.
    //
    // Kept rather than deleted, inverted, because it is the analysis's sharpest edge: the cycle
    // it detects is real, and one collection route is what breaks a cycle. Provisioning
    // operations are still inside one.
    expect(reachability.producedBy.get("api/v1/manifests")).toBe("GET /api/v1/manifests");
    expect(reachability.producedBy.has("api/v1/provisioning-operations")).toBe(false);
  });

  it("no longer blocks the change-sets route, because its one missing space was filled", () => {
    // The precision this test was written for paid off: it said ONE missing collection route,
    // not two, and exactly one route made the whole path reachable. Had it over-reported, an API
    // owner would have built something already reachable.
    const path = "/api/v1/manifests/{manifest_id}/change-sets";
    expect(reachability.isReachable(path)).toBe(true);
    expect(reachability.unreachableSpacesOf(path)).toEqual([]);
  });

  it("reaches teardown evidence, because ranges are enumerable", () => {
    // This is what makes `listEvidence` a frontend selection step and NOT a backend gap.
    expect(reachability.isReachable("/api/v1/ranges/{range_id}/teardown-evidence")).toBe(true);
  });

  it("does not let one audit route unlock the API", () => {
    // `AuditEventOut` has an `id`, and an earlier version matched a bare `id` against every space
    // whose plural fitted the key name. Reachability should not flow from an audit log.
    const viaAudit = [...reachability.producedBy].filter(([, via]) => via === "GET /api/v1/audit");
    expect(viaAudit).toEqual([]);
  });
});

describe("the analysis is conservative where the contract is ambiguous", () => {
  it("leaves a meaningful fraction of spaces unreachable rather than guessing", () => {
    // A run that reached everything would mean the rules had stopped discriminating. This is a
    // smoke check on the analysis itself, not a claim about the right number.
    expect(reachability.producedBy.size).toBeGreaterThan(10);
    expect(reachability.producedBy.size).toBeLessThan(reachability.spaces.size);
  });

  it("never produces a space from a route that consumes it", () => {
    // An item read hands back what you already had. Without this every `/X/{x_id}` bootstrapped
    // its own space and the whole contract looked reachable from itself.
    for (const [space, via] of reachability.producedBy) {
      const path = via.replace(/^GET /, "");
      expect(
        reachability.unreachableSpacesOf(path).concat(
          path.includes(`${space.split("/").pop()}/{`) ? [] : [],
        ),
      ).not.toContain(space);
      expect(path.startsWith(`/${space}/{`), `${space} produced by its own item read`).toBe(false);
    }
  });
});

describe("owners", () => {
  it("routes each reason to the side that can fix it", () => {
    // Mirrors UNAVAILABLE_OWNER in spatial/integrations/query-state.ts. The two are read together.
    expect(REASON_OWNER["no-endpoint"]).toBe("backend");
    expect(REASON_OWNER["parent-unreachable"]).toBe("backend");
    expect(REASON_OWNER["parent-not-selected"]).toBe("frontend");
  });
});

describe("it refuses to answer rather than reporting a confident nothing", () => {
  // The property none of the guards that bit this program today had. A traversal that stops
  // finding edges reports EVERY space as unreachable — indistinguishable from a real finding, and
  // this module's output decides whether backend routes get built. A confident wrong answer here
  // is a queue of gaps that are not gaps.

  it("refuses when no rule matches, instead of reporting the whole API unreachable", () => {
    // A contract whose schemas carry no identifier of any kind. Without the guard this returns a
    // perfectly well-formed result in which nothing is reachable, and every entry in the map
    // becomes `parent-unreachable` — seven fabricated backend tickets.
    const blind: ContractDocument = {
      paths: {
        "/api/v1/ranges": { get: okReturning("Thing") },
        "/api/v1/ranges/{range_id}": { get: okReturning("Thing") },
      },
      components: { schemas: { Thing: { properties: { name: {} } } } },
    };
    expect(() => analyseReachability(blind)).toThrow(ReachabilityUnmeasurable);
    expect(() => analyseReachability(blind)).toThrow(/matched nothing/);
  });

  it("refuses when there is nowhere to start", () => {
    const noSeed: ContractDocument = {
      paths: { "/api/v1/ranges/{range_id}": { get: okReturning("RangeOut") } },
      components: { schemas: { RangeOut: { properties: { id: {} } } } },
    };
    expect(() => analyseReachability(noSeed)).toThrow(/parameter-free GET route/);
  });

  it("refuses on a document shape it does not recognise", () => {
    expect(() => analyseReachability({ paths: {} })).toThrow(/declares no paths/);
    expect(() =>
      analyseReachability({ paths: { "/a": { get: {} } }, components: { schemas: {} } }),
    ).toThrow(/no component schemas/);
  });

  it("still answers for the real contract", () => {
    // The other half: a guard that refused everything would also be useless.
    expect(() => analyseReachability(document)).not.toThrow();
  });
});

/** A minimal 200-JSON operation returning `$ref` to `name`. */
function okReturning(name: string) {
  return {
    responses: {
      "200": {
        content: { "application/json": { schema: { $ref: `#/components/schemas/${name}` } } },
      },
    },
  };
}
