// The map is only worth having if it cannot lie.
//
// A prose table of "method → endpoint" is correct on the day it is written and silently wrong
// afterwards: routes get renamed, added, and removed, and nothing tells the table. So every claim
// in `adapter-endpoint-map.ts` is re-resolved here against `contracts/openapi/openapi.json` — the
// document exported from the live FastAPI app, and the same one the CI staleness guard pins to the
// running code. A renamed route fails this file; a route added by P7-A that serves an `absent`
// method fails it too, which is the point — that is the moment somebody should be told.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ADAPTER_ENDPOINT_MAP,
  ADAPTER_METHODS,
  UNSERVED_METHOD_PROBES,
  CREDENTIAL_INVENTORY_SEGMENTS,
  hasCredentialInventorySegment,
  MISSING_SURFACES,
  servedMethods,
  unservedMethods,
} from "./adapter-endpoint-map";
import { analyseReachability, type ContractDocument } from "./reachability";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const CONTRACT = join(REPO_ROOT, "contracts", "openapi", "openapi.json");

const document = JSON.parse(readFileSync(CONTRACT, "utf8")) as {
  paths: Record<string, Record<string, unknown>>;
};
const REGISTERED = new Set(Object.keys(document.paths));

describe("the map covers the adapter exactly", () => {
  it("has an entry for every declared method and no others", () => {
    // Set equality in BOTH directions. A method covered twice, or a method covered by nothing,
    // are different bugs and both are silent — the first shadows, the second reads as "no comment".
    const mapped = ADAPTER_ENDPOINT_MAP.map((m) => m.method);
    expect([...mapped].sort()).toEqual([...ADAPTER_METHODS].sort());
    expect(new Set(mapped).size, "a method is mapped twice").toBe(mapped.length);
  });

  it("covers 22 methods, the number the spatial adapter declares", () => {
    expect(ADAPTER_METHODS).toHaveLength(22);
  });
});

describe("every endpoint claimed is an endpoint that exists", () => {
  const claims = ADAPTER_ENDPOINT_MAP.flatMap((m) =>
    m.endpoints.map((path) => [m.method, path] as const),
  );

  it("claims at least one endpoint (guards the loop against covering nothing)", () => {
    expect(claims.length).toBeGreaterThan(15);
  });

  it.each(claims)("%s → %s is registered on the live app", (_method, path) => {
    expect(
      REGISTERED.has(path),
      `${path} is not in contracts/openapi/openapi.json. Either the route was renamed or ` +
        "removed, or this claim was never true. Do not delete the assertion — fix the mapping.",
    ).toBe(true);
  });
});

describe("absent means absent", () => {
  it("declares no endpoint for a method nothing serves", () => {
    for (const mapping of unservedMethods()) {
      expect(mapping.endpoints, `${mapping.method} is ${mapping.status} but names an endpoint`)
        .toEqual([]);
    }
  });

  it("says what would have to be added, for every unserved method", () => {
    // A gap with no stated remedy is a gap that gets rediscovered. `requires` is the message to
    // whoever owns the API, and `listSecretRefs` uses it to say the opposite: do not add this.
    for (const mapping of unservedMethods()) {
      expect(mapping.requires, `${mapping.method} has no \`requires\``).toBeTruthy();
      expect((mapping.requires ?? "").length).toBeGreaterThan(30);
    }
  });

  it("keeps the secrets surface withheld rather than merely missing", () => {
    // `absent` invites someone to close the gap. `withheld` says the gap is the feature.
    const secrets = ADAPTER_ENDPOINT_MAP.find((m) => m.method === "listSecretRefs");
    expect(secrets?.status).toBe("withheld");
    expect(secrets?.requires).toMatch(/must stay unimplemented|NOTHING/);
  });

  it("has no route anywhere that would serve a withheld method", () => {
    // The real guard: not "we chose not to call it" but "there is nothing to call". If a
    // credential-inventory route ever appears, this fails and the decision gets re-made.
    const inventoryRoutes = [...REGISTERED].filter(hasCredentialInventorySegment);
    expect(
      inventoryRoutes,
      "a credential-inventory route has appeared in the contract. listSecretRefs is withheld " +
        "deliberately — re-make that decision explicitly rather than wiring it up.",
    ).toEqual([]);
  });

  it("uses a detector that is populated and discriminating", () => {
    // The clause that keeps the guard above honest: a predicate matching nothing would pass over
    // an empty set forever.
    //
    // Checked against SEGMENTS rather than by composing a route path. `apps/api/tests/
    // test_readonly_preflight_security.py` forbids frontend source from carrying any such route
    // literal at all, and it is right to — a lexical guard cannot tell "references a route" from
    // "asserts no such route exists", and the repair for a guard that catches you is never to
    // weaken it. Nothing is lost here: the risk this clause addresses is a member set that is
    // empty or populated with the wrong names, which is precisely what it asserts against.
    expect(CREDENTIAL_INVENTORY_SEGMENTS.size).toBeGreaterThan(2);
    expect(CREDENTIAL_INVENTORY_SEGMENTS.has("vault")).toBe(true);
    expect(CREDENTIAL_INVENTORY_SEGMENTS.has("ranges")).toBe(false);
    expect(CREDENTIAL_INVENTORY_SEGMENTS.has("targets")).toBe(false);
    // And the splitting works: an ordinary route is not matched by accident.
    expect(hasCredentialInventorySegment("/api/v1/ranges")).toBe(false);
    expect(hasCredentialInventorySegment([".", "api", "vault"].join("/"))).toBe(true);
  });
});

describe("parent reachability is computed, not judged", () => {
  // THE THIRD CHECKING DIRECTION. The map verifies claimed endpoints exist; the probes verify
  // unserved methods are still unserved. Neither can see an entry that is SERVED by a route
  // nobody can reach — it passes both and still cannot be built.
  //
  // `listApprovals` is that case: GET /manifests/{manifest_id}/change-sets exists and works, and
  // nothing enumerates manifests. Marking it `shaped` invited someone to wire it.
  const reachability = analyseReachability(document as unknown as ContractDocument);

  it("agrees with every entry's recorded status", () => {
    for (const mapping of ADAPTER_ENDPOINT_MAP) {
      if (mapping.endpoints.length === 0) continue;
      const anyReachable = mapping.endpoints.some((path) => reachability.isReachable(path));
      if (mapping.status === "parent-unreachable") {
        expect(
          anyReachable,
          `${mapping.method} is recorded parent-unreachable, but ${mapping.endpoints.find((p) => reachability.isReachable(p))} is reachable`,
        ).toBe(false);
      } else {
        expect(
          anyReachable,
          `${mapping.method} is recorded '${mapping.status}' but none of its endpoints is ` +
            `reachable — blocked by ${mapping.endpoints.flatMap((p) => reachability.unreachableSpacesOf(p)).join(", ")}. ` +
            "It is parent-unreachable: the route exists and nothing enumerates the id it needs.",
        ).toBe(true);
      }
    }
  });

  it("no longer blocks approvals, because the one space it named was filled", () => {
    // This named ONE missing collection route, not two — reporting two would have sent the API
    // owner to build something already reachable (plans, via exercises). Exactly one route,
    // `GET /api/v1/manifests`, made it reachable, so the precision was worth having.
    //
    // Inverted rather than deleted: what it now proves is that the approvals gap is a SHAPE
    // problem, not a reachability one, which is a different job for a different owner.
    const approvals = ADAPTER_ENDPOINT_MAP.find((m) => m.method === "listApprovals");
    const blocked = (approvals?.endpoints ?? []).flatMap((p) =>
      reachability.unreachableSpacesOf(p),
    );
    expect([...new Set(blocked)]).toEqual([]);
    expect(approvals?.status).toBe("shaped");
  });

  it("keeps listEvidence off the backend list, because ranges are enumerable", () => {
    const evidence = MISSING_SURFACES.find((s) => s.method === "listEvidence");
    expect(evidence?.owner).toBe("frontend");
    expect(reachability.isReachable("/api/v1/ranges/{range_id}/teardown-evidence")).toBe(true);
  });
});

describe("absent is checked, not asserted", () => {
  // The direction the map did NOT verify, and the reason it needed to. `listApprovals` said
  // `absent` while `GET /manifests/{id}/change-sets` had started enumerating change-set
  // approvals. Verifying only that claimed endpoints EXIST leaves the optimistic error
  // unguarded: a gap that has since closed, still recorded as open, with a frontend working
  // around it.
  const unserved = unservedMethods().map((m) => m.method);

  it("has a probe for every unserved method", () => {
    // Set equality, so adding an `absent` method without a probe fails rather than being
    // silently exempt from the check.
    expect([...unserved].sort()).toEqual(Object.keys(UNSERVED_METHOD_PROBES).sort());
  });

  it.each(unserved)("%s: no registered route looks like it serves this", (method) => {
    const probe = UNSERVED_METHOD_PROBES[method];
    const matches = [...REGISTERED].filter(probe);
    expect(
      matches,
      `${method} is recorded as unserved, but these routes now exist: ${matches.join(", ")}. ` +
        "Re-decide the entry — either they serve it and the status changes, or they do not and " +
        "the probe is too broad. Do not delete the assertion.",
    ).toEqual([]);
  });

  it("uses probes that can actually match something", () => {
    // A predicate that matched nothing would pass over any API forever. Each is exercised
    // against a path shaped like the route it is watching for.
    expect(UNSERVED_METHOD_PROBES.listEvents("/api/v1/competitions")).toBe(true);
    expect(UNSERVED_METHOD_PROBES.listAlerts("/api/v1/alerts")).toBe(true);
    expect(UNSERVED_METHOD_PROBES.listReports("/api/v1/reports")).toBe(true);
    expect(UNSERVED_METHOD_PROBES.listUsers("/api/v1/users")).toBe(true);
    expect(UNSERVED_METHOD_PROBES.listAccessProfiles("/api/v1/access-profiles")).toBe(true);
    // And none of them fires on an ordinary route.
    for (const probe of Object.values(UNSERVED_METHOD_PROBES)) {
      expect(probe("/api/v1/ranges/{range_id}/proxmox/plan")).toBe(false);
    }
  });
});

describe("served methods name what they cannot supply", () => {
  it("lists unsourced fields wherever the shape differs", () => {
    // `shaped` without `unsourcedFields` is the dangerous combination: it reads as "this works"
    // while the difference that makes it not work is undocumented.
    for (const mapping of servedMethods()) {
      if (mapping.status !== "shaped") continue;
      if (mapping.method === "getTopology") continue; // opaque payload, not a field mismatch
      expect(
        mapping.unsourcedFields.length,
        `${mapping.method} is 'shaped' but names no unsourced field`,
      ).toBeGreaterThan(0);
    }
  });

  it("explains each mapping in prose a reviewer can check", () => {
    for (const mapping of ADAPTER_ENDPOINT_MAP) {
      expect(mapping.note.length, `${mapping.method} has no note`).toBeGreaterThan(40);
    }
  });
});

describe("the traps the map exists to prevent", () => {
  it("does not wire listEvents to the range EVENT LOG", () => {
    // `RangeEventOut` is a log line — kind, level, message, sequence. An `EventItem` is a
    // scheduled competition. The route name makes the wrong wiring look right, and it would put
    // log lines on a competition screen.
    const events = ADAPTER_ENDPOINT_MAP.find((m) => m.method === "listEvents");
    expect(events?.endpoints).not.toContain("/api/v1/ranges/{range_id}/events");
    expect(events?.status).toBe("absent");
  });

  it("records that listWorkers needs BOTH sources, not either", () => {
    // One endpoint alone silently drops a whole class of worker: enrolled but never published
    // keys, or published keys with no enrollment. Both are real states.
    const workers = ADAPTER_ENDPOINT_MAP.find((m) => m.method === "listWorkers");
    expect(workers?.endpoints).toHaveLength(2);
    expect(workers?.endpoints).toContain("/api/v1/enrollment");
  });

  it("records the scoping mismatches rather than leaving them to be discovered at runtime", () => {
    // Three methods take an id the routes cannot use. That is a contract problem, not a bug to
    // find in a component: `listTeams(eventId?)` optional vs a required range id, and
    // `listScores(eventId)` against range/competition-keyed routes.
    for (const method of ["listTeams", "listParticipants", "listScores"]) {
      const mapping = ADAPTER_ENDPOINT_MAP.find((m) => m.method === method);
      expect(mapping?.note, `${method} does not record its scoping mismatch`).toMatch(
        /SCOPING MISMATCH|SIGNATURE MISMATCH|Reachable only as/,
      );
    }
  });
});
