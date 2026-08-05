// The five states must stay five states.
//
// Every assertion here is about a COLLAPSE, not about a happy path. Each of the
// dangerous confusions renders something plausible: a refused query shown as
// empty looks like a quiet system, an outage shown as empty looks healthy, and
// an unavailable endpoint shown as empty looks like a platform with no records.
// So the tests assert that each pair is DISTINGUISHABLE, which is the property a
// renderer depends on and the one a careless refactor destroys.

import { describe, expect, it } from "vitest";

import {
  failed,
  loading,
  pageProvenance,
  provenanceOf,
  refused,
  rowsOf,
  served,
  unavailable,
  UNAVAILABLE_OWNER,
  type QueryState,
  type UnavailableReason,
} from "./query-state";

const ROW = { id: "1" };

describe("the five states are five states", () => {
  it("gives every state a distinct status", () => {
    const statuses = [
      loading().status,
      refused(["audit:read"]).status,
      unavailable("no-endpoint", "x").status,
      served([], "live").status,
      failed("boom").status,
      served([ROW], "live").status,
    ];
    expect(new Set(statuses).size).toBe(statuses.length);
  });

  it("does NOT collapse refused into empty", () => {
    // "You may not see this" and "there is nothing to see" are different facts,
    // and only one of them is about the data.
    expect(refused(["audit:read"]).status).not.toBe(served([], "live").status);
    const r = refused<typeof ROW>(["audit:read"]);
    expect(r.status).toBe("refused");
    if (r.status === "refused") expect(r.requires).toEqual(["audit:read"]);
  });

  it("does NOT collapse unavailable into empty", () => {
    // "No route serves this" is a statement about the platform, not the records.
    const u = unavailable<typeof ROW>("parent-unreachable", "no route enumerates manifests");
    expect(u.status).not.toBe("empty");
    if (u.status === "unavailable") {
      expect(u.reason).toBe("parent-unreachable");
      expect(u.detail).toContain("manifests");
    }
  });

  it("does NOT collapse failed into empty", () => {
    // The worst collapse of the five: an outage behind a clean screen looks
    // healthy, so nobody investigates.
    expect(failed("timeout").status).not.toBe(served([], "live").status);
  });

  it("distinguishes empty from ready rather than using rows.length", () => {
    // A renderer branching on `rows.length` would treat "served nothing" and
    // "not asked yet" identically. Zero rows is its own status.
    expect(served([], "live").status).toBe("empty");
    expect(served([ROW], "live").status).toBe("ready");
  });
});

describe("no state invents rows", () => {
  it("yields rows only when ready", () => {
    const states: QueryState<typeof ROW>[] = [
      loading(),
      refused(["p"]),
      unavailable("no-endpoint", "d"),
      served([], "live"),
      failed("e"),
    ];
    for (const s of states) expect(rowsOf(s), s.status).toEqual([]);
    expect(rowsOf(served([ROW], "live"))).toEqual([ROW]);
  });
});

describe("provenance is carried per query", () => {
  it("reports provenance only for states that actually served data", () => {
    // `empty` counts -- the answer was nothing, and nothing is an answer.
    expect(provenanceOf(served([ROW], "live"))).toBe("live");
    expect(provenanceOf(served([], "fixture"))).toBe("fixture");
    // These served nothing, so there is no provenance to report. A badge derived
    // from them would be describing data that does not exist.
    expect(provenanceOf(loading())).toBeNull();
    expect(provenanceOf(refused(["p"]))).toBeNull();
    expect(provenanceOf(unavailable("no-endpoint", "d"))).toBeNull();
    expect(provenanceOf(failed("e"))).toBeNull();
  });

  it("folds a page to FIXTURE when any query is fixture-backed", () => {
    // The absorbing rule: one live reading plus one fixture panel is a fixture
    // page. The cautious claim wins.
    expect(pageProvenance([served([ROW], "live"), served([ROW], "fixture")])).toBe("fixture");
    expect(pageProvenance([served([ROW], "fixture"), served([ROW], "live")])).toBe("fixture");
  });

  it("folds to LIVE only when every serving query is live", () => {
    expect(pageProvenance([served([ROW], "live"), served([], "live")])).toBe("live");
  });

  it("ignores queries that served nothing, in both directions", () => {
    // A refused query must not drag a live page to fixture, and must not make a
    // fixture page look live either.
    expect(pageProvenance([served([ROW], "live"), refused(["p"])])).toBe("live");
    expect(pageProvenance([served([ROW], "fixture"), failed("e")])).toBe("fixture");
    expect(pageProvenance([loading(), refused(["p"])])).toBeNull();
  });

  it("returns null rather than guessing when nothing has served", () => {
    // Defaulting to "live" here would label an unloaded page as a real reading.
    expect(pageProvenance([])).toBeNull();
    expect(pageProvenance([loading()])).toBeNull();
  });
});

describe("unavailable reasons fund different work", () => {
  it("assigns an owner to every reason, exhaustively", () => {
    // `satisfies Record<UnavailableReason, ...>` makes a new reason without an
    // owner a compile error. This asserts the runtime shape too, so the mapping
    // cannot be emptied without a test failing as well as the build.
    const reasons: UnavailableReason[] = [
      "no-endpoint",
      "parent-unreachable",
      "parent-not-selected",
    ];
    for (const r of reasons) {
      expect(UNAVAILABLE_OWNER[r], r).toMatch(/^(backend|frontend)$/);
    }
    expect(Object.keys(UNAVAILABLE_OWNER).sort()).toEqual([...reasons].sort());
  });

  it("puts TWO of the three on the backend, not one", () => {
    // The distinction that earns the three-way split: `no-endpoint` needs a new
    // route and `parent-unreachable` needs a new COLLECTION route -- different
    // asks, both backend. Only the unselected parent is frontend work.
    const backend = Object.entries(UNAVAILABLE_OWNER)
      .filter(([, owner]) => owner === "backend")
      .map(([reason]) => reason)
      .sort();
    expect(backend).toEqual(["no-endpoint", "parent-unreachable"]);
    expect(UNAVAILABLE_OWNER["parent-not-selected"]).toBe("frontend");
  });
});
