// Enrollment inventory view model.
//
// The properties under test are the ones that stop a paged, server-ordered, server-filtered list
// from quietly becoming a lie: counts that describe only what was loaded, an order that is never
// re-derived, a cursor that is never interpreted, and a filter that is always pushed to the server.

import { describe, expect, it } from "vitest";

import type { EnrollmentStatus } from "../api/types";
import {
  ATTENTION_STATES,
  COMPLETE_NOTICE,
  EMPTY_PAGE,
  INVENTORY_ERROR_TEXT,
  MORE_MAY_REMAIN_NOTICE,
  PAGE_INTEGRITY_CODE,
  PAGE_INTEGRITY_STEPS,
  INVENTORY_SCOPES,
  PAGE_SIZE_DEFAULT,
  PAGE_SIZE_MAX,
  PARTIAL_COUNT_NOTICE,
  PENDING_STATES,
  SCOPE_DESCRIPTIONS,
  SCOPE_LABELS,
  appendPage,
  clampPageSize,
  emptyScopeBody,
  findEnrollment,
  inventoryRevokeGate,
  inventoryRow,
  inventoryRows,
  inventorySummary,
  isInventoryScope,
  listGate,
  loadMoreGate,
  replaceRow,
  isPageIntegrityFailure,
  scopeStates,
  type InventoryPage,
} from "./enrollment-inventory";
import {
  ENROLLMENT_ERROR_TEXT,
  ENROLLMENT_FORWARD_STATES,
  MISSING_READ_REASON,
} from "./worker-enrollment";

const NOW = Date.parse("2026-07-30T10:00:00+00:00");
const LATER = "2026-07-30T11:00:00+00:00";
const EARLIER = "2026-07-30T09:00:00+00:00";

function id(char: string): string {
  return "sha256:" + char.repeat(64);
}

function status(over: Partial<EnrollmentStatus> = {}): EnrollmentStatus {
  return {
    enrollment_id: id("a"),
    state: "invited",
    revision: 0,
    controller_installation_id: "controller-aaaaaaaa",
    controller_key_fingerprint: "cccccccccccc",
    worker_installation_id: "",
    worker_key_fingerprint: "",
    release_fingerprint: "eeeeeeeeeeee",
    offer_fingerprint: "",
    result_fingerprint: "",
    expires_at: LATER,
    updated_at: "2026-07-30T10:00:00+00:00",
    refusal_reason: "",
    deployment_site_label: "site-one",
    ...over,
  };
}

function page(items: EnrollmentStatus[], cursor: string | null = null): InventoryPage {
  return appendPage(EMPTY_PAGE, { items, next_cursor: cursor });
}

// --------------------------------------------------------------------- scopes

describe("scopes", () => {
  it("names every scope and describes what it asks for", () => {
    for (const scope of INVENTORY_SCOPES) {
      expect(SCOPE_LABELS[scope], scope).toBeTruthy();
      expect(SCOPE_DESCRIPTIONS[scope].length, scope).toBeGreaterThan(40);
      expect(emptyScopeBody(scope).length, scope).toBeGreaterThan(30);
    }
  });

  it("recognises exactly the closed scope set", () => {
    for (const scope of INVENTORY_SCOPES) expect(isInventoryScope(scope)).toBe(true);
    expect(isInventoryScope("everything")).toBe(false);
    expect(isInventoryScope("")).toBe(false);
    // Prototype keys must not resolve as scopes.
    expect(isInventoryScope("constructor")).toBe(false);
  });

  it("splits the forward lifecycle so healthy is the worker inventory and the rest is the queue", () => {
    expect(scopeStates("workers")).toEqual(["healthy"]);
    expect(PENDING_STATES).toEqual(
      ENROLLMENT_FORWARD_STATES.filter((s) => s !== "healthy"),
    );
    expect(scopeStates("queue")).toEqual(PENDING_STATES);
    expect(scopeStates("queue")).not.toContain("healthy");
  });

  it("puts both terminals under the attention scope", () => {
    expect(ATTENTION_STATES).toEqual(["refused", "recovery_required"]);
    expect(scopeStates("attention")).toEqual(ATTENTION_STATES);
  });

  /**
   * The load-bearing one. "Everything" must send NO state parameter rather than enumerate the
   * closed set: a controller that grows a state this build has never heard of would otherwise have
   * that state permanently invisible in every scope, which is exactly the failure the unknown-state
   * counter exists to make visible.
   */
  it("sends no state filter at all for the everything scope", () => {
    expect(scopeStates("all")).toEqual([]);
  });
});

// --------------------------------------------------------------------- paging

describe("page size", () => {
  it("keeps a sane request inside the server's documented bounds", () => {
    expect(clampPageSize(PAGE_SIZE_DEFAULT)).toBe(PAGE_SIZE_DEFAULT);
    expect(clampPageSize(PAGE_SIZE_MAX)).toBe(PAGE_SIZE_MAX);
    expect(clampPageSize(PAGE_SIZE_MAX + 1)).toBe(PAGE_SIZE_MAX);
    expect(clampPageSize(0)).toBe(1);
    expect(clampPageSize(-5)).toBe(1);
    expect(clampPageSize(12.7)).toBe(12);
    expect(clampPageSize(Number.NaN)).toBe(PAGE_SIZE_DEFAULT);
    expect(clampPageSize(Number.POSITIVE_INFINITY)).toBe(PAGE_SIZE_DEFAULT);
  });
});

describe("accumulating pages", () => {
  it("starts from nothing loaded, which is not the same as an empty result", () => {
    expect(EMPTY_PAGE.pages).toBe(0);
    expect(EMPTY_PAGE.items).toEqual([]);
    // `complete` must be false before anything is loaded — otherwise an unloaded page would claim
    // to be a complete count of zero.
    expect(inventorySummary(EMPTY_PAGE, NOW).complete).toBe(false);
  });

  it("appends the next page in server order without reordering", () => {
    const first = page([status({ enrollment_id: id("a") })], "cursor-1");
    const next = appendPage(first, {
      items: [status({ enrollment_id: id("b") })],
      next_cursor: null,
    });
    expect(next.items.map((i) => i.enrollment_id)).toEqual([id("a"), id("b")]);
    expect(next.pages).toBe(2);
    expect(next.cursor).toBeNull();
  });

  it("replaces a repeated id in place rather than growing a second row", () => {
    const first = page([status({ enrollment_id: id("a"), revision: 1 }), status({ enrollment_id: id("b") })], "c1");
    const next = appendPage(first, {
      items: [status({ enrollment_id: id("a"), revision: 2, state: "worker_bound" })],
      next_cursor: null,
    });
    expect(next.items).toHaveLength(2);
    expect(next.items[0].state).toBe("worker_bound");
    // still first: a refresh must not make a row jump
    expect(next.items.map((i) => i.enrollment_id)).toEqual([id("a"), id("b")]);
  });

  it("discards a row whose revision has gone backwards", () => {
    const first = page([status({ revision: 5, state: "verified" })], "c1");
    const next = appendPage(first, {
      items: [status({ revision: 4, state: "worker_bound" })],
      next_cursor: null,
    });
    expect(next.items[0].revision).toBe(5);
    expect(next.items[0].state).toBe("verified");
  });

  it("treats the cursor as the only end-of-list signal", () => {
    // A short page is permitted and must NOT be read as the end.
    const short = page([status()], "cursor-1");
    expect(inventorySummary(short, NOW).complete).toBe(false);
    expect(short.cursor).toBe("cursor-1");
    const done = appendPage(short, { items: [], next_cursor: null });
    expect(inventorySummary(done, NOW).complete).toBe(true);
  });
});

describe("replacing one observed row", () => {
  it("updates in place without reordering or changing the cursor", () => {
    const loaded = page(
      [status({ enrollment_id: id("a") }), status({ enrollment_id: id("b"), revision: 1 })],
      "cursor-9",
    );
    const after = replaceRow(loaded, status({ enrollment_id: id("b"), revision: 2, state: "refused" }));
    expect(after.items.map((i) => i.enrollment_id)).toEqual([id("a"), id("b")]);
    expect(after.items[1].state).toBe("refused");
    expect(after.cursor).toBe("cursor-9");
    expect(after.pages).toBe(loaded.pages);
  });

  it("ignores a record that is not loaded, and one whose revision went backwards", () => {
    const loaded = page([status({ revision: 3 })]);
    expect(replaceRow(loaded, status({ enrollment_id: id("z") }))).toBe(loaded);
    expect(replaceRow(loaded, status({ revision: 2 })).items[0].revision).toBe(3);
  });
});

describe("finding a selected record", () => {
  it("resolves only from what is loaded, and never from a null selection", () => {
    const loaded = page([status({ enrollment_id: id("a") })]);
    expect(findEnrollment(loaded, id("a"))?.enrollment_id).toBe(id("a"));
    expect(findEnrollment(loaded, id("z"))).toBeNull();
    expect(findEnrollment(loaded, null)).toBeNull();
  });
});

// --------------------------------------------------------------------- rows

describe("row projection", () => {
  it("carries the site label from the projection and never guesses one", () => {
    expect(inventoryRow(status(), NOW).siteLabel).toBe("site-one");
    const older = status();
    delete (older as { deployment_site_label?: string }).deployment_site_label;
    expect(inventoryRow(older, NOW).siteLabel).toBe("");
  });

  it("shows a worker identity only once the worker has bound", () => {
    expect(inventoryRow(status(), NOW).workerInstallationId).toBe("");
    expect(
      inventoryRow(status({ worker_installation_id: "worker-one" }), NOW)
        .workerInstallationId,
    ).toBe("worker-one");
  });

  it("keeps the raw expiry alongside the derived view", () => {
    const row = inventoryRow(status({ expires_at: LATER }), NOW);
    expect(row.expiresAt).toBe(LATER);
    expect(row.expiry.expired).toBe(false);
    expect(row.expiry.label).toContain("Expires in");
  });

  it("flags an unfinished record past its expiry, but never a finished one", () => {
    expect(inventoryRow(status({ expires_at: EARLIER }), NOW).pastExpiry).toBe(true);
    expect(
      inventoryRow(status({ state: "healthy", expires_at: EARLIER }), NOW).pastExpiry,
    ).toBe(false);
    expect(
      inventoryRow(status({ state: "refused", expires_at: EARLIER }), NOW).pastExpiry,
    ).toBe(false);
    expect(
      inventoryRow(status({ state: "recovery_required", expires_at: EARLIER }), NOW)
        .pastExpiry,
    ).toBe(false);
  });

  it("never invents a past-expiry flag from an unparseable timestamp", () => {
    const row = inventoryRow(status({ expires_at: "not a date" }), NOW);
    expect(row.expiry.valid).toBe(false);
    expect(row.pastExpiry).toBe(false);
  });

  it("preserves the order the controller returned", () => {
    const loaded = page([
      status({ enrollment_id: id("c"), expires_at: EARLIER }),
      status({ enrollment_id: id("a"), expires_at: LATER }),
      status({ enrollment_id: id("b"), expires_at: LATER }),
    ]);
    expect(inventoryRows(loaded, NOW).map((r) => r.enrollmentId)).toEqual([
      id("c"),
      id("a"),
      id("b"),
    ]);
  });

  it("shows a bounded refusal code verbatim and nothing when there is none", () => {
    expect(inventoryRow(status(), NOW).refusalReason).toBe("");
    expect(
      inventoryRow(status({ state: "refused", refusal_reason: "operator_revoked" }), NOW)
        .refusalReason,
    ).toBe("operator_revoked");
  });
});

// --------------------------------------------------------------------- summary

describe("summary", () => {
  const mixed = page(
    [
      status({ enrollment_id: id("1"), state: "healthy" }),
      status({ enrollment_id: id("2"), state: "invited" }),
      status({ enrollment_id: id("3"), state: "worker_bound", expires_at: EARLIER }),
      status({ enrollment_id: id("4"), state: "refused" }),
      status({ enrollment_id: id("5"), state: "recovery_required" }),
      status({ enrollment_id: id("6"), state: "a_state_from_the_future" }),
    ],
    "cursor-next",
  );

  it("counts each lifecycle group separately", () => {
    const s = inventorySummary(mixed, NOW);
    expect(s.loaded).toBe(6);
    expect(s.workers).toBe(1);
    expect(s.queue).toBe(2);
    expect(s.attention).toBe(2);
    expect(s.unknown).toBe(1);
    expect(s.pastExpiry).toBe(1);
  });

  /** An unrecognised state must never be filed as progress. */
  it("counts an unknown state on its own rather than as pending", () => {
    const s = inventorySummary(page([status({ state: "a_state_from_the_future" })]), NOW);
    expect(s.unknown).toBe(1);
    expect(s.queue).toBe(0);
    expect(s.workers).toBe(0);
    expect(s.attention).toBe(0);
  });

  it("reports incomplete while a cursor remains and complete only when it is null", () => {
    expect(inventorySummary(mixed, NOW).complete).toBe(false);
    const done = appendPage(mixed, { items: [], next_cursor: null });
    expect(inventorySummary(done, NOW).complete).toBe(true);
  });

  // The counts are of loaded rows. Both sentences must say so, in opposite directions.
  it("has copy for both the partial and the complete case", () => {
    expect(PARTIAL_COUNT_NOTICE).toContain("rows loaded");
    expect(PARTIAL_COUNT_NOTICE).toContain("not your whole organization");
    expect(COMPLETE_NOTICE).toContain("Every page has been loaded");
  });
});

// --------------------------------------------------------------------- gates

describe("gates", () => {
  const READ = { read: true, manage: false };
  const MANAGE = { read: false, manage: true };
  const BOTH = { read: true, manage: true };
  const NONE = { read: false, manage: false };

  it("requires enrollment:read to list, and says so by name", () => {
    expect(listGate(READ, false).ok).toBe(true);
    expect(listGate(NONE, false)).toEqual({ ok: false, reason: MISSING_READ_REASON });
    // manage does NOT imply read
    expect(listGate(MANAGE, false).ok).toBe(false);
    expect(listGate(READ, true).ok).toBe(false);
  });

  it("offers load-more only when the server said there is another page", () => {
    expect(loadMoreGate(READ, EMPTY_PAGE, false).ok).toBe(false);
    expect(loadMoreGate(READ, EMPTY_PAGE, false).reason).toContain("Load the list first");

    const more = page([status()], "cursor-1");
    expect(loadMoreGate(READ, more, false).ok).toBe(true);
    expect(loadMoreGate(READ, more, true).ok).toBe(false);

    const done = page([status()], null);
    expect(loadMoreGate(READ, done, false).ok).toBe(false);
    expect(loadMoreGate(READ, done, false).reason).toContain("Every page has been loaded");
  });

  it("requires enrollment:manage to revoke and explains that read is not enough", () => {
    const selected = status();
    expect(inventoryRevokeGate(READ, selected, false).ok).toBe(false);
    expect(inventoryRevokeGate(READ, selected, false).reason).toContain("enrollment:manage");
    expect(inventoryRevokeGate(READ, selected, false).reason).toContain("enrollment:read");
    expect(inventoryRevokeGate(BOTH, selected, false).ok).toBe(true);
  });

  it("refuses to offer revoke without a selected record", () => {
    expect(inventoryRevokeGate(BOTH, null, false).ok).toBe(false);
    expect(inventoryRevokeGate(BOTH, null, false).reason).toContain("Select an enrollment");
  });

  it("refuses to offer revoke on a record that already ended", () => {
    const refused = inventoryRevokeGate(BOTH, status({ state: "refused" }), false);
    expect(refused.ok).toBe(false);
    expect(refused.reason).toContain("already refused");

    const recovery = inventoryRevokeGate(
      BOTH,
      status({ state: "recovery_required" }),
      false,
    );
    expect(recovery.ok).toBe(false);
    expect(recovery.reason).toContain("recovery");
  });

  it("never returns an unavailable gate without a reason", () => {
    const gates = [
      listGate(NONE, false),
      loadMoreGate(READ, EMPTY_PAGE, false),
      inventoryRevokeGate(READ, status(), false),
      inventoryRevokeGate(BOTH, null, false),
      inventoryRevokeGate(BOTH, status({ state: "refused" }), false),
      inventoryRevokeGate(BOTH, status(), true),
    ];
    for (const gate of gates) {
      expect(gate.ok).toBe(false);
      expect((gate.reason ?? "").length, JSON.stringify(gate)).toBeGreaterThan(10);
    }
  });
});

// --------------------------------------------------------------------- page integrity

describe("a page refused because one row cannot be projected", () => {
  /**
   * The controller fails the WHOLE page rather than dropping the row, deliberately: omitting it
   * would tell an operator an enrollment does not exist. The consequence is that a single bad
   * record makes a whole page unreadable, and the interface has to distinguish that from the two
   * other ways a table ends up empty.
   */
  it("recognises the code the controller actually returns", () => {
    // Read off the shipped service: a projection failure raises the same state_corrupt code a
    // single-record read does. If that ever becomes a distinct code, this is the one place to change.
    expect(PAGE_INTEGRITY_CODE).toBe("enrollment_state_corrupt");
    expect(isPageIntegrityFailure(PAGE_INTEGRITY_CODE)).toBe(true);
    expect(isPageIntegrityFailure("api_unreachable")).toBe(false);
    expect(isPageIntegrityFailure("enrollment_forbidden")).toBe(false);
    expect(isPageIntegrityFailure(null)).toBe(false);
    expect(isPageIntegrityFailure(undefined)).toBe(false);
  });

  /** The shared map says "the enrollment you asked for"; on a list that would be wrong. */
  it("says something different from the single-record copy for the same code", () => {
    const shared = ENROLLMENT_ERROR_TEXT[PAGE_INTEGRITY_CODE];
    const page = INVENTORY_ERROR_TEXT[PAGE_INTEGRITY_CODE];
    expect(shared).toBeTruthy();
    expect(page).toBeTruthy();
    expect(page).not.toBe(shared);
    expect(page).toContain("One enrollment on this page");
    expect(page).toContain("refused the whole page");
    // and it must not leave the operator thinking rows went missing
    expect(page).toContain("Nothing is missing");
  });

  it("layers over the shared map rather than replacing it", () => {
    for (const code of Object.keys(ENROLLMENT_ERROR_TEXT)) {
      expect(INVENTORY_ERROR_TEXT, code).toHaveProperty(code);
    }
    // an unrelated code keeps its shared copy exactly
    expect(INVENTORY_ERROR_TEXT.enrollment_forbidden).toBe(
      ENROLLMENT_ERROR_TEXT.enrollment_forbidden,
    );
  });

  it("carries the list-route codes the controller can actually return", () => {
    for (const code of ["enrollment_cursor_invalid", "enrollment_state_invalid"]) {
      expect(INVENTORY_ERROR_TEXT[code], code).toBeTruthy();
      expect(INVENTORY_ERROR_TEXT[code].length, code).toBeGreaterThan(40);
    }
  });

  it("gives the operator steps that are true today", () => {
    expect(PAGE_INTEGRITY_STEPS.length).toBeGreaterThan(2);
    const all = PAGE_INTEGRITY_STEPS.join(" ");
    expect(all).toContain("preserved, not repaired");
    expect(all).toContain("No row was silently dropped");
    expect(all).toContain("different lifecycle filter");
    // No step may promise a skip-past-the-bad-row control: the failing keyset position is not in
    // the error body, so this interface could not aim one.
    expect(all).not.toMatch(/skip past|continue past|advance past/i);
  });
});

describe("cursor semantics as the controller actually implements them", () => {
  /**
   * `next_cursor` is non-null whenever a page came back FULL, which includes the case where the
   * page after it is empty. "More pages remain" would therefore be a claim the response does not
   * support, and the copy says the weaker true thing instead.
   */
  it("says there may be more, not that there certainly are", () => {
    expect(MORE_MAY_REMAIN_NOTICE).toContain("came back full");
    expect(MORE_MAY_REMAIN_NOTICE).toContain("does not guarantee");
    expect(MORE_MAY_REMAIN_NOTICE).not.toMatch(/more pages remain/i);
  });

  /** The real end-of-list shape: a full page yields a cursor, and the next page returns nothing. */
  it("completes cleanly when a full page is followed by an empty one", () => {
    const full = page([status({ enrollment_id: id("a") })], "cursor-1");
    expect(inventorySummary(full, NOW).complete).toBe(false);
    const after = appendPage(full, { items: [], next_cursor: null });
    expect(after.items).toHaveLength(1);
    expect(after.pages).toBe(2);
    expect(inventorySummary(after, NOW).complete).toBe(true);
  });
});

// --------------------------------------------------------------------- no client-side row loss

/**
 * The controller fails a whole page rather than omitting a row it cannot project, precisely so an
 * operator is never told an enrollment does not exist. A client that dropped rows would re-create
 * that defect one layer up, where no backend decision can protect against it — so "every row the
 * server returned is rendered" is pinned directly rather than left as a property of the code.
 */
describe("no row is ever dropped client-side", () => {
  it("renders one row per item, for every state including ones it does not recognise", () => {
    const items = [
      status({ enrollment_id: id("1"), state: "invited" }),
      status({ enrollment_id: id("2"), state: "healthy" }),
      status({ enrollment_id: id("3"), state: "refused" }),
      status({ enrollment_id: id("4"), state: "recovery_required" }),
      status({ enrollment_id: id("5"), state: "a_state_from_the_future" }),
      status({ enrollment_id: id("6"), state: "" }),
    ];
    const loaded = page(items);
    const rows = inventoryRows(loaded, NOW);
    expect(rows).toHaveLength(items.length);
    expect(rows.map((r) => r.enrollmentId)).toEqual(items.map((i) => i.enrollment_id));
  });

  it("keeps a row whose fields are blank or unparseable rather than filtering it out", () => {
    const awkward = [
      status({ enrollment_id: id("7"), expires_at: "not a date" }),
      status({ enrollment_id: id("8"), expires_at: "" }),
      status({ enrollment_id: id("9"), worker_installation_id: "", refusal_reason: "" }),
    ];
    const rows = inventoryRows(page(awkward), NOW);
    expect(rows).toHaveLength(3);
    // the unparseable expiry is reported as unavailable, not silently treated as expired
    expect(rows[0].expiry.valid).toBe(false);
    expect(rows[0].pastExpiry).toBe(false);
  });

  it("counts every loaded row in exactly one summary group", () => {
    const items = [
      status({ enrollment_id: id("1"), state: "invited" }),
      status({ enrollment_id: id("2"), state: "healthy" }),
      status({ enrollment_id: id("3"), state: "refused" }),
      status({ enrollment_id: id("4"), state: "a_state_from_the_future" }),
    ];
    const s = inventorySummary(page(items), NOW);
    expect(s.workers + s.queue + s.attention + s.unknown).toBe(s.loaded);
    expect(s.loaded).toBe(items.length);
  });

  /** Accumulation across pages must not lose a row either. */
  it("keeps every distinct row across several pages", () => {
    let acc = EMPTY_PAGE;
    for (const char of ["1", "2", "3", "4"]) {
      acc = appendPage(acc, {
        items: [status({ enrollment_id: id(char) })],
        next_cursor: char === "4" ? null : `cursor-${char}`,
      });
    }
    expect(acc.items.map((i) => i.enrollment_id)).toEqual([id("1"), id("2"), id("3"), id("4")]);
    expect(inventorySummary(acc, NOW).loaded).toBe(4);
  });

  /** A stale duplicate is kept as the NEWER row, never removed. */
  it("never shrinks the loaded set when a duplicate arrives", () => {
    const first = page([status({ enrollment_id: id("a"), revision: 3 })], "c1");
    const stale = appendPage(first, {
      items: [status({ enrollment_id: id("a"), revision: 1 })],
      next_cursor: null,
    });
    expect(stale.items).toHaveLength(1);
    expect(stale.items[0].revision).toBe(3);
  });
});
