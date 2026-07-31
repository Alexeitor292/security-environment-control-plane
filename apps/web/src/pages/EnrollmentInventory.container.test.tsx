// @vitest-environment jsdom
//
// Container-level tests for the enrollment inventory: the async orchestration, mounted for real.
//
// WHY THIS FILE EXISTS. Every other enrollment suite targets the props-only `*View`, a pure module,
// or the source text. All three are blind to the container — where requests are issued, where
// responses are merged, and where two of them can be in flight at once. A well-tested surface still
// shipped a race because of that gap: a response from a filter the operator had already left
// stamped its rows AND its keyset cursor onto the new filter, and the next "load more" then sent
// this filter's query with the other filter's cursor. The controller answers that 200, with rows
// silently missing.
//
// So these tests interleave async on purpose. Every request is a promise this file resolves by
// hand, in an order it chooses, with the component mounted and reacting in between.

import { createElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { EnrollmentListPage, EnrollmentStatus } from "../api/types";

// Deferred so a request can be left in flight across an interaction. Declared before the mock
// factory that closes over them, because `vi.mock` is hoisted above the imports.
interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
}

function defer<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const listCalls: Array<Record<string, unknown>> = [];
const listQueue: Array<Deferred<EnrollmentListPage>> = [];

vi.mock("../api/client", () => ({
  api: {
    listEnrollments: (query: Record<string, unknown>) => {
      listCalls.push(query);
      const pending = defer<EnrollmentListPage>();
      listQueue.push(pending);
      return pending.promise;
    },
    getEnrollmentStatus: vi.fn(),
    revokeEnrollment: vi.fn(),
    markEnrollmentRecoveryRequired: vi.fn(),
  },
}));

vi.mock("../auth/AuthProvider", () => ({
  useAuth: () => ({
    principal: {
      user_id: "u-1",
      organization_id: "org-1",
      email: "operator@example.test",
      permissions: ["enrollment:read", "enrollment:manage"],
      is_dev_fallback: false,
    },
  }),
}));

const { EnrollmentInventory } = await import("./EnrollmentInventory");
const { mount } = await import("../testing/dom-a11y");

function id(char: string): string {
  return "sha256:" + char.repeat(64);
}

function status(over: Partial<EnrollmentStatus> = {}): EnrollmentStatus {
  return {
    enrollment_id: id("a"),
    state: "healthy",
    revision: 1,
    controller_installation_id: "controller-aaaaaaaa",
    controller_key_fingerprint: "cccccccccccc",
    worker_installation_id: "worker-one",
    worker_key_fingerprint: "ffffffffffff",
    release_fingerprint: "eeeeeeeeeeee",
    offer_fingerprint: "",
    result_fingerprint: "",
    expires_at: "2099-01-01T00:00:00+00:00",
    updated_at: "2026-07-30T10:00:00+00:00",
    refusal_reason: "",
    deployment_site_label: "site-one",
    ...over,
  };
}

beforeEach(() => {
  listCalls.length = 0;
  listQueue.length = 0;
});

function render() {
  return mount(createElement(EnrollmentInventory));
}

/** Text of every button, so a control can be found the way an operator would. */
function buttons(container: HTMLElement): HTMLButtonElement[] {
  return [...container.querySelectorAll<HTMLButtonElement>("button")];
}

function click(container: HTMLElement, label: string, view: { run(fn: () => void): void }) {
  const button = buttons(container).find((b) => (b.textContent ?? "").includes(label));
  if (button === undefined) {
    throw new Error(
      `no button matching "${label}" — found: ${buttons(container)
        .map((b) => b.textContent)
        .join(" | ")}`,
    );
  }
  view.run(() => button.click());
  return button;
}

/** Let a resolved promise's `.then` chain flush inside act. */
async function settle(view: { run(fn: () => void): void }) {
  await Promise.resolve();
  await Promise.resolve();
  view.run(() => {});
  await Promise.resolve();
}

function rowIds(container: HTMLElement): string[] {
  return [...container.querySelectorAll("tbody tr td:first-child")].map(
    (cell) => cell.textContent ?? "",
  );
}

describe("EnrollmentInventory container - a filter change during an in-flight load", () => {
  /**
   * THE REGRESSION. Load under one filter, switch filter before it returns, then let it return.
   * The response belongs to a filter that is no longer on screen and must not appear at all.
   */
  it("discards a response for a filter the operator has already left", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      expect(listCalls).toHaveLength(1);
      expect(listCalls[0].state).toEqual(["healthy"]);

      // switch to the pending queue while the healthy request is still in flight
      click(view.container, "Waiting on a worker", view);

      // ...and only now does the healthy response arrive
      listQueue[0].resolve({
        items: [status({ enrollment_id: id("1") })],
        next_cursor: "healthy-cursor",
      });
      await settle(view);

      // No healthy row may appear under the pending filter.
      expect(rowIds(view.container)).toEqual([]);
      expect(view.container.textContent).not.toContain("sha256:111111111111");
      // ...and nothing may be announced for a load this filter never made.
      expect(view.container.querySelector("#einv-status")?.textContent ?? "").toBe("");
    } finally {
      view.unmount();
    }
  });

  /**
   * THE REASON IT WAS A BLOCKER. The stale cursor is a keyset over the OTHER filter's order. Sent
   * with this filter's query the controller answers 200 and silently omits every matching row
   * ordered before that position — no error, nothing for an operator to notice.
   */
  it("never sends one filter's cursor with another filter's query", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      click(view.container, "Waiting on a worker", view);
      listQueue[0].resolve({
        items: [status({ enrollment_id: id("1") })],
        next_cursor: "healthy-cursor",
      });
      await settle(view);

      // Load the new filter properly and page it.
      click(view.container, "Load enrollments", view);
      listQueue[1].resolve({
        items: [status({ enrollment_id: id("2"), state: "invited" })],
        next_cursor: "pending-cursor",
      });
      await settle(view);
      click(view.container, "Load more", view);

      const paged = listCalls[listCalls.length - 1];
      expect(paged.after).toBe("pending-cursor");
      expect(paged.after).not.toBe("healthy-cursor");
      expect(paged.state).not.toContain("healthy");
      // every request this test made carried a cursor from its own filter, or none at all
      for (const call of listCalls) {
        if (call.after === "healthy-cursor") {
          expect(call.state, JSON.stringify(call)).toEqual(["healthy"]);
        }
      }
    } finally {
      view.unmount();
    }
  });

  /** The compounding half: a superseded request must not hold the new filter's controls disabled. */
  it("lets the operator load the new filter immediately, without waiting for the stale response", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      click(view.container, "Waiting on a worker", view);

      // The stale request has NOT resolved. The load control must still be usable.
      const load = buttons(view.container).find((b) =>
        (b.textContent ?? "").includes("Load enrollments"),
      );
      expect(load?.disabled).toBe(false);

      click(view.container, "Load enrollments", view);
      expect(listCalls).toHaveLength(2);
      expect(listCalls[1].state).not.toContain("healthy");
    } finally {
      view.unmount();
    }
  });

  /** A superseded failure is not the operator's problem either. */
  it("shows no error banner when a request for an abandoned filter fails", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      click(view.container, "Waiting on a worker", view);
      listQueue[0].reject(
        Object.assign(new Error("refused"), { code: "enrollment_forbidden", status: 403 }),
      );
      await settle(view);

      expect(view.container.textContent).not.toContain("belongs to another organization");
    } finally {
      view.unmount();
    }
  });
});

describe("EnrollmentInventory container - the ordinary paths still work", () => {
  it("renders the rows a load returned, under the filter that asked for them", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].resolve({
        items: [status({ enrollment_id: id("1") }), status({ enrollment_id: id("2") })],
        next_cursor: null,
      });
      await settle(view);

      expect(rowIds(view.container)).toHaveLength(2);
      expect(view.container.querySelector("#einv-status")?.textContent).toContain(
        "Loaded 2 more; 2 shown.",
      );
      expect(view.container.querySelector("#einv-status")?.textContent).toContain(
        "No further pages.",
      );
    } finally {
      view.unmount();
    }
  });

  it("continues the same filter with the cursor it was given", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].resolve({
        items: [status({ enrollment_id: id("1") })],
        next_cursor: "page-2",
      });
      await settle(view);

      click(view.container, "Load more", view);
      expect(listCalls[1]).toMatchObject({ after: "page-2", state: ["healthy"] });

      listQueue[1].resolve({
        items: [status({ enrollment_id: id("2") })],
        next_cursor: null,
      });
      await settle(view);
      expect(rowIds(view.container)).toHaveLength(2);
    } finally {
      view.unmount();
    }
  });

  /**
   * The live region reports GROWTH, not response size. A response that replaced already-loaded rows
   * in place did not add them — the concurrent-write case the page model is written to expect.
   */
  it("announces rows added, not rows returned, when a page replaces rows in place", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].resolve({
        items: [status({ enrollment_id: id("1"), revision: 1 })],
        next_cursor: "page-2",
      });
      await settle(view);

      click(view.container, "Load more", view);
      listQueue[1].resolve({
        items: [
          status({ enrollment_id: id("1"), revision: 2 }), // replaces in place
          status({ enrollment_id: id("2") }), // genuinely new
        ],
        next_cursor: null,
      });
      await settle(view);

      const announced = view.container.querySelector("#einv-status")?.textContent ?? "";
      expect(announced).toContain("Loaded 1 more; 2 shown.");
      expect(announced).toContain("1 updated in place.");
      expect(announced).not.toContain("Loaded 2 more");
    } finally {
      view.unmount();
    }
  });

  /** No request is issued until the operator asks for one. */
  it("issues no request on mount", () => {
    const view = render();
    try {
      expect(listCalls).toHaveLength(0);
    } finally {
      view.unmount();
    }
  });

  /** Nothing is dropped: every row the server returned is on screen. */
  it("renders every row returned, including states it does not recognise", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].resolve({
        items: [
          status({ enrollment_id: id("1"), state: "a_state_from_the_future" }),
          status({ enrollment_id: id("2"), state: "refused" }),
          status({ enrollment_id: id("3"), expires_at: "not a date" }),
        ],
        next_cursor: null,
      });
      await settle(view);
      expect(rowIds(view.container)).toHaveLength(3);
    } finally {
      view.unmount();
    }
  });
});

describe("EnrollmentInventory container - continuing past an unreadable row", () => {
  /** The refusal shape read off Stream B's source: `{code, recovery_cursor}`, 409. */
  const pageIntegrity = (recoveryCursor?: string) =>
    Object.assign(new Error("page integrity"), {
      code: "enrollment_page_integrity",
      status: 409,
      ...(recoveryCursor === undefined ? {} : { recoveryCursor }),
    });

  it("offers the continue control only once the server supplies a position", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].reject(pageIntegrity("past-the-bad-row"));
      await settle(view);

      expect(view.container.textContent).toContain(
        "One enrollment on this page failed its own integrity check",
      );
      expect(view.container.textContent).toContain("supplied a position past the failing row");
      const control = buttons(view.container).find((b) =>
        (b.textContent ?? "").includes("Continue past the unreadable row"),
      );
      expect(control).toBeDefined();
    } finally {
      view.unmount();
    }
  });

  /**
   * The older fallback refusal carries no position. A control must NOT appear, and the copy must
   * admit the dead end — an aim-less button is the thing this surface refused to build.
   */
  it("offers no continue control when the refusal carried no position", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].reject(
        Object.assign(new Error("corrupt"), { code: "enrollment_state_corrupt", status: 409 }),
      );
      await settle(view);

      expect(view.container.textContent).toContain(
        "One enrollment on this page failed its own integrity check",
      );
      expect(view.container.textContent).toContain("cannot be reached through this list");
      expect(
        buttons(view.container).some((b) =>
          (b.textContent ?? "").includes("Continue past the unreadable row"),
        ),
      ).toBe(false);
    } finally {
      view.unmount();
    }
  });

  /** The cursor is echoed back verbatim as `after`, under the same filter. */
  it("resumes from the server-supplied position, unmodified", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].reject(pageIntegrity("past-the-bad-row"));
      await settle(view);

      click(view.container, "Continue past the unreadable row", view);
      expect(listCalls[1]).toMatchObject({
        after: "past-the-bad-row",
        state: ["healthy"],
      });

      listQueue[1].resolve({
        items: [status({ enrollment_id: id("9") })],
        next_cursor: null,
      });
      await settle(view);
      expect(rowIds(view.container)).toHaveLength(1);
    } finally {
      view.unmount();
    }
  });

  /** A success must retire the aim, or a stale control outlives the failure that produced it. */
  it("withdraws the continue control once a load succeeds", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].reject(pageIntegrity("past-the-bad-row"));
      await settle(view);
      click(view.container, "Continue past the unreadable row", view);
      listQueue[1].resolve({ items: [status()], next_cursor: null });
      await settle(view);

      expect(
        buttons(view.container).some((b) =>
          (b.textContent ?? "").includes("Continue past the unreadable row"),
        ),
      ).toBe(false);
    } finally {
      view.unmount();
    }
  });

  /**
   * The recovery cursor NECESSARILY encodes the failing row's enrollment id — there is no way to
   * step past a row in a keyset order without naming its position. That is ratified and fine for
   * this caller, who is organization-scoped with `enrollment:read` and receives every id on a
   * successful page anyway.
   *
   * It still must not be RENDERED. An opaque token is opaque to the operator too: printing it puts
   * an identifier on screen in a form nobody can act on, in a context that invites copying it
   * somewhere it does not belong. It is a value to hand back, not one to show.
   */
  it("never renders the recovery cursor, which carries an enrollment id", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].reject(pageIntegrity("cursor-encoding-" + id("f")));
      await settle(view);

      // the control is offered...
      expect(view.container.textContent).toContain("Continue past the unreadable row");
      // ...and the token behind it appears nowhere in the document, nor in any attribute
      expect(view.container.textContent ?? "").not.toContain("cursor-encoding-");
      expect(view.container.innerHTML).not.toContain("cursor-encoding-");
    } finally {
      view.unmount();
    }
  });

  /** Changing the filter must retire it too: the position is bound to the filter it came from. */
  it("withdraws the continue control when the filter changes", async () => {
    const view = render();
    try {
      click(view.container, "Load enrollments", view);
      listQueue[0].reject(pageIntegrity("past-the-bad-row"));
      await settle(view);
      click(view.container, "Waiting on a worker", view);

      expect(
        buttons(view.container).some((b) =>
          (b.textContent ?? "").includes("Continue past the unreadable row"),
        ),
      ).toBe(false);
    } finally {
      view.unmount();
    }
  });
});
