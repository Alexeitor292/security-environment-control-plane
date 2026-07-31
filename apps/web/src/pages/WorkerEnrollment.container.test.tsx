// @vitest-environment jsdom
//
// Container-level tests for the worker-enrollment surface: the async orchestration, mounted.
//
// Same gap as the inventory's container suite. Several row refreshes can be in flight at once and
// their responses can land in any order — which the props-only suites cannot see at all, because
// the container is where the requests are issued and where their results are merged.
//
// The invitation is bearer-grade, so this file also does the one check only a container can do:
// mount the real thing, drive a real create, and assert the material is not in the document until
// the operator opens it.

import { createElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";

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

const statusCalls: string[] = [];
const statusQueue = new Map<string, Deferred<EnrollmentStatus>>();
const createQueue: Array<Deferred<EnrollmentInvitation>> = [];

vi.mock("../api/client", () => ({
  api: {
    getEnrollmentStatus: (enrollmentId: string) => {
      statusCalls.push(enrollmentId);
      const pending = defer<EnrollmentStatus>();
      statusQueue.set(enrollmentId, pending);
      return pending.promise;
    },
    createEnrollmentInvitation: () => {
      const pending = defer<EnrollmentInvitation>();
      createQueue.push(pending);
      return pending.promise;
    },
    revokeEnrollment: vi.fn(),
    markEnrollmentRecoveryRequired: vi.fn(),
    listEnrollments: vi.fn(),
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

const { WorkerEnrollment } = await import("./WorkerEnrollment");
const { mount } = await import("../testing/dom-a11y");

const A = "sha256:" + "a".repeat(64);
const B = "sha256:" + "b".repeat(64);

function status(over: Partial<EnrollmentStatus> = {}): EnrollmentStatus {
  return {
    enrollment_id: A,
    state: "invited",
    revision: 1,
    controller_installation_id: "controller-aaaaaaaa",
    controller_key_fingerprint: "cccccccccccc",
    worker_installation_id: "",
    worker_key_fingerprint: "",
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

const INVITATION: EnrollmentInvitation = {
  enrollment_id: A,
  invitation_id: "sha256:" + "9".repeat(64),
  controller_installation_id: "controller-aaaaaaaa",
  controller_key_id: "sha256:" + "c".repeat(64),
  controller_trust_anchor_hex: "d".repeat(64),
  controller_origin: "https://controller.example",
  release_digest: "sha256:" + "e".repeat(64),
  transaction_id: "txn-0123456789abcdef",
  deployment_site_label: "site-one",
  created_at: "2026-07-30T10:00:00+00:00",
  expires_at: "2099-01-01T00:00:00+00:00",
  state: "invited",
  revision: 0,
};

beforeEach(() => {
  statusCalls.length = 0;
  statusQueue.clear();
  createQueue.length = 0;
});

function render() {
  return mount(createElement(WorkerEnrollment));
}

function buttons(container: HTMLElement): HTMLButtonElement[] {
  return [...container.querySelectorAll<HTMLButtonElement>("button")];
}

function clickAll(container: HTMLElement, label: string): HTMLButtonElement[] {
  const found = buttons(container).filter((b) => (b.textContent ?? "").includes(label));
  expect(found.length, `no button matching "${label}"`).toBeGreaterThan(0);
  return found;
}

function typeInto(input: HTMLInputElement, value: string, view: { run(fn: () => void): void }) {
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  )?.set;
  view.run(() => {
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function settle(view: { run(fn: () => void): void }) {
  await Promise.resolve();
  await Promise.resolve();
  view.run(() => {});
  await Promise.resolve();
}

/** Look one enrollment up so the tab-local table has a row to refresh. */
async function trackOne(
  view: { container: HTMLElement; run(fn: () => void): void },
  enrollmentId: string,
  state: string,
) {
  const input = view.container.querySelector<HTMLInputElement>('input.mono');
  typeInto(input as HTMLInputElement, enrollmentId, view);
  const lookup = clickAll(view.container, "Look up status")[0];
  view.run(() => lookup.click());
  statusQueue.get(enrollmentId)?.resolve(status({ enrollment_id: enrollmentId, state }));
  await settle(view);
}

describe("WorkerEnrollment container - concurrent row refreshes", () => {
  /**
   * Two rows refreshing at once. A single scalar "which row is busy" could only mark one, so the
   * second refresh cleared the first row's affordance while its request was still running.
   */
  it("keeps each refreshing row busy independently", async () => {
    const view = render();
    try {
      await trackOne(view, A, "invited");
      await trackOne(view, B, "worker_bound");
      statusQueue.clear();
      statusCalls.length = 0;

      const refreshes = clickAll(view.container, "Refresh");
      expect(refreshes).toHaveLength(2);
      view.run(() => refreshes[0].click());
      view.run(() => refreshes[1].click());
      expect(statusCalls).toHaveLength(2);

      // both rows are busy while both are in flight
      expect(
        buttons(view.container).filter((b) => (b.textContent ?? "").includes("Refreshing")),
      ).toHaveLength(2);

      // resolving ONE must not release the other
      statusQueue.get(statusCalls[0])?.resolve(status({ enrollment_id: statusCalls[0] }));
      await settle(view);
      expect(
        buttons(view.container).filter((b) => (b.textContent ?? "").includes("Refreshing")),
      ).toHaveLength(1);
    } finally {
      view.unmount();
    }
  });

  /**
   * The detail panel must show the row the operator most recently asked about — not whichever
   * request happened to finish last.
   */
  it("lets only the newest refresh move the detail panel", async () => {
    const view = render();
    try {
      await trackOne(view, A, "invited");
      await trackOne(view, B, "worker_bound");
      statusQueue.clear();
      statusCalls.length = 0;

      const refreshes = clickAll(view.container, "Refresh");
      view.run(() => refreshes[0].click()); // older request
      view.run(() => refreshes[1].click()); // newer request

      const [first, second] = statusCalls;
      // the NEWER one lands first...
      statusQueue.get(second)?.resolve(status({ enrollment_id: second, state: "verified" }));
      await settle(view);
      // ...then the older one lands late and must NOT take the panel back
      statusQueue.get(first)?.resolve(status({ enrollment_id: first, state: "healthy" }));
      await settle(view);

      const detail = view.container.querySelector(".wenr-status__head");
      expect(detail?.textContent).toContain("verified");
      expect(detail?.textContent).not.toContain("healthy");
    } finally {
      view.unmount();
    }
  });

  /** Both rows still get their own state, whichever order the responses land in. */
  it("updates every refreshed row regardless of which response lands first", async () => {
    const view = render();
    try {
      await trackOne(view, A, "invited");
      await trackOne(view, B, "invited");
      statusQueue.clear();
      statusCalls.length = 0;

      const refreshes = clickAll(view.container, "Refresh");
      view.run(() => refreshes[0].click());
      view.run(() => refreshes[1].click());
      const [first, second] = statusCalls;
      statusQueue.get(second)?.resolve(
        status({ enrollment_id: second, state: "verified", revision: 5 }),
      );
      await settle(view);
      statusQueue.get(first)?.resolve(
        status({ enrollment_id: first, state: "worker_bound", revision: 4 }),
      );
      await settle(view);

      const table = view.container.querySelector("tbody")?.textContent ?? "";
      expect(table).toContain("verified");
      expect(table).toContain("worker bound");
    } finally {
      view.unmount();
    }
  });

  /** A refused ROW refresh belongs with the table, not under the look-up control. */
  it("reports a refused row refresh with the table rather than under the look-up card", async () => {
    const view = render();
    try {
      await trackOne(view, A, "invited");
      statusQueue.clear();
      statusCalls.length = 0;

      const refresh = clickAll(view.container, "Refresh")[0];
      view.run(() => refresh.click());
      statusQueue
        .get(statusCalls[0])
        ?.reject(
          Object.assign(new Error("gone"), { code: "enrollment_not_found", status: 404 }),
        );
      await settle(view);

      const trackedCard = [...view.container.querySelectorAll(".ui-card")].find((card) =>
        (card.textContent ?? "").includes("Tracked in this tab"),
      );
      expect(trackedCard?.textContent).toContain("No enrollment exists with that id");

      const lookupCard = [...view.container.querySelectorAll(".ui-card")].find((card) =>
        (card.textContent ?? "").includes("Look up an enrollment"),
      );
      expect(lookupCard?.textContent).not.toContain("No enrollment exists with that id");
    } finally {
      view.unmount();
    }
  });
});

describe("WorkerEnrollment container - bearer material through a real create", () => {
  /**
   * The one check only a container can make: drive the real create path and assert the invitation
   * is not in the document until the operator opens it. Every other suite feeds the invitation in
   * as a prop, which cannot prove what the container does with a live response.
   */
  it("puts no invitation material in the document until the operator reveals it", async () => {
    const view = render();
    try {
      const site = view.container.querySelector<HTMLInputElement>("input:not(.mono)");
      typeInto(site as HTMLInputElement, "site-one", view);
      const create = clickAll(view.container, "Create invitation")[0];
      view.run(() => create.click());
      createQueue[0].resolve(INVITATION);
      await settle(view);

      // the card is there...
      expect(view.container.textContent).toContain("Hand this to the worker");
      // ...and the bearer values are not
      const text = view.container.textContent ?? "";
      for (const secretish of [
        INVITATION.invitation_id,
        INVITATION.controller_trust_anchor_hex,
        INVITATION.transaction_id,
        INVITATION.release_digest,
      ]) {
        expect(text, secretish.slice(0, 20)).not.toContain(secretish);
      }

      // Anti-vacuity: revealing must actually put them there, or the check above proves nothing.
      const reveal = clickAll(view.container, "Reveal invitation")[0];
      view.run(() => reveal.click());
      expect(view.container.textContent).toContain(INVITATION.transaction_id);
    } finally {
      view.unmount();
    }
  });

  /** Nothing bearer-grade may reach anything the browser persists. */
  it("writes nothing to storage or the URL when an invitation is created", async () => {
    const before = window.location.href;
    const view = render();
    try {
      const site = view.container.querySelector<HTMLInputElement>("input:not(.mono)");
      typeInto(site as HTMLInputElement, "site-one", view);
      view.run(() => clickAll(view.container, "Create invitation")[0].click());
      createQueue[0].resolve(INVITATION);
      await settle(view);

      expect(window.localStorage.length).toBe(0);
      expect(window.sessionStorage.length).toBe(0);
      expect(document.cookie).toBe("");
      expect(window.location.href).toBe(before);
    } finally {
      view.unmount();
    }
  });
});
