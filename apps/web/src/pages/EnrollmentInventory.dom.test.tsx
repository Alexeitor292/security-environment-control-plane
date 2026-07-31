// @vitest-environment jsdom
//
// Real-DOM accessibility contract for the enrollment inventory.
//
// This suite exists because the other two cannot answer the questions that decide whether the page
// is operable: where focus is after an action, what an aria idref actually resolves to, what the
// tab order contains, and what an automated accessibility scan finds. Those need a document, so
// this file mounts the real component into one.
//
// MACHINE-CHECKED HERE: the axe-core rule set (names, roles, required parents/children, idref
// validity, duplicate ids, labelling, aria attribute validity, tabindex misuse, list structure,
// table structure), plus focus movement, tab order and disabled-state reachability asserted
// directly against the live DOM.
//
// NOT machine-checked here, and asserted by inspection instead: rendered colour contrast and
// visual focus-ring visibility, both of which need real layout — see RULES_NOT_MACHINE_CHECKED.

import { createElement } from "react";
import { describe, expect, it } from "vitest";

import type { EnrollmentStatus } from "../api/types";
import {
  RULES_NOT_MACHINE_CHECKED,
  axeViolations,
  describeViolations,
  mount,
  tabbable,
} from "../testing/dom-a11y";
import {
  EnrollmentInventoryView,
  type EnrollmentInventoryViewProps,
} from "./EnrollmentInventory";
import { EMPTY_PAGE, appendPage, type InventoryPage } from "./enrollment-inventory";

const NOW = Date.parse("2026-07-30T10:00:00+00:00");

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
    expires_at: "2026-07-30T11:00:00+00:00",
    updated_at: "2026-07-30T10:00:00+00:00",
    refusal_reason: "",
    deployment_site_label: "site-one",
    ...over,
  };
}

function loaded(items: EnrollmentStatus[], cursor: string | null = null): InventoryPage {
  return appendPage(EMPTY_PAGE, { items, next_cursor: cursor });
}

const ROWS = loaded(
  [
    status({ enrollment_id: id("1"), state: "healthy", worker_installation_id: "worker-one" }),
    status({ enrollment_id: id("2"), state: "invited" }),
    status({ enrollment_id: id("3"), state: "refused", refusal_reason: "operator_revoked" }),
  ],
  "cursor-next",
);

function props(over: Partial<EnrollmentInventoryViewProps> = {}): EnrollmentInventoryViewProps {
  return {
    permissions: { read: true, manage: true },
    scope: "all",
    onScopeChange: () => {},
    page: ROWS,
    loading: false,
    firstLoad: false,
    listError: null,
    onReload: () => {},
    onLoadMore: () => {},
    selectedId: null,
    onSelect: () => {},
    onClearSelection: () => {},
    onRereadSelected: () => {},
    rereading: false,
    rereadError: null,
    onRevoke: () => {},
    revoking: false,
    revokeError: null,
    liveNotice: null,
    nowMs: NOW,
    ...over,
  };
}

function render(over: Partial<EnrollmentInventoryViewProps> = {}) {
  return mount(createElement(EnrollmentInventoryView, props(over)));
}

// Every meaningfully different shape of the page. A scan of one state proves nothing about the
// others, and the states that differ most are exactly the ones a hand check skips.
const STATES: ReadonlyArray<readonly [string, Partial<EnrollmentInventoryViewProps>]> = [
  ["nothing loaded", { page: EMPTY_PAGE }],
  ["first load in flight", { page: EMPTY_PAGE, firstLoad: true, loading: true }],
  ["rows loaded", {}],
  ["rows loaded, last page", { page: loaded([status()], null) }],
  ["a row selected", { selectedId: id("1") }],
  ["a terminal row selected", { selectedId: id("3") }],
  ["read only", { permissions: { read: true, manage: false }, selectedId: id("2") }],
  ["manage only", { permissions: { read: false, manage: true }, page: EMPTY_PAGE }],
  ["no enrollment permission", { permissions: { read: false, manage: false }, page: EMPTY_PAGE }],
  ["list refused", { listError: { code: "enrollment_forbidden", text: "" }, page: EMPTY_PAGE }],
  [
    "revoke refused on a selected row",
    { selectedId: id("2"), revokeError: { code: "enrollment_revision_conflict", text: "" } },
  ],
  ["a live notice present", { liveNotice: "Loaded 3 more; 3 shown. More pages remain." }],
  ["an unrecognised state", { page: loaded([status({ state: "a_state_from_the_future" })]) }],
];

describe("EnrollmentInventoryView - automated accessibility scan", () => {
  it.each(STATES)("has no axe violations: %s", async (_name, over) => {
    const view = render(over);
    try {
      const violations = await axeViolations(view.container);
      expect(describeViolations(violations)).toEqual([]);
    } finally {
      view.unmount();
    }
  });

  // Anti-vacuity: a scan that silently stopped finding anything would pass every case above.
  // Deliberately break a rule the suite relies on and prove the scan reports it.
  it("actually reports a violation when one is introduced", async () => {
    const view = render();
    try {
      // A button whose only content is an image with no alternative text has no accessible name.
      const broken = document.createElement("button");
      broken.appendChild(document.createElement("img"));
      view.container.appendChild(broken);
      const violations = await axeViolations(view.container);
      expect(violations.map((v) => v.id)).toContain("button-name");
    } finally {
      view.unmount();
    }
  });

  it("states which properties it cannot check, rather than implying full coverage", () => {
    const rules = RULES_NOT_MACHINE_CHECKED.map(([rule]) => rule);
    expect(rules).toContain("color-contrast");
    for (const [rule, why] of RULES_NOT_MACHINE_CHECKED) {
      expect(why.length, rule).toBeGreaterThan(20);
    }
  });
});

describe("EnrollmentInventoryView - focus behaviour a string cannot see", () => {
  /**
   * The defect this test exists for: selecting a row renders the record BELOW the table, so
   * without moving focus the action reads to a keyboard or screen-reader user as having done
   * nothing at all — the new content is off-screen and behind them in the reading order.
   */
  it("moves focus onto the selected record when a row is chosen", () => {
    const view = mount(createElement(EnrollmentInventoryView, props()));
    try {
      expect(document.activeElement).toBe(document.body);
      view.run(() => {
        view.root.render(
          createElement(EnrollmentInventoryView, props({ selectedId: id("1") })),
        );
      });
      const region = document.getElementById("einv-selection");
      expect(region).not.toBeNull();
      expect(document.activeElement).toBe(region);
    } finally {
      view.unmount();
    }
  });

  /** The focus target must be programmatically focusable but never a tab stop of its own. */
  it("makes the selection region focusable without putting it in the tab order", () => {
    const view = render({ selectedId: id("1") });
    try {
      const region = view.container.querySelector<HTMLElement>("#einv-selection");
      expect(region?.getAttribute("tabindex")).toBe("-1");
      expect(tabbable(view.container)).not.toContain(region);
    } finally {
      view.unmount();
    }
  });

  it("keeps the focus target mounted before anything is selected, so it is never a dangling target", () => {
    const view = render({ page: EMPTY_PAGE });
    try {
      expect(view.container.querySelector("#einv-selection")).not.toBeNull();
    } finally {
      view.unmount();
    }
  });
});

describe("EnrollmentInventoryView - keyboard reachability", () => {
  /** Every control is a real element, so the browser gives it keyboard operability for free. */
  it("has no click-handling div anywhere", () => {
    const view = render({ selectedId: id("1") });
    try {
      for (const el of view.container.querySelectorAll<HTMLElement>("div, span, p, li")) {
        expect(el.getAttribute("role"), el.outerHTML.slice(0, 80)).not.toBe("button");
      }
      // and every focusable thing is a real control or an explicit focus target
      for (const el of tabbable(view.container)) {
        expect(
          ["A", "BUTTON", "INPUT", "SELECT", "TEXTAREA", "SUMMARY", "DIV"],
          el.outerHTML.slice(0, 80),
        ).toContain(el.tagName);
      }
    } finally {
      view.unmount();
    }
  });

  /**
   * A disabled button is out of the tab order and most screen readers will not announce its
   * `aria-describedby`. That is exactly why the reason is ALSO adjacent visible text — asserted
   * here against the live DOM rather than against a string, so "the reason is reachable" is
   * checked as a property of the document.
   */
  it("keeps the reason for every disabled control present as real text in the document", () => {
    const view = render({ permissions: { read: false, manage: false }, page: EMPTY_PAGE });
    try {
      const disabled = [...view.container.querySelectorAll<HTMLButtonElement>("button[disabled]")];
      expect(disabled.length).toBeGreaterThan(0);
      for (const button of disabled) {
        expect(tabbable(view.container)).not.toContain(button);
        const described = button.getAttribute("aria-describedby");
        expect(described, button.textContent ?? "").not.toBeNull();
        const reason = view.container.ownerDocument.getElementById(described as string);
        // resolves to a real element...
        expect(reason, described as string).not.toBeNull();
        // ...that carries real text, not an empty node
        expect((reason?.textContent ?? "").length).toBeGreaterThan(10);
      }
    } finally {
      view.unmount();
    }
  });

  /**
   * A dangling `aria-describedby` is invisible in a string test and silent in a browser: the
   * reference simply resolves to nothing, so the control loses its description with no error
   * anywhere. Checked here across every state, because the states that gain a reference (a
   * disabled control gaining its reason) are exactly the ones where one can be introduced.
   */
  it("resolves every aria idref to an element that exists, in every state", () => {
    const attrs = ["aria-describedby", "aria-labelledby", "aria-controls"];
    let checked = 0;
    for (const [name, over] of STATES) {
      const view = render(over);
      try {
        for (const el of view.container.querySelectorAll<HTMLElement>("*")) {
          for (const attr of attrs) {
            const value = el.getAttribute(attr);
            if (value === null) continue;
            for (const ref of value.split(/\s+/).filter(Boolean)) {
              checked += 1;
              expect(document.getElementById(ref), `${name}: ${attr}="${ref}"`).not.toBeNull();
            }
          }
        }
      } finally {
        view.unmount();
      }
    }
    // Anti-vacuity: a page with no idrefs at all would pass the loop above trivially.
    expect(checked).toBeGreaterThan(20);
  });

  it("uses a unique id for every element that has one", () => {
    const view = render({ selectedId: id("1") });
    try {
      const ids = [...view.container.querySelectorAll<HTMLElement>("[id]")].map((el) => el.id);
      expect(ids.length).toBeGreaterThan(3);
      expect(new Set(ids).size).toBe(ids.length);
    } finally {
      view.unmount();
    }
  });
});

describe("EnrollmentInventoryView - tab rail semantics in a real tree", () => {
  it("exposes exactly one tab stop for the rail, on the selected tab", () => {
    const view = render();
    try {
      const tabs = [...view.container.querySelectorAll<HTMLElement>('[role="tab"]')];
      expect(tabs).toHaveLength(4);
      const stops = tabs.filter((t) => t.getAttribute("tabindex") === "0");
      expect(stops).toHaveLength(1);
      expect(stops[0].getAttribute("aria-selected")).toBe("true");
    } finally {
      view.unmount();
    }
  });

  it("points the selected tab at a panel that is really in the document", () => {
    const view = render();
    try {
      const selected = view.container.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]');
      const controls = selected?.getAttribute("aria-controls");
      expect(controls).toBeTruthy();
      const panel = document.getElementById(controls as string);
      expect(panel).not.toBeNull();
      expect(panel?.getAttribute("role")).toBe("tabpanel");
      expect(panel?.getAttribute("aria-labelledby")).toBe(selected?.id);
    } finally {
      view.unmount();
    }
  });

  it("leaves no dangling aria-controls on the unselected tabs", () => {
    const view = render();
    try {
      for (const tab of view.container.querySelectorAll<HTMLElement>(
        '[role="tab"][aria-selected="false"]',
      )) {
        expect(tab.getAttribute("aria-controls")).toBeNull();
      }
    } finally {
      view.unmount();
    }
  });
});

describe("EnrollmentInventoryView - live region", () => {
  /** A region added at the moment it has something to say is often missed by screen readers; this
   *  one is mounted from the start so it has existed long enough to announce. */
  it("is present before there is anything to announce", () => {
    const view = render({ page: EMPTY_PAGE, liveNotice: null });
    try {
      const live = view.container.querySelector<HTMLElement>("#einv-status");
      expect(live).not.toBeNull();
      expect(live?.getAttribute("role")).toBe("status");
      expect(live?.textContent).toBe("");
    } finally {
      view.unmount();
    }
  });

  it("carries the text once there is, without being remounted", () => {
    const view = mount(createElement(EnrollmentInventoryView, props()));
    try {
      const before = view.container.querySelector("#einv-status");
      view.run(() => {
        view.root.render(
          createElement(EnrollmentInventoryView, props({ liveNotice: "Loaded 3 more; 3 shown." })),
        );
      });
      const after = view.container.querySelector("#einv-status");
      expect(after).toBe(before);
      expect(after?.textContent).toContain("Loaded 3 more");
    } finally {
      view.unmount();
    }
  });
});

describe("EnrollmentInventoryView - table semantics in a real tree", () => {
  it("gives the table an accessible name and a header cell per column", () => {
    const view = render();
    try {
      const table = view.container.querySelector("table");
      expect(table?.getAttribute("aria-label")).toContain("Enrollments in your organization");
      const headers = [...view.container.querySelectorAll("th")];
      expect(headers).toHaveLength(6);
      for (const th of headers) expect(th.getAttribute("scope")).toBe("col");
      const firstRow = view.container.querySelector("tbody tr");
      expect(firstRow?.querySelectorAll("td")).toHaveLength(headers.length);
    } finally {
      view.unmount();
    }
  });

  it("names each row action with the enrollment it acts on", () => {
    const view = render();
    try {
      const buttons = [...view.container.querySelectorAll<HTMLButtonElement>("tbody button")];
      expect(buttons).toHaveLength(3);
      for (const button of buttons) {
        expect(button.textContent).toContain("for enrollment sha256:");
      }
    } finally {
      view.unmount();
    }
  });

  it("marks the selected row by state as well as by style", () => {
    const view = render({ selectedId: id("1") });
    try {
      const pressed = [
        ...view.container.querySelectorAll<HTMLButtonElement>('tbody button[aria-pressed="true"]'),
      ];
      expect(pressed).toHaveLength(1);
      expect(pressed[0].textContent).toContain("Showing");
    } finally {
      view.unmount();
    }
  });
});
