// Accessibility contract for the worker-enrollment surface.
//
// The suite runs in the node environment against `renderToStaticMarkup`, so these are MARKUP
// properties — the ones an automated checker (axe, the HTML validator, a screen reader's own
// accessibility tree) derives its findings from: names, roles, relationships, focus order and
// text alternatives. What cannot be proven this way is stated as such rather than implied:
// there is no DOM, so nothing here executes a keypress or measures a rendered contrast ratio.
// Keyboard operability is instead asserted structurally — every control is a real <button>,
// <input>, <summary> or <a>, never a click-handling <div>, which is what makes it reachable by
// keyboard in the first place — and contrast is held by the CSS token discipline (semantic tokens
// only, never --ink-muted for text) that worker-enrollment.css states and follows.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import { WorkerEnrollmentView, type WorkerEnrollmentViewProps } from "./WorkerEnrollment";
import {
  INVITATION_CLEARED_NOTICE,
  trackedFromInvitation,
  type TrackedEnrollment,
} from "./worker-enrollment";

const ID = "sha256:" + "a".repeat(64);
const NOW = Date.parse("2026-07-30T10:00:00+00:00");

const INVITATION: EnrollmentInvitation = {
  enrollment_id: ID,
  invitation_id: "sha256:" + "b".repeat(64),
  controller_installation_id: "controller-aaaaaaaa",
  controller_key_id: "sha256:" + "c".repeat(64),
  controller_trust_anchor_hex: "d".repeat(64),
  controller_origin: "https://controller.example",
  release_digest: "sha256:" + "e".repeat(64),
  transaction_id: "txn-0123456789abcdef",
  deployment_site_label: "site-one",
  created_at: "2026-07-30T10:00:00+00:00",
  expires_at: "2026-07-30T11:00:00+00:00",
  state: "invited",
  revision: 0,
};

const STATUS: EnrollmentStatus = {
  enrollment_id: ID,
  state: "worker_bound",
  revision: 1,
  controller_installation_id: "controller-aaaaaaaa",
  controller_key_fingerprint: "cccccccccccc",
  worker_installation_id: "worker-one",
  worker_key_fingerprint: "ffffffffffff",
  release_fingerprint: "eeeeeeeeeeee",
  offer_fingerprint: "",
  result_fingerprint: "",
  expires_at: "2026-07-30T11:00:00+00:00",
  updated_at: "2026-07-30T10:05:00+00:00",
  refusal_reason: "",
};

const TRACKED: TrackedEnrollment[] = [
  trackedFromInvitation(INVITATION),
  {
    enrollmentId: "sha256:" + "9".repeat(64),
    siteLabel: "",
    createdAt: "",
    expiresAt: "2026-07-30T09:00:00+00:00",
    state: "offer_transported",
    revision: 3,
  },
];

function html(over: Partial<WorkerEnrollmentViewProps> = {}): string {
  const props: WorkerEnrollmentViewProps = {
    permissions: { read: true, manage: true },
    siteLabel: "site-one",
    onSiteLabelChange: () => {},
    ttlSeconds: "3600",
    onTtlSecondsChange: () => {},
    onCreate: () => {},
    creating: false,
    createError: null,
    invitation: null,
    revealed: false,
    onToggleReveal: () => {},
    onCopyHandoff: () => {},
    copyNotice: null,
    onDismissInvitation: () => {},
    dismissNotice: null,
    lookupId: "",
    onLookupIdChange: () => {},
    onLookup: () => {},
    lookingUp: false,
    status: null,
    statusError: null,
    onRevoke: () => {},
    revoking: false,
    revokeError: null,
    tracked: [],
    trackedFilter: "all",
    onTrackedFilterChange: () => {},
    onRefreshTracked: () => {},
    onForgetTracked: () => {},
    refreshingId: null,
    nowMs: NOW,
    ...over,
  };
  return renderToStaticMarkup(createElement(WorkerEnrollmentView, props));
}

/** The states this page can be in. Every structural property below is asserted across ALL of them,
 *  because an accessibility defect that only appears once an invitation exists is the one an
 *  operator actually meets. */
const RENDERS: [string, Partial<WorkerEnrollmentViewProps>][] = [
  ["empty", {}],
  ["invitation closed", { invitation: INVITATION, revealed: false }],
  ["invitation revealed", { invitation: INVITATION, revealed: true }],
  ["status", { status: STATUS }],
  ["terminal status", { status: { ...STATUS, state: "recovery_required" } }],
  ["tracked rows", { tracked: TRACKED }],
  ["tracked filtered", { tracked: TRACKED, trackedFilter: "pending" }],
  ["refreshing a row", { tracked: TRACKED, refreshingId: TRACKED[0].enrollmentId }],
  ["no permissions", { permissions: { read: false, manage: false }, status: STATUS }],
  [
    "errors",
    {
      status: STATUS,
      createError: { code: "forbidden", text: "" },
      statusError: { code: "enrollment_not_found", text: "" },
      revokeError: { code: "enrollment_revision_conflict", text: "" },
    },
  ],
];

// --------------------------------------------------------------------- markup extraction

function allIds(out: string): string[] {
  return [...out.matchAll(/\sid="([^"]*)"/g)].map((m) => m[1]);
}

/** Every id reference the document makes, as (attribute, single id) pairs — the ARIA relationship
 *  attributes are space-separated id LISTS, so each token is checked on its own. */
function idRefs(out: string): { attr: string; id: string }[] {
  const refs: { attr: string; id: string }[] = [];
  const pattern = /\s(aria-labelledby|aria-describedby|aria-controls|for)="([^"]*)"/g;
  for (const match of out.matchAll(pattern)) {
    for (const token of match[2].split(/\s+/).filter(Boolean)) {
      refs.push({ attr: match[1], id: token });
    }
  }
  return refs;
}

function elements(out: string, tag: string): string[] {
  return out.match(new RegExp(`<${tag}\\b[\\s\\S]*?</${tag}>`, "g")) ?? [];
}

function voidElements(out: string, tag: string): string[] {
  return out.match(new RegExp(`<${tag}\\b[^>]*/?>`, "g")) ?? [];
}

/** Visible text of an element, with sr-only spans included — that is exactly what a screen reader
 *  computes an accessible name from when there is no aria-label. */
function textOf(element: string): string {
  return element
    .replace(/<[^>]*>/g, " ")
    .replace(/&[a-z]+;|&#x?[0-9a-f]+;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// --------------------------------------------------------------------- relationships

describe("worker-enrollment accessibility — names, roles and relationships", () => {
  it("never emits a dangling id reference in any state", () => {
    for (const [name, over] of RENDERS) {
      const out = html(over);
      const ids = new Set(allIds(out));
      const refs = idRefs(out);
      // Anti-vacuity: this page wires labels, hints, tab panels and gate reasons, so an empty
      // extraction means the scan broke rather than that the document is relationship-free.
      expect(refs.length, name).toBeGreaterThan(3);
      for (const ref of refs) {
        expect(ids, `${name}: ${ref.attr}="${ref.id}"`).toContain(ref.id);
      }
    }
  });

  it("never emits a duplicate id, which would make a reference ambiguous", () => {
    for (const [name, over] of RENDERS) {
      const ids = allIds(html(over));
      expect(ids.length, name).toBeGreaterThan(0);
      expect(new Set(ids).size, `${name}: ${ids.join(", ")}`).toBe(ids.length);
    }
  });

  it("gives every text input a label element bound to it", () => {
    for (const [name, over] of RENDERS) {
      const out = html(over);
      const inputs = voidElements(out, "input");
      expect(inputs.length, name).toBeGreaterThanOrEqual(2);
      for (const input of inputs) {
        const id = /\sid="([^"]*)"/.exec(input)?.[1];
        expect(id, `${name}: ${input}`).toBeTruthy();
        expect(out, `${name}: no <label for="${id}">`).toContain(`for="${id}"`);
      }
    }
  });

  it("binds each field's hint and validation text to the input that owns them", () => {
    // Every field on the page is invalid in this render, so every one of them must describe both
    // its hint and its error — a field that dropped one would show the operator text no screen
    // reader ever reads out.
    const out = html({ siteLabel: "-bad", ttlSeconds: "0", lookupId: "nope" });
    const inputs = voidElements(out, "input");
    expect(inputs).toHaveLength(3);
    for (const input of inputs) {
      const described = /aria-describedby="([^"]*)"/.exec(input)?.[1] ?? "";
      expect(described.split(/\s+/).filter(Boolean).length, input).toBe(2);
      expect(input, input).toContain('aria-invalid="true"');
    }
    // Positive control: the same fields describe only their hint when valid, so the count above
    // is measuring the error wiring and not just "two of something".
    for (const input of voidElements(html(), "input")) {
      const described = /aria-describedby="([^"]*)"/.exec(input)?.[1] ?? "";
      expect(described.split(/\s+/).filter(Boolean).length, input).toBe(1);
      expect(input, input).not.toContain("aria-invalid");
    }
  });

  it("describes a disabled control with the reason it is unavailable", () => {
    const out = html({ permissions: { read: false, manage: false }, status: STATUS });
    for (const reason of ["wenr-create-reason", "wenr-lookup-reason", "wenr-revoke-reason"]) {
      expect(out, reason).toContain(`aria-describedby="${reason}"`);
      expect(out, reason).toContain(`id="${reason}"`);
    }
    // ...and drops the reference entirely once the control is usable, so it can never point at
    // an element that is not there.
    const allowed = html({ permissions: { read: true, manage: true }, status: STATUS });
    expect(allowed).not.toContain("wenr-revoke-reason");
  });

  it("exposes the hand-off block as a proper disclosure in both states", () => {
    const closed = html({ invitation: INVITATION, revealed: false });
    const open = html({ invitation: INVITATION, revealed: true });
    expect(closed).toContain('aria-expanded="false"');
    expect(open).toContain('aria-expanded="true"');
    // The controlled region exists in both states — a disclosure whose target appears only when
    // open leaves aria-controls dangling exactly when it matters.
    expect(closed).toContain('id="wenr-handoff-region"');
    expect(open).toContain('id="wenr-handoff-region"');
    // ...and is marked hidden while closed, so it is out of the accessibility tree.
    expect(/id="wenr-handoff-region"[^>]*hidden/.test(closed)).toBe(true);
    expect(/id="wenr-handoff-region"[^>]*hidden/.test(open)).toBe(false);
  });

  it("wires the filter tabs to the panel they control", () => {
    const out = html({ tracked: TRACKED, trackedFilter: "pending" });
    expect(out).toContain('role="tablist"');
    expect(out).toContain('aria-label="Filter tracked enrollments"');
    expect(out).toContain('role="tabpanel"');
    expect(out).toContain('aria-controls="wenr-tracked-panel-pending"');
    expect(out).toContain('id="wenr-tracked-panel-pending"');
    expect(out).toContain('aria-labelledby="wenr-tracked-tab-pending"');
    // Roving tabindex: exactly one tab is in the tab order.
    const tabs = elements(out, "button").filter((b) => b.includes('role="tab"'));
    expect(tabs).toHaveLength(4);
    expect(tabs.filter((t) => t.includes('tabindex="0"'))).toHaveLength(1);
    expect(tabs.every((t) => /aria-selected="(true|false)"/.test(t))).toBe(true);
  });

  it("names the tracked table and its scrollable region", () => {
    const out = html({ tracked: TRACKED });
    expect(out).toContain('aria-label="Enrollments tracked in this browser tab"');
    expect(out).toContain('role="region"');
    // Column headers are real headers, so each cell is announced with its column.
    expect(out.match(/<th scope="col">/g) ?? []).toHaveLength(5);
  });

  it("uses a live region for the copy outcome, present before the message arrives", () => {
    const before = html({ invitation: INVITATION, revealed: true, copyNotice: null });
    const after = html({
      invitation: INVITATION,
      revealed: true,
      copyNotice: "Copied. Deliver it to one worker, then clear your clipboard.",
    });
    // A live region announces nothing if it is mounted at the same moment as its content.
    expect(before).toContain('role="status"');
    expect(after).toContain('role="status"');
    expect(after).toContain("Copied. Deliver it");
  });

  // Dismissing unmounts the card the operator was working in, so the focused control goes with it
  // and the browser drops focus to <body>. The outcome must therefore be announced from a region
  // that was ALREADY mounted, or the interaction ends in silence with no focus and no message.
  it("announces a dismissal from a region that outlives the card being dismissed", () => {
    const before = html({ invitation: INVITATION, revealed: true });
    expect(before).toContain('role="status"');
    expect(before).toContain("Done — clear it from this browser");

    const after = html({ invitation: null, dismissNotice: INVITATION_CLEARED_NOTICE });
    expect(after).not.toContain("Hand this to the worker");
    expect(after).toContain("Invitation cleared from this browser");
    expect(after).toContain('role="status"');
  });

  it("marks every decorative icon aria-hidden", () => {
    for (const [name, over] of RENDERS) {
      const svgs = elements(html(over), "svg");
      expect(svgs.length, name).toBeGreaterThan(0);
      for (const svg of svgs) expect(svg, `${name}: ${svg}`).toContain("aria-hidden");
    }
  });
});

// --------------------------------------------------------------------- keyboard reachability

describe("worker-enrollment accessibility — keyboard reachability", () => {
  // There is no DOM here to press a key against. What IS provable, and is the precondition for
  // keyboard operability, is that every interactive affordance is a natively focusable element
  // rather than a div with a click handler.
  it("uses only natively focusable elements for interaction", () => {
    for (const [name, over] of RENDERS) {
      const out = html(over);
      // React does not render onClick into markup, so a click-handling div is invisible to a
      // string scan. Assert the positive instead: the controls this page offers are buttons.
      const buttons = elements(out, "button");
      expect(buttons.length, name).toBeGreaterThan(3);
      for (const button of buttons) {
        expect(button, `${name}: ${button}`).toContain('type="button"');
      }
    }
  });

  it("gives every button a non-empty accessible name", () => {
    for (const [name, over] of RENDERS) {
      for (const button of elements(html(over), "button")) {
        const label = /aria-label="([^"]*)"/.exec(button)?.[1] ?? textOf(button);
        expect(label.length, `${name}: ${button}`).toBeGreaterThan(0);
      }
    }
  });

  // Repeated row actions must not all be announced as "Refresh" — a screen-reader user listing
  // the buttons on the page would get a wall of identical names with nothing to choose between.
  it("distinguishes repeated row actions by including the enrollment they act on", () => {
    const out = html({ tracked: TRACKED });
    const rowButtons = elements(out, "button").filter(
      (b) => textOf(b).startsWith("Refresh") || textOf(b).startsWith("Forget"),
    );
    expect(rowButtons).toHaveLength(4); // two rows, two actions each
    const names = rowButtons.map(textOf);
    expect(new Set(names).size).toBe(names.length);
    for (const enrollmentId of TRACKED.map((t) => t.enrollmentId)) {
      expect(names.filter((n) => n.includes(enrollmentId))).toHaveLength(2);
    }
  });

  it("keeps a long value scrollable by keyboard instead of widening the page", () => {
    const out = html({ invitation: INVITATION, revealed: true });
    // The hand-off block scrolls horizontally, so it needs to be focusable to scroll with arrows.
    expect(/<pre[^>]*tabindex="0"/.test(out)).toBe(true);
  });

  it("offers the scope disclosure as a native details/summary", () => {
    const out = html();
    expect(out).toContain("<details");
    expect(out).toContain("<summary>What this interface can and cannot do</summary>");
  });
});

// --------------------------------------------------------------------- non-visual information

describe("worker-enrollment accessibility — nothing carried by colour alone", () => {
  it("spells out an expired invitation rather than only recolouring it", () => {
    const out = html({
      invitation: { ...INVITATION, expires_at: "2026-07-30T09:00:00+00:00" },
    });
    expect(out).toContain("wenr-expiry--expired");
    expect(out).toContain("Expired"); // the class is not the only signal
  });

  it("spells out a past-expiry row in the table", () => {
    const out = html({ tracked: TRACKED });
    expect(out).toContain("wenr-past-expiry");
    expect(out).toContain("Past its expiry by this browser");
  });

  it("spells out each control's availability in the scope disclosure", () => {
    const out = html();
    expect(out).toContain("wenr-scope__item--yes");
    expect(out).toContain("wenr-scope__item--no");
    expect(out).toContain(">Available<");
    expect(out).toContain(">Not available<");
  });

  it("labels the lifecycle badge for a reader that cannot see the tone", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("Lifecycle state:");
    expect(out).toContain("worker bound");
  });

  it("exposes a blocked lifecycle step's reason to assistive technology", () => {
    const out = html({ status: { ...STATUS, state: "refused" } });
    expect(out).toContain("ui-sr-only");
    expect(out).toContain("no worker enrolled");
  });

  it("states an unestablished evidence rung in words as well as in its icon", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("Not established yet");
    expect(out).toContain("unverifiable");
  });
});

// --------------------------------------------------------------------- document structure

describe("worker-enrollment accessibility — document structure", () => {
  it("has exactly one h1, and it names the page", () => {
    for (const [name, over] of RENDERS) {
      const out = html(over);
      expect(out.match(/<h1\b/g) ?? [], name).toHaveLength(1);
      expect(out, name).toContain("<h1>Worker Enrollment</h1>");
    }
  });

  /**
   * RECORDED HONESTLY, not asserted away: there IS one skipped level in this document, h1 → h3,
   * and it is not this page's. `CyberCard` renders every card title as h3 across the whole app;
   * re-levelling that shared component would relabel every other page and is outside this stream.
   * It is an axe "heading-order" best-practice finding, not a WCAG failure — headings are marked
   * up as headings, and the reading order is correct.
   *
   * What this page DOES own is that it adds no further skip below that, and the test asserts
   * exactly that rather than a weaker "no skips at all" that would have to be suppressed.
   */
  it("adds no heading skip of its own below the shared card titles", () => {
    for (const [name, over] of RENDERS) {
      const out = html(over);
      const levels = [...out.matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
      expect(levels.length, name).toBeGreaterThan(1);
      // Exactly three levels are in play: the page h1, CyberCard's h3, and this page's h4
      // subheads. Anything else means a new heading was introduced without re-levelling.
      for (const level of new Set(levels)) {
        expect([1, 3, 4], `${name}: unexpected h${level}`).toContain(level);
      }
      expect(levels, name).toContain(1);
      // Every h4 sits under an h3 that precedes it — no subhead is orphaned above its card.
      for (let i = 0; i < levels.length; i += 1) {
        if (levels[i] === 4) {
          expect(levels.slice(0, i), `${name}: h4 at index ${i}`).toContain(3);
        }
      }
    }
  });

  it("marks the page heading region as a header landmark", () => {
    expect(html()).toContain("<header");
  });

  it("gives the recovery panel a heading its section is named by", () => {
    const out = html({ status: { ...STATUS, state: "recovery_required" } });
    expect(out).toContain('aria-labelledby="wenr-recovery-title"');
    expect(out).toContain('id="wenr-recovery-title"');
  });

  it("uses a definition list for key/value metadata rather than a layout table", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("<dl");
    expect(out).toContain("<dt>");
    expect(out).toContain("<dd");
  });

  it("gives the safety notices the ARIA role their urgency deserves", () => {
    const handoff = html({ invitation: INVITATION });
    // The bearer-grade warning is assertive; the rest are static notes.
    expect(handoff).toContain('role="alert"');
    expect(handoff).toContain('role="note"');
  });
});
