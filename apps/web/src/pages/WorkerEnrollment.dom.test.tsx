// @vitest-environment jsdom
//
// Real-DOM accessibility contract for the worker-enrollment surface.
//
// The sibling `WorkerEnrollment.a11y.test.tsx` asserts MARKUP properties over a string. This suite
// is the half that string could never reach: an automated accessibility scan of a live document,
// plus focus, tab order and resolved aria references measured against the real DOM. It was added
// after two defects shipped that a DOM-less suite could not see, and it immediately paid for
// itself — the h1 -> h3 heading skip that the previous suite recorded as unfixable is caught here
// as an axe `heading-order` violation, and is now fixed rather than documented.
//
// MACHINE-CHECKED HERE: the axe-core rule set, focus movement after a dismissal, tab order,
// disclosure state, idref resolution and id uniqueness.
//
// NOT machine-checked here: rendered colour contrast and focus-ring visibility, which need real
// layout — see RULES_NOT_MACHINE_CHECKED, and the CSS token discipline the stylesheet states.

import { createElement } from "react";
import { describe, expect, it } from "vitest";

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import { axeViolations, describeViolations, mount, tabbable } from "../testing/dom-a11y";
import {
  WorkerEnrollmentView,
  type WorkerEnrollmentViewProps,
} from "./WorkerEnrollment";
import { INVITATION_CLEARED_NOTICE, trackedFromInvitation } from "./worker-enrollment";

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
  deployment_site_label: "site-one",
};

function props(over: Partial<WorkerEnrollmentViewProps> = {}): WorkerEnrollmentViewProps {
  return {
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
    lookupId: ID,
    onLookupIdChange: () => {},
    onLookup: () => {},
    lookingUp: false,
    status: null,
    statusError: null,
    onRevoke: () => {},
    revoking: false,
    revokeError: null,
    onRecover: () => {},
    recovering: false,
    recoverError: null,
    tracked: [],
    trackedFilter: "all",
    onTrackedFilterChange: () => {},
    onRefreshTracked: () => {},
    onForgetTracked: () => {},
    refreshingIds: [],
    refreshError: null,
    nowMs: NOW,
    ...over,
  };
}

function render(over: Partial<WorkerEnrollmentViewProps> = {}) {
  return mount(createElement(WorkerEnrollmentView, props(over)));
}

const STATES: ReadonlyArray<readonly [string, Partial<WorkerEnrollmentViewProps>]> = [
  ["empty", {}],
  ["invitation held, not revealed", { invitation: INVITATION }],
  ["invitation revealed", { invitation: INVITATION, revealed: true }],
  ["status shown", { status: STATUS }],
  ["status refused", { status: { ...STATUS, state: "refused", refusal_reason: "operator_revoked" } }],
  [
    "status needing recovery",
    { status: { ...STATUS, state: "recovery_required" } },
  ],
  ["tracked rows", { tracked: [trackedFromInvitation(INVITATION)] }],
  ["read only", { permissions: { read: true, manage: false }, status: STATUS }],
  ["manage only", { permissions: { read: false, manage: true } }],
  ["no permission", { permissions: { read: false, manage: false } }],
  [
    "every error surface at once",
    {
      createError: { code: "enrollment_controller_identity_unavailable", text: "" },
      statusError: { code: "enrollment_not_found", text: "" },
      status: STATUS,
      revokeError: { code: "enrollment_revision_conflict", text: "" },
    },
  ],
  ["after a dismissal", { dismissNotice: INVITATION_CLEARED_NOTICE }],
];

describe("WorkerEnrollmentView - automated accessibility scan", () => {
  it.each(STATES)("has no axe violations: %s", async (_name, over) => {
    const view = render(over);
    try {
      const violations = await axeViolations(view.container);
      expect(describeViolations(violations)).toEqual([]);
    } finally {
      view.unmount();
    }
  });

  /**
   * The specific finding this suite was added to catch. The previous DOM-less suite recorded the
   * h1 -> h3 skip as something it could not fix; it is fixed now, and this pins it so the shared
   * card component cannot silently take it back.
   */
  it("has a heading outline with no skipped level", () => {
    for (const [name, over] of STATES) {
      const view = render(over);
      try {
        const levels = [...view.container.querySelectorAll("h1,h2,h3,h4,h5,h6")].map((el) =>
          Number(el.tagName.slice(1)),
        );
        expect(levels[0], name).toBe(1);
        for (let i = 1; i < levels.length; i += 1) {
          expect(levels[i] - levels[i - 1], `${name}: h${levels[i - 1]} -> h${levels[i]}`,
          ).toBeLessThanOrEqual(1);
        }
      } finally {
        view.unmount();
      }
    }
  });
});

describe("WorkerEnrollmentView - focus behaviour a string cannot see", () => {
  /**
   * Dismissing the invitation unmounts the card holding the focused control. A browser then drops
   * focus to <body>, which returns a keyboard user to the top of the document with their place
   * lost. This is the assertion that the recovery actually happens — the string suite could only
   * check that a target element exists.
   */
  it("moves focus to the dismissal notice when the invitation card goes away", () => {
    const view = mount(
      createElement(WorkerEnrollmentView, props({ invitation: INVITATION, revealed: true })),
    );
    try {
      expect(document.activeElement).toBe(document.body);
      view.run(() => {
        view.root.render(
          createElement(
            WorkerEnrollmentView,
            props({ invitation: null, dismissNotice: INVITATION_CLEARED_NOTICE }),
          ),
        );
      });
      const notice = document.getElementById("wenr-dismiss-notice");
      expect(notice).not.toBeNull();
      expect(document.activeElement).toBe(notice);
      // ...and the text is already there when focus and the announcement land on it.
      expect(notice?.textContent).toContain("cannot be shown again");
    } finally {
      view.unmount();
    }
  });

  it("keeps the dismissal notice out of the tab order while it is empty", () => {
    const view = render();
    try {
      const notice = view.container.querySelector<HTMLElement>("#wenr-dismiss-notice");
      expect(notice?.getAttribute("tabindex")).toBe("-1");
      expect(notice?.textContent).toBe("");
      expect(tabbable(view.container)).not.toContain(notice);
    } finally {
      view.unmount();
    }
  });
});

describe("WorkerEnrollmentView - the reveal disclosure in a real tree", () => {
  /**
   * The invitation is bearer-grade. "Nothing about it is in the document until the operator opens
   * it" is a claim about the DOM, so it is checked against the DOM: the values must be absent from
   * `textContent` while closed, not merely visually hidden.
   */
  it("puts no invitation material in the document until it is revealed", () => {
    const closed = render({ invitation: INVITATION, revealed: false });
    try {
      const text = closed.container.textContent ?? "";
      for (const secretish of [
        INVITATION.invitation_id,
        INVITATION.controller_trust_anchor_hex,
        INVITATION.transaction_id,
        INVITATION.release_digest,
      ]) {
        expect(text, secretish.slice(0, 24)).not.toContain(secretish);
      }
    } finally {
      closed.unmount();
    }

    const open = render({ invitation: INVITATION, revealed: true });
    try {
      // Anti-vacuity: prove the values DO appear once revealed, or the check above proves nothing.
      expect(open.container.textContent).toContain(INVITATION.transaction_id);
    } finally {
      open.unmount();
    }
  });

  it("keeps the toggle focusable and its region reference resolvable in both states", () => {
    for (const revealed of [false, true]) {
      const view = render({ invitation: INVITATION, revealed });
      try {
        const toggle = [...view.container.querySelectorAll<HTMLButtonElement>("button")].find(
          (b) => (b.getAttribute("aria-controls") ?? "") === "wenr-handoff-region",
        );
        expect(toggle, String(revealed)).toBeDefined();
        expect(toggle?.getAttribute("aria-expanded")).toBe(String(revealed));
        // The region exists in BOTH states, so the reference is never dangling.
        const region = document.getElementById("wenr-handoff-region");
        expect(region, String(revealed)).not.toBeNull();
        expect(region?.hasAttribute("hidden")).toBe(!revealed);
        expect(tabbable(view.container)).toContain(toggle as HTMLElement);
      } finally {
        view.unmount();
      }
    }
  });
});

describe("WorkerEnrollmentView - gated controls in a real tree", () => {
  it("keeps every disabled control out of the tab order with its reason present as text", () => {
    const view = render({ permissions: { read: false, manage: false } });
    try {
      const disabled = [...view.container.querySelectorAll<HTMLButtonElement>("button[disabled]")];
      expect(disabled.length).toBeGreaterThan(0);
      for (const button of disabled) {
        expect(tabbable(view.container)).not.toContain(button);
        const described = button.getAttribute("aria-describedby");
        expect(described, button.textContent ?? "").not.toBeNull();
        const reason = document.getElementById(described as string);
        expect(reason, described as string).not.toBeNull();
        expect((reason?.textContent ?? "").length).toBeGreaterThan(10);
      }
    } finally {
      view.unmount();
    }
  });

  it("uses a unique id for every element that has one, in every state", () => {
    for (const [name, over] of STATES) {
      const view = render(over);
      try {
        const ids = [...view.container.querySelectorAll<HTMLElement>("[id]")].map((el) => el.id);
        expect(new Set(ids).size, name).toBe(ids.length);
      } finally {
        view.unmount();
      }
    }
  });

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
    expect(checked).toBeGreaterThan(20);
  });
});
