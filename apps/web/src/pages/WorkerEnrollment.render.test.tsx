import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import { WorkerEnrollmentView, type WorkerEnrollmentViewProps } from "./WorkerEnrollment";
import {
  handoffText,
  trackedFromInvitation,
  type TrackedEnrollment,
} from "./worker-enrollment";

const ID = "sha256:" + "a".repeat(64);
const INVITATION_ID = "sha256:" + "b".repeat(64);
const TRANSACTION_ID = "txn-0123456789abcdef";
const NOW = Date.parse("2026-07-30T10:00:00+00:00");

const INVITATION: EnrollmentInvitation = {
  enrollment_id: ID,
  invitation_id: INVITATION_ID,
  controller_installation_id: "controller-aaaaaaaa",
  controller_key_id: "sha256:" + "c".repeat(64),
  controller_trust_anchor_hex: "d".repeat(64),
  controller_origin: "https://controller.example",
  release_digest: "sha256:" + "e".repeat(64),
  transaction_id: TRANSACTION_ID,
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

/** Every state of the closed lifecycle. Used wherever a property must hold in ALL of them — the
 *  previous six-state loop left `refused` and `recovery_required` unchecked. */
const ALL_LIFECYCLE_STATES = [
  "invited",
  "worker_bound",
  "offer_transported",
  "result_transported",
  "verified",
  "healthy",
  "refused",
  "recovery_required",
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

/**
 * Search rendered HTML for a value in every form it could legitimately take.
 *
 * Two encodings sit between a value and the document, and either can silently defeat a plain
 * `includes` — which would turn `expect(out).not.toContain(v)` into an assertion that can never
 * fail, green forever while testing nothing:
 *
 *   * the hand-off block is now `JSON.stringify` output, so a real newline is emitted as the two
 *     characters `\` and `n`. Every hand-off field is an unconstrained server-chosen string, so a
 *     value containing one is permitted by the contract whether or not any field is expected to.
 *   * `renderToStaticMarkup` escapes `&`, `<`, `>`, `"` and `'` in text nodes.
 *
 * All four combinations are checked so the NEGATIVE direction stays honest, and every block of
 * exclusions below is paired with a positive control proving this search can still match at all.
 */
function htmlEscaped(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}
function jsonEncoded(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}
function appearsIn(out: string, value: string): boolean {
  return [value, jsonEncoded(value)].some(
    (form) => out.includes(form) || out.includes(htmlEscaped(form)),
  );
}

/**
 * The invitation fields that may legitimately be in the document BEFORE the operator reveals
 * anything. Everything else in the payload is forbidden — see the derivation below.
 */
const PRE_REVEAL_ALLOWED: Record<string, string> = {
  deployment_site_label:
    "rendered in the pre-reveal meta block on purpose: the operator has to see which site an invitation is for before deciding whether to open it, and the label is an opaque grouping label that grants nothing.",
  state:
    'the closed lifecycle token, always "invited" on creation. Zero entropy, no capability, and it shares vocabulary with this page\'s own copy — asserting it would be noise, not a leak check.',
  revision:
    "the integer 0. A low-entropy scalar that occurs throughout unrelated markup (element ids, the lifetime field), so an assertion about it could only ever be noise.",
};

describe("WorkerEnrollmentView — hand-off material exposure", () => {
  // The single most important behaviour on this page: the invitation is bearer-grade, so it must
  // not be in the document until the operator explicitly asks for it.
  it("renders no invitation material before the operator reveals it", () => {
    const out = html({ invitation: INVITATION, revealed: false });

    // DERIVED FROM THE WHOLE PAYLOAD, not from what the reveal happens to disclose. Deriving from
    // handoffFields() only ever proved "what the reveal discloses is hidden before the reveal" —
    // four of the thirteen invitation fields were outside that set entirely. Starting from
    // Object.values(INVITATION) and subtracting a stated allowlist inverts the default: a field
    // added to EnrollmentInvitation is FORBIDDEN until someone justifies it here.
    //
    // created_at is deliberately NOT allowlisted. It is not rendered today and it is not
    // invitation material, but leaving it in the forbidden set means a future edit that surfaces
    // it before the reveal has to come back to this list and say why.
    const forbidden = Object.entries(INVITATION)
      .filter(([key]) => !(key in PRE_REVEAL_ALLOWED))
      .map(([, value]) => String(value));

    // --- anti-vacuity, all asserted before any negative claim is trusted -----------------------
    // The payload has not silently shrunk, so "every field is classified" still means something.
    expect(Object.keys(INVITATION)).toHaveLength(13);
    // Every allowlist entry names a real field — a stale one would silently widen the exemption.
    for (const key of Object.keys(PRE_REVEAL_ALLOWED)) {
      expect(Object.prototype.hasOwnProperty.call(INVITATION, key), key).toBe(true);
    }
    expect(forbidden).toHaveLength(10);
    expect(new Set(forbidden).size).toBe(10); // distinct, so no value is checked by accident
    // The forbidden set still covers the ENTIRE serialised hand-off artefact. This is the link
    // that keeps the whole-payload derivation at least as strong as deriving from the artefact
    // itself: if a hand-off value ever escaped this set, the coverage claim fails here.
    const artefact = Object.values(JSON.parse(handoffText(INVITATION)) as Record<string, string>);
    expect(artefact).toHaveLength(8);
    for (const value of artefact) expect(forbidden, value).toContain(value);
    expect(forbidden).toContain(INVITATION.controller_trust_anchor_hex);

    for (const value of forbidden) {
      expect(appearsIn(out, value), value).toBe(false);
    }
  });

  // POSITIVE CONTROL for the search the exclusion above depends on. Without it, an `appearsIn`
  // that could never match — because of JSON escaping, HTML escaping, or a typo — would leave the
  // pre-reveal test green while proving nothing at all.
  it("finds every revealed value with the identical search, so the exclusion can fail", () => {
    const out = html({ invitation: INVITATION, revealed: true });
    const artefact = Object.values(JSON.parse(handoffText(INVITATION)) as Record<string, string>);
    expect(artefact).toHaveLength(8);
    for (const value of artefact) expect(appearsIn(out, value), value).toBe(true);
    expect(appearsIn(out, INVITATION.controller_trust_anchor_hex)).toBe(true);
  });

  /**
   * The escaping trap, demonstrated and closed on a real render.
   *
   * Inside the hand-off <pre> the block is JSON, so a value with real newlines is present only in
   * its escaped form. A plain `includes` therefore cannot find it — which means
   * `expect(block).not.toContain(multiLineValue)` would pass whether or not the value leaked.
   * This proves the search actually used by every assertion in this file does find it, and that
   * the gate still excludes it beforehand.
   *
   * The <pre> is isolated with the hardened-slice pattern (prove the anchor, bound the slice,
   * prove the slice's content, only then assert) because the revealed page ALSO renders each
   * value raw in the field list below the block; scanning the whole document would find the
   * verbatim form there and prove nothing about the serialised block.
   */
  it("finds and excludes a multi-line value, the case escaping made invisible", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n";
    const withPem: EnrollmentInvitation = { ...INVITATION, controller_origin: pem };
    const open = html({ invitation: withPem, revealed: true });

    const anchor = '<pre class="wenr-handoff__block"';
    const start = open.indexOf(anchor);
    expect(start, "the hand-off <pre> was renamed — re-anchor this test").toBeGreaterThan(-1);
    const end = open.indexOf("</pre>", start);
    expect(end, "unterminated <pre> — the slice below would run to end of document").toBeGreaterThan(
      start,
    );
    const block = open.slice(start, end);
    // The slice really is the JSON document, not an empty or truncated fragment.
    expect(block).toContain("enrollment_id");
    expect(block).toContain(INVITATION.enrollment_id);

    // The trap: the verbatim value is NOT findable in the serialised block...
    expect(block.includes(pem)).toBe(false);
    // ...but the search this file uses everywhere is not fooled by that.
    expect(appearsIn(block, pem)).toBe(true);
    // And the gate still holds for such a value: nothing of it before the reveal.
    expect(appearsIn(html({ invitation: withPem, revealed: false }), pem)).toBe(false);
  });

  /**
   * Control for the THIRD `appearsIn` branch. The JSON-escaping branch is exercised by the PEM
   * test above and the verbatim branch by every other assertion, but no value in the fixture
   * contains `& < > " '`, so the HTML-escaping branch was never proven to work — it could have
   * been broken from the day it was written and nothing would have shown it.
   *
   * A `controller_origin` carrying a query string does contain them, and it is a realistic value:
   * the field is a server-chosen URL.
   */
  it("finds an HTML-escaped value, the branch the other controls do not reach", () => {
    const origin = 'https://controller.example/?a=1&b=2&q="x"<y>';
    const withEntities: EnrollmentInvitation = { ...INVITATION, controller_origin: origin };
    const out = html({ invitation: withEntities, revealed: true });

    // The trap: React escapes the text, so the verbatim value is not in the document...
    expect(out.includes(origin)).toBe(false);
    // ...and the escaped form is what is actually there.
    expect(out).toContain(htmlEscaped(origin));
    // The search used by every assertion in this file is not fooled by that.
    expect(appearsIn(out, origin)).toBe(true);
    // And the gate still excludes such a value before the reveal.
    expect(appearsIn(html({ invitation: withEntities, revealed: false }), origin)).toBe(false);
  });

  it("still offers the reveal control and states why it matters", () => {
    const out = html({ invitation: INVITATION, revealed: false });
    expect(out).toContain("Reveal invitation for hand-off");
    expect(out).toContain("Treat this invitation as a credential");
    expect(out).toContain("only time these values are available");
  });

  it("renders the block as parseable JSON with the CLI's own key names", () => {
    const out = html({ invitation: INVITATION, revealed: true });
    // The rendered block is HTML-escaped, so compare against the escaped serialisation rather
    // than re-deriving it — this asserts the page renders exactly handoffText(), not a variant.
    expect(out).toContain(htmlEscaped(handoffText(INVITATION)));
    expect(out).toContain("secpctl worker enroll --invitation");
  });

  it("shows the expiry alongside the material", () => {
    expect(html({ invitation: INVITATION, revealed: true })).toContain("Expires in 1 hour");
  });

  it("renders nothing at all when there is no invitation", () => {
    const out = html({ invitation: null });
    expect(out).not.toContain("Hand this to the worker");
    expect(appearsIn(out, INVITATION_ID)).toBe(false);
  });

  it("keeps the reveal control in place as a toggle, so focus is never stranded", () => {
    const closed = html({ invitation: INVITATION, revealed: false });
    const open = html({ invitation: INVITATION, revealed: true });
    expect(closed).toContain('aria-expanded="false"');
    expect(open).toContain('aria-expanded="true"');
    expect(open).toContain("Hide invitation");
    expect(closed).toContain('aria-controls="wenr-handoff-region"');
  });
});

describe("WorkerEnrollmentView — out-of-band verification context", () => {
  it("shows the controller and release identity with what each one proves", () => {
    const out = html({ invitation: INVITATION, revealed: true });
    expect(out).toContain("Confirm this out of band");
    expect(out).toContain("Controller trust anchor");
    expect(out).toContain("Read them back to the controller&#x27;s operator");
    expect(out).toContain("A content address, not a download location");
  });

  // It is bootstrap context, but it is still shown behind the same gate: adding it to the
  // pre-reveal surface would have widened exactly the exposure the gate exists to prevent.
  it("lives inside the reveal gate, not beside it", () => {
    expect(html({ invitation: INVITATION, revealed: false })).not.toContain(
      "Confirm this out of band",
    );
  });
});

describe("WorkerEnrollmentView — no fabricated lifecycle authority", () => {
  /**
   * Every `<button>` element in the document, attributes and label text included. Buttons cannot
   * nest, so the non-greedy match is exact.
   *
   * This replaces a document-wide ban on four literals. That ban had to go: the page now NAMES the
   * controls it does not have, in prose, because saying so is the deliverable — and a document-wide
   * substring ban is unsatisfiable once the page is allowed to use the words. Scanning only
   * interactive elements is what the ban was ever trying to express, and it is strictly stronger:
   * it covers ANY approve/reject-shaped affordance rather than four exact strings, and it now runs
   * over all eight lifecycle states rather than six.
   */
  function buttonElements(out: string): string[] {
    return out.match(/<button\b[\s\S]*?<\/button>/g) ?? [];
  }

  it("offers no approve, reject, deny or accept affordance in any lifecycle state", () => {
    for (const state of ALL_LIFECYCLE_STATES) {
      const buttons = buttonElements(html({ status: { ...STATUS, state } }));
      // Anti-vacuity: this page always renders controls, so an empty extraction means the scan
      // broke — never that the page is clean.
      expect(buttons.length, state).toBeGreaterThan(3);
      for (const button of buttons) {
        expect(button, `${state}: ${button}`).not.toMatch(/approve|reject|deny|accept/i);
      }
    }
  });

  it("declares the absent controls in copy rather than quietly omitting them", () => {
    const out = html();
    expect(out).toContain("What this interface can and cannot do");
    expect(out).toContain("Approve or reject an enrollment");
    expect(out).toContain("Not available");
    expect(out).toContain("no approval edge");
    expect(out).toContain("no list route");
    expect(out).toContain("no separate cancel route");
  });

  it("says plainly that only the worker advances an enrollment", () => {
    expect(html()).toContain("Enrollment advances only on evidence the worker signs");
  });

  it("discloses that there is no inventory or queue", () => {
    expect(html()).toContain("no enrollment inventory or pending queue");
  });

  it("labels the tracked list as tab-local, not a server inventory", () => {
    expect(html()).toContain("kept only until you reload");
    expect(html()).toContain("This is not an inventory");
  });
});

describe("WorkerEnrollmentView — permission gating explains itself", () => {
  it("names the missing permission next to a disabled create", () => {
    const out = html({ permissions: { read: true, manage: false } });
    expect(out).toContain("Requires the enrollment:manage permission.");
    expect(out).toContain("disabled");
  });

  it("names the missing permission next to a disabled look-up", () => {
    const out = html({ permissions: { read: false, manage: true } });
    expect(out).toContain("Requires the enrollment:read permission.");
  });

  // The backend pins that manage does not imply read; the page says so before it bites.
  it("warns a manage-only principal that status will be refused", () => {
    const out = html({ permissions: { read: false, manage: true } });
    expect(out).toContain("manage does not include read");
  });

  it("does not warn when the principal holds both", () => {
    expect(html({ permissions: { read: true, manage: true } })).not.toContain(
      "manage does not include read",
    );
  });

  it("disables a row refresh for a principal that cannot read status", () => {
    const tracked = [trackedFromInvitation(INVITATION)];
    const out = html({ tracked, permissions: { read: false, manage: true } });
    expect(out).toContain("Refresh");
    expect(out).toContain("disabled");
  });
});

describe("WorkerEnrollmentView — status, evidence and recovery", () => {
  it("renders the lifecycle state as a badge and the bounded projection rows", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("worker bound"); // statusDisplayLabel replaces underscores
    expect(out).toContain("cccccccccccc");
    expect(out).toContain("worker-one");
  });

  it("names an unestablished fingerprint rather than leaving it blank", () => {
    expect(html({ status: STATUS })).toContain("Not established yet");
  });

  it("renders each evidence rung with the projection field it reads", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("Evidence recorded so far");
    for (const field of [
      "controller_key_fingerprint",
      "worker_key_fingerprint",
      "release_fingerprint",
      "offer_fingerprint",
      "result_fingerprint",
    ]) {
      expect(out, field).toContain(field);
    }
    expect(out).toContain("Worker key possession");
  });

  // An unreached rung must not read as a failure anywhere on the surface.
  it("renders an unreached rung as unverifiable, never as a failed check", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("unverifiable");
    expect(out).not.toContain("ui-evidence--fail");
    expect(out).toContain("not a failed check");
  });

  it("offers revoke on a live enrollment and explains that it is permanent", () => {
    const out = html({ status: STATUS });
    expect(out).toContain("Revoke enrollment");
    expect(out).toContain("cannot be undone");
  });

  it("disables revoke on a terminal enrollment and says which terminal", () => {
    const out = html({ status: { ...STATUS, state: "refused" } });
    expect(out).toContain("already refused");
    expect(out).toContain("disabled");
  });

  it("shows recovery guidance on both terminals, and offers no repair", () => {
    const refused = html({ status: { ...STATUS, state: "refused" } });
    expect(refused).toContain("Refused — no worker was enrolled");
    expect(refused).toContain("Create a new invitation if you still intend");

    const recovery = html({ status: { ...STATUS, state: "recovery_required" } });
    expect(recovery).toContain("Recovery required — no worker was enrolled");
    expect(recovery).toContain("cannot be resumed or extended");
  });

  it("flags a past expiry as an observation and leaves the lifecycle to the controller", () => {
    const out = html({
      status: { ...STATUS, expires_at: "2026-07-30T09:00:00+00:00" },
    });
    expect(out).toContain("Past its expiry");
    expect(out).toContain("expiry sweep");
    expect(out).toContain("Expired");
    // It has not been relabelled as the terminal the controller has not yet assigned.
    expect(out).not.toContain("Recovery required — no worker was enrolled");
  });

  it("shows no recovery panel while an enrollment is live and in time", () => {
    const out = html({ status: STATUS });
    expect(out).not.toContain("Past its expiry");
    expect(out).not.toContain("no worker was enrolled");
  });

  it("renders no status card until an enrollment was looked up", () => {
    expect(html({ status: null })).not.toContain("Enrollment status");
  });
});

describe("WorkerEnrollmentView — tab-local working set", () => {
  const tracked: TrackedEnrollment[] = [
    trackedFromInvitation(INVITATION),
    {
      enrollmentId: "sha256:" + "9".repeat(64),
      siteLabel: "",
      createdAt: "",
      expiresAt: "2026-07-30T09:00:00+00:00",
      state: "offer_transported",
      revision: 3,
    },
    {
      enrollmentId: "sha256:" + "8".repeat(64),
      siteLabel: "site-two",
      createdAt: "2026-07-30T09:00:00+00:00",
      expiresAt: "2026-07-30T11:00:00+00:00",
      state: "healthy",
      revision: 7,
    },
  ];

  it("summarises the working set without claiming it is a server query", () => {
    const out = html({ tracked });
    expect(out).toContain("Tracked in this tab");
    expect(out).toContain("Waiting on a worker");
    expect(out).toContain("Worker healthy");
    expect(out).toContain("Past expiry");
    expect(out).toContain("the control plane has no endpoint that lists enrollments");
    expect(out).toContain("Nothing polls");
  });

  it("renders one row per tracked enrollment with its last observed revision", () => {
    const out = html({ tracked });
    expect(out).toContain("at revision 3");
    expect(out).toContain("at revision 7");
    expect(out).toContain("offer transported");
    expect(out).toContain("site-two");
  });

  it("says the site label is unknown rather than inventing one for a looked-up row", () => {
    expect(html({ tracked })).toContain("Not known in this tab");
  });

  it("marks a past-expiry row in words, not by colour alone", () => {
    const out = html({ tracked });
    expect(out).toContain("Past its expiry by this browser&#x27;s clock");
    expect(out).toContain("expiry sweep is what moves an unfinished enrollment");
  });

  it("filters to one group and keeps the unrecognised reachable under All tracked", () => {
    const odd: TrackedEnrollment[] = [
      ...tracked,
      { ...tracked[2], enrollmentId: "sha256:" + "7".repeat(64), state: "some_future_state" },
    ];
    const pending = html({ tracked: odd, trackedFilter: "pending" });
    expect(pending).not.toContain("some future state");
    const all = html({ tracked: odd, trackedFilter: "all" });
    expect(all).toContain("some future state");
    expect(all).toContain("State not recognised");
  });

  it("offers only a refresh and a tab-local forget on each row", () => {
    const out = html({ tracked });
    expect(out).toContain("Refresh");
    expect(out).toContain("Forget");
    expect(out).toContain("changes nothing on the control plane");
  });

  it("shows only the refreshing row as busy", () => {
    const out = html({ tracked, refreshingId: tracked[0].enrollmentId });
    expect(out).toContain("Refreshing…");
    expect(out.match(/Refreshing…/g)).toHaveLength(1);
  });

  it("explains an empty working set instead of implying nothing exists server-side", () => {
    const out = html({ tracked: [] });
    expect(out).toContain("Nothing to show under this filter");
    expect(out).toContain("it will be tracked here for this tab");
  });

  // The row carries the handle and the labels; the capability never reaches it.
  it("puts no invitation material in a row", () => {
    const out = html({ tracked: [trackedFromInvitation(INVITATION)] });
    for (const value of [
      INVITATION.invitation_id,
      INVITATION.controller_key_id,
      INVITATION.controller_trust_anchor_hex,
      INVITATION.release_digest,
      INVITATION.transaction_id,
      INVITATION.controller_origin,
    ]) {
      expect(appearsIn(out, value), value).toBe(false);
    }
    // Positive control: the row does render the handle it is addressed by.
    expect(appearsIn(out, INVITATION.enrollment_id)).toBe(true);
  });
});

describe("WorkerEnrollmentView — errors are closed-code copy", () => {
  // Real prose, so the assertion below CAN fail. With text: "" it could not: changing the page
  // from `message: ""` to `message: createError.text` would have kept every one of these green.
  const BACKEND_PROSE = "BACKEND PROSE THAT MUST NEVER REACH THE DOCUMENT";

  it("renders mapped copy plus the code, never a backend message", () => {
    const out = html({
      createError: {
        code: "enrollment_controller_identity_unavailable",
        text: BACKEND_PROSE,
      },
    });
    expect(out).toContain("no active enrollment identity yet");
    expect(out).toContain("enrollment_controller_identity_unavailable");
    expect(out).not.toContain(BACKEND_PROSE);
  });

  // All three ClosedCodeError call sites pass `message: ""` literally, so backend prose is
  // structurally discarded rather than filtered. Each site is proven, not just the first.
  it("discards backend prose at every error site, not only on create", () => {
    const cases: Partial<WorkerEnrollmentViewProps>[] = [
      { createError: { code: "enrollment_scope_mismatch", text: BACKEND_PROSE } },
      { statusError: { code: "enrollment_not_found", text: BACKEND_PROSE } },
      {
        status: STATUS,
        revokeError: { code: "enrollment_revision_conflict", text: BACKEND_PROSE },
      },
    ];
    for (const over of cases) {
      const out = html(over);
      expect(out, JSON.stringify(over)).not.toContain(BACKEND_PROSE);
    }
    // Positive control: the mapped copy for each of those codes IS rendered, so the assertions
    // above are about prose being dropped and not about the error surface failing to render.
    expect(html(cases[0])).toContain("deployment site label was rejected");
    expect(html(cases[1])).toContain("No enrollment exists with that id");
    expect(html(cases[2])).toContain("This enrollment changed since the status");
  });

  it("frames the uncommissioned-controller refusal as expected, not as a failure", () => {
    const out = html({
      createError: {
        code: "enrollment_controller_identity_unavailable",
        text: BACKEND_PROSE,
      },
    });
    expect(out).toContain("nothing is broken");
  });

  it("distinguishes a missing permission from a cross-organization refusal", () => {
    expect(html({ statusError: { code: "forbidden", text: BACKEND_PROSE } })).toContain(
      "separate permissions",
    );
    expect(
      html({ statusError: { code: "enrollment_forbidden", text: BACKEND_PROSE } }),
    ).toContain("another organization");
  });
});

describe("WorkerEnrollmentView — busy states", () => {
  it("disables and relabels the in-flight action", () => {
    expect(html({ creating: true })).toContain("Creating…");
    expect(html({ lookingUp: true })).toContain("Loading…");
    expect(html({ status: STATUS, revoking: true })).toContain("Revoking…");
  });
});
