// Rendered-output contract for the enrollment inventory.
//
// These are markup properties, asserted over `renderToStaticMarkup`. The complementary real-DOM
// suite (EnrollmentInventory.dom.test.tsx) covers what a string cannot answer: focus, tab order,
// resolved aria references and an automated accessibility scan.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { EnrollmentStatus } from "../api/types";
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
  return appendPage(EMPTY_PAGE, { items, next_cursor: cursor }, "all");
}

const ROWS = loaded([
  status({ enrollment_id: id("1"), state: "healthy", worker_installation_id: "worker-one" }),
  status({ enrollment_id: id("2"), state: "invited" }),
  status({
    enrollment_id: id("3"),
    state: "refused",
    refusal_reason: "operator_revoked",
    deployment_site_label: "site-two",
  }),
]);

function html(over: Partial<EnrollmentInventoryViewProps> = {}): string {
  const props: EnrollmentInventoryViewProps = {
    permissions: { read: true, manage: true },
    scope: "all",
    onScopeChange: () => {},
    page: ROWS,
    loading: false,
    firstLoad: false,
    listError: null,
    recoveryCursor: null,
    onContinuePastFailure: () => {},
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
    onRecover: () => {},
    recovering: false,
    recoverError: null,
    liveNotice: null,
    nowMs: NOW,
    ...over,
  };
  return renderToStaticMarkup(createElement(EnrollmentInventoryView, props));
}

describe("EnrollmentInventoryView - framing", () => {
  it("names itself and says what it is a read of", () => {
    const out = html();
    expect(out).toContain("Enrollment Inventory");
    expect(out).toContain("Every enrollment in your organization");
  });

  /** The single most important claim on the page: there is nothing here to decide. */
  it("states that there is no approve or reject and that nothing is queued for a decision", () => {
    const out = html();
    expect(out).toContain("There is no approve or reject here");
    expect(out).toContain("nothing is queued for your decision");
    expect(out).toContain("Revoking is the only operator write");
    // and it must never present one
    expect(out).not.toContain(">Approve<");
    expect(out).not.toContain(">Reject<");
  });

  it("says the list is organization-scoped and never cross-organization", () => {
    expect(html()).toContain("Records are never readable across the organization boundary");
  });

  it("says the ordering comes from the controller and is not re-sorted", () => {
    expect(html()).toContain("That order comes from the controller and is not re-sorted here");
  });

  it("says filtering happens on the controller, not over the loaded rows", () => {
    expect(html()).toContain("Filtering is done by the controller, not in this browser");
  });

  it("says nothing polls", () => {
    expect(html()).toContain("Nothing refreshes on a timer");
  });

  it("frames the deployment site as an opaque label that grants nothing", () => {
    const out = html();
    expect(out).toContain("opaque grouping label");
    expect(out).toContain("not a tenant, address, region, endpoint or provider");
    expect(out).toContain("grants nothing");
  });

  it("says the expiry sweep, not this page, moves an unfinished enrollment", () => {
    // Apostrophes are HTML-escaped in static markup, so the assertion avoids them.
    expect(html()).toContain("moved to recovery required by the controller");
    expect(html()).toContain("own expiry sweep, not by this page");
  });

  it("says a settled record cannot be resumed, extended or un-revoked", () => {
    expect(html({ selectedId: id("3") })).toContain(
      "cannot be resumed, extended or un-revoked",
    );
  });
});

describe("EnrollmentInventoryView - counts describe what was loaded", () => {
  it("says the counts are partial while a cursor remains", () => {
    const out = html({ page: loaded([status()], "cursor-1") });
    expect(out).toContain("not your whole organization");
    expect(out).not.toContain("now cover every enrollment in your organization");
  });

  it("says the counts are complete only once every page has been loaded", () => {
    const out = html({ page: loaded([status()], null) });
    expect(out).toContain("now cover every enrollment in your organization");
    expect(out).not.toContain("not your whole organization");
  });

  it("labels the row count as rows loaded, never as a total", () => {
    const out = html();
    expect(out).toContain("Rows loaded");
    expect(out).not.toContain("Total enrollments");
  });

  it("counts an unrecognised state separately and explains it", () => {
    const out = html({ page: loaded([status({ state: "a_state_from_the_future" })]) });
    expect(out).toContain("State not recognised");
    expect(out).toContain("A state this build does not know the name of");
  });
});

describe("EnrollmentInventoryView - rows", () => {
  it("renders one row per enrollment with site, state and revision", () => {
    const out = html();
    expect(out).toContain("site-one");
    expect(out).toContain("site-two");
    expect(out).toContain("at revision 0");
    expect(out).toContain("healthy");
    expect(out).toContain("invited");
  });

  it("shows the worker identity once bound, and says so plainly before then", () => {
    const out = html();
    expect(out).toContain("worker-one");
    expect(out).toContain("No worker bound yet");
    expect(out).toContain("no worker has proved key possession");
  });

  it("shows a bounded refusal code as a code, never as prose", () => {
    const out = html();
    expect(out).toContain("Reason code:");
    expect(out).toContain("operator_revoked");
  });

  it("says the site is not recorded rather than rendering a blank or a guess", () => {
    const missing = status({ enrollment_id: id("9") });
    delete (missing as { deployment_site_label?: string }).deployment_site_label;
    const out = html({ page: loaded([missing]) });
    expect(out).toContain("Not recorded");
    expect(out).not.toContain("undefined");
  });

  it("marks a past-expiry row with words, not only a colour", () => {
    const out = html({
      page: loaded([status({ expires_at: "2026-07-30T09:00:00+00:00" })]),
    });
    expect(out).toContain("Expired");
    expect(out).toContain("Past its expiry by this browser");
  });

  /**
   * The list carries the bounded status projection and nothing else. This is asserted against the
   * rendered document rather than trusted from the type, because the type is a description of a
   * server response and the document is what an operator (and anyone over their shoulder) sees.
   */
  it("renders no invitation material anywhere", () => {
    const out = html({ selectedId: id("1") });
    for (const field of [
      "invitation_id",
      "controller_trust_anchor_hex",
      "controller_origin",
      "transaction_id",
      "release_digest",
      "Reveal invitation",
      "Copy hand-off block",
    ]) {
      expect(out, field).not.toContain(field);
    }
    expect(out).toContain("No invitation material appears on this page");
  });
});

describe("EnrollmentInventoryView - loading and error states", () => {
  it("shows a skeleton only on a structural first load", () => {
    expect(html({ firstLoad: true, loading: true, page: EMPTY_PAGE })).toContain(
      "ui-skeleton",
    );
    // a reload over loaded data keeps the table visible rather than blanking it
    const reloading = html({ firstLoad: false, loading: true });
    expect(reloading).not.toContain("ui-skeleton");
    expect(reloading).toContain("site-one");
  });

  it("announces the load in words, not only as a shape", () => {
    expect(html({ firstLoad: true, loading: true, page: EMPTY_PAGE })).toContain(
      "Loading enrollments",
    );
    expect(html({ liveNotice: "Loaded 2 more; 5 shown. More pages remain." })).toContain(
      "Loaded 2 more; 5 shown. More pages remain.",
    );
  });

  it("distinguishes nothing-loaded-yet from nothing-matches", () => {
    expect(html({ page: EMPTY_PAGE })).toContain("Nothing has been loaded yet");
    expect(html({ page: loaded([], null), scope: "workers" })).toContain(
      "No enrollment in your organization has reached healthy yet",
    );
  });

  /** Backend prose is never rendered: the code resolves fixed copy and the message is discarded. */
  it("renders closed-code copy and never a backend message", () => {
    const out = html({
      listError: { code: "enrollment_forbidden", text: "raw backend prose from the server" },
    });
    expect(out).toContain("belongs to another organization");
    expect(out).not.toContain("raw backend prose from the server");
    expect(out).toContain("enrollment_forbidden");
  });

  /**
   * The three ways this table ends up showing nothing are different events with different
   * remedies, and only one of them is an administrator's problem. A single "something went wrong"
   * would collapse them.
   */
  it("distinguishes a page-integrity refusal from an unreachable API", () => {
    const integrity = html({
      listError: { code: "enrollment_state_corrupt", text: "" },
      page: EMPTY_PAGE,
    });
    expect(integrity).toContain("One enrollment on this page failed its own integrity check");
    expect(integrity).toContain("refused the whole page");
    expect(integrity).toContain("This page contains a record this controller cannot project");
    expect(integrity).toContain("preserved, not repaired");
    expect(integrity).toContain("No row was silently dropped");

    const unreachable = html({
      listError: { code: "api_unreachable", text: "" },
      page: EMPTY_PAGE,
    });
    expect(unreachable).toContain("Cannot reach the control-plane API");
    // the administrator-facing explanation belongs only to the integrity case
    expect(unreachable).not.toContain("cannot project");
    expect(unreachable).not.toContain("No row was silently dropped");
  });

  /** No affordance may be offered that this interface cannot actually aim. */
  it("offers no skip-past-the-bad-row control, since the failing position is not returned", () => {
    const out = html({
      listError: { code: "enrollment_state_corrupt", text: "" },
      page: EMPTY_PAGE,
    });
    expect(out).not.toMatch(/Skip (this|past)/i);
    expect(out).not.toMatch(/Continue past/i);
  });

  it("explains the list-route refusals the controller can actually return", () => {
    expect(html({ listError: { code: "enrollment_cursor_invalid", text: "" } })).toContain(
      "Load the list again from the first page",
    );
    expect(html({ listError: { code: "enrollment_state_invalid", text: "" } })).toContain(
      "That lifecycle filter was refused",
    );
  });

  it("says load-more does not guarantee another row is behind it", () => {
    expect(html()).toContain("does not guarantee another row is behind it");
  });

  /** The backend inconsistency made visible honestly: listed, but the detail refuses. */
  it("says a row that refuses its detail still exists and was not deleted", () => {
    const out = html({
      selectedId: id("1"),
      rereadError: { code: "enrollment_history_inconsistent", text: "" },
    });
    expect(out).toContain("This enrollment is listed, but its full record cannot be served");
    expect(out).toContain("has not been deleted");
    expect(out).toContain("do not run the same integrity checks");
    // the row itself stays on screen — hiding it would be the client-side drop we refuse to do
    expect(out).toContain("sha256:111111111111");
  });

  it("does not show that explanation for an ordinary not-found", () => {
    const out = html({
      selectedId: id("1"),
      rereadError: { code: "enrollment_not_found", text: "" },
    });
    expect(out).toContain("No enrollment exists with that id");
    expect(out).not.toContain("do not run the same integrity checks");
  });

  it("keeps a refused re-read separate from a refused revoke", () => {
    const out = html({
      selectedId: id("2"),
      rereadError: { code: "enrollment_not_found", text: "" },
      revokeError: { code: "enrollment_revision_conflict", text: "" },
    });
    expect(out).toContain("No enrollment exists with that id");
    expect(out).toContain("This enrollment changed since the status you are looking at");
  });
});

describe("EnrollmentInventoryView - permission gating explains itself", () => {
  it("names enrollment:read when the principal cannot list", () => {
    const out = html({ permissions: { read: false, manage: false }, page: EMPTY_PAGE });
    expect(out).toContain("requires the enrollment:read permission");
    expect(out).toContain("Requires the enrollment:read permission.");
  });

  /** The pinned backend decision, stated where it bites. */
  it("explains that manage does not include read when the principal has only manage", () => {
    const out = html({ permissions: { read: false, manage: true }, page: EMPTY_PAGE });
    expect(out).toContain("enrollment:manage does not include it");
    expect(out).toContain("deliberate rather than a fault");
  });

  it("explains that read is not enough to revoke", () => {
    const out = html({ permissions: { read: true, manage: false }, selectedId: id("2") });
    expect(out).toContain("Requires the enrollment:manage permission");
    expect(out).toContain("separate from the enrollment:read this list uses");
  });

  it("says why load-more is unavailable once every page is in", () => {
    expect(html({ page: loaded([status()], null) })).toContain(
      "Every page has been loaded.",
    );
  });
});

describe("EnrollmentInventoryView - selection", () => {
  it("prompts for a selection rather than rendering an empty detail panel", () => {
    const out = html();
    expect(out).toContain("Select an enrollment above to see its evidence");
    expect(out).not.toContain("Evidence recorded so far");
  });

  it("renders the shared status panel for the selected record", () => {
    const out = html({ selectedId: id("1") });
    expect(out).toContain("Selected enrollment");
    expect(out).toContain("Evidence recorded so far");
    expect(out).toContain("Enrollment lifecycle");
    expect(out).toContain("Revoke enrollment");
  });

  it("says the detail is a snapshot at the revision the row was loaded at", () => {
    expect(html({ selectedId: id("1") })).toContain(
      "at the revision that row was loaded at",
    );
  });

  it("marks the selected row by text as well as by style", () => {
    const out = html({ selectedId: id("1") });
    expect(out).toContain('aria-pressed="true"');
    expect(out).toContain(">Showing<");
  });

  /** The second operator write. It exists now, so it is offered — and distinguished from the first. */
  it("offers operator-triggered recovery and says how it differs from revoking", () => {
    const out = html({ selectedId: id("2") });
    expect(out).toContain("Mark for recovery");
    expect(out).toContain("Revoke withdraws the invitation");
    expect(out).toContain("Both are permanent");
    expect(out).toContain("neither can be reversed");
  });

  it("refuses recovery on a record that already ended, with the reason", () => {
    const out = html({ selectedId: id("3") });
    expect(out).toContain("already refused, so there is nothing left to recover");
  });

  it("names the missing permission when the principal cannot mark for recovery", () => {
    const out = html({ permissions: { read: true, manage: false }, selectedId: id("2") });
    expect(out).toContain("Mark for recovery");
    expect(out).toContain("Requires the enrollment:manage permission");
  });

  it("warns that a revoke is permanent before offering it", () => {
    expect(html({ selectedId: id("2") })).toContain("Revoking is permanent");
  });
});
