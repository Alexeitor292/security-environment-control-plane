// The PAGE, not its parts. The units under this page all have their own tests
// and all of them passed while the page rendered `revoked` in the wrong badge --
// because every property here is a property of the COMPOSITION, and composition
// is exactly what a unit test cannot see.
//
// The seam (`query-state.ts`) refuses to hand out a value that lets the six
// states be confused, and `QueryStateView` refuses to render two of them the
// same way. Neither can stop a page from wrapping the whole thing in something
// that flattens it, or from passing the wrong field into the renderer. So these
// assertions read the rendered markup.
//
// WHY THE STATES ARE COMPARED TO EACH OTHER RATHER THAN TO FIXED STRINGS. A test
// that pins each state's copy verbatim goes green when two states are given the
// SAME copy, and pinned copy is the assertion that keeps passing after it stops
// being true. Rendering all six and asserting they are pairwise distinct fails
// the moment any two collapse, whatever wording they collapse onto.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditRowView } from "../../../../../integrations/audit-projection";
import { NOT_SUPPLIED } from "../../../../../integrations/audit-projection";
import { SpatialPrincipalProvider } from "../../../../../integrations/principal";
import {
  failed,
  loading,
  refused,
  served,
  unavailable,
  type QueryState,
} from "../../../../../integrations/query-state";

// The page's own specifier, so the mock intercepts the module the page imports
// rather than a second copy resolved by a different path.
let stubbed: QueryState<AuditRowView> = loading();
vi.mock("../../../../../integrations/use-reader-query", () => ({
  useReaderQuery: () => stubbed,
}));

const { default: AuditPage } = await import("./AuditPage");

function row(over: Partial<AuditRowView> = {}): AuditRowView {
  return {
    id: `id-${over.outcome ?? "success"}`,
    time: "2026-08-05T12:00:00Z",
    actor: "operator@example.test",
    action: "target.register",
    resource: "execution_target 2222",
    outcome: "success",
    origin: NOT_SUPPLIED,
    ...over,
  };
}

/** A row carrying one specific outcome word, whatever the design system makes of it. */
function withOutcome(outcome: string): AuditRowView {
  return row({ id: `id-${outcome}`, outcome });
}

function paint(state: QueryState<AuditRowView>, permissions: readonly string[] = ["audit:read"]) {
  stubbed = state;
  return renderToStaticMarkup(
    createElement(SpatialPrincipalProvider, {
      permissions,
      children: createElement(AuditPage),
    }),
  );
}

/** Just the audit card, so the evidence half's own loading skeleton cannot satisfy an assertion. */
function auditRegion(html: string): string {
  return html.slice(0, html.indexOf("Evidence records"));
}

beforeEach(() => {
  stubbed = loading();
});

describe("the six seam states reach the page without collapsing", () => {
  it("renders every state differently from every other", () => {
    // THE LOAD-BEARING ASSERTION of this file. `empty` versus `ready` is the pair
    // the status type exists to keep apart, and `refused`/`unavailable`/`failed`
    // are the three that a page most easily renders as emptiness -- which tells
    // an operator the system is quiet when it is forbidden, unbuilt or broken.
    const painted = {
      loading: paint(loading()),
      refused: paint(refused(["audit:read"])),
      unavailableBackend: paint(unavailable("no-endpoint", "No route serves this yet.")),
      unavailableFrontend: paint(unavailable("parent-not-selected", "Choose a range first.")),
      failed: paint(failed("connection refused")),
      empty: paint(served([], "live")),
      ready: paint(served([row()], "live")),
    };

    const names = Object.keys(painted) as (keyof typeof painted)[];
    for (const a of names) {
      for (const b of names) {
        if (a >= b) continue;
        expect(auditRegion(painted[a]), `${a} vs ${b} must not render alike`).not.toBe(
          auditRegion(painted[b]),
        );
      }
    }
  });

  it("shows a table for ready and no table for empty", () => {
    // The specific collapse: an empty result set rendered through the table
    // component would produce its own "nothing here" and look like a served page
    // with no rows, erasing the difference between answered-with-nothing and
    // never-answered.
    //
    // THIS ASSERTION IS NOT REDUNDANT WITH THE PAIRWISE ONE ABOVE, measured.
    // Collapsing `empty` into the ready branch was tried, and the pairwise test
    // stayed GREEN: `DataTable` has an empty branch of its own, so the collapsed
    // state still rendered markup unlike any other -- "No audit events match.
    // Adjust the outcome filter or search", advice for a filter nobody applied,
    // about a ledger that is simply empty. Distinct output is necessary and not
    // sufficient; two states can differ and still both be wrong.
    expect(auditRegion(paint(served([row()], "live")))).toContain("<table");
    expect(auditRegion(paint(served([], "live")))).not.toContain("<table");
    expect(auditRegion(paint(served([], "live")))).toContain("No audit events recorded");
  });

  it("never renders a blocked state as an empty table", () => {
    for (const state of [
      refused(["audit:read"]),
      unavailable("no-endpoint", "No route serves this yet."),
      failed("connection refused"),
    ] as QueryState<AuditRowView>[]) {
      expect(auditRegion(paint(state))).not.toContain("<table");
    }
  });

  it("says which permission is missing rather than showing nothing", () => {
    const html = auditRegion(paint(refused(["audit:read"])));
    expect(html).toContain("audit:read");
    expect(html.length).toBeGreaterThan(0);
  });

  it("surfaces the failure text instead of a clean screen", () => {
    // An outage behind a tidy empty state looks healthy. The message has to land.
    expect(auditRegion(paint(failed("connection refused")))).toContain("connection refused");
  });

  it("distinguishes a missing route from a range the operator has not chosen", () => {
    const backend = auditRegion(paint(unavailable("no-endpoint", "No route serves this yet.")));
    const frontend = auditRegion(paint(unavailable("parent-not-selected", "Choose a range first.")));
    expect(backend).not.toBe(frontend);
  });
});

describe("the permission gate is in front of the data, not beside it", () => {
  it("withholds the ledger from a principal without audit:read", () => {
    // The gate must win even when the seam would have served rows -- otherwise
    // the page is relying on the query to refuse, and a query that fails open
    // paints the table.
    const held = auditRegion(paint(served([row()], "live"), ["audit:read"]));
    const denied = auditRegion(paint(served([row()], "live"), []));
    expect(held).toContain("<table");
    expect(denied).not.toContain("<table");
    expect(denied).not.toContain("operator@example.test");
  });

  it("defaults to deny when no principal has been established", () => {
    // Fail-closed: an absent principal is not a permitted one. The seam is set to
    // SERVE ROWS first -- assert against a page that would otherwise paint a
    // table, or this only re-measures the loading state and passes regardless.
    stubbed = served([row()], "live");
    const html = auditRegion(renderToStaticMarkup(createElement(AuditPage)));
    expect(html).not.toContain("<table");
    expect(html).not.toContain("operator@example.test");
    expect(html).toContain("audit:read");
  });

  it("says something when it withholds, rather than rendering nothing", () => {
    const denied = auditRegion(paint(served([row()], "live"), []));
    expect(denied).toContain("audit:read");
  });
});

describe("outcomes reach the DOM as the server wrote them", () => {
  const VOCABULARY = ["success", "denied", "failed", "revoked", "expired", "refused", "failure"];

  it("prints every server outcome verbatim", () => {
    // Including the four outside the migrated union. Dropping or renaming one is
    // the specific failure an audit surface exists to prevent, and both look
    // perfectly fine on screen.
    const html = auditRegion(paint(served(VOCABULARY.map(withOutcome), "live")));
    for (const raw of VOCABULARY) {
      expect(html, `${raw} must appear as itself`).toContain(`>${raw}</span>`);
    }
  });

  it("keeps `failure` and `failed` as two different words on screen", () => {
    const html = auditRegion(paint(served([withOutcome("failure"), withOutcome("failed")], "live")));
    expect(html).toContain(">failure</span>");
    expect(html).toContain(">failed</span>");
  });

  it("gives revoked and expired the error tone, not the neutral one", () => {
    // The defect this file was written for. Both sat in `c-badge--unknown`
    // because the page read `toned` -- a fact about the MIGRATED TYPE -- to pick
    // a colour, so two outcomes the design system has always classified as
    // errors rendered grey in a ledger where `failed` is red.
    for (const raw of ["revoked", "expired"]) {
      const html = auditRegion(paint(served([withOutcome(raw)], "live")));
      expect(html, `${raw} badge tone`).toContain("c-badge--error");
      expect(html, `${raw} must not read as undetermined`).not.toContain("c-badge--unknown");
    }
  });

  it("leaves genuinely unclassified outcomes in the neutral badge", () => {
    // `refused` and `failure` have no entry in the tone map. Neutral is honest;
    // the word carries the meaning and the colour claims nothing.
    for (const raw of ["refused", "failure", "quarantined"]) {
      const html = auditRegion(paint(served([withOutcome(raw)], "live")));
      expect(html, `${raw} badge tone`).toContain("c-badge--unknown");
      expect(html).toContain(`>${raw}</span>`);
    }
  });

  it("renders an outcome nobody has written yet without dropping the row", () => {
    const html = auditRegion(paint(served([withOutcome("chartreuse"), row()], "live")));
    expect(html).toContain(">chartreuse</span>");
    expect(html).toContain("<table");
  });
});

describe("a field with no wire source says so, once", () => {
  it("spends no table column on a value that is always absent", () => {
    // Every cell of an origin column would read the same three words. The
    // column is gone; what must not follow is the absence going unmentioned,
    // which is the difference between "not supplied" and "we forgot".
    const html = auditRegion(paint(served([row()], "live")));
    expect(html).not.toContain("<th>Origin</th>");
  });

  it("states the absence in the card footnote instead", () => {
    // The standing property of the surface, said once where it applies to every
    // row, rather than repeated per row where it applies to none of them
    // specifically.
    const html = auditRegion(paint(served([row()], "live")));
    expect(html).toContain("does not record an origin");
    expect(html).toContain("not supplied");
  });

  it("never renders an absent field as a blank or a dash anywhere", () => {
    // "" and "—" both read as "this record has no origin". The control plane
    // does not publish the field at all, which is a different statement.
    const html = auditRegion(paint(served([row()], "live")));
    expect(html).not.toContain("<td>—</td>");
    expect(html).not.toContain("<td></td>");
  });

  // NOT COVERED HERE, and stated rather than left to be assumed: the per-record
  // `Origin: not supplied by the control plane` line lives in the drawer, which
  // opens on a row click. These assertions render to static markup with no
  // interaction, so the drawer never mounts. Covering it needs a DOM test that
  // clicks a row -- `use-reader-query.test.tsx` shows the `mount` helper that
  // would do it. The footnote above is what this file can prove.
});

describe("the outcome filter does not overstate its reach", () => {
  it("labels itself as covering the loaded entries only", () => {
    // There is no facet endpoint, so this control can only ever offer the values
    // present in the rows already fetched. Calling it "All outcomes" would claim
    // a filter over the ledger.
    const html = auditRegion(paint(served(["success", "revoked"].map(withOutcome), "live")));
    expect(html).toContain("All loaded outcomes");
    expect(html).not.toContain(">All outcomes<");
  });

  it("offers exactly the outcomes present in the loaded rows", () => {
    const html = auditRegion(paint(served([withOutcome("revoked"), withOutcome("success")], "live")));
    expect(html).toContain('value="revoked"');
    expect(html).toContain('value="success"');
    // Not offered, because no loaded row carries it -- the honest limitation.
    expect(html).not.toContain('value="expired"');
  });

  it("offers no outcome options at all when nothing is loaded", () => {
    const html = auditRegion(paint(served([], "live")));
    expect(html).not.toContain('value="success"');
  });
});
