// Fixture data must be observably fixture data.
//
// WHAT THIS TEST IS AVOIDING. The cheap version of this test renders the badge
// and asserts it contains "Sample data". That proves nothing: it restates a
// string this branch also wrote, so it passes just as happily on the day the
// badge stops being connected to the adapter and starts being unconditional
// decoration. This repository has already been burned by exactly that shape --
// a "Simulated execution only" banner whose test kept passing for months after
// the claim became false.
//
// SO THE ASSERTIONS HERE ARE DIFFERENTIAL. The same provider is mounted twice
// against two adapters whose only meaningful difference is the provenance they
// declare, and the test asserts the rendered output DIFFERS accordingly. The
// expected attribute value is read off the adapter object itself, never from a
// literal duplicated here. A badge that ignores the adapter fails the `live`
// case; a badge wired to the wrong field fails both.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AdapterProvider } from "../apps/prototype-suite/core/integrations/AdapterContext";
import type { ControlPlaneAdapter } from "../apps/prototype-suite/core/integrations/adapter";
import { mockAdapter } from "../apps/prototype-suite/core/integrations/mock-adapter";
import { PROVENANCE_ATTRIBUTE, isFixture } from "./provenance";

/**
 * A stand-in for the not-yet-written live adapter.
 *
 * It only has to satisfy the type and declare `live`; no method is called,
 * because the provenance decision happens at mount, before any read. Built by
 * wrapping the mock so this stays compilable as the interface grows -- if a
 * method is added to `ControlPlaneAdapter`, this keeps working, and the test
 * keeps testing provenance rather than becoming a maintenance chore that
 * someone eventually deletes.
 */
const liveAdapter: ControlPlaneAdapter = Object.assign(Object.create(Object.getPrototypeOf(mockAdapter)), mockAdapter, {
  provenance: "live" as const,
});

function render(adapter: ControlPlaneAdapter): string {
  return renderToStaticMarkup(
    createElement(AdapterProvider, { adapter }, createElement("p", null, "workspace content")),
  );
}

/** The badge is identified by its test id, not by its wording. */
const BADGE = 'data-testid="secp-fixture-badge"';

describe("adapter data provenance", () => {
  it("publishes the active adapter's own declared provenance to the DOM", () => {
    // Expectation comes from the adapter object, so this cannot drift into
    // asserting a hardcoded string.
    for (const adapter of [mockAdapter, liveAdapter]) {
      expect(render(adapter)).toContain(`${PROVENANCE_ATTRIBUTE}="${adapter.provenance}"`);
    }
  });

  it("shows the fixture badge for fixture data and NOT for live data", () => {
    const fixtureOut = render(mockAdapter);
    const liveOut = render(liveAdapter);

    // The differential. Both halves matter: the first alone would pass on an
    // unconditional badge, the second alone would pass on no badge at all.
    expect(fixtureOut).toContain(BADGE);
    expect(liveOut).not.toContain(BADGE);
  });

  it("marks live output with a provenance attribute too, so a missing mark is a bug not a claim", () => {
    // If only fixture data were marked, "no attribute" would be an implicit and
    // unverifiable assertion of being real -- indistinguishable from a
    // ProvenanceBoundary that failed to mount.
    expect(render(liveAdapter)).toContain(PROVENANCE_ATTRIBUTE);
  });

  it("keeps the shipped mock adapter declaring itself fixture-backed", () => {
    // Pins the one value the whole mechanism hangs on. Every row this adapter
    // returns is a literal from `mocks/`; if this ever flips to `live`, real
    // operators would be shown sample estates with no marker at all.
    expect(mockAdapter.provenance).toBe("fixture");
    expect(isFixture(mockAdapter)).toBe(true);
    expect(isFixture(liveAdapter)).toBe(false);
  });

  it("defaults to a marked surface when a caller supplies no adapter at all", () => {
    // The migrated prototype's provider defaults to the mock. That default is
    // the single most likely way fixture data reaches a production screen, so
    // the no-argument case is asserted explicitly rather than assumed to follow
    // from the explicit-argument cases above.
    const out = renderToStaticMarkup(
      createElement(AdapterProvider, null, createElement("p", null, "workspace content")),
    );

    expect(out).toContain(BADGE);
    expect(out).toContain(`${PROVENANCE_ATTRIBUTE}="fixture"`);
  });
});
