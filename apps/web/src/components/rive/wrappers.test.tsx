import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";

import {
  RiveApprovalStamp,
  RiveAuthorizationPulse,
  RiveDiscoveryScan,
  RivePacketFlow,
  RiveSealedLock,
  RiveTopologyNode,
  RiveWorkerBundle,
} from "./wrappers";

/** Server-render a wrapper; Suspense yields the static fallback (the Rive
 *  overlay is client-only), which is exactly the fallback we assert on. */
function render(el: React.ReactElement): string {
  return renderToStaticMarkup(el);
}

describe("Rive wrappers render an accessible static fallback (no .riv needed)", () => {
  it("sealed lock keeps sealed / authorized / active separate in the aria-label", () => {
    expect(render(createElement(RiveSealedLock, { sealed: true, label: "Resolver" })))
      .toContain('data-state="sealed"');
    expect(render(createElement(RiveSealedLock, { authorized: true, label: "Resolver" })))
      .toContain("authorization recorded");
    // authorized + sealed stays sealed (a decision is not activation)
    const both = render(createElement(RiveSealedLock, { authorized: true, sealed: true, label: "R" }));
    expect(both).toContain('data-state="sealed"');
    // active requires the explicit flag and not sealed
    expect(render(createElement(RiveSealedLock, { active: true, label: "R" })))
      .toContain('data-state="active"');
    expect(render(createElement(RiveSealedLock, { active: true, sealed: true, label: "R" })))
      .toContain('data-state="sealed"');
  });

  it("packet flow shows sealed as no-traffic and denied as not-success", () => {
    expect(render(createElement(RivePacketFlow, { sealed: true, running: true, readOnly: true, label: "P" })))
      .toContain("sealed — no traffic");
    expect(render(createElement(RivePacketFlow, { denied: true, label: "P" }))).toContain("denied");
    expect(render(createElement(RivePacketFlow, { running: true, readOnly: true, label: "P" })))
      .toContain("read-only path");
  });

  it("approval stamp says decision recorded for approved, never execution", () => {
    const svg = render(createElement(RiveApprovalStamp, { status: "approved", label: "Plan" }));
    expect(svg).toContain("decision recorded");
    expect(svg.toLowerCase()).not.toContain("executed");
    expect(svg.toLowerCase()).not.toContain("deployed");
  });

  it("worker bundle 'ready' says prepared, not discovery-completed", () => {
    const svg = render(createElement(RiveWorkerBundle, { ready: true, label: "Bundle" }));
    expect(svg).toContain("bundle prepared");
    expect(svg.toLowerCase()).not.toContain("discovery completed");
  });

  it("discovery scan keeps queued/running/completed distinct and completed != eligible", () => {
    expect(render(createElement(RiveDiscoveryScan, { status: "requested", label: "D" }))).toContain('data-state="queued"');
    expect(render(createElement(RiveDiscoveryScan, { status: "discovering", label: "D" }))).toContain('data-state="running"');
    const completed = render(createElement(RiveDiscoveryScan, { status: "discovered", label: "D" }));
    expect(completed).toContain('data-state="completed"');
    expect(completed.toLowerCase()).not.toContain("eligible");
  });

  it("authorization pulse maps unknown to draft (least-operational)", () => {
    expect(render(createElement(RiveAuthorizationPulse, { status: "bogus", label: "A" })))
      .toContain('data-state="draft"');
  });

  it("topology node conveys state by shape (data-state), not color alone", () => {
    for (const [props, state] of [
      [{ compromised: true }, "compromised"],
      [{ isolated: true }, "isolated"],
      [{ sealed: true }, "sealed"],
      [{ selected: true }, "selected"],
      [{}, "default"],
    ] as const) {
      expect(render(createElement(RiveTopologyNode, { ...props, label: "N" })))
        .toContain(`data-state="${state}"`);
    }
  });

  it("every fallback exposes role=img with a label and bakes no raw color", () => {
    const svg = render(createElement(RiveSealedLock, { sealed: true, label: "Resolver" }));
    expect(svg).toContain('role="img"');
    expect(svg).toContain("aria-label");
    expect(svg).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
    expect(svg).not.toMatch(/rgb\(/);
  });
});
