import { createElement, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter, Outlet, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { ProxmoxCreatePlacement } from "./ProxmoxCreatePlacement";
import { ProxmoxPlacement } from "./ProxmoxPlacement";
import { ProxmoxPlanReview } from "./ProxmoxPlanReview";
import { ProxmoxTeardown } from "./ProxmoxTeardown";
import { ProxmoxTopology } from "./ProxmoxTopology";
import { ProxmoxVerification } from "./ProxmoxVerification";
import { OFFLINE_DATA_LABEL } from "./provenance";
import { EXECUTION_STATUS_NOT_APPLIED } from "./proxmox-types";
import type { RangeContext } from "../RangeLayout";
import type { Range } from "../../../api/range-types";

// Static-render tests, Node env, matching the repo convention (renderToStaticMarkup, no jsdom).
// Effects do not run under static rendering, so no page issues a request here; what is under test
// is the MARKUP each surface commits to, which is exactly where the labelling invariants live.

function range(over: Partial<Range> = {}): Range {
  return {
    id: "rng-1",
    name: "Web Breach Lab",
    template_slug: "web-breach-lab",
    template_name: "Web Breach Lab",
    provider: "local_docker",
    state: "draft",
    state_reason: null,
    created_at: "2026-08-05T00:00:00Z",
    updated_at: "2026-08-05T00:00:00Z",
    deployed_at: null,
    destroyed_at: null,
    competition_id: null,
    current_operation: null,
    residue_verdict: null,
    access: [],
    ...over,
  };
}

function context(r: Range): RangeContext {
  return {
    range: r,
    lifecycle: { phase: r.state, recorded: r.state, known: true } as RangeContext["lifecycle"],
    reloadRange: async () => r,
    polling: false,
  };
}

function html(page: ReactElement, r: Range = range()): string {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      { initialEntries: ["/p"] },
      createElement(
        Routes,
        null,
        createElement(
          Route,
          { path: "/", element: createElement(Outlet, { context: context(r) }) },
          createElement(Route, { path: "p", element: page }),
        ),
      ),
    ),
  );
}

const OFFLINE_PAGES: readonly [string, ReactElement][] = [
  ["Topology", createElement(ProxmoxTopology)],
  ["Plan & apply", createElement(ProxmoxPlanReview)],
  ["Verification", createElement(ProxmoxVerification)],
  ["Teardown", createElement(ProxmoxTeardown)],
];

describe("no fake Proxmox record renders as live data", () => {
  it.each(OFFLINE_PAGES)("%s carries the offline label", (_name, page) => {
    expect(html(page)).toContain(OFFLINE_DATA_LABEL);
  });

  it.each(OFFLINE_PAGES)("%s says no Proxmox host was contacted", (_name, page) => {
    expect(html(page)).toContain("No Proxmox host was contacted");
  });

  it.each(OFFLINE_PAGES)("%s marks each fixture panel on the panel itself", (_name, page) => {
    // Not only in prose: the panel element carries the discriminant, so a reviewer can grep the
    // markup rather than trust the copy.
    expect(html(page)).toContain('data-provenance="offline-fixture"');
  });

  it.each(OFFLINE_PAGES)("%s names the backend module each example models", (_name, page) => {
    expect(html(page)).toMatch(/secp_(api|worker)\./);
  });
});

describe("Placement is live and says so", () => {
  const out = html(createElement(ProxmoxPlacement));

  it("carries no offline label", () => {
    expect(out).not.toContain(OFFLINE_DATA_LABEL);
  });

  it("marks its panels live and stamps the exact endpoint", () => {
    expect(out).toContain('data-provenance="live"');
    expect(out).toContain("GET /api/v1/targets");
    expect(out).toContain("GET /api/v1/enrollment");
    expect(out).toContain("GET /api/v1/target-discovery");
  });

  it("states that no control here pins a range to a target", () => {
    expect(out).toContain("carries no target or worker field");
  });

  it("says which surfaces are not live", () => {
    expect(out).toContain("have no HTTP surface");
  });
});

describe("Teardown mixes live and offline, and labels each", () => {
  const out = html(createElement(ProxmoxTeardown));

  it("marks the live teardown-evidence panel with its endpoint", () => {
    expect(out).toContain('data-provenance="live"');
    expect(out).toContain("teardown-evidence");
  });

  it("still labels every Proxmox-specific panel offline", () => {
    expect(out).toContain('data-provenance="offline-fixture"');
    expect(out).toContain(OFFLINE_DATA_LABEL);
  });
});

describe("apply approval does not read as starting apply", () => {
  const out = html(createElement(ProxmoxPlanReview));

  it("renders EXECUTION STATUS: NOT APPLIED verbatim, unsoftened", () => {
    expect(out).toContain(EXECUTION_STATUS_NOT_APPLIED);
    expect(out).toContain("Execution status");
  });

  it("states that approving records a decision and does not start apply", () => {
    expect(out).toContain("does not start apply");
    expect(out).toContain("Approving a plan records a decision");
  });

  it("offers no destroy control on the apply page", () => {
    expect(out).not.toContain("Approve destroy plan");
  });

  it("shows the destroy hash only under a heading that says the two are separate", () => {
    expect(out).toContain("Destroy authorization is not part of this decision");
  });
});

describe("destroy authorization is not a continuation of apply", () => {
  const out = html(createElement(ProxmoxTeardown));

  it("shows the deletion-set hash, which the apply plan does not have", () => {
    expect(out).toContain("Deletion-set hash");
  });

  it("names the refusal code that stops an apply approval being replayed", () => {
    expect(out).toContain("approval_is_not_for_destroy");
  });

  it("does not describe destroy as continuing or completing the apply", () => {
    const lowered = out.toLowerCase();
    expect(lowered).not.toContain("continue the apply");
    expect(lowered).not.toContain("finish the deployment");
  });

  it("offers no apply-approval control on the destroy page", () => {
    expect(out).not.toContain("Approve plan<");
  });
});

describe("unproven and recovery_required render distinctly", () => {
  const verification = html(createElement(ProxmoxVerification));
  const teardown = html(createElement(ProxmoxTeardown));

  it("labels unobserved verification checks as not observed, not as failed", () => {
    expect(verification).toContain("not observed");
    expect(verification).toContain("Recovery required");
  });

  it("says isolation is UNPROVEN rather than failed when no probe ran", () => {
    expect(verification).toContain("UNPROVEN");
    expect(verification).toContain("nobody looked");
  });

  it("gives unproven rows their own row class, distinct from ok and danger", () => {
    expect(verification).toContain("pmx-row-unproven");
    expect(teardown).toContain("pmx-row-unproven");
  });

  it("states that an unproven teardown is not a clean one", () => {
    expect(teardown).toContain("An unproven result is not a clean result");
  });

  it("renders the undetermined deletion bucket as its own group", () => {
    expect(teardown).toContain("Undetermined");
    expect(teardown).toContain("fourth answer");
  });
});

describe("the browser is never presented as the authorization boundary", () => {
  it.each([
    ["Plan & apply", createElement(ProxmoxPlanReview)],
    ["Teardown", createElement(ProxmoxTeardown)],
  ])("%s says the absence of a control is not the security property", (_name, page) => {
    const out = html(page);
    expect(out).toContain("not the security boundary");
    expect(out).toContain("authorized server-side");
  });
});

describe("provider applicability is stated on every Proxmox surface", () => {
  const pages: readonly [string, ReactElement][] = [
    ["Placement", createElement(ProxmoxPlacement)],
    ...OFFLINE_PAGES,
  ];

  it.each(pages)("%s warns when the range is not a Proxmox range", (_name, page) => {
    const out = html(page, range({ provider: "local_docker" }));
    expect(out).toContain("not Proxmox");
    expect(out).toContain("Nothing on these Proxmox tabs describes this range");
  });

  it.each(pages)("%s does not warn for a Proxmox range", (_name, page) => {
    const out = html(page, range({ provider: "proxmox" }));
    expect(out).not.toContain("Nothing on these Proxmox tabs describes this range");
    expect(out).toContain("recorded against provider &quot;proxmox&quot;");
  });
});

describe("no flag value can reach the browser", () => {
  it.each([["Topology", createElement(ProxmoxTopology)], ...OFFLINE_PAGES])(
    "%s renders no flag-shaped string",
    (_name, page) => {
      const out = html(page);
      // The backend schemas carry no flag field at all; this asserts nothing crept into the
      // fixtures either. `flags_delivered_out_of_band` is a readiness requirement NAME, not a value.
      expect(out).not.toMatch(/SECP\{/);
      expect(out).not.toMatch(/flag\s*[:=]\s*["']/i);
    },
  );
});

describe("scores are never computed in the browser", () => {
  it("says so on the surface that discusses reset clearing them", () => {
    const out = html(createElement(ProxmoxVerification));
    expect(out).toContain("Scores are computed and held by the server");
  });
});

describe("the Proxmox create step offers no control it cannot honour", () => {
  const out = renderToStaticMarkup(
    createElement(MemoryRouter, null, createElement(ProxmoxCreatePlacement)),
  );

  it("is live, and stamps the endpoints it read", () => {
    expect(out).toContain('data-provenance="live"');
    expect(out).toContain("GET /api/v1/targets");
    expect(out).not.toContain(OFFLINE_DATA_LABEL);
  });

  it("explains why there is no target picker rather than shipping one that discards the choice", () => {
    expect(out).toContain("carries no target or worker field");
    expect(out).toContain("Placement is decided server-side");
  });

  it("renders no form control at all", () => {
    expect(out).not.toContain("<select");
    expect(out).not.toContain("<input");
  });
});
