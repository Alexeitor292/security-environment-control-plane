import {
  approvalVisual,
  authorizationVisual,
  bundleVisual,
  discoveryVisual,
  flowVisual,
  globeVisual,
  lockVisual,
  nodeVisual,
  resolveMotion,
} from "./rive-state";

describe("resolveMotion", () => {
  it("static/reduced always yield static; auto honors the media query", () => {
    expect(resolveMotion("static", false)).toBe("static");
    expect(resolveMotion("reduced", false)).toBe("static");
    expect(resolveMotion("auto", true)).toBe("static");
    expect(resolveMotion("auto", false)).toBe("animate");
  });
});

describe("lockVisual — sealed/authorized/active are separate", () => {
  it("sealed is the default and authorized never implies active", () => {
    expect(lockVisual({})).toBe("sealed");
    expect(lockVisual({ sealed: true })).toBe("sealed");
    expect(lockVisual({ authorized: true })).toBe("authorized");
    // authorized + sealed stays sealed (authorization is a recorded decision)
    expect(lockVisual({ authorized: true, sealed: true })).toBe("sealed");
  });

  it("active requires the explicit active flag AND not sealed", () => {
    expect(lockVisual({ active: true })).toBe("active");
    expect(lockVisual({ active: true, sealed: true })).toBe("sealed");
    expect(lockVisual({ authorized: true, active: false })).toBe("authorized");
  });

  it("refused dominates", () => {
    expect(lockVisual({ refused: true, active: true })).toBe("refused");
  });
});

describe("authorizationVisual", () => {
  it("maps the decision lifecycle and treats active as approved (a decision, not execution)", () => {
    expect(authorizationVisual("draft")).toBe("draft");
    expect(authorizationVisual("awaiting_approval")).toBe("pending");
    expect(authorizationVisual("approved")).toBe("approved");
    expect(authorizationVisual("expired")).toBe("expired");
    expect(authorizationVisual("revoked")).toBe("revoked");
    expect(authorizationVisual("rejected")).toBe("refused");
  });

  it("unknown status resolves to the least-operational draft, never approved", () => {
    expect(authorizationVisual("totally_unknown")).toBe("draft");
    expect(authorizationVisual("")).toBe("draft");
  });
});

describe("flowVisual — sealed shows no traffic; denied is not success", () => {
  it("sealed dominates and shows no flow", () => {
    expect(flowVisual({ sealed: true, running: true, readOnly: true })).toBe("sealed");
  });
  it("denied is distinct from a read-only path", () => {
    expect(flowVisual({ denied: true })).toBe("denied");
    expect(flowVisual({ running: true, readOnly: true })).toBe("read-only");
  });
  it("running without read-only does not animate a write/apply path", () => {
    expect(flowVisual({ running: true, readOnly: false })).toBe("idle");
    expect(flowVisual({})).toBe("idle");
  });
});

describe("nodeVisual", () => {
  it("prioritizes compromised, then sealed, then isolated, then selected", () => {
    expect(nodeVisual({ compromised: true, selected: true })).toBe("compromised");
    expect(nodeVisual({ sealed: true })).toBe("sealed");
    expect(nodeVisual({ isolated: true })).toBe("isolated");
    expect(nodeVisual({ selected: true })).toBe("selected");
    expect(nodeVisual({})).toBe("default");
  });
});

describe("approvalVisual — approved is a recorded decision", () => {
  it("maps decision states and unknown to pending", () => {
    expect(approvalVisual("approved")).toBe("approved");
    expect(approvalVisual("rejected")).toBe("rejected");
    expect(approvalVisual("superseded")).toBe("stale");
    expect(approvalVisual("plan_ready")).toBe("pending");
    expect(approvalVisual("no_such")).toBe("pending");
  });
});

describe("bundleVisual — ready means prepared, not discovery-completed", () => {
  it("failed/sealed dominate; ready requires the flag; default sealed", () => {
    expect(bundleVisual({ failed: true, ready: true })).toBe("failed");
    expect(bundleVisual({ sealed: true })).toBe("sealed");
    expect(bundleVisual({ ready: true })).toBe("ready");
    expect(bundleVisual({ preparing: true })).toBe("preparing");
    expect(bundleVisual({})).toBe("sealed");
  });
});

describe("discoveryVisual — queued != running, completed != eligible", () => {
  it("keeps queued and running distinct", () => {
    expect(discoveryVisual("requested")).toBe("queued");
    expect(discoveryVisual("queued")).toBe("queued");
    expect(discoveryVisual("discovering")).toBe("running");
  });
  it("completed maps from discovered/plan_ready/approved (never asserting eligibility)", () => {
    expect(discoveryVisual("discovered")).toBe("completed");
    expect(discoveryVisual("plan_ready")).toBe("completed");
    expect(discoveryVisual("approved")).toBe("completed");
    expect(discoveryVisual("failed")).toBe("failed");
  });
  it("unknown resolves to queued (least-active), never running/completed", () => {
    expect(discoveryVisual("weird")).toBe("queued");
  });
});

describe("globeVisual", () => {
  it("passes through known states and defaults unknown to decorative ambient", () => {
    for (const s of ["ambient", "sealed", "authorized", "active", "degraded"]) {
      expect(globeVisual(s)).toBe(s);
    }
    expect(globeVisual("operational")).toBe("ambient");
    expect(globeVisual("")).toBe("ambient");
  });
});
