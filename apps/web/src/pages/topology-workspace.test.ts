import type { TeamTopology } from "../api/types";
import {
  EVIDENCE_UNAVAILABLE_REASON,
  HISTORY_LIMIT,
  SIMULATED_MODE_NOTE,
  WORKSPACE_DECLARATIVE_NOTE,
  WORKSPACE_LOCAL_DRAFT_NOTE,
  ZONE_DECLARED_NOTE,
  connectionKind,
  displayDraftForMode,
  draftFromTopology,
  draftKey,
  hasRecordedSimulatorState,
  initialWorkspace,
  isDraftLocalId,
  modeAllowsEditing,
  modeAvailability,
  newDraftNode,
  portsForKind,
  validateDraft,
  validationStale,
  workspaceReducer,
  workspaceSummaryText,
  zonesFromDraft,
  type WorkspaceState,
} from "./topology-workspace";

const TOPO: TeamTopology = {
  instance_id: "i1",
  team_ref: "team-1",
  team_index: 0,
  lifecycle_state: "running",
  nodes: [
    { id: "h1", type: "host", data: { label: "attacker", kind: "attacker", ip: "10.20.0.10" } },
    { id: "h2", type: "host", data: { label: "web", kind: "target", ip: "10.20.0.20" } },
    { id: "s1", type: "host", data: { label: "sensor", kind: "sensor" } },
    { id: "n1", type: "net", data: { label: "team-net", kind: "network", cidr: "10.20.0.0/24" } },
  ],
  edges: [
    { id: "e1", source: "h1", target: "n1", label: "network", data: { kind: "network" } },
    { id: "e2", source: "h2", target: "n1", label: "network", data: { kind: "network" } },
    { id: "e3", source: "s1", target: "h2", label: "monitors", data: { kind: "monitors" } },
  ],
};

function ws(): WorkspaceState {
  return initialWorkspace(TOPO);
}

describe("migration identity", () => {
  it("draft preserves authoritative node and edge identity", () => {
    const d = draftFromTopology(TOPO);
    expect(d.nodes.map((n) => n.id).sort()).toEqual(["h1", "h2", "n1", "s1"]);
    expect(d.edges.map((e) => e.id).sort()).toEqual(["e1", "e2", "e3"]);
  });
});

describe("modes", () => {
  it("evidence is unavailable with an honest reason; simulated gated on recorded state", () => {
    const withState = modeAvailability(true);
    expect(withState.evidence.available).toBe(false);
    expect(withState.evidence.reason).toBe(EVIDENCE_UNAVAILABLE_REASON);
    expect(withState.simulated.available).toBe(true);
    const without = modeAvailability(false);
    expect(without.simulated.available).toBe(false);
    expect(without.planned.available).toBe(true);
  });

  it("only edit mode allows editing", () => {
    expect(modeAllowsEditing("edit")).toBe(true);
    for (const m of ["planned", "validation", "simulated", "evidence"] as const) {
      expect(modeAllowsEditing(m), m).toBe(false);
    }
  });
});

describe("ports and connection compatibility", () => {
  it("derives ports from schema relationships only", () => {
    expect(portsForKind("network").map((p) => p.id)).toEqual(["members"]);
    expect(portsForKind("attacker").map((p) => p.id)).toEqual(["net", "monitored"]);
    expect(portsForKind("sensor").map((p) => p.id)).toEqual([
      "net",
      "monitored",
      "monitor",
    ]);
  });

  it("resolves valid connections and refuses everything else", () => {
    expect(connectionKind("attacker", "net", "network", "members")).toBe("network");
    expect(connectionKind("sensor", "monitor", "target", "monitored")).toBe("monitors");
    // refused shapes
    expect(connectionKind("network", "net", "network", "members")).toBeNull();
    expect(connectionKind("attacker", "net", "target", "monitored")).toBeNull();
    expect(connectionKind("target", "monitor", "attacker", "monitored")).toBeNull();
    expect(connectionKind("sensor", "monitor", "network", "monitored")).toBeNull();
  });
});

describe("workspace reducer — semantic history only, bounded, deterministic", () => {
  it("add + undo + redo round-trips deterministically", () => {
    let s = ws();
    s = workspaceReducer(s, { type: "add-node", kind: "target", x: 10, y: 20 });
    expect(s.draft.nodes).toHaveLength(5);
    expect(s.dirty).toBe(true);
    const added = s.draft.nodes[4];
    expect(isDraftLocalId(added.id)).toBe(true);
    expect(added.ip).toBeNull(); // nothing fabricated

    s = workspaceReducer(s, { type: "undo" });
    expect(s.draft.nodes).toHaveLength(4);
    s = workspaceReducer(s, { type: "redo" });
    expect(s.draft.nodes).toHaveLength(5);
  });

  it("a new edit invalidates redo", () => {
    let s = ws();
    s = workspaceReducer(s, { type: "add-node", kind: "target", x: 0, y: 0 });
    s = workspaceReducer(s, { type: "undo" });
    expect(s.future).toHaveLength(1);
    s = workspaceReducer(s, { type: "move-node", id: "h1", x: 99, y: 99 });
    expect(s.future).toHaveLength(0);
  });

  it("history is bounded", () => {
    let s = ws();
    for (let i = 0; i < HISTORY_LIMIT + 20; i++) {
      s = workspaceReducer(s, { type: "move-node", id: "h1", x: i + 1, y: 0 });
    }
    expect(s.past.length).toBeLessThanOrEqual(HISTORY_LIMIT);
  });

  it("no-op actions do not pollute history", () => {
    let s = ws();
    const before = s.past.length;
    s = workspaceReducer(s, { type: "move-node", id: "h1", x: 40, y: 40 }); // same position
    s = workspaceReducer(s, { type: "remove", nodeIds: [], edgeIds: [] });
    s = workspaceReducer(s, { type: "disconnect", edgeId: "nope" });
    expect(s.past.length).toBe(before);
  });

  it("connect refuses schema-invalid connections before they enter the draft", () => {
    let s = ws();
    const edgesBefore = s.draft.edges.length;
    s = workspaceReducer(s, {
      type: "connect",
      source: "h1",
      sourceHandle: "net",
      target: "h2",
      targetHandle: "monitored",
    });
    expect(s.draft.edges).toHaveLength(edgesBefore);
    expect(s.past).toHaveLength(0);
    // and accepts a valid one, deduplicating repeats
    s = workspaceReducer(s, {
      type: "connect",
      source: "s1",
      sourceHandle: "net",
      target: "n1",
      targetHandle: "members",
    });
    expect(s.draft.edges).toHaveLength(edgesBefore + 1);
    s = workspaceReducer(s, {
      type: "connect",
      source: "s1",
      sourceHandle: "net",
      target: "n1",
      targetHandle: "members",
    });
    expect(s.draft.edges).toHaveLength(edgesBefore + 1);
  });

  it("removing a node removes its edges", () => {
    let s = ws();
    s = workspaceReducer(s, { type: "remove", nodeIds: ["n1"], edgeIds: [] });
    expect(s.draft.nodes.map((n) => n.id)).not.toContain("n1");
    expect(s.draft.edges.map((e) => e.id)).toEqual(["e3"]);
  });

  it("switching authoritative topology resets the draft safely", () => {
    let s = ws();
    s = workspaceReducer(s, { type: "add-node", kind: "target", x: 0, y: 0 });
    const other: TeamTopology = { ...TOPO, instance_id: "i2", team_ref: "team-2" };
    s = workspaceReducer(s, { type: "reset", topo: other });
    expect(s.authoritativeKey).toBe("i2");
    expect(s.dirty).toBe(false);
    expect(s.past).toHaveLength(0);
    expect(s.draft.nodes).toHaveLength(4);
  });

  it("layout applies as a single undoable history entry", () => {
    let s = ws();
    s = workspaceReducer(s, {
      type: "layout",
      positions: { h1: { x: 1, y: 2 }, h2: { x: 3, y: 4 } },
    });
    expect(s.past).toHaveLength(1);
    s = workspaceReducer(s, { type: "undo" });
    expect(s.draft.nodes.find((n) => n.id === "h1")?.x).toBe(40);
  });
});

describe("validation — deterministic, stale-aware, never approval", () => {
  it("a well-formed draft has no errors", () => {
    const findings = validateDraft(draftFromTopology(TOPO));
    expect(findings.filter((f) => f.severity === "error")).toEqual([]);
  });

  it("detects unattached hosts, empty networks, idle sensors, invalid edges", () => {
    let s = ws();
    s = workspaceReducer(s, { type: "add-node", kind: "attacker", x: 0, y: 0 });
    s = workspaceReducer(s, { type: "add-node", kind: "network", x: 0, y: 0 });
    s = workspaceReducer(s, { type: "validate" });
    const codes = s.findings.map((f) => f.code);
    expect(codes).toContain("unattached_host");
    expect(codes).toContain("empty_network");
    // findings link to elements
    expect(s.findings.every((f) => f.nodeId || f.edgeId)).toBe(true);
  });

  it("flags schema-invalid edges and missing references", () => {
    const findings = validateDraft({
      nodes: [
        { id: "a", kind: "attacker", label: "a", role: null, ip: null, cidr: null, x: 0, y: 0 },
        { id: "b", kind: "target", label: "b", role: null, ip: null, cidr: null, x: 0, y: 0 },
      ],
      edges: [
        { id: "x1", source: "a", target: "b", kind: "network" },
        { id: "x2", source: "a", target: "ghost", kind: "monitors" },
      ],
    });
    const codes = findings.map((f) => f.code);
    expect(codes).toContain("invalid_connection");
    expect(codes).toContain("missing_reference");
  });

  it("validation goes stale after an edit", () => {
    let s = ws();
    s = workspaceReducer(s, { type: "validate" });
    expect(validationStale(s)).toBe(false);
    s = workspaceReducer(s, { type: "move-node", id: "h1", x: 500, y: 0 });
    expect(validationStale(s)).toBe(true);
  });

  it("unknown kinds warn and render as generic — never a fake specific type", () => {
    const findings = validateDraft({
      nodes: [
        { id: "q", kind: "quantum", label: "q", role: null, ip: null, cidr: null, x: 0, y: 0 },
      ],
      edges: [],
    });
    expect(findings.map((f) => f.code)).toContain("unknown_kind");
  });
});

describe("zones — declared membership, never isolation", () => {
  it("derives zones deterministically from attached edges", () => {
    const zones = zonesFromDraft(draftFromTopology(TOPO));
    expect(zones).toHaveLength(1);
    expect(zones[0].label).toBe("team-net");
    expect(zones[0].memberIds).toEqual(["h1", "h2"]);
    expect(ZONE_DECLARED_NOTE).toContain("not verified isolation");
  });
});

describe("simulated mode — recorded projection only", () => {
  it("displayDraftForMode never exposes draft-local fabrication in simulated mode", () => {
    let s = ws();
    s = workspaceReducer(s, { type: "add-node", kind: "target", x: 0, y: 0 });
    const authoritative = draftFromTopology(TOPO);
    const shown = displayDraftForMode("simulated", s.draft, authoritative);
    expect(shown.nodes.some((n) => isDraftLocalId(n.id))).toBe(false);
    expect(shown.nodes).toHaveLength(4);
    // every other mode shows the draft
    expect(displayDraftForMode("edit", s.draft, authoritative).nodes).toHaveLength(5);
  });

  it("simulated availability requires a lifecycle implying recorded inventory", () => {
    expect(hasRecordedSimulatorState("running")).toBe(true);
    expect(hasRecordedSimulatorState("resetting")).toBe(true);
    for (const st of ["deploying", "failed", "destroyed", "draft", ""]) {
      expect(hasRecordedSimulatorState(st), st).toBe(false);
    }
  });
});

describe("content-derived dirty", () => {
  it("undoing every edit truthfully restores 'matches plan'", () => {
    let s = ws();
    expect(s.dirty).toBe(false);
    s = workspaceReducer(s, { type: "move-node", id: "h1", x: 500, y: 0 });
    expect(s.dirty).toBe(true);
    s = workspaceReducer(s, { type: "undo" });
    expect(s.dirty).toBe(false);
    s = workspaceReducer(s, { type: "redo" });
    expect(s.dirty).toBe(true);
  });
});

describe("contract edge kinds", () => {
  it("authoritative 'reaches' edges are contract-legal, never declared invalid", () => {
    const findings = validateDraft({
      nodes: [
        { id: "a", kind: "attacker", label: "a", role: null, ip: null, cidr: null, x: 0, y: 0 },
        { id: "b", kind: "target", label: "b", role: null, ip: null, cidr: null, x: 0, y: 0 },
      ],
      edges: [{ id: "r1", source: "a", target: "b", kind: "reaches" }],
    });
    expect(findings.filter((f) => f.code === "invalid_connection")).toEqual([]);
    // but reaches into a network node is still invalid
    const bad = validateDraft({
      nodes: [
        { id: "a", kind: "attacker", label: "a", role: null, ip: null, cidr: null, x: 0, y: 0 },
        { id: "n", kind: "network", label: "n", role: null, ip: null, cidr: null, x: 0, y: 0 },
      ],
      edges: [{ id: "r2", source: "a", target: "n", kind: "reaches" }],
    });
    expect(bad.map((f) => f.code)).toContain("invalid_connection");
  });
});

describe("truth copy", () => {
  it("local draft never claims persistence; edges never claim traffic", () => {
    expect(WORKSPACE_LOCAL_DRAFT_NOTE).toContain("never sent to the backend");
    expect(WORKSPACE_DECLARATIVE_NOTE).toContain("never observed traffic");
    expect(SIMULATED_MODE_NOTE).toContain("not real infrastructure");
  });

  it("new draft nodes fabricate nothing", () => {
    const n = newDraftNode("target", 7, 1, 2);
    expect(n.ip).toBeNull();
    expect(n.cidr).toBeNull();
    expect(n.id).toBe("draft:target-7");
  });

  it("summary carries mode, counts, zones, findings, selection — no live language", () => {
    const s = ws();
    const text = workspaceSummaryText(s.draft, "planned", [], "attacker");
    expect(text).toContain("Planned (read-only)");
    expect(text).toContain("3 hosts");
    expect(text).toContain("Selected: attacker");
    expect(text.toLowerCase()).not.toContain("live");
    expect(text.toLowerCase()).not.toContain("packet");
  });

  it("draftKey is stable under reordering", () => {
    const d = draftFromTopology(TOPO);
    const shuffled = { nodes: [...d.nodes].reverse(), edges: [...d.edges].reverse() };
    expect(draftKey(shuffled)).toBe(draftKey(d));
  });
});
