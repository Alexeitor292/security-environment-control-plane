import { ApiClientError } from "../api/client";
import type { TeamTopology } from "../api/types";
import {
  APPROVAL_RECORDS_ONLY_NOTE,
  DEPLOY_DISPATCH_NOTE,
  DESTROY_DISPATCH_NOTE,
  EDITOR_REVISION_NOTE,
  ENVIRONMENTS_ERROR_TEXT,
  LIBRARY_INTRO,
  TEMPLATE_IS_DEFINITION_NOTE,
  TOPOLOGY_DECLARATIVE_NOTE,
  VALIDATION_IS_NOT_APPROVAL_NOTE,
  canDecidePlan,
  canDeployExercise,
  canDestroyExercise,
  canGeneratePlan,
  canResetInstance,
  canSubmitPlan,
  canValidateExercise,
  definitionSummary,
  edgeLegendLabel,
  exerciseRailItems,
  exerciseRows,
  exerciseStatusLabel,
  isExerciseOffRail,
  nodeIconName,
  nodeKindClass,
  onlyNotFoundAsNull,
  planStatusLabel,
  recordedDate,
  topologyGraph,
  topologySummaryText,
  validationView,
} from "./environments-view";

// ---------------------------------------------------------------- library

describe("library truth copy", () => {
  it("a template is a definition only, never a running/deployable environment", () => {
    expect(LIBRARY_INTRO).toContain("definition only");
    expect(LIBRARY_INTRO).toContain("not a running environment");
    expect(TEMPLATE_IS_DEFINITION_NOTE).toContain("not approval");
    expect(TEMPLATE_IS_DEFINITION_NOTE).toContain("not deployment");
  });
});

// ------------------------------------------------------ definition summary

describe("definitionSummary — allowlisted and bounded", () => {
  const SPEC = {
    apiVersion: "controlplane.security/v1alpha1",
    kind: "Environment",
    metadata: { name: "web-breach-101", displayName: "Web Breach 101" },
    spec: {
      teams: { count: 2, isolationPolicy: "strict" },
      networks: [
        { name: "team-network", cidrStrategy: "per-team", baseCidr: "10.20.0.0/16", isolated: true },
      ],
      roles: [
        { name: "attacker", kind: "attacker", image: "kali-linux", network: "team-network" },
      ],
      vulnerabilityPacks: [{ ref: "weak-ssh", version: "1.0.0" }],
      telemetry: { providers: ["wazuh"] },
      validation: { provider: "ctfd", objectives: [{ id: "o1" }] },
      requiredPlugins: ["simulator"],
    },
  };

  it("extracts only known fields", () => {
    const s = definitionSummary(SPEC)!;
    expect(s.displayName).toBe("Web Breach 101");
    expect(s.teamCount).toBe(2);
    expect(s.isolationPolicy).toBe("strict");
    expect(s.networks).toHaveLength(1);
    expect(s.roles[0]).toEqual({
      name: "attacker",
      kind: "attacker",
      image: "kali-linux",
      network: "team-network",
    });
    expect(s.vulnerabilityPacks).toEqual(["weak-ssh@1.0.0"]);
    expect(s.objectiveCount).toBe(1);
    expect(s.unrecognizedSpecKeys).toBe(0);
  });

  it("counts unrecognized spec keys instead of rendering them", () => {
    const s = definitionSummary({
      ...SPEC,
      spec: { ...SPEC.spec, secretStuff: { token: "x" }, extra: 1 },
    })!;
    expect(s.unrecognizedSpecKeys).toBe(2);
  });

  it("caps list sizes and string lengths; drops non-object entries", () => {
    const s = definitionSummary({
      spec: {
        roles: [...Array(100).fill({ name: "r", kind: "k", image: "i", network: "n" }), "junk"],
        networks: [{ name: "x".repeat(500), cidrStrategy: "s", baseCidr: "c" }],
      },
    })!;
    expect(s.roles.length).toBeLessThanOrEqual(32);
    expect(s.networks[0].name.length).toBeLessThanOrEqual(120);
  });

  it("returns null for non-object input, never throws", () => {
    expect(definitionSummary(null)).toBeNull();
    expect(definitionSummary("scalar")).toBeNull();
    expect(definitionSummary([1, 2])).toBeNull();
  });
});

// --------------------------------------------------------- validation view

describe("validationView — not-run, valid, warnings, invalid, stale distinct", () => {
  it("not run is never a failure", () => {
    const v = validationView(null);
    expect(v.state).toBe("not-run");
    expect(v.errors).toEqual([]);
  });

  it("warnings are never plain success", () => {
    const v = validationView({ ok: true, errors: [], warnings: ["w1"] });
    expect(v.state).toBe("valid-with-warnings");
    expect(v.warnings).toEqual(["w1"]);
  });

  it("valid says schema-only, never approval", () => {
    const v = validationView({ ok: true, errors: [], warnings: [] });
    expect(v.state).toBe("valid");
    expect(v.label.toLowerCase()).toContain("not approval");
    expect(VALIDATION_IS_NOT_APPROVAL_NOTE).toContain("not an approved plan");
  });

  it("stale marks results whose source changed", () => {
    const v = validationView({ ok: true, errors: [], warnings: [] }, true);
    expect(v.state).toBe("stale");
    expect(v.label).toContain("re-run");
  });

  it("bounds finding counts and lengths, counting what was dropped", () => {
    const v = validationView({
      ok: false,
      errors: Array(30).fill("e".repeat(500)),
      warnings: [],
    });
    expect(v.state).toBe("invalid");
    expect(v.errors).toHaveLength(20);
    expect(v.errors[0].length).toBeLessThanOrEqual(300);
    expect(v.droppedFindings).toBe(10);
  });
});

// ------------------------------------------------------ exercise lifecycle

describe("exercise lifecycle — truthful labels and rail", () => {
  it("labels keep dispatched/simulated distinctions explicit", () => {
    expect(exerciseStatusLabel("approved")).toBe("Approved (not deployed)");
    expect(exerciseStatusLabel("deploying")).toBe("Deploying (dispatched work)");
    expect(exerciseStatusLabel("running")).toBe("Running (simulated)");
    expect(exerciseStatusLabel("destroying")).toBe("Destroying (dispatched work)");
    expect(exerciseStatusLabel("unknown_state")).toBe("unknown_state");
  });

  it("rail: earlier steps complete, later blocked; off-rail blocks everything", () => {
    const atApproved = exerciseRailItems("approved");
    expect(atApproved.find((i) => i.id === "validated")?.state).toBe("complete");
    expect(atApproved.find((i) => i.id === "approved")?.state).toBe("current");
    expect(atApproved.find((i) => i.id === "running")?.state).toBe("blocked");

    for (const off of ["failed", "destroying", "destroyed", "resetting"]) {
      expect(isExerciseOffRail(off), off).toBe(true);
      expect(exerciseRailItems(off).every((i) => i.state === "blocked"), off).toBe(true);
    }
  });

  it("approval step never reads complete for a skipped path", () => {
    // deploying implies approval happened (backend enforces the gate), so
    // earlier steps read complete only because the lifecycle passed them.
    const atDeploying = exerciseRailItems("deploying");
    expect(atDeploying.find((i) => i.id === "approved")?.state).toBe("complete");
    // but a draft exercise shows nothing complete
    const atDraft = exerciseRailItems("draft");
    expect(atDraft.filter((i) => i.state === "complete")).toHaveLength(0);
  });
});

describe("exercise predicates — exactly the pre-redesign gating", () => {
  it("mirrors the original inline conditions", () => {
    expect(canValidateExercise("draft")).toBe(true);
    expect(canValidateExercise("validated")).toBe(false);
    expect(canGeneratePlan("validated")).toBe(true);
    expect(canGeneratePlan("draft")).toBe(false);
    expect(canDeployExercise("approved")).toBe(true);
    expect(canDeployExercise("awaiting_approval")).toBe(false);
    expect(canDestroyExercise("running")).toBe(true);
    expect(canDestroyExercise("failed")).toBe(true);
    expect(canDestroyExercise("destroyed")).toBe(false);
    expect(canResetInstance({ lifecycle_state: "running" })).toBe(true);
    expect(canResetInstance({ lifecycle_state: "failed" })).toBe(false);
  });
});

// ------------------------------------------------------------- plan review

describe("plan review", () => {
  it("preserves submit/decide predicates exactly", () => {
    expect(canSubmitPlan({ status: "generated" })).toBe(true);
    expect(canSubmitPlan({ status: "awaiting_approval" })).toBe(false);
    expect(canDecidePlan({ status: "awaiting_approval" })).toBe(true);
    expect(canDecidePlan({ status: "approved" })).toBe(false);
    expect(canDecidePlan({ status: "rejected" })).toBe(false);
  });

  it("approved label records a decision, never deployment", () => {
    expect(planStatusLabel("approved")).toContain("not deployed");
    expect(APPROVAL_RECORDS_ONLY_NOTE).toContain("does not deploy");
    expect(APPROVAL_RECORDS_ONLY_NOTE).toContain("exact plan hash");
  });

  it("deploy/destroy copy states dispatching, not completion", () => {
    expect(DEPLOY_DISPATCH_NOTE).toContain("Dispatching is not running");
    expect(DEPLOY_DISPATCH_NOTE.toLowerCase()).toContain("simulated");
    expect(DESTROY_DISPATCH_NOTE).toContain("Requested is not destroyed");
    expect(EDITOR_REVISION_NOTE.toLowerCase()).toContain("immutable");
  });

  it("closed-code map never contains raw backend interpolation", () => {
    for (const text of Object.values(ENVIRONMENTS_ERROR_TEXT)) {
      expect(text).not.toContain("{");
      expect(text.length).toBeGreaterThan(10);
    }
  });
});

describe("onlyNotFoundAsNull — absence vs unavailable", () => {
  it("maps only not_found to null and rethrows everything else", async () => {
    const notFound = new ApiClientError(404, "not_found", "x");
    expect(onlyNotFoundAsNull(notFound)).toBeNull();
    const serverError = new ApiClientError(500, "domain_error", "x");
    expect(() => onlyNotFoundAsNull(serverError)).toThrow();
    expect(() => onlyNotFoundAsNull(new Error("network down"))).toThrow();
  });
});

// --------------------------------------------------------------- inventory

describe("exerciseRows", () => {
  it("sorts newest first and carries truthful labels", () => {
    const rows = exerciseRows([
      {
        id: "a", organization_id: "o", template_id: "t", environment_version_id: "v1",
        name: "Old", lifecycle_state: "draft", team_count: 2, created_at: "2026-07-01T00:00:00",
      },
      {
        id: "b", organization_id: "o", template_id: "t", environment_version_id: "v2",
        name: "New", lifecycle_state: "running", team_count: 3, created_at: "2026-07-09T00:00:00",
      },
    ]);
    expect(rows.map((r) => r.id)).toEqual(["b", "a"]);
    expect(rows[0].label).toBe("Running (simulated)");
    expect(recordedDate(rows[0].createdAt)).toBe("2026-07-09");
  });
});

// ----------------------------------------------------------- topology view

const TOPO: TeamTopology = {
  instance_id: "i1",
  team_ref: "team-1",
  team_index: 0,
  lifecycle_state: "running",
  nodes: [
    { id: "n1", type: "host", data: { label: "attacker", kind: "attacker", ip: "10.20.0.10", role: "attacker" } },
    { id: "n2", type: "host", data: { label: "web-server", kind: "target", ip: "10.20.0.20" } },
    { id: "n3", type: "net", data: { label: "team-network", kind: "network", cidr: "10.20.0.0/24" } },
    { id: "n4", type: "host", data: { label: "mystery", kind: "quantum-router" } },
  ],
  edges: [
    { id: "e1", source: "n1", target: "n3", label: "network", data: { kind: "network" } },
    { id: "e2", source: "n2", target: "n3", label: "network", data: { kind: "monitors" } },
  ],
};

describe("topology preview — declarative, never live", () => {
  it("maps nodes and edges deterministically with no animation flags", () => {
    const g = topologyGraph(TOPO);
    expect(g.nodes).toHaveLength(4);
    expect(g.edges).toHaveLength(2);
    for (const e of g.edges) {
      expect(e).not.toHaveProperty("animated");
    }
    // hosts on the top lane, networks below
    const net = g.nodes.find((n) => n.kind === "network")!;
    const host = g.nodes.find((n) => n.kind === "attacker")!;
    expect(net.y).toBeGreaterThan(host.y);
  });

  it("unknown node kinds fall back to neutral, never a misleading type", () => {
    expect(nodeIconName("quantum-router")).toBe("topology");
    expect(nodeKindClass("quantum-router")).toBe("unknown");
    expect(nodeIconName("network")).toBe("network-segment");
    expect(nodeIconName("sensor")).toBe("evidence");
  });

  it("produces an accessible textual summary of the planned shape", () => {
    const text = topologySummaryText(TOPO);
    expect(text).toContain("team-1");
    expect(text).toContain("3 hosts");
    expect(text).toContain("1 network");
    expect(text).toContain("2 declared links");
    expect(text.toLowerCase()).toContain("planned");
  });

  it("edge legend labels everything as declared; declarative note has no live/packet claim", () => {
    expect(edgeLegendLabel("monitors")).toContain("declared");
    expect(edgeLegendLabel("network")).toContain("attached to network");
    expect(edgeLegendLabel("unheard-of")).toContain("declared");
    expect(TOPOLOGY_DECLARATIVE_NOTE).toContain("not observed");
    expect(TOPOLOGY_DECLARATIVE_NOTE.toLowerCase()).toContain("no live traffic");
  });
});
