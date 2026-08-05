import { describe, expect, it } from "vitest";

import type {
  AuditEvent,
  DeploymentPlan,
  Exercise,
  Instance,
  TeamTopology,
  Template,
  Version,
} from "../../api/types";
import {
  accessTargets,
  canResetInstance,
  deployGate,
  destroyConfirmationMatches,
  filterBlueprints,
  rangeBlueprints,
  rangeSummaries,
  teamInstanceRows,
  timelineEntries,
  timelineTally,
} from "./range-view";
import { displayRank, orderScoreboard, type ScoreboardRow } from "./scoreboard-view";

function template(over: Partial<Template> = {}): Template {
  return {
    id: "t1",
    organization_id: "org",
    name: "web-dmz",
    slug: "web-dmz",
    display_name: "Web DMZ",
    description: "An exposed web tier.",
    created_at: "2026-01-01T00:00:00",
    ...over,
  };
}

function version(over: Partial<Version> = {}): Version {
  return {
    id: "v1",
    template_id: "t1",
    version_number: 1,
    api_version: "secp.io/v1alpha2",
    content_hash: "sha256:aaa",
    spec: {},
    created_at: "2026-01-01T00:00:00",
    publication_provenance: null,
    ...over,
  };
}

function exercise(over: Partial<Exercise> = {}): Exercise {
  return {
    id: "e1",
    organization_id: "org",
    template_id: "t1",
    environment_version_id: "v1",
    name: "Range One",
    lifecycle_state: "draft",
    team_count: 2,
    created_at: "2026-01-02T00:00:00",
    ...over,
  };
}

describe("rangeBlueprints", () => {
  it("picks the highest version number, not the last array element", () => {
    const versions = [version({ id: "v1", version_number: 1 }), version({ id: "v3", version_number: 3 }), version({ id: "v2", version_number: 2 })];
    const [b] = rangeBlueprints([template()], new Map([["t1", versions]]));
    expect(b.latestVersionId).toBe("v3");
    expect(b.latestVersionNumber).toBe(3);
    expect(b.deployable).toBe(true);
  });

  it("distinguishes 'no versions published' from 'versions not loaded'", () => {
    const [loaded] = rangeBlueprints([template()], new Map([["t1", []]]));
    expect(loaded.deployable).toBe(false);
    expect(loaded.unavailableReason).toMatch(/no immutable version/i);

    const [missing] = rangeBlueprints([template()], new Map());
    expect(missing.deployable).toBe(false);
    expect(missing.unavailableReason).toMatch(/could not be loaded/i);
  });

  it("falls back to name when display_name is empty", () => {
    const [b] = rangeBlueprints([template({ display_name: "" })], new Map());
    expect(b.name).toBe("web-dmz");
  });

  it("sorts by display name", () => {
    const list = rangeBlueprints(
      [template({ id: "b", display_name: "Zulu" }), template({ id: "a", display_name: "Alpha" })],
      new Map(),
    );
    expect(list.map((b) => b.name)).toEqual(["Alpha", "Zulu"]);
  });
});

describe("filterBlueprints", () => {
  const list = rangeBlueprints(
    [template({ id: "a", display_name: "Web DMZ", slug: "web-dmz", description: "exposed tier" }), template({ id: "b", display_name: "AD Forest", slug: "ad-forest", description: "directory" })],
    new Map(),
  );

  it("matches name, slug and description case-insensitively", () => {
    expect(filterBlueprints(list, "DMZ").map((b) => b.slug)).toEqual(["web-dmz"]);
    expect(filterBlueprints(list, "ad-for").map((b) => b.slug)).toEqual(["ad-forest"]);
    expect(filterBlueprints(list, "directory").map((b) => b.slug)).toEqual(["ad-forest"]);
  });

  it("returns everything for an empty or whitespace query", () => {
    expect(filterBlueprints(list, "   ")).toHaveLength(2);
  });
});

describe("deployGate", () => {
  it("walks the approval gate in order", () => {
    expect(deployGate(exercise({ lifecycle_state: "draft" }), null).next).toBe("validate");
    expect(deployGate(exercise({ lifecycle_state: "validated" }), null).next).toBe("generate-plan");
    expect(deployGate(exercise({ lifecycle_state: "approved" }), null).next).toBe("deploy");
  });

  it("uses the plan status to choose the next step when planned", () => {
    const planned = exercise({ lifecycle_state: "planned" });
    const plan = (status: string) => ({ status } as Pick<DeploymentPlan, "status">);
    expect(deployGate(planned, plan("generated")).next).toBe("submit-plan");
    expect(deployGate(planned, plan("awaiting_approval")).next).toBe("approve-plan");
    expect(deployGate(planned, plan("approved")).next).toBe("deploy");
  });

  it("sends a rejected plan back to generation rather than to deploy", () => {
    const gate = deployGate(exercise({ lifecycle_state: "planned" }), {
      status: "rejected",
    } as Pick<DeploymentPlan, "status">);
    expect(gate.next).toBe("generate-plan");
    expect(gate.help).toMatch(/rejected/i);
  });

  it("does not claim a plan step when the plan could not be read", () => {
    const gate = deployGate(exercise({ lifecycle_state: "planned" }), null);
    expect(gate.next).toBe("generate-plan");
  });

  it("offers no action mid-flight and says why", () => {
    const gate = deployGate(exercise({ lifecycle_state: "deploying" }), null);
    expect(gate.next).toBe("none");
    expect(gate.blockedReason).toMatch(/in progress/i);
  });

  it("treats a deployed range as finished, not blocked", () => {
    const gate = deployGate(exercise({ lifecycle_state: "running" }), null);
    expect(gate.next).toBe("none");
    expect(gate.blockedReason).toBeNull();
  });

  it("reports a destroyed range as unrecoverable", () => {
    const gate = deployGate(exercise({ lifecycle_state: "destroyed" }), null);
    expect(gate.blockedReason).toMatch(/destroyed/i);
  });
});

describe("accessTargets", () => {
  const topo: TeamTopology = {
    instance_id: "i1",
    team_ref: "team-1",
    team_index: 1,
    lifecycle_state: "running",
    nodes: [
      { id: "n1", type: "x", data: { label: "victim", kind: "target", ip: "10.0.0.5", role: "web" } },
      { id: "n2", type: "x", data: { label: "lan", kind: "network", cidr: "10.0.0.0/24" } },
      { id: "n3", type: "x", data: { label: "attacker", kind: "attacker", ip: "10.0.0.2" } },
    ],
    edges: [],
  };

  it("excludes network segments — they are not things to connect to", () => {
    const rows = accessTargets([topo]);
    expect(rows.map((r) => r.label)).toEqual(["attacker", "victim"]);
  });

  it("carries the declared address through without inventing one", () => {
    const rows = accessTargets([topo]);
    expect(rows.find((r) => r.label === "victim")?.ip).toBe("10.0.0.5");
  });

  it("reports a null ip when the plan declares none rather than guessing", () => {
    const noIp: TeamTopology = {
      ...topo,
      nodes: [{ id: "n9", type: "x", data: { label: "ghost", kind: "target" } }],
    };
    expect(accessTargets([noIp])[0].ip).toBeNull();
  });

  it("orders by team index then label so reloads are stable", () => {
    const second: TeamTopology = { ...topo, instance_id: "i2", team_ref: "team-2", team_index: 2 };
    const rows = accessTargets([second, topo]);
    expect(rows.map((r) => r.teamIndex)).toEqual([1, 1, 2, 2]);
  });
});

describe("teamInstanceRows", () => {
  const instances: Instance[] = [
    { id: "i2", exercise_id: "e1", team_index: 2, team_ref: "team-2", instance_ref: "r2", lifecycle_state: "running", provider: "sim" },
    { id: "i1", exercise_id: "e1", team_index: 1, team_ref: "team-1", instance_ref: "r1", lifecycle_state: "deploying", provider: "sim" },
  ];

  it("sorts by team index", () => {
    expect(teamInstanceRows(instances, []).map((r) => r.teamIndex)).toEqual([1, 2]);
  });

  it("counts targets per instance", () => {
    const topo: TeamTopology = {
      instance_id: "i1",
      team_ref: "team-1",
      team_index: 1,
      lifecycle_state: "running",
      nodes: [
        { id: "a", type: "x", data: { label: "a", kind: "target" } },
        { id: "b", type: "x", data: { label: "b", kind: "network" } },
      ],
      edges: [],
    };
    const rows = teamInstanceRows(instances, [topo]);
    expect(rows.find((r) => r.instanceId === "i1")?.targetCount).toBe(1);
    expect(rows.find((r) => r.instanceId === "i2")?.targetCount).toBe(0);
  });

  it("permits reset only on a ready instance", () => {
    const rows = teamInstanceRows(instances, []);
    expect(canResetInstance(rows.find((r) => r.instanceId === "i2")!)).toBe(true);
    expect(canResetInstance(rows.find((r) => r.instanceId === "i1")!)).toBe(false);
  });
});

describe("timeline", () => {
  const events: AuditEvent[] = [
    { id: "1", actor: "a", action: "exercise.deployed", resource_type: "exercise", resource_id: "e1", outcome: "success", data: {}, created_at: "2026-01-01T01:00:00" },
    { id: "2", actor: "a", action: "execution.refused", resource_type: "exercise", resource_id: "e1", outcome: "refused", data: {}, created_at: "2026-01-01T02:00:00" },
  ];

  it("orders newest first", () => {
    expect(timelineEntries(events).map((e) => e.id)).toEqual(["2", "1"]);
  });

  it("flags any non-success outcome", () => {
    const entries = timelineEntries(events);
    expect(entries.find((e) => e.id === "2")?.flagged).toBe(true);
    expect(entries.find((e) => e.id === "1")?.flagged).toBe(false);
  });

  it("tallies only loaded events", () => {
    expect(timelineTally(timelineEntries(events))).toEqual({ total: 2, flagged: 1 });
  });

  it("synthesizes nothing for an empty ledger", () => {
    expect(timelineEntries([])).toEqual([]);
  });
});

describe("rangeSummaries", () => {
  it("orders newest first and projects the lifecycle", () => {
    const list = rangeSummaries([
      exercise({ id: "old", created_at: "2026-01-01T00:00:00", lifecycle_state: "running" }),
      exercise({ id: "new", created_at: "2026-02-01T00:00:00", lifecycle_state: "draft" }),
    ]);
    expect(list.map((r) => r.id)).toEqual(["new", "old"]);
    expect(list[1].lifecycle.phase).toBe("ready");
  });
});

describe("destroyConfirmationMatches", () => {
  it("requires an exact name match after trimming", () => {
    expect(destroyConfirmationMatches("  Range One  ", "Range One")).toBe(true);
    expect(destroyConfirmationMatches("Range One", "Range One")).toBe(true);
  });

  it("rejects a case-insensitive near-miss", () => {
    // The control exists so the operator reads the specific name. Looser matching defeats it.
    expect(destroyConfirmationMatches("range one", "Range One")).toBe(false);
  });

  it("rejects an empty confirmation even against an empty name", () => {
    expect(destroyConfirmationMatches("", "")).toBe(false);
  });
});

describe("scoreboard ordering", () => {
  const row = (over: Partial<ScoreboardRow>): ScoreboardRow => ({
    team_id: "t",
    team_ref: "team",
    display_name: "Team",
    score: 0,
    rank: null,
    solved_count: 0,
    last_solve_at: null,
    ...over,
  });

  it("honours the server's rank when present", () => {
    const rows = orderScoreboard([
      row({ team_ref: "b", rank: 2, score: 999 }),
      row({ team_ref: "a", rank: 1, score: 1 }),
    ]);
    expect(rows.map((r) => r.team_ref)).toEqual(["a", "b"]);
  });

  it("sorts unranked rows after every ranked row", () => {
    const rows = orderScoreboard([
      row({ team_ref: "unranked", rank: null, score: 500 }),
      row({ team_ref: "ranked", rank: 9, score: 1 }),
    ]);
    expect(rows.map((r) => r.team_ref)).toEqual(["ranked", "unranked"]);
  });

  it("breaks ties stably by team ref", () => {
    const rows = orderScoreboard([
      row({ team_ref: "b", score: 10 }),
      row({ team_ref: "a", score: 10 }),
    ]);
    expect(rows.map((r) => r.team_ref)).toEqual(["a", "b"]);
  });

  it("never alters a score while ordering", () => {
    const input = [row({ team_ref: "a", score: 7 }), row({ team_ref: "b", score: 3 })];
    const out = orderScoreboard(input);
    expect(out.map((r) => r.score).sort()).toEqual([3, 7]);
    expect(input.map((r) => r.score)).toEqual([7, 3]); // input untouched
  });

  it("shows an em dash rather than a position the server did not assign", () => {
    expect(displayRank({ rank: null })).toBe("—");
    expect(displayRank({ rank: 3 })).toBe("3");
  });
});
