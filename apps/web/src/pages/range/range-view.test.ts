import { describe, expect, it } from "vitest";

import type {
  Range,
  RangeOperation,
  RangeOperationSummary,
  RangeResource,
  RangeTemplate,
  TeardownEvidence,
} from "../../api/range-types";
import {
  accessRows,
  blastRadius,
  destroyConfirmationMatches,
  estimatedDuration,
  filterBlueprints,
  liveResources,
  operationInFlight,
  operationOutcomeText,
  operationProgress,
  rangeBlueprints,
  rangeSummaries,
  reachabilityText,
  resourceRows,
  teardownSummary,
} from "./range-view";
import type { ScoreboardEntry } from "../../api/range-types";
import {
  VERDICT_LABEL,
  displayRank,
  isTiedRank,
  orderScoreboard,
  verdictTone,
} from "./scoreboard-view";

function template(over: Partial<RangeTemplate> = {}): RangeTemplate {
  return {
    slug: "web-breach-lab",
    name: "Web Breach Lab",
    summary: "Two vulnerable web apps.",
    description: "Longer prose.",
    provider: "local_docker",
    difficulty: "beginner",
    estimated_deploy_seconds: 180,
    warning: "Intentionally vulnerable.",
    components: [
      { key: "juice", name: "Juice Shop", role: "target", image: "juice:1", container_port: 3000, protocol: "http", path: "/" },
      { key: "dvwa", name: "DVWA", role: "target", image: "dvwa:1", container_port: 80, protocol: "http", path: "/" },
      { key: "scorer", name: "Scorer", role: "scoring", image: "scorer:1", container_port: null, protocol: "http", path: "/" },
    ],
    challenge_count: 6,
    total_points: 600,
    ...over,
  };
}

function range(over: Partial<Range> = {}): Range {
  return {
    id: "rng-1",
    name: "Tuesday cohort",
    template_slug: "web-breach-lab",
    template_name: "Web Breach Lab",
    provider: "local_docker",
    state: "ready",
    state_reason: null,
    created_at: "2026-08-01T00:00:00",
    updated_at: "2026-08-01T00:05:00",
    deployed_at: "2026-08-01T00:05:00",
    destroyed_at: null,
    competition_id: null,
    current_operation: null,
    residue_verdict: null,
    access: [],
    ...over,
  };
}

function operation(over: Partial<RangeOperationSummary> = {}): RangeOperationSummary {
  return {
    id: "op-1",
    kind: "deploy",
    status: "running",
    phase: "create",
    // The default is a LIVE operation. `stale` is a third outcome beside running and finished —
    // the lease lapsed and nobody recorded how it ended — and it leaves `status` saying whatever
    // it last said, so a fixture that omitted it was describing a state the server never sends.
    stale: false,
    completed_steps: 2,
    total_steps: 4,
    percent: 50,
    ...over,
  };
}

function resource(over: Partial<RangeResource> = {}): RangeResource {
  return {
    id: "res-1",
    kind: "container",
    provider: "local_docker",
    component_key: "juice",
    name: "secp-range-juice",
    external_id: "ctr1",
    image: "juice:1",
    image_digest: "sha256:abc",
    state: "verified",
    host_port: 34011,
    created_at: "2026-08-01T00:05:00",
    removed_at: null,
    detail: {},
    ...over,
  };
}

describe("rangeBlueprints", () => {
  it("counts only target components as targets", () => {
    // The scoring component is plumbing, not something a competitor attacks.
    const [b] = rangeBlueprints([template()]);
    expect(b.targetCount).toBe(2);
    expect(b.componentNames).toHaveLength(3);
  });

  it("carries the vulnerability warning through verbatim", () => {
    const [b] = rangeBlueprints([template({ warning: "DO NOT EXPOSE" })]);
    expect(b.warning).toBe("DO NOT EXPOSE");
  });

  it("sorts by name", () => {
    const list = rangeBlueprints([
      template({ slug: "z", name: "Zulu" }),
      template({ slug: "a", name: "Alpha" }),
    ]);
    expect(list.map((b) => b.name)).toEqual(["Alpha", "Zulu"]);
  });
});

describe("filterBlueprints", () => {
  const list = rangeBlueprints([
    template({ slug: "web-breach-lab", name: "Web Breach Lab", summary: "vulnerable web", difficulty: "beginner" }),
    template({ slug: "ad-forest", name: "AD Forest", summary: "directory", difficulty: "advanced" }),
  ]);

  it("matches name, slug, summary and difficulty case-insensitively", () => {
    expect(filterBlueprints(list, "BREACH").map((b) => b.slug)).toEqual(["web-breach-lab"]);
    expect(filterBlueprints(list, "directory").map((b) => b.slug)).toEqual(["ad-forest"]);
    expect(filterBlueprints(list, "advanced").map((b) => b.slug)).toEqual(["ad-forest"]);
  });

  it("returns everything for a whitespace query", () => {
    expect(filterBlueprints(list, "   ")).toHaveLength(2);
  });
});

describe("estimatedDuration", () => {
  it("reports unknown rather than zero for a missing estimate", () => {
    expect(estimatedDuration(0)).toBe("unknown");
    expect(estimatedDuration(-5)).toBe("unknown");
  });

  it("uses seconds below 90 and minutes above", () => {
    expect(estimatedDuration(45)).toBe("about 45s");
    expect(estimatedDuration(180)).toBe("about 3 min");
  });
});

describe("operationProgress — the pre-plan window", () => {
  it("reports indeterminate when the worker has not planned the operation", () => {
    // total_steps: 0 while pending means THE PLAN DOES NOT EXIST YET. Rendering 0% would claim no
    // work has been done; the truth is that nobody knows yet how much work there is.
    const p = operationProgress(operation({ status: "pending", total_steps: 0, completed_steps: 0, percent: 0 }));
    expect(p.kind).toBe("indeterminate");
    expect(p.percent).toBeNull();
    expect(p.totalSteps).toBeNull();
  });

  it("never divides by total_steps", () => {
    // A zero total must not produce NaN or Infinity anywhere in the result.
    const p = operationProgress(operation({ status: "running", total_steps: 0, completed_steps: 0, percent: 0 }));
    expect(Number.isNaN(p.percent as number)).toBe(false);
    expect(p.percent).toBeNull();
  });

  it("uses the server's percent once a plan exists", () => {
    const p = operationProgress(operation({ total_steps: 4, completed_steps: 3, percent: 75 }));
    expect(p.kind).toBe("determinate");
    expect(p.percent).toBe(75);
    expect(p.label).toBe("3 of 4 steps");
  });

  it("distinguishes a settled zero-step operation from an unplanned one", () => {
    const settled = operationProgress(operation({ status: "succeeded", total_steps: 0, percent: 100 }));
    expect(settled.kind).toBe("determinate");
    expect(settled.label).toMatch(/planned no steps/i);
  });

  it("reports no operation distinctly from a zero-progress one", () => {
    const none = operationProgress(null);
    expect(none.kind).toBe("none");
    expect(none.percent).toBeNull();
  });
});

describe("operationInFlight", () => {
  it("polls only while pending or running", () => {
    expect(operationInFlight(operation({ status: "pending" }))).toBe(true);
    expect(operationInFlight(operation({ status: "running" }))).toBe(true);
    expect(operationInFlight(operation({ status: "succeeded" }))).toBe(false);
    expect(operationInFlight(operation({ status: "unproven" }))).toBe(false);
    expect(operationInFlight(null)).toBe(false);
  });
});

describe("operationOutcomeText", () => {
  const full = (
    status: RangeOperationSummary["status"],
    over: { failure_code?: string | null } = {},
  ): RangeOperation => ({
    ...operation({ status }),
    range_id: "rng-1",
    stale_reason: null,
    failure_code: null,
    failure_message: null,
    started_at: "2026-08-01T00:00:00",
    finished_at: null,
    steps: [],
    ...over,
  });

  it("says nothing for a success", () => {
    expect(operationOutcomeText(full("succeeded"))).toBeNull();
  });

  it("describes unproven as unknown, not as a failure", () => {
    const text = operationOutcomeText(full("unproven")) ?? "";
    expect(text).toMatch(/unknown/i);
    expect(text).toMatch(/did not necessarily fail/i);
  });

  it("names the failure code when one is present", () => {
    expect(
      operationOutcomeText(full("failed", { failure_code: "range_provider_unavailable" })),
    ).toContain("range_provider_unavailable");
  });
});

describe("accessRows and reachability", () => {
  const withAccess = range({
    access: [
      { component_key: "b", name: "Beta", url: "http://127.0.0.1:2/", host: "127.0.0.1", port: 2, protocol: "http", reachable: true, observed_at: "2026-08-01T00:05:00" },
      { component_key: "a", name: "Alpha", url: "http://127.0.0.1:1/", host: "127.0.0.1", port: 1, protocol: "http", reachable: false, observed_at: "2026-08-01T00:05:00" },
      { component_key: "c", name: "Gamma", url: "http://127.0.0.1:3/", host: "127.0.0.1", port: 3, protocol: "http", reachable: false, observed_at: null },
    ],
  });

  it("orders by name so reloads are stable", () => {
    expect(accessRows(withAccess).map((a) => a.name)).toEqual(["Alpha", "Beta", "Gamma"]);
  });

  it("keeps 'did not respond' and 'never checked' apart", () => {
    const rows = accessRows(withAccess);
    expect(reachabilityText(rows.find((r) => r.name === "Beta")!)).toBe("responded");
    expect(reachabilityText(rows.find((r) => r.name === "Alpha")!)).toBe("did not respond");
    // Never probed is NOT the same as probed-and-failed.
    expect(reachabilityText(rows.find((r) => r.name === "Gamma")!)).toBe("not checked");
  });

  it("returns nothing when the range records no access", () => {
    expect(accessRows(range())).toEqual([]);
  });
});

describe("rangeSummaries", () => {
  it("orders newest first and counts observed reachability", () => {
    const list = rangeSummaries([
      range({ id: "old", created_at: "2026-01-01T00:00:00" }),
      range({
        id: "new",
        created_at: "2026-02-01T00:00:00",
        access: [
          { component_key: "a", name: "A", url: "u", host: "h", port: 1, protocol: "http", reachable: true, observed_at: "t" },
          { component_key: "b", name: "B", url: "u", host: "h", port: 2, protocol: "http", reachable: false, observed_at: "t" },
        ],
      }),
    ]);
    expect(list.map((r) => r.id)).toEqual(["new", "old"]);
    expect(list[0].reachableCount).toBe(1);
    expect(list[0].accessCount).toBe(2);
  });

  it("reports whether a competition exists without inventing one", () => {
    expect(rangeSummaries([range()])[0].hasCompetition).toBe(false);
    expect(rangeSummaries([range({ competition_id: "c1" })])[0].hasCompetition).toBe(true);
  });
});

describe("resources and blast radius", () => {
  const resources = [
    resource({ id: "r1", kind: "container", name: "juice" }),
    resource({ id: "r2", kind: "network", name: "net", host_port: null, component_key: null }),
    resource({ id: "r3", kind: "container", name: "gone", state: "removed", removed_at: "2026-08-01T01:00:00", host_port: 34012 }),
  ];

  it("excludes already-removed resources from the blast radius", () => {
    const r = blastRadius(resources);
    expect(r.resourceCount).toBe(2);
    expect(r.containerCount).toBe(1);
    expect(r.networkCount).toBe(1);
    expect(r.ports).toEqual([34011]);
  });

  it("enumerates what will be destroyed by name and state", () => {
    expect(blastRadius(resources).lines).toEqual([
      "container juice (verified)",
      "network net (verified)",
    ]);
  });

  it("marks the enumeration incomplete when the list could not be read", () => {
    // Under-stating a blast radius is the failure mode that matters, so an unreadable source is
    // reported rather than silently producing an empty list.
    const r = blastRadius(null);
    expect(r.complete).toBe(false);
    expect(r.incompleteReason).toMatch(/incomplete/i);
    expect(r.resourceCount).toBe(0);
  });

  it("treats an empty list as genuinely empty, not as unknown", () => {
    const r = blastRadius([]);
    expect(r.complete).toBe(true);
    expect(r.resourceCount).toBe(0);
  });

  it("keeps unproven resources in the live set — they were never proved gone", () => {
    const unproven = [resource({ id: "u", state: "unproven", removed_at: null })];
    expect(liveResources(unproven)).toHaveLength(1);
    expect(blastRadius(unproven).resourceCount).toBe(1);
  });

  it("sorts rows by kind then name", () => {
    expect(resourceRows(resources).map((r) => r.name)).toEqual(["gone", "juice", "net"]);
  });
});

describe("teardownSummary", () => {
  const evidence = (over: Partial<TeardownEvidence> = {}): TeardownEvidence => ({
    id: "tev-1",
    range_id: "rng-1",
    operation_id: "op-1",
    verdict: "clean",
    probe_reachable: true,
    expected_count: 3,
    removed_confirmed: 3,
    still_present: 0,
    unproven_count: 0,
    reason: null,
    observed_at: "2026-08-01T01:00:00",
    resources: [],
    ...over,
  });

  it("reports a reachable clean probe as proved", () => {
    const s = teardownSummary(evidence());
    expect(s.provedClean).toBe(true);
    expect(s.headline).toMatch(/verified clean/i);
  });

  it("refuses to call it proved when the probe could not run", () => {
    // The removal and the existence check share a failure mode, so absence was never established.
    const s = teardownSummary(evidence({ probe_reachable: false }));
    expect(s.provedClean).toBe(false);
    expect(s.headline).toMatch(/could not run/i);
  });

  it("does not report an unproven verdict as clean", () => {
    const s = teardownSummary(evidence({ verdict: "unproven", probe_reachable: false, unproven_count: 3, removed_confirmed: 0 }));
    expect(s.provedClean).toBe(false);
    expect(s.headline).toMatch(/could not be verified/i);
    expect(s.unprovenCount).toBe(3);
  });

  it("names residue plainly", () => {
    const s = teardownSummary(evidence({ verdict: "residue", still_present: 2 }));
    expect(s.provedClean).toBe(false);
    expect(s.headline).toMatch(/still present/i);
  });

  it("prefers the server's own reason over generated copy", () => {
    const s = teardownSummary(evidence({ verdict: "unproven", reason: "docker daemon unreachable" }));
    expect(s.detail).toBe("docker daemon unreachable");
  });
});

describe("destroyConfirmationMatches", () => {
  it("requires an exact name match after trimming", () => {
    expect(destroyConfirmationMatches("  Tuesday cohort  ", "Tuesday cohort")).toBe(true);
  });

  it("rejects a case-insensitive near-miss", () => {
    expect(destroyConfirmationMatches("tuesday cohort", "Tuesday cohort")).toBe(false);
  });

  it("rejects an empty confirmation even against an empty name", () => {
    expect(destroyConfirmationMatches("", "")).toBe(false);
  });
});

describe("scoreboard ordering", () => {
  const row = (over: Partial<ScoreboardEntry>): ScoreboardEntry => ({
    team_id: "t",
    team_name: "Team",
    rank: 1,
    score: 0,
    solved_count: 0,
    last_solve_at: null,
    solved_challenge_ids: [],
    ...over,
  });

  it("honours the server's rank over the score", () => {
    const rows = orderScoreboard([
      row({ team_name: "b", rank: 2, score: 999 }),
      row({ team_name: "a", rank: 1, score: 1 }),
    ]);
    expect(rows.map((r) => r.team_name)).toEqual(["a", "b"]);
  });

  it("preserves shared ranks instead of renumbering them", () => {
    // The backend ties on (score, last_solve_at) together, so shared ranks are rare — but when
    // they happen, standard competition ranking means the next team is 3rd, not 2nd. Using the
    // array index would silently rewrite that.
    const rows = orderScoreboard([
      row({ team_name: "b", rank: 1, score: 300 }),
      row({ team_name: "a", rank: 1, score: 300 }),
      row({ team_name: "c", rank: 3, score: 100 }),
    ]);
    expect(rows.map((r) => r.rank)).toEqual([1, 1, 3]);
    expect(rows.map((r) => displayRank(r))).toEqual(["1", "1", "3"]);
  });

  it("breaks ties stably by team name so polls do not reshuffle", () => {
    const rows = orderScoreboard([row({ team_name: "b", rank: 1 }), row({ team_name: "a", rank: 1 })]);
    expect(rows.map((r) => r.team_name)).toEqual(["a", "b"]);
  });

  it("never alters a score while ordering", () => {
    const input = [row({ team_name: "a", rank: 1, score: 7 }), row({ team_name: "b", rank: 2, score: 3 })];
    expect(orderScoreboard(input).map((r) => r.score)).toEqual([7, 3]);
    expect(input.map((r) => r.score)).toEqual([7, 3]);
  });

  it("displays the server's rank, never the array index", () => {
    expect(displayRank(orderScoreboard([row({ rank: 4 })])[0])).toBe("4");
  });

  it("marks tied rows as tied", () => {
    const entries = [row({ rank: 1 }), row({ rank: 1 }), row({ rank: 3 })];
    expect(isTiedRank(entries[0], entries)).toBe(true);
    expect(isTiedRank(entries[2], entries)).toBe(false);
  });
});

describe("submission verdicts", () => {
  it("labels every verdict", () => {
    for (const v of ["accepted", "incorrect", "duplicate", "already_solved", "not_open", "attempts_exhausted"] as const) {
      expect(VERDICT_LABEL[v]).toBeTruthy();
    }
  });

  it("does not present an already-solved challenge as a wrong answer", () => {
    // `already_solved` comes back for ANY submission once the team holds the solve — including a
    // wrong guess. Rendering it as an error would tell a competitor their solved challenge failed.
    expect(verdictTone("already_solved")).not.toBe("danger");
    expect(verdictTone("duplicate")).not.toBe("danger");
    expect(verdictTone("incorrect")).toBe("danger");
  });

  it("treats only accepted as a scoring success", () => {
    expect(verdictTone("accepted")).toBe("ok");
    for (const v of ["incorrect", "duplicate", "already_solved", "not_open", "attempts_exhausted"] as const) {
      expect(verdictTone(v)).not.toBe("ok");
    }
  });
});
