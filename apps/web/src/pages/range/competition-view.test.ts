// Tests for the competition semantics the backend called out as easy to get wrong.
//
// Each of these guards a specific way the UI could tell a competitor something false.

import { describe, expect, it } from "vitest";

import type {
  Challenge,
  Competition,
  CompetitionTeam,
  Scoreboard,
} from "../../api/range-types";
import {
  COMPETITION_STATE_LABEL,
  MEMBERSHIP_GRANTS_NOTHING_NOTE,
  TEAMS_ARE_FROZEN_WHEN_RUNNING_NOTE,
  VERDICT_LABEL,
  challengeRows,
  competitionControls,
  isSolvedBy,
  scoreFraction,
  scoreboardRows,
  teamRows,
  verdictTone,
} from "./scoreboard-view";

function competition(over: Partial<Competition> = {}): Competition {
  return {
    id: "c1",
    range_id: "r1",
    name: "Tuesday CTF",
    state: "draft",
    started_at: null,
    stopped_at: null,
    team_count: 2,
    challenge_count: 6,
    total_points: 600,
    created_at: "2026-08-01T00:00:00",
    ...over,
  };
}

describe("competitionControls — the start precondition", () => {
  it("names the missing half rather than just disabling the button", () => {
    const noRange = competitionControls(competition(), "draft", 2);
    expect(noRange.canStart).toBe(false);
    expect(noRange.startBlockedReason).toMatch(/ready/i);

    const noTeams = competitionControls(competition(), "ready", 0);
    expect(noTeams.canStart).toBe(false);
    expect(noTeams.startBlockedReason).toMatch(/at least one team/i);
  });

  it("permits start only with a ready range and at least one team", () => {
    const ok = competitionControls(competition(), "ready", 1);
    expect(ok.canStart).toBe(true);
    expect(ok.startBlockedReason).toBeNull();
  });

  it("offers nothing when no competition exists", () => {
    const none = competitionControls(null, "ready", 3);
    expect(none.canStart).toBe(false);
    expect(none.canAddTeam).toBe(false);
    expect(none.canAddMember).toBe(false);
    expect(none.canSubmit).toBe(false);
  });
});

describe("the teams/members asymmetry is deliberate", () => {
  const running = competitionControls(competition({ state: "running" }), "active", 2);
  const draft = competitionControls(competition({ state: "draft" }), "ready", 2);

  it("freezes TEAMS while the competition runs", () => {
    // A team appearing mid-event changes what the scoreboard means.
    expect(running.canAddTeam).toBe(false);
    expect(running.canRemoveTeam).toBe(false);
    expect(draft.canAddTeam).toBe(true);
  });

  it("keeps MEMBERS addable while the competition runs", () => {
    // A latecomer does not change what the scoreboard means.
    expect(running.canAddMember).toBe(true);
    expect(draft.canAddMember).toBe(true);
  });

  it("accepts submissions only while running", () => {
    expect(running.canSubmit).toBe(true);
    expect(draft.canSubmit).toBe(false);
    expect(competitionControls(competition({ state: "stopped" }), "ready", 2).canSubmit).toBe(false);
  });

  it("refuses a score reset while running", () => {
    expect(running.canResetScores).toBe(false);
    expect(draft.canResetScores).toBe(true);
  });

  it("says the asymmetry out loud rather than leaving it to be discovered", () => {
    expect(TEAMS_ARE_FROZEN_WHEN_RUNNING_NOTE).toMatch(/members can be added/i);
  });
});

describe("membership grants nothing", () => {
  it("states that removal does not retract solves", () => {
    // The scoreboard is a record of what happened, not a function of the current roster.
    expect(MEMBERSHIP_GRANTS_NOTHING_NOTE).toMatch(/does not retract/i);
    expect(MEMBERSHIP_GRANTS_NOTHING_NOTE).toMatch(/not consulted when a submission is judged/i);
  });
});

describe("verdict rendering", () => {
  it("labels every verdict", () => {
    for (const v of ["accepted", "incorrect", "duplicate", "already_solved", "not_open", "attempts_exhausted"] as const) {
      expect(VERDICT_LABEL[v]).toBeTruthy();
    }
  });

  it("never renders already_solved or duplicate as an error", () => {
    // `already_solved` comes back for ANY submission once the team holds the solve — including a
    // wrong guess. Keying "error" off the value having been wrong would misfire on that path;
    // the tone keys off the verdict alone.
    expect(verdictTone("already_solved")).not.toBe("danger");
    expect(verdictTone("duplicate")).not.toBe("danger");
  });

  it("does not phrase already_solved as a wrong answer", () => {
    expect(VERDICT_LABEL.already_solved).not.toMatch(/incorrect|wrong/i);
    expect(VERDICT_LABEL.already_solved).toMatch(/already solved/i);
  });

  it("treats only accepted as a scoring success", () => {
    expect(verdictTone("accepted")).toBe("ok");
    for (const v of ["incorrect", "duplicate", "already_solved", "not_open", "attempts_exhausted"] as const) {
      expect(verdictTone(v)).not.toBe("ok");
    }
  });
});

describe("scoreboard rendering computes nothing", () => {
  const scoreboard = (entries: Scoreboard["entries"]): Scoreboard => ({
    competition_id: "c1",
    state: "running",
    generated_at: "2026-08-01T10:00:00",
    total_points: 600,
    entries,
  });

  it("renders an absent scoreboard as no rows, not as zeroed teams", () => {
    expect(scoreboardRows(null)).toEqual([]);
  });

  it("passes server scores through untouched", () => {
    const rows = scoreboardRows(
      scoreboard([
        { rank: 1, team_id: "a", team_name: "A", score: 300, solved_count: 3, last_solve_at: null, solved_challenge_ids: [] },
        { rank: 2, team_id: "b", team_name: "B", score: 100, solved_count: 1, last_solve_at: null, solved_challenge_ids: [] },
      ]),
    );
    expect(rows.map((r) => r.score)).toEqual([300, 100]);
  });

  it("computes a bar fraction without ever producing a score", () => {
    expect(scoreFraction({ score: 300 }, 600)).toBe(0.5);
    // A competition with no points is not a team on 0%.
    expect(scoreFraction({ score: 0 }, 0)).toBeNull();
  });

  it("clamps a bar fraction rather than overflowing", () => {
    expect(scoreFraction({ score: 900 }, 600)).toBe(1);
    expect(scoreFraction({ score: -5 }, 600)).toBe(0);
  });
});

describe("challenges never carry a flag", () => {
  const challenge = (over: Partial<Challenge> = {}): Challenge => ({
    id: "ch1",
    competition_id: "c1",
    key: "js-admin",
    title: "Log in as admin",
    description: "Reach the admin account.",
    category: "web",
    points: 100,
    component_key: "juice",
    hint: "The login form is not as strict as it looks.",
    max_attempts: 25,
    solve_count: 2,
    solved_by_team_ids: ["t1"],
    ...over,
  });

  it("exposes no field that could hold a solution", () => {
    const [row] = challengeRows([challenge()]);
    const keys = Object.keys(row);
    for (const forbidden of ["flag", "value", "answer", "solution", "secret"]) {
      expect(keys, `challenge row must not expose ${forbidden}`).not.toContain(forbidden);
    }
  });

  it("reads solve state from the server's own list", () => {
    const [row] = challengeRows([challenge()]);
    expect(isSolvedBy(row, "t1")).toBe(true);
    expect(isSolvedBy(row, "t2")).toBe(false);
  });

  it("orders by category then points", () => {
    const rows = challengeRows([
      challenge({ id: "b", category: "web", points: 200 }),
      challenge({ id: "a", category: "web", points: 50 }),
      challenge({ id: "c", category: "crypto", points: 500 }),
    ]);
    expect(rows.map((r) => r.id)).toEqual(["c", "a", "b"]);
  });
});

describe("teamRows", () => {
  const team = (over: Partial<CompetitionTeam> = {}): CompetitionTeam => ({
    id: "t1",
    competition_id: "c1",
    name: "Red Team",
    slug: "red-team",
    join_code: "R7K2QX",
    score: 300,
    solved_count: 3,
    created_at: "2026-08-01T00:00:00",
    ...over,
  });

  it("passes the server's score through without adjustment", () => {
    expect(teamRows([team({ score: 275 })])[0].score).toBe(275);
  });

  it("sorts by name for a stable roster", () => {
    const rows = teamRows([team({ id: "b", name: "Zulu" }), team({ id: "a", name: "Alpha" })]);
    expect(rows.map((r) => r.name)).toEqual(["Alpha", "Zulu"]);
  });
});

describe("competition state labels", () => {
  it("calls draft 'not started' rather than 'draft'", () => {
    // "Draft" is range vocabulary; for a competition the operator's question is whether it has begun.
    expect(COMPETITION_STATE_LABEL.draft).toMatch(/not started/i);
    expect(COMPETITION_STATE_LABEL.running).toBe("Running");
    expect(COMPETITION_STATE_LABEL.stopped).toBe("Stopped");
  });
});
