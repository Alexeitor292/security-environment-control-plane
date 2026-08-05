// Competition, team and scoreboard view-model.
//
// ── WHY THIS MODULE COMPUTES NO SCORES ────────────────────────────────────────────────────────
// Scores are authoritative on the server. This module renders what the backend returns and does
// arithmetic on NONE of it. There is deliberately no `total()`, no `applyPenalty()`, no
// `recomputeRank()` and no optimistic adjustment: a scoreboard that disagrees with the server is
// worse than one that is briefly stale, because a competitor reads it as the result.
//
// `points_awarded` on a submission is a REPORT of what the server recorded — displayed once and
// then forgotten, never accumulated into a client-held total.
//
// ── TWO BACKEND SEMANTICS THAT ARE EASY TO GET WRONG ──────────────────────────────────────────
// 1. MEMBERSHIP GRANTS NOTHING. A roster entry carries no permission and is not consulted when a
//    submission is judged — the TEAM scores and the authenticated principal authorizes. So
//    removing a member does NOT retract their team's solves, and nothing here recalculates a score
//    when a roster changes. Rewriting a scoreboard because a roster changed would make it
//    unreliable as a record of what happened.
// 2. MEMBERS may be added while a competition is running; TEAMS may not. A team appearing
//    mid-event changes what the scoreboard means; a latecomer does not. The asymmetry is
//    deliberate and the copy below says so rather than smoothing it over.

import type {
  Challenge,
  Competition,
  CompetitionState,
  CompetitionTeam,
  Scoreboard,
  ScoreboardEntry,
  SubmissionVerdict,
} from "../../api/range-types";

// ------------------------------------------------------------------------------------- copy

export const SCOREBOARD_AUTHORITY_NOTE =
  "Scores are authoritative on the server. This view renders exactly what the API returns and never computes, adjusts or projects a score in the browser.";

export const FLAGS_ARE_NEVER_RETURNED_NOTE =
  "Flag values are never present in any API response — they are stored salted-hashed and compared server-side only. A submission returns a verdict, never the answer.";

export const MEMBERSHIP_GRANTS_NOTHING_NOTE =
  "A roster entry is a name, not an account or a permission. It is not consulted when a submission is judged — the team scores. Removing someone does not retract their team's solves, and the scoreboard is left exactly as the competition earned it.";

export const COMPETITOR_IS_NOT_A_USER_NOTE =
  "Competitors are usually students, visitors or a rotating workshop cast rather than provisioned users, so a name is all that is required.";

export const TEAMS_ARE_FROZEN_WHEN_RUNNING_NOTE =
  "Teams cannot be added or removed while the competition is running — a team appearing mid-event changes what the scoreboard means. Members can be added at any time; a latecomer does not.";

export const START_REQUIREMENTS_NOTE =
  "Starting requires a range that is ready and at least one team. Starting moves the range to active; stopping moves it back to ready and refuses further submissions.";

export const RESET_SCORES_NOTE =
  "Clearing scores removes every submission and score but keeps the teams and challenges. It does not touch the containers — use Reset on the range for that.";

// -------------------------------------------------------------------------- competition state

export const COMPETITION_STATE_LABEL: Record<CompetitionState, string> = {
  draft: "Not started",
  running: "Running",
  stopped: "Stopped",
};

export const COMPETITION_STATE_HELP: Record<CompetitionState, string> = {
  draft: "Teams and challenges are set up. No submissions are accepted yet.",
  running: "Submissions are being accepted and scored.",
  stopped: "Ended. Submissions are refused; the standings stand as they were.",
};

export interface CompetitionControls {
  canStart: boolean;
  canStop: boolean;
  canAddTeam: boolean;
  canRemoveTeam: boolean;
  canAddMember: boolean;
  canResetScores: boolean;
  canSubmit: boolean;
  /** Why start is unavailable, or null when it is. */
  startBlockedReason: string | null;
}

/**
 * Which competition controls are available, from the competition's own state and the range's.
 *
 * A CLIENT-SIDE AFFORDANCE only — the server re-checks every one of these. It exists so the UI
 * does not offer a control whose sole outcome is a refusal, and so the deliberate asymmetry
 * (members yes, teams no, while running) is visible rather than surprising.
 */
export function competitionControls(
  competition: Competition | null,
  rangePhase: string,
  teamCount: number,
): CompetitionControls {
  if (competition === null) {
    return {
      canStart: false,
      canStop: false,
      canAddTeam: false,
      canRemoveTeam: false,
      canAddMember: false,
      canResetScores: false,
      canSubmit: false,
      startBlockedReason: "No competition exists on this range yet.",
    };
  }
  const running = competition.state === "running";
  const rangeReady = rangePhase === "ready";

  // The server's precondition, mirrored so the operator is told which half is missing.
  const startBlockedReason = running
    ? "The competition is already running."
    : !rangeReady
      ? "Starting needs a range that is ready. Deploy it first."
      : teamCount === 0
        ? "Starting needs at least one team."
        : null;

  return {
    canStart: !running && startBlockedReason === null,
    canStop: running,
    // Teams are frozen while running; members are not.
    canAddTeam: !running,
    canRemoveTeam: !running,
    canAddMember: true,
    canResetScores: !running,
    canSubmit: running,
    startBlockedReason: running || startBlockedReason !== null ? startBlockedReason : null,
  };
}

// ------------------------------------------------------------------------------ submissions

/**
 * Copy for each verdict.
 *
 * `already_solved` comes back for ANY submission once the team holds the solve — a correct value,
 * a different value, or an outright wrong guess. So it is NOT phrased as a wrong answer, and no
 * rule anywhere keys "error" off the value having been wrong; it keys off the verdict alone.
 */
export const VERDICT_LABEL: Record<SubmissionVerdict, string> = {
  accepted: "Accepted",
  incorrect: "Incorrect",
  duplicate: "Already submitted this exact value",
  already_solved: "Your team has already solved this — nothing further to score",
  not_open: "The competition is not running",
  attempts_exhausted: "No attempts remaining",
};

/** Only `accepted` is a scoring success; the two "already" verdicts are neutral, not failures. */
export function verdictTone(verdict: SubmissionVerdict): "ok" | "warn" | "danger" {
  switch (verdict) {
    case "accepted":
      return "ok";
    case "already_solved":
    case "duplicate":
    case "not_open":
      return "warn";
    case "incorrect":
    case "attempts_exhausted":
      return "danger";
  }
}

// -------------------------------------------------------------------------------- scoreboard

/**
 * Presentation ordering ONLY: by the server's rank, with the team name as a stable tie-break so
 * rows do not reshuffle between polls. This reorders rows; it never changes, combines or
 * recomputes a score.
 */
export function orderScoreboard(entries: readonly ScoreboardEntry[]): ScoreboardEntry[] {
  return [...entries].sort(
    (a, b) => a.rank - b.rank || a.team_name.localeCompare(b.team_name),
  );
}

/**
 * The placement to DISPLAY. Always the server's rank — never the array index.
 *
 * The backend ties on `(score, last_solve_at)` TOGETHER, so two teams on equal points who reached
 * them at different times come back as 1 and 2, not as a shared rank. A genuine tie is therefore
 * rare, but when it happens standard competition ranking applies: two teams at 1 are followed by
 * rank 3. Renumbering from the array index would quietly turn that into a 1 and a 2.
 */
export function displayRank(entry: Pick<ScoreboardEntry, "rank">): string {
  return String(entry.rank);
}

/** True when this row shares its rank — the UI marks a tie rather than hiding it. */
export function isTiedRank(
  entry: Pick<ScoreboardEntry, "rank">,
  entries: readonly Pick<ScoreboardEntry, "rank">[],
): boolean {
  return entries.filter((e) => e.rank === entry.rank).length > 1;
}

/**
 * Percentage of the available points a team holds, for a progress bar.
 *
 * This is NOT a score computation — it is a ratio of two server-supplied numbers, used only for
 * bar width, and it never feeds back into anything displayed as a score. Guarded against a zero
 * denominator, which is a competition with no points rather than a team on 0%.
 */
export function scoreFraction(
  entry: Pick<ScoreboardEntry, "score">,
  totalPoints: number,
): number | null {
  if (totalPoints <= 0) return null;
  return Math.max(0, Math.min(1, entry.score / totalPoints));
}

/** Rows a scoreboard should render, in display order. Empty is empty — never a fabricated row. */
export function scoreboardRows(scoreboard: Scoreboard | null): ScoreboardEntry[] {
  return scoreboard === null ? [] : orderScoreboard(scoreboard.entries);
}

// -------------------------------------------------------------------------------- challenges

export interface ChallengeRow {
  id: string;
  key: string;
  title: string;
  description: string;
  category: string;
  points: number;
  hint: string | null;
  maxAttempts: number;
  solveCount: number;
  solvedByTeamIds: string[];
}

export function challengeRows(challenges: readonly Challenge[]): ChallengeRow[] {
  return [...challenges]
    .sort((a, b) => a.category.localeCompare(b.category) || a.points - b.points)
    .map((c) => ({
      id: c.id,
      key: c.key,
      title: c.title,
      description: c.description,
      category: c.category,
      points: c.points,
      hint: c.hint,
      maxAttempts: c.max_attempts,
      solveCount: c.solve_count,
      solvedByTeamIds: c.solved_by_team_ids,
    }));
}

/** Whether a given team has solved a challenge, from the server's own solve list. */
export function isSolvedBy(challenge: Pick<ChallengeRow, "solvedByTeamIds">, teamId: string): boolean {
  return challenge.solvedByTeamIds.includes(teamId);
}

// ------------------------------------------------------------------------------------- teams

export interface TeamRow {
  id: string;
  name: string;
  slug: string;
  joinCode: string;
  score: number;
  solvedCount: number;
}

export function teamRows(teams: readonly CompetitionTeam[]): TeamRow[] {
  return [...teams]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((t) => ({
      id: t.id,
      name: t.name,
      slug: t.slug,
      joinCode: t.join_code,
      score: t.score,
      solvedCount: t.solved_count,
    }));
}
