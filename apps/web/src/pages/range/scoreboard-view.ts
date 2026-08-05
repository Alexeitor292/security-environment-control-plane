// Competition and scoreboard view-model.
//
// ── WHY THIS MODULE COMPUTES NO SCORES ────────────────────────────────────────────────────────
// Scores are authoritative on the server. This module renders what the backend returns and does
// arithmetic on NONE of it. There is deliberately no `total()`, no `applyPenalty()`, no
// `recomputeRank()` and no optimistic adjustment: a scoreboard that disagrees with the server is
// worse than one that is briefly stale, because a competitor reads it as the result.
//
// `points_awarded` on a submission is a REPORT of what the server recorded, never an instruction —
// it is displayed and then forgotten, never accumulated into a client-held total.
//
// The only ordering here is a presentation sort over a server-supplied rank, and it refuses to
// invent a rank the server did not assign.
//
// ── CURRENT STATUS: SHAPES FROZEN, ROUTES NOT ON MAIN ─────────────────────────────────────────
// The types below mirror the FROZEN range API contract published by owner-range-backend
// (branch `feature/secp-range-backend`). As of this build that branch is UNPUSHED and
// `apps/api/secp_api/routers/` on main has no range router, so none of these routes answer.
// The pages render an explicit unavailable state naming the exact missing routes. Nothing here
// fabricates a score, a rank, a challenge or a team.

/** Routes these surfaces need, verbatim from the frozen contract. */
export const MISSING_COMPETITION_ENDPOINTS: readonly string[] = [
  "POST|GET /api/v1/ranges/{id}/competition — create and read the competition",
  "POST /api/v1/competitions/{cid}/start|stop|reset-scores — competition control",
  "POST|GET /api/v1/competitions/{cid}/teams — team roster",
  "GET /api/v1/competitions/{cid}/challenges — challenge definitions and solve state",
  "POST|GET /api/v1/competitions/{cid}/submissions — flag submission and history",
  "GET /api/v1/competitions/{cid}/scoreboard — authoritative scores and ranking",
];

export const COMPETITION_UNAVAILABLE_TITLE = "Competition control is not available yet";

export const COMPETITION_UNAVAILABLE_BODY =
  "The range API's competition routes are specified and frozen, but they are not on main yet — the backend branch is unmerged, so nothing answers these calls. This page is deliberately empty rather than showing placeholder standings: a scoreboard that is not the server's scoreboard is misinformation, not a preview.";

export const SCOREBOARD_AUTHORITY_NOTE =
  "Scores are authoritative on the server. This view renders exactly what the API returns and never computes, adjusts or projects a score in the browser.";

export const FLAGS_ARE_NEVER_RETURNED_NOTE =
  "Flag values are never present in any API response — they are stored salted-hashed and compared server-side only. A submission returns a verdict, never the answer.";

// ─────────────────────────────────────────────────────────── contract types (frozen shapes)

export type CompetitionState = "draft" | "running" | "stopped";

export type SubmissionVerdict =
  | "accepted"
  | "incorrect"
  | "duplicate"
  | "already_solved"
  | "not_open"
  | "attempts_exhausted";

export interface Competition {
  id: string;
  range_id: string;
  name: string;
  state: CompetitionState;
  started_at: string | null;
  stopped_at: string | null;
  team_count: number;
  challenge_count: number;
  total_points: number;
  created_at: string;
}

export interface CompetitionTeam {
  id: string;
  competition_id: string;
  name: string;
  slug: string;
  join_code: string;
  /** Server-computed. Never derived, summed or adjusted here. */
  score: number;
  solved_count: number;
  created_at: string;
}

export interface Challenge {
  id: string;
  competition_id: string;
  key: string;
  title: string;
  description: string;
  category: string;
  points: number;
  component_key: string | null;
  hint: string | null;
  max_attempts: number;
  solve_count: number;
  solved_by_team_ids: string[];
}

export interface Submission {
  id: string;
  competition_id: string;
  team_id: string;
  team_name: string;
  challenge_id: string;
  challenge_title: string;
  verdict: SubmissionVerdict;
  /** A REPORT of what the server recorded. Never accumulated client-side. */
  points_awarded: number;
  attempts_remaining: number;
  submitted_at: string;
}

export interface ScoreboardEntry {
  /** Server-assigned placement. Ties SHARE a rank (contract §4). */
  rank: number;
  team_id: string;
  team_name: string;
  score: number;
  solved_count: number;
  last_solve_at: string | null;
  solved_challenge_ids: string[];
}

export interface Scoreboard {
  competition_id: string;
  state: CompetitionState;
  /** The server's own generation time — shown as-is, never a client clock reading. */
  generated_at: string;
  total_points: number;
  entries: ScoreboardEntry[];
}

// ────────────────────────────────────────────────────────────────────── presentation only

export const COMPETITION_STATE_LABEL: Record<CompetitionState, string> = {
  draft: "Not started",
  running: "Running",
  stopped: "Stopped",
};

/**
 * Copy for each submission verdict. `already_solved` and `duplicate` are deliberately NOT phrased
 * as failures — the team did solve it, they just earn nothing further. Conflating either with
 * `incorrect` would tell a competitor their correct answer was wrong.
 */
export const VERDICT_LABEL: Record<SubmissionVerdict, string> = {
  accepted: "Accepted",
  incorrect: "Incorrect",
  duplicate: "Already submitted this exact value",
  already_solved: "Already solved by this team — no further points",
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

/**
 * Presentation ordering ONLY: by the server's rank, with the team name as a stable tie-break so
 * teams sharing a rank do not reshuffle between polls. This reorders rows; it never changes,
 * combines or recomputes a score.
 *
 * The contract says ties SHARE a rank, so equal ranks are expected and must never be renumbered.
 */
export function orderScoreboard(entries: readonly ScoreboardEntry[]): ScoreboardEntry[] {
  return [...entries].sort(
    (a, b) => a.rank - b.rank || a.team_name.localeCompare(b.team_name),
  );
}

/**
 * The placement to DISPLAY. Always the server's rank — never the array index, because the index
 * would silently renumber the shared ranks the contract produces for ties, turning two teams tied
 * at 1st into a 1st and a 2nd.
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
