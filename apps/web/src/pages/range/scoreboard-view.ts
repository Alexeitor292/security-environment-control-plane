// Competition and scoreboard view-model.
//
// ── WHY THIS MODULE COMPUTES NO SCORES ────────────────────────────────────────────────────────
// Scores are authoritative on the server. This module renders what the backend returns and does
// arithmetic on NONE of it. There is deliberately no `total()`, no `applyPenalty()`, no
// `recomputeRank()` and no optimistic adjustment: a scoreboard that disagrees with the server is
// worse than one that is briefly stale, because a competitor reads it as the result.
//
// The only ordering this module performs is a presentation sort over a server-supplied rank field,
// and it refuses to invent a rank when the server did not send one.
//
// ── CURRENT STATUS: NO BACKEND ────────────────────────────────────────────────────────────────
// As of this build the control-plane API exposes NO competition, team-membership or scoring
// endpoints. `apps/api/secp_api/routers/` has no competition router; there is no scoring service.
// The types below describe the shape this UI will consume, and the pages render an explicit
// unavailable state naming the missing endpoints. Nothing here fabricates a score, a rank, a
// challenge or a team, and no page renders placeholder competition data.

/** The endpoints these surfaces need. Rendered verbatim so the gap is legible, not vague. */
export const MISSING_COMPETITION_ENDPOINTS: readonly string[] = [
  "GET/POST /api/v1/ranges/{id}/competition — competition state and start/stop control",
  "GET/POST /api/v1/ranges/{id}/teams — team roster and membership management",
  "GET /api/v1/ranges/{id}/scoreboard — authoritative scores and ranking",
  "GET /api/v1/ranges/{id}/challenges — challenge definitions and per-team solve state",
];

export const COMPETITION_UNAVAILABLE_TITLE = "Competition control is not available yet";

export const COMPETITION_UNAVAILABLE_BODY =
  "The control-plane API does not expose competition, team-membership or scoring endpoints in this build. This page is deliberately empty rather than showing placeholder standings: a scoreboard that is not the server's scoreboard is misinformation, not a preview.";

export const SCOREBOARD_AUTHORITY_NOTE =
  "Scores are authoritative on the server. This view renders exactly what the API returns and never computes, adjusts or projects a score in the browser.";

// ─────────────────────────────────────────────────────────────────── consumption-ready types
//
// These mirror the shapes the range backend is expected to publish. They are types only — no
// constructor, no default, no sample value that could leak into a render.

export type CompetitionState = "not_started" | "running" | "paused" | "ended";

export interface Competition {
  id: string;
  range_id: string;
  state: CompetitionState;
  started_at: string | null;
  ended_at: string | null;
}

export interface CompetitionTeam {
  id: string;
  range_id: string;
  team_ref: string;
  display_name: string;
  member_count: number;
}

export interface ScoreboardRow {
  team_id: string;
  team_ref: string;
  display_name: string;
  /** Server-computed. Never derived, summed or adjusted here. */
  score: number;
  /** Server-assigned placement. null when the server did not rank. */
  rank: number | null;
  solved_count: number;
  last_solve_at: string | null;
}

export interface Scoreboard {
  range_id: string;
  competition_state: CompetitionState;
  /** The server's own generation time — the UI shows this, not a client clock reading. */
  generated_at: string;
  rows: ScoreboardRow[];
}

/**
 * Presentation ordering ONLY: by the server's rank when it supplied one, otherwise by the server's
 * score descending, with the team ref as a stable tie-break so equal rows do not reshuffle between
 * polls. This reorders rows; it never changes, combines or recomputes a score.
 *
 * Rows the server left unranked sort after every ranked row rather than being assigned a position,
 * because "the server did not rank this team" and "this team came last" are different facts.
 */
export function orderScoreboard(rows: readonly ScoreboardRow[]): ScoreboardRow[] {
  return [...rows].sort((a, b) => {
    if (a.rank !== null && b.rank !== null) {
      return a.rank - b.rank || a.team_ref.localeCompare(b.team_ref);
    }
    if (a.rank !== null) return -1;
    if (b.rank !== null) return 1;
    return b.score - a.score || a.team_ref.localeCompare(b.team_ref);
  });
}

/**
 * The placement to DISPLAY for a row: the server's rank, or an explicit em dash when it sent none.
 * Never the array index — showing "1" for the first row of an unranked list states a placement the
 * server did not make.
 */
export function displayRank(row: Pick<ScoreboardRow, "rank">): string {
  return row.rank === null ? "—" : String(row.rank);
}

export const COMPETITION_STATE_LABEL: Record<CompetitionState, string> = {
  not_started: "Not started",
  running: "Running",
  paused: "Paused",
  ended: "Ended",
};
