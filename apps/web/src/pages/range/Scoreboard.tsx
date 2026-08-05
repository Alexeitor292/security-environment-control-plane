import "./range.css";

import { useCallback, useMemo, useState } from "react";

import { api } from "../../api/client";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberSelect,
  CyberTable,
  DataPanel,
  EmptyState,
  SafetyNotice,
  StatusBadge,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_ERROR_TEXT } from "./range-view";
import {
  COMPETITION_STATE_LABEL,
  FLAGS_ARE_NEVER_RETURNED_NOTE,
  SCOREBOARD_AUTHORITY_NOTE,
  VERDICT_LABEL,
  challengeRows,
  competitionControls,
  displayRank,
  isTiedRank,
  scoreFraction,
  scoreboardRows,
  teamRows,
  verdictTone,
} from "./scoreboard-view";
import { usePolledAsync } from "./use-range-polling";
import { onlyNotFoundAsNull } from "../environments-view";
import type { Submission } from "../../api/range-types";

/**
 * Page 7 — Live Scoreboard, and flag submission.
 *
 * Live, and polls every 3s while the competition is running. Everything on it is the server's:
 * the ranks, the scores and the verdicts. Nothing is computed, adjusted or optimistically applied
 * here — a submission's `points_awarded` is displayed as a report of what the server recorded and
 * is never added to a client-held total. The next scoreboard poll is what moves the standings.
 */
export function Scoreboard() {
  const { range, lifecycle } = useRange();
  const submitAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const [teamId, setTeamId] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [value, setValue] = useState("");
  const [lastSubmission, setLastSubmission] = useState<Submission | null>(null);

  const competition = useAsync(
    () => api.getCompetition(range.id).catch(onlyNotFoundAsNull),
    [range.id, range.competition_id, range.updated_at],
  );

  // The authoritative standings. Polling is decided from the scoreboard's own reported state.
  const scoreboard = usePolledAsync(
    () =>
      range.competition_id === null
        ? Promise.resolve(null)
        : api.getScoreboard(range.id).catch(onlyNotFoundAsNull),
    [range.id, range.competition_id],
    { intervalMs: 3000, shouldPoll: (s) => s !== null && s.state === "running" },
  );

  const teams = useAsync(
    () => (range.competition_id === null ? Promise.resolve([]) : api.listTeams(range.id)),
    [range.id, range.competition_id],
  );
  const challenges = useAsync(
    () => (range.competition_id === null ? Promise.resolve([]) : api.listChallenges(range.id)),
    [range.id, range.competition_id],
  );

  const rows = useMemo(() => scoreboardRows(scoreboard.data), [scoreboard.data]);
  const teamOptions = useMemo(() => teamRows(teams.data ?? []), [teams.data]);
  const challengeOptions = useMemo(() => challengeRows(challenges.data ?? []), [challenges.data]);
  const controls = useMemo(
    () => competitionControls(competition.data, lifecycle.phase, teamOptions.length),
    [competition.data, lifecycle.phase, teamOptions.length],
  );
  const totalPoints = scoreboard.data?.total_points ?? 0;

  const refreshAfterSubmit = useCallback(async () => {
    // The scoreboard is re-read from the server. The submission response is NOT used to adjust
    // any score shown here.
    await Promise.all([scoreboard.reload(), teams.reload(), challenges.reload()]);
  }, [scoreboard, teams, challenges]);

  const submit = () =>
    submitAction.run(async () => {
      const comp = competition.data;
      if (comp === null) return;
      const result = await api.submitFlag(comp.id, {
        team_id: teamId,
        challenge_id: challengeId,
        value,
      });
      setLastSubmission(result);
      setValue("");
      await refreshAfterSubmit();
    });

  if (range.competition_id === null) {
    return (
      <div className="rng">
        <CyberCard heading="Scoreboard" headingLevel={2}>
          <EmptyState title="No competition on this range yet">
            Create one on the Competition tab to get a scoreboard.
          </EmptyState>
        </CyberCard>
      </div>
    );
  }

  return (
    <div className="rng">
      <SafetyNotice role="note" tone="info">
        {SCOREBOARD_AUTHORITY_NOTE}
      </SafetyNotice>

      <CyberCard heading="Standings" headingLevel={2}>
        <div className="rng-identity">
          {scoreboard.data !== null && (
            <>
              <StatusBadge
                state={scoreboard.data.state === "running" ? "succeeded" : "pending"}
                domain="range-operation"
              />
              <span>{COMPETITION_STATE_LABEL[scoreboard.data.state]}</span>
              {/* The SERVER's generation time, not a client clock reading. */}
              <span className="rng-recorded">
                generated {scoreboard.data.generated_at.slice(11, 19)}
              </span>
            </>
          )}
          {scoreboard.polling && (
            <span className="rng-live" role="status">
              <span className="rng-live-dot" aria-hidden="true" />
              Live — {scoreboard.refreshCount} server update
              {scoreboard.refreshCount === 1 ? "" : "s"}
            </span>
          )}
        </div>

        <DataPanel
          state={scoreboard}
          isEmpty={() => rows.length === 0}
          empty={
            <EmptyState title="No standings yet">
              No team has scored. This is the server&rsquo;s scoreboard — an empty one means
              nothing has been solved, not that it could not be loaded.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Scoreboard"
              head={["Rank", "Team", "Score", "Solved", "Last solve"]}
              caption={`${rows.length} team${rows.length === 1 ? "" : "s"} · ranks and scores are exactly what the server returned`}
            >
              {rows.map((e) => {
                const fraction = scoreFraction(e, totalPoints);
                return (
                  <tr key={e.team_id}>
                    <td className="mono">
                      {displayRank(e)}
                      {isTiedRank(e, rows) && <span className="muted"> (tied)</span>}
                    </td>
                    <td>{e.team_name}</td>
                    <td>
                      {e.score}
                      {fraction !== null && (
                        <div
                          className="rng-meter"
                          style={{ ["--rng-progress" as string]: String(fraction) }}
                          aria-hidden="true"
                        >
                          <div className="rng-meter-fill" />
                        </div>
                      )}
                    </td>
                    <td>{e.solved_count}</td>
                    <td className="muted mono">
                      {e.last_solve_at === null ? "—" : e.last_solve_at.slice(11, 19)}
                    </td>
                  </tr>
                );
              })}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <CyberCard heading="Submit a flag" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {FLAGS_ARE_NEVER_RETURNED_NOTE}
        </SafetyNotice>

        {!controls.canSubmit ? (
          <EmptyState title="Submissions are not open">
            The competition is{" "}
            {competition.data === null
              ? "not created"
              : COMPETITION_STATE_LABEL[competition.data.state].toLowerCase()}
            . Start it on the Competition tab to accept submissions.
          </EmptyState>
        ) : (
          <>
            <div className="rng-grid">
              <CyberSelect
                label="Team"
                value={teamId}
                onChange={(e) => setTeamId(e.target.value)}
                options={[
                  { value: "", label: "Select a team…" },
                  ...teamOptions.map((t) => ({ value: t.id, label: t.name })),
                ]}
              />
              <CyberSelect
                label="Challenge"
                value={challengeId}
                onChange={(e) => setChallengeId(e.target.value)}
                options={[
                  { value: "", label: "Select a challenge…" },
                  ...challengeOptions.map((c) => ({
                    value: c.id,
                    label: `${c.title} (${c.points} pts)`,
                  })),
                ]}
              />
            </div>
            <CyberInput
              label="Flag"
              mono
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />

            {submitAction.error !== null && (
              <ClosedCodeError
                error={submitAction.error}
                codeText={RANGE_ERROR_TEXT}
                onDismiss={submitAction.clearError}
              />
            )}

            {/* The server's verdict, rendered as-is. `already_solved` and `duplicate` are neutral:
                a team that has solved a challenge gets this verdict for ANY further submission,
                right or wrong, so treating it as an error would call a correct answer wrong. */}
            {lastSubmission !== null && (
              <SafetyNotice
                role="status"
                tone={
                  verdictTone(lastSubmission.verdict) === "ok"
                    ? "info"
                    : verdictTone(lastSubmission.verdict) === "warn"
                      ? "warn"
                      : "danger"
                }
              >
                {VERDICT_LABEL[lastSubmission.verdict]}
                {lastSubmission.verdict === "accepted" &&
                  ` — the server recorded ${lastSubmission.points_awarded} points for ${lastSubmission.team_name}.`}
                {lastSubmission.verdict === "incorrect" &&
                  ` ${lastSubmission.attempts_remaining} attempt${lastSubmission.attempts_remaining === 1 ? "" : "s"} remaining.`}
              </SafetyNotice>
            )}

            <div className="rng-card-foot">
              <CyberButton
                variant="primary"
                disabled={
                  teamId === "" || challengeId === "" || value.trim() === "" || submitAction.busy
                }
                onClick={submit}
              >
                {submitAction.busy ? "Submitting…" : "Submit flag"}
              </CyberButton>
            </div>
          </>
        )}
      </CyberCard>
    </div>
  );
}
