import "./range.css";

import { useCallback, useMemo, useState } from "react";

import { api } from "../../api/client";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberTable,
  DataPanel,
  EmptyState,
  MetricTile,
  SafetyNotice,
  StatusBadge,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_PHASE_LABEL } from "./range-lifecycle";
import { RANGE_ERROR_TEXT } from "./range-view";
import {
  COMPETITION_STATE_HELP,
  COMPETITION_STATE_LABEL,
  FLAGS_ARE_NEVER_RETURNED_NOTE,
  RESET_SCORES_NOTE,
  START_REQUIREMENTS_NOTE,
  challengeRows,
  competitionControls,
} from "./scoreboard-view";
import { onlyNotFoundAsNull } from "../environments-view";

/**
 * Page 5 — Competition Control.
 *
 * Live. Creates the range's single competition, starts and stops it, and clears scores.
 *
 * Start is gated on the SERVER's precondition — a `ready` range and at least one team — mirrored
 * here only so the operator is told which half is missing rather than being handed a 409.
 */
export function CompetitionControl() {
  const { range, lifecycle, reloadRange } = useRange();
  const createAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const controlAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const [name, setName] = useState("");

  // A range legitimately has no competition until one is created; only a 404 means that.
  const competition = useAsync(
    () => api.getCompetition(range.id).catch(onlyNotFoundAsNull),
    [range.id, range.competition_id, range.updated_at],
  );
  const teams = useAsync(
    () => (range.competition_id === null ? Promise.resolve([]) : api.listTeams(range.id)),
    [range.id, range.competition_id],
  );
  const challenges = useAsync(
    () => (range.competition_id === null ? Promise.resolve([]) : api.listChallenges(range.id)),
    [range.id, range.competition_id],
  );

  const comp = competition.data;
  const controls = useMemo(
    () => competitionControls(comp, lifecycle.phase, teams.data?.length ?? 0),
    [comp, lifecycle.phase, teams.data],
  );
  const rows = useMemo(() => challengeRows(challenges.data ?? []), [challenges.data]);

  const refresh = useCallback(async () => {
    await Promise.all([reloadRange(), competition.reload(), teams.reload(), challenges.reload()]);
  }, [reloadRange, competition, teams, challenges]);

  const create = () =>
    createAction.run(
      () => api.createCompetition(range.id, name.trim() === "" ? {} : { name: name.trim() }),
      refresh,
    );

  const run = (fn: (id: string) => Promise<unknown>) => () => {
    if (comp === null) return;
    void controlAction.run(() => fn(comp.id), refresh);
  };

  if (comp === null && !competition.loading) {
    return (
      <div className="rng">
        <CyberCard heading="Create a competition" headingLevel={2}>
          <p className="rng-sub">
            A competition seeds this blueprint&rsquo;s challenges and flags, and holds the teams and
            scores. One per range.
          </p>
          <SafetyNotice role="note" tone="info">
            {FLAGS_ARE_NEVER_RETURNED_NOTE}
          </SafetyNotice>

          <div className="rng-confirm-field">
            <CyberInput
              label="Competition name (optional)"
              hint="Defaults to a name derived from the range."
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={range.name}
            />
          </div>

          {createAction.error !== null && (
            <ClosedCodeError
              error={createAction.error}
              codeText={RANGE_ERROR_TEXT}
              onDismiss={createAction.clearError}
            />
          )}

          <div className="rng-card-foot">
            <CyberButton variant="primary" disabled={createAction.busy} onClick={create}>
              {createAction.busy ? "Creating…" : "Create competition"}
            </CyberButton>
          </div>
        </CyberCard>
      </div>
    );
  }

  return (
    <div className="rng">
      <DataPanel state={competition} skeletonLines={4}>
        {(c) =>
          c === null ? null : (
            <>
              <div className="rng-grid">
                <MetricTile
                  label="Competition"
                  value={COMPETITION_STATE_LABEL[c.state]}
                  detail={COMPETITION_STATE_HELP[c.state]}
                  tone={c.state === "running" ? "ok" : "default"}
                />
                <MetricTile
                  label="Teams"
                  value={c.team_count}
                  detail={teams.error !== null ? "Team list unavailable." : "Server-held roster"}
                />
                <MetricTile
                  label="Challenges"
                  value={c.challenge_count}
                  detail={`${c.total_points} points available`}
                />
              </div>

              <CyberCard heading={c.name} headingLevel={2}>
                <div className="rng-identity">
                  <StatusBadge
                    state={c.state === "running" ? "succeeded" : c.state === "stopped" ? "removed" : "pending"}
                    domain="range-operation"
                  />
                  <span>{COMPETITION_STATE_LABEL[c.state]}</span>
                  {c.started_at !== null && (
                    <span className="rng-recorded">
                      started {c.started_at.slice(0, 19).replace("T", " ")}
                    </span>
                  )}
                </div>

                <SafetyNotice role="note" tone="info">
                  {START_REQUIREMENTS_NOTE}
                </SafetyNotice>

                {/* The precondition, named specifically rather than as a disabled button. */}
                {controls.startBlockedReason !== null && !controls.canStop && (
                  <SafetyNotice role="status" tone="warn">
                    {controls.startBlockedReason} The range is currently{" "}
                    {RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}.
                  </SafetyNotice>
                )}

                {controlAction.error !== null && (
                  <ClosedCodeError
                    error={controlAction.error}
                    codeText={RANGE_ERROR_TEXT}
                    onDismiss={controlAction.clearError}
                  />
                )}

                <div className="rng-card-foot">
                  {controls.canStart && (
                    <CyberButton
                      variant="primary"
                      disabled={controlAction.busy}
                      onClick={run((id) => api.startCompetition(id))}
                    >
                      {controlAction.busy ? "Working…" : "Start competition"}
                    </CyberButton>
                  )}
                  {controls.canStop && (
                    <CyberButton
                      variant="danger"
                      disabled={controlAction.busy}
                      onClick={run((id) => api.stopCompetition(id))}
                    >
                      {controlAction.busy ? "Working…" : "Stop competition"}
                    </CyberButton>
                  )}
                  <CyberButton onClick={() => void refresh()} disabled={controlAction.busy}>
                    Refresh
                  </CyberButton>
                </div>
              </CyberCard>

              <CyberCard heading="Clear scores" headingLevel={2}>
                <SafetyNotice role="note" tone="warn">
                  {RESET_SCORES_NOTE}
                </SafetyNotice>
                {controls.canResetScores ? (
                  <div className="rng-card-foot">
                    <CyberButton
                      variant="danger"
                      disabled={controlAction.busy}
                      onClick={run((id) => api.resetCompetitionScores(id))}
                    >
                      Clear all scores and submissions
                    </CyberButton>
                  </div>
                ) : (
                  <EmptyState title="Not available while the competition is running">
                    Stop the competition first.
                  </EmptyState>
                )}
              </CyberCard>
            </>
          )
        }
      </DataPanel>

      <CyberCard heading="Challenges" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {FLAGS_ARE_NEVER_RETURNED_NOTE}
        </SafetyNotice>
        <DataPanel
          state={challenges}
          isEmpty={() => rows.length === 0}
          empty={<EmptyState title="No challenges">This competition has no challenges.</EmptyState>}
        >
          {() => (
            <CyberTable
              label="Challenges"
              head={["Challenge", "Category", "Points", "Solves", "Attempts"]}
              caption={`${rows.length} challenge${rows.length === 1 ? "" : "s"} · no response from this API ever contains a flag`}
            >
              {rows.map((c) => (
                <tr key={c.id}>
                  <td>
                    {c.title}
                    <div className="muted">{c.description}</div>
                  </td>
                  <td className="muted">{c.category}</td>
                  <td>{c.points}</td>
                  <td>{c.solveCount}</td>
                  <td className="muted mono">{c.maxAttempts}</td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>
    </div>
  );
}
