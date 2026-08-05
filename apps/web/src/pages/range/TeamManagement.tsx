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
  SafetyNotice,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_ERROR_TEXT } from "./range-view";
import {
  COMPETITOR_IS_NOT_A_USER_NOTE,
  MEMBERSHIP_GRANTS_NOTHING_NOTE,
  TEAMS_ARE_FROZEN_WHEN_RUNNING_NOTE,
  competitionControls,
  teamRows,
} from "./scoreboard-view";
import { onlyNotFoundAsNull } from "../environments-view";

/**
 * Page 6 — Team Management.
 *
 * Live. Teams belong to the range's competition, and a member is a ROSTER ENTRY: a display name,
 * with no account, no permission and no effect on scoring.
 *
 * Three things this page is careful NOT to imply:
 *  - that removing a member changes a score. It does not; the team scores, and the scoreboard is a
 *    record of what happened rather than a function of the current roster.
 *  - that a competitor must be a SECP user. `user_id` is optional and this form does not ask for
 *    it — a free-text name is the common case at a training event.
 *  - that "add team" being disabled mid-competition is a bug. A team appearing mid-event changes
 *    what the scoreboard means; a latecomer does not. The copy states the asymmetry.
 */
export function TeamManagement() {
  const { range, lifecycle } = useRange();
  const teamAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const memberAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const [teamName, setTeamName] = useState("");
  const [openTeamId, setOpenTeamId] = useState<string | null>(null);
  const [memberName, setMemberName] = useState("");

  const competition = useAsync(
    () => api.getCompetition(range.id).catch(onlyNotFoundAsNull),
    [range.id, range.competition_id, range.updated_at],
  );
  const teams = useAsync(
    () => (range.competition_id === null ? Promise.resolve([]) : api.listTeams(range.id)),
    [range.id, range.competition_id],
  );
  const members = useAsync(
    () =>
      openTeamId === null
        ? Promise.resolve([])
        : api.listTeamMembers(range.id, openTeamId),
    [range.id, openTeamId],
  );

  const rows = useMemo(() => teamRows(teams.data ?? []), [teams.data]);
  const controls = useMemo(
    () => competitionControls(competition.data, lifecycle.phase, rows.length),
    [competition.data, lifecycle.phase, rows.length],
  );

  const refreshTeams = useCallback(async () => {
    await teams.reload();
  }, [teams]);

  const addTeam = () =>
    teamAction.run(() => api.createTeam(range.id, { name: teamName.trim() }), async () => {
      setTeamName("");
      await refreshTeams();
    });

  const removeTeam = (teamId: string) => {
    const comp = competition.data;
    if (comp === null) return;
    void teamAction.run(() => api.deleteTeam(comp.id, teamId), async () => {
      if (openTeamId === teamId) setOpenTeamId(null);
      await refreshTeams();
    });
  };

  const addMember = () => {
    if (openTeamId === null) return;
    // `display_name` only. No user picker: requiring an account would either block the common case
    // or push the platform into minting throwaway users for workshop attendees.
    void memberAction.run(
      () => api.addTeamMember(range.id, openTeamId, { display_name: memberName.trim() }),
      async () => {
        setMemberName("");
        await Promise.all([members.reload(), refreshTeams()]);
      },
    );
  };

  const removeMember = (memberId: string) => {
    if (openTeamId === null) return;
    // Deliberately does NOT reload the scoreboard or recompute anything: removing a member does
    // not retract solves, and refreshing scores here would imply it might.
    void memberAction.run(
      () => api.removeTeamMember(range.id, openTeamId, memberId),
      () => members.reload(),
    );
  };

  if (range.competition_id === null) {
    return (
      <div className="rng">
        <CyberCard heading="Teams" headingLevel={2}>
          <EmptyState title="No competition on this range yet">
            Teams belong to a competition, not to the range itself. Create one on the Competition
            tab first.
          </EmptyState>
        </CyberCard>
      </div>
    );
  }

  const openTeam = rows.find((t) => t.id === openTeamId) ?? null;

  return (
    <div className="rng">
      <CyberCard heading="Teams" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {TEAMS_ARE_FROZEN_WHEN_RUNNING_NOTE}
        </SafetyNotice>

        {controls.canAddTeam && (
          <div className="rng-search">
            <CyberInput
              label="New team name"
              value={teamName}
              onChange={(e) => setTeamName(e.target.value)}
            />
            <CyberButton
              variant="primary"
              disabled={teamName.trim() === "" || teamAction.busy}
              onClick={addTeam}
            >
              {teamAction.busy ? "Adding…" : "Add team"}
            </CyberButton>
          </div>
        )}

        {teamAction.error !== null && (
          <ClosedCodeError
            error={teamAction.error}
            codeText={RANGE_ERROR_TEXT}
            onDismiss={teamAction.clearError}
          />
        )}

        <DataPanel
          state={teams}
          isEmpty={() => rows.length === 0}
          empty={
            <EmptyState title="No teams yet">
              A competition needs at least one team before it can start.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Teams"
              head={["Team", "Join code", "Score", "Solved", "Roster", ""]}
              caption={`${rows.length} team${rows.length === 1 ? "" : "s"} · scores are held and computed by the server`}
            >
              {rows.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td className="mono">{t.joinCode}</td>
                  {/* Rendered exactly as the server reports it. Never adjusted here. */}
                  <td>{t.score}</td>
                  <td>{t.solvedCount}</td>
                  <td>
                    <CyberButton
                      size="sm"
                      aria-expanded={openTeamId === t.id}
                      onClick={() => setOpenTeamId(openTeamId === t.id ? null : t.id)}
                    >
                      {openTeamId === t.id ? "Hide roster" : "Roster"}
                    </CyberButton>
                  </td>
                  <td>
                    {controls.canRemoveTeam ? (
                      <CyberButton
                        size="sm"
                        variant="danger"
                        disabled={teamAction.busy}
                        onClick={() => removeTeam(t.id)}
                      >
                        Remove
                      </CyberButton>
                    ) : (
                      <span className="muted">frozen while running</span>
                    )}
                  </td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      {openTeam !== null && (
        <CyberCard heading={`Roster — ${openTeam.name}`} headingLevel={2}>
          <SafetyNotice role="note" tone="info">
            {MEMBERSHIP_GRANTS_NOTHING_NOTE}
          </SafetyNotice>

          <div className="rng-search">
            <CyberInput
              label="Competitor name"
              hint={COMPETITOR_IS_NOT_A_USER_NOTE}
              value={memberName}
              onChange={(e) => setMemberName(e.target.value)}
            />
            <CyberButton
              variant="primary"
              disabled={memberName.trim() === "" || memberAction.busy}
              onClick={addMember}
            >
              {memberAction.busy ? "Adding…" : "Add member"}
            </CyberButton>
          </div>

          {memberAction.error !== null && (
            <ClosedCodeError
              error={memberAction.error}
              codeText={RANGE_ERROR_TEXT}
              onDismiss={memberAction.clearError}
            />
          )}

          <DataPanel
            state={members}
            isEmpty={() => (members.data?.length ?? 0) === 0}
            empty={
              <EmptyState title="No members on this team">
                A team can compete with an empty roster — membership is a record of who took part,
                not a requirement for scoring.
              </EmptyState>
            }
          >
            {(list) => (
              <CyberTable
                label="Team members"
                head={["Name", "Linked user", "Added", ""]}
                caption="Removing a member does not retract their team's solves."
              >
                {list.map((m) => (
                  <tr key={m.id}>
                    <td>{m.display_name}</td>
                    <td className="muted mono">{m.user_id ?? "not linked"}</td>
                    <td className="muted mono">{m.created_at.slice(0, 10)}</td>
                    <td>
                      <CyberButton
                        size="sm"
                        disabled={memberAction.busy}
                        onClick={() => removeMember(m.id)}
                      >
                        Remove
                      </CyberButton>
                    </td>
                  </tr>
                ))}
              </CyberTable>
            )}
          </DataPanel>
        </CyberCard>
      )}
    </div>
  );
}
