import "./range.css";

import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

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
  StatusBadge,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_PHASE_LABEL, permittedActions } from "./range-lifecycle";
import {
  DESTROY_IS_IRREVERSIBLE_NOTE,
  RANGE_ERROR_TEXT,
  RESET_IS_DISPATCHED_NOTE,
  canResetInstance,
  destroyConfirmationMatches,
  teamInstanceRows,
} from "./range-view";

/**
 * Page 9 — Reset and Destroy Confirmation.
 *
 * Reset is per team instance, because that is the granularity the API offers. Destroy is
 * range-wide, irreversible, and gated behind typing the range's exact name — the operator has to
 * read which range they are about to tear down, which a plain "are you sure" does not require.
 *
 * Both actions are offered only when the RECORDED phase permits them. The server re-checks
 * everything; these controls exist so the UI does not present a button whose only outcome is a
 * refusal.
 */
export function RangeLifecycleActions() {
  const { range, lifecycle, reloadRange } = useRange();
  const navigate = useNavigate();
  const resetAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const destroyAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const [confirmation, setConfirmation] = useState("");

  const instances = useAsync(
    () => api.listInstances(range.id),
    [range.id, range.lifecycle_state],
  );
  const topology = useAsync(
    () => api.exerciseTopology(range.id).catch(() => []),
    [range.id, range.lifecycle_state],
  );

  const teams = useMemo(
    () => (instances.data ? teamInstanceRows(instances.data, topology.data ?? []) : []),
    [instances.data, topology.data],
  );

  const allowed = permittedActions(lifecycle);
  const canDestroy = allowed.includes("destroy");
  const confirmed = destroyConfirmationMatches(confirmation, range.name);

  const refresh = useCallback(async () => {
    await Promise.all([reloadRange(), instances.reload()]);
  }, [reloadRange, instances]);

  const resetOne = (instanceId: string) =>
    resetAction.run(() => api.resetInstance(range.id, instanceId), refresh);

  const destroy = () =>
    destroyAction.run(async () => {
      await api.destroyExercise(range.id);
      // Stay on the range: destroy is DISPATCHED, not done. The layout keeps polling and the
      // phase advances to destroyed on its own. Navigating to the catalog here would imply the
      // teardown had already finished.
      await reloadRange();
      setConfirmation("");
    });

  return (
    <div className="rng">
      <CyberCard heading="Reset team instances" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {RESET_IS_DISPATCHED_NOTE}
        </SafetyNotice>

        {resetAction.error !== null && (
          <ClosedCodeError
            error={resetAction.error}
            codeText={RANGE_ERROR_TEXT}
            onDismiss={resetAction.clearError}
          />
        )}

        <DataPanel
          state={instances}
          isEmpty={() => teams.length === 0}
          empty={
            <EmptyState title="No team instances to reset">
              This range has no instances. They are created when it is deployed.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Team instances"
              head={["Team", "Phase", "Recorded", "Action"]}
              caption="Reset returns one team's targets to their initial state. It is dispatched per instance."
            >
              {teams.map((t) => {
                const resettable = canResetInstance(t);
                return (
                  <tr key={t.instanceId}>
                    <td>{t.teamRef}</td>
                    <td>
                      <StatusBadge state={t.lifecycle.phase} domain="range" />
                    </td>
                    <td className="muted mono">{t.lifecycle.recorded}</td>
                    <td>
                      {resettable ? (
                        <CyberButton
                          size="sm"
                          disabled={resetAction.busy}
                          onClick={() => resetOne(t.instanceId)}
                        >
                          {resetAction.busy ? "Dispatching…" : "Reset"}
                        </CyberButton>
                      ) : (
                        <span className="muted">
                          Not resettable while {RANGE_PHASE_LABEL[t.lifecycle.phase].toLowerCase()}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <CyberCard heading="Destroy range" headingLevel={2}>
        <div className="rng-danger">
          <h3>This cannot be undone</h3>
          <SafetyNotice role="alert" tone="danger">
            {DESTROY_IS_IRREVERSIBLE_NOTE}
          </SafetyNotice>

          {!canDestroy ? (
            <EmptyState title="Destroy is not available in this phase">
              The range is {RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}.
              {!lifecycle.known &&
                " The recorded state is not recognized by this build, so no lifecycle action is offered."}
            </EmptyState>
          ) : (
            <>
              <p className="rng-sub">
                Destroying tears down all {range.team_count} team instance
                {range.team_count === 1 ? "" : "s"}. To confirm, type the range name exactly:{" "}
                <strong>{range.name}</strong>
              </p>

              <div className="rng-confirm-field">
                <CyberInput
                  label="Confirm range name"
                  value={confirmation}
                  onChange={(e) => setConfirmation(e.target.value)}
                  errorText={
                    confirmation !== "" && !confirmed
                      ? "The name does not match exactly."
                      : undefined
                  }
                />
              </div>

              {destroyAction.error !== null && (
                <ClosedCodeError
                  error={destroyAction.error}
                  codeText={RANGE_ERROR_TEXT}
                  onDismiss={destroyAction.clearError}
                />
              )}

              <div className="rng-card-foot">
                <CyberButton
                  variant="danger"
                  disabled={!confirmed || destroyAction.busy}
                  onClick={destroy}
                >
                  {destroyAction.busy ? "Dispatching teardown…" : "Destroy this range"}
                </CyberButton>
                <CyberButton onClick={() => navigate(`/ranges/${range.id}`)}>Cancel</CyberButton>
              </div>
            </>
          )}
        </div>
      </CyberCard>
    </div>
  );
}
