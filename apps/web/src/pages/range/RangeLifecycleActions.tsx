import "./range.css";

import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../../api/client";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  EmptyState,
  SafetyNotice,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_PHASE_LABEL, permittedActions } from "./range-lifecycle";
import {
  DESTROY_IS_IRREVERSIBLE_NOTE,
  RANGE_ERROR_TEXT,
  RESET_IS_DISPATCHED_NOTE,
  blastRadius,
  destroyConfirmationMatches,
} from "./range-view";

/**
 * Page 9 — Reset and Destroy Confirmation.
 *
 * Both actions return 202 and run on the worker, so neither navigates away or claims completion:
 * the layout keeps polling and the recorded state is what says the work finished.
 *
 * Destroy is gated behind typing the range's exact name, and states its blast radius from the
 * server's own resource records first. A confirmation that cannot say what it will destroy is a
 * button with a warning label.
 */
export function RangeLifecycleActions() {
  const { range, lifecycle, reloadRange } = useRange();
  const navigate = useNavigate();
  const resetAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const destroyAction = useAction({ codeText: RANGE_ERROR_TEXT });
  const [confirmation, setConfirmation] = useState("");

  // `null` on failure rather than `[]`, so the blast radius can tell "nothing there" apart from
  // "could not look" — the difference between an empty list and an unknown one.
  const resources = useAsync(
    () => api.listRangeResources(range.id).catch(() => null),
    [range.id, range.updated_at],
  );

  const radius = useMemo(() => blastRadius(resources.data), [resources.data]);
  const allowed = permittedActions(lifecycle);
  const canReset = allowed.includes("reset");
  const canDestroy = allowed.includes("destroy");
  const confirmed = destroyConfirmationMatches(confirmation, range.name);

  const refresh = useCallback(async () => {
    await Promise.all([reloadRange(), resources.reload()]);
  }, [reloadRange, resources]);

  const reset = () => resetAction.run(() => api.resetRange(range.id), refresh);

  const destroy = () =>
    destroyAction.run(async () => {
      await api.destroyRange(range.id);
      // Stay on the range: destroy is DISPATCHED, not done. The layout keeps polling and the state
      // advances to `destroyed` — or to `recovery_required` if the teardown could not be observed.
      // Navigating to the catalog here would imply the teardown had already finished cleanly.
      await refresh();
      setConfirmation("");
    });

  return (
    <div className="rng">
      <CyberCard heading="Reset range" headingLevel={2}>
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

        {canReset ? (
          <div className="rng-card-foot">
            <CyberButton disabled={resetAction.busy} onClick={reset}>
              {resetAction.busy ? "Dispatching…" : "Reset this range"}
            </CyberButton>
          </div>
        ) : (
          <EmptyState title="Reset is not available in this state">
            The range is {RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}.
            {lifecycle.phase === "recovery_required" &&
              " Retrying an operation over infrastructure nobody could observe turns one unproven outcome into two — destroy is the action that can still resolve it."}
          </EmptyState>
        )}
      </CyberCard>

      <CyberCard heading="Destroy range" headingLevel={2}>
        <div className="rng-danger">
          <h3>This cannot be undone</h3>
          <SafetyNotice role="alert" tone="danger">
            {DESTROY_IS_IRREVERSIBLE_NOTE}
          </SafetyNotice>

          {!canDestroy ? (
            <EmptyState title="Destroy is not available in this state">
              The range is {RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}.
              {!lifecycle.known &&
                " The recorded state is not recognized by this build, so no lifecycle action is offered."}
            </EmptyState>
          ) : (
            <>
              <div className="rng-blast">
                <h4>What will be destroyed</h4>
                <p className="rng-sub">
                  {radius.resourceCount} resource{radius.resourceCount === 1 ? "" : "s"} —{" "}
                  {radius.containerCount} container{radius.containerCount === 1 ? "" : "s"} and{" "}
                  {radius.networkCount} network{radius.networkCount === 1 ? "" : "s"}:
                </p>
                {radius.lines.length === 0 ? (
                  <p className="rng-sub muted">
                    The server records no live resources for this range.
                  </p>
                ) : (
                  <ul className="rng-blast-list">
                    {radius.lines.map((line) => (
                      <li key={line} className="mono">
                        {line}
                      </li>
                    ))}
                  </ul>
                )}
                {radius.ports.length > 0 && (
                  <p className="rng-sub">
                    These host ports will stop answering:{" "}
                    <span className="mono">{radius.ports.join(", ")}</span>
                  </p>
                )}
                {!radius.complete && (
                  <SafetyNotice role="alert" tone="warn">
                    {radius.incompleteReason}
                  </SafetyNotice>
                )}
              </div>

              <p className="rng-sub">
                To confirm, type the range name exactly: <strong>{range.name}</strong>
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
