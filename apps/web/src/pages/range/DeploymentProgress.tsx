import "./range.css";

import { useCallback, useMemo } from "react";

import { api } from "../../api/client";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberTable,
  DataPanel,
  EmptyState,
  SafetyNotice,
  StatusBadge,
  useAction,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_PHASE_HELP, permittedActions } from "./range-lifecycle";
import {
  EXECUTION_POSTURE_NOTE,
  OPERATION_KIND_LABEL,
  RANGE_ERROR_TEXT,
  UNPROVEN_NOTE,
  operationOutcomeText,
  operationProgress,
} from "./range-view";

/**
 * Page 3 — Deployment Progress.
 *
 * Progress comes from the server's own operation record, re-read by the layout every 2s while
 * anything is in flight. Nothing here animates expected progress: if the server does not advance,
 * neither does the page.
 *
 * The critical case is the window between the 202 and the worker picking the operation up. In that
 * window `total_steps` is 0 because THE PLAN DOES NOT EXIST YET — the API is not permitted to hold
 * a provider, so it cannot plan the steps. That is rendered as an indeterminate bar, never as 0%,
 * because "we do not know how much work there is" and "no work has been done" are different
 * claims and only the first is true.
 */
export function DeploymentProgress() {
  const { range, lifecycle, reloadRange, polling } = useRange();
  const action = useAction({ codeText: RANGE_ERROR_TEXT });

  // The full operation record — steps live here, not on the range summary.
  const operationId = range.current_operation?.id ?? null;
  const operation = useAsync(
    () => (operationId === null ? Promise.resolve(null) : api.getRangeOperation(operationId)),
    [operationId, range.updated_at],
  );

  // The server's incremental log for this range.
  const events = useAsync(() => api.listRangeEvents(range.id), [range.id, range.updated_at]);

  const progress = useMemo(
    () => operationProgress(range.current_operation),
    [range.current_operation],
  );
  const outcome = operationOutcomeText(operation.data);
  const canDeploy = permittedActions(lifecycle).includes("deploy");

  const refreshAll = useCallback(async () => {
    await Promise.all([reloadRange(), operation.reload(), events.reload()]);
  }, [reloadRange, operation, events]);

  const deploy = () => action.run(() => api.deployRange(range.id), refreshAll);

  const recent = useMemo(
    () => [...(events.data ?? [])].sort((a, b) => b.sequence - a.sequence).slice(0, 12),
    [events.data],
  );

  return (
    <div className="rng">
      <CyberCard heading="Deployment" headingLevel={2}>
        {progress.kind === "none" ? (
          <EmptyState title="Not deployed yet">
            {RANGE_PHASE_HELP[lifecycle.phase]}
          </EmptyState>
        ) : (
          <>
            <div className="rng-meta">
              <StatusBadge
                state={range.current_operation?.status ?? "pending"}
                domain="range-operation"
              />
              <span>
                {OPERATION_KIND_LABEL[range.current_operation?.kind ?? ""] ?? "Operation"}
                {range.current_operation?.phase !== null &&
                range.current_operation?.phase !== undefined
                  ? ` · ${range.current_operation.phase}`
                  : ""}
              </span>
              <span className="muted">{progress.label}</span>
            </div>

            {progress.kind === "indeterminate" ? (
              // No numeric value: an indeterminate bar states "working, amount unknown". Giving it
              // aria-valuenow={0} would announce "0 percent" to a screen reader, which is the same
              // false claim as showing 0%.
              <div
                className="rng-meter rng-meter--indeterminate"
                role="progressbar"
                aria-label="Deployment progress"
                aria-valuetext="Waiting for the worker to plan the steps"
              >
                <div className="rng-meter-sweep" />
              </div>
            ) : (
              <div
                className="rng-meter"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={progress.percent ?? 0}
                aria-label="Deployment progress"
                style={{ ["--rng-progress" as string]: String((progress.percent ?? 0) / 100) }}
              >
                <div className="rng-meter-fill" />
              </div>
            )}

            {outcome !== null && (
              <SafetyNotice
                role="alert"
                tone={operation.data?.status === "unproven" ? "warn" : "danger"}
              >
                {outcome}
              </SafetyNotice>
            )}
            {operation.data?.status === "unproven" && (
              <SafetyNotice role="note" tone="warn">
                {UNPROVEN_NOTE}
              </SafetyNotice>
            )}

            {polling && (
              <p className="rng-live" role="status">
                <span className="rng-live-dot" aria-hidden="true" />
                An operation is in flight. This page is re-reading the recorded state until it
                settles.
              </p>
            )}
          </>
        )}

        {action.error !== null && (
          <ClosedCodeError
            error={action.error}
            codeText={RANGE_ERROR_TEXT}
            onDismiss={action.clearError}
          />
        )}

        <div className="rng-card-foot">
          {canDeploy && (
            <CyberButton variant="primary" disabled={action.busy} onClick={deploy}>
              {action.busy ? "Dispatching…" : "Deploy range"}
            </CyberButton>
          )}
          <CyberButton onClick={() => void refreshAll()} disabled={action.busy}>
            Refresh
          </CyberButton>
        </div>
      </CyberCard>

      <CyberCard heading="Operation steps" headingLevel={2}>
        <DataPanel
          state={operation}
          isEmpty={() => (operation.data?.steps.length ?? 0) === 0}
          empty={
            <EmptyState title="No steps planned yet">
              {/* The honest reading of total_steps: 0 while pending. */}
              The worker plans an operation&rsquo;s steps when it picks it up. Until then there is
              no plan to show — this is not an empty deployment.
            </EmptyState>
          }
        >
          {(op) => (
            <ol className="rng-steps">
              {op === null
                ? null
                : op.steps.map((step) => (
                    <li key={step.key} className={`rng-step rng-step--${step.status}`}>
                      <StatusBadge state={step.status} domain="range-operation" />
                      <span className="rng-step-name">{step.label}</span>
                      <span className="rng-step-note">
                        {step.detail ?? (step.at === null ? "" : step.at.slice(11, 19))}
                      </span>
                    </li>
                  ))}
            </ol>
          )}
        </DataPanel>
      </CyberCard>

      <CyberCard heading="Recent events" headingLevel={2}>
        <DataPanel
          state={events}
          isEmpty={() => recent.length === 0}
          empty={
            <EmptyState title="No events recorded for this range yet">
              The server appends an event for everything that happens to this range.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Recent range events"
              head={["#", "When", "Event", "Level"]}
              caption="The twelve most recent server-recorded events, newest first."
            >
              {recent.map((e) => (
                <tr key={e.id}>
                  <td className="muted mono">{e.sequence}</td>
                  <td className="muted mono">{e.occurred_at.slice(11, 19)}</td>
                  <td>{e.message}</td>
                  <td>
                    <StatusBadge state={e.level} domain="range-event" />
                  </td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <SafetyNotice role="note" tone="warn">
        {EXECUTION_POSTURE_NOTE}
      </SafetyNotice>
    </div>
  );
}
