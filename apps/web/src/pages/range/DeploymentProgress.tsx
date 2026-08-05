import "./range.css";

import { useCallback } from "react";

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
import {
  DEPLOYMENT_STEPS,
  RANGE_PHASE_HELP,
  RANGE_PHASE_LABEL,
  deploymentProgress,
  deploymentStepStatus,
} from "./range-lifecycle";
import {
  DEPLOY_IS_GATED_NOTE,
  EXECUTION_POSTURE_NOTE,
  GATE_LABEL,
  RANGE_ERROR_TEXT,
  deployGate,
  timelineEntries,
} from "./range-view";
import { onlyNotFoundAsNull } from "../environments-view";

/**
 * Page 3 — Deployment Progress.
 *
 * The step rail and the meter are computed from the range's RECORDED lifecycle state, which the
 * layout re-reads from the server every couple of seconds while an operation is in flight. Nothing
 * here animates expected progress: if the server does not advance, neither does the rail.
 *
 * The page also walks the approval gate, because on this control plane a range cannot be deployed
 * until its plan has been generated, submitted and approved. Exactly one next action is offered at
 * a time, and it is derived from the recorded state rather than from what the operator last
 * clicked.
 */
export function DeploymentProgress() {
  const { range, lifecycle, reloadRange, polling } = useRange();
  const action = useAction({ codeText: RANGE_ERROR_TEXT });

  // A plan may legitimately not exist yet. Only a 404 means "no plan"; every other failure must
  // surface as an error rather than as a false claim of absence.
  const plan = useAsync(
    () => api.latestPlan(range.id).catch(onlyNotFoundAsNull),
    [range.id, range.lifecycle_state],
  );

  // The recent recorded events for this range — the evidence that the phase changes above came
  // from the backend and not from the client.
  const events = useAsync(
    () => api.audit(range.id),
    [range.id, range.lifecycle_state],
  );

  const gate = deployGate(range, plan.data ?? null);
  const progress = deploymentProgress(lifecycle);

  const refreshAll = useCallback(async () => {
    await Promise.all([reloadRange(), plan.reload(), events.reload()]);
  }, [reloadRange, plan, events]);

  const runGateAction = () => {
    const call = {
      validate: () => api.validateExercise(range.id),
      "generate-plan": () => api.generatePlan(range.id),
      "submit-plan": async () => {
        const p = plan.data ?? (await api.latestPlan(range.id));
        return api.submitPlan(p.id);
      },
      "approve-plan": async () => {
        const p = plan.data ?? (await api.latestPlan(range.id));
        return api.approvePlan(p.id, "Approved from the range deployment page.");
      },
      deploy: () => api.deployExercise(range.id),
      none: async () => undefined,
    }[gate.next];
    return action.run(call, refreshAll);
  };

  const recent = events.data ? timelineEntries(events.data).slice(0, 8) : [];

  return (
    <div className="rng">
      <CyberCard heading="Deployment" headingLevel={2}>
        <div
          className="rng-meter"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(progress * 100)}
          aria-label="Deployment progress"
          style={{ ["--rng-progress" as string]: String(progress) }}
        >
          <div className="rng-meter-fill" />
        </div>

        <ol className="rng-steps">
          {DEPLOYMENT_STEPS.map((step) => {
            const status = deploymentStepStatus(step, lifecycle);
            return (
              <li key={step} className={`rng-step rng-step--${status}`}>
                <StatusBadge state={step} domain="range" />
                <span className="rng-step-name">{RANGE_PHASE_LABEL[step]}</span>
                <span className="rng-step-note">
                  {status === "failed"
                    ? "This step failed. Inspect the events below."
                    : status === "current"
                      ? "In progress — waiting on the server."
                      : status === "done"
                        ? "Complete."
                        : RANGE_PHASE_HELP[step]}
                </span>
              </li>
            );
          })}
        </ol>

        {polling && (
          <p className="rng-live" role="status">
            <span className="rng-live-dot" aria-hidden="true" />
            The server is mid-operation. This page is re-reading the recorded state until it
            settles.
          </p>
        )}
      </CyberCard>

      <CyberCard heading="Approval gate" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {DEPLOY_IS_GATED_NOTE}
        </SafetyNotice>

        {gate.next === "none" ? (
          <EmptyState
            title={
              gate.blockedReason === null
                ? "Deployment complete"
                : "No deployment action available"
            }
          >
            {gate.blockedReason ?? RANGE_PHASE_HELP[lifecycle.phase]}
          </EmptyState>
        ) : (
          <>
            <ol className="rng-steps">
              {(["validate", "generate-plan", "submit-plan", "approve-plan", "deploy"] as const).map(
                (step) => {
                  const done = gate.completed.includes(step);
                  const current = gate.next === step;
                  return (
                    <li
                      key={step}
                      className={`rng-step ${current ? "rng-step--current" : done ? "rng-step--done" : ""}`}
                    >
                      <span className="rng-step-name">{GATE_LABEL[step]}</span>
                      <span className="rng-step-note">
                        {done ? "Complete." : current ? gate.help : "Not reached."}
                      </span>
                    </li>
                  );
                },
              )}
            </ol>

            {action.error !== null && (
              <ClosedCodeError
                error={action.error}
                codeText={RANGE_ERROR_TEXT}
                onDismiss={action.clearError}
              />
            )}

            <div className="rng-card-foot">
              <CyberButton
                variant="primary"
                disabled={action.busy || !lifecycle.known}
                onClick={runGateAction}
              >
                {action.busy ? "Working…" : gate.label}
              </CyberButton>
              <CyberButton onClick={() => void refreshAll()} disabled={action.busy}>
                Refresh
              </CyberButton>
            </div>
          </>
        )}
      </CyberCard>

      <CyberCard heading="Recent recorded events" headingLevel={2}>
        <DataPanel
          state={events}
          isEmpty={() => recent.length === 0}
          empty={
            <EmptyState title="No events recorded for this range yet">
              The ledger records every mutation and authorization decision. Nothing has been
              recorded against this range so far.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Recent range events"
              head={["When", "Action", "Outcome", "Actor"]}
              caption="The eight most recent recorded events. This is the server's ledger — no client-side entries."
            >
              {recent.map((e) => (
                <tr key={e.id}>
                  <td className="muted mono">{e.at.slice(0, 19).replace("T", " ")}</td>
                  <td className="mono">{e.action}</td>
                  <td>
                    <StatusBadge state={e.outcome} domain="audit" />
                  </td>
                  <td className="muted">{e.actor}</td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <SafetyNotice role="note" tone="info">
        {EXECUTION_POSTURE_NOTE}
      </SafetyNotice>
    </div>
  );
}
