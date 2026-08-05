import "../range.css";
import "./proxmox.css";

import { CyberTable, KeyValueList, MetricTile, SafetyNotice } from "../../../components/ui";
import { ProxmoxSection } from "./ProxmoxSection";
import { SourcedPanel } from "./SourcedPanel";
import { reconcileFixture, resetPlanFixture, verificationFixture } from "./proxmox-fixtures";
import {
  CHECK_STATUS_LABEL,
  CHECK_STATUS_TONE,
  RECONCILE_ACTION_LABEL,
  RECONCILE_ACTION_TONE,
  RESET_DISPOSITION_TONE,
  SCORES_ARE_SERVER_SIDE_NOTE,
  UNPROVEN_IS_NOT_CLEAN_NOTE,
  VERIFICATION_OUTCOME_HELP,
  VERIFICATION_OUTCOME_LABEL,
  VERIFICATION_OUTCOME_TONE,
  checkStatus,
  humanize,
  verificationSummary,
} from "./proxmox-view";

/**
 * Network verification, reconciliation and reset.
 *
 * OFFLINE. `proxmox_verification.verify_deployment` and `proxmox_reconcile.decide_reconciliation`
 * run on the worker against the cluster; no endpoint serves their output.
 *
 * This is the page where collapsing three outcomes into two does the most damage, so the example
 * deliberately shows the amber case: eleven checks observed and passed, four isolation checks that
 * could not be run at all, and an outcome of `recovery_required`. A renderer that reads only `ok`
 * would paint those four red and report "isolation failed" — a finding nobody made. One that reads
 * only the outcome's neighbours would round it to verified. Both are wrong in the same way.
 */
export function ProxmoxVerification() {
  const report = verificationFixture.value;
  const summary = verificationSummary(report);
  const reset = resetPlanFixture.value;

  const outcomeTone = VERIFICATION_OUTCOME_TONE[summary.outcome];

  return (
    <div className="rng">
      <ProxmoxSection>
      <div className="rng-grid">
        <div className={`ui-metric ui-metric--${outcomeTone === "ok" ? "ok" : outcomeTone === "danger" ? "danger" : "warn"}`}>
          <div className="ui-metric__label">Verification outcome</div>
          <div className="ui-metric__value">{VERIFICATION_OUTCOME_LABEL[summary.outcome]}</div>
          <div className="ui-metric__detail">{VERIFICATION_OUTCOME_HELP[summary.outcome]}</div>
        </div>
        <MetricTile
          label="Checks observed and passed"
          value={summary.passed}
          detail="Observed by the worker against the cluster"
          tone={summary.passed > 0 ? "ok" : "default"}
        />
        <MetricTile
          label="Checks not observed"
          value={summary.notObserved}
          detail="Could not be run. Neither passed nor failed."
          tone={summary.notObserved > 0 ? "warn" : "default"}
        />
        <MetricTile
          label="Checks failed"
          value={summary.failed}
          detail="Observed and did not pass"
          tone={summary.failed > 0 ? "danger" : "default"}
        />
      </div>

      {summary.isolationNotObserved.length > 0 && (
        <SafetyNotice role="alert" tone="warn">
          {summary.isolationNotObserved.length} segmentation check
          {summary.isolationNotObserved.length === 1 ? " was" : "s were"} not observed:{" "}
          {summary.isolationNotObserved.map(humanize).join(", ")}. Isolation is therefore UNPROVEN
          for this deployment. That is not a finding that isolation failed, and it is not evidence
          that it holds — nobody looked. Treat the range as unsegregated until a probe runs.
        </SafetyNotice>
      )}

      <SourcedPanel
        heading="Verification checks"
        record={verificationFixture}
        intro="Each check reports two independent facts: whether it could be OBSERVED, and whether it passed. A check that was not observed carries no pass/fail meaning at all."
        render={(r) => (
          <CyberTable
            label="Verification checks"
            head={["Check", "Result", "Detail"]}
            caption={`${r.findings.length} checks · "not observed" is a third result, never rendered as either neighbour`}
          >
            {r.findings.map((f) => {
              const status = checkStatus(f);
              return (
                <tr key={f.check} className={status === "not_observed" ? "pmx-row-unproven" : undefined}>
                  <td className="mono">{humanize(f.check)}</td>
                  <td>
                    <span className={`badge ${CHECK_STATUS_TONE[status]}`}>
                      {CHECK_STATUS_LABEL[status]}
                    </span>
                  </td>
                  <td className={status === "not_observed" ? "pmx-unproven" : "muted"}>{f.detail}</td>
                </tr>
              );
            })}
          </CyberTable>
        )}
      />

      <SourcedPanel
        heading="Recovery and reconciliation"
        record={reconcileFixture}
        intro="What the worker decided to do next given the verification outcome. Halting to ask a human is a correct decision, not a failure."
        render={(d) => (
          <>
            <KeyValueList
              items={[
                {
                  key: "Action",
                  value: (
                    <span className={`badge ${RECONCILE_ACTION_TONE[d.action]}`}>
                      {RECONCILE_ACTION_LABEL[d.action]}
                    </span>
                  ),
                },
                {
                  key: "Outcome",
                  value: (
                    <span className={`badge ${VERIFICATION_OUTCOME_TONE[d.outcome]}`}>
                      {VERIFICATION_OUTCOME_LABEL[d.outcome]}
                    </span>
                  ),
                },
                { key: "Reason", value: d.reason, mono: true },
                { key: "Detail", value: d.detail },
                {
                  key: "Guests to create on resume",
                  value: d.create_vmids.length === 0 ? "none" : d.create_vmids.join(", "),
                  mono: true,
                },
              ]}
            />
            <SafetyNotice role="note" tone="warn">
              {UNPROVEN_IS_NOT_CLEAN_NOTE}
            </SafetyNotice>
          </>
        )}
      />

      <SourcedPanel
        heading="Reset plan"
        record={resetPlanFixture}
        intro={`Operation generation ${reset.operation_generation} · topology fingerprint pinned. A reset advances the operation generation and reuses the sealed allocation ledger, so a range keeps its addresses across resets.`}
        render={(p) => (
          <>
            <CyberTable
              label="Reset actions"
              head={["Subject", "Disposition", "Detail"]}
              caption={`${p.actions.length} subjects · ${p.recreated_guest_refs.length} guests recreated: ${p.recreated_guest_refs.join(", ")}`}
            >
              {p.actions.map((a) => (
                <tr key={a.subject}>
                  <td className="mono">{humanize(a.subject)}</td>
                  <td>
                    <span className={`badge ${RESET_DISPOSITION_TONE[a.disposition]}`}>
                      {a.disposition}
                    </span>
                  </td>
                  <td className="muted">{a.detail}</td>
                </tr>
              ))}
            </CyberTable>
            <SafetyNotice role="note" tone="info">
              {SCORES_ARE_SERVER_SIDE_NOTE}
            </SafetyNotice>
          </>
        )}
      />
      </ProxmoxSection>
    </div>
  );
}
