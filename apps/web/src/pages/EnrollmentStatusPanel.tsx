// The enrollment status/evidence panel, shared by the two enrollment surfaces.
//
// It exists as one component rather than two because both pages show the SAME record: the
// worker-enrollment page shows the one an operator looked up by id, and the inventory page shows the
// one they selected from the organization list. Two copies of this markup would drift, and the
// half that drifted would be the half describing what a piece of evidence proves — which is the
// part that must not quietly become wrong.
//
// It is props-only: no fetching, no clock, no randomness and no hooks, so it renders under
// `renderToStaticMarkup` in the node test environment and behaves identically in a browser.

import type { ReactNode } from "react";

import type { EnrollmentStatus } from "../api/types";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  EvidenceBadge,
  KeyValueList,
  SafetyNotice,
  StatusBadge,
  StepRail,
} from "../components/ui";
import type { ClosedCodeCopy } from "../components/ui";
import {
  ENROLLMENT_ERROR_TEXT,
  EVIDENCE_NOTICE,
  RECOVER_CONFIRM_NOTICE,
  RECOVER_VS_REVOKE_NOTICE,
  REVOKE_CONFIRM_NOTICE,
  enrollmentEvidence,
  enrollmentStepItems,
  expiryView,
  recoveryView,
  statusDetailRows,
  type Gate,
} from "./worker-enrollment";

/**
 * A control plus the fixed reason it is unavailable. The reason is always rendered, so a disabled
 * affordance never leaves the operator guessing which permission or gate is missing.
 *
 * The reason carries a stable id so the control can point at it with `aria-describedby`. A
 * `disabled` button is out of the tab order and most screen readers will not announce its
 * description, which is exactly why the reason is ALSO adjacent visible text: it stays reachable in
 * browse mode and to sighted keyboard users who tab past the control. `disabled` is kept over
 * `aria-disabled` deliberately — these controls gate writes, and a control that cannot be clicked
 * at all is the safer failure.
 */
export function GatedAction({
  gate,
  reasonId,
  children,
}: {
  gate: { ok: boolean; reason?: string };
  reasonId: string;
  /** Receives the id to hang `aria-describedby` on, or undefined when there is no reason to
   *  describe. Passing it in rather than letting the caller decide is what guarantees the
   *  reference and the element it points at can only ever appear together. */
  children: (describedBy: string | undefined) => ReactNode;
}) {
  const showReason = !gate.ok && Boolean(gate.reason);
  return (
    <div className="wenr-actions">
      {children(showReason ? reasonId : undefined)}
      {showReason && (
        <p className="wenr-reason" id={reasonId} role="note">
          {gate.reason}
        </p>
      )}
    </div>
  );
}

/** An expiry as text, with the expired state carried by a word and not only by colour. */
export function Expiry({ at, nowMs }: { at: string; nowMs: number }) {
  const view = expiryView(at, nowMs);
  return (
    <span
      className={view.expired ? "wenr-expiry wenr-expiry--expired" : "wenr-expiry"}
    >
      {view.label}
    </span>
  );
}

export interface EnrollmentStatusPanelProps {
  status: EnrollmentStatus;
  /** Injected so expiry copy is deterministic in tests. */
  nowMs: number;
  heading?: string;
  revokeGate: Gate;
  revokeReasonId: string;
  revoking: boolean;
  onRevoke: () => void;
  revokeError: ClosedCodeCopy | null;

  /**
   * Operator-triggered recovery — the second and last operator write in the lifecycle. Optional so
   * a surface that does not offer it simply does not pass it; when it is absent the panel renders
   * no recovery control at all rather than a disabled one, because a control that is missing for
   * structural reasons should not look like one you lack permission for.
   */
  recoverGate?: Gate;
  recoverReasonId?: string;
  recovering?: boolean;
  onRecover?: () => void;
  recoverError?: ClosedCodeCopy | null;

  /** Extra read-only controls for the surface hosting the panel (e.g. re-read this record). Placed
   *  above the revoke block so a destructive control is never the first thing under the evidence. */
  actions?: ReactNode;
  /**
   * The level of the card title. The panel's own subheads follow at one level below it, so the
   * outline stays correct wherever the panel is mounted: a page that places it directly under its
   * `h1` passes 2 and gets h2/h3, and one that nests it under a section heading keeps the default.
   */
  headingLevel?: 2 | 3;
}

export function EnrollmentStatusPanel({
  status,
  nowMs,
  heading = "Enrollment status and evidence",
  revokeGate,
  revokeReasonId,
  revoking,
  onRevoke,
  revokeError,
  recoverGate,
  recoverReasonId,
  recovering = false,
  onRecover,
  recoverError = null,
  actions,
  headingLevel = 2,
}: EnrollmentStatusPanelProps) {
  // Both halves must be present for the control to be offered: a gate with no handler could not
  // act, and a handler with no gate would be an ungated write.
  const offersRecovery =
    recoverGate !== undefined && onRecover !== undefined && recoverReasonId !== undefined;
  const recovery = recoveryView(status.state, expiryView(status.expires_at, nowMs));
  // Derived, never passed separately: a subhead level that could disagree with the card level is
  // exactly how a heading skip gets reintroduced.
  const Subhead = (headingLevel === 2 ? "h3" : "h4") as "h3" | "h4";

  return (
    <CyberCard heading={heading} headingLevel={headingLevel}>
      <div className="wenr-status__head">
        <Subhead className="wenr-status__state">
          <span className="ui-sr-only">Lifecycle state: </span>
          <StatusBadge state={status.state} domain="enrollment" />
        </Subhead>
        <Expiry at={status.expires_at} nowMs={nowMs} />
      </div>

      {recovery.needed && (
        <section className="wenr-recovery" aria-labelledby="wenr-recovery-title">
          <SafetyNotice role="note" tone="warn">
            <strong id="wenr-recovery-title">{recovery.title}</strong>
            <p className="wenr-recovery__body">{recovery.body}</p>
            <ul className="wenr-recovery__steps">
              {recovery.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          </SafetyNotice>
        </section>
      )}

      <KeyValueList
        items={statusDetailRows(status).map((row) => ({
          key: row.key,
          value: row.value,
          mono: row.mono,
        }))}
      />

      <Subhead className="wenr-subhead">Evidence recorded so far</Subhead>
      <p className="wenr-reason">{EVIDENCE_NOTICE}</p>
      <div className="wenr-evidence">
        {enrollmentEvidence(status).map((item) => (
          <EvidenceBadge
            key={item.field}
            title={item.field}
            status={item.status}
            detail={
              <>
                <span className="wenr-evidence__label">{item.label}</span>
                <span className="wenr-evidence__proves">{item.proves}</span>
                <code className="wenr-evidence__value mono">{item.value}</code>
              </>
            }
          />
        ))}
      </div>

      <Subhead className="wenr-subhead">Lifecycle</Subhead>
      <div className="wenr-rail">
        <StepRail
          items={enrollmentStepItems(status.state)}
          aria-label="Enrollment lifecycle"
        />
      </div>

      {actions}

      <SafetyNotice role="note" tone="warn">
        {REVOKE_CONFIRM_NOTICE}
      </SafetyNotice>
      <GatedAction gate={revokeGate} reasonId={revokeReasonId}>
        {(describedBy) => (
          <CyberButton
            variant="danger"
            disabled={!revokeGate.ok}
            aria-describedby={describedBy}
            onClick={onRevoke}
          >
            {revoking ? "Revoking…" : "Revoke enrollment"}
          </CyberButton>
        )}
      </GatedAction>
      {revokeError && (
        <ClosedCodeError
          error={{ code: revokeError.code, message: "" }}
          codeText={ENROLLMENT_ERROR_TEXT}
        />
      )}

      {offersRecovery && (
        <>
          {/* Two permanent, unreversible writes sit next to each other here. Which one an operator
              wants is not obvious from the button labels alone, so the difference is stated once,
              between them, rather than left to be inferred. */}
          <SafetyNotice role="note" tone="warn">
            {RECOVER_VS_REVOKE_NOTICE}
          </SafetyNotice>
          <p className="wenr-reason">{RECOVER_CONFIRM_NOTICE}</p>
          <GatedAction gate={recoverGate} reasonId={recoverReasonId}>
            {(describedBy) => (
              <CyberButton
                variant="secondary"
                disabled={!recoverGate.ok}
                aria-describedby={describedBy}
                onClick={onRecover}
              >
                {recovering ? "Marking…" : "Mark for recovery"}
              </CyberButton>
            )}
          </GatedAction>
          {recoverError && (
            <ClosedCodeError
              error={{ code: recoverError.code, message: "" }}
              codeText={ENROLLMENT_ERROR_TEXT}
            />
          )}
        </>
      )}
    </CyberCard>
  );
}
