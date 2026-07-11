import { useState } from "react";

import type {
  TopologyDocumentDetail,
  TopologyRevisionSummary,
  TopologyValidationResult,
} from "../api/types";
import {
  CyberButton,
  CyberCard,
  CyberInput,
  CyberTable,
  EmptyState,
  EvidenceBadge,
  HashChip,
  KeyValueList,
  SafetyNotice,
  shortId,
} from "../components/ui";
import type { ClosedCodeCopy } from "../components/ui/closed-code-error";
import {
  DECISION_NOTE,
  SAVE_REVISION_NOTE,
  SUBMIT_NOTE,
  VALIDATE_NOTE,
  type ConflictInfo,
  type ControlEligibility,
  type ValidationView,
  type WorkspacePosture,
  conflictInfo,
  postureLabel,
  postureNote,
  revisionRows,
  revisionStatusLabel,
} from "./topology-persistence";

const VALIDATION_BADGE: Record<
  ValidationView["display"],
  "pass" | "fail" | "unverifiable" | "pending"
> = {
  "not-run": "pending",
  valid: "pass",
  valid_with_warnings: "unverifiable",
  invalid: "fail",
  unverifiable: "unverifiable",
  stale: "pending",
};

export interface PersistenceActions {
  save: ControlEligibility;
  validate: ControlEligibility;
  submit: ControlEligibility;
  approve: ControlEligibility;
  reject: ControlEligibility;
}

export interface PersistencePanelProps {
  posture: WorkspacePosture;
  document: TopologyDocumentDetail;
  revisions: TopologyRevisionSummary[] | null;
  validation: ValidationView;
  validationResult: TopologyValidationResult | null;
  baseRevisionNumber: number | null;
  baseHash: string | null;
  actions: PersistenceActions;
  busy: boolean;
  error: ClosedCodeCopy | null;
  onSave: (changeNote: string) => void;
  onValidate: () => void;
  onSubmit: () => void;
  onApprove: (reason: string) => void;
  onReject: (reason: string) => void;
  onReload: () => void;
  onLoadRevision: (revisionId: string) => void;
  onDiscardAndLoadLatest: () => void;
  viewingRevisionId: string | null;
}

function ControlButton({
  eligibility,
  busy,
  variant,
  onClick,
  children,
  title,
}: {
  eligibility: ControlEligibility;
  busy: boolean;
  variant?: "secondary" | "ok" | "danger";
  onClick: () => void;
  children: React.ReactNode;
  title: string;
}) {
  return (
    <CyberButton
      variant={variant ?? "secondary"}
      size="sm"
      disabled={busy || !eligibility.eligible}
      title={eligibility.eligible ? title : (eligibility.reason ?? title)}
      onClick={onClick}
    >
      {children}
    </CyberButton>
  );
}

export function TopologyPersistencePanel(props: PersistencePanelProps) {
  const {
    posture,
    document,
    revisions,
    validation,
    baseRevisionNumber,
    baseHash,
    actions,
    busy,
    error,
    onSave,
    onValidate,
    onSubmit,
    onApprove,
    onReject,
    onReload,
    onLoadRevision,
    onDiscardAndLoadLatest,
    viewingRevisionId,
  } = props;

  const [changeNote, setChangeNote] = useState("");
  const [decisionReason, setDecisionReason] = useState("");
  const rev = document.current_revision;
  const conflict: ConflictInfo = conflictInfo(baseRevisionNumber, baseHash, document);
  const decidable = actions.approve.eligible || actions.reject.eligible;

  return (
    <div className="tw-persist" id="tw-persist">
      <CyberCard heading="Durable topology revision">
        <div className="tw-persist-head">
          <span className={`tw-posture tw-posture--${posture}`}>{postureLabel(posture)}</span>
          {rev && (
            <span className="env-hashline">
              revision {rev.revision_number} ·{" "}
              <HashChip value={rev.content_hash} digits={12} /> ·{" "}
              {revisionStatusLabel(rev.status)}
            </span>
          )}
        </div>
        {postureNote(posture) && <p className="tw-note">{postureNote(posture)}</p>}

        {error && (
          <div className="error-box" role="alert">
            {error.text} <code className="mono">{error.code}</code>
          </div>
        )}

        {posture === "stale-base" && (
          <SafetyNotice role="status" tone="warn">
            <div className="tw-conflict">
              <div>
                Your local base: revision {conflict.localRevisionNumber ?? "—"}
                {conflict.localBaseHash && (
                  <>
                    {" "}
                    (<HashChip value={conflict.localBaseHash} digits={10} />)
                  </>
                )}
              </div>
              <div>
                Current server: revision {conflict.serverRevisionNumber ?? "—"}
                {conflict.serverHash && (
                  <>
                    {" "}
                    (<HashChip value={conflict.serverHash} digits={10} />)
                  </>
                )}
              </div>
              <div className="tw-conflict-actions">
                <CyberButton variant="secondary" size="sm" disabled={busy} onClick={onReload}>
                  Review latest revision
                </CyberButton>
                <CyberButton
                  variant="danger"
                  size="sm"
                  disabled={busy}
                  title="Discards your local draft and loads the current server revision. Changes are never merged."
                  onClick={onDiscardAndLoadLatest}
                >
                  Discard local draft & load latest
                </CyberButton>
              </div>
            </div>
          </SafetyNotice>
        )}

        <div className="tw-persist-actions">
          <span className="tw-persist-field">
            <CyberInput
              label="Change note (optional)"
              value={changeNote}
              onChange={(e) => setChangeNote(e.target.value)}
              placeholder="what changed in this revision"
              disabled={!actions.save.eligible || busy}
            />
          </span>
          <ControlButton
            eligibility={actions.save}
            busy={busy}
            variant="ok"
            title={SAVE_REVISION_NOTE}
            onClick={() => onSave(changeNote)}
          >
            Save new revision
          </ControlButton>
          <ControlButton
            eligibility={actions.validate}
            busy={busy}
            title={VALIDATE_NOTE}
            onClick={onValidate}
          >
            Validate revision
          </ControlButton>
          <ControlButton
            eligibility={actions.submit}
            busy={busy}
            title={SUBMIT_NOTE}
            onClick={onSubmit}
          >
            Submit for review
          </ControlButton>
          <CyberButton variant="secondary" size="sm" disabled={busy} onClick={onReload}>
            Reload authoritative
          </CyberButton>
        </div>
        {/* Disabled controls set the native `disabled` attribute (unfocusable),
            so their title is not announced. Surface the reasons visibly here so
            keyboard/screen-reader users know why an action is unavailable. */}
        {(() => {
          const reasons: string[] = [];
          if (!actions.save.eligible && actions.save.reason)
            reasons.push(`Save: ${actions.save.reason}`);
          if (!actions.validate.eligible && actions.validate.reason)
            reasons.push(`Validate: ${actions.validate.reason}`);
          if (!actions.submit.eligible && actions.submit.reason)
            reasons.push(`Submit: ${actions.submit.reason}`);
          return reasons.length > 0 ? (
            <ul className="tw-reasons" aria-label="Why some actions are unavailable">
              {reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          ) : null;
        })()}
        <p className="tw-note">{SAVE_REVISION_NOTE}</p>
      </CyberCard>

      <div className="tw-persist-grid">
        <CyberCard surface="well" heading="Validation">
          <EvidenceBadge title={validation.label} status={VALIDATION_BADGE[validation.display]} />
          {validation.findings.length > 0 && (
            <ul className="env-validation-list env-validation-list--errors">
              {validation.findings.map((f, i) => (
                <li key={i} className={f.severity === "warning" ? "tw-warn" : undefined}>
                  {f.code}
                  {f.nodeId ? ` · ${f.nodeId}` : f.edgeId ? ` · ${f.edgeId}` : ""}
                </li>
              ))}
            </ul>
          )}
          <p className="tw-note">{VALIDATE_NOTE}</p>
        </CyberCard>

        <CyberCard
          surface="well"
          heading="Review decision"
        >
          {rev && rev.status === "submitted" ? (
            <>
              <KeyValueList
                items={[
                  { key: "Revision", value: String(rev.revision_number) },
                  { key: "Hash", value: <HashChip value={rev.content_hash} digits={12} /> },
                  { key: "Status", value: revisionStatusLabel(rev.status) },
                ]}
              />
              {decidable && (
                <>
                  <CyberInput
                    label="Decision reason (optional)"
                    value={decisionReason}
                    onChange={(e) => setDecisionReason(e.target.value)}
                    placeholder="recorded with the decision"
                    disabled={busy}
                  />
                  <div className="tw-persist-actions">
                    <ControlButton
                      eligibility={actions.approve}
                      busy={busy}
                      variant="ok"
                      title={DECISION_NOTE}
                      onClick={() => onApprove(decisionReason)}
                    >
                      Approve revision
                    </ControlButton>
                    <ControlButton
                      eligibility={actions.reject}
                      busy={busy}
                      variant="danger"
                      title="Records a rejection for this revision."
                      onClick={() => onReject(decisionReason)}
                    >
                      Reject revision
                    </ControlButton>
                  </div>
                </>
              )}
              <p className="tw-note">{DECISION_NOTE}</p>
            </>
          ) : rev && (rev.status === "approved" || rev.status === "rejected") ? (
            <KeyValueList
              items={[
                { key: "Decision", value: revisionStatusLabel(rev.status) },
                { key: "Revision", value: String(rev.revision_number) },
                { key: "Decided by", value: rev.decided_by ? shortId(rev.decided_by) : "—", mono: rev.decided_by !== null },
                { key: "Decided at", value: rev.decided_at ? rev.decided_at.slice(0, 19).replace("T", " ") + " UTC" : "—", mono: rev.decided_at !== null },
              ]}
            />
          ) : (
            <EmptyState title="No submitted revision">
              A revision must be validated and submitted before it can be
              approved or rejected. {DECISION_NOTE}
            </EmptyState>
          )}
        </CyberCard>
      </div>

      <CyberCard heading="Revision history">
        {revisions === null ? (
          <p className="muted">Revision history unavailable.</p>
        ) : revisions.length === 0 ? (
          <EmptyState title="No revisions" />
        ) : (
          <CyberTable
            label="Topology revisions"
            head={["Revision", "Hash", "Status", "Change note", "Author", "Created", ""]}
            caption={`${revisions.length} immutable revision${revisions.length === 1 ? "" : "s"} — newest first`}
          >
            {revisionRows(revisions, document.current_revision_id).map((r) => (
              <tr key={r.id} className={r.id === viewingRevisionId ? "tw-rev--viewing" : undefined}>
                <td className="mono">
                  v{r.revisionNumber}
                  {r.isCurrent ? " · current" : ""}
                </td>
                <td>
                  <HashChip value={r.contentHash} digits={12} />
                </td>
                <td>{revisionStatusLabel(r.status)}</td>
                <td className="muted">{r.changeNote || "—"}</td>
                <td className="muted mono" title={r.createdBy ?? undefined}>
                  {r.createdBy ? shortId(r.createdBy) : "—"}
                </td>
                <td className="muted mono">{r.createdAt.slice(0, 10)}</td>
                <td>
                  {!r.isCurrent && (
                    <CyberButton
                      variant="secondary"
                      size="sm"
                      disabled={busy}
                      title="Loads this historical revision read-only."
                      onClick={() => onLoadRevision(r.id)}
                    >
                      View
                    </CyberButton>
                  )}
                </td>
              </tr>
            ))}
          </CyberTable>
        )}
        <p className="tw-note">
          Historical revisions load read-only. Editing from history requires
          loading the current revision first — revisions are never overwritten.
        </p>
      </CyberCard>
    </div>
  );
}
