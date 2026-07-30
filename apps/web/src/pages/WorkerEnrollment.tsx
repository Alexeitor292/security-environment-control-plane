import "./worker-enrollment.css";

import { useState, type ReactNode } from "react";

import { api } from "../api/client";
import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  EmptyState,
  KeyValueList,
  SafetyNotice,
  StatusBadge,
  StepRail,
  useAction,
} from "../components/ui";
import type { ClosedCodeCopy } from "../components/ui";
import {
  ENROLLMENT_ERROR_TEXT,
  ENROLLMENT_ID_HINT,
  HANDOFF_BEARER_NOTICE,
  HANDOFF_ONE_TIME_NOTICE,
  HANDOFF_REVEAL_LABEL,
  MANAGE_WITHOUT_READ_NOTICE,
  NO_INVENTORY_NOTICE,
  RECENT_LIST_NOTICE,
  REVOKE_CONFIRM_NOTICE,
  SITE_LABEL_HINT,
  TTL_DEFAULT_SECONDS,
  TTL_HINT,
  TRUST_ANCHOR_NOTICE,
  ENROLLMENT_INTRO,
  WORKER_DRIVEN_NOTICE,
  addRecent,
  createGate,
  enrollmentStepItems,
  expiryView,
  handoffFields,
  handoffText,
  lookupGate,
  newIdempotencyKey,
  parseEnrollmentId,
  parseTtlSeconds,
  resolveEnrollmentPermissions,
  revokeGate,
  shouldWarnManageWithoutRead,
  statusDetailRows,
  validateSiteLabel,
  type EnrollmentPermissions,
  type RecentEnrollment,
} from "./worker-enrollment";

/** A control plus the fixed reason it is unavailable. The reason is always rendered, so a disabled
 *  affordance never leaves the operator guessing which permission or gate is missing. */
function GatedAction({
  gate,
  children,
}: {
  gate: { ok: boolean; reason?: string };
  children: ReactNode;
}) {
  return (
    <div className="wenr-actions">
      {children}
      {!gate.ok && gate.reason && <p className="wenr-reason">{gate.reason}</p>}
    </div>
  );
}

export interface WorkerEnrollmentViewProps {
  permissions: EnrollmentPermissions;

  // create
  siteLabel: string;
  onSiteLabelChange: (value: string) => void;
  ttlSeconds: string;
  onTtlSecondsChange: (value: string) => void;
  onCreate: () => void;
  creating: boolean;
  createError: ClosedCodeCopy | null;

  // hand-off
  invitation: EnrollmentInvitation | null;
  revealed: boolean;
  onReveal: () => void;
  onCopyHandoff: () => void;
  copyNotice: string | null;
  onDismissInvitation: () => void;

  // look-up
  lookupId: string;
  onLookupIdChange: (value: string) => void;
  onLookup: () => void;
  lookingUp: boolean;
  status: EnrollmentStatus | null;
  statusError: ClosedCodeCopy | null;

  // revoke
  onRevoke: () => void;
  revoking: boolean;
  revokeError: ClosedCodeCopy | null;

  recent: readonly RecentEnrollment[];
  /** Injected so expiry copy is deterministic in tests. */
  nowMs: number;
}

/**
 * Presentational worker-enrollment surface. Props only — no hooks, no data fetching, no clock and
 * no randomness — so it renders under `renderToStaticMarkup` in the node test environment.
 */
export function WorkerEnrollmentView({
  permissions,
  siteLabel,
  onSiteLabelChange,
  ttlSeconds,
  onTtlSecondsChange,
  onCreate,
  creating,
  createError,
  invitation,
  revealed,
  onReveal,
  onCopyHandoff,
  copyNotice,
  onDismissInvitation,
  lookupId,
  onLookupIdChange,
  onLookup,
  lookingUp,
  status,
  statusError,
  onRevoke,
  revoking,
  revokeError,
  recent,
  nowMs,
}: WorkerEnrollmentViewProps) {
  const site = validateSiteLabel(siteLabel);
  const ttl = parseTtlSeconds(ttlSeconds);
  const id = parseEnrollmentId(lookupId);
  const create = createGate(permissions, site, ttl, creating);
  const lookup = lookupGate(permissions, id, lookingUp);
  const revoke = revokeGate(permissions, status, revoking);

  return (
    <div className="wenr">
      <header className="wenr-head">
        <h1>Worker Enrollment</h1>
        <p className="wenr-intro">{ENROLLMENT_INTRO}</p>
      </header>

      <SafetyNotice role="note" tone="info">
        {WORKER_DRIVEN_NOTICE}
      </SafetyNotice>

      {shouldWarnManageWithoutRead(permissions) && (
        <SafetyNotice role="note" tone="warn">
          {MANAGE_WITHOUT_READ_NOTICE}
        </SafetyNotice>
      )}

      <div className="wenr-grid">
        <CyberCard heading="Create an invitation">
          <div className="wenr-form">
            <CyberInput
              label="Deployment site label"
              hint={SITE_LABEL_HINT}
              value={siteLabel}
              errorText={siteLabel !== "" && !site.ok ? site.error : undefined}
              onChange={(e) => onSiteLabelChange(e.target.value)}
            />
            <CyberInput
              label="Invitation lifetime (seconds)"
              hint={TTL_HINT}
              inputMode="numeric"
              value={ttlSeconds}
              errorText={ttlSeconds !== "" && !ttl.ok ? ttl.error : undefined}
              onChange={(e) => onTtlSecondsChange(e.target.value)}
            />
            <GatedAction gate={create}>
              <CyberButton disabled={!create.ok} onClick={onCreate}>
                {creating ? "Creating…" : "Create invitation"}
              </CyberButton>
            </GatedAction>
            {createError && (
              <ClosedCodeError
                error={{ code: createError.code, message: "" }}
                codeText={ENROLLMENT_ERROR_TEXT}
              />
            )}
          </div>
        </CyberCard>

        <CyberCard heading="Look up an enrollment">
          <div className="wenr-form">
            <CyberInput
              label="Enrollment id"
              hint={ENROLLMENT_ID_HINT}
              mono
              value={lookupId}
              errorText={lookupId !== "" && !id.ok ? id.error : undefined}
              onChange={(e) => onLookupIdChange(e.target.value)}
            />
            <GatedAction gate={lookup}>
              <CyberButton
                variant="secondary"
                disabled={!lookup.ok}
                onClick={onLookup}
              >
                {lookingUp ? "Loading…" : "Look up status"}
              </CyberButton>
            </GatedAction>
            <p className="wenr-reason">{NO_INVENTORY_NOTICE}</p>
            {statusError && (
              <ClosedCodeError
                error={{ code: statusError.code, message: "" }}
                codeText={ENROLLMENT_ERROR_TEXT}
              />
            )}
          </div>
        </CyberCard>
      </div>

      {invitation && (
        <CyberCard heading="Hand this to the worker" glow="danger">
          <div className="wenr-handoff">
            <SafetyNotice role="alert" tone="danger">
              {HANDOFF_BEARER_NOTICE}
            </SafetyNotice>
            <SafetyNotice role="note" tone="warn">
              {HANDOFF_ONE_TIME_NOTICE}
            </SafetyNotice>

            <div className="wenr-handoff__meta">
              <span>
                Site: <strong>{invitation.deployment_site_label}</strong>
              </span>
              <span
                className={
                  expiryView(invitation.expires_at, nowMs).expired
                    ? "wenr-expiry wenr-expiry--expired"
                    : "wenr-expiry"
                }
              >
                {expiryView(invitation.expires_at, nowMs).label}
              </span>
            </div>

            {revealed ? (
              <>
                <pre className="wenr-handoff__block">{handoffText(invitation)}</pre>
                <KeyValueList
                  items={handoffFields(invitation).map((f) => ({
                    key: f.label,
                    value: f.value,
                    mono: true,
                  }))}
                />
                <p className="wenr-reason">{TRUST_ANCHOR_NOTICE}</p>
                <KeyValueList
                  items={[
                    {
                      key: "Controller trust anchor",
                      value: invitation.controller_trust_anchor_hex,
                      mono: true,
                    },
                  ]}
                />
                <div className="wenr-actions">
                  <CyberButton variant="secondary" onClick={onCopyHandoff}>
                    Copy hand-off block
                  </CyberButton>
                  <CyberButton variant="ghost" onClick={onDismissInvitation}>
                    Done — hide it
                  </CyberButton>
                  {copyNotice && (
                    <p className="wenr-reason" role="status">
                      {copyNotice}
                    </p>
                  )}
                </div>
              </>
            ) : (
              <div className="wenr-actions">
                <CyberButton onClick={onReveal}>{HANDOFF_REVEAL_LABEL}</CyberButton>
              </div>
            )}
          </div>
        </CyberCard>
      )}

      {status && (
        <CyberCard heading="Enrollment status">
          <div className="wenr-status__head">
            <h3>
              <StatusBadge state={status.state} domain="enrollment" />
            </h3>
            <span
              className={
                expiryView(status.expires_at, nowMs).expired
                  ? "wenr-expiry wenr-expiry--expired"
                  : "wenr-expiry"
              }
            >
              {expiryView(status.expires_at, nowMs).label}
            </span>
          </div>

          <KeyValueList
            items={statusDetailRows(status).map((row) => ({
              key: row.key,
              value: row.value,
              mono: row.mono,
            }))}
          />

          <div className="wenr-rail">
            <StepRail
              items={enrollmentStepItems(status.state)}
              aria-label="Enrollment lifecycle"
            />
          </div>

          <SafetyNotice role="note" tone="warn">
            {REVOKE_CONFIRM_NOTICE}
          </SafetyNotice>
          <GatedAction gate={revoke}>
            <CyberButton
              variant="danger"
              disabled={!revoke.ok}
              onClick={onRevoke}
            >
              {revoking ? "Revoking…" : "Revoke enrollment"}
            </CyberButton>
          </GatedAction>
          {revokeError && (
            <ClosedCodeError
              error={{ code: revokeError.code, message: "" }}
              codeText={ENROLLMENT_ERROR_TEXT}
            />
          )}
        </CyberCard>
      )}

      <CyberCard heading="Created in this tab">
        <p className="wenr-reason">{RECENT_LIST_NOTICE}</p>
        {recent.length === 0 ? (
          <EmptyState title="Nothing created in this tab yet" />
        ) : (
          <ul className="wenr-recent">
            {recent.map((entry) => (
              <li className="wenr-recent__item" key={entry.enrollmentId}>
                <span className="mono">{entry.enrollmentId}</span>
                <span className="wenr-recent__site">
                  {entry.siteLabel} · {expiryView(entry.expiresAt, nowMs).label}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CyberCard>
    </div>
  );
}

/**
 * Container: owns state and the three supported calls. Everything it remembers lives in React
 * state for the life of this component — the invitation material is never written to any storage,
 * never placed in the URL, and never logged.
 */
export function WorkerEnrollment() {
  const { principal } = useAuth();
  const permissions = resolveEnrollmentPermissions(principal?.permissions);

  const [siteLabel, setSiteLabel] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState(String(TTL_DEFAULT_SECONDS));
  const [invitation, setInvitation] = useState<EnrollmentInvitation | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const [lookupId, setLookupId] = useState("");
  const [status, setStatus] = useState<EnrollmentStatus | null>(null);
  const [recent, setRecent] = useState<readonly RecentEnrollment[]>([]);

  const createAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });
  const lookupAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });
  const revokeAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });

  const onCreate = () => {
    const site = validateSiteLabel(siteLabel);
    const ttl = parseTtlSeconds(ttlSeconds);
    if (!site.ok || !ttl.ok) return;
    void createAction.run(async () => {
      const created = await api.createEnrollmentInvitation({
        // Generated per attempt, never typed. A retry of a failed create is a NEW request rather
        // than a replay of the previous key, so it can never collide with different bound input.
        idempotency_key: newIdempotencyKey(),
        deployment_site_label: site.value,
        ttl_seconds: ttl.value,
      });
      setInvitation(created);
      // Deliberately closed: the operator opts in to seeing bearer-grade material.
      setRevealed(false);
      setCopyNotice(null);
      setRecent((list) =>
        addRecent(list, {
          enrollmentId: created.enrollment_id,
          siteLabel: created.deployment_site_label,
          createdAt: created.created_at,
          expiresAt: created.expires_at,
        }),
      );
    });
  };

  const onLookup = () => {
    const id = parseEnrollmentId(lookupId);
    if (!id.ok) return;
    void lookupAction.run(async () => {
      setStatus(await api.getEnrollmentStatus(id.value));
    });
  };

  const onRevoke = () => {
    if (status === null) return;
    // The revision always comes from the status we actually observed — never from user input.
    const observed = status;
    void revokeAction.run(async () => {
      setStatus(await api.revokeEnrollment(observed.enrollment_id, observed.revision));
    });
  };

  const onCopyHandoff = () => {
    if (!invitation) return;
    const text = handoffText(invitation);
    const clipboard = navigator.clipboard;
    if (!clipboard) {
      setCopyNotice("Copying is unavailable here — select the block above instead.");
      return;
    }
    void clipboard.writeText(text).then(
      () => setCopyNotice("Copied. Deliver it to one worker, then clear your clipboard."),
      () =>
        setCopyNotice("Copying was refused — select the block above instead."),
    );
  };

  return (
    <WorkerEnrollmentView
      permissions={permissions}
      siteLabel={siteLabel}
      onSiteLabelChange={setSiteLabel}
      ttlSeconds={ttlSeconds}
      onTtlSecondsChange={setTtlSeconds}
      onCreate={onCreate}
      creating={createAction.busy}
      createError={createAction.error}
      invitation={invitation}
      revealed={revealed}
      onReveal={() => setRevealed(true)}
      onCopyHandoff={onCopyHandoff}
      copyNotice={copyNotice}
      onDismissInvitation={() => {
        setInvitation(null);
        setRevealed(false);
        setCopyNotice(null);
      }}
      lookupId={lookupId}
      onLookupIdChange={setLookupId}
      onLookup={onLookup}
      lookingUp={lookupAction.busy}
      status={status}
      statusError={lookupAction.error}
      onRevoke={onRevoke}
      revoking={revokeAction.busy}
      revokeError={revokeAction.error}
      recent={recent}
      nowMs={Date.now()}
    />
  );
}
