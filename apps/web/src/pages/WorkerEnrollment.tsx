import "./worker-enrollment.css";

import { useEffect, useState } from "react";

import { api } from "../api/client";
import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberTable,
  EmptyState,
  HashChip,
  KeyValueList,
  MetricTile,
  SafetyNotice,
  StatusBadge,
  TabRail,
  tabId,
  tabPanelId,
  useAction,
} from "../components/ui";
import type { ClosedCodeCopy } from "../components/ui";
import { Expiry, GatedAction, EnrollmentStatusPanel } from "./EnrollmentStatusPanel";
import {
  CONTROLS_NOTICE,
  ENROLLMENT_CONTROLS,
  ENROLLMENT_ERROR_TEXT,
  ENROLLMENT_ID_HINT,
  HANDOFF_BEARER_NOTICE,
  HANDOFF_FILE_NOTICE,
  HANDOFF_ONE_TIME_NOTICE,
  HANDOFF_REVEAL_LABEL,
  INVITATION_CLEARED_NOTICE,
  MANAGE_WITHOUT_READ_NOTICE,
  NO_INVENTORY_NOTICE,
  PAST_EXPIRY_NOTICE,
  SITE_LABEL_HINT,
  TRACKED_FILTERS,
  TRACKED_FILTER_LABELS,
  TRACKED_LIST_NOTICE,
  TRACKED_STALENESS_NOTICE,
  TRACKED_UNKNOWN_NOTICE,
  TTL_DEFAULT_SECONDS,
  TTL_HINT,
  VERIFICATION_CONTEXT_NOTICE,
  ENROLLMENT_INTRO,
  WORKER_DRIVEN_NOTICE,
  addTracked,
  createGate,
  filterTracked,
  handoffFields,
  handoffText,
  isPastExpiry,
  lookupGate,
  newIdempotencyKey,
  parseEnrollmentId,
  parseTtlSeconds,
  removeTracked,
  resolveEnrollmentPermissions,
  recoverGate,
  revokeGate,
  shouldWarnManageWithoutRead,
  trackedFromInvitation,
  trackedFromStatus,
  trackedSummary,
  validateSiteLabel,
  verificationContext,
  type EnrollmentPermissions,
  type TrackedEnrollment,
  type TrackedFilter,
} from "./worker-enrollment";

// Static element ids. The view renders once per route, so a fixed id is unique in the document and
// — unlike a generated one — is stable enough for an aria-* reference to be asserted in a test.
const CREATE_REASON = "wenr-create-reason";
const LOOKUP_REASON = "wenr-lookup-reason";
const REVOKE_REASON = "wenr-revoke-reason";
const RECOVER_REASON = "wenr-recover-reason";
const HANDOFF_REGION = "wenr-handoff-region";
const TRACKED_TABS = "wenr-tracked";
const DISMISS_NOTICE = "wenr-dismiss-notice";

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
  onToggleReveal: () => void;
  onCopyHandoff: () => void;
  copyNotice: string | null;
  onDismissInvitation: () => void;
  /** Announced after a dismissal, in a live region that outlives the card being dismissed. */
  dismissNotice: string | null;

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

  // operator-triggered recovery
  onRecover: () => void;
  recovering: boolean;
  recoverError: ClosedCodeCopy | null;

  // tab-local working set
  tracked: readonly TrackedEnrollment[];
  trackedFilter: TrackedFilter;
  onTrackedFilterChange: (filter: TrackedFilter) => void;
  onRefreshTracked: (enrollmentId: string) => void;
  onForgetTracked: (enrollmentId: string) => void;
  /** The row a status request is in flight for, so only that row shows a busy control. */
  refreshingId: string | null;

  /** Injected so expiry copy is deterministic in tests. */
  nowMs: number;
}

/**
 * Presentational worker-enrollment surface. Props only — no data fetching, no clock and no
 * randomness — so it renders under `renderToStaticMarkup` in the node test environment.
 *
 * It holds exactly one hook, an effect that moves focus after a dismissal (see below). Effects do
 * not run under `renderToStaticMarkup`, so the rendered markup remains a pure function of the
 * props and every assertion in the node suite stays deterministic.
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
  onToggleReveal,
  onCopyHandoff,
  copyNotice,
  onDismissInvitation,
  dismissNotice,
  lookupId,
  onLookupIdChange,
  onLookup,
  lookingUp,
  status,
  statusError,
  onRevoke,
  revoking,
  revokeError,
  onRecover,
  recovering,
  recoverError,
  tracked,
  trackedFilter,
  onTrackedFilterChange,
  onRefreshTracked,
  onForgetTracked,
  refreshingId,
  nowMs,
}: WorkerEnrollmentViewProps) {
  const site = validateSiteLabel(siteLabel);
  const ttl = parseTtlSeconds(ttlSeconds);
  const id = parseEnrollmentId(lookupId);
  const create = createGate(permissions, site, ttl, creating);
  const lookup = lookupGate(permissions, id, lookingUp);
  const revoke = revokeGate(permissions, status, revoking);
  const recover = recoverGate(permissions, status, recovering);

  /**
   * Move focus to the dismissal notice when it appears.
   *
   * Dismissing removes the card that contains the focused control, and the browser responds by
   * dropping focus to <body> — measured in Chromium, not assumed — which returns a keyboard user
   * to the top of the document with their place lost. The notice is mounted from the start, so it
   * is always a valid target, and an effect runs after commit so its text is already present when
   * focus and the live-region announcement land on it.
   *
   * This is the view's ONLY hook and it is deliberately here rather than in the container: the
   * DOM being managed is this component's own, and a container-side effect would not fire for any
   * other consumer of the view. It does not compromise the node test environment —
   * `renderToStaticMarkup` never runs effects, so the rendered markup stays a pure function of
   * the props.
   *
   * Addressed by id rather than by ref because the view is otherwise prop-only; the ids are
   * static and are asserted by the accessibility suite.
   */
  useEffect(() => {
    if (dismissNotice === null) return;
    document.getElementById(DISMISS_NOTICE)?.focus();
  }, [dismissNotice]);

  const summary = trackedSummary(tracked, nowMs);
  const rows = filterTracked(tracked, trackedFilter);

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

      {/* Dismissing the invitation unmounts the card the operator was working in, which takes the
          focused control with it. Verified in a browser, not inferred: the browser then drops
          focus to <body>, so a keyboard user is returned to the top of the document with no
          announcement. This region lives OUTSIDE that card and is mounted from the start, so it
          is both a valid focus target at the moment the card disappears and a live region that
          has existed long enough to announce. The container moves focus here; see the effect. */}
      <p
        className="wenr-reason wenr-dismiss"
        id={DISMISS_NOTICE}
        role="status"
        tabIndex={-1}
      >
        {dismissNotice}
      </p>

      {/* Native disclosure: keyboard-operable and screen-reader-announced with no JS state. */}
      <details className="wenr-scope">
        <summary>What this interface can and cannot do</summary>
        <p className="wenr-reason">{CONTROLS_NOTICE}</p>
        <ul className="wenr-scope__list">
          {ENROLLMENT_CONTROLS.map((control) => (
            <li
              className={
                control.available
                  ? "wenr-scope__item wenr-scope__item--yes"
                  : "wenr-scope__item wenr-scope__item--no"
              }
              key={control.id}
            >
              <span className="wenr-scope__verdict">
                {control.available ? "Available" : "Not available"}
              </span>
              <span className="wenr-scope__label">{control.label}</span>
              <span className="wenr-scope__detail">{control.detail}</span>
            </li>
          ))}
        </ul>
      </details>

      <div className="wenr-grid">
        <CyberCard heading="Create an invitation" headingLevel={2}>
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
            <GatedAction gate={create} reasonId={CREATE_REASON}>
              {(describedBy) => (
                <CyberButton
                  disabled={!create.ok}
                  aria-describedby={describedBy}
                  onClick={onCreate}
                >
                  {creating ? "Creating…" : "Create invitation"}
                </CyberButton>
              )}
            </GatedAction>
            {createError && (
              <ClosedCodeError
                error={{ code: createError.code, message: "" }}
                codeText={ENROLLMENT_ERROR_TEXT}
              />
            )}
          </div>
        </CyberCard>

        <CyberCard heading="Look up an enrollment" headingLevel={2}>
          <div className="wenr-form">
            <CyberInput
              label="Enrollment id"
              hint={ENROLLMENT_ID_HINT}
              mono
              value={lookupId}
              errorText={lookupId !== "" && !id.ok ? id.error : undefined}
              onChange={(e) => onLookupIdChange(e.target.value)}
            />
            <GatedAction gate={lookup} reasonId={LOOKUP_REASON}>
              {(describedBy) => (
                <CyberButton
                  variant="secondary"
                  disabled={!lookup.ok}
                  aria-describedby={describedBy}
                  onClick={onLookup}
                >
                  {lookingUp ? "Loading…" : "Look up status"}
                </CyberButton>
              )}
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
        <CyberCard heading="Hand this to the worker" glow="danger" headingLevel={2}>
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
              <Expiry at={invitation.expires_at} nowMs={nowMs} />
            </div>

            {/* A toggle rather than a one-way button: focus stays on this control when the region
                opens and closes, so revealing never strands the keyboard on <body>, and closing it
                again is a first-class action rather than a page reload. */}
            <div className="wenr-actions">
              <CyberButton
                onClick={onToggleReveal}
                aria-expanded={revealed}
                aria-controls={HANDOFF_REGION}
              >
                {revealed ? "Hide invitation" : HANDOFF_REVEAL_LABEL}
              </CyberButton>
            </div>

            {/* The region element always exists so `aria-controls` above is never a dangling
                reference and the disclosure relationship is stable in both states. Its CONTENT is
                still strictly conditional — nothing about the invitation is in the document until
                the operator opens it. */}
            <div
              className="wenr-handoff__region"
              id={HANDOFF_REGION}
              role="group"
              aria-label="Invitation hand-off material"
              hidden={!revealed}
            >
              {revealed && (
                <>
                  <p className="wenr-reason">{HANDOFF_FILE_NOTICE}</p>
                  <pre className="wenr-handoff__block" tabIndex={0}>
                    {handoffText(invitation)}
                  </pre>
                  <KeyValueList
                    items={handoffFields(invitation).map((f) => ({
                      key: f.label,
                      value: f.value,
                      mono: true,
                    }))}
                  />

                  <h3 className="wenr-subhead">Confirm this out of band</h3>
                  <p className="wenr-reason">{VERIFICATION_CONTEXT_NOTICE}</p>
                  <ul className="wenr-verify">
                    {verificationContext(invitation).map((row) => (
                      <li className="wenr-verify__item" key={row.field}>
                        <span className="wenr-verify__label">{row.label}</span>
                        <code className="wenr-verify__value mono">{row.value}</code>
                        <span className="wenr-verify__proves">{row.proves}</span>
                      </li>
                    ))}
                  </ul>

                  <div className="wenr-actions">
                    <CyberButton variant="secondary" onClick={onCopyHandoff}>
                      Copy hand-off block
                    </CyberButton>
                    <CyberButton variant="ghost" onClick={onDismissInvitation}>
                      Done — clear it from this browser
                    </CyberButton>
                  </div>
                  <p className="wenr-reason" role="status">
                    {copyNotice}
                  </p>
                </>
              )}
            </div>
          </div>
        </CyberCard>
      )}

      {status && (
        <EnrollmentStatusPanel
          status={status}
          nowMs={nowMs}
          revokeGate={revoke}
          revokeReasonId={REVOKE_REASON}
          revoking={revoking}
          onRevoke={onRevoke}
          revokeError={revokeError}
          recoverGate={recover}
          recoverReasonId={RECOVER_REASON}
          recovering={recovering}
          onRecover={onRecover}
          recoverError={recoverError}
        />
      )}

      <CyberCard heading="Tracked in this tab" headingLevel={2}>
        <p className="wenr-reason">{TRACKED_LIST_NOTICE}</p>
        <p className="wenr-reason">{TRACKED_STALENESS_NOTICE}</p>

        <div className="wenr-metrics">
          <MetricTile label="Tracked here" value={summary.total} />
          <MetricTile
            label="Waiting on a worker"
            value={summary.pending}
            tone={summary.pending > 0 ? "warn" : "default"}
          />
          <MetricTile
            label="Worker healthy"
            value={summary.healthy}
            tone={summary.healthy > 0 ? "ok" : "default"}
          />
          <MetricTile
            label="No worker enrolled"
            value={summary.settled}
            tone={summary.settled > 0 ? "danger" : "default"}
          />
          <MetricTile
            label="Past expiry"
            value={summary.pastExpiry}
            tone={summary.pastExpiry > 0 ? "danger" : "default"}
            detail={summary.pastExpiry > 0 ? PAST_EXPIRY_NOTICE : undefined}
          />
          <MetricTile
            label="State not recognised"
            value={summary.unknown}
            detail={summary.unknown > 0 ? TRACKED_UNKNOWN_NOTICE : undefined}
          />
        </div>

        <TabRail
          tabs={TRACKED_FILTERS.map((filter) => ({
            id: filter,
            label: `${TRACKED_FILTER_LABELS[filter]} (${
              filter === "all" ? summary.total : summary[filter]
            })`,
          }))}
          active={trackedFilter}
          onSelect={(next) => onTrackedFilterChange(next as TrackedFilter)}
          idBase={TRACKED_TABS}
          aria-label="Filter tracked enrollments"
        />

        <div
          role="tabpanel"
          id={tabPanelId(TRACKED_TABS, trackedFilter)}
          aria-labelledby={tabId(TRACKED_TABS, trackedFilter)}
        >
          {rows.length === 0 ? (
            <EmptyState title="Nothing to show under this filter">
              {tracked.length === 0
                ? "Create an invitation or look one up by id, and it will be tracked here for this tab."
                : "Other enrollments are tracked under a different filter."}
            </EmptyState>
          ) : (
            <CyberTable
              label="Enrollments tracked in this browser tab"
              caption={TRACKED_UNKNOWN_NOTICE}
              head={[
                "Enrollment id",
                "Site",
                "Last observed state",
                "Expiry",
                "Actions",
              ]}
            >
              {rows.map((entry) => {
                const past = isPastExpiry(entry, nowMs);
                const busy = refreshingId === entry.enrollmentId;
                return (
                  <tr key={entry.enrollmentId}>
                    <td>
                      <HashChip value={entry.enrollmentId} />
                    </td>
                    <td>
                      {entry.siteLabel === "" ? (
                        <span className="wenr-unknown">
                          Not known in this tab
                          <span className="ui-sr-only">
                            {" "}
                            — neither the create response nor the status this tab observed carried
                            a site label for this enrollment
                          </span>
                        </span>
                      ) : (
                        entry.siteLabel
                      )}
                    </td>
                    <td>
                      <StatusBadge state={entry.state} domain="enrollment" />
                      <span className="wenr-revision">
                        {" "}
                        at revision {entry.revision}
                      </span>
                    </td>
                    <td>
                      <Expiry at={entry.expiresAt} nowMs={nowMs} />
                      {past && (
                        <span className="wenr-past-expiry" role="note">
                          {PAST_EXPIRY_NOTICE}
                        </span>
                      )}
                    </td>
                    <td>
                      <div className="wenr-actions">
                        <CyberButton
                          size="sm"
                          variant="secondary"
                          disabled={!permissions.read || busy}
                          onClick={() => onRefreshTracked(entry.enrollmentId)}
                        >
                          {busy ? "Refreshing…" : "Refresh"}
                          <span className="ui-sr-only">
                            {" "}
                            enrollment {entry.enrollmentId}
                          </span>
                        </CyberButton>
                        <CyberButton
                          size="sm"
                          variant="ghost"
                          onClick={() => onForgetTracked(entry.enrollmentId)}
                        >
                          Forget
                          <span className="ui-sr-only">
                            {" "}
                            enrollment {entry.enrollmentId} — removes this row from this tab only
                            and changes nothing on the control plane
                          </span>
                        </CyberButton>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </CyberTable>
          )}
        </div>
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
  const [dismissNotice, setDismissNotice] = useState<string | null>(null);
  const [lookupId, setLookupId] = useState("");
  const [status, setStatus] = useState<EnrollmentStatus | null>(null);
  const [tracked, setTracked] = useState<readonly TrackedEnrollment[]>([]);
  const [trackedFilter, setTrackedFilter] = useState<TrackedFilter>("pending");
  const [refreshingId, setRefreshingId] = useState<string | null>(null);

  const createAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });
  const lookupAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });
  const revokeAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });
  const recoverAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });

  /** Every observed status updates the working set, so the table can never disagree with the
   *  detail panel about a state this tab has already seen. */
  const observe = (observed: EnrollmentStatus) => {
    setStatus(observed);
    setTracked((list) => addTracked(list, trackedFromStatus(observed)));
  };

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
      setDismissNotice(null);
      setTracked((list) => addTracked(list, trackedFromInvitation(created)));
    });
  };

  const onLookup = () => {
    const id = parseEnrollmentId(lookupId);
    if (!id.ok) return;
    void lookupAction.run(async () => {
      observe(await api.getEnrollmentStatus(id.value));
    });
  };

  /** A row refresh is the same supported read, addressed by an id this tab already holds — so it
   *  needs no parsing and can never widen the set of routes this page calls. */
  const onRefreshTracked = (enrollmentId: string) => {
    setRefreshingId(enrollmentId);
    void lookupAction.run(async () => {
      // finally, not the success callback: a refused refresh must release the row too, or that
      // row keeps a busy control forever and the operator cannot retry it.
      try {
        observe(await api.getEnrollmentStatus(enrollmentId));
      } finally {
        setRefreshingId(null);
      }
    });
  };

  const onRevoke = () => {
    if (status === null) return;
    // The revision always comes from the status we actually observed — never from user input.
    const observed = status;
    void revokeAction.run(async () => {
      observe(await api.revokeEnrollment(observed.enrollment_id, observed.revision));
    });
  };

  /** The second operator write. Same discipline as revoke: the revision always comes from the
   *  status this tab actually observed, never from user input. */
  const onRecover = () => {
    if (status === null) return;
    const observed = status;
    void recoverAction.run(async () => {
      observe(
        await api.markEnrollmentRecoveryRequired(observed.enrollment_id, observed.revision),
      );
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
      onToggleReveal={() => setRevealed((open) => !open)}
      onCopyHandoff={onCopyHandoff}
      copyNotice={copyNotice}
      onDismissInvitation={() => {
        setInvitation(null);
        setRevealed(false);
        setCopyNotice(null);
        setDismissNotice(INVITATION_CLEARED_NOTICE);
      }}
      dismissNotice={dismissNotice}
      lookupId={lookupId}
      onLookupIdChange={setLookupId}
      onLookup={onLookup}
      lookingUp={lookupAction.busy}
      status={status}
      statusError={lookupAction.error}
      onRevoke={onRevoke}
      revoking={revokeAction.busy}
      revokeError={revokeAction.error}
      onRecover={onRecover}
      recovering={recoverAction.busy}
      recoverError={recoverAction.error}
      tracked={tracked}
      trackedFilter={trackedFilter}
      onTrackedFilterChange={setTrackedFilter}
      onRefreshTracked={onRefreshTracked}
      onForgetTracked={(enrollmentId) =>
        setTracked((list) => removeTracked(list, enrollmentId))
      }
      refreshingId={refreshingId}
      nowMs={Date.now()}
    />
  );
}
