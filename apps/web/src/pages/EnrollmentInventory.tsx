import "./worker-enrollment.css";
import "./enrollment-inventory.css";

import { useEffect, useState } from "react";

import { api } from "../api/client";
import type { EnrollmentStatus } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberTable,
  EmptyState,
  HashChip,
  MetricTile,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  TabRail,
  tabId,
  tabPanelId,
  useAction,
} from "../components/ui";
import type { ClosedCodeCopy } from "../components/ui";
import { EnrollmentStatusPanel, Expiry, GatedAction } from "./EnrollmentStatusPanel";
import {
  COMPLETE_NOTICE,
  EMPTY_PAGE,
  EMPTY_SCOPE_TITLE,
  FILTER_NOTICE,
  INVENTORY_ERROR_TEXT,
  INVENTORY_INTRO,
  INVENTORY_SCOPES,
  LIST_NEEDS_READ_NOTICE,
  MORE_MAY_REMAIN_NOTICE,
  NO_DECISION_NOTICE,
  NO_INVITATION_IN_LIST_NOTICE,
  ORDERING_NOTICE,
  ORG_SCOPE_NOTICE,
  PAGE_INTEGRITY_STEPS,
  PARTIAL_COUNT_NOTICE,
  RECOVERY_NOT_RESUMABLE_NOTICE,
  SCOPE_DESCRIPTIONS,
  SCOPE_LABELS,
  SELECTION_NOTICE,
  SITE_LABEL_NOTICE,
  SITE_UNAVAILABLE_TEXT,
  STALENESS_NOTICE,
  SWEEP_NOTICE,
  appendPage,
  emptyScopeBody,
  findEnrollment,
  inventoryRevokeGate,
  inventoryRows,
  inventorySummary,
  isPageIntegrityFailure,
  listGate,
  loadMoreGate,
  replaceRow,
  scopeStates,
  type InventoryPage,
  type InventoryScope,
} from "./enrollment-inventory";
import {
  ENROLLMENT_ERROR_TEXT,
  PAST_EXPIRY_NOTICE,
  resolveEnrollmentPermissions,
  shouldWarnManageWithoutRead,
  type EnrollmentPermissions,
} from "./worker-enrollment";

// Static element ids. The view renders once per route, so a fixed id is unique in the document and
// — unlike a generated one — is stable enough for an aria-* reference to be asserted in a test.
const SCOPE_TABS = "einv-scope";
const LOAD_REASON = "einv-load-reason";
const MORE_REASON = "einv-more-reason";
const REVOKE_REASON = "einv-revoke-reason";
const SELECTION_REGION = "einv-selection";
const SELECTION_HEADING = "einv-selection-heading";
const INTEGRITY_TITLE = "einv-integrity-title";
const STATUS_LINE = "einv-status";

export interface EnrollmentInventoryViewProps {
  permissions: EnrollmentPermissions;

  scope: InventoryScope;
  onScopeChange: (scope: InventoryScope) => void;

  page: InventoryPage;
  loading: boolean;
  /** True only for the very first load of a scope, so a refresh never blanks a populated table. */
  firstLoad: boolean;
  listError: ClosedCodeCopy | null;
  onReload: () => void;
  onLoadMore: () => void;

  selectedId: string | null;
  onSelect: (enrollmentId: string) => void;
  onClearSelection: () => void;
  /** Re-read of the selected record only — one row, one request, never the whole page. */
  onRereadSelected: () => void;
  rereading: boolean;
  /** Kept separate from the revoke failure on purpose: a refused re-read and a refused revoke are
   *  different events with different remedies, and folding them into one slot would show the wrong
   *  closed code for whichever happened second. */
  rereadError: ClosedCodeCopy | null;

  onRevoke: () => void;
  revoking: boolean;
  revokeError: ClosedCodeCopy | null;

  /** Announced when the loaded set changes, in a region that outlives the table. */
  liveNotice: string | null;

  /** Injected so expiry copy is deterministic in tests. */
  nowMs: number;
}

/**
 * Presentational enrollment inventory. Props only — no data fetching, no clock and no randomness —
 * so it renders under `renderToStaticMarkup` in the node test environment.
 *
 * It holds exactly one hook: an effect that moves focus onto the selected record when a row is
 * chosen. Effects do not run under `renderToStaticMarkup`, so the rendered markup stays a pure
 * function of the props.
 */
export function EnrollmentInventoryView({
  permissions,
  scope,
  onScopeChange,
  page,
  loading,
  firstLoad,
  listError,
  onReload,
  onLoadMore,
  selectedId,
  onSelect,
  onClearSelection,
  onRereadSelected,
  rereading,
  rereadError,
  onRevoke,
  revoking,
  revokeError,
  liveNotice,
  nowMs,
}: EnrollmentInventoryViewProps) {
  const rows = inventoryRows(page, nowMs);
  const summary = inventorySummary(page, nowMs);
  const selected = findEnrollment(page, selectedId);
  const load = listGate(permissions, loading);
  const more = loadMoreGate(permissions, page, loading);
  const revoke = inventoryRevokeGate(permissions, selected, revoking);

  /**
   * Move focus to the selected record when one is chosen.
   *
   * Selecting a row renders a detail panel BELOW the table. Without this, a keyboard or screen
   * reader user activates the row control and nothing moves: the new content is off-screen and
   * behind them in the reading order, so the action reads as having done nothing. The region is
   * mounted from the start so it is always a valid target, and an effect runs after commit so the
   * record is already rendered when focus lands on it.
   */
  useEffect(() => {
    if (selectedId === null) return;
    document.getElementById(SELECTION_REGION)?.focus();
  }, [selectedId]);

  return (
    <div className="wenr einv">
      <header className="wenr-head">
        <h1>Enrollment Inventory</h1>
        <p className="wenr-intro">{INVENTORY_INTRO}</p>
      </header>

      <SafetyNotice role="note" tone="info">
        {NO_DECISION_NOTICE}
      </SafetyNotice>

      {!permissions.read && (
        <SafetyNotice role="note" tone="warn">
          {shouldWarnManageWithoutRead(permissions)
            ? LIST_NEEDS_READ_NOTICE
            : "Viewing enrollments requires the enrollment:read permission. Ask an organization admin to grant it."}
        </SafetyNotice>
      )}

      {/* Mounted from the start so it has existed long enough to announce, and so it is never a
          dangling reference. It reports what the last load actually did — how many rows arrived
          and whether more remain — because a table that silently grows announces nothing. */}
      <p className="wenr-reason einv-live" id={STATUS_LINE} role="status">
        {liveNotice}
      </p>

      <CyberCard heading="Filter" headingLevel={2}>
        <p className="wenr-reason">{FILTER_NOTICE}</p>
        <TabRail
          tabs={INVENTORY_SCOPES.map((id) => ({ id, label: SCOPE_LABELS[id] }))}
          active={scope}
          onSelect={(next) => onScopeChange(next as InventoryScope)}
          idBase={SCOPE_TABS}
          aria-label="Filter enrollments by lifecycle"
        />
        <div
          role="tabpanel"
          id={tabPanelId(SCOPE_TABS, scope)}
          aria-labelledby={tabId(SCOPE_TABS, scope)}
        >
          <p className="wenr-reason einv-scope-detail">{SCOPE_DESCRIPTIONS[scope]}</p>

          <div className="wenr-metrics">
            <MetricTile label="Rows loaded" value={summary.loaded} />
            <MetricTile
              label="Enrolled workers"
              value={summary.workers}
              tone={summary.workers > 0 ? "ok" : "default"}
            />
            <MetricTile
              label="Waiting on a worker"
              value={summary.queue}
              tone={summary.queue > 0 ? "warn" : "default"}
            />
            <MetricTile
              label="No worker enrolled"
              value={summary.attention}
              tone={summary.attention > 0 ? "danger" : "default"}
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
              detail={
                summary.unknown > 0
                  ? "A state this build does not know the name of. It is counted separately rather than filed as progress it might not be."
                  : undefined
              }
            />
          </div>

          {/* Which of the two sentences is shown is load-bearing: a count over a partial page must
              never read as a count of the organization. */}
          <p className="wenr-reason">
            {summary.complete ? COMPLETE_NOTICE : PARTIAL_COUNT_NOTICE}
          </p>
          <p className="wenr-reason">{ORDERING_NOTICE}</p>
          <p className="wenr-reason">{MORE_MAY_REMAIN_NOTICE}</p>
          <p className="wenr-reason">{STALENESS_NOTICE}</p>

          <div className="wenr-actions">
            <GatedAction gate={load} reasonId={LOAD_REASON}>
              {(describedBy) => (
                <CyberButton
                  variant="secondary"
                  disabled={!load.ok}
                  aria-describedby={describedBy}
                  onClick={onReload}
                >
                  {loading
                    ? "Loading…"
                    : page.pages === 0
                      ? "Load enrollments"
                      : "Reload from the first page"}
                </CyberButton>
              )}
            </GatedAction>
          </div>

          {listError && (
            <>
              <ClosedCodeError
                error={{ code: listError.code, message: "" }}
                codeText={INVENTORY_ERROR_TEXT}
              />
              {/* A page refused because one row failed its integrity check is not the same event
                  as an unreachable API, and it does not have the same remedy. The closed code
                  alone does not carry that difference — the controller returns the same code a
                  single-record read does — so the page-scoped consequences are spelled out. */}
              {isPageIntegrityFailure(listError.code) && (
                <section
                  aria-labelledby={INTEGRITY_TITLE}
                  className="einv-integrity"
                >
                  <SafetyNotice role="note" tone="warn">
                    <strong id={INTEGRITY_TITLE}>
                      This page contains a record this controller cannot project
                    </strong>
                    <ul className="wenr-recovery__steps">
                      {PAGE_INTEGRITY_STEPS.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ul>
                  </SafetyNotice>
                </section>
              )}
            </>
          )}

          {firstLoad && loading ? (
            <div className="einv-skeleton">
              {/* aria-hidden inside Skeleton, so the load is announced in words by the live
                  region above rather than by a shape a screen reader cannot see. */}
              <Skeleton lines={4} />
              <p className="wenr-reason">Loading enrollments…</p>
            </div>
          ) : rows.length === 0 ? (
            <EmptyState title={EMPTY_SCOPE_TITLE}>
              {page.pages === 0
                ? "Nothing has been loaded yet. Use Load enrollments above."
                : emptyScopeBody(scope)}
            </EmptyState>
          ) : (
            <>
              <CyberTable
                label={`Enrollments in your organization — ${SCOPE_LABELS[scope]}`}
                caption={ORG_SCOPE_NOTICE}
                head={[
                  "Enrollment id",
                  "Deployment site",
                  "State",
                  "Worker identity",
                  "Expiry",
                  "Actions",
                ]}
              >
                {rows.map((row) => {
                  const isSelected = row.enrollmentId === selectedId;
                  return (
                    <tr
                      key={row.enrollmentId}
                      className={isSelected ? "einv-row einv-row--selected" : "einv-row"}
                    >
                      <td>
                        <HashChip value={row.enrollmentId} />
                      </td>
                      <td>
                        {row.siteLabel === "" ? (
                          <span className="wenr-unknown">{SITE_UNAVAILABLE_TEXT}</span>
                        ) : (
                          row.siteLabel
                        )}
                      </td>
                      <td>
                        <StatusBadge state={row.state} domain="enrollment" />
                        <span className="wenr-revision"> at revision {row.revision}</span>
                        {row.refusalReason !== "" && (
                          <span className="einv-refusal">
                            Reason code: <code className="mono">{row.refusalReason}</code>
                          </span>
                        )}
                      </td>
                      <td>
                        {row.workerInstallationId === "" ? (
                          <span className="wenr-unknown">
                            No worker bound yet
                            <span className="ui-sr-only">
                              {" "}
                              — no worker has proved key possession against this enrollment
                            </span>
                          </span>
                        ) : (
                          <code className="mono einv-worker">
                            {row.workerInstallationId}
                          </code>
                        )}
                      </td>
                      <td>
                        <Expiry at={row.expiresAt} nowMs={nowMs} />
                        {row.pastExpiry && (
                          <span className="wenr-past-expiry" role="note">
                            {PAST_EXPIRY_NOTICE}
                          </span>
                        )}
                      </td>
                      <td>
                        <CyberButton
                          size="sm"
                          variant={isSelected ? "primary" : "secondary"}
                          aria-pressed={isSelected}
                          onClick={() => onSelect(row.enrollmentId)}
                        >
                          {isSelected ? "Showing" : "Show details"}
                          <span className="ui-sr-only">
                            {" "}
                            for enrollment {row.enrollmentId}
                          </span>
                        </CyberButton>
                      </td>
                    </tr>
                  );
                })}
              </CyberTable>

              <GatedAction gate={more} reasonId={MORE_REASON}>
                {(describedBy) => (
                  <CyberButton
                    variant="secondary"
                    disabled={!more.ok}
                    aria-describedby={describedBy}
                    onClick={onLoadMore}
                  >
                    {loading ? "Loading…" : "Load more"}
                  </CyberButton>
                )}
              </GatedAction>
            </>
          )}
        </div>
      </CyberCard>

      <p className="wenr-reason">{SITE_LABEL_NOTICE}</p>
      <p className="wenr-reason">{SWEEP_NOTICE}</p>
      <p className="wenr-reason">{NO_INVITATION_IN_LIST_NOTICE}</p>

      {/* Always mounted: it is the focus target at the moment a row is selected, and an
          `aria-controls` target that appeared only when populated would be a dangling reference
          for as long as nothing is selected. */}
      <section
        aria-labelledby={SELECTION_HEADING}
        className="einv-selection"
        id={SELECTION_REGION}
        tabIndex={-1}
      >
        <h2 className="einv-selection__title" id={SELECTION_HEADING}>
          Selected enrollment
        </h2>
        {selected === null ? (
          <p className="wenr-reason">
            Select an enrollment above to see its evidence, lifecycle and the one operator action
            that exists for it.
          </p>
        ) : (
          <>
            <p className="wenr-reason">{SELECTION_NOTICE}</p>
            <p className="wenr-reason">{RECOVERY_NOT_RESUMABLE_NOTICE}</p>
            <EnrollmentStatusPanel
              status={selected}
              nowMs={nowMs}
              heading="Status and evidence"
              headingLevel={3}
              revokeGate={revoke}
              revokeReasonId={REVOKE_REASON}
              revoking={revoking}
              onRevoke={onRevoke}
              revokeError={revokeError}
              actions={
                <>
                  <div className="wenr-actions">
                    <CyberButton
                      variant="secondary"
                      disabled={!permissions.read || rereading}
                      onClick={onRereadSelected}
                    >
                      {rereading ? "Re-reading…" : "Re-read this enrollment"}
                    </CyberButton>
                    <CyberButton variant="ghost" onClick={onClearSelection}>
                      Close details
                    </CyberButton>
                  </div>
                  {rereadError && (
                    <ClosedCodeError
                      error={{ code: rereadError.code, message: "" }}
                      codeText={ENROLLMENT_ERROR_TEXT}
                    />
                  )}
                </>
              }
            />
          </>
        )}
      </section>
    </div>
  );
}

/**
 * Container: owns state and the two supported reads plus the one supported write.
 *
 * Nothing loads on mount. A list read costs the controller a scan per call, and a page that issues
 * requests the operator never asked for turns a deliberate read into background traffic — so the
 * first load is an explicit action, exactly as the per-row reads are on the worker-enrollment page.
 */
export function EnrollmentInventory() {
  const { principal } = useAuth();
  const permissions = resolveEnrollmentPermissions(principal?.permissions);

  const [scope, setScope] = useState<InventoryScope>("workers");
  const [page, setPage] = useState<InventoryPage>(EMPTY_PAGE);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [liveNotice, setLiveNotice] = useState<string | null>(null);

  const listAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });
  const rereadAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });
  const revokeAction = useAction({ codeText: ENROLLMENT_ERROR_TEXT });

  /**
   * What the load actually did, stated in rows rather than implied by the table changing size.
   *
   * "There may be more" rather than "more pages remain": the controller returns a cursor whenever a
   * page came back FULL, which includes the case where the next page turns out to be empty. Saying
   * more remain would be a claim the response does not support.
   */
  const announce = (next: InventoryPage, added: number) => {
    const more = next.cursor === null ? "No further pages." : "There may be more.";
    setLiveNotice(`Loaded ${added} more; ${next.items.length} shown. ${more}`);
  };

  const load = (from: InventoryPage, cursor: string | undefined) => {
    void listAction.run(async () => {
      const response = await api.listEnrollments({
        state: scopeStates(scope),
        ...(cursor === undefined ? {} : { after: cursor }),
      });
      const next = appendPage(from, response);
      setPage(next);
      announce(next, response.items.length);
    });
  };

  /** Changing the filter starts again: the cursor is a keyset over one filtered order and cannot
   *  be carried across to a different filter. The selection goes with it — a record that is no
   *  longer in the loaded set must not stay open below the table. */
  const onScopeChange = (next: InventoryScope) => {
    setScope(next);
    setPage(EMPTY_PAGE);
    setSelectedId(null);
    setLiveNotice(null);
  };

  /** Re-read of exactly one record, through the same supported status route the other surface
   *  uses, addressed by an id this page already holds. */
  const onRereadSelected = () => {
    if (selectedId === null) return;
    const id = selectedId;
    void rereadAction.run(async () => {
      const observed = await api.getEnrollmentStatus(id);
      setPage((current) => replaceRow(current, observed));
      setLiveNotice("Re-read this enrollment from the controller.");
    });
  };

  const onRevoke = () => {
    const selected: EnrollmentStatus | null = findEnrollment(page, selectedId);
    if (selected === null) return;
    // The revision always comes from the record that was actually loaded — never from user input.
    void revokeAction.run(async () => {
      const observed = await api.revokeEnrollment(
        selected.enrollment_id,
        selected.revision,
      );
      setPage((current) => replaceRow(current, observed));
      setLiveNotice("Enrollment revoked. It can no longer be used by any worker.");
    });
  };

  return (
    <EnrollmentInventoryView
      permissions={permissions}
      scope={scope}
      onScopeChange={onScopeChange}
      page={page}
      loading={listAction.busy}
      firstLoad={page.pages === 0}
      listError={listAction.error}
      onReload={() => load(EMPTY_PAGE, undefined)}
      onLoadMore={() => {
        if (page.cursor === null) return;
        load(page, page.cursor);
      }}
      selectedId={selectedId}
      onSelect={setSelectedId}
      onClearSelection={() => setSelectedId(null)}
      onRereadSelected={onRereadSelected}
      rereading={rereadAction.busy}
      rereadError={rereadAction.error}
      onRevoke={onRevoke}
      revoking={revokeAction.busy}
      revokeError={revokeAction.error}
      liveNotice={liveNotice}
      nowMs={Date.now()}
    />
  );
}
