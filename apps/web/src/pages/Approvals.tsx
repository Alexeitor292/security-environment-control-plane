import "./governance.css";

import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { Onboarding } from "../api/types";
import {
  CyberCard,
  DecisionCard,
  EmptyState,
  MetricTile,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  shortId,
} from "../components/ui";
import { CyberGridBackground } from "../components/backgrounds";
import { ApprovalIcon, RefusedIcon } from "../components/icons";
import { useAsync } from "../hooks";
import {
  QUEUE_EXECUTES_NOTHING,
  QUEUE_INTRO,
  REFUSAL_FIRST_NOTE,
  decisionRecords,
  ledgerTimestamp,
  type DecisionRecord,
} from "./audit-view";
import {
  DECISION_SOURCE_TOTAL,
  NO_DECISIONS_BODY,
  NO_DECISIONS_PARTIAL_TITLE,
  NO_DECISIONS_TITLE,
  decisionCountValue,
  deriveDecisionItems,
  unavailableSourceCount,
  type DecisionSources,
} from "./overview";

const opt = <T,>(p: Promise<T>): Promise<T | null> => p.catch(() => null);

interface QueueLoad {
  sources: DecisionSources;
  /** True when SOME (not all) per-target onboarding calls failed — the queue
   *  is then incomplete and a zero would be a false claim. */
  fanoutPartial: boolean;
}

/** Same source sequencing the dashboard uses: the four list endpoints plus a
 *  per-target onboarding fan-out. A failed source contributes null (a truthful
 *  sources-unavailable caveat renders instead of a fake zero); a PARTIALLY
 *  failed fan-out is flagged so it is never presented as complete. */
async function loadQueueSources(): Promise<QueueLoad> {
  const [exercises, targets, stagingLabs, stagingDeployments, discoveryEnrollments] =
    await Promise.all([
      opt(api.listExercises()),
      opt(api.listTargets()),
      opt(api.listStagingLabs()),
      opt(api.listStagingDeployments()),
      opt(api.listDiscoveryEnrollments()),
    ]);
  let onboardings: Onboarding[] | null = null;
  let fanoutPartial = false;
  if (targets) {
    const settled = await Promise.allSettled(
      targets.map((t) => api.listOnboardings(t.id)),
    );
    const ok = settled.filter(
      (s): s is PromiseFulfilledResult<Onboarding[]> => s.status === "fulfilled",
    );
    if (settled.length > 0 && ok.length === 0) {
      // All fan-out calls failing means the source is unavailable, not empty.
      onboardings = null;
    } else {
      onboardings = ok.flatMap((s) => s.value);
      fanoutPartial = ok.length < settled.length;
    }
  }
  return {
    sources: { exercises, onboardings, stagingLabs, stagingDeployments, discoveryEnrollments },
    fanoutPartial,
  };
}

function RecordRow({ record }: { record: DecisionRecord }) {
  return (
    <div className="gov-record">
      <span className="gov-record__action">{record.action}</span>
      <StatusBadge state={record.outcome} domain="audit" />
      {record.reasonCode && (
        <span className="gov-record__reason">{record.reasonCode}</span>
      )}
      <span className="gov-record__meta" title={record.resourceId ?? undefined}>
        {record.resourceType}
        {record.resourceId ? `/${shortId(record.resourceId)}` : ""} ·{" "}
        {ledgerTimestamp(record.createdAt)} UTC
      </span>
    </div>
  );
}

export function Approvals() {
  const sources = useAsync(loadQueueSources, []);
  const audit = useAsync(() => opt(api.audit()), []);

  const loaded = sources.data?.sources ?? null;
  const fanoutPartial = sources.data?.fanoutPartial ?? false;
  const pending = loaded ? deriveDecisionItems(loaded) : [];
  const unavailable = loaded ? unavailableSourceCount(loaded) : 0;
  // A partially failed onboarding fan-out makes the queue incomplete: a zero
  // may not render as a definitive "0" and the caveat must show.
  const incomplete = unavailable > 0 || fanoutPartial;
  const auditLoading = audit.loading && audit.data === undefined;
  const auditList = audit.data ?? null;
  const records = auditList
    ? decisionRecords(auditList)
    : { refusals: [], approvals: [] };

  const loading = sources.loading && !sources.data;

  return (
    <div className="gov">
      <CyberGridBackground intensity="subtle" className="gov-bg" />
      <div className="gov-head">
        <h1>Approvals Queue</h1>
        <p className="gov-sub">{QUEUE_INTRO}</p>
      </div>

      <SafetyNotice role="note" tone="warn">
        {QUEUE_EXECUTES_NOTHING}
      </SafetyNotice>

      {loading ? (
        <CyberCard>
          <Skeleton lines={5} />
        </CyberCard>
      ) : (
        <>
          <div className="gov-tally">
            <MetricTile
              label="Pending decisions"
              value={decisionCountValue(pending.length, incomplete ? Math.max(unavailable, 1) : 0)}
              detail={
                unavailable > 0
                  ? `${DECISION_SOURCE_TOTAL - unavailable} of ${DECISION_SOURCE_TOTAL} sources available`
                  : fanoutPartial
                    ? "some targets' onboarding queues unreachable"
                    : "across plans, onboardings, labs, deployments, and discovery"
              }
              tone={pending.length > 0 ? "warn" : "default"}
            />
            <MetricTile
              label="Recorded refusals"
              value={auditList ? String(records.refusals.length) : "—"}
              detail={
                auditList
                  ? "from the append-only ledger"
                  : auditLoading
                    ? "ledger loading…"
                    : "ledger unavailable"
              }
              tone={records.refusals.length > 0 ? "danger" : "default"}
            />
            <MetricTile
              label="Recorded approvals"
              value={auditList ? String(records.approvals.length) : "—"}
              detail={
                auditList
                  ? "decisions recorded — not executions"
                  : auditLoading
                    ? "ledger loading…"
                    : "ledger unavailable"
              }
            />
          </div>

          <div className="gov-grid">
            <CyberCard heading="Pending — decided on the owning surface">
              {unavailable > 0 && (
                <p className="gov-note" role="status">
                  {unavailable} of {DECISION_SOURCE_TOTAL} decision sources
                  unavailable — this queue may be incomplete.
                </p>
              )}
              {fanoutPartial && (
                <p className="gov-note" role="status">
                  Some targets&apos; onboarding queues were unreachable — this
                  queue may be incomplete.
                </p>
              )}
              {pending.length === 0 ? (
                <EmptyState
                  title={
                    incomplete ? NO_DECISIONS_PARTIAL_TITLE : NO_DECISIONS_TITLE
                  }
                >
                  {NO_DECISIONS_BODY}
                </EmptyState>
              ) : (
                <div className="gov-queue">
                  {pending.map((item) => (
                    <DecisionCard
                      key={item.id}
                      chip={item.chip}
                      title={item.title}
                      meta={item.meta}
                      href={item.href}
                    />
                  ))}
                </div>
              )}
            </CyberCard>

            <div style={{ display: "grid", gap: 14 }}>
              <CyberCard
                heading={
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                    <RefusedIcon size={15} /> Recorded refusals & denials
                  </span>
                }
              >
                <p className="gov-note">{REFUSAL_FIRST_NOTE}</p>
                {auditLoading ? (
                  <Skeleton lines={3} />
                ) : !auditList ? (
                  <p className="muted">Ledger unavailable.</p>
                ) : records.refusals.length === 0 ? (
                  <EmptyState title="No refusals recorded">
                    Refusals, denials, and revocations appear here the moment
                    they are recorded.
                  </EmptyState>
                ) : (
                  <div className="gov-records">
                    {records.refusals.slice(0, 8).map((r) => (
                      <RecordRow key={r.id} record={r} />
                    ))}
                    {records.refusals.length > 8 && (
                      <p className="gov-note">
                        Showing 8 of {records.refusals.length} —{" "}
                        <Link to="/audit">full ledger</Link>.
                      </p>
                    )}
                  </div>
                )}
              </CyberCard>

              <CyberCard
                heading={
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                    <ApprovalIcon size={15} /> Recorded approvals
                  </span>
                }
              >
                <p className="gov-note">
                  Each approval is an immutable recorded decision, pinned to the
                  reviewed content. It does not execute anything.
                </p>
                {auditLoading ? (
                  <Skeleton lines={3} />
                ) : !auditList ? (
                  <p className="muted">Ledger unavailable.</p>
                ) : records.approvals.length === 0 ? (
                  <EmptyState title="No approvals recorded">
                    Approval decisions appear here after they are recorded on
                    their owning surface.
                  </EmptyState>
                ) : (
                  <div className="gov-records">
                    {records.approvals.slice(0, 8).map((r) => (
                      <RecordRow key={r.id} record={r} />
                    ))}
                    {records.approvals.length > 8 && (
                      <p className="gov-note">
                        Showing 8 of {records.approvals.length} —{" "}
                        <Link to="/audit">full ledger</Link>.
                      </p>
                    )}
                  </div>
                )}
              </CyberCard>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
