import "./governance.css";

import { useState } from "react";

import { api } from "../api/client";
import type { AuditEvent } from "../api/types";
import {
  CyberCard,
  CyberInput,
  CyberSelect,
  CyberTable,
  EmptyState,
  HashChip,
  KeyValueList,
  MetricTile,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  shortId,
} from "../components/ui";
import { CyberGridBackground } from "../components/backgrounds";
import { AuditLedgerIcon } from "../components/icons";
import { useAsync } from "../hooks";
import {
  EMPTY_LEDGER_FILTER,
  LEDGER_INTRO,
  LEDGER_UNAVAILABLE,
  OPERATOR_SAFE_NOTE,
  detailFields,
  filterLedger,
  hiddenFieldsNote,
  ledgerCategories,
  ledgerTally,
  ledgerTimestamp,
  type LedgerFilter,
  type OutcomeFilter,
} from "./audit-view";

function EventDetail({ event }: { event: AuditEvent }) {
  const { fields, hiddenCount } = detailFields(event);
  return (
    <CyberCard surface="well" heading="Event detail — operator-safe view">
      <div className="gov-detail-head">
        <span className="mono">{event.action}</span>
        <StatusBadge state={event.outcome} domain="audit" />
      </div>
      <KeyValueList
        items={[
          // Rendered verbatim from the recorded value — naive-UTC, never
          // re-parsed through Date (which would shift it to local time).
          { key: "Recorded at (UTC)", value: ledgerTimestamp(event.created_at), mono: true },
          { key: "Actor", value: event.actor, mono: true },
          {
            key: "Resource",
            value: `${event.resource_type}${event.resource_id ? ` · ${event.resource_id}` : ""}`,
            mono: true,
          },
          ...fields.map((f) =>
            f.hash
              ? { key: f.label, value: <HashChip value={f.value} digits={12} /> }
              : { key: f.label, value: f.value, mono: f.mono },
          ),
        ]}
      />
      {hiddenCount > 0 && <p className="gov-note">{hiddenFieldsNote(hiddenCount)}</p>}
      <p className="gov-note">{OPERATOR_SAFE_NOTE}</p>
    </CyberCard>
  );
}

export function AuditLog() {
  const events = useAsync(() => api.audit(), []);
  const [filter, setFilter] = useState<LedgerFilter>(EMPTY_LEDGER_FILTER);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const all = events.data ?? null;
  const rows = all ? filterLedger(all, filter) : [];
  const tally = all ? ledgerTally(all) : null;
  const categories = all ? ledgerCategories(all) : [];
  const selected = rows.find((e) => e.id === selectedId) ?? null;

  function set<K extends keyof LedgerFilter>(key: K, value: LedgerFilter[K]) {
    setFilter((f) => ({ ...f, [key]: value }));
  }

  return (
    <div className="gov">
      <CyberGridBackground intensity="subtle" className="gov-bg" />
      <div className="gov-head">
        <h1>Audit Ledger</h1>
        <p className="gov-sub">{LEDGER_INTRO}</p>
      </div>

      {events.error !== null && events.error !== undefined && (
        <div className="error-box" role="alert">
          {LEDGER_UNAVAILABLE}
        </div>
      )}

      {events.loading && !all ? (
        <CyberCard>
          <Skeleton lines={6} />
        </CyberCard>
      ) : all ? (
        <>
          <div className="gov-tally">
            <MetricTile
              label="Recorded events"
              value={String(tally!.total)}
              detail="loaded from the append-only ledger"
            />
            <MetricTile
              label="Refusals / failures"
              value={String(tally!.flagged)}
              detail="non-success outcomes — recorded, never hidden"
              tone={tally!.flagged > 0 ? "danger" : "default"}
            />
            <MetricTile
              label="Decision records"
              value={String(tally!.decisions)}
              detail="approvals, rejections, refusals, revocations, denials"
            />
          </div>

          <CyberCard heading="Ledger">
            <div className="gov-filters">
              <CyberSelect
                label="Outcome"
                value={filter.outcome}
                onChange={(e) => set("outcome", e.target.value as OutcomeFilter)}
                options={[
                  { value: "all", label: "All outcomes" },
                  { value: "flagged", label: "Refusals / failures only" },
                  { value: "success", label: "Success only" },
                ]}
              />
              <CyberSelect
                label="Category"
                value={filter.category}
                onChange={(e) => set("category", e.target.value)}
                options={[
                  { value: "all", label: "All categories" },
                  ...categories.map((c) => ({ value: c, label: c })),
                ]}
              />
              <CyberInput
                label="Search"
                value={filter.query}
                onChange={(e) => set("query", e.target.value)}
                placeholder="action, resource, actor…"
              />
            </div>
            <p className="gov-note">
              Showing {rows.length} of {tally!.total} recorded events. Filters
              never delete — the ledger is append-only.
            </p>
            {rows.length === 0 ? (
              <EmptyState title="No events match the current filters">
                Clear the filters to see every recorded event.
              </EmptyState>
            ) : (
              <CyberTable
                label="Audit events"
                head={["Time (UTC)", "Action", "Resource", "Actor", "Outcome"]}
                caption={`${rows.length} of ${tally!.total} recorded events shown`}
              >
                {rows.map((e) => (
                  <tr
                    key={e.id}
                    className={e.id === selectedId ? "gov-row--selected" : undefined}
                  >
                    <td className="muted mono">{ledgerTimestamp(e.created_at)}</td>
                    <td>
                      <button
                        type="button"
                        className="gov-row-btn mono"
                        onClick={() =>
                          setSelectedId((cur) => (cur === e.id ? null : e.id))
                        }
                        aria-expanded={e.id === selectedId}
                        aria-controls="gov-event-detail"
                      >
                        <AuditLedgerIcon size={13} />
                        {e.action}
                      </button>
                    </td>
                    <td className="muted mono" title={e.resource_id ?? undefined}>
                      {e.resource_type}
                      {e.resource_id ? `/${shortId(e.resource_id)}` : ""}
                    </td>
                    <td className="muted mono" title={e.actor}>
                      {shortId(e.actor)}
                    </td>
                    <td>
                      <StatusBadge state={e.outcome} domain="audit" />
                    </td>
                  </tr>
                ))}
              </CyberTable>
            )}
          </CyberCard>

          <div id="gov-event-detail">
            {selected && <EventDetail event={selected} />}
          </div>

          <SafetyNotice role="note" tone="info">
            Recording an event proves the event was recorded — it does not imply
            the underlying operation executed anything beyond what its own
            surface states.
          </SafetyNotice>
        </>
      ) : null}
    </div>
  );
}
