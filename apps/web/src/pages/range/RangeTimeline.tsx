import "./range.css";

import { useMemo, useState } from "react";

import { api } from "../../api/client";
import {
  CyberButton,
  CyberCard,
  CyberInput,
  CyberTable,
  DataPanel,
  EmptyState,
  MetricTile,
  SafetyNotice,
  StatusBadge,
  shortId,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { detailFields, hiddenFieldsNote, ledgerTimestamp, OPERATOR_SAFE_NOTE } from "../audit-view";
import { useRange } from "./RangeLayout";
import { timelineEntries, timelineTally } from "./range-view";

/**
 * Page 8 — Evidence and Event Timeline.
 *
 * The range-scoped slice of the append-only audit ledger, read live from `GET /api/v1/audit`.
 * Event detail renders through the SAME operator-safe allowlist the global ledger uses
 * (`audit-view.detailFields`), so free-form backend internals and secret-shaped values are withheld
 * here exactly as they are there — this page does not get its own, looser rules.
 */
export function RangeTimeline() {
  const { range } = useRange();
  const [query, setQuery] = useState("");
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const events = useAsync(
    () => api.audit(range.id),
    [range.id, range.lifecycle_state],
  );

  const all = useMemo(() => timelineEntries(events.data ?? []), [events.data]);
  const tally = useMemo(() => timelineTally(all), [all]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all.filter((e) => {
      if (flaggedOnly && !e.flagged) return false;
      if (!q) return true;
      return `${e.action} ${e.actor} ${e.outcome} ${e.resourceType}`.toLowerCase().includes(q);
    });
  }, [all, query, flaggedOnly]);

  const byId = useMemo(
    () => new Map((events.data ?? []).map((e) => [e.id, e])),
    [events.data],
  );

  return (
    <div className="rng">
      <div className="rng-grid">
        <MetricTile
          label="Recorded events"
          value={events.data === null ? "—" : tally.total}
          detail={events.data === null ? "Ledger unavailable." : "Scoped to this range"}
        />
        <MetricTile
          label="Flagged"
          value={events.data === null ? "—" : tally.flagged}
          tone={tally.flagged > 0 ? "warn" : "default"}
          detail="Any outcome other than success"
        />
      </div>

      <CyberCard heading="Event timeline" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {OPERATOR_SAFE_NOTE}
        </SafetyNotice>

        <div className="rng-search">
          <CyberInput
            label="Filter events"
            placeholder="Action, actor or outcome"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <CyberButton
            variant={flaggedOnly ? "primary" : undefined}
            aria-pressed={flaggedOnly}
            onClick={() => setFlaggedOnly((v) => !v)}
          >
            {flaggedOnly ? "Showing flagged only" : "Show flagged only"}
          </CyberButton>
          <CyberButton onClick={() => void events.reload()}>Refresh</CyberButton>
        </div>

        <DataPanel
          state={events}
          isEmpty={() => all.length === 0}
          empty={
            <EmptyState title="No events recorded for this range">
              Nothing has been recorded against this range yet. The timeline shows only what the
              ledger holds — it never infers an event from the current state.
            </EmptyState>
          }
        >
          {() =>
            visible.length === 0 ? (
              <EmptyState title="No event matches those filters">
                {tally.total} event{tally.total === 1 ? "" : "s"} recorded for this range.
              </EmptyState>
            ) : (
              <CyberTable
                label="Range event timeline"
                head={["When", "Action", "Outcome", "Actor", "Resource", ""]}
                caption={`${visible.length} of ${tally.total} recorded event${tally.total === 1 ? "" : "s"} · append-only ledger, newest first`}
              >
                {visible.map((e) => {
                  const raw = byId.get(e.id);
                  const isOpen = expanded === e.id;
                  const detail = raw ? detailFields(raw) : { fields: [], hiddenCount: 0 };
                  return (
                    <tr key={e.id}>
                      <td className="muted mono">{ledgerTimestamp(e.at)}</td>
                      <td className="mono">{e.action}</td>
                      <td>
                        <StatusBadge state={e.outcome} domain="audit" />
                      </td>
                      <td className="muted">{e.actor}</td>
                      <td className="muted mono" title={e.resourceId ?? undefined}>
                        {e.resourceId === null ? e.resourceType : shortId(e.resourceId)}
                      </td>
                      <td>
                        <CyberButton
                          size="sm"
                          aria-expanded={isOpen}
                          onClick={() => setExpanded(isOpen ? null : e.id)}
                        >
                          {isOpen ? "Hide" : "Evidence"}
                        </CyberButton>
                        {isOpen && (
                          <div className="rng-meta">
                            {detail.fields.length === 0 ? (
                              <span className="muted">
                                No displayable recorded fields for this event.
                              </span>
                            ) : (
                              detail.fields.map((f) => (
                                <span key={f.key} className={f.mono ? "mono" : undefined}>
                                  <strong>{f.label}:</strong> {f.value}
                                </span>
                              ))
                            )}
                            {detail.hiddenCount > 0 && (
                              <span className="muted">
                                {hiddenFieldsNote(detail.hiddenCount)}
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </CyberTable>
            )
          }
        </DataPanel>
      </CyberCard>
    </div>
  );
}
