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
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { UNPROVEN_NOTE, teardownSummary } from "./range-view";

/**
 * Page 8 — Evidence and Event Timeline.
 *
 * Two live reads: the append-only range event log, and the teardown evidence. The evidence half is
 * the reason this page matters — it is where "we could not prove the residue is gone" is stated in
 * full rather than compressed into a status badge.
 */
export function RangeTimeline() {
  const { range } = useRange();
  const [query, setQuery] = useState("");
  const [problemsOnly, setProblemsOnly] = useState(false);

  const events = useAsync(
    () => api.listRangeEvents(range.id),
    [range.id, range.updated_at],
  );
  const evidence = useAsync(
    () => api.listTeardownEvidence(range.id).catch(() => []),
    [range.id, range.updated_at],
  );

  // Newest first for reading; the server returns oldest first for incremental fetch.
  const all = useMemo(
    () => [...(events.data ?? [])].sort((a, b) => b.sequence - a.sequence),
    [events.data],
  );
  const problems = all.filter((e) => e.level !== "info").length;

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all.filter((e) => {
      if (problemsOnly && e.level === "info") return false;
      if (!q) return true;
      return `${e.message} ${e.kind} ${e.level}`.toLowerCase().includes(q);
    });
  }, [all, query, problemsOnly]);

  const teardowns = useMemo(
    () => (evidence.data ?? []).map(teardownSummary),
    [evidence.data],
  );

  return (
    <div className="rng">
      <div className="rng-grid">
        <MetricTile
          label="Recorded events"
          value={events.data === null ? "—" : all.length}
          detail={events.data === null ? "Event log unavailable." : "Append-only, server-owned"}
        />
        <MetricTile
          label="Warnings and errors"
          value={events.data === null ? "—" : problems}
          tone={problems > 0 ? "warn" : "default"}
          detail="Events above info level"
        />
      </div>

      {teardowns.length > 0 && (
        <CyberCard heading="Teardown evidence" headingLevel={2}>
          {teardowns.map((t) => (
            <div key={t.observedAt} className="rng-evidence">
              <div className="rng-identity">
                <StatusBadge state={t.verdict} domain="range-operation" />
                <strong>{t.headline}</strong>
                <span className="rng-recorded">{t.observedAt.slice(0, 19).replace("T", " ")}</span>
              </div>
              <p className="rng-sub">{t.detail}</p>
              <div className="rng-meta">
                <span>{t.expected} expected</span>
                <span>{t.removedConfirmed} confirmed removed</span>
                <span>{t.stillPresent} still present</span>
                {/* Never folded into either of the two counts above. */}
                <span>{t.unprovenCount} unproven</span>
              </div>
              {!t.provedClean && (
                <SafetyNotice role="alert" tone="warn">
                  {UNPROVEN_NOTE}
                </SafetyNotice>
              )}
              {t.resources.length > 0 && (
                <CyberTable
                  label="Teardown resources"
                  head={["Resource", "Kind", "Verdict", "Detail"]}
                  caption="Per-resource verdict from the teardown probe"
                >
                  {t.resources.map((r) => (
                    <tr key={`${r.kind}:${r.name}`}>
                      <td className="mono">{r.name}</td>
                      <td className="muted">{r.kind}</td>
                      <td>
                        <StatusBadge
                          state={r.verdict === "removed" ? "removed" : r.verdict}
                          domain="range-operation"
                        />
                      </td>
                      <td className="muted">{r.detail ?? "—"}</td>
                    </tr>
                  ))}
                </CyberTable>
              )}
            </div>
          ))}
        </CyberCard>
      )}

      <CyberCard heading="Event timeline" headingLevel={2}>
        <div className="rng-search">
          <CyberInput
            label="Filter events"
            placeholder="Message, kind or level"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <CyberButton
            variant={problemsOnly ? "primary" : undefined}
            aria-pressed={problemsOnly}
            onClick={() => setProblemsOnly((v) => !v)}
          >
            {problemsOnly ? "Showing problems only" : "Show problems only"}
          </CyberButton>
          <CyberButton onClick={() => void events.reload()}>Refresh</CyberButton>
        </div>

        <DataPanel
          state={events}
          isEmpty={() => all.length === 0}
          empty={
            <EmptyState title="No events recorded for this range">
              The timeline shows only what the server recorded — it never infers an event from the
              current state.
            </EmptyState>
          }
        >
          {() =>
            visible.length === 0 ? (
              <EmptyState title="No event matches those filters">
                {all.length} event{all.length === 1 ? "" : "s"} recorded for this range.
              </EmptyState>
            ) : (
              <CyberTable
                label="Range event timeline"
                head={["#", "When", "Event", "Kind", "Level"]}
                caption={`${visible.length} of ${all.length} recorded event${all.length === 1 ? "" : "s"} · append-only, newest first`}
              >
                {visible.map((e) => (
                  <tr key={e.id}>
                    <td className="muted mono">{e.sequence}</td>
                    <td className="muted mono">{e.occurred_at.slice(0, 19).replace("T", " ")}</td>
                    {/* `message` is the display text; `kind` is a stable machine string. */}
                    <td>{e.message}</td>
                    <td className="muted mono">{e.kind}</td>
                    <td>
                      <StatusBadge state={e.level} domain="range-event" />
                    </td>
                  </tr>
                ))}
              </CyberTable>
            )
          }
        </DataPanel>
      </CyberCard>
    </div>
  );
}
