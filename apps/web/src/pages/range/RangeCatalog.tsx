import "./range.css";

import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../../api/client";
import { CyberGridBackground } from "../../components/backgrounds";
import {
  CyberButton,
  CyberCard,
  CyberInput,
  CyberTable,
  DataPanel,
  EmptyState,
  SafetyNotice,
  StatusBadge,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { RANGE_PHASE_LABEL } from "./range-lifecycle";
import {
  CATALOG_INTRO,
  VULNERABLE_SOFTWARE_NOTE,
  estimatedDuration,
  filterBlueprints,
  rangeBlueprints,
  rangeSummaries,
} from "./range-view";

/**
 * Page 1 — Range Catalog.
 *
 * Two live reads: the blueprints (`GET /range-templates`) and the ranges that already exist
 * (`GET /ranges`, including destroyed ones so the history stays visible). Nothing is hardcoded.
 */
export function RangeCatalog() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  const catalog = useAsync(() => api.listRangeTemplates(), []);
  const ranges = useAsync(() => api.listRanges({ includeDestroyed: true }), []);

  const blueprints = useMemo(
    () => (catalog.data ? rangeBlueprints(catalog.data) : []),
    [catalog.data],
  );
  const visible = useMemo(() => filterBlueprints(blueprints, query), [blueprints, query]);
  const existing = useMemo(
    () => (ranges.data ? rangeSummaries(ranges.data) : []),
    [ranges.data],
  );

  return (
    <div className="rng">
      <CyberGridBackground intensity="subtle" className="rng-bg" />

      <div className="rng-head">
        <div>
          <h1>Range catalog</h1>
          <p className="rng-sub">{CATALOG_INTRO}</p>
        </div>
      </div>

      <SafetyNotice role="note" tone="warn">
        {VULNERABLE_SOFTWARE_NOTE}
      </SafetyNotice>

      <CyberCard heading="Blueprints" headingLevel={2}>
        <div className="rng-search">
          <CyberInput
            label="Search blueprints"
            placeholder="Name, slug, summary or difficulty"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        <DataPanel
          state={catalog}
          isEmpty={() => blueprints.length === 0}
          empty={<EmptyState title="No blueprints available">The range catalog is empty.</EmptyState>}
        >
          {() =>
            visible.length === 0 ? (
              <EmptyState title="No blueprint matches that search">
                Clear the search to see all {blueprints.length} blueprints.
              </EmptyState>
            ) : (
              <div className="rng-grid">
                {visible.map((b) => (
                  <CyberCard key={b.slug} heading={b.name}>
                    <p className="rng-sub">{b.summary}</p>
                    <div className="rng-meta">
                      <span className="mono">{b.slug}</span>
                      <span>{b.difficulty}</span>
                      <span>
                        {b.targetCount} target{b.targetCount === 1 ? "" : "s"}
                      </span>
                      <span>
                        {b.challengeCount} challenge{b.challengeCount === 1 ? "" : "s"} ·{" "}
                        {b.totalPoints} pts
                      </span>
                      <span>{estimatedDuration(b.estimatedDeploySeconds)} to deploy</span>
                    </div>
                    {/* The template's own warning, rendered always and never suppressed. */}
                    {b.warning !== "" && (
                      <SafetyNotice role="note" tone="warn">
                        {b.warning}
                      </SafetyNotice>
                    )}
                    <div className="rng-card-foot">
                      <CyberButton
                        variant="primary"
                        onClick={() => navigate(`/ranges/new?template=${b.slug}`)}
                      >
                        Create range
                      </CyberButton>
                      <span className="muted mono">{b.provider}</span>
                    </div>
                  </CyberCard>
                ))}
              </div>
            )
          }
        </DataPanel>
      </CyberCard>

      <CyberCard heading="Your ranges" headingLevel={2}>
        <DataPanel
          state={ranges}
          isEmpty={() => existing.length === 0}
          empty={
            <EmptyState title="No ranges yet">
              Choose a blueprint above to create your first range.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Ranges"
              head={["Range", "Blueprint", "State", "Access", "Created"]}
              caption={`${existing.length} range${existing.length === 1 ? "" : "s"} · state is recorded by the control plane`}
            >
              {existing.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Link to={`/ranges/${r.id}`}>{r.name}</Link>
                  </td>
                  <td className="muted">{r.templateName}</td>
                  <td>
                    <span className="rng-identity">
                      <StatusBadge state={r.lifecycle.phase} domain="range" />
                      <span className="muted">{RANGE_PHASE_LABEL[r.lifecycle.phase]}</span>
                    </span>
                  </td>
                  <td className="muted">
                    {/* Reachability is the server's observation, so an absent access list reads as
                        "nothing to show" rather than "nothing is reachable". */}
                    {r.accessCount === 0
                      ? "—"
                      : `${r.reachableCount} of ${r.accessCount} responded`}
                  </td>
                  <td className="muted mono">{r.createdAt.slice(0, 10)}</td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>
    </div>
  );
}
