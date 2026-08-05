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
  shortId,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { RANGE_PHASE_LABEL } from "./range-lifecycle";
import {
  CATALOG_INTRO,
  EXECUTION_POSTURE_NOTE,
  filterBlueprints,
  rangeBlueprints,
  rangeSummaries,
} from "./range-view";
import type { Version } from "../../api/types";

/**
 * Page 1 — Range Catalog.
 *
 * Two live reads: the blueprints an operator can instantiate (templates + their immutable
 * versions), and the ranges that already exist (exercises). Both come from the API; nothing on this
 * page is seeded, sampled or hardcoded.
 *
 * Versions are fetched per template because the API exposes them per template. That is N+1 requests
 * over a catalog that is small by construction, and it is done with `allSettled` so ONE failing
 * template degrades that single row into "versions could not be loaded" instead of emptying the
 * whole catalog.
 */
export function RangeCatalog() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  const catalog = useAsync(async () => {
    const templates = await api.listTemplates();
    const results = await Promise.allSettled(
      templates.map(async (t) => [t.id, await api.listVersions(t.id)] as const),
    );
    const versions = new Map<string, readonly Version[]>();
    for (const r of results) {
      if (r.status === "fulfilled") versions.set(r.value[0], r.value[1]);
    }
    return { templates, versions };
  }, []);

  const ranges = useAsync(() => api.listExercises(), []);

  const blueprints = useMemo(
    () =>
      catalog.data ? rangeBlueprints(catalog.data.templates, catalog.data.versions) : [],
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

      <SafetyNotice role="note" tone="info">
        {EXECUTION_POSTURE_NOTE}
      </SafetyNotice>

      <CyberCard heading="Blueprints" headingLevel={2}>
        <div className="rng-search">
          <CyberInput
            label="Search blueprints"
            placeholder="Name, slug or description"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        <DataPanel
          state={catalog}
          isEmpty={() => blueprints.length === 0}
          empty={
            <EmptyState title="No blueprints available">
              Your organization has no environment definitions yet. Create one in the{" "}
              <Link to="/templates">environment library</Link>.
            </EmptyState>
          }
        >
          {() =>
            visible.length === 0 ? (
              <EmptyState title="No blueprint matches that search">
                Clear the search to see all {blueprints.length} blueprints.
              </EmptyState>
            ) : (
              <div className="rng-grid">
                {visible.map((b) => (
                  <CyberCard key={b.templateId} heading={b.name}>
                    <p className="rng-sub">{b.description || "No description recorded."}</p>
                    <div className="rng-meta">
                      <span className="mono">{b.slug}</span>
                      <span>
                        {b.versionCount} version{b.versionCount === 1 ? "" : "s"}
                      </span>
                      {b.latestContentHash !== null && (
                        <span className="mono" title={b.latestContentHash}>
                          {shortId(b.latestContentHash)}
                        </span>
                      )}
                    </div>
                    <div className="rng-card-foot">
                      {b.deployable ? (
                        <CyberButton
                          variant="primary"
                          onClick={() => navigate(`/ranges/new?template=${b.templateId}`)}
                        >
                          Create range
                        </CyberButton>
                      ) : (
                        <span className="muted">{b.unavailableReason}</span>
                      )}
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
              head={["Range", "Phase", "Recorded", "Teams", "Created"]}
              caption={`${existing.length} range${existing.length === 1 ? "" : "s"} · phase is projected from the recorded control-plane state`}
            >
              {existing.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Link to={`/ranges/${r.id}`}>{r.name}</Link>
                  </td>
                  <td>
                    <span className="rng-identity">
                      <StatusBadge state={r.lifecycle.phase} domain="range" />
                      <span className="muted">{RANGE_PHASE_LABEL[r.lifecycle.phase]}</span>
                    </span>
                  </td>
                  <td className="muted mono">{r.lifecycle.recorded}</td>
                  <td>{r.teamCount}</td>
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
