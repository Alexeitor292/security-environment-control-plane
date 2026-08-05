import "./range.css";

import { useMemo } from "react";

import { api } from "../../api/client";
import {
  CyberCard,
  CyberTable,
  DataPanel,
  EmptyState,
  SafetyNotice,
  StatusBadge,
  shortId,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { PendingContractPanel } from "./PendingContractPanel";
import { useRange } from "./RangeLayout";
import { accessTargets, teamInstanceRows } from "./range-view";

/**
 * Page 6 — Team Management.
 *
 * PARTIALLY WIRED, and the page says which half is which.
 *
 * The teams themselves are real: the control plane creates one isolated instance per team from the
 * definition's team count, and this reads that list live along with each team's declared targets.
 *
 * What does NOT exist is team MEMBERSHIP — there is no roster, no invitation and no assignment
 * endpoint, so there is nothing to add a competitor to. That half renders as an explicit missing
 * surface rather than as an empty roster table, which would imply the teams have no members rather
 * than that members are not a thing this build models.
 */
export function TeamManagement() {
  const { range } = useRange();

  const instances = useAsync(
    () => api.listInstances(range.id),
    [range.id, range.lifecycle_state],
  );
  const topology = useAsync(
    () => api.exerciseTopology(range.id).catch(() => []),
    [range.id, range.lifecycle_state],
  );

  const topologies = useMemo(() => topology.data ?? [], [topology.data]);
  const teams = useMemo(
    () => (instances.data ? teamInstanceRows(instances.data, topologies) : []),
    [instances.data, topologies],
  );
  const targetsByInstance = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const t of accessTargets(topologies)) {
      map.set(t.instanceId, [...(map.get(t.instanceId) ?? []), t.label]);
    }
    return map;
  }, [topologies]);

  return (
    <div className="rng">
      <CyberCard heading="Teams" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          Teams are created by the control plane from the definition&rsquo;s declared team count —
          one isolated instance each. This list is read live from the range&rsquo;s instances.
        </SafetyNotice>

        <DataPanel
          state={instances}
          isEmpty={() => teams.length === 0}
          empty={
            <EmptyState title="No teams yet">
              The definition declares {range.team_count} team
              {range.team_count === 1 ? "" : "s"}, but no instances exist yet. They are created
              when the range is deployed.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Teams"
              head={["Team", "Instance", "Phase", "Targets", "Isolation"]}
              caption={`${teams.length} team${teams.length === 1 ? "" : "s"} · each team gets its own isolated instance`}
            >
              {teams.map((t) => (
                <tr key={t.instanceId}>
                  <td>{t.teamRef}</td>
                  <td className="muted mono" title={t.instanceRef}>
                    {shortId(t.instanceRef)}
                  </td>
                  <td>
                    <StatusBadge state={t.lifecycle.phase} domain="range" />
                  </td>
                  <td className="muted">
                    {(targetsByInstance.get(t.instanceId) ?? []).join(", ") || "none declared"}
                  </td>
                  <td className="muted">per-team instance</td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <PendingContractPanel
        heading="Team membership"
        title="Team rosters are not modelled in this build"
        body="The control plane creates teams, but it has no concept of a person belonging to one: there is no roster, invitation or assignment endpoint. This is shown as a missing surface rather than an empty roster, because an empty table would say these teams have no members — the truth is that membership is not something this build records at all."
        endpoints={[
          "GET/POST /api/v1/ranges/{id}/teams — team roster and membership management",
          "POST /api/v1/ranges/{id}/teams/{team}/members — assign a competitor to a team",
        ]}
      />
    </div>
  );
}
