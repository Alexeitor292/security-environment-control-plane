import "./range.css";

import { useMemo } from "react";

import { api } from "../../api/client";
import {
  CyberCard,
  CyberTable,
  DataPanel,
  EmptyState,
  MetricTile,
  SafetyNotice,
  StatusBadge,
  shortId,
} from "../../components/ui";
import { useAsync } from "../../hooks";
import { useRange } from "./RangeLayout";
import { RANGE_PHASE_LABEL, hasLiveInfrastructure } from "./range-lifecycle";
import {
  ACCESS_IS_DECLARED_NOTE,
  EXECUTION_POSTURE_NOTE,
  accessTargets,
  teamInstanceRows,
} from "./range-view";

/**
 * Page 4 — Range Overview, including the access details for reaching targets.
 *
 * Instances and topology are both live reads. Addresses shown here are the ones RECORDED in the
 * plan; the page states that plainly rather than implying it has probed anything.
 */
export function RangeOverview() {
  const { range, lifecycle } = useRange();

  // Re-read when the recorded state changes so a completed deploy fills these in without a
  // manual refresh.
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
  const targets = useMemo(() => accessTargets(topologies), [topologies]);
  const live = hasLiveInfrastructure(lifecycle.phase);

  return (
    <div className="rng">
      <div className="rng-grid">
        <MetricTile label="Phase" value={RANGE_PHASE_LABEL[lifecycle.phase]} detail={`recorded: ${lifecycle.recorded}`} />
        <MetricTile
          label="Teams"
          value={instances.data === null ? "—" : teams.length}
          detail={
            instances.data === null
              ? "Instance list unavailable."
              : `${range.team_count} declared by the definition`
          }
        />
        <MetricTile
          label="Targets"
          value={topology.data === null ? "—" : targets.length}
          detail={
            topology.data === null
              ? "Topology unavailable."
              : "Declared in the plan across all teams"
          }
        />
      </div>

      <CyberCard heading="Team instances" headingLevel={2}>
        <DataPanel
          state={instances}
          isEmpty={() => teams.length === 0}
          empty={
            <EmptyState title="No team instances yet">
              Instances are created when the range is deployed. This range has not produced any
              yet.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Team instances"
              head={["Team", "Instance", "Phase", "Recorded", "Provider", "Targets"]}
              caption={`${teams.length} team instance${teams.length === 1 ? "" : "s"} · phase is projected from each instance's own recorded state`}
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
                  <td className="muted mono">{t.lifecycle.recorded}</td>
                  <td className="muted">{t.provider}</td>
                  <td>{t.targetCount}</td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <CyberCard heading="Access targets" headingLevel={2}>
        <SafetyNotice role="note" tone="info">
          {ACCESS_IS_DECLARED_NOTE}
        </SafetyNotice>

        {!live && (
          <SafetyNotice role="status" tone="warn">
            This range is {RANGE_PHASE_LABEL[lifecycle.phase].toLowerCase()}. Any addresses below
            are declared in the plan and are not reachable in this phase.
          </SafetyNotice>
        )}

        <DataPanel
          state={topology}
          isEmpty={() => targets.length === 0}
          empty={
            <EmptyState title="No targets declared">
              The plan for this range declares no reachable hosts, or the topology has not been
              produced yet.
            </EmptyState>
          }
        >
          {() => (
            <CyberTable
              label="Access targets"
              head={["Team", "Target", "Kind", "Role", "Address", "Network"]}
              caption={`${targets.length} declared target${targets.length === 1 ? "" : "s"} · addresses are from the recorded plan, not from a probe`}
            >
              {targets.map((t) => (
                <tr key={`${t.instanceId}:${t.nodeId}`}>
                  <td>{t.teamRef}</td>
                  <td>{t.label}</td>
                  <td className="muted">{t.kind}</td>
                  <td className="muted">{t.role ?? "—"}</td>
                  <td className="mono">{t.ip ?? "not declared"}</td>
                  <td className="muted mono">{t.network ?? "—"}</td>
                </tr>
              ))}
            </CyberTable>
          )}
        </DataPanel>
      </CyberCard>

      <SafetyNotice role="note" tone="info">
        {EXECUTION_POSTURE_NOTE}
      </SafetyNotice>
    </div>
  );
}
