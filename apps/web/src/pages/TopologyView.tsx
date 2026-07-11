import "./environments.css";

import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import ReactFlow, {
  Background,
  Controls,
  type Edge,
  type Node,
} from "reactflow";

import { api } from "../api/client";
import type { TeamTopology } from "../api/types";
import { SECP_ICONS } from "../components/icons";
import {
  CyberCard,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  TabRail,
  tabId,
  tabPanelId,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  TOPOLOGY_DECLARATIVE_NOTE,
  edgeLegendLabel,
  nodeIconName,
  nodeKindClass,
  topologyGraph,
  topologySummaryText,
  type TopologyNodeVM,
} from "./environments-view";

function NodeCard({ vm }: { vm: TopologyNodeVM }) {
  const Icon = SECP_ICONS[nodeIconName(vm.kind)];
  return (
    <div className={`env-node env-node--${nodeKindClass(vm.kind)}`}>
      <span className="env-node__head">
        <Icon size={14} />
        {vm.label}
      </span>
      {vm.cidr && <span className="env-node__meta">{vm.cidr}</span>}
      {vm.ip && <span className="env-node__meta">{vm.ip} (planned)</span>}
      {vm.role && <span className="env-node__meta">{vm.role}</span>}
    </div>
  );
}

/** Build React Flow props from the pure graph view-model. Edges are static —
 *  a declarative plan preview never animates traffic. */
function flowProps(topo: TeamTopology): { nodes: Node[]; edges: Edge[] } {
  const g = topologyGraph(topo);
  return {
    nodes: g.nodes.map((vm) => ({
      id: vm.id,
      position: { x: vm.x, y: vm.y },
      data: { label: <NodeCard vm={vm} /> },
      style: { background: "transparent", border: "none", padding: 0, width: "auto" },
    })),
    edges: g.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.kind,
      animated: false,
      // Unknown declared kinds get their own neutral style — never coerced
      // into looking like a known relationship.
      className: `env-edge env-edge--${
        e.kind === "monitors" ? "monitors" : e.kind === "attached" ? "attached" : "unknown"
      }`,
    })),
  };
}

const LEGEND: { kind: string; label: string }[] = [
  { kind: "attacker", label: "attacker host" },
  { kind: "target", label: "target host" },
  { kind: "sensor", label: "sensor" },
  { kind: "network", label: "network segment" },
];

export function TopologyView() {
  const { exerciseId = "" } = useParams();
  const topo = useAsync(() => api.exerciseTopology(exerciseId), [exerciseId]);
  const [active, setActive] = useState(0);

  const data = topo.data ?? null;
  const current = data ? data[Math.min(active, data.length - 1)] : null;
  const props = useMemo(() => (current ? flowProps(current) : null), [current]);

  if (topo.error !== null && topo.error !== undefined)
    return (
      <div className="error-box" role="alert">
        Topology unavailable.
      </div>
    );
  if (!data)
    return (
      <CyberCard>
        <Skeleton lines={5} />
      </CyberCard>
    );

  return (
    <div className="env">
      <div className="env-head">
        <div>
          <h1>Topology Preview</h1>
          <p className="env-sub">
            Each team sees only its own isolated environment instance; networks
            have per-team CIDRs and there are no links between teams.
          </p>
        </div>
        <Link to={`/exercises/${exerciseId}`}>← Back to exercise</Link>
      </div>

      <SafetyNotice role="note" tone="info">
        {TOPOLOGY_DECLARATIVE_NOTE}
      </SafetyNotice>

      {data.length === 0 ? (
        <CyberCard>
          <p className="muted">
            No team instances yet — the preview appears after deployment work
            creates them.
          </p>
        </CyberCard>
      ) : (
        <>
          <TabRail
            aria-label="Teams"
            idBase="env-topo"
            tabs={data.map((t) => ({ id: t.instance_id, label: t.team_ref }))}
            active={current?.instance_id ?? data[0].instance_id}
            onSelect={(id) => {
              const idx = data.findIndex((t) => t.instance_id === id);
              if (idx >= 0) setActive(idx);
            }}
          />

          {current && (
            <div
              role="tabpanel"
              id={tabPanelId("env-topo", current.instance_id)}
              aria-labelledby={tabId("env-topo", current.instance_id)}
              style={{ display: "grid", gap: 14 }}
            >
              <div className="env-hashline">
                <StatusBadge state={current.lifecycle_state} domain="lifecycle" />
                <span className="env-legend">
                  {LEGEND.map((l) => (
                    <span className="env-legend__item" key={l.kind}>
                      <span
                        className={`env-legend__swatch env-legend__swatch--${l.kind}`}
                      />
                      {l.label}
                    </span>
                  ))}
                  <span className="env-legend__item">
                    edges: {edgeLegendLabel("attached")} · {edgeLegendLabel("monitors")}
                  </span>
                </span>
              </div>

              {props && (
                <div className="env-topology">
                  <ReactFlow
                    nodes={props.nodes}
                    edges={props.edges}
                    fitView
                    nodesDraggable={false}
                    nodesConnectable={false}
                    elementsSelectable={false}
                    proOptions={{ hideAttribution: true }}
                  >
                    <Background />
                    <Controls showInteractive={false} />
                  </ReactFlow>
                </div>
              )}

              <CyberCard surface="well" heading="Planned topology (text summary)">
                <p className="env-topology-summary">{topologySummaryText(current)}</p>
              </CyberCard>
            </div>
          )}
        </>
      )}
    </div>
  );
}
