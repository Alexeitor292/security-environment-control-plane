import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import ReactFlow, {
  Background,
  Controls,
  type Edge,
  type Node,
} from "reactflow";

import { api } from "../api/client";
import type { TeamTopology, TopologyNode } from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";

function nodeLabel(n: TopologyNode) {
  return (
    <div className={`node-card ${n.data.kind}`}>
      <div className="title">{n.data.label}</div>
      {n.data.cidr && <div className="mono">{n.data.cidr}</div>}
      {n.data.ip && <div className="mono">{n.data.ip}</div>}
      {n.data.role && <div className="muted">{n.data.role}</div>}
    </div>
  );
}

/** Deterministic layout: networks on a middle lane, hosts on the top lane. */
function layout(topo: TeamTopology): { nodes: Node[]; edges: Edge[] } {
  const networks = topo.nodes.filter((n) => n.data.kind === "network");
  const hosts = topo.nodes.filter((n) => n.data.kind !== "network");

  const nodes: Node[] = [];
  networks.forEach((n, i) => {
    nodes.push({
      id: n.id,
      position: { x: 160 + i * 320, y: 240 },
      data: { label: nodeLabel(n) },
      className: `rf-${n.data.kind}`,
      style: { background: "transparent", border: "none", padding: 0, width: "auto" },
    });
  });
  hosts.forEach((n, i) => {
    nodes.push({
      id: n.id,
      position: { x: 40 + i * 220, y: 40 },
      data: { label: nodeLabel(n) },
      className: `rf-${n.data.kind}`,
      style: { background: "transparent", border: "none", padding: 0, width: "auto" },
    });
  });

  const edges: Edge[] = topo.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.data.kind,
    animated: e.data.kind === "monitors",
    style: { stroke: e.data.kind === "monitors" ? "#4c9aff" : "#3fb950" },
  }));

  return { nodes, edges };
}

export function TopologyView() {
  const { exerciseId = "" } = useParams();
  const topo = useAsync(() => api.exerciseTopology(exerciseId), [exerciseId]);
  const [active, setActive] = useState(0);

  if (topo.error) return <div className="error-box">{topo.error}</div>;
  if (!topo.data) return <p className="muted">Loading topology…</p>;
  if (topo.data.length === 0)
    return <p className="muted">No deployed instances yet.</p>;

  const current = topo.data[Math.min(active, topo.data.length - 1)];
  const { nodes, edges } = layout(current);

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Per-team topology</h2>
        <Link to={`/exercises/${exerciseId}`}>← Back to exercise</Link>
      </div>
      <p className="muted">
        Each team sees only its own isolated environment instance. Networks have
        per-team CIDRs and there are no edges between teams.
      </p>

      <div className="tabs">
        {topo.data.map((t, i) => (
          <button
            key={t.instance_id}
            className={i === active ? "secondary active" : "secondary"}
            onClick={() => setActive(i)}
          >
            {t.team_ref} <StatusBadge state={t.lifecycle_state} />
          </button>
        ))}
      </div>

      <div className="topology">
        <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
          <Background />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  );
}
