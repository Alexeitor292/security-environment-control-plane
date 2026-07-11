import "./environments.css";

import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
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
import { TOPOLOGY_DECLARATIVE_NOTE } from "./environments-view";
import { TopologyWorkspace } from "./TopologyWorkspace";

export function TopologyView() {
  const { exerciseId = "" } = useParams();
  const topo = useAsync(() => api.exerciseTopology(exerciseId), [exerciseId]);
  const [active, setActive] = useState(0);

  const data = topo.data ?? null;
  const current = data ? data[Math.min(active, data.length - 1)] : null;

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
          <h1>Topology Workspace</h1>
          <p className="env-sub">
            Each team&apos;s view is filtered to its own environment instance —
            the projection contains no cross-team links. Per-team CIDRs are
            declared; declared segmentation is not verified isolation.
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
            No team instances yet — the workspace appears after deployment work
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
                <span className="muted">
                  recorded simulator state · not real infrastructure
                </span>
              </div>
              <TopologyWorkspace topo={current} />
            </div>
          )}
        </>
      )}
    </div>
  );
}
