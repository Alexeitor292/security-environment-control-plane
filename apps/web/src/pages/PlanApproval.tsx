import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";

export function PlanApproval() {
  const { exerciseId = "" } = useParams();
  const navigate = useNavigate();
  const plan = useAsync(() => api.latestPlan(exerciseId).catch(() => null), [exerciseId]);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function act(fn: () => Promise<unknown>, back = false) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      if (back) navigate(`/exercises/${exerciseId}`);
      else plan.reload();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (plan.loading) return <p className="muted">Loading plan…</p>;
  if (!plan.data)
    return (
      <div>
        <h2>Deployment plan approval</h2>
        <p className="muted">No plan generated for this exercise yet.</p>
      </div>
    );

  const p = plan.data;
  const canDecide = p.status === "awaiting_approval";
  const canSubmit = p.status === "generated";

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ marginBottom: 4 }}>Deployment plan approval</h2>
        <StatusBadge state={p.status} />
      </div>
      <p className="muted mono">
        deterministic plan · pinned to version hash {p.version_content_hash.slice(7, 23)}…
      </p>

      {error && <div className="error-box">{error}</div>}

      <div className="panel">
        <h3>What will be created</h3>
        <p className="muted">
          {p.summary.total_nodes} simulated nodes across {p.summary.teams} isolated
          teams · {p.summary.isolation} isolation · plugin{" "}
          <span className="mono">{p.summary.plugin}</span>
        </p>
        <div className="grid cols-2">
          {p.summary.per_team.map((team) => (
            <div className="panel" key={team.team_ref} style={{ background: "#0b0f15" }}>
              <h3 style={{ marginTop: 0 }}>{team.team_ref}</h3>
              <label>Networks</label>
              {team.networks.map((n) => (
                <div key={n.name} className="mono">
                  {n.name} → {n.cidr}
                </div>
              ))}
              <label>Nodes</label>
              {team.nodes.map((n) => (
                <div key={n.name} className="mono">
                  {n.role} · {n.kind} · {n.ip}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <h3>Decision</h3>
        <label>Reason / note</label>
        <input
          type="text"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="optional justification recorded in the audit log"
        />
        <div className="row" style={{ marginTop: 12 }}>
          {canSubmit && (
            <button
              className="secondary"
              disabled={busy}
              onClick={() => act(() => api.submitPlan(p.id))}
            >
              Submit for approval
            </button>
          )}
          <button
            className="ok"
            disabled={busy || !canDecide}
            onClick={() => act(() => api.approvePlan(p.id, reason), true)}
          >
            Approve
          </button>
          <button
            className="danger"
            disabled={busy || !canDecide}
            onClick={() => act(() => api.rejectPlan(p.id, reason))}
          >
            Reject
          </button>
        </div>
        {p.approved_content_hash && (
          <p className="muted" style={{ marginTop: 10 }}>
            Approved · pinned hash {p.approved_content_hash.slice(7, 23)}… · apply may
            now proceed.
          </p>
        )}
      </div>
    </div>
  );
}
