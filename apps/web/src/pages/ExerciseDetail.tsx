import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";

export function ExerciseDetail() {
  const { exerciseId = "" } = useParams();
  const exercise = useAsync(() => api.getExercise(exerciseId), [exerciseId]);
  const instances = useAsync(() => api.listInstances(exerciseId), [exerciseId]);
  const plan = useAsync(() => api.latestPlan(exerciseId).catch(() => null), [exerciseId]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function reloadAll() {
    exercise.reload();
    instances.reload();
    plan.reload();
  }

  async function action(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      reloadAll();
    } catch (e: any) {
      setError(`${e.message}${e.details ? " — " + e.details.join("; ") : ""}`);
    } finally {
      setBusy(false);
    }
  }

  if (exercise.error) return <div className="error-box">{exercise.error}</div>;
  if (!exercise.data) return <p className="muted">Loading…</p>;

  const ex = exercise.data;
  const state = ex.lifecycle_state;
  const planData = plan.data;

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ marginBottom: 4 }}>{ex.name}</h2>
        <StatusBadge state={state} />
      </div>
      <p className="muted mono">
        version {ex.environment_version_id.slice(0, 8)} · {ex.team_count} teams
      </p>

      {error && <div className="error-box">{error}</div>}

      <div className="panel">
        <h3>Lifecycle</h3>
        <div className="row">
          <button
            className="secondary"
            disabled={busy || state !== "draft"}
            onClick={() => action(() => api.validateExercise(ex.id))}
          >
            1. Validate
          </button>
          <button
            className="secondary"
            disabled={busy || state !== "validated"}
            onClick={() => action(() => api.generatePlan(ex.id))}
          >
            2. Generate plan
          </button>
          <Link to={`/exercises/${ex.id}/plan`}>
            <button className="secondary" disabled={!planData}>
              3. Plan &amp; approval →
            </button>
          </Link>
          <button
            disabled={busy || state !== "approved"}
            onClick={() => action(() => api.deployExercise(ex.id))}
          >
            4. Start simulated exercise
          </button>
        </div>
        <p className="muted" style={{ marginTop: 10 }}>
          Deploy is refused until a plan is explicitly approved (approval gate).
        </p>
      </div>

      <div className="panel">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h3>Team instances</h3>
          <div className="row">
            <Link to={`/exercises/${ex.id}/topology`}>
              <button className="secondary" disabled={!instances.data?.length}>
                View topologies
              </button>
            </Link>
            <button
              className="danger"
              disabled={busy || !["running", "failed"].includes(state)}
              onClick={() => action(() => api.destroyExercise(ex.id))}
            >
              Destroy exercise
            </button>
          </div>
        </div>
        {instances.data && instances.data.length === 0 && (
          <p className="muted">No instances yet — deploy to create one per team.</p>
        )}
        {instances.data && instances.data.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Team</th>
                <th>Instance</th>
                <th>Lifecycle</th>
                <th>Provider</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {instances.data.map((inst) => (
                <tr key={inst.id}>
                  <td>{inst.team_ref}</td>
                  <td className="mono">{inst.instance_ref}</td>
                  <td>
                    <StatusBadge state={inst.lifecycle_state} />
                  </td>
                  <td>
                    {inst.provider}{" "}
                    <span className="badge accent">simulated</span>
                  </td>
                  <td>
                    <button
                      className="secondary"
                      disabled={busy || inst.lifecycle_state !== "running"}
                      onClick={() =>
                        action(() => api.resetInstance(ex.id, inst.id))
                      }
                    >
                      Reset
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h3>Deployment plan</h3>
        {!planData && <p className="muted">No plan generated yet.</p>}
        {planData && (
          <div>
            <div className="row">
              <StatusBadge state={planData.status} />
              <span className="muted mono">
                hash {planData.version_content_hash.slice(7, 19)}…
              </span>
            </div>
            <p className="muted">
              {planData.summary.total_nodes} nodes ·{" "}
              {planData.summary.total_networks} networks ·{" "}
              {planData.summary.isolation} isolation
            </p>
            <Link to={`/exercises/${ex.id}/plan`}>Open approval screen →</Link>
          </div>
        )}
      </div>

      <div className="row">
        <Link to={`/audit`}>View full audit log →</Link>
      </div>
    </div>
  );
}
