import { Link } from "react-router-dom";

import { api } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";

export function Dashboard() {
  const exercises = useAsync(() => api.listExercises(), []);
  const templates = useAsync(() => api.listTemplates(), []);
  const plugins = useAsync(() => api.plugins(), []);

  return (
    <div>
      <h2>Dashboard</h2>

      <div className="grid cols-3">
        <div className="panel">
          <h3>Templates</h3>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {templates.data?.length ?? "—"}
          </div>
          <Link to="/templates">Environment library →</Link>
        </div>
        <div className="panel">
          <h3>Exercises</h3>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {exercises.data?.length ?? "—"}
          </div>
          <Link to="/templates/new">New definition →</Link>
        </div>
        <div className="panel">
          <h3>Plugins</h3>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {plugins.data?.length ?? "—"}
          </div>
          <span className="muted">capability-aware integrations</span>
        </div>
      </div>

      <div className="panel">
        <h3>Recent exercises</h3>
        {exercises.error && <div className="error-box">{exercises.error}</div>}
        {exercises.data && exercises.data.length === 0 && (
          <p className="muted">
            No exercises yet. Create an environment definition, then start an
            exercise.
          </p>
        )}
        {exercises.data && exercises.data.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Lifecycle</th>
                <th>Teams</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {exercises.data.map((ex) => (
                <tr key={ex.id}>
                  <td>
                    <Link to={`/exercises/${ex.id}`}>{ex.name}</Link>
                  </td>
                  <td>
                    <StatusBadge state={ex.lifecycle_state} />
                  </td>
                  <td>{ex.team_count}</td>
                  <td className="muted">
                    {new Date(ex.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h3>Plugin health</h3>
        {plugins.data && (
          <table>
            <thead>
              <tr>
                <th>Plugin</th>
                <th>Version</th>
                <th>Contract</th>
                <th>Health</th>
                <th>Capabilities</th>
              </tr>
            </thead>
            <tbody>
              {plugins.data.map((p) => (
                <tr key={p.name}>
                  <td>
                    {p.name}{" "}
                    {p.simulated && <span className="badge accent">simulated</span>}
                  </td>
                  <td className="mono">{p.version}</td>
                  <td className="mono">v{p.contract_version}</td>
                  <td>
                    <span className={`badge ${p.healthy ? "ok" : "danger"}`}>
                      {p.healthy ? "healthy" : "down"}
                    </span>
                  </td>
                  <td className="muted mono">{p.capabilities.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
