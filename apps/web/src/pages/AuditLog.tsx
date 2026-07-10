import { api } from "../api/client";
import { StatusBadge } from "../components/ui";
import { useAsync } from "../hooks";

export function AuditLog() {
  const events = useAsync(() => api.audit(), []);

  return (
    <div>
      <h2>Audit log</h2>
      <p className="muted">
        Immutable, append-only record. Every mutation and authorization decision is
        captured (Charter Invariant 10).
      </p>
      {events.error && <div className="error-box">{events.error}</div>}
      {events.data && (
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Actor</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {events.data.map((e) => (
                <tr key={e.id}>
                  <td className="muted mono">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td className="mono">{e.action}</td>
                  <td className="muted mono">
                    {e.resource_type}
                    {e.resource_id ? `/${e.resource_id.slice(0, 8)}` : ""}
                  </td>
                  <td className="muted mono">{e.actor.slice(0, 12)}</td>
                  <td>
                    <StatusBadge state={e.outcome} domain="audit" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
