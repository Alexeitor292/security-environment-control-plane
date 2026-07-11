import "./environments.css";

import { Link } from "react-router-dom";

import { api } from "../api/client";
import { CyberGridBackground } from "../components/backgrounds";
import {
  CyberCard,
  CyberTable,
  EmptyState,
  Skeleton,
  StatusBadge,
  shortId,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  SIMULATED_POSTURE_NOTE,
  exerciseRows,
  recordedDate,
} from "./environments-view";

export function Exercises() {
  const exercises = useAsync(() => api.listExercises(), []);
  const list = exercises.data ?? null;
  const rows = list ? exerciseRows(list) : [];

  return (
    <div className="env">
      <CyberGridBackground intensity="subtle" className="env-bg" />
      <div className="env-head">
        <div>
          <h1>Exercises</h1>
          <p className="env-sub">
            Exercises instantiate an immutable definition version for a set of
            isolated teams. {SIMULATED_POSTURE_NOTE}
          </p>
        </div>
      </div>

      {exercises.error !== null && exercises.error !== undefined && (
        <div className="error-box" role="alert">
          Exercises unavailable.
        </div>
      )}

      {exercises.loading && !list ? (
        <CyberCard>
          <Skeleton lines={4} />
        </CyberCard>
      ) : list && rows.length === 0 ? (
        <CyberCard>
          <EmptyState title="No exercises yet">
            Create one from an immutable version in the{" "}
            <Link to="/templates">environment library</Link>.
          </EmptyState>
        </CyberCard>
      ) : list ? (
        <CyberCard heading="Exercise inventory">
          <CyberTable
            label="Exercises"
            head={["Exercise", "Version", "Teams", "Lifecycle", "Posture", "Created"]}
            caption={`${rows.length} exercise${rows.length === 1 ? "" : "s"} · lifecycle reflects recorded state only`}
          >
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link to={`/exercises/${r.id}`} className="env-name">
                    {r.name}
                  </Link>
                </td>
                <td className="muted mono" title={r.versionRef}>
                  {shortId(r.versionRef)}
                </td>
                <td>{r.teamCount}</td>
                <td>
                  <span className="env-hashline">
                    <StatusBadge state={r.lifecycle} domain="lifecycle" />
                    <span className="muted">{r.label}</span>
                  </span>
                </td>
                <td className="muted mono">simulated</td>
                <td className="muted mono">{recordedDate(r.createdAt)}</td>
              </tr>
            ))}
          </CyberTable>
        </CyberCard>
      ) : null}
    </div>
  );
}
