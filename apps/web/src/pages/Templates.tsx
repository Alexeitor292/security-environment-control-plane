import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { Version } from "../api/types";
import { useAsync } from "../hooks";

function VersionList({ templateId }: { templateId: string }) {
  const navigate = useNavigate();
  const versions = useAsync(() => api.listVersions(templateId), [templateId]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function startExercise(v: Version) {
    setBusy(true);
    setError(null);
    try {
      const ex = await api.createExercise({
        template_id: templateId,
        version_id: v.id,
        name: `Exercise from v${v.version_number}`,
      });
      navigate(`/exercises/${ex.id}`);
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  }

  if (versions.loading) return <span className="muted">loading versions…</span>;
  if (!versions.data || versions.data.length === 0)
    return <span className="muted">no versions</span>;
  return (
    <>
      {error && <div className="error-box">{error}</div>}
      <table>
        <thead>
          <tr>
            <th>Version</th>
            <th>API version</th>
            <th>Content hash (immutable)</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {versions.data.map((v: Version) => (
            <tr key={v.id}>
              <td>v{v.version_number}</td>
              <td className="mono">{v.api_version}</td>
              <td className="mono">{v.content_hash.slice(0, 23)}…</td>
              <td className="muted">{new Date(v.created_at).toLocaleString()}</td>
              <td>
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() => startExercise(v)}
                >
                  Create exercise
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export function Templates() {
  const templates = useAsync(() => api.listTemplates(), []);
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Environment library</h2>
        <Link to="/templates/new">
          <button>New definition</button>
        </Link>
      </div>

      {templates.error && <div className="error-box">{templates.error}</div>}
      {templates.data && templates.data.length === 0 && (
        <p className="muted">No templates yet. Create one in the definition editor.</p>
      )}

      {templates.data?.map((t) => (
        <div className="panel" key={t.id}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <div>
              <h3 style={{ marginBottom: 2 }}>{t.display_name || t.name}</h3>
              <div className="muted mono">{t.slug}</div>
            </div>
            <button
              className="secondary"
              onClick={() => setExpanded(expanded === t.id ? null : t.id)}
            >
              {expanded === t.id ? "Hide versions" : "Show versions"}
            </button>
          </div>
          {t.description && <p className="muted">{t.description}</p>}
          {expanded === t.id && <VersionList templateId={t.id} />}
        </div>
      ))}
    </div>
  );
}
