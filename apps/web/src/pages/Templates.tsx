import "./environments.css";

import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { Template, Version } from "../api/types";
import { ProviderMeshBackground } from "../components/backgrounds";
import { SECP_ICONS } from "../components/icons";
import {
  CyberButton,
  CyberCard,
  CyberTable,
  EmptyState,
  HashChip,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  useAction,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  ENVIRONMENTS_ERROR_TEXT,
  LIBRARY_INTRO,
  TEMPLATE_IS_DEFINITION_NOTE,
  definitionSummary,
  recordedDate,
} from "./environments-view";

const LibraryIcon = SECP_ICONS["secp-mark"];

function DefinitionPreview({ version }: { version: Version }) {
  const summary = definitionSummary(version.spec);
  if (!summary) {
    return <p className="muted">Definition content could not be summarized.</p>;
  }
  return (
    <div className="env-grid">
      <CyberCard surface="well" heading="Definition identity">
        <KeyValueList
          items={[
            { key: "Name", value: summary.displayName },
            { key: "API version", value: summary.apiVersion, mono: true },
            { key: "Kind", value: summary.kind || "—" },
            {
              key: "Teams",
              value:
                summary.teamCount !== null
                  ? `${summary.teamCount} · ${summary.isolationPolicy || "—"} isolation`
                  : "—",
            },
            {
              key: "Required plugins",
              value: summary.requiredPlugins.join(", ") || "—",
              mono: true,
            },
            {
              key: "Telemetry",
              value: summary.telemetryProviders.join(", ") || "—",
              mono: true,
            },
            {
              key: "Validation",
              value: summary.validationProvider
                ? `${summary.validationProvider}${summary.objectiveCount !== null ? ` · ${summary.objectiveCount} objective${summary.objectiveCount === 1 ? "" : "s"}` : ""}`
                : "—",
            },
            {
              key: "Vulnerability packs",
              value: summary.vulnerabilityPacks.join(", ") || "—",
              mono: true,
            },
          ]}
        />
        {summary.unrecognizedSpecKeys > 0 && (
          <p className="env-note">
            {summary.unrecognizedSpecKeys} unrecognized spec section
            {summary.unrecognizedSpecKeys === 1 ? "" : "s"} not displayed.
          </p>
        )}
      </CyberCard>
      <CyberCard surface="well" heading="Declared topology (planned)">
        <KeyValueList
          items={[
            {
              key: "Systems / roles",
              value:
                summary.roles
                  .map((r) => `${r.name} (${r.kind} · ${r.image})`)
                  .join(", ") || "—",
              mono: true,
            },
            {
              key: "Networks",
              value:
                summary.networks
                  .map(
                    (n) =>
                      `${n.name} (${n.cidrStrategy}${n.isolated === true ? ", isolated" : ""})`,
                  )
                  .join(", ") || "—",
              mono: true,
            },
          ]}
        />
      </CyberCard>
    </div>
  );
}

function VersionList({ template }: { template: Template }) {
  const navigate = useNavigate();
  const versions = useAsync(() => api.listVersions(template.id), [template.id]);
  const action = useAction({ codeText: ENVIRONMENTS_ERROR_TEXT });
  const [previewId, setPreviewId] = useState<string | null>(null);

  function startExercise(v: Version) {
    void action.run(async () => {
      const ex = await api.createExercise({
        template_id: template.id,
        version_id: v.id,
        name: `Exercise from v${v.version_number}`,
      });
      navigate(`/exercises/${ex.id}`);
    });
  }

  if (versions.loading && !versions.data) return <Skeleton lines={3} />;
  if (versions.error !== null && versions.error !== undefined)
    return <p className="muted">Versions unavailable.</p>;
  if (!versions.data || versions.data.length === 0)
    return (
      <EmptyState title="No versions yet">
        Create an immutable version from the definition editor.
      </EmptyState>
    );

  const preview = versions.data.find((v) => v.id === previewId) ?? null;

  return (
    <>
      {action.error && (
        <div className="error-box" role="alert">
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}
      <CyberTable
        label={`Versions of ${template.display_name || template.name}`}
        head={["Version", "API version", "Content hash (immutable)", "Created", "Actions"]}
        caption={`${versions.data.length} immutable version${versions.data.length === 1 ? "" : "s"}`}
      >
        {versions.data.map((v) => (
          <tr key={v.id} className={v.id === previewId ? "env-row--selected" : undefined}>
            <td className="mono">v{v.version_number}</td>
            <td className="mono muted">{v.api_version}</td>
            <td>
              <HashChip value={v.content_hash} digits={12} />
            </td>
            <td className="muted mono">{recordedDate(v.created_at)}</td>
            <td>
              <span className="env-actions">
                <CyberButton
                  variant="secondary"
                  size="sm"
                  aria-expanded={v.id === previewId}
                  aria-controls="env-version-preview"
                  onClick={() => setPreviewId((cur) => (cur === v.id ? null : v.id))}
                >
                  {v.id === previewId ? "Hide definition" : "View definition"}
                </CyberButton>
                <CyberButton
                  size="sm"
                  disabled={action.busy}
                  title="Creates a draft exercise from this immutable version. Nothing is validated, approved, or deployed."
                  onClick={() => startExercise(v)}
                >
                  Create exercise
                </CyberButton>
              </span>
            </td>
          </tr>
        ))}
      </CyberTable>
      <div id="env-version-preview">
        {preview && <DefinitionPreview version={preview} />}
      </div>
    </>
  );
}

export function Templates() {
  const navigate = useNavigate();
  const templates = useAsync(() => api.listTemplates(), []);
  const [expanded, setExpanded] = useState<string | null>(null);

  const list = templates.data ?? null;
  const selected = list?.find((t) => t.id === expanded) ?? null;

  return (
    <div className="env">
      <ProviderMeshBackground intensity="subtle" className="env-bg" />
      <div className="env-head">
        <div>
          <h1>Environment Library</h1>
          <p className="env-sub">{LIBRARY_INTRO}</p>
        </div>
        <CyberButton onClick={() => navigate("/templates/new")}>
          New definition
        </CyberButton>
      </div>

      <SafetyNotice role="note" tone="info">
        {TEMPLATE_IS_DEFINITION_NOTE}
      </SafetyNotice>

      {templates.error !== null && templates.error !== undefined && (
        <div className="error-box" role="alert">
          Library unavailable.
        </div>
      )}

      {templates.loading && !list ? (
        <CyberCard>
          <Skeleton lines={4} />
        </CyberCard>
      ) : list && list.length === 0 ? (
        <CyberCard>
          <EmptyState title="No definitions yet">
            Create the first environment definition in the editor.
          </EmptyState>
        </CyberCard>
      ) : list ? (
        <CyberCard heading="Definitions">
          <CyberTable
            label="Environment definitions"
            head={["Definition", "Description", "Created", ""]}
            caption={`${list.length} definition${list.length === 1 ? "" : "s"} — templates are definitions, not running environments`}
          >
            {list.map((t) => (
              <tr key={t.id} className={t.id === expanded ? "env-row--selected" : undefined}>
                <td>
                  <button
                    type="button"
                    className="env-row-btn"
                    onClick={() => setExpanded((cur) => (cur === t.id ? null : t.id))}
                    aria-expanded={t.id === expanded}
                    aria-controls="env-template-detail"
                  >
                    <LibraryIcon size={15} />
                    <span>
                      <span className="env-name">{t.display_name || t.name}</span>
                      <span className="env-slug">{t.slug}</span>
                    </span>
                  </button>
                </td>
                <td className="muted">{t.description || "—"}</td>
                <td className="muted mono">{recordedDate(t.created_at)}</td>
                <td className="muted">{t.id === expanded ? "selected" : ""}</td>
              </tr>
            ))}
          </CyberTable>
        </CyberCard>
      ) : null}

      <div id="env-template-detail">
        {selected && (
          <CyberCard heading={`${selected.display_name || selected.name} — immutable versions`}>
            {/* Keyed so switching templates remounts the list: no stale rows,
                preview, or action error can carry across templates. */}
            <VersionList key={selected.id} template={selected} />
          </CyberCard>
        )}
      </div>
    </div>
  );
}
