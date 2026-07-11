import "./environments.css";

import yaml from "js-yaml";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../api/client";
import { BlueprintMeshBackground } from "../components/backgrounds";
import {
  CyberButton,
  CyberCard,
  CyberInput,
  KeyValueList,
  SafetyNotice,
  useAction,
} from "../components/ui";
import {
  EDITOR_INTRO,
  EDITOR_REVISION_NOTE,
  ENVIRONMENTS_ERROR_TEXT,
  VALIDATION_IS_NOT_APPROVAL_NOTE,
  definitionSummary,
  validationView,
  type ValidationView,
} from "./environments-view";

const STARTER = `apiVersion: controlplane.security/v1alpha1
kind: Environment
metadata:
  name: web-breach-101
  displayName: Web Breach 101
spec:
  teams:
    count: 2
    isolationPolicy: strict
  networks:
    - name: team-network
      cidrStrategy: per-team
      baseCidr: 10.20.0.0/16
      isolated: true
  roles:
    - name: attacker
      kind: attacker
      image: kali-linux
      network: team-network
    - name: web-server
      kind: target
      image: ubuntu-server-22.04
      network: team-network
      vulnerabilityPacks: [weak-ssh]
    - name: wazuh-sensor
      kind: sensor
      image: wazuh-agent
      network: team-network
  vulnerabilityPacks:
    - ref: weak-ssh
      version: "1.0.0"
  telemetry:
    providers: [wazuh]
  validation:
    provider: ctfd
    objectives:
      - id: gain-initial-access
        description: Obtain a shell on the vulnerable web server.
        points: 100
  requiredPlugins: [simulator, proxmox, wazuh, ctfd]
`;

/** Validation posture badge with its own closed vocabulary — the validation
 *  states are known precisely, so none may fall to an "unknown" style. */
function ValidationStateBadge({ view }: { view: ValidationView }) {
  return (
    <span className={`env-vbadge env-vbadge--${view.state}`}>{view.label}</span>
  );
}

function StructuredPreview({ parsed }: { parsed: unknown }) {
  const summary = definitionSummary(parsed);
  if (!summary) return <p className="muted">Nothing parseable yet.</p>;
  return (
    <>
      <KeyValueList
        items={[
          { key: "Name", value: summary.displayName || "—" },
          { key: "API version", value: summary.apiVersion || "—", mono: true },
          {
            key: "Teams",
            value:
              summary.teamCount !== null
                ? `${summary.teamCount} · ${summary.isolationPolicy || "—"}`
                : "—",
          },
          {
            key: "Roles",
            value:
              summary.roles.map((r) => `${r.name} (${r.kind})`).join(", ") || "—",
            mono: true,
          },
          {
            key: "Networks",
            value:
              summary.networks
                .map((n) => `${n.name} (${n.cidrStrategy})`)
                .join(", ") || "—",
            mono: true,
          },
          {
            key: "Required plugins",
            value: summary.requiredPlugins.join(", ") || "—",
            mono: true,
          },
        ]}
      />
      {summary.unrecognizedSpecKeys > 0 && (
        <p className="env-note">
          {summary.unrecognizedSpecKeys} unrecognized spec section
          {summary.unrecognizedSpecKeys === 1 ? "" : "s"} not shown here (kept in
          the YAML verbatim).
        </p>
      )}
    </>
  );
}

function ValidationPanel({ view }: { view: ValidationView }) {
  return (
    <CyberCard surface="well" heading="Validation">
      <ValidationStateBadge view={view} />
      {view.errors.length > 0 && (
        <ul className="env-validation-list env-validation-list--errors">
          {view.errors.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
      )}
      {view.warnings.length > 0 && (
        <ul className="env-validation-list env-validation-list--warnings">
          {view.warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
      {view.droppedFindings > 0 && (
        <p className="env-note">
          {view.droppedFindings} additional finding
          {view.droppedFindings === 1 ? "" : "s"} not displayed.
        </p>
      )}
      <p className="env-note">{VALIDATION_IS_NOT_APPROVAL_NOTE}</p>
    </CyberCard>
  );
}

export function DefinitionEditor() {
  const navigate = useNavigate();
  const [text, setText] = useState(STARTER);
  const [name, setName] = useState("Web Breach 101");
  const [slug, setSlug] = useState("web-breach-101");
  const [validated, setValidated] = useState<{
    forText: string;
    result: { ok: boolean; errors: string[]; warnings: string[] };
  } | null>(null);
  const validateAction = useAction({ codeText: ENVIRONMENTS_ERROR_TEXT });
  const createAction = useAction({ codeText: ENVIRONMENTS_ERROR_TEXT });

  const { parsed, parseError } = useMemo(() => {
    try {
      // Exact serialization contract: the parsed YAML object is sent verbatim.
      return { parsed: yaml.load(text) as Record<string, unknown>, parseError: null };
    } catch (e) {
      return {
        parsed: null,
        parseError: e instanceof Error ? e.message.slice(0, 400) : "YAML parse error",
      };
    }
  }, [text]);

  const view = validationView(
    validated?.result ?? null,
    validated !== null && validated.forText !== text,
  );

  function runValidate() {
    if (!parsed) return;
    const forText = text;
    void validateAction.run(async () => {
      const r = await api.validateDefinition(parsed);
      setValidated({ forText, result: r });
    });
  }

  function createTemplateAndVersion() {
    if (!parsed) return;
    void createAction.run(async () => {
      const template = await api.createTemplate({ name, slug });
      await api.createVersion(template.id, parsed);
      navigate("/templates");
    });
  }

  return (
    <div className="env">
      <BlueprintMeshBackground intensity="subtle" className="env-bg" />
      <div className="env-head">
        <div>
          <h1>Definition Editor</h1>
          <p className="env-sub">{EDITOR_INTRO}</p>
        </div>
      </div>

      <div className="env-editor-grid env-editor">
        <CyberCard heading="Definition (YAML — persisted verbatim)">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            aria-label="Environment definition YAML"
            spellCheck={false}
          />
          {parseError && (
            <div className="error-box" role="alert" style={{ marginTop: 8 }}>
              YAML parse error: <code className="mono">{parseError}</code>
            </div>
          )}
          <p className="env-note">
            {validated === null
              ? "Not validated yet — validation has not run for this content."
              : view.state === "stale"
                ? "Unsaved changes since the last validation — re-run before creating a version."
                : "Validated against exactly this content."}
          </p>
        </CyberCard>

        <div style={{ display: "grid", gap: 14 }}>
          <CyberCard surface="well" heading="Structured view (allowlisted)">
            <StructuredPreview parsed={parsed} />
          </CyberCard>

          <ValidationPanel view={view} />

          <CyberCard surface="well" heading="Create template & immutable version">
            <div style={{ display: "grid", gap: 10 }}>
              <CyberInput
                label="Template name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <CyberInput
                label="Slug"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
              />
            </div>
            <p className="env-note">{EDITOR_REVISION_NOTE}</p>
            {validateAction.error && (
              <div className="error-box" role="alert">
                {validateAction.error.text}{" "}
                <code className="mono">{validateAction.error.code}</code>
              </div>
            )}
            {createAction.error && (
              <div className="error-box" role="alert">
                {createAction.error.text}{" "}
                <code className="mono">{createAction.error.code}</code>
              </div>
            )}
            <div className="env-actions" style={{ marginTop: 10 }}>
              <CyberButton
                variant="secondary"
                disabled={!parsed || validateAction.busy}
                onClick={runValidate}
              >
                Validate definition
              </CyberButton>
              <CyberButton
                disabled={!parsed || createAction.busy}
                title="Records an immutable version of this content. It does not validate an exercise, approve a plan, or deploy anything."
                onClick={createTemplateAndVersion}
              >
                {createAction.busy ? "Creating…" : "Create template & version"}
              </CyberButton>
            </div>
          </CyberCard>

          <SafetyNotice role="note" tone="warn">
            {VALIDATION_IS_NOT_APPROVAL_NOTE}
          </SafetyNotice>
        </div>
      </div>
    </div>
  );
}
