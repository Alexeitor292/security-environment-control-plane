import yaml from "js-yaml";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../api/client";

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

interface StructuredViewProps {
  parsed: Record<string, any> | null;
  error: string | null;
}

function StructuredView({ parsed, error }: StructuredViewProps) {
  if (error) return <div className="error-box">YAML parse error: {error}</div>;
  if (!parsed) return null;
  const spec = (parsed.spec ?? {}) as Record<string, any>;
  return (
    <div>
      <p>
        <strong>{parsed.metadata?.displayName ?? parsed.metadata?.name}</strong>{" "}
        <span className="muted mono">{parsed.apiVersion}</span>
      </p>
      <div className="grid cols-2">
        <div>
          <label>Teams</label>
          <div>
            {spec.teams?.count} ·{" "}
            <span className="badge accent">{spec.teams?.isolationPolicy}</span>
          </div>
          <label>Networks</label>
          <ul>
            {(spec.networks ?? []).map((n: any) => (
              <li key={n.name} className="mono">
                {n.name} ({n.cidrStrategy})
              </li>
            ))}
          </ul>
          <label>Required plugins</label>
          <div className="mono">{(spec.requiredPlugins ?? []).join(", ")}</div>
        </div>
        <div>
          <label>Roles</label>
          <ul>
            {(spec.roles ?? []).map((r: any) => (
              <li key={r.name} className="mono">
                {r.name} · {r.kind} · {r.image}
              </li>
            ))}
          </ul>
          <label>Telemetry / validation</label>
          <div className="mono">
            telemetry: {(spec.telemetry?.providers ?? []).join(", ") || "—"}
            <br />
            validation: {spec.validation?.provider ?? "—"}
          </div>
        </div>
      </div>
    </div>
  );
}

export function DefinitionEditor() {
  const navigate = useNavigate();
  const [text, setText] = useState(STARTER);
  const [name, setName] = useState("Web Breach 101");
  const [slug, setSlug] = useState("web-breach-101");
  const [validation, setValidation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const { parsed, parseError } = useMemo(() => {
    try {
      return { parsed: yaml.load(text) as Record<string, any>, parseError: null };
    } catch (e: any) {
      return { parsed: null, parseError: e?.message ?? String(e) };
    }
  }, [text]);

  async function validate() {
    setValidation(null);
    setError(null);
    if (!parsed) return;
    try {
      const r = await api.validateDefinition(parsed);
      setValidation(
        r.ok
          ? `Valid ✓${r.warnings.length ? " — warnings: " + r.warnings.join("; ") : ""}`
          : "Invalid: " + r.errors.join("; "),
      );
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function createTemplateAndVersion() {
    if (!parsed) return;
    setBusy(true);
    setError(null);
    try {
      const template = await api.createTemplate({ name, slug });
      await api.createVersion(template.id, parsed);
      navigate("/templates");
    } catch (e: any) {
      setError(`${e.message}${e.details ? " — " + e.details.join("; ") : ""}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2>Definition editor</h2>
      <p className="muted">
        Declarative environment definition. Edit the YAML; the structured view and
        validation update live. Versions are immutable once created.
      </p>

      {error && <div className="error-box">{error}</div>}

      <div className="grid cols-2">
        <div className="panel">
          <h3>Raw YAML</h3>
          <textarea value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <div className="panel">
          <h3>Structured view</h3>
          <StructuredView parsed={parsed} error={parseError} />
        </div>
      </div>

      <div className="panel">
        <h3>Create template &amp; immutable version</h3>
        <div className="grid cols-2">
          <div>
            <label>Template name</label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <label>Slug</label>
            <input type="text" value={slug} onChange={(e) => setSlug(e.target.value)} />
          </div>
        </div>
        <div className="row" style={{ marginTop: 12 }}>
          <button className="secondary" onClick={validate} disabled={!parsed}>
            Validate
          </button>
          <button onClick={createTemplateAndVersion} disabled={!parsed || busy}>
            {busy ? "Creating…" : "Create template & version"}
          </button>
          {validation && <span className="muted">{validation}</span>}
        </div>
      </div>
    </div>
  );
}
