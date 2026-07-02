import { useState } from "react";

import { api } from "../api/client";
import type { ExecutionTarget, InventorySnapshot } from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";
import {
  DEFAULT_PROVISIONING_BOUNDARY,
  buildRegisterTargetPayload,
  type ProvisioningBoundaryDraft,
} from "./provider-targets";

function RegisterForm({ onCreated }: { onCreated: () => void }) {
  const [displayName, setDisplayName] = useState("Lab Proxmox (placeholder)");
  const [baseUrl, setBaseUrl] = useState("https://proxmox.example.test:8006/api2/json");
  const [secretRef, setSecretRef] = useState("env:SECP_PROVIDER_SECRET__LAB");
  const [boundary, setBoundary] = useState<ProvisioningBoundaryDraft>(
    DEFAULT_PROVISIONING_BOUNDARY,
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function setBoundaryField<K extends keyof ProvisioningBoundaryDraft>(
    key: K,
    value: ProvisioningBoundaryDraft[K],
  ) {
    setBoundary((current) => ({ ...current, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const payload = buildRegisterTargetPayload({
        displayName,
        baseUrl,
        secretRef,
        boundary,
      });
      if (!payload.ok || !payload.value) {
        setError(payload.errors.join("; "));
        return;
      }
      await api.registerTarget(payload.value);
      onCreated();
    } catch (e: any) {
      setError(`${e.message}${e.details ? " — " + e.details.join("; ") : ""}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <h3>Register execution target</h3>
      <p className="muted">
        Non-secret configuration only. Provide an <strong>opaque secret reference</strong>{" "}
        (e.g. <code>env:SECP_PROVIDER_SECRET__LAB</code>) — never a real secret. There is
        no secret-entry form by design.
      </p>
      {error && <div className="error-box">{error}</div>}
      <div className="grid cols-2">
        <div>
          <label>Display name</label>
          <input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          <label>Base URL (non-secret)</label>
          <input type="text" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
        </div>
        <div>
          <label>Secret reference (opaque pointer)</label>
          <input type="text" value={secretRef} onChange={(e) => setSecretRef(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <h3 style={{ marginTop: 0 }}>Allowed provisioning boundary</h3>
        <p className="muted">
          Provider-neutral fake lab values only. These approved values define what the
          onboarding wizard may select; no infrastructure discovery, provider validation,
          network calls, or provisioning actions are performed here.
        </p>
        <div className="grid cols-2">
          <div>
            <label>Allowed nodes</label>
            <input
              value={boundary.allowedNodes}
              onChange={(e) => setBoundaryField("allowedNodes", e.target.value)}
            />
            <label>Allowed storage</label>
            <input
              value={boundary.allowedStorage}
              onChange={(e) => setBoundaryField("allowedStorage", e.target.value)}
            />
            <label>Allowed network segments / bridges</label>
            <input
              value={boundary.networkSegments}
              onChange={(e) => setBoundaryField("networkSegments", e.target.value)}
            />
            <p className="muted">
              A network segment is a bridge, VNet, or VLAN name such as
              <span className="mono"> lab-isolated-segment</span>, not an IP range.
            </p>
            <label>Approved CIDR reservations</label>
            <input
              value={boundary.cidrs}
              onChange={(e) => setBoundaryField("cidrs", e.target.value)}
            />
            <p className="muted">
              CIDRs are lab address ranges, for example
              <span className="mono"> 10.60.0.0/16</span>.
            </p>
            <label>Allowed templates/images</label>
            <input
              value={boundary.allowedTemplates}
              onChange={(e) => setBoundaryField("allowedTemplates", e.target.value)}
            />
          </div>
          <div>
            <div className="grid cols-2">
              <div>
                <label>VM-ID start</label>
                <input
                  value={boundary.vmidStart}
                  onChange={(e) => setBoundaryField("vmidStart", e.target.value)}
                />
              </div>
              <div>
                <label>VM-ID end</label>
                <input
                  value={boundary.vmidEnd}
                  onChange={(e) => setBoundaryField("vmidEnd", e.target.value)}
                />
              </div>
            </div>
            <label>Max teams / VMs / containers</label>
            <div className="grid cols-2">
              <input
                value={boundary.maxTeams}
                onChange={(e) => setBoundaryField("maxTeams", e.target.value)}
              />
              <input
                value={boundary.maxVms}
                onChange={(e) => setBoundaryField("maxVms", e.target.value)}
              />
            </div>
            <input
              value={boundary.maxContainers}
              onChange={(e) => setBoundaryField("maxContainers", e.target.value)}
            />
            <label>Max vCPU / memory (MB) / disk (GB)</label>
            <div className="grid cols-2">
              <input
                value={boundary.maxVcpu}
                onChange={(e) => setBoundaryField("maxVcpu", e.target.value)}
              />
              <input
                value={boundary.maxMemoryMb}
                onChange={(e) => setBoundaryField("maxMemoryMb", e.target.value)}
              />
            </div>
            <input
              value={boundary.maxDiskGb}
              onChange={(e) => setBoundaryField("maxDiskGb", e.target.value)}
            />
            <label>Default template sizing: vCPU / memory (MB) / disk (GB)</label>
            <div className="grid cols-2">
              <input
                value={boundary.sizingVcpu}
                onChange={(e) => setBoundaryField("sizingVcpu", e.target.value)}
              />
              <input
                value={boundary.sizingMemoryMb}
                onChange={(e) => setBoundaryField("sizingMemoryMb", e.target.value)}
              />
            </div>
            <input
              value={boundary.sizingDiskGb}
              onChange={(e) => setBoundaryField("sizingDiskGb", e.target.value)}
            />
            <p className="muted mono" style={{ marginTop: 8 }}>
              external connectivity: deny (fixed)
            </p>
          </div>
        </div>
      </div>
      <div className="row" style={{ marginTop: 12 }}>
        <button onClick={submit} disabled={busy}>
          {busy ? "Registering…" : "Register target"}
        </button>
      </div>
    </div>
  );
}

function TargetCard({ target, onChanged }: { target: ExecutionTarget; onChanged: () => void }) {
  const snapshots = useAsync(() => api.listSnapshots(target.id), [target.id]);
  const provisioning = (target.scope_policy as any)?.provisioning ?? {};
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function discover() {
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const snap: InventorySnapshot = await api.requestDiscovery(target.id);
      setMsg(`Discovery queued (snapshot ${snap.id.slice(0, 8)}, status ${snap.status}).`);
      snapshots.reload();
    } catch (e: any) {
      // In inline dev mode this is intentionally refused.
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div>
          <h3 style={{ marginBottom: 2 }}>{target.display_name}</h3>
          <div className="muted mono">
            {target.plugin_name} · {target.config_hash.slice(7, 19)}…
          </div>
        </div>
        <div className="row">
          <StatusBadge state={target.status} />
          <button className="secondary" disabled={busy} onClick={discover}>
            Request read-only discovery
          </button>
          <button
            className="danger"
            disabled={busy || target.status === "disabled"}
            onClick={async () => {
              await api.disableTarget(target.id);
              onChanged();
            }}
          >
            Disable
          </button>
        </div>
      </div>
      {target.secret_ref && (
        <div className="muted mono">secret_ref: {target.secret_ref} (reference, not a secret)</div>
      )}
      {provisioning.allowed_bridges && (
        <div className="muted mono" style={{ marginTop: 8 }}>
          approved boundary: nodes={(provisioning.allowed_nodes ?? []).join(", ")} Â· storage=
          {(provisioning.allowed_storage ?? []).join(", ")} Â· segments=
          {(provisioning.allowed_bridges ?? []).join(", ")} Â· cidrs=
          {(provisioning.allowed_cidr_reservations ?? []).join(", ")}
        </div>
      )}
      {msg && <div className="muted" style={{ marginTop: 8 }}>{msg}</div>}
      {error && (
        <div className="error-box" style={{ marginTop: 8 }}>
          {error} (discovery requires the Temporal worker path; it is refused in inline dev mode)
        </div>
      )}
      {snapshots.data && snapshots.data.length > 0 && (
        <table style={{ marginTop: 10 }}>
          <thead>
            <tr>
              <th>Snapshot</th>
              <th>Status</th>
              <th>Resources</th>
              <th>Requested</th>
            </tr>
          </thead>
          <tbody>
            {snapshots.data.map((s) => (
              <tr key={s.id}>
                <td className="mono">{s.id.slice(0, 8)}</td>
                <td>
                  <StatusBadge state={s.status} />
                </td>
                <td className="muted">{String((s.summary as any)?.total ?? "—")}</td>
                <td className="muted">{new Date(s.requested_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function ProviderTargets() {
  const caps = useAsync(() => api.providerCapabilities(), []);
  const targets = useAsync(() => api.listTargets(), []);

  return (
    <div>
      <h2>Provider targets</h2>
      <div className="error-box" style={{ background: "transparent" }}>
        <strong>SECP-002A — read-only.</strong> Proxmox provisioning is{" "}
        <strong>NOT enabled</strong>. Discovery is read-only and runs only through the
        Temporal worker; provisioning is deferred to SECP-002B. No real endpoint is
        contacted in this milestone.
      </div>
      {caps.data && (
        <p className="muted mono">
          {caps.data.milestone} · provisioning_enabled={String(caps.data.provisioning_enabled)} ·
          discovery={caps.data.discovery}
        </p>
      )}

      <RegisterForm onCreated={() => targets.reload()} />

      {targets.error && <div className="error-box">{targets.error}</div>}
      {targets.data && targets.data.length === 0 && (
        <p className="muted">No execution targets registered yet.</p>
      )}
      {targets.data?.map((t) => (
        <TargetCard key={t.id} target={t} onChanged={() => targets.reload()} />
      ))}
    </div>
  );
}
