import { useState } from "react";

import { api } from "../api/client";
import type { ExecutionTarget, InventorySnapshot } from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";

function RegisterForm({ onCreated }: { onCreated: () => void }) {
  const [displayName, setDisplayName] = useState("Lab Proxmox (placeholder)");
  const [baseUrl, setBaseUrl] = useState("https://proxmox.example.test:8006/api2/json");
  const [secretRef, setSecretRef] = useState("env:SECP_PROVIDER_SECRET__LAB");
  const [cidr, setCidr] = useState("10.60.0.0/16");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.registerTarget({
        display_name: displayName,
        plugin_name: "proxmox",
        config: { base_url: baseUrl, verify_tls: true },
        secret_ref: secretRef || null,
        scope_policy: {},
        address_spaces: cidr ? [{ cidr_block: cidr, subnet_prefix: 24 }] : [],
      });
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
          <label>Approved address space (CIDR)</label>
          <input type="text" value={cidr} onChange={(e) => setCidr(e.target.value)} />
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
