import { useState } from "react";

import { api } from "../api/client";
import type {
  BootstrapScript,
  BootstrapSession,
  ExecutionTarget,
  WorkerDiscoveryNode,
} from "../api/types";
import { useAsync } from "../hooks";
import {
  READ_ONLY_BOOTSTRAP_INTRO,
  SCRIPT_ACTIONS,
  STEP_LABELS,
  WORKER_NOT_API_NOTICE,
  WORKER_SIDE_PREREQUISITES,
  bootstrapStatusLabel,
  currentStep,
  describeApiError,
  validateFingerprint,
  validatePublicKey,
} from "./read-only-bootstrap";

// SECP-B7 — Proxmox read-only discovery bootstrap wizard. Replaces the manual SECP-B6 canary steps.
// Handles ONLY non-secret values (an SSH PUBLIC key, a public fingerprint, a bounded proof). Never a
// private key or a raw command. Backend errors are surfaced with a safe code/message (never a
// generic "Failed to fetch").
export function ReadOnlyBootstrap() {
  const targets = useAsync<ExecutionTarget[]>(() => api.listTargets(), []);
  // SECP-B8: the worker OWNS + generates its keypair and publishes only the PUBLIC key — so the
  // operator never runs ssh-keygen. This list drives the auto-populate picker below.
  const workerNodes = useAsync<WorkerDiscoveryNode[]>(() => api.listWorkerNodes(), []);
  const [session, setSession] = useState<BootstrapSession | null>(null);
  const [script, setScript] = useState<BootstrapScript | null>(null);
  const [targetId, setTargetId] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [proof, setProof] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const step = currentStep(session);
  const keyCheck = validatePublicKey(publicKey);
  const fpCheck = validateFingerprint(fingerprint);
  const proxmoxTargets = (targets.data ?? []).filter((t) => t.plugin_name === "proxmox");
  const nodes = workerNodes.data ?? [];

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(describeApiError(err));
    } finally {
      setBusy(false);
    }
  }

  const create = () =>
    run(async () => {
      const s = await api.createBootstrapSession({
        execution_target_id: targetId,
        worker_ssh_public_key: publicKey.trim(),
      });
      setSession(s);
      setScript(await api.getBootstrapScript(s.id));
    });

  const complete = () =>
    run(async () => {
      if (!session) return;
      setSession(
        await api.completeBootstrapSession(session.id, {
          host_key_fingerprint: fingerprint.trim(),
          proof_text: proof.trim() || null,
        }),
      );
    });

  const bind = () =>
    run(async () => {
      if (!session) return;
      setSession(await api.bindBootstrapSession(session.id));
    });

  // SECP-B8: guided target-admin action to grant staging-substrate eligibility — fixes the B7
  // `readonly_preflight_substrate_ineligible` gap. Requires staging_substrate:manage; the backend
  // enforces it and NEVER silently auto-grants (a forbidden error surfaces if the actor lacks it).
  const grantEligibility = () =>
    run(async () => {
      if (!session) return;
      setNotice(null);
      await api.grantSubstrateEligibility(session.execution_target_id);
      setNotice("Staging-substrate eligibility granted. You can now create the live-read authorization.");
    });

  function applyWorkerNode(node: WorkerDiscoveryNode) {
    setPublicKey(node.ssh_public_key);
    setNotice(
      `Using the worker's published PUBLIC key (fingerprint ${node.ssh_public_key_fingerprint}). ` +
        "The worker owns the private key — you never handle it.",
    );
  }

  return (
    <section>
      <h1>Prepare Proxmox Read-Only Bootstrap</h1>
      <p>{READ_ONLY_BOOTSTRAP_INTRO}</p>
      <p role="note">{WORKER_NOT_API_NOTICE}</p>

      <ol aria-label="wizard steps">
        {(Object.keys(STEP_LABELS) as (keyof typeof STEP_LABELS)[])
          .filter((k) => k !== "done")
          .map((k) => (
            <li key={k} aria-current={step === k ? "step" : undefined}>
              <strong>{step === k ? "▶ " : ""}</strong>
              {STEP_LABELS[k]}
            </li>
          ))}
      </ol>

      {error && (
        <div role="alert" data-testid="bootstrap-error">
          <strong>{error.code}:</strong> {error.message}
        </div>
      )}

      {notice && (
        <div role="status" data-testid="bootstrap-notice">
          {notice}
        </div>
      )}

      {!session && (
        <fieldset>
          <legend>{STEP_LABELS.create}</legend>
          <label>
            Proxmox target
            <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
              <option value="">Select an active-onboarded proxmox target…</option>
              {proxmoxTargets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.display_name}
                </option>
              ))}
            </select>
          </label>

          {/* SECP-B8: the worker generates + OWNS its key. Pick a published worker to auto-fill the
              PUBLIC key — no ssh-keygen. */}
          <div data-testid="worker-key-picker">
            <p>
              <strong>Worker public key</strong> — the worker generates and owns its SSH keypair; the
              app surfaces only the PUBLIC key. You never run <code>ssh-keygen</code> or handle a
              private key.
            </p>
            {nodes.length > 0 ? (
              <label>
                Use a published worker&apos;s public key
                <select
                  value=""
                  onChange={(e) => {
                    const n = nodes.find((x) => x.id === e.target.value);
                    if (n) applyWorkerNode(n);
                  }}
                >
                  <option value="">Select a worker node…</option>
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.node_label} ({n.ssh_public_key_fingerprint})
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <p role="note" data-testid="no-worker-nodes">
                No worker has published a public key yet. Enable the worker-managed discovery profile
                (<code>SECP_DISCOVERY_WORKER_MANAGED_BUNDLE=true</code>) — the worker will generate its
                keypair and publish its PUBLIC key here automatically. You can also paste a public key
                below.
              </p>
            )}
          </div>

          <label>
            Worker SSH PUBLIC key (never a private key)
            <textarea
              rows={2}
              value={publicKey}
              placeholder="ssh-ed25519 AAAA... worker@secp"
              onChange={(e) => setPublicKey(e.target.value)}
            />
          </label>
          {publicKey && !keyCheck.ok && <p role="alert">{keyCheck.message}</p>}
          <button disabled={busy || !targetId || !keyCheck.ok} onClick={create}>
            Generate bootstrap script
          </button>
        </fieldset>
      )}

      {session && script && step === "run-script" && (
        <fieldset>
          <legend>{STEP_LABELS["run-script"]}</legend>
          <p>Run this once as root on the Proxmox host. It will:</p>
          <ul>
            {SCRIPT_ACTIONS.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
          <button onClick={() => navigator.clipboard?.writeText(script.script)}>Copy script</button>
          <pre data-testid="bootstrap-script">{script.script}</pre>
        </fieldset>
      )}

      {session && step === "bind" && session.status === "pending" && (
        <p>Bootstrap script generated. Run it, then confirm below.</p>
      )}

      {session && (step === "run-script" || step === "bind") && (
        <fieldset>
          <legend>{STEP_LABELS.complete}</legend>
          <label>
            Host SSH key fingerprint (from the proof / <code>ssh-keygen -lf</code>)
            <input
              value={fingerprint}
              placeholder="SHA256:…"
              onChange={(e) => setFingerprint(e.target.value)}
            />
          </label>
          {fingerprint && !fpCheck.ok && <p role="alert">{fpCheck.message}</p>}
          <label>
            Bounded proof (paste the full SECPDISC-PROOF block)
            <textarea rows={3} value={proof} onChange={(e) => setProof(e.target.value)} />
          </label>
          <p role="note">
            Paste the whole proof block. It carries the host&apos;s PUBLIC key line, which the worker
            uses to pin <code>known_hosts</code> and assemble its bundle automatically — no manual
            bundle files.
          </p>
          <button disabled={busy || !fpCheck.ok || session.status !== "pending"} onClick={complete}>
            Confirm bootstrap
          </button>
        </fieldset>
      )}

      {session && step === "bind" && (
        <fieldset>
          <legend>{STEP_LABELS.bind}</legend>
          <p>
            Endpoint binding digest computed. Create the separately-approved live-read authorization
            for this exact endpoint.
          </p>
          <button disabled={busy} onClick={bind}>
            Create live-read authorization
          </button>
          {/* SECP-B8: if binding fails with substrate_ineligible, grant eligibility here (target-admin
              action). Never auto-granted — the backend enforces staging_substrate:manage. */}
          <details data-testid="substrate-grant">
            <summary>Target not staging-substrate eligible?</summary>
            <p>
              If creating the authorization fails with{" "}
              <code>readonly_preflight_substrate_ineligible</code>, an operator with the{" "}
              <code>staging_substrate:manage</code> capability can grant eligibility for this target:
            </p>
            <button disabled={busy} onClick={grantEligibility}>
              Grant staging-substrate eligibility
            </button>
          </details>
        </fieldset>
      )}

      {session && step === "run-discovery" && (
        <fieldset>
          <legend>{STEP_LABELS["run-discovery"]}</legend>
          <p data-testid="bootstrap-bound">
            Status: <strong>{bootstrapStatusLabel(session.status)}</strong>. This target is bound to
            an approved live-read authorization (endpoint digest{" "}
            <code>{session.endpoint_binding_hash?.slice(0, 18)}…</code>). Go to{" "}
            <a href="/target-discovery">Target Discovery</a> to run read-only discovery and review
            the candidate plan. Live deployment apply remains sealed.
          </p>
          {/* SECP-B8: the control-plane side is complete. If discovery still reports it cannot reach
              the host, the missing prerequisite is WORKER-side (the control plane cannot observe it).
              Surface exactly what to check instead of an opaque probe_source_sealed. */}
          <details data-testid="worker-side-prerequisites">
            <summary>Discovery still can&apos;t reach the host? Check the worker-side prerequisites</summary>
            <p>
              The control-plane steps are done. The remaining prerequisites live on the WORKER (the
              app cannot observe them). If discovery fails with <code>probe_source_sealed</code>,
              confirm:
            </p>
            <ul>
              {WORKER_SIDE_PREREQUISITES.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </details>
        </fieldset>
      )}
    </section>
  );
}
