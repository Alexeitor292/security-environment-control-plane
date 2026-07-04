import { useState } from "react";

import { api } from "../api/client";
import type { EligibleSubstrate, StagingLab as StagingLabModel } from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";
import {
  BOOTSTRAP_PROFILES,
  QUEUED_NOTICE,
  RESOURCE_CLASSES,
  ROLLBACK_POLICIES,
  SAFETY_CONSTRAINTS,
  SIMULATION_ONLY_LABEL,
  type StagingLabDraft,
  canApprove,
  canCreate,
  canPlan,
  canQueueSimulation,
  canQueueTeardown,
  canSubmit,
  emptyDraft,
  isQueuedOrRunning,
  observedResources,
  planHashPrefix,
  planResourceKinds,
  rollbackPosture,
  statusLabel,
  substrateOptions,
  validateDraft,
} from "./staging-lab";

function SimulationBanner() {
  return (
    <div className="dev-banner" role="note">
      {SIMULATION_ONLY_LABEL}
    </div>
  );
}

function CreateForm({
  substrates,
  onCreated,
}: {
  substrates: EligibleSubstrate[];
  onCreated: (lab: StagingLabModel) => void;
}) {
  const [draft, setDraft] = useState<StagingLabDraft>(emptyDraft());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const options = substrateOptions(substrates);
  const validation = validateDraft(draft);

  function set<K extends keyof StagingLabDraft>(key: K, value: StagingLabDraft[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const lab = await api.createStagingLab({
        execution_target_id: draft.executionTargetId,
        resource_class: draft.resourceClass,
        bootstrap_artifact_profile: draft.bootstrapArtifactProfile,
        rollback_policy: draft.rollbackPolicy,
        logical_name: draft.logicalName.trim() || null,
      });
      onCreated(lab);
      setDraft(emptyDraft());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Create Disposable Staging Lab</h2>
      <SimulationBanner />
      <label>
        Eligible substrate (server alias)
        <select
          value={draft.executionTargetId}
          onChange={(e) => set("executionTargetId", e.target.value)}
        >
          <option value="">Select an eligible substrate…</option>
          {options.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Optional logical name (kebab-case; server owns the identity)
        <input
          value={draft.logicalName}
          onChange={(e) => set("logicalName", e.target.value)}
          placeholder="alpha"
        />
      </label>
      <label>
        Bounded resource profile
        <select
          value={draft.resourceClass}
          onChange={(e) => set("resourceClass", e.target.value as StagingLabDraft["resourceClass"])}
        >
          {RESOURCE_CLASSES.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Approved bootstrap-artifact profile
        <select
          value={draft.bootstrapArtifactProfile}
          onChange={(e) =>
            set(
              "bootstrapArtifactProfile",
              e.target.value as StagingLabDraft["bootstrapArtifactProfile"],
            )
          }
        >
          {BOOTSTRAP_PROFILES.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Rollback policy
        <select
          value={draft.rollbackPolicy}
          onChange={(e) =>
            set("rollbackPolicy", e.target.value as StagingLabDraft["rollbackPolicy"])
          }
        >
          {ROLLBACK_POLICIES.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      {!validation.ok && (
        <ul className="errors">
          {validation.errors.map((msg) => (
            <li key={msg}>{msg}</li>
          ))}
        </ul>
      )}
      {error && <div className="error">{error}</div>}
      <button disabled={!canCreate(busy, draft)} onClick={submit}>
        Create staging lab (draft)
      </button>
    </section>
  );
}

function LabDetail({ lab, onChanged }: { lab: StagingLabModel; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(action: () => Promise<StagingLabModel>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const planKinds = planResourceKinds(lab);
  const observed = observedResources(lab);

  return (
    <section className="card">
      <header className="row">
        <h3>{lab.display_name}</h3>
        <StatusBadge state={lab.status} />
      </header>
      <SimulationBanner />
      {isQueuedOrRunning(lab.status) && (
        <div className="dev-banner" role="status">
          {QUEUED_NOTICE}
        </div>
      )}

      <dl className="kv">
        <dt>Ownership identity</dt>
        <dd className="mono">{lab.ownership_label}</dd>
        <dt>Plan hash</dt>
        <dd className="mono">{planHashPrefix(lab.plan_hash)}</dd>
        <dt>Plan version</dt>
        <dd>{lab.plan_version}</dd>
        <dt>Lifecycle</dt>
        <dd>{statusLabel(lab.status)}</dd>
        <dt>Rollback posture</dt>
        <dd>{rollbackPosture(lab)}</dd>
      </dl>

      {planKinds.length > 0 && (
        <div>
          <h4>Planned logical resources</h4>
          <ul>
            {planKinds.map((k) => (
              <li key={k} className="mono">
                {k}
              </li>
            ))}
          </ul>
          <h4>Safety constraints</h4>
          <ul>
            {SAFETY_CONSTRAINTS.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      )}

      {observed.length > 0 ? (
        <div>
          <h4>Simulated observations (fake — worker-recorded)</h4>
          <ul>
            {observed.map((r) => (
              <li key={r.kind} className="mono">
                {r.kind} · owner={r.owner} · {r.phase}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        isQueuedOrRunning(lab.status) && (
          <p className="muted">Observations appear once the worker records completion.</p>
        )
      )}

      {error && <div className="error">{error}</div>}

      <div className="actions">
        <button disabled={busy || !canPlan(lab)} onClick={() => run(() => api.planStagingLab(lab.id))}>
          Generate plan
        </button>
        <button
          disabled={busy || !canSubmit(lab)}
          onClick={() => run(() => api.submitStagingLab(lab.id))}
        >
          Submit for approval
        </button>
        <button
          disabled={busy || !canApprove(lab)}
          onClick={() => run(() => api.approveStagingLab(lab.id, lab.plan_hash))}
        >
          Approve (sim only)
        </button>
        <button
          disabled={busy || !canQueueSimulation(lab)}
          onClick={() => run(() => api.queueStagingLabSimulation(lab.id))}
          title={SIMULATION_ONLY_LABEL}
        >
          Simulate Provisioning (queue)
        </button>
        <button
          disabled={busy || !canQueueTeardown(lab)}
          onClick={() => run(() => api.queueStagingLabTeardown(lab.id))}
          title={SIMULATION_ONLY_LABEL}
        >
          Simulate Teardown (queue)
        </button>
      </div>
    </section>
  );
}

export function StagingLab() {
  const substrates = useAsync(() => api.listEligibleSubstrates(), []);
  const labs = useAsync(() => api.listStagingLabs(), []);

  function reloadAll() {
    labs.reload();
  }

  return (
    <div className="page">
      <h1>Disposable Staging Labs</h1>
      <p className="muted">
        Define a disposable read-only staging lab, generate an immutable plan, approve it, and
        QUEUE a labeled fake simulation for a worker to process. {SIMULATION_ONLY_LABEL}
      </p>
      <CreateForm substrates={substrates.data ?? []} onCreated={reloadAll} />
      {labs.loading && <div>Loading…</div>}
      {labs.error && <div className="error">{labs.error}</div>}
      {(labs.data ?? []).map((lab) => (
        <LabDetail key={lab.id} lab={lab} onChanged={reloadAll} />
      ))}
    </div>
  );
}
