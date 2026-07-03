import { useState } from "react";

import { api } from "../api/client";
import type { ExecutionTarget, StagingLab as StagingLabModel } from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";
import {
  RESOURCE_CLASSES,
  ROLLBACK_POLICIES,
  SAFETY_CONSTRAINTS,
  SIMULATION_ONLY_LABEL,
  type StagingLabDraft,
  canApprove,
  canCreate,
  canPlan,
  canSimulate,
  canSubmit,
  canTeardown,
  emptyDraft,
  observedResources,
  planHashPrefix,
  planResourceKinds,
  rollbackPosture,
  substrateOptions,
  teardownStatusLabel,
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
  targets,
  onCreated,
}: {
  targets: ExecutionTarget[];
  onCreated: (lab: StagingLabModel) => void;
}) {
  const [draft, setDraft] = useState<StagingLabDraft>(emptyDraft());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const options = substrateOptions(targets);
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
        display_name: draft.displayName.trim(),
        ownership_label: draft.ownershipLabel.trim(),
        resource_class: draft.resourceClass,
        rollback_policy: draft.rollbackPolicy,
        bootstrap_artifact_profile_id: draft.bootstrapArtifactProfileId.trim(),
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
        Approved substrate target
        <select
          value={draft.executionTargetId}
          onChange={(e) => set("executionTargetId", e.target.value)}
        >
          <option value="">Select an approved substrate…</option>
          {options.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Lab display name
        <input
          value={draft.displayName}
          onChange={(e) => set("displayName", e.target.value)}
          placeholder="Alpha staging lab"
        />
      </label>
      <label>
        Ownership label (immutable lab identity)
        <input
          value={draft.ownershipLabel}
          onChange={(e) => set("ownershipLabel", e.target.value)}
          placeholder="secp-lab-alpha"
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
        <input
          value={draft.bootstrapArtifactProfileId}
          onChange={(e) => set("bootstrapArtifactProfileId", e.target.value)}
          placeholder="approved-offline-profile-a"
        />
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

      <dl className="kv">
        <dt>Ownership identity</dt>
        <dd className="mono">{lab.ownership_label}</dd>
        <dt>Plan hash</dt>
        <dd className="mono">{planHashPrefix(lab.plan_hash)}</dd>
        <dt>Plan version</dt>
        <dd>{lab.plan_version}</dd>
        <dt>Rollback posture</dt>
        <dd>{rollbackPosture(lab)}</dd>
        <dt>Teardown status</dt>
        <dd>{teardownStatusLabel(lab.status)}</dd>
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

      {observed.length > 0 && (
        <div>
          <h4>Simulated observations (fake)</h4>
          <ul>
            {observed.map((r) => (
              <li key={r.kind} className="mono">
                {r.kind} · owner={r.owner} · {r.phase}
              </li>
            ))}
          </ul>
        </div>
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
          onClick={() => run(() => api.approveStagingLab(lab.id, lab.plan_hash, "approved via UI"))}
        >
          Approve (sim only)
        </button>
        <button
          disabled={busy || !canSimulate(lab)}
          onClick={() => run(() => api.simulateStagingLab(lab.id))}
          title={SIMULATION_ONLY_LABEL}
        >
          Simulate provisioning
        </button>
        <button
          disabled={busy || !canTeardown(lab)}
          onClick={() => run(() => api.teardownStagingLab(lab.id))}
          title={SIMULATION_ONLY_LABEL}
        >
          Simulate teardown
        </button>
      </div>
    </section>
  );
}

export function StagingLab() {
  const targets = useAsync(() => api.listTargets(), []);
  const labs = useAsync(() => api.listStagingLabs(), []);

  function reloadAll() {
    labs.reload();
  }

  return (
    <div className="page">
      <h1>Disposable Staging Labs</h1>
      <p className="muted">
        Define a disposable read-only staging lab, generate an immutable plan, approve it, and run
        a labeled fake simulation. {SIMULATION_ONLY_LABEL}
      </p>
      <CreateForm targets={targets.data ?? []} onCreated={reloadAll} />
      {labs.loading && <div>Loading…</div>}
      {labs.error && <div className="error">{labs.error}</div>}
      {(labs.data ?? []).map((lab) => (
        <LabDetail key={lab.id} lab={lab} onChanged={reloadAll} />
      ))}
    </div>
  );
}
