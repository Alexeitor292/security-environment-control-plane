import { useEffect, useState } from "react";

import { api } from "../api/client";
import type {
  BootstrapAvailability,
  EligibleSubstrate,
  StagingDeployment as DeploymentModel,
  StagingDeploymentPlan,
} from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";
import {
  CONTROL_PLANE_ONLY_LABEL,
  DEPLOY_ENQUEUED_NOTICE,
  RESOURCE_PROFILES,
  SAFETY_CONSTRAINTS,
  type DeploymentDraft,
  bootstrapAvailabilityLabel,
  canApprove,
  canCreate,
  canDeploy,
  canPlan,
  canSubmit,
  canTeardown,
  emptyDraft,
  isInFlight,
  planHashPrefix,
  planResourceKinds,
  statusLabel,
  validateDraft,
} from "./staging-deployment";

function ControlPlaneBanner() {
  return (
    <div className="dev-banner" role="note">
      {CONTROL_PLANE_ONLY_LABEL}
    </div>
  );
}

function CreateForm({
  substrates,
  onCreated,
}: {
  substrates: EligibleSubstrate[];
  onCreated: (dep: DeploymentModel) => void;
}) {
  const [draft, setDraft] = useState<DeploymentDraft>(emptyDraft());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const validation = validateDraft(draft);

  function set<K extends keyof DeploymentDraft>(key: K, value: DeploymentDraft[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const dep = await api.createStagingDeployment({
        execution_target_id: draft.executionTargetId,
        resource_profile: draft.resourceProfile,
        logical_name: draft.logicalName.trim() || null,
      });
      onCreated(dep);
      setDraft(emptyDraft());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Deploy Isolated Staging Lab</h2>
      <ControlPlaneBanner />
      <label>
        Eligible substrate (server alias)
        <select
          value={draft.executionTargetId}
          onChange={(e) => set("executionTargetId", e.target.value)}
        >
          <option value="">Select an eligible substrate…</option>
          {substrates.map((s) => (
            <option key={s.id} value={s.id}>
              {s.alias}
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
          value={draft.resourceProfile}
          onChange={(e) =>
            set("resourceProfile", e.target.value as DeploymentDraft["resourceProfile"])
          }
        >
          {RESOURCE_PROFILES.map((o) => (
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
        Create deployment (draft)
      </button>
    </section>
  );
}

function DeploymentDetail({
  dep,
  onChanged,
}: {
  dep: DeploymentModel;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<StagingDeploymentPlan | null>(null);
  const [bootstrap, setBootstrap] = useState<BootstrapAvailability | null>(null);

  useEffect(() => {
    let alive = true;
    if (dep.plan_hash) {
      api
        .getStagingDeploymentPlan(dep.id)
        .then((p) => alive && setPlan(p))
        .catch(() => alive && setPlan(null));
    }
    api
      .getStagingDeploymentBootstrapAvailability(dep.id)
      .then((b) => alive && setBootstrap(b))
      .catch(() => alive && setBootstrap(null));
    return () => {
      alive = false;
    };
  }, [dep.id, dep.plan_hash]);

  async function run(action: () => Promise<DeploymentModel>) {
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

  const planKinds = planResourceKinds(plan);

  return (
    <section className="card">
      <header className="row">
        <h3>{dep.display_name}</h3>
        <StatusBadge state={dep.status} />
      </header>
      <ControlPlaneBanner />
      {isInFlight(dep.status) && (
        <div className="dev-banner" role="status">
          {DEPLOY_ENQUEUED_NOTICE}
        </div>
      )}

      <dl className="kv">
        <dt>Ownership identity</dt>
        <dd className="mono">{dep.ownership_label}</dd>
        <dt>Plan hash</dt>
        <dd className="mono">{planHashPrefix(dep.plan_hash)}</dd>
        <dt>Plan version</dt>
        <dd>{dep.plan_version}</dd>
        <dt>Lifecycle</dt>
        <dd>{statusLabel(dep.status)}</dd>
        <dt>Bootstrap authority</dt>
        <dd>{bootstrapAvailabilityLabel(bootstrap)}</dd>
        {dep.failure_code && (
          <>
            <dt>Failure</dt>
            <dd className="mono">{dep.failure_code}</dd>
          </>
        )}
      </dl>

      {planKinds.length > 0 && (
        <div>
          <h4>Planned resources (the app creates all of these)</h4>
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

      {error && <div className="error">{error}</div>}

      <div className="actions">
        <button
          disabled={busy || !canPlan(dep)}
          onClick={() => run(() => api.planStagingDeployment(dep.id))}
        >
          Generate plan
        </button>
        <button
          disabled={busy || !canSubmit(dep)}
          onClick={() => run(() => api.submitStagingDeployment(dep.id))}
        >
          Submit for approval
        </button>
        <button
          disabled={busy || !canApprove(dep)}
          onClick={() => run(() => api.approveStagingDeployment(dep.id, dep.plan_hash))}
        >
          Approve exact plan
        </button>
        <button
          disabled={busy || !canDeploy(dep)}
          onClick={() => run(() => api.deployStagingDeployment(dep.id))}
          title={CONTROL_PLANE_ONLY_LABEL}
        >
          Deploy (enqueue apply)
        </button>
        <button
          disabled={busy || !canTeardown(dep)}
          onClick={() => run(() => api.teardownStagingDeployment(dep.id))}
        >
          Request teardown
        </button>
      </div>
    </section>
  );
}

export function StagingDeployment() {
  const substrates = useAsync(() => api.listEligibleSubstrates(), []);
  const deployments = useAsync(() => api.listStagingDeployments(), []);

  function reloadAll() {
    deployments.reload();
  }

  return (
    <div className="page">
      <h1>Isolated Staging Lab Deployments</h1>
      <p className="muted">
        Create a deployment, compile an immutable content-addressed plan, approve the exact plan,
        and enqueue a worker-executed apply. {CONTROL_PLANE_ONLY_LABEL}
      </p>
      <CreateForm substrates={substrates.data ?? []} onCreated={reloadAll} />
      {deployments.loading && <div>Loading…</div>}
      {deployments.error && <div className="error">{deployments.error}</div>}
      {(deployments.data ?? []).map((dep) => (
        <DeploymentDetail key={dep.id} dep={dep} onChanged={reloadAll} />
      ))}
    </div>
  );
}
