import { useEffect, useState } from "react";

import { api } from "../api/client";
import type {
  DiscoveryCandidatePlan,
  DiscoveryEnrollment,
  DiscoveryEvidence,
  EligibleSubstrate,
} from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";
import {
  READ_ONLY_LABEL,
  RESOURCE_PROFILES,
  SAFETY_CONSTRAINTS,
  SEALED_APPLY_MESSAGE,
  type DiscoveryDraft,
  canApprove,
  canRequest,
  canRerun,
  emptyDraft,
  evidenceSummary,
  isInFlight,
  planHashPrefix,
  planResourceKinds,
  statusLabel,
  validateDraft,
} from "./target-discovery";

function ReadOnlyBanner() {
  return (
    <div className="dev-banner" role="note">
      {READ_ONLY_LABEL}
    </div>
  );
}

function RequestForm({
  substrates,
  onCreated,
}: {
  substrates: EligibleSubstrate[];
  onCreated: (e: DiscoveryEnrollment) => void;
}) {
  const [draft, setDraft] = useState<DiscoveryDraft>(emptyDraft());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const validation = validateDraft(draft);

  function set<K extends keyof DiscoveryDraft>(key: K, value: DiscoveryDraft[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const e = await api.requestTargetDiscovery({
        execution_target_id: draft.executionTargetId,
        resource_profile: draft.resourceProfile,
        logical_name: draft.logicalName.trim() || null,
      });
      onCreated(e);
      setDraft(emptyDraft());
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Enroll Target for Read-Only Discovery</h2>
      <ReadOnlyBanner />
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
            set("resourceProfile", e.target.value as DiscoveryDraft["resourceProfile"])
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
      <button disabled={!canRequest(busy, draft)} onClick={submit}>
        Request read-only discovery
      </button>
    </section>
  );
}

function EnrollmentDetail({
  enrollment,
  onChanged,
}: {
  enrollment: DiscoveryEnrollment;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<DiscoveryCandidatePlan | null>(null);
  const [evidence, setEvidence] = useState<DiscoveryEvidence | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .getDiscoveryEvidence(enrollment.id)
      .then((e) => alive && setEvidence(e))
      .catch(() => alive && setEvidence(null));
    if (enrollment.active_plan_hash) {
      api
        .getDiscoveryCandidatePlan(enrollment.id)
        .then((p) => alive && setPlan(p))
        .catch(() => alive && setPlan(null));
    }
    return () => {
      alive = false;
    };
  }, [enrollment.id, enrollment.active_plan_hash]);

  async function run(action: () => Promise<DiscoveryEnrollment>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const planKinds = planResourceKinds(plan);

  return (
    <section className="card">
      <header className="row">
        <h3>{enrollment.display_name}</h3>
        <StatusBadge state={enrollment.status} />
      </header>
      <ReadOnlyBanner />
      {isInFlight(enrollment.status) && (
        <div className="dev-banner" role="status">
          Read-only discovery job queued — a worker will run the probes.
        </div>
      )}

      <dl className="kv">
        <dt>Ownership identity</dt>
        <dd className="mono">{enrollment.ownership_label}</dd>
        <dt>Lifecycle</dt>
        <dd>{statusLabel(enrollment.status)}</dd>
        <dt>Enrollment version</dt>
        <dd>{enrollment.enrollment_version}</dd>
        <dt>Candidate plan</dt>
        <dd className="mono">{planHashPrefix(enrollment.active_plan_hash)}</dd>
        {enrollment.failure_code && (
          <>
            <dt>Reason</dt>
            <dd className="mono">{enrollment.failure_code}</dd>
          </>
        )}
      </dl>

      {evidence && (
        <div>
          <h4>Capability / eligibility (read-only)</h4>
          <ul>
            {evidenceSummary(evidence).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      )}

      {planKinds.length > 0 && plan && (
        <div>
          <h4>
            Discovery-derived candidate plan — node <span className="mono">{plan.node}</span>,
            storage <span className="mono">{plan.storage}</span>
          </h4>
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
          <div className="dev-banner" role="note">
            {SEALED_APPLY_MESSAGE}
          </div>
        </div>
      )}

      {error && <div className="error">{error}</div>}

      <div className="actions">
        <button
          disabled={busy || !canRerun(enrollment)}
          onClick={() => run(() => api.rerunDiscovery(enrollment.id))}
        >
          Re-run discovery
        </button>
        <button
          disabled={busy || !canApprove(enrollment)}
          onClick={() => run(() => api.approveDiscoveryPlan(enrollment.id, enrollment.active_plan_hash))}
          title={SEALED_APPLY_MESSAGE}
        >
          Approve candidate plan (apply sealed)
        </button>
        <button
          disabled={busy || !canApprove(enrollment)}
          onClick={() => run(() => api.rejectDiscoveryPlan(enrollment.id))}
        >
          Reject
        </button>
      </div>
    </section>
  );
}

export function TargetDiscovery() {
  const substrates = useAsync(() => api.listEligibleSubstrates(), []);
  const enrollments = useAsync(() => api.listDiscoveryEnrollments(), []);

  function reloadAll() {
    enrollments.reload();
  }

  return (
    <div className="page">
      <h1>Target Enrollment &amp; Read-Only Discovery</h1>
      <p className="muted">
        Enroll a Proxmox substrate, run a worker-owned read-only discovery job, and review + approve
        the discovery-derived candidate plan. {READ_ONLY_LABEL}
      </p>
      <RequestForm substrates={substrates.data ?? []} onCreated={reloadAll} />
      {enrollments.loading && <div>Loading…</div>}
      {enrollments.error && <div className="error">{enrollments.error}</div>}
      {(enrollments.data ?? []).map((e) => (
        <EnrollmentDetail key={e.id} enrollment={e} onChanged={reloadAll} />
      ))}
    </div>
  );
}
