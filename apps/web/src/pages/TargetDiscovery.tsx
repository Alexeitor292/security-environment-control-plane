import "./discovery.css";

import { useState } from "react";

import { ApiClientError, api } from "../api/client";
import type {
  DiscoveryCandidatePlan,
  DiscoveryEnrollment,
  DiscoveryEvidence,
  EligibleSubstrate,
} from "../api/types";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberSelect,
  CyberTable,
  EmptyState,
  EvidenceBadge,
  HashChip,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  StepRail,
  useAction,
} from "../components/ui";
import { RiveDiscoveryScan } from "../components/rive/wrappers";
import { useAsync } from "../hooks";
import {
  CANDIDATE_PLAN_STALE_HINT,
  DISCOVERY_ERROR_TEXT,
  PLAN_APPROVAL_DECISION_NOTICE,
  PLAN_NON_EXECUTABLE_NOTICE,
  REQUEST_ENQUEUE_NOTICE,
  WORKER_QUEUED_NOTICE,
  WORKER_RUNNING_NOTICE,
  candidatePlanRows,
  discoveryRailItems,
  eligibilityView,
  evidenceFacts,
  isOffRail,
  planIsApprovable,
  workerPostureRows,
} from "./discovery-view";
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
  statusLabel,
  validateDraft,
} from "./target-discovery";

const opt = <T,>(p: Promise<T>): Promise<T | null> => p.catch(() => null);

/** A not-recorded 404 is the expected pending state (evidence null, not an
 *  outage). Only a real transport/server error is "unavailable". */
async function loadEvidence(
  id: string,
): Promise<{ evidence: DiscoveryEvidence | null; unavailable: boolean }> {
  try {
    return { evidence: await api.getDiscoveryEvidence(id), unavailable: false };
  } catch (e) {
    const notRecorded =
      e instanceof ApiClientError && (e.status === 404 || e.code === "not_found");
    return { evidence: null, unavailable: !notRecorded };
  }
}

interface DiscoveryExtras {
  evidence: DiscoveryEvidence | null;
  evidenceUnavailable: boolean;
  plan: DiscoveryCandidatePlan | null;
}

function RequestForm({
  substrates,
  substratesUnavailable,
  onCreated,
}: {
  substrates: EligibleSubstrate[];
  substratesUnavailable: boolean;
  onCreated: (e: DiscoveryEnrollment) => void;
}) {
  const [draft, setDraft] = useState<DiscoveryDraft>(emptyDraft());
  const [apiError, setApiError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [interacted, setInteracted] = useState(false);
  const validation = validateDraft(draft);

  function set<K extends keyof DiscoveryDraft>(key: K, value: DiscoveryDraft[K]) {
    setInteracted(true);
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setApiError(null);
    try {
      const e = await api.requestTargetDiscovery({
        execution_target_id: draft.executionTargetId,
        resource_profile: draft.resourceProfile,
        logical_name: draft.logicalName.trim() || null,
      });
      onCreated(e);
      setDraft(emptyDraft());
      setInteracted(false);
    } catch (err) {
      setApiError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <CyberCard heading="Enroll target for read-only discovery">
      <SafetyNotice role="note" tone="warn">
        {READ_ONLY_LABEL}
      </SafetyNotice>
      {substratesUnavailable ? (
        <div className="error-box">Eligible substrates could not be loaded.</div>
      ) : (
        <div className="disc-create-grid">
          <CyberSelect
            label="Eligible substrate (server alias)"
            hint="Required."
            required
            value={draft.executionTargetId}
            onChange={(e) => set("executionTargetId", e.target.value)}
            options={[
              { value: "", label: "Select an eligible substrate…" },
              ...substrates.map((s) => ({ value: s.id, label: s.alias })),
            ]}
          />
          <CyberInput
            label="Optional logical name (kebab-case; server owns the identity)"
            value={draft.logicalName}
            onChange={(e) => set("logicalName", e.target.value)}
            placeholder="alpha"
          />
          <CyberSelect
            label="Bounded resource profile"
            value={draft.resourceProfile}
            showHelp
            onChange={(e) =>
              set("resourceProfile", e.target.value as DiscoveryDraft["resourceProfile"])
            }
            options={RESOURCE_PROFILES.map((o) => ({
              value: o.value,
              label: o.label,
              help: o.help,
            }))}
          />
        </div>
      )}
      <p className="disc-note">{REQUEST_ENQUEUE_NOTICE}</p>
      {interacted && !validation.ok && (
        <ul className="errors error-box">
          {validation.errors.map((msg) => (
            <li key={msg}>{msg}</li>
          ))}
        </ul>
      )}
      {apiError !== null && (
        <ClosedCodeError
          error={apiError}
          codeText={DISCOVERY_ERROR_TEXT}
          onDismiss={() => setApiError(null)}
        />
      )}
      <div style={{ marginTop: 10 }}>
        <CyberButton disabled={!canRequest(busy, draft)} onClick={submit}>
          Request read-only discovery
        </CyberButton>
      </div>
    </CyberCard>
  );
}

function EligibilityPanel({ evidence }: { evidence: DiscoveryEvidence | null }) {
  const view = eligibilityView(evidence);
  const facts = evidenceFacts(evidence);
  return (
    <CyberCard surface="well" heading="Eligibility / capability (read-only)">
      <div className="disc-eligibility">
        <StatusBadge state={view.state} domain="eligibility" />
        <span className="muted">{view.label}</span>
      </div>
      {view.reasonCode && (
        <p className="disc-reason">
          <span className="muted">reason</span>{" "}
          <code className="mono">{view.reasonCode}</code>
        </p>
      )}
      {view.state === "unverifiable" && (
        <p className="disc-note">
          Unverifiable is neither pass nor fail — a probe could not confirm this
          fact. It does not imply the host is ineligible or production-safe.
        </p>
      )}
      {!view.recorded ? (
        <EmptyState title="Nothing recorded yet">
          Eligibility facts appear only after a worker durably records evidence.
          Queueing discovery does not create them.
        </EmptyState>
      ) : facts.length > 0 ? (
        <div className="disc-facts">
          {facts.map((f) => (
            <EvidenceBadge
              key={f.key}
              title={`${f.label}: ${f.value}`}
              status={view.state === "eligible" ? "pass" : "unverifiable"}
            />
          ))}
        </div>
      ) : (
        <p className="muted">No allowlisted facts recorded.</p>
      )}
    </CyberCard>
  );
}

function CandidatePlanPanel({ plan }: { plan: DiscoveryCandidatePlan }) {
  return (
    <CyberCard surface="well" heading="Discovery-derived candidate plan">
      <div className="disc-plan-head">
        <StatusBadge state={plan.status} domain="plan-decision" />
        <span className="disc-hashline">
          plan <HashChip value={plan.plan_hash} digits={12} /> · evidence{" "}
          <HashChip value={plan.evidence_hash} digits={8} />
        </span>
      </div>
      <KeyValueList
        items={candidatePlanRows(plan).map((r) => ({
          key: r.key,
          value: r.value,
          mono: r.mono,
        }))}
      />
      {plan.resources.length > 0 && (
        <>
          <h4>Proposed resources</h4>
          <ul className="disc-kinds">
            {plan.resources.map((r) => (
              <li key={`${r.kind}-${r.resource_ref}`} className="mono">
                {r.kind} · {r.resource_ref}
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="disc-note">{PLAN_NON_EXECUTABLE_NOTICE}</p>
      <SafetyNotice role="note" tone="warn">
        {SEALED_APPLY_MESSAGE}
      </SafetyNotice>
    </CyberCard>
  );
}

function EnrollmentDetail({
  enrollment,
  onChanged,
}: {
  enrollment: DiscoveryEnrollment;
  onChanged: () => void;
}) {
  const action = useAction({ codeText: DISCOVERY_ERROR_TEXT });
  const extras = useAsync<DiscoveryExtras>(async () => {
    const [ev, plan] = await Promise.all([
      loadEvidence(enrollment.id),
      enrollment.active_plan_hash
        ? opt(api.getDiscoveryCandidatePlan(enrollment.id))
        : Promise.resolve(null),
    ]);
    return { evidence: ev.evidence, evidenceUnavailable: ev.unavailable, plan };
  }, [enrollment.id, enrollment.active_plan_hash, enrollment.status]);

  const run = (fn: () => Promise<DiscoveryEnrollment>) =>
    action.run(async () => {
      await fn();
    }, onChanged);

  const evidence = extras.data?.evidence ?? null;
  const evidenceUnavailable = extras.data?.evidenceUnavailable ?? false;
  const plan = extras.data?.plan ?? null;
  const offRail = isOffRail(enrollment.status);
  const approvable = planIsApprovable(plan, enrollment) && canApprove(enrollment);

  return (
    <CyberCard>
      <div className="disc-detail-head">
        <div>
          <h3>{enrollment.display_name}</h3>
          <div className="disc-sub mono">{enrollment.ownership_label}</div>
        </div>
        <span className="disc-eligibility">
          <RiveDiscoveryScan
            status={enrollment.status}
            label="Discovery"
            size={22}
          />
          <StatusBadge state={enrollment.status} domain="discovery" />
        </span>
      </div>
      <SafetyNotice role="note" tone="warn">
        {READ_ONLY_LABEL}
      </SafetyNotice>
      {enrollment.status === "requested" && (
        <div className="disc-offrail">
          <SafetyNotice role="status" tone="info">
            {WORKER_QUEUED_NOTICE}
          </SafetyNotice>
        </div>
      )}
      {enrollment.status === "discovering" && (
        <div className="disc-offrail">
          <SafetyNotice role="status" tone="info">
            {WORKER_RUNNING_NOTICE}
          </SafetyNotice>
        </div>
      )}

      <div className="disc-rail">
        <StepRail
          items={discoveryRailItems(enrollment.status)}
          aria-label="Discovery lifecycle"
        />
        {offRail && (
          <div className="disc-offrail">
            <SafetyNotice role="status" tone="danger">
              Current state: {statusLabel(enrollment.status)}
              {enrollment.failure_code && (
                <>
                  {" · reason "}
                  <code className="mono">{enrollment.failure_code}</code>
                </>
              )}
            </SafetyNotice>
          </div>
        )}
      </div>

      <div className="disc-grid">
        <CyberCard surface="well" heading="Worker-owned execution">
          <KeyValueList items={workerPostureRows(enrollment)} />
          <p className="disc-note">
            The API enqueues a durable job; a worker claims it and owns every
            Proxmox read probe. Ownership identity is server-owned. Enqueueing is
            distinct from a worker claiming; worker identity approval is distinct
            from host authorization.
          </p>
          {enrollment.active_plan_hash && (
            <p className="disc-hashline">
              active candidate plan{" "}
              <HashChip value={enrollment.active_plan_hash} digits={12} />
            </p>
          )}
        </CyberCard>

        {extras.loading && !extras.data ? (
          <CyberCard surface="well" heading="Eligibility / capability (read-only)">
            <Skeleton lines={3} />
          </CyberCard>
        ) : evidenceUnavailable ? (
          <CyberCard surface="well" heading="Eligibility / capability (read-only)">
            <p className="muted">Evidence source unavailable.</p>
          </CyberCard>
        ) : (
          // evidence null here means "not recorded yet" — EligibilityPanel
          // renders the truthful pending EmptyState.
          <EligibilityPanel evidence={evidence} />
        )}
      </div>

      {evidence && (
        <details className="disc-disclosure">
          <summary>Operator detail — recorded evidence hash</summary>
          <p className="disc-hashline">
            immutable evidence <HashChip value={evidence.evidence_hash} digits={18} />{" "}
            · recorded {evidence.created_at.slice(0, 19).replace("T", " ")} UTC
          </p>
        </details>
      )}

      {plan && <CandidatePlanPanel plan={plan} />}

      {plan === null && enrollment.active_plan_hash && !extras.loading && (
        <p className="muted">Candidate plan unavailable.</p>
      )}

      {(enrollment.status === "plan_ready" ||
        enrollment.status === "discovered" ||
        offRail) &&
        !plan &&
        !enrollment.active_plan_hash &&
        !extras.loading && (
          <EmptyState title="No candidate plan yet">
            A candidate plan appears only after discovery records evidence and
            derives one. It is discovery-derived and non-executable.
          </EmptyState>
        )}

      <CyberCard surface="well" heading="Safety constraints — fixed by the server contract">
        <ul className="disc-constraints">
          {SAFETY_CONSTRAINTS.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      </CyberCard>

      {action.error && (
        <div className="error-box" role="alert" style={{ marginTop: 10 }}>
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}

      <div className="disc-actions">
        <CyberButton
          variant="secondary"
          size="sm"
          disabled={action.busy || !canRerun(enrollment)}
          title={
            canRerun(enrollment)
              ? "Re-run produces a new authoritative enrollment revision."
              : `Available when plan-ready, failed, or approved — current: ${statusLabel(enrollment.status)}`
          }
          onClick={() => run(() => api.rerunDiscovery(enrollment.id))}
        >
          Re-run discovery
        </CyberButton>
        <CyberButton
          variant="ok"
          size="sm"
          disabled={action.busy || !approvable}
          title={
            approvable
              ? PLAN_APPROVAL_DECISION_NOTICE
              : !canApprove(enrollment)
                ? `Available when a candidate plan is ready — current: ${statusLabel(enrollment.status)}`
                : plan === null
                  ? "The candidate plan could not be loaded — reload before approving."
                  : CANDIDATE_PLAN_STALE_HINT
          }
          onClick={() =>
            run(() => api.approveDiscoveryPlan(enrollment.id, enrollment.active_plan_hash))
          }
        >
          Approve candidate plan (apply sealed)
        </CyberButton>
        <CyberButton
          variant="danger"
          size="sm"
          disabled={action.busy || !canApprove(enrollment)}
          title={
            canApprove(enrollment)
              ? "Reject the candidate plan for this enrollment."
              : `Available when a candidate plan is ready — current: ${statusLabel(enrollment.status)}`
          }
          onClick={() => run(() => api.rejectDiscoveryPlan(enrollment.id))}
        >
          Reject
        </CyberButton>
      </div>
      <p className="disc-note">{PLAN_APPROVAL_DECISION_NOTICE}</p>
    </CyberCard>
  );
}

export function TargetDiscovery() {
  const substrates = useAsync(() => api.listEligibleSubstrates(), []);
  const enrollments = useAsync(() => api.listDiscoveryEnrollments(), []);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const list = enrollments.data ?? null;
  const selected = list?.find((e) => e.id === selectedId) ?? null;

  return (
    <div className="disc">
      <div className="disc-head">
        <h1>Target Enrollment &amp; Read-Only Discovery</h1>
        <p className="disc-intro">
          Enroll a Proxmox substrate, run a worker-owned read-only discovery job,
          and review + approve the discovery-derived candidate plan.{" "}
          {READ_ONLY_LABEL}
        </p>
      </div>

      <RequestForm
        substrates={substrates.data ?? []}
        substratesUnavailable={substrates.error !== null && !substrates.loading}
        onCreated={(e) => {
          enrollments.reload();
          setSelectedId(e.id);
        }}
      />

      {enrollments.loading && !enrollments.data && <Skeleton lines={4} />}
      {enrollments.error && (
        <div className="error-box">Discovery enrollments could not be loaded.</div>
      )}
      {list && list.length === 0 && (
        <EmptyState title="No discovery enrollments yet">
          Request read-only discovery above — the app enqueues a worker job and
          contacts no host.
        </EmptyState>
      )}
      {list && list.length > 0 && (
        <CyberTable
          head={["Enrollment", "Substrate", "Lifecycle", "Plan", "Reason", "Status"]}
          label="Discovery enrollments"
          caption={`${list.length} enrollment${list.length === 1 ? "" : "s"} · ${READ_ONLY_LABEL}`}
        >
          {list.map((e) => (
            <tr
              key={e.id}
              className={selectedId === e.id ? "disc-row--selected" : undefined}
            >
              <td>
                <button
                  type="button"
                  className="disc-item-btn"
                  onClick={() =>
                    setSelectedId((cur) => (cur === e.id ? null : e.id))
                  }
                  aria-expanded={selectedId === e.id}
                  aria-controls="disc-detail"
                >
                  <span>
                    <span className="disc-item-name">{e.display_name}</span>
                    <span className="disc-item-sub mono">{e.ownership_label}</span>
                  </span>
                </button>
              </td>
              <td className="mono">{e.execution_target_id.slice(0, 8)}</td>
              <td className="muted">{statusLabel(e.status)}</td>
              <td>
                {e.active_plan_hash ? (
                  <HashChip value={e.active_plan_hash} digits={12} />
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              <td className="mono">{e.failure_code ?? "—"}</td>
              <td>
                <StatusBadge state={e.status} domain="discovery" />
              </td>
            </tr>
          ))}
        </CyberTable>
      )}

      <div id="disc-detail">
        {selected && (
          <EnrollmentDetail
            key={selected.id}
            enrollment={selected}
            onChanged={() => enrollments.reload()}
          />
        )}
      </div>
    </div>
  );
}
