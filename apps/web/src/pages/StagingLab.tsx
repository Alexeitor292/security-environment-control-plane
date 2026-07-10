import "./staging.css";

import { useState } from "react";

import { api } from "../api/client";
import type { EligibleSubstrate, StagingLab as StagingLabModel } from "../api/types";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberSelect,
  CyberTable,
  EmptyState,
  HashChip,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  StepRail,
  shortId,
  useAction,
} from "../components/ui";
import { CyberGridBackground } from "../components/backgrounds";
import { useAsync } from "../hooks";
import {
  BOOTSTRAP_PROFILES,
  LIFECYCLE_STEPS,
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
  isFailed,
  isQueuedOrRunning,
  lifecycleIndex,
  observedResources,
  planResourceKinds,
  rollbackPosture,
  statusLabel,
  substrateOptions,
  validateDraft,
} from "./staging-lab";
import {
  LAB_APPROVAL_SCOPE_NOTICE,
  OBSERVATIONS_EMPTY_TITLE,
  OBSERVATIONS_IDLE_BODY,
  OBSERVATIONS_QUEUED_BODY,
  PLAN_PIN_NOTICE,
  STAGING_ERROR_TEXT,
  isOffRail,
  lifecycleRailItems,
} from "./staging-view";

function planHashCell(hash: string | null | undefined) {
  return hash ? (
    <HashChip value={hash} digits={12} />
  ) : (
    <span className="muted">pending</span>
  );
}

function teardownState(status: StagingLabModel["status"]): string {
  if (status === "teardown_queued" || status === "tearing_down" || status === "destroyed") {
    return statusLabel(status);
  }
  return "No teardown requested.";
}

function hasRecordedSimulation(lab: StagingLabModel): boolean {
  const resources = (lab.simulated_observed_state as
    | { resources?: unknown[] }
    | null
    | undefined)?.resources;
  return Array.isArray(resources) && resources.length > 0;
}

function labCompletedStatuses(lab: StagingLabModel): StagingLabModel["status"][] {
  const approvedPath: StagingLabModel["status"][] = [
    "draft",
    "planned",
    "awaiting_approval",
    "approved",
  ];
  if (lab.status === "simulating") return [...approvedPath, "simulation_queued"];
  if (
    lab.status === "teardown_queued" ||
    lab.status === "tearing_down" ||
    lab.status === "destroyed"
  ) {
    return hasRecordedSimulation(lab)
      ? [...approvedPath, "simulation_queued", "simulated_ready"]
      : approvedPath;
  }
  if (lab.status === "failed") {
    if (lab.approved_plan_hash) return approvedPath;
    if (lab.plan_hash) return ["draft", "planned", "awaiting_approval"];
  }
  return [];
}

function labRailItems(lab: StagingLabModel) {
  const idx = lifecycleIndex(lab.status);
  if (idx === -1 || lab.status === "destroyed") {
    return lifecycleRailItems(LIFECYCLE_STEPS, idx, {
      completedStatuses: labCompletedStatuses(lab),
      currentStatus: lab.status === "destroyed" ? lab.status : undefined,
    });
  }
  return lifecycleRailItems(LIFECYCLE_STEPS, idx);
}

function CreateForm({
  substrates,
  onCreated,
}: {
  substrates: EligibleSubstrate[];
  onCreated: (lab: StagingLabModel) => void;
}) {
  const [draft, setDraft] = useState<StagingLabDraft>(emptyDraft());
  const [apiError, setApiError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [interacted, setInteracted] = useState(false);
  const options = substrateOptions(substrates);
  const validation = validateDraft(draft);

  function set<K extends keyof StagingLabDraft>(key: K, value: StagingLabDraft[K]) {
    setInteracted(true);
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setApiError(null);
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
      setInteracted(false);
    } catch (e) {
      setApiError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <CyberCard heading="Create Disposable Staging Lab">
      <SafetyNotice role="note" tone="warn">
        {SIMULATION_ONLY_LABEL}
      </SafetyNotice>
      <div className="stag-create-grid">
        <CyberSelect
          label="Eligible substrate (server alias)"
          hint="Required."
          required
          value={draft.executionTargetId}
          onChange={(e) => set("executionTargetId", e.target.value)}
          options={[
            { value: "", label: "Select an eligible substrate…" },
            ...options.map((o) => ({ value: o.id, label: o.label })),
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
          value={draft.resourceClass}
          showHelp
          onChange={(e) =>
            set("resourceClass", e.target.value as StagingLabDraft["resourceClass"])
          }
          options={RESOURCE_CLASSES.map((o) => ({
            value: o.value,
            label: o.label,
            help: o.help,
          }))}
        />
        <CyberSelect
          label="Approved bootstrap-artifact profile"
          value={draft.bootstrapArtifactProfile}
          showHelp
          onChange={(e) =>
            set(
              "bootstrapArtifactProfile",
              e.target.value as StagingLabDraft["bootstrapArtifactProfile"],
            )
          }
          options={BOOTSTRAP_PROFILES.map((o) => ({
            value: o.value,
            label: o.label,
            help: o.help,
          }))}
        />
        <CyberSelect
          label="Rollback policy"
          value={draft.rollbackPolicy}
          showHelp
          onChange={(e) =>
            set("rollbackPolicy", e.target.value as StagingLabDraft["rollbackPolicy"])
          }
          options={ROLLBACK_POLICIES.map((o) => ({
            value: o.value,
            label: o.label,
            help: o.help,
          }))}
        />
      </div>
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
          codeText={STAGING_ERROR_TEXT}
          onDismiss={() => setApiError(null)}
        />
      )}
      <div style={{ marginTop: 10 }}>
        <CyberButton disabled={!canCreate(busy, draft)} onClick={submit}>
          Create staging lab (draft)
        </CyberButton>
      </div>
    </CyberCard>
  );
}

function LabDetail({ lab, onChanged }: { lab: StagingLabModel; onChanged: () => void }) {
  const action = useAction({ codeText: STAGING_ERROR_TEXT });
  const run = (fn: () => Promise<StagingLabModel>) =>
    action.run(async () => {
      await fn();
    }, onChanged);

  const planKinds = planResourceKinds(lab);
  const observed = observedResources(lab);
  const idx = lifecycleIndex(lab.status);
  const failed = isFailed(lab.status);

  return (
    <CyberCard>
      <div className="stag-detail-head">
        <div>
          <h3>{lab.display_name}</h3>
          <div className="stag-detail-sub mono">{lab.ownership_label}</div>
        </div>
        <StatusBadge state={lab.status} domain="staging-lab" />
      </div>
      <SafetyNotice role="note" tone="warn">
        {SIMULATION_ONLY_LABEL}
      </SafetyNotice>
      {isQueuedOrRunning(lab.status) && (
        <div className="stag-offrail">
          <SafetyNotice role="status" tone="info">
            {QUEUED_NOTICE}
          </SafetyNotice>
        </div>
      )}

      <div className="stag-rail">
        <StepRail
          items={labRailItems(lab)}
          aria-label="Staging lab lifecycle"
        />
        {isOffRail(idx) && (
          <div className="stag-offrail">
            <SafetyNotice role="status" tone={failed ? "danger" : "info"}>
              Current state: {statusLabel(lab.status)}
            </SafetyNotice>
          </div>
        )}
      </div>

      <div className="stag-grid">
        <CyberCard surface="well" heading="Immutable plan">
          <KeyValueList
            items={[
              { key: "Plan hash", value: planHashCell(lab.plan_hash) },
              { key: "Plan version", value: String(lab.plan_version) },
              { key: "Resource class", value: lab.resource_class, mono: true },
              {
                key: "Bootstrap profile",
                value: lab.bootstrap_artifact_profile,
                mono: true,
              },
              { key: "Network intent", value: lab.network_intent, mono: true },
            ]}
          />
          {planKinds.length > 0 && (
            <>
              <h4>Planned logical resources</h4>
              <ul className="stag-kinds">
                {planKinds.map((k) => (
                  <li key={k} className="mono">
                    {k}
                  </li>
                ))}
              </ul>
            </>
          )}
          <p className="stag-note">{PLAN_PIN_NOTICE}</p>
          <p className="stag-note">{LAB_APPROVAL_SCOPE_NOTICE}</p>
        </CyberCard>

        <CyberCard surface="well" heading="Safety constraints — fixed by the server contract">
          <ul className="stag-constraints">
            {SAFETY_CONSTRAINTS.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </CyberCard>

        <CyberCard surface="well" heading="Worker observations">
          {observed.length > 0 ? (
            <>
              <h4>Simulated observations (fake — worker-recorded)</h4>
              <ul className="stag-obs">
                {observed.map((r) => (
                  <li key={r.kind} className="mono">
                    {r.kind} · owner={r.owner} · {r.phase}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <EmptyState title={OBSERVATIONS_EMPTY_TITLE}>
              {isQueuedOrRunning(lab.status)
                ? OBSERVATIONS_QUEUED_BODY
                : OBSERVATIONS_IDLE_BODY}
            </EmptyState>
          )}
        </CyberCard>

        <CyberCard surface="well" heading="Rollback posture">
          <KeyValueList
            items={[
              { key: "Policy", value: rollbackPosture(lab), mono: true },
              { key: "Teardown", value: teardownState(lab.status) },
              { key: "Decision code", value: lab.decision_code || "-", mono: true },
            ]}
          />
        </CyberCard>
      </div>

      {action.error && (
        <div className="error-box" role="alert" style={{ marginTop: 10 }}>
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}

      <div className="stag-actions">
        <CyberButton
          variant="secondary"
          size="sm"
          disabled={action.busy || !canPlan(lab)}
          title={canPlan(lab) ? undefined : `Available in draft — current: ${statusLabel(lab.status)}`}
          onClick={() => run(() => api.planStagingLab(lab.id))}
        >
          Generate plan
        </CyberButton>
        <CyberButton
          variant="secondary"
          size="sm"
          disabled={action.busy || !canSubmit(lab)}
          title={canSubmit(lab) ? undefined : `Available once a plan exists — current: ${statusLabel(lab.status)}`}
          onClick={() => run(() => api.submitStagingLab(lab.id))}
        >
          Submit for approval
        </CyberButton>
        <CyberButton
          variant="ok"
          size="sm"
          disabled={action.busy || !canApprove(lab)}
          title={canApprove(lab) ? undefined : `Available while awaiting approval — current: ${statusLabel(lab.status)}`}
          onClick={() => run(() => api.approveStagingLab(lab.id, lab.plan_hash))}
        >
          Approve (sim only)
        </CyberButton>
        <CyberButton
          variant="secondary"
          size="sm"
          disabled={action.busy || !canQueueSimulation(lab)}
          title={SIMULATION_ONLY_LABEL}
          onClick={() => run(() => api.queueStagingLabSimulation(lab.id))}
        >
          Simulate Provisioning (queue)
        </CyberButton>
        <CyberButton
          variant="secondary"
          size="sm"
          disabled={action.busy || !canQueueTeardown(lab)}
          title={SIMULATION_ONLY_LABEL}
          onClick={() => run(() => api.queueStagingLabTeardown(lab.id))}
        >
          Simulate Teardown (queue)
        </CyberButton>
      </div>
    </CyberCard>
  );
}

export function StagingLab() {
  const substrates = useAsync(() => api.listEligibleSubstrates(), []);
  const labs = useAsync(() => api.listStagingLabs(), []);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const labList = labs.data ?? null;
  const selected = labList?.find((l) => l.id === selectedId) ?? null;

  return (
    <div className="stag">
      <CyberGridBackground intensity="subtle" className="stag-bg" />
      <div className="stag-head">
        <h1>Disposable Staging Labs</h1>
        <p className="stag-intro">
          Define a disposable read-only staging lab, generate an immutable plan, approve
          it, and QUEUE a labeled fake simulation for a worker to process.{" "}
          {SIMULATION_ONLY_LABEL}
        </p>
      </div>

      <CreateForm
        substrates={substrates.data ?? []}
        onCreated={(lab) => {
          labs.reload();
          setSelectedId(lab.id);
        }}
      />

      {labs.loading && !labs.data && <Skeleton lines={4} />}
      {labs.error && (
        <div className="error-box">Staging labs could not be loaded.</div>
      )}
      {labList && labList.length === 0 && (
        <EmptyState title="No staging labs yet">
          Create a draft above to begin — nothing contacts infrastructure.
        </EmptyState>
      )}
      {labList && labList.length > 0 && (
        <CyberTable
          head={["Lab", "Substrate", "Lifecycle", "Plan", "Rollback", "Status"]}
          label="Staging labs"
          caption={`${labList.length} lab${labList.length === 1 ? "" : "s"} · ${SIMULATION_ONLY_LABEL}`}
        >
          {labList.map((lab) => (
            <tr
              key={lab.id}
              className={selectedId === lab.id ? "stag-row--selected" : undefined}
            >
              <td>
                <button
                  type="button"
                  className="stag-item-btn"
                  onClick={() =>
                    setSelectedId((cur) => (cur === lab.id ? null : lab.id))
                  }
                  aria-expanded={selectedId === lab.id}
                  aria-controls="stag-lab-detail"
                >
                  <span>
                    <span className="stag-item-name">{lab.display_name}</span>
                    <span className="stag-item-sub mono">{lab.ownership_label}</span>
                  </span>
                </button>
              </td>
              <td className="mono">{shortId(lab.execution_target_id)}</td>
              <td className="muted">{statusLabel(lab.status)}</td>
              <td>
                {planHashCell(lab.plan_hash)}{" "}
                <span className="muted">v{lab.plan_version}</span>
              </td>
              <td className="mono">{lab.rollback_policy}</td>
              <td>
                <StatusBadge state={lab.status} domain="staging-lab" />
              </td>
            </tr>
          ))}
        </CyberTable>
      )}

      <div id="stag-lab-detail">
        {selected && (
          <LabDetail key={selected.id} lab={selected} onChanged={() => labs.reload()} />
        )}
      </div>
    </div>
  );
}
