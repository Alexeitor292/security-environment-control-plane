import "./staging.css";

import { useState } from "react";

import { api } from "../api/client";
import type {
  BootstrapAvailability,
  EligibleSubstrate,
  StagingDeployment as DeploymentModel,
  StagingDeploymentPlan,
  StagingDeploymentVerificationRecord,
} from "../api/types";
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
import { useAsync } from "../hooks";
import {
  CONTROL_PLANE_ONLY_LABEL,
  DEPLOY_ENQUEUED_NOTICE,
  LIFECYCLE_STEPS,
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
  isFailureState,
  isInFlight,
  lifecycleIndex,
  planHashPrefix,
  planResourceKinds,
  statusLabel,
  validateDraft,
} from "./staging-deployment";
import {
  DEPLOYMENT_APPROVAL_SCOPE_NOTICE,
  PLAN_PIN_NOTICE,
  STAGING_ERROR_TEXT,
  isOffRail,
  lifecycleRailItems,
} from "./staging-view";

const opt = <T,>(p: Promise<T>): Promise<T | null> => p.catch(() => null);

interface DeploymentExtras {
  plan: StagingDeploymentPlan | null;
  bootstrap: BootstrapAvailability | null;
  verifications: StagingDeploymentVerificationRecord[] | null;
}

function deploymentCompletedStatuses(
  dep: DeploymentModel,
): DeploymentModel["status"][] {
  const approvalPath: DeploymentModel["status"][] = [
    "draft",
    "planned",
    "awaiting_approval",
    "approved",
  ];
  const applyStarted: DeploymentModel["status"][] = [
    ...approvalPath,
    "bootstrap_pending",
    "applying",
  ];
  if (dep.status === "failed") {
    if (dep.approved_plan_hash) return applyStarted;
    if (dep.plan_hash) return ["draft", "planned", "awaiting_approval"];
  }
  if (
    dep.status === "rollback_required" ||
    dep.status === "rolling_back" ||
    dep.status === "rolled_back"
  ) {
    return applyStarted;
  }
  if (
    dep.status === "teardown_requested" ||
    dep.status === "tearing_down" ||
    dep.status === "destroyed"
  ) {
    if (!dep.approved_plan_hash) return dep.plan_hash ? ["draft", "planned"] : [];
    return dep.failure_code
      ? applyStarted
      : [...applyStarted, "verifying", "ready"];
  }
  return [];
}

function deploymentRailItems(dep: DeploymentModel) {
  const idx = lifecycleIndex(dep.status);
  if (idx === -1) {
    return lifecycleRailItems(LIFECYCLE_STEPS, idx, {
      completedStatuses: deploymentCompletedStatuses(dep),
    });
  }
  return lifecycleRailItems(LIFECYCLE_STEPS, idx);
}

function CreateForm({
  substrates,
  onCreated,
}: {
  substrates: EligibleSubstrate[];
  onCreated: (dep: DeploymentModel) => void;
}) {
  const [draft, setDraft] = useState<DeploymentDraft>(emptyDraft());
  const [apiError, setApiError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [interacted, setInteracted] = useState(false);
  const validation = validateDraft(draft);

  function set<K extends keyof DeploymentDraft>(key: K, value: DeploymentDraft[K]) {
    setInteracted(true);
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setApiError(null);
    try {
      const dep = await api.createStagingDeployment({
        execution_target_id: draft.executionTargetId,
        resource_profile: draft.resourceProfile,
        logical_name: draft.logicalName.trim() || null,
      });
      onCreated(dep);
      setDraft(emptyDraft());
      setInteracted(false);
    } catch (e) {
      setApiError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <CyberCard heading="Deploy Isolated Staging Lab">
      <SafetyNotice role="note" tone="warn">
        {CONTROL_PLANE_ONLY_LABEL}
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
            set("resourceProfile", e.target.value as DeploymentDraft["resourceProfile"])
          }
          options={RESOURCE_PROFILES.map((o) => ({
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
          Create deployment (draft)
        </CyberButton>
      </div>
    </CyberCard>
  );
}

function DeploymentDetail({
  dep,
  onChanged,
}: {
  dep: DeploymentModel;
  onChanged: () => void;
}) {
  const action = useAction({ codeText: STAGING_ERROR_TEXT });
  const extras = useAsync<DeploymentExtras>(async () => {
    const [plan, bootstrap, verifications] = await Promise.all([
      dep.plan_hash
        ? opt(api.getStagingDeploymentPlan(dep.id))
        : Promise.resolve(null),
      opt(api.getStagingDeploymentBootstrapAvailability(dep.id)),
      opt(api.listStagingDeploymentVerifications(dep.id)),
    ]);
    return { plan, bootstrap, verifications };
  }, [dep.id, dep.plan_hash, dep.status]);

  const run = (fn: () => Promise<DeploymentModel>) =>
    action.run(async () => {
      await fn();
    }, onChanged);

  const plan = extras.data?.plan ?? null;
  const planKinds = planResourceKinds(plan);
  const verifications = extras.data?.verifications ?? null;
  const idx = lifecycleIndex(dep.status);
  const failureish = isFailureState(dep.status);

  return (
    <CyberCard>
      <div className="stag-detail-head">
        <div>
          <h3>{dep.display_name}</h3>
          <div className="stag-detail-sub mono">{dep.ownership_label}</div>
        </div>
        <StatusBadge state={dep.status} domain="staging-deployment" />
      </div>
      <SafetyNotice role="note" tone="warn">
        {CONTROL_PLANE_ONLY_LABEL}
      </SafetyNotice>
      {(isInFlight(dep.status) || dep.status === "teardown_requested") && (
        <div className="stag-offrail">
          <SafetyNotice role="status" tone="info">
            {dep.status === "teardown_requested"
              ? "Teardown requested - a worker will process it."
              : DEPLOY_ENQUEUED_NOTICE}
          </SafetyNotice>
        </div>
      )}

      <div className="stag-rail">
        <StepRail
          items={deploymentRailItems(dep)}
          aria-label="Deployment lifecycle"
        />
        {isOffRail(idx) && (
          <div className="stag-offrail">
            <SafetyNotice role="status" tone={failureish ? "danger" : "info"}>
              Current state: {statusLabel(dep.status)}
            </SafetyNotice>
          </div>
        )}
      </div>

      <div className="stag-grid">
        <CyberCard surface="well" heading="Immutable plan">
          {extras.loading && !extras.data ? (
            <Skeleton lines={3} />
          ) : (
            <>
              <KeyValueList
                items={[
                  {
                    key: "Plan hash",
                    value: dep.plan_hash ? (
                      <HashChip value={dep.plan_hash} digits={12} />
                    ) : (
                      <span className="muted">{planHashPrefix(dep.plan_hash)}</span>
                    ),
                  },
                  { key: "Plan version", value: String(dep.plan_version) },
                  { key: "Revision", value: String(dep.revision) },
                  { key: "Resource profile", value: dep.resource_profile, mono: true },
                  ...(plan
                    ? [
                        {
                          key: "Ownership tag",
                          value: plan.ownership_tag,
                          mono: true,
                        },
                      ]
                    : []),
                  {
                    key: "Bootstrap authority",
                    value: bootstrapAvailabilityLabel(extras.data?.bootstrap ?? null),
                  },
                ]}
              />
              {planKinds.length > 0 && (
                <>
                  <h4>
                    Planned resources (the app will create all of these once execution
                    is enabled)
                  </h4>
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
              <p className="stag-note">{DEPLOYMENT_APPROVAL_SCOPE_NOTICE}</p>
            </>
          )}
        </CyberCard>

        <CyberCard surface="well" heading="Safety constraints — fixed by the server contract">
          <ul className="stag-constraints">
            {SAFETY_CONSTRAINTS.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </CyberCard>

        <CyberCard surface="well" heading="Worker verification records">
          {extras.loading && !extras.data ? (
            <Skeleton lines={2} />
          ) : verifications === null ? (
            <p className="muted">Verification records unavailable.</p>
          ) : verifications.length > 0 ? (
            <ul className="stag-obs">
              {verifications.map((v) => (
                <li key={v.check_code} className="mono">
                  {v.check_code} <StatusBadge state={v.status} domain="verification" />
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="Nothing recorded yet">
              Verification records appear only after the worker durably records them.
            </EmptyState>
          )}
        </CyberCard>

        <CyberCard surface="well" heading="Failure / rollback posture">
          <KeyValueList
            items={[
              {
                key: "Failure code",
                value: dep.failure_code ? (
                  <span className="mono">{dep.failure_code}</span>
                ) : (
                  "none recorded"
                ),
              },
              {
                key: "Rollback",
                value: failureish
                  ? statusLabel(dep.status)
                  : "Not required - no failure recorded.",
              },
              { key: "Decision code", value: dep.decision_code || "-", mono: true },
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
          disabled={action.busy || !canPlan(dep)}
          title={canPlan(dep) ? undefined : `Available in draft/planned — current: ${statusLabel(dep.status)}`}
          onClick={() => run(() => api.planStagingDeployment(dep.id))}
        >
          Generate plan
        </CyberButton>
        <CyberButton
          variant="secondary"
          size="sm"
          disabled={action.busy || !canSubmit(dep)}
          title={canSubmit(dep) ? undefined : `Available once a plan exists — current: ${statusLabel(dep.status)}`}
          onClick={() => run(() => api.submitStagingDeployment(dep.id))}
        >
          Submit for approval
        </CyberButton>
        <CyberButton
          variant="ok"
          size="sm"
          disabled={action.busy || !canApprove(dep)}
          title={canApprove(dep) ? undefined : `Available while awaiting approval — current: ${statusLabel(dep.status)}`}
          onClick={() => run(() => api.approveStagingDeployment(dep.id, dep.plan_hash))}
        >
          Approve exact plan
        </CyberButton>
        <CyberButton
          variant="secondary"
          size="sm"
          disabled={action.busy || !canDeploy(dep)}
          title={CONTROL_PLANE_ONLY_LABEL}
          onClick={() => run(() => api.deployStagingDeployment(dep.id))}
        >
          Deploy (enqueue apply)
        </CyberButton>
        <CyberButton
          variant="danger"
          size="sm"
          disabled={action.busy || !canTeardown(dep)}
          title={canTeardown(dep) ? undefined : `Available when ready, failed, or rolled back — current: ${statusLabel(dep.status)}`}
          onClick={() => run(() => api.teardownStagingDeployment(dep.id))}
        >
          Request teardown
        </CyberButton>
      </div>
    </CyberCard>
  );
}

export function StagingDeployment() {
  const substrates = useAsync(() => api.listEligibleSubstrates(), []);
  const deployments = useAsync(() => api.listStagingDeployments(), []);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const depList = deployments.data ?? null;
  const selected = depList?.find((d) => d.id === selectedId) ?? null;

  return (
    <div className="stag">
      <div className="stag-head">
        <h1>Isolated Staging Lab Deployments</h1>
        <p className="stag-intro">
          Create a deployment, compile an immutable content-addressed plan, approve the
          exact plan, and enqueue a durable worker job. Execution is a sealed,
          fail-closed worker contract — real host action is not yet enabled and requires
          the integration-validated seams on the isolated worker.{" "}
          {CONTROL_PLANE_ONLY_LABEL}
        </p>
      </div>

      <CreateForm
        substrates={substrates.data ?? []}
        onCreated={(dep) => {
          deployments.reload();
          setSelectedId(dep.id);
        }}
      />

      {deployments.loading && !deployments.data && <Skeleton lines={4} />}
      {deployments.error && (
        <div className="error-box">Deployments could not be loaded.</div>
      )}
      {depList && depList.length === 0 && (
        <EmptyState title="No staging deployments yet">
          Create a draft above to begin — the app contacts no infrastructure.
        </EmptyState>
      )}
      {depList && depList.length > 0 && (
        <CyberTable
          head={["Deployment", "Substrate", "Lifecycle", "Plan", "Failure", "Status"]}
          label="Staging deployments"
          caption={`${depList.length} deployment${depList.length === 1 ? "" : "s"} · ${CONTROL_PLANE_ONLY_LABEL}`}
        >
          {depList.map((dep) => (
            <tr
              key={dep.id}
              className={selectedId === dep.id ? "stag-row--selected" : undefined}
            >
              <td>
                <button
                  type="button"
                  className="stag-item-btn"
                  onClick={() =>
                    setSelectedId((cur) => (cur === dep.id ? null : dep.id))
                  }
                  aria-expanded={selectedId === dep.id}
                  aria-controls="stag-dep-detail"
                >
                  <span>
                    <span className="stag-item-name">{dep.display_name}</span>
                    <span className="stag-item-sub mono">{dep.ownership_label}</span>
                  </span>
                </button>
              </td>
              <td className="mono">{shortId(dep.execution_target_id)}</td>
              <td className="muted">{statusLabel(dep.status)}</td>
              <td>
                {dep.plan_hash ? (
                  <HashChip value={dep.plan_hash} digits={12} />
                ) : (
                  <span className="muted">pending</span>
                )}{" "}
                <span className="muted">v{dep.plan_version}</span>
              </td>
              <td className="mono">{dep.failure_code ?? "-"}</td>
              <td>
                <StatusBadge state={dep.status} domain="staging-deployment" />
              </td>
            </tr>
          ))}
        </CyberTable>
      )}

      <div id="stag-dep-detail">
        {selected && (
          <DeploymentDetail
            key={selected.id}
            dep={selected}
            onChanged={() => deployments.reload()}
          />
        )}
      </div>
    </div>
  );
}
