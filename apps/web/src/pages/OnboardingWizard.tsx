import "./wizard.css";

import { useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  IsolationModelName,
  Onboarding,
  OnboardingMode,
  TargetEvidence,
} from "../api/types";
import {
  ApprovedValuePicker,
  CyberButton,
  CyberCard,
  CyberInput,
  EvidenceBadge,
  KeyValueList,
  OptionCardGroup,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  StepRail,
  truncateHash,
  useAction,
  type ActionState,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  ISOLATION_MODELS,
  ISOLATION_PROFILES,
  CIDR_HELPER_TEXT,
  LIFECYCLE_STEPS,
  NETWORK_APPROACHES,
  NETWORK_SEGMENT_HELPER_TEXT,
  NO_APPROVED_SEGMENTS_MESSAGE,
  ONBOARDING_MODES,
  REVIEW_STATEMENT,
  SIMULATED_EVIDENCE_NOTICE,
  buildBoundary,
  canCreateOnboardingDraft,
  draftFromScope,
  evidenceHashPrefix,
  emptyDraft,
  isTerminalRejected,
  lifecycleIndex,
  parseList,
  scopeOptionsFromPolicy,
  targetHasApprovedSegments,
  toggleDraftListValue,
  valuesOutsideApproved,
  type BoundaryDraft,
  type TargetScopeOptions,
} from "./onboarding-wizard";
import {
  BOUNDARY_LOCKED_NOTICE,
  DRAFT_NOT_SAVED_NOTICE,
  LIFECYCLE_ACTIONS,
  ONBOARDING_ERROR_TEXT,
  STEP_TITLES,
  SUMMARY_TRUTH_NOTICE,
  TARGETS_UNAVAILABLE_TEXT,
  boundarySummaryDeclaredRows,
  boundarySummaryDraftRows,
  lifecycleActionEnabled,
  wizardStepStates,
} from "./onboarding-wizard-view";

export function OnboardingWizard() {
  const targets = useAsync(() => api.listTargets(), []);
  const [step, setStep] = useState(0);
  const [targetId, setTargetId] = useState<string>("");
  const [mode, setMode] = useState<OnboardingMode>("existing_environment");
  const [isolationModel, setIsolationModel] = useState<IsolationModelName>("physical");
  const [draft, setDraft] = useState<BoundaryDraft>(emptyDraft());
  const [onboarding, setOnboarding] = useState<Onboarding | null>(null);
  const action = useAction({ codeText: ONBOARDING_ERROR_TEXT });

  const target = targets.data?.find((t) => t.id === targetId);
  const targetOptions = useMemo(
    () => scopeOptionsFromPolicy(target?.scope_policy),
    [target?.scope_policy],
  );
  const hasApprovedSegments = targetHasApprovedSegments(targetOptions);
  const validation = useMemo(
    () => buildBoundary(draft, targetOptions),
    [draft, targetOptions],
  );

  function selectTarget(id: string) {
    setTargetId(id);
    const t = targets.data?.find((x) => x.id === id);
    setDraft(draftFromScope(t?.scope_policy));
    setOnboarding(null);
  }

  function set<K extends keyof BoundaryDraft>(key: K, value: BoundaryDraft[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  const act = (fn: () => Promise<Onboarding>) =>
    action.run(async () => {
      setOnboarding(await fn());
    });

  const gateArgs = {
    targetSelected: !!targetId,
    targetHasSegments: hasApprovedSegments,
    validationOk: validation.ok,
    onboardingExists: !!onboarding,
  };
  const railItems = wizardStepStates(step, gateArgs);
  const canNext =
    step < STEP_TITLES.length - 1 && railItems[step + 1].state !== "blocked";

  // Navigating steps clears a stale action error so the alert never asserts a
  // failure the current screen no longer reflects.
  function goStep(next: number) {
    action.clearError();
    setStep(Math.min(STEP_TITLES.length - 1, Math.max(0, next)));
  }
  const canCreateDraft = canCreateOnboardingDraft(
    action.busy,
    !!targetId,
    hasApprovedSegments,
    validation.ok,
  );

  return (
    <div className="wiz">
      <div>
        <h2>Target onboarding wizard</h2>
        <SafetyNotice role="note" tone="warn">
          <strong>Simulated onboarding (SECP-002B-1B-0.1).</strong> This constrains an
          approved boundary; SECP later creates scenario resources inside it. Preflight is{" "}
          <strong>simulated</strong> and the live-evidence seal remains in force — no real
          server, network, bridge, or provider is contacted.
        </SafetyNotice>
      </div>

      {action.error && (
        <div className="error-box" role="alert">
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}

      <div className="wiz-grid">
        <aside className="wiz-rail">
          <CyberCard>
            <StepRail
              items={railItems}
              onSelect={(id) => goStep(Number(id))}
              aria-label="Onboarding steps"
            />
          </CyberCard>
        </aside>

        <section>
          <CyberCard heading={`${step + 1}. ${STEP_TITLES[step]}`}>
            {step === 0 && (
              <div>
                <p className="muted">
                  Selecting an <strong>existing environment</strong> means selecting an
                  existing hypervisor/cluster <strong>boundary</strong> — it does{" "}
                  <strong>not</strong> adopt existing VMs or containers.
                </p>
                {targets.loading && !targets.data && <Skeleton lines={3} />}
                {targets.error && (
                  <div className="error-box">{TARGETS_UNAVAILABLE_TEXT}</div>
                )}
                {targets.data && targets.data.length === 0 && (
                  <p className="muted">
                    No registered targets. Register one under “Provider Targets” first.
                  </p>
                )}
                {targets.data && targets.data.length > 0 && (
                  <OptionCardGroup
                    name="onboarding_target"
                    legend="Registered execution target"
                    options={targets.data.map((t) => ({
                      value: t.id,
                      label: t.display_name,
                      help: `${t.plugin_name} plugin · ${truncateHash(t.config_hash, { prefix: "strip", digits: 12, ellipsis: false })}`,
                      meta: <StatusBadge state={t.status} domain="target" />,
                    }))}
                    value={targetId}
                    onChange={selectTarget}
                  />
                )}
                {targetId && !hasApprovedSegments && (
                  <div className="error-box" style={{ marginTop: 10 }}>
                    {NO_APPROVED_SEGMENTS_MESSAGE}
                  </div>
                )}
              </div>
            )}

            {step === 1 && (
              <OptionCardGroup
                name="onboarding_mode"
                legend="Onboarding mode"
                legendHidden
                options={ONBOARDING_MODES}
                value={mode}
                onChange={(v) => setMode(v)}
              />
            )}

            {step === 2 && (
              <div>
                <OptionCardGroup
                  name="isolation_model"
                  legend="Isolation model"
                  legendHidden
                  options={ISOLATION_MODELS}
                  value={isolationModel}
                  onChange={(v) => setIsolationModel(v)}
                />
                {isolationModel === "logical" && (
                  <div className="error-box" style={{ marginTop: 10 }}>
                    Logical isolation requires a complete, verified boundary with{" "}
                    <strong>no route</strong> to management, home, corporate, storage, or
                    public networks. The <span className="mono">no_route_to_protected</span>{" "}
                    preflight check must pass.
                  </div>
                )}
              </div>
            )}

            {step === 3 && (
              <div>
                <OptionCardGroup
                  name="network_approach"
                  legend="Lab network approach"
                  legendHidden
                  options={NETWORK_APPROACHES}
                  value={draft.networkApproach}
                  onChange={(v) => set("networkApproach", v)}
                />
                {draft.networkApproach === "secp_managed_dedicated_segment" && (
                  <div className="error-box" style={{ marginTop: 10 }}>
                    Activation pending — <strong>no network is created in this release</strong>.
                    The declared segment must still be within the target’s approved segments.
                  </div>
                )}
                {targetOptions.networkSegments.length > 0 && (
                  <p className="muted mono" style={{ marginTop: 8 }}>
                    approved segments: {targetOptions.networkSegments.join(", ")}
                  </p>
                )}
                {targetId && !hasApprovedSegments && (
                  <div className="error-box" style={{ marginTop: 10 }}>
                    {NO_APPROVED_SEGMENTS_MESSAGE}
                  </div>
                )}
              </div>
            )}

            {step === 4 && (
              <OptionCardGroup
                name="isolation_profile"
                legend="Isolation profile"
                legendHidden
                options={ISOLATION_PROFILES.map((p) => ({
                  value: p.value,
                  label: p.label,
                  help: p.description,
                  disabled: !p.available,
                  disabledReason: "planned, not available yet",
                  meta: p.recommended ? (
                    <span className="badge ok">recommended</span>
                  ) : !p.available ? (
                    <span className="badge pending">planned, not available yet</span>
                  ) : undefined,
                }))}
                value={draft.isolationProfile}
                onChange={(v) => set("isolationProfile", v)}
              />
            )}

            {step === 5 && (
              <BoundaryStep
                draft={draft}
                targetOptions={targetOptions}
                validation={validation}
                onboarding={onboarding}
                mode={mode}
                isolationModel={isolationModel}
                canCreateDraft={canCreateDraft}
                onSet={set}
                onCreate={() =>
                  act(() =>
                    api.createOnboarding(targetId, {
                      onboarding_mode: mode,
                      isolation_model: isolationModel,
                      declared_boundary: validation.boundary!,
                    }),
                  )
                }
              />
            )}

            {step === 6 && (
              <LifecycleStep onboarding={onboarding} action={action} act={act} />
            )}

            <div className="wiz-step-actions">
              <CyberButton
                variant="secondary"
                disabled={step === 0}
                onClick={() => goStep(step - 1)}
              >
                Back
              </CyberButton>
              <CyberButton disabled={!canNext} onClick={() => goStep(step + 1)}>
                Next
              </CyberButton>
            </div>
          </CyberCard>
        </section>

        <aside className="wiz-summary">
          <CyberCard heading="Boundary summary">
            <div className="wiz-summary-status">
              {onboarding ? (
                <>
                  <StatusBadge state={onboarding.status} domain="onboarding" />
                  <span className="mono">
                    onboarding {onboarding.id.slice(0, 8)} · boundary{" "}
                    {truncateHash(onboarding.boundary_hash, { prefix: "strip", digits: 12 })}
                  </span>
                </>
              ) : (
                <span>{DRAFT_NOT_SAVED_NOTICE}</span>
              )}
            </div>
            <KeyValueList
              items={
                onboarding
                  ? boundarySummaryDeclaredRows(onboarding)
                  : boundarySummaryDraftRows(mode, isolationModel, draft)
              }
            />
            <p className="wiz-summary-note">{SUMMARY_TRUTH_NOTICE}</p>
          </CyberCard>
        </aside>
      </div>
    </div>
  );
}

function BoundaryStep({
  draft,
  targetOptions,
  validation,
  onboarding,
  mode,
  isolationModel,
  canCreateDraft,
  onSet,
  onCreate,
}: {
  draft: BoundaryDraft;
  targetOptions: TargetScopeOptions;
  validation: ReturnType<typeof buildBoundary>;
  onboarding: Onboarding | null;
  mode: OnboardingMode;
  isolationModel: IsolationModelName;
  canCreateDraft: boolean;
  onSet: <K extends keyof BoundaryDraft>(key: K, value: BoundaryDraft[K]) => void;
  onCreate: () => void;
}) {
  const picker = (
    key: "nodes" | "storage" | "networkSegments" | "cidrs",
    label: string,
    approved: string[],
    helper?: string,
    emptyText?: string,
  ) => {
    const selectedValues = parseList(draft[key]);
    return (
      <ApprovedValuePicker
        label={label}
        approvedValues={approved}
        selectedValues={selectedValues}
        outOfBound={valuesOutsideApproved(selectedValues, approved)}
        helper={helper}
        emptyText={emptyText}
        onToggle={(value, checked) =>
          onSet(key, toggleDraftListValue(draft[key], value, checked))
        }
      />
    );
  };

  return (
    <div>
      {onboarding && <p className="wiz-locked-note">{BOUNDARY_LOCKED_NOTICE}</p>}
      <fieldset className="wiz-fieldset" disabled={!!onboarding}>
      <div className="grid cols-2">
        <div>
          {picker("nodes", "Allowed nodes", targetOptions.nodes)}
          {picker("storage", "Allowed storage", targetOptions.storage)}
          {picker(
            "networkSegments",
            "Network segments / bridges",
            targetOptions.networkSegments,
            NETWORK_SEGMENT_HELPER_TEXT,
            NO_APPROVED_SEGMENTS_MESSAGE,
          )}
          {picker("cidrs", "CIDR reservations", targetOptions.cidrs, CIDR_HELPER_TEXT)}
          <CyberInput
            label="Credential-scope label (opaque, non-secret)"
            value={draft.credentialScope}
            onChange={(e) => onSet("credentialScope", e.target.value)}
          />
        </div>
        <div>
          <div className="grid cols-2">
            <CyberInput
              label="VM-ID start"
              type="number"
              min={targetOptions.vmidRange?.start}
              max={targetOptions.vmidRange?.end}
              value={draft.vmidStart}
              onChange={(e) => onSet("vmidStart", e.target.value)}
            />
            <CyberInput
              label="VM-ID end"
              type="number"
              min={targetOptions.vmidRange?.start}
              max={targetOptions.vmidRange?.end}
              value={draft.vmidEnd}
              onChange={(e) => onSet("vmidEnd", e.target.value)}
            />
          </div>
          {targetOptions.vmidRange && (
            <p className="muted mono" style={{ marginTop: 4 }}>
              approved VM-ID range: {targetOptions.vmidRange.start}-
              {targetOptions.vmidRange.end}
            </p>
          )}
          <div className="grid cols-2">
            <CyberInput
              label="Max teams"
              type="number"
              min={1}
              max={targetOptions.quotas.maxTeams}
              value={draft.maxTeams}
              onChange={(e) => onSet("maxTeams", e.target.value)}
            />
            <CyberInput
              label="Max VMs"
              type="number"
              min={1}
              max={targetOptions.quotas.maxVms}
              value={draft.maxVms}
              onChange={(e) => onSet("maxVms", e.target.value)}
            />
          </div>
          <CyberInput
            label="Max containers"
            type="number"
            min={0}
            max={targetOptions.quotas.maxContainers}
            value={draft.maxContainers}
            onChange={(e) => onSet("maxContainers", e.target.value)}
          />
          <div className="grid cols-2">
            <CyberInput
              label="Max vCPU"
              type="number"
              min={1}
              max={targetOptions.quotas.maxVcpu}
              value={draft.maxVcpu}
              onChange={(e) => onSet("maxVcpu", e.target.value)}
            />
            <CyberInput
              label="Max memory (MB)"
              type="number"
              min={1}
              max={targetOptions.quotas.maxMemoryMb}
              value={draft.maxMemoryMb}
              onChange={(e) => onSet("maxMemoryMb", e.target.value)}
            />
          </div>
          <CyberInput
            label="Max disk (GB)"
            type="number"
            min={1}
            max={targetOptions.quotas.maxDiskGb}
            value={draft.maxDiskGb}
            onChange={(e) => onSet("maxDiskGb", e.target.value)}
          />
          <p className="muted mono" style={{ marginTop: 8 }}>
            approved limits: teams={targetOptions.quotas.maxTeams ?? "unset"}, vms=
            {targetOptions.quotas.maxVms ?? "unset"}, containers=
            {targetOptions.quotas.maxContainers ?? "unset"}, vcpu=
            {targetOptions.quotas.maxVcpu ?? "unset"}, memory_mb=
            {targetOptions.quotas.maxMemoryMb ?? "unset"}, disk_gb=
            {targetOptions.quotas.maxDiskGb ?? "unset"}
          </p>
          <p className="muted mono" style={{ marginTop: 8 }}>
            external connectivity: deny (fixed)
          </p>
        </div>
      </div>
      </fieldset>

      {!validation.ok && (
        <div className="error-box" style={{ marginTop: 10 }}>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {validation.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      <CyberCard surface="well" heading="Review" className="wiz-review">
        <p>{REVIEW_STATEMENT}</p>
        <p className="muted mono wiz-mono-line">
          mode={mode} · isolation={isolationModel} · network={draft.networkApproach} ·
          profile={draft.isolationProfile}
        </p>
        {!onboarding ? (
          <CyberButton variant="ok" disabled={!canCreateDraft} onClick={onCreate}>
            Create onboarding draft
          </CyberButton>
        ) : (
          <p className="muted">
            Onboarding draft created (
            <span className="mono">{onboarding.id.slice(0, 8)}</span>). Continue to the
            lifecycle step.
          </p>
        )}
      </CyberCard>
    </div>
  );
}

function EvidencePanel({
  onboardingId,
  status,
}: {
  onboardingId: string;
  /** Refetches when the lifecycle moves (preflight records new evidence). */
  status: string;
}) {
  const evidence = useAsync(
    () => api.listTargetEvidence(onboardingId),
    [onboardingId, status],
  );
  const latest: TargetEvidence | undefined = evidence.data?.[evidence.data.length - 1];
  return (
    <CyberCard surface="well" heading="Observed target evidence" className="wiz-evidence">
      <p className="muted">
        <strong>simulated evidence</strong> - {SIMULATED_EVIDENCE_NOTICE}.
      </p>
      {evidence.error && <div className="error-box">{evidence.error}</div>}
      {!latest && !evidence.error && (
        <p className="muted">Run simulated preflight to collect comparison evidence.</p>
      )}
      {latest && (
        <div>
          <p className="muted mono">
            source={latest.evidence_source} | verification={latest.verification_level} |
            hash={evidenceHashPrefix(latest.evidence_hash)} | status={latest.status}
          </p>
          <div className="wiz-evidence-list">
            {latest.findings.map((finding) => (
              <EvidenceBadge
                key={finding.check}
                title={finding.check}
                status={finding.status}
                detail={finding.detail}
              />
            ))}
          </div>
        </div>
      )}
    </CyberCard>
  );
}

function LifecycleStep({
  onboarding,
  action,
  act,
}: {
  onboarding: Onboarding | null;
  action: ActionState;
  act: (fn: () => Promise<Onboarding>) => Promise<void>;
}) {
  if (!onboarding) {
    return <p className="muted">Create the onboarding draft (previous step) first.</p>;
  }
  const idx = lifecycleIndex(onboarding.status);
  const rejected = isTerminalRejected(onboarding.status);

  const runners: Record<string, () => Promise<Onboarding>> = {
    preflight: () =>
      api.requestPreflight(onboarding.id).then(() => api.getOnboarding(onboarding.id)),
    submit: () => api.submitOnboarding(onboarding.id),
    approve: () => api.approveOnboarding(onboarding.id, "approved via wizard"),
    activate: () => api.activateOnboarding(onboarding.id),
  };

  return (
    <div>
      <div className="wiz-lifecycle-head">
        <p className="muted mono">
          onboarding {onboarding.id.slice(0, 8)} · boundary{" "}
          {truncateHash(onboarding.boundary_hash, { prefix: "strip", digits: 12 })}
        </p>
        <StatusBadge state={onboarding.status} domain="onboarding" />
      </div>

      <ol className="wizard-steps">
        {LIFECYCLE_STEPS.map((s, i) => (
          <li key={s.status} className={idx === i ? "current" : idx > i ? "done" : ""}>
            {s.label}
          </li>
        ))}
      </ol>

      <p className="muted">
        Simulated workflow — the preflight is fake and labelled{" "}
        <span className="mono">simulated</span>; the B1-B-0 live-evidence seal is in force
        and no real infrastructure is contacted. Human approval is required before{" "}
        <span className="mono">active</span>.
      </p>
      <EvidencePanel onboardingId={onboarding.id} status={onboarding.status} />

      <div className="wiz-actions-list">
        {LIFECYCLE_ACTIONS.map((a) => {
          const enabled = lifecycleActionEnabled(a.id, onboarding.status);
          return (
            <div className="wiz-action" key={a.id}>
              <div className="wiz-action__body">
                <div className="wiz-action__title">
                  {a.label}
                  {a.simulated && <span className="badge accent">simulated</span>}
                </div>
                <p className="wiz-action__line">
                  <strong>Does:</strong> {a.does}
                </p>
                <p className="wiz-action__line">
                  <strong>Does not:</strong> {a.doesNot}
                </p>
                <p className="wiz-action__line">
                  <strong>Next:</strong> {a.next}
                </p>
              </div>
              <div className="wiz-action__cta">
                <CyberButton
                  variant={a.id === "approve" || a.id === "activate" ? "ok" : "secondary"}
                  size="sm"
                  disabled={action.busy || !enabled}
                  title={
                    enabled
                      ? undefined
                      : `Available when the onboarding is in the required state — current: ${onboarding.status.replace(/_/g, " ")}.`
                  }
                  onClick={() => void act(runners[a.id])}
                >
                  {a.label}
                </CyberButton>
              </div>
            </div>
          );
        })}
      </div>

      {onboarding.status === "active" && (
        <p className="muted" style={{ marginTop: 10 }}>
          Active · verification level{" "}
          <span className="mono">{onboarding.approved_verification_level ?? "simulated"}</span>.
          SECP may now generate scenario plans inside this approved boundary.
        </p>
      )}
      {rejected && <p className="muted">This onboarding is {onboarding.status}.</p>}
    </div>
  );
}
