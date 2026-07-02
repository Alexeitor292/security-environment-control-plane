import { useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  IsolationModelName,
  Onboarding,
  OnboardingMode,
} from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
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
  buildBoundary,
  canAdvanceWizardStep,
  canCreateOnboardingDraft,
  draftFromScope,
  emptyDraft,
  isTerminalRejected,
  lifecycleIndex,
  parseList,
  scopeOptionsFromPolicy,
  targetHasApprovedSegments,
  toggleDraftListValue,
  type BoundaryDraft,
} from "./onboarding-wizard";

const STEP_TITLES = [
  "Select target",
  "Onboarding mode",
  "Isolation model",
  "Lab network approach",
  "Isolation profile",
  "Define & review boundary",
  "Lifecycle (simulated)",
];

export function OnboardingWizard() {
  const targets = useAsync(() => api.listTargets(), []);
  const [step, setStep] = useState(0);
  const [targetId, setTargetId] = useState<string>("");
  const [mode, setMode] = useState<OnboardingMode>("existing_environment");
  const [isolationModel, setIsolationModel] = useState<IsolationModelName>("physical");
  const [draft, setDraft] = useState<BoundaryDraft>(emptyDraft());
  const [onboarding, setOnboarding] = useState<Onboarding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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

  async function act(fn: () => Promise<Onboarding>) {
    setBusy(true);
    setError(null);
    try {
      setOnboarding(await fn());
    } catch (e: any) {
      setError(`${e.message}${e.details ? " — " + e.details.join("; ") : ""}`);
    } finally {
      setBusy(false);
    }
  }

  const canNext = canAdvanceWizardStep(
    step,
    !!targetId,
    hasApprovedSegments,
    validation.ok,
    !!onboarding,
  );
  const canCreateDraft = canCreateOnboardingDraft(
    busy,
    !!targetId,
    hasApprovedSegments,
    validation.ok,
  );

  return (
    <div>
      <h2>Target onboarding wizard</h2>
      <div className="error-box" style={{ background: "transparent" }}>
        <strong>Simulated onboarding (SECP-002B-1B-0.1).</strong> This constrains an
        approved boundary; SECP later creates scenario resources inside it. Preflight is{" "}
        <strong>simulated</strong> and the live-evidence seal remains in force — no real
        server, network, bridge, or provider is contacted.
      </div>

      <ol className="wizard-steps">
        {STEP_TITLES.map((title, i) => (
          <li key={title} className={i === step ? "current" : i < step ? "done" : ""}>
            <span className="mono">{i + 1}</span> {title}
          </li>
        ))}
      </ol>

      {error && <div className="error-box">{error}</div>}

      <div className="panel">
        <h3>
          {step + 1}. {STEP_TITLES[step]}
        </h3>

        {step === 0 && (
          <div>
            <p className="muted">
              Selecting an <strong>existing environment</strong> means selecting an existing
              hypervisor/cluster <strong>boundary</strong> — it does <strong>not</strong>{" "}
              adopt existing VMs or containers.
            </p>
            {targets.data && targets.data.length === 0 && (
              <p className="muted">
                No registered targets. Register one under “Provider Targets” first.
              </p>
            )}
            <label>Registered execution target</label>
            <select value={targetId} onChange={(e) => selectTarget(e.target.value)}>
              <option value="">— select a target —</option>
              {targets.data?.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.display_name} · {t.plugin_name}
                </option>
              ))}
            </select>
            {targetId && !hasApprovedSegments && (
              <div className="error-box" style={{ marginTop: 10 }}>
                {NO_APPROVED_SEGMENTS_MESSAGE}
              </div>
            )}
          </div>
        )}

        {step === 1 && (
          <RadioGroup
            options={ONBOARDING_MODES}
            value={mode}
            onChange={(v) => setMode(v as OnboardingMode)}
          />
        )}

        {step === 2 && (
          <div>
            <RadioGroup
              options={ISOLATION_MODELS}
              value={isolationModel}
              onChange={(v) => setIsolationModel(v as IsolationModelName)}
            />
            {isolationModel === "logical" && (
              <div className="error-box" style={{ marginTop: 10 }}>
                Logical isolation requires a complete, verified boundary with{" "}
                <strong>no route</strong> to management, home, corporate, storage, or public
                networks. The <span className="mono">no_route_to_protected</span> preflight
                check must pass.
              </div>
            )}
          </div>
        )}

        {step === 3 && (
          <div>
            <RadioGroup
              options={NETWORK_APPROACHES}
              value={draft.networkApproach}
              onChange={(v) => set("networkApproach", v as BoundaryDraft["networkApproach"])}
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
          <div>
            {ISOLATION_PROFILES.map((p) => (
              <label
                key={p.value}
                className="radio-row"
                style={{ opacity: p.available ? 1 : 0.55 }}
              >
                <input
                  type="radio"
                  name="isolation_profile"
                  disabled={!p.available}
                  checked={draft.isolationProfile === p.value}
                  onChange={() => set("isolationProfile", p.value)}
                />
                <span>
                  <strong>{p.label}</strong>
                  {p.recommended && <span className="badge ok"> recommended</span>}
                  {!p.available && <span className="badge pending"> planned, not available yet</span>}
                  <div className="muted">{p.description}</div>
                </span>
              </label>
            ))}
          </div>
        )}

        {step === 5 && (
          <div>
            <div className="grid cols-2">
              <div>
                <ApprovedValuePicker
                  label="Allowed nodes"
                  approvedValues={targetOptions.nodes}
                  selectedRaw={draft.nodes}
                  onChange={(value) => set("nodes", value)}
                />
                <ApprovedValuePicker
                  label="Allowed storage"
                  approvedValues={targetOptions.storage}
                  selectedRaw={draft.storage}
                  onChange={(value) => set("storage", value)}
                />
                <ApprovedValuePicker
                  label="Network segments / bridges"
                  approvedValues={targetOptions.networkSegments}
                  selectedRaw={draft.networkSegments}
                  onChange={(value) => set("networkSegments", value)}
                  helper={NETWORK_SEGMENT_HELPER_TEXT}
                  emptyText={NO_APPROVED_SEGMENTS_MESSAGE}
                />
                <ApprovedValuePicker
                  label="CIDR reservations"
                  approvedValues={targetOptions.cidrs}
                  selectedRaw={draft.cidrs}
                  onChange={(value) => set("cidrs", value)}
                  helper={CIDR_HELPER_TEXT}
                />
                <label>Credential-scope label (opaque, non-secret)</label>
                <input
                  value={draft.credentialScope}
                  onChange={(e) => set("credentialScope", e.target.value)}
                />
              </div>
              <div>
                <div className="grid cols-2">
                  <div>
                    <label>VM-ID start</label>
                    <input
                      type="number"
                      min={targetOptions.vmidRange?.start}
                      max={targetOptions.vmidRange?.end}
                      value={draft.vmidStart}
                      onChange={(e) => set("vmidStart", e.target.value)}
                    />
                  </div>
                  <div>
                    <label>VM-ID end</label>
                    <input
                      type="number"
                      min={targetOptions.vmidRange?.start}
                      max={targetOptions.vmidRange?.end}
                      value={draft.vmidEnd}
                      onChange={(e) => set("vmidEnd", e.target.value)}
                    />
                  </div>
                </div>
                {targetOptions.vmidRange && (
                  <p className="muted mono" style={{ marginTop: 4 }}>
                    approved VM-ID range: {targetOptions.vmidRange.start}-
                    {targetOptions.vmidRange.end}
                  </p>
                )}
                <label>Max teams / VMs / containers</label>
                <div className="grid cols-2">
                  <input
                    type="number"
                    min={1}
                    max={targetOptions.quotas.maxTeams}
                    value={draft.maxTeams}
                    onChange={(e) => set("maxTeams", e.target.value)}
                  />
                  <input
                    type="number"
                    min={1}
                    max={targetOptions.quotas.maxVms}
                    value={draft.maxVms}
                    onChange={(e) => set("maxVms", e.target.value)}
                  />
                </div>
                <input
                  type="number"
                  min={0}
                  max={targetOptions.quotas.maxContainers}
                  value={draft.maxContainers}
                  onChange={(e) => set("maxContainers", e.target.value)}
                />
                <label>Max vCPU / memory (MB) / disk (GB)</label>
                <div className="grid cols-2">
                  <input
                    type="number"
                    min={1}
                    max={targetOptions.quotas.maxVcpu}
                    value={draft.maxVcpu}
                    onChange={(e) => set("maxVcpu", e.target.value)}
                  />
                  <input
                    type="number"
                    min={1}
                    max={targetOptions.quotas.maxMemoryMb}
                    value={draft.maxMemoryMb}
                    onChange={(e) => set("maxMemoryMb", e.target.value)}
                  />
                </div>
                <input
                  type="number"
                  min={1}
                  max={targetOptions.quotas.maxDiskGb}
                  value={draft.maxDiskGb}
                  onChange={(e) => set("maxDiskGb", e.target.value)}
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

            {!validation.ok && (
              <div className="error-box" style={{ marginTop: 10 }}>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {validation.errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="panel" style={{ background: "#0b0f15", marginTop: 12 }}>
              <h3 style={{ marginTop: 0 }}>Review</h3>
              <p>{REVIEW_STATEMENT}</p>
              <p className="muted mono">
                mode={mode} · isolation={isolationModel} · network={draft.networkApproach} ·
                profile={draft.isolationProfile}
              </p>
              {!onboarding ? (
                <button
                  className="ok"
                  disabled={!canCreateDraft}
                  onClick={() =>
                    act(() =>
                      api.createOnboarding(targetId, {
                        onboarding_mode: mode,
                        isolation_model: isolationModel,
                        declared_boundary: validation.boundary!,
                      }),
                    )
                  }
                >
                  Create onboarding draft
                </button>
              ) : (
                <p className="muted">
                  Onboarding draft created (<span className="mono">{onboarding.id.slice(0, 8)}</span>
                  ). Continue to the lifecycle step.
                </p>
              )}
            </div>
          </div>
        )}

        {step === 6 && <LifecycleStep onboarding={onboarding} busy={busy} error={error} act={act} />}
      </div>

      <div className="row" style={{ marginTop: 12 }}>
        <button
          className="secondary"
          disabled={step === 0}
          onClick={() => setStep((s) => Math.max(0, s - 1))}
        >
          Back
        </button>
        <button
          disabled={step === STEP_TITLES.length - 1 || !canNext}
          onClick={() => setStep((s) => Math.min(STEP_TITLES.length - 1, s + 1))}
        >
          Next
        </button>
      </div>
    </div>
  );
}

function RadioGroup<T extends string>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: string; help: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div>
      {options.map((o) => (
        <label key={o.value} className="radio-row">
          <input
            type="radio"
            checked={value === o.value}
            onChange={() => onChange(o.value)}
          />
          <span>
            <strong>{o.label}</strong>
            <div className="muted">{o.help}</div>
          </span>
        </label>
      ))}
    </div>
  );
}

function ApprovedValuePicker({
  label,
  approvedValues,
  selectedRaw,
  helper,
  emptyText,
  onChange,
}: {
  label: string;
  approvedValues: string[];
  selectedRaw: string;
  helper?: string;
  emptyText?: string;
  onChange: (value: string) => void;
}) {
  const selected = new Set(parseList(selectedRaw));
  return (
    <div style={{ marginBottom: 10 }}>
      <label>{label}</label>
      {helper && <p className="muted">{helper}</p>}
      {approvedValues.length === 0 ? (
        <div className="error-box" style={{ marginTop: 6 }}>
          {emptyText ?? `No approved values configured for ${label}.`}
        </div>
      ) : (
        <div>
          <p className="muted mono" style={{ marginTop: 0 }}>
            approved values: {approvedValues.join(", ")}
          </p>
          {approvedValues.map((value) => (
            <label key={value} className="radio-row">
              <input
                type="checkbox"
                checked={selected.has(value)}
                onChange={(e) =>
                  onChange(toggleDraftListValue(selectedRaw, value, e.target.checked))
                }
              />
              <span className="mono">{value}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

function LifecycleStep({
  onboarding,
  busy,
  error,
  act,
}: {
  onboarding: Onboarding | null;
  busy: boolean;
  error: string | null;
  act: (fn: () => Promise<Onboarding>) => void;
}) {
  if (!onboarding) {
    return <p className="muted">Create the onboarding draft (previous step) first.</p>;
  }
  const idx = lifecycleIndex(onboarding.status);
  const rejected = isTerminalRejected(onboarding.status);
  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <p className="muted mono">
          onboarding {onboarding.id.slice(0, 8)} · boundary {onboarding.boundary_hash.slice(7, 19)}…
        </p>
        <StatusBadge state={onboarding.status} />
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
        <span className="mono">simulated</span>; the B1-B-0 live-evidence seal is in force and
        no real infrastructure is contacted. Human approval is required before{" "}
        <span className="mono">active</span>.
      </p>
      {error && <div className="error-box">{error}</div>}

      <div className="row" style={{ marginTop: 8 }}>
        <button
          className="secondary"
          disabled={busy || onboarding.status !== "draft"}
          onClick={() => act(() => api.requestPreflight(onboarding.id).then(() => api.getOnboarding(onboarding.id)))}
        >
          Run simulated preflight
        </button>
        <button
          className="secondary"
          disabled={busy || onboarding.status !== "preflight_pending"}
          onClick={() => act(() => api.submitOnboarding(onboarding.id))}
        >
          Submit for review
        </button>
        <button
          className="ok"
          disabled={busy || onboarding.status !== "ready_for_review"}
          onClick={() => act(() => api.approveOnboarding(onboarding.id, "approved via wizard"))}
        >
          Approve (human)
        </button>
        <button
          className="ok"
          disabled={busy || onboarding.status !== "approved"}
          onClick={() => act(() => api.activateOnboarding(onboarding.id))}
        >
          Activate
        </button>
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
