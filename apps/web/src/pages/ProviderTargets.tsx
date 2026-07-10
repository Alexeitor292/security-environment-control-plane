import "./targets.css";

import { Boxes } from "lucide-react";
import { useState } from "react";

import { ApiClientError, api } from "../api/client";
import type {
  ExecutionTarget,
  InventorySnapshot,
  Onboarding,
  PreflightAuthorization,
  ResolverActivation,
  TargetEvidence,
} from "../api/types";
import {
  AccessChain,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberTable,
  EmptyState,
  EvidenceBadge,
  HashChip,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  TabRail,
  tabId,
  tabPanelId,
  truncateHash,
  useAction,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  DEFAULT_PROVISIONING_BOUNDARY,
  buildRegisterTargetPayload,
  type ProvisioningBoundaryDraft,
} from "./provider-targets";
import {
  CHAIN_FOOTER,
  CHAIN_INTRO,
  DISCOVERY_REFUSED_HINT,
  INVENTORY_TAGLINE,
  MILESTONE_NOTICE,
  SECRET_REF_CAPTION,
  boundarySummaryFromScope,
  buildAccessChain,
  evidenceCellView,
  liveAccessCellView,
  type CellView,
} from "./target-hub";

/** Swallow one source's failure — it renders as an explicit truthful
 *  unavailable state instead of failing the whole surface. */
const opt = <T,>(p: Promise<T>): Promise<T | null> => p.catch(() => null);

/** Authorization listing for a substrate-ineligible target is a definite
 *  backend refusal (closed code), not an outage: no authorization is listable
 *  or usable for this substrate, so it truthfully renders as Sealed (empty
 *  list) rather than "unavailable". */
const optAuthorizations = (
  p: Promise<PreflightAuthorization[]>,
): Promise<PreflightAuthorization[] | null> =>
  p.catch((e) =>
    e instanceof ApiClientError &&
    e.code === "readonly_preflight_substrate_ineligible"
      ? []
      : null,
  );

function newestOnboarding(onboardings: Onboarding[]): Onboarding | null {
  if (onboardings.length === 0) return null;
  return [...onboardings].sort((a, b) =>
    b.created_at.localeCompare(a.created_at),
  )[0];
}

interface TargetRowData {
  onboardings: Onboarding[] | null;
  evidence: TargetEvidence[] | null;
  authorizations: PreflightAuthorization[] | null;
}

async function loadInventoryDetails(
  targets: ExecutionTarget[],
): Promise<Record<string, TargetRowData>> {
  const perTarget = await Promise.all(
    targets.map(async (t) => {
      const [onboardings, authorizations] = await Promise.all([
        opt(api.listOnboardings(t.id)),
        optAuthorizations(api.listPreflightAuthorizations(t.id)),
      ]);
      let evidence: TargetEvidence[] | null = [];
      if (onboardings === null) {
        evidence = null;
      } else {
        const latest = newestOnboarding(onboardings);
        if (latest) evidence = await opt(api.listTargetEvidence(latest.id));
      }
      return [t.id, { onboardings, evidence, authorizations }] as const;
    }),
  );
  return Object.fromEntries(perTarget);
}

interface TargetDetailData {
  onboardings: Onboarding[] | null;
  authorizations: PreflightAuthorization[] | null;
  resolverActivations: ResolverActivation[] | null;
  snapshots: InventorySnapshot[] | null;
  evidence: TargetEvidence[] | null;
}

async function loadTargetDetail(targetId: string): Promise<TargetDetailData> {
  const [onboardings, authorizations, resolverActivations, snapshots] =
    await Promise.all([
      opt(api.listOnboardings(targetId)),
      optAuthorizations(api.listPreflightAuthorizations(targetId)),
      opt(api.listResolverActivations(targetId)),
      opt(api.listSnapshots(targetId)),
    ]);
  let evidence: TargetEvidence[] | null = [];
  if (onboardings === null) {
    evidence = null;
  } else {
    const latest = newestOnboarding(onboardings);
    if (latest) evidence = await opt(api.listTargetEvidence(latest.id));
  }
  return { onboardings, authorizations, resolverActivations, snapshots, evidence };
}

function CellValue({ view }: { view: CellView }) {
  return (
    <div>
      <span className={`thub-cell--${view.tone}`}>{view.label}</span>
      {view.meta && <div className="thub-cellmeta mono">{view.meta}</div>}
    </div>
  );
}

function RegisterForm({ onCreated }: { onCreated: () => void }) {
  const [displayName, setDisplayName] = useState("Lab Proxmox (placeholder)");
  const [baseUrl, setBaseUrl] = useState("https://proxmox.example.test:8006/api2/json");
  const [secretRef, setSecretRef] = useState("env:SECP_PROVIDER_SECRET__LAB");
  const [boundary, setBoundary] = useState<ProvisioningBoundaryDraft>(
    DEFAULT_PROVISIONING_BOUNDARY,
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function setBoundaryField<K extends keyof ProvisioningBoundaryDraft>(
    key: K,
    value: ProvisioningBoundaryDraft[K],
  ) {
    setBoundary((current) => ({ ...current, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const payload = buildRegisterTargetPayload({
        displayName,
        baseUrl,
        secretRef,
        boundary,
      });
      if (!payload.ok || !payload.value) {
        setError(payload.errors.join("; "));
        return;
      }
      await api.registerTarget(payload.value);
      onCreated();
    } catch (e: any) {
      setError(`${e.message}${e.details ? " — " + e.details.join("; ") : ""}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <CyberCard heading="Register execution target">
      <p className="muted">
        Non-secret configuration only. Provide an <strong>opaque secret reference</strong>{" "}
        (e.g. <code>env:SECP_PROVIDER_SECRET__LAB</code>) — never a real secret. There is
        no secret-entry form by design.
      </p>
      {error && <div className="error-box">{error}</div>}
      <div className="grid cols-2">
        <div>
          <CyberInput
            label="Display name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
          <CyberInput
            label="Base URL (non-secret)"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
          />
        </div>
        <div>
          <CyberInput
            label="Secret reference (opaque pointer)"
            value={secretRef}
            onChange={(e) => setSecretRef(e.target.value)}
          />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <h3 style={{ marginTop: 0 }}>Allowed provisioning boundary</h3>
        <p className="muted">
          Provider-neutral fake lab values only. These approved values define what the
          onboarding wizard may select; no infrastructure discovery, provider validation,
          network calls, or provisioning actions are performed here.
        </p>
        <div className="grid cols-2">
          <div>
            <CyberInput
              label="Allowed nodes"
              value={boundary.allowedNodes}
              onChange={(e) => setBoundaryField("allowedNodes", e.target.value)}
            />
            <CyberInput
              label="Allowed storage"
              value={boundary.allowedStorage}
              onChange={(e) => setBoundaryField("allowedStorage", e.target.value)}
            />
            <CyberInput
              label="Allowed network segments / bridges"
              hint="A network segment is a bridge, VNet, or VLAN name such as lab-isolated-segment, not an IP range."
              value={boundary.networkSegments}
              onChange={(e) => setBoundaryField("networkSegments", e.target.value)}
            />
            <CyberInput
              label="Approved CIDR reservations"
              hint="CIDRs are lab address ranges, for example 10.60.0.0/16."
              value={boundary.cidrs}
              onChange={(e) => setBoundaryField("cidrs", e.target.value)}
            />
            <CyberInput
              label="Allowed templates/images"
              value={boundary.allowedTemplates}
              onChange={(e) => setBoundaryField("allowedTemplates", e.target.value)}
            />
          </div>
          <div>
            <div className="grid cols-2">
              <CyberInput
                label="VM-ID start"
                value={boundary.vmidStart}
                onChange={(e) => setBoundaryField("vmidStart", e.target.value)}
              />
              <CyberInput
                label="VM-ID end"
                value={boundary.vmidEnd}
                onChange={(e) => setBoundaryField("vmidEnd", e.target.value)}
              />
            </div>
            <div className="grid cols-2">
              <CyberInput
                label="Max teams"
                value={boundary.maxTeams}
                onChange={(e) => setBoundaryField("maxTeams", e.target.value)}
              />
              <CyberInput
                label="Max VMs"
                value={boundary.maxVms}
                onChange={(e) => setBoundaryField("maxVms", e.target.value)}
              />
            </div>
            <CyberInput
              label="Max containers"
              value={boundary.maxContainers}
              onChange={(e) => setBoundaryField("maxContainers", e.target.value)}
            />
            <div className="grid cols-2">
              <CyberInput
                label="Max vCPU"
                value={boundary.maxVcpu}
                onChange={(e) => setBoundaryField("maxVcpu", e.target.value)}
              />
              <CyberInput
                label="Max memory (MB)"
                value={boundary.maxMemoryMb}
                onChange={(e) => setBoundaryField("maxMemoryMb", e.target.value)}
              />
            </div>
            <CyberInput
              label="Max disk (GB)"
              value={boundary.maxDiskGb}
              onChange={(e) => setBoundaryField("maxDiskGb", e.target.value)}
            />
            <div className="grid cols-2">
              <CyberInput
                label="Default template vCPU"
                value={boundary.sizingVcpu}
                onChange={(e) => setBoundaryField("sizingVcpu", e.target.value)}
              />
              <CyberInput
                label="Default template memory (MB)"
                value={boundary.sizingMemoryMb}
                onChange={(e) => setBoundaryField("sizingMemoryMb", e.target.value)}
              />
            </div>
            <CyberInput
              label="Default template disk (GB)"
              value={boundary.sizingDiskGb}
              onChange={(e) => setBoundaryField("sizingDiskGb", e.target.value)}
            />
            <p className="muted mono" style={{ marginTop: 8 }}>
              external connectivity: deny (fixed)
            </p>
          </div>
        </div>
      </div>
      <div className="row" style={{ marginTop: 12 }}>
        <CyberButton onClick={submit} disabled={busy}>
          {busy ? "Registering…" : "Register target"}
        </CyberButton>
      </div>
    </CyberCard>
  );
}

const DETAIL_TABS = [
  { id: "overview", label: "Overview" },
  { id: "boundary", label: "Boundary" },
  { id: "evidence", label: "Evidence" },
  { id: "access", label: "Access chain" },
  { id: "snapshots", label: "Snapshots" },
];

function TargetDetail({
  target,
  onChanged,
}: {
  target: ExecutionTarget;
  onChanged: () => void;
}) {
  const detail = useAsync(() => loadTargetDetail(target.id), [target.id]);
  const [tab, setTab] = useState("overview");
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const disableAction = useAction();
  const [confirmDisable, setConfirmDisable] = useState(false);

  async function discover() {
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const snap: InventorySnapshot = await api.requestDiscovery(target.id);
      setMsg(`Discovery queued (snapshot ${snap.id.slice(0, 8)}, status ${snap.status}).`);
      detail.reload();
    } catch (e: any) {
      // In inline dev mode this is intentionally refused.
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const boundary = boundarySummaryFromScope(target.scope_policy);
  const latestEvidenceRecord =
    detail.data?.evidence && detail.data.evidence.length > 0
      ? [...detail.data.evidence].sort((a, b) =>
          b.collected_at.localeCompare(a.collected_at),
        )[0]
      : null;
  const idBase = `target-${target.id.slice(0, 8)}`;

  return (
    <CyberCard>
      <div className="thub-detail-head">
        <div>
          <h3>{target.display_name}</h3>
          <div className="thub-detail-sub mono">{target.plugin_name} plugin</div>
        </div>
        <div className="thub-detail-actions">
          <StatusBadge state={target.status} domain="target" />
          <CyberButton variant="secondary" size="sm" disabled={busy} onClick={discover}>
            Request read-only discovery
          </CyberButton>
          <CyberButton
            variant="danger"
            size="sm"
            disabled={busy || disableAction.busy || target.status === "disabled"}
            title={
              target.status === "disabled" ? "This target is already disabled." : undefined
            }
            onClick={() => {
              if (!confirmDisable) {
                setConfirmDisable(true);
                return;
              }
              void disableAction.run(
                () => api.disableTarget(target.id),
                () => {
                  setConfirmDisable(false);
                  onChanged();
                },
              );
            }}
          >
            {confirmDisable ? "Confirm disable" : "Disable"}
          </CyberButton>
          {confirmDisable && !disableAction.busy && (
            <CyberButton
              variant="ghost"
              size="sm"
              onClick={() => setConfirmDisable(false)}
            >
              Cancel
            </CyberButton>
          )}
        </div>
      </div>
      <div className="thub-meta-chips">
        <span className="thub-chip mono">
          config <HashChip value={target.config_hash} digits={12} />
        </span>
        {target.secret_ref && (
          <span className="thub-chip mono">
            secret_ref: {target.secret_ref} (reference, not a secret)
          </span>
        )}
      </div>
      {msg && <p className="muted">{msg}</p>}
      {error && (
        <div className="error-box">
          {error} ({DISCOVERY_REFUSED_HINT})
        </div>
      )}
      {disableAction.error && (
        <div className="error-box" role="alert">
          {disableAction.error.text}{" "}
          <code className="mono">{disableAction.error.code}</code>
        </div>
      )}

      <TabRail
        tabs={DETAIL_TABS}
        active={tab}
        onSelect={setTab}
        idBase={idBase}
        aria-label={`${target.display_name} sections`}
      />
      <div
        role="tabpanel"
        id={tabPanelId(idBase, tab)}
        aria-labelledby={tabId(idBase, tab)}
        tabIndex={0}
      >
        {tab === "overview" && (
          <div>
            <KeyValueList
              items={[
                { key: "Plugin", value: target.plugin_name, mono: true },
                {
                  key: "Status",
                  value: <StatusBadge state={target.status} domain="target" />,
                },
                {
                  key: "Config hash",
                  value: <HashChip value={target.config_hash} digits={16} />,
                },
                {
                  key: "Secret reference",
                  value: target.secret_ref
                    ? `${target.secret_ref} (reference, not a secret)`
                    : "none",
                  mono: true,
                },
                {
                  key: "Registered",
                  value: new Date(target.created_at).toLocaleString(),
                },
              ]}
            />
            <p className="thub-caption">{SECRET_REF_CAPTION}</p>
          </div>
        )}
        {tab === "boundary" &&
          (boundary ? (
            <div>
              <KeyValueList items={boundary.rows} />
              <p className="thub-caption">
                Approved values only — the onboarding wizard can narrow this
                boundary but never widen it.
              </p>
            </div>
          ) : (
            <EmptyState title="No provisioning boundary declared">
              Register targets with an allowed provisioning boundary to define
              what onboarding may select.
            </EmptyState>
          ))}
        {tab === "evidence" &&
          (detail.loading && !detail.data ? (
            <Skeleton lines={3} />
          ) : detail.data?.evidence === null ? (
            <p className="muted">Target evidence unavailable.</p>
          ) : latestEvidenceRecord ? (
            <div>
              <div className="thub-evidence-meta mono">
                {latestEvidenceRecord.evidence_source} evidence{" "}
                <HashChip value={latestEvidenceRecord.evidence_hash} digits={8} /> ·
                collected {latestEvidenceRecord.collected_at.slice(0, 10)}
              </div>
              <div className="thub-evidence-list">
                {latestEvidenceRecord.findings.map((f) => (
                  <EvidenceBadge
                    key={f.check}
                    title={f.check}
                    status={f.status}
                    detail={f.detail}
                  />
                ))}
              </div>
            </div>
          ) : (
            <EmptyState title="No target evidence recorded">
              Evidence is collected by onboarding preflights; none has been
              recorded for this target yet.
            </EmptyState>
          ))}
        {tab === "access" &&
          (detail.loading && !detail.data ? (
            <Skeleton lines={4} />
          ) : (
            <div>
              <p className="muted">{CHAIN_INTRO}</p>
              <AccessChain
                links={buildAccessChain({
                  onboardings: detail.data?.onboardings ?? null,
                  authorizations: detail.data?.authorizations ?? null,
                  resolverActivations: detail.data?.resolverActivations ?? null,
                })}
                footer={CHAIN_FOOTER}
              />
            </div>
          ))}
        {tab === "snapshots" &&
          (detail.loading && !detail.data ? (
            <Skeleton lines={3} />
          ) : detail.data?.snapshots === null ? (
            <p className="muted">Snapshots unavailable.</p>
          ) : detail.data && detail.data.snapshots!.length > 0 ? (
            <CyberTable
              head={["Snapshot", "Status", "Resources", "Requested"]}
              label="Inventory snapshots"
            >
              {detail.data.snapshots!.map((s) => (
                <tr key={s.id}>
                  <td className="mono">
                    <HashChip value={s.id} digits={8} />
                  </td>
                  <td>
                    <StatusBadge state={s.status} />
                  </td>
                  <td className="muted">
                    {String((s.summary as { total?: unknown })?.total ?? "—")}
                  </td>
                  <td className="muted">
                    {new Date(s.requested_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </CyberTable>
          ) : (
            <EmptyState title="No inventory snapshots">
              Request read-only discovery to queue a snapshot; results appear
              only after the worker records completion.
            </EmptyState>
          ))}
      </div>
    </CyberCard>
  );
}

export function ProviderTargets() {
  const caps = useAsync(() => opt(api.providerCapabilities()), []);
  const targets = useAsync(() => api.listTargets(), []);
  const targetList = targets.data ?? null;
  const rowData = useAsync(
    () =>
      targetList
        ? loadInventoryDetails(targetList)
        : Promise.resolve<Record<string, TargetRowData>>({}),
    [targetList],
  );
  const [showRegister, setShowRegister] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selected = targetList?.find((t) => t.id === selectedId) ?? null;

  return (
    <div className="thub">
      <div className="thub-head">
        <div>
          <h2>Target Inventory</h2>
          <p className="thub-tagline">{INVENTORY_TAGLINE}</p>
        </div>
        <CyberButton
          variant="outline"
          onClick={() => setShowRegister((v) => !v)}
          aria-expanded={showRegister}
        >
          {showRegister ? "Hide registration" : "Register target"}
        </CyberButton>
      </div>

      <SafetyNotice role="note" tone="warn">
        {MILESTONE_NOTICE}
      </SafetyNotice>

      {caps.data && (
        <div className="thub-chips">
          <span className="thub-chip mono">{caps.data.milestone}</span>
          <span className="thub-chip mono">
            provisioning_enabled={String(caps.data.provisioning_enabled)}
          </span>
          <span className="thub-chip mono">discovery={caps.data.discovery}</span>
        </div>
      )}

      {showRegister && (
        <RegisterForm
          onCreated={() => {
            setShowRegister(false);
            targets.reload();
          }}
        />
      )}

      {targets.error && <div className="error-box">{targets.error}</div>}
      {targets.loading && !targets.data && <Skeleton lines={4} />}
      {targetList && targetList.length === 0 && (
        <EmptyState
          title="No execution targets registered yet"
          action={
            <CyberButton variant="outline" onClick={() => setShowRegister(true)}>
              Register target
            </CyberButton>
          }
        >
          Registering a target stores non-secret configuration and an opaque
          secret reference — no endpoint is contacted.
        </EmptyState>
      )}
      {targetList && targetList.length > 0 && (
        <CyberTable
          head={["Target", "Type", "Boundary", "Latest evidence", "Live access", "Status"]}
          label="Target inventory"
          caption={`${targetList.length} target${targetList.length === 1 ? "" : "s"} · ${SECRET_REF_CAPTION}`}
        >
          {targetList.map((t) => {
            const data = rowData.data?.[t.id];
            const boundary = boundarySummaryFromScope(t.scope_policy);
            const loadingCell: CellView = {
              label: "—",
              tone: "none",
              meta: rowData.loading ? "loading…" : "unavailable",
            };
            return (
              <tr
                key={t.id}
                className={selectedId === t.id ? "thub-row--selected" : undefined}
              >
                <td>
                  <button
                    type="button"
                    className="thub-target-btn"
                    onClick={() =>
                      setSelectedId((cur) => (cur === t.id ? null : t.id))
                    }
                    aria-expanded={selectedId === t.id}
                    aria-controls="thub-detail"
                  >
                    <span className="thub-hex" aria-hidden>
                      <Boxes size={14} />
                    </span>
                    <span>
                      <span className="thub-target-name">{t.display_name}</span>
                      <span className="thub-target-sub mono">
                        {truncateHash(t.config_hash, {
                          prefix: "strip",
                          digits: 12,
                          ellipsis: false,
                        })}
                      </span>
                    </span>
                  </button>
                </td>
                <td className="mono">{t.plugin_name}</td>
                <td>
                  {boundary ? (
                    <div>
                      <span>{boundary.counts}</span>
                      <div className="thub-cellmeta mono">{boundary.detail}</div>
                    </div>
                  ) : (
                    <span className="muted">no boundary declared</span>
                  )}
                </td>
                <td>
                  <CellValue view={data ? evidenceCellView(data.evidence) : loadingCell} />
                </td>
                <td>
                  <CellValue
                    view={data ? liveAccessCellView(data.authorizations) : loadingCell}
                  />
                </td>
                <td>
                  <StatusBadge state={t.status} domain="target" />
                </td>
              </tr>
            );
          })}
        </CyberTable>
      )}

      <div id="thub-detail">
        {selected && (
          <TargetDetail
            key={selected.id}
            target={selected}
            onChanged={() => targets.reload()}
          />
        )}
      </div>
    </div>
  );
}
