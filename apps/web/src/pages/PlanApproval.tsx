import "./environments.css";

import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import { CyberGridBackground } from "../components/backgrounds";
import {
  CyberButton,
  CyberCard,
  CyberInput,
  CyberTable,
  HashChip,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  useAction,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  APPROVAL_RECORDS_ONLY_NOTE,
  ENVIRONMENTS_ERROR_TEXT,
  PLAN_PINNED_NOTE,
  canDecidePlan,
  canSubmitPlan,
  onlyNotFoundAsNull,
  planBindingView,
  planStatusLabel,
} from "./environments-view";
import type { PlanEnvironmentVersionBinding, VersionPublicationProvenance } from "../api/types";

/** Typed publication provenance rows (server-owned; ADR-016 PR C/E). Rendered
 *  ONLY from the plan binding's provenance — never from plan.summary or spec. */
function ProvenanceList({ provenance }: { provenance: VersionPublicationProvenance }) {
  return (
    <KeyValueList
      items={[
        { key: "Topology document", value: <HashChip value={provenance.topology_document_id} digits={12} /> },
        { key: "Topology revision", value: <HashChip value={provenance.topology_revision_id} digits={12} /> },
        { key: "Topology content hash", value: <HashChip value={provenance.topology_content_hash} digits={14} /> },
        { key: "Validation result", value: <HashChip value={provenance.topology_validation_result_id} digits={12} /> },
        { key: "Validation result hash", value: <HashChip value={provenance.topology_validation_result_hash} digits={14} /> },
        {
          key: "Base version",
          value: provenance.base_environment_version_id ? (
            <HashChip value={provenance.base_environment_version_id} digits={12} />
          ) : (
            "none"
          ),
        },
        { key: "Publication contract", value: provenance.publication_contract_version, mono: true },
        { key: "Publication fingerprint", value: <HashChip value={provenance.publication_fingerprint} digits={14} /> },
      ]}
    />
  );
}

/**
 * The plan's ONE-version binding + its publication provenance (ADR-016 PR E).
 * Origin and provenance are read solely from `plan.environment_version_binding`
 * (via `planBindingView`) — never from plan.summary, the version spec, a
 * workspace, or a URL. A legacy/manual version therefore can never read as
 * published, and a published version's provenance can never be fabricated from
 * plan content. Purely presentational: it renders no mutation control.
 */
export function PlanBindingCard({ binding }: { binding: PlanEnvironmentVersionBinding }) {
  const view = planBindingView(binding);
  return (
    <CyberCard surface="well" heading="Environment version binding">
      <p className="env-note">
        {view.originLabel} — {view.originNote}
      </p>
      <KeyValueList
        items={[
          { key: "Version number", value: String(view.versionNumber) },
          { key: "Version id", value: <HashChip value={view.environmentVersionId} digits={12} /> },
          { key: "Template id", value: <HashChip value={view.templateId} digits={12} /> },
          { key: "API version", value: view.apiVersion, mono: true },
          { key: "Content hash", value: <HashChip value={view.contentHash} digits={16} /> },
        ]}
      />
      {view.provenance ? (
        <>
          <p className="env-note">Publication provenance (server-owned):</p>
          <ProvenanceList provenance={view.provenance} />
        </>
      ) : (
        <p className="env-note">No publication provenance — legacy/manual immutable version.</p>
      )}
      <p className="env-links">
        <Link to={view.libraryDeepLink}>Open in Environment Library →</Link>
      </p>
    </CyberCard>
  );
}

export function PlanApproval() {
  const { exerciseId = "" } = useParams();
  const navigate = useNavigate();
  // Only a not_found means "no plan recorded"; any other failure is an
  // unavailable state, never a claim of absence.
  const plan = useAsync(() => api.latestPlan(exerciseId).catch(onlyNotFoundAsNull), [exerciseId]);
  const [reason, setReason] = useState("");
  const action = useAction({ codeText: ENVIRONMENTS_ERROR_TEXT });

  if (plan.loading && !plan.data)
    return (
      <CyberCard>
        <Skeleton lines={5} />
      </CyberCard>
    );
  if (plan.error !== null && plan.error !== undefined)
    return (
      <div className="error-box" role="alert">
        Plan unavailable.
      </div>
    );
  if (!plan.data)
    return (
      <div className="env">
        <div className="env-head">
          <div>
            <h1>Deployment Plan Review</h1>
            <p className="env-sub">No plan generated for this exercise yet.</p>
          </div>
        </div>
        <p className="env-note">
          <Link to={`/exercises/${exerciseId}`}>← Back to exercise</Link>
        </p>
      </div>
    );

  const p = plan.data;
  const submitAllowed = canSubmitPlan(p);
  const decideAllowed = canDecidePlan(p);

  return (
    <div className="env">
      <CyberGridBackground intensity="subtle" className="env-bg" />
      <div className="env-head">
        <div>
          <h1>Deployment Plan Review</h1>
          <p className="env-sub">{PLAN_PINNED_NOTE}</p>
        </div>
        <StatusBadge state={p.status} domain="plan" />
      </div>

      <div className="env-hashline">
        <span>
          pinned to version hash <HashChip value={p.version_content_hash} digits={16} />
        </span>
        {p.approved_content_hash && (
          <span>
            · approved hash <HashChip value={p.approved_content_hash} digits={16} />
          </span>
        )}
      </div>

      <SafetyNotice role="note" tone="warn">
        {APPROVAL_RECORDS_ONLY_NOTE}
      </SafetyNotice>

      {action.error && (
        <div className="error-box" role="alert">
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}

      <PlanBindingCard binding={p.environment_version_binding} />

      <CyberCard heading="Planned shape (simulated)">
        <KeyValueList
          items={[
            {
              key: "Totals",
              value: `${p.summary.total_nodes} simulated nodes · ${p.summary.total_networks} networks · ${p.summary.teams} isolated teams`,
            },
            { key: "Isolation", value: p.summary.isolation },
            { key: "Plugin", value: p.summary.plugin, mono: true },
            { key: "Status", value: planStatusLabel(p.status) },
            {
              key: "Decided at",
              value: p.decided_at ? p.decided_at.slice(0, 19).replace("T", " ") + " UTC" : "— (no decision recorded)",
              mono: p.decided_at !== null,
            },
          ]}
        />
      </CyberCard>

      <div className="env-grid">
        {p.summary.per_team.map((team) => (
          <CyberCard key={team.team_ref} surface="well" heading={team.team_ref}>
            <CyberTable
              label={`${team.team_ref} networks`}
              head={["Network", "Planned CIDR"]}
            >
              {team.networks.map((n) => (
                <tr key={n.name}>
                  <td className="mono">{n.name}</td>
                  <td className="mono muted">{n.cidr}</td>
                </tr>
              ))}
            </CyberTable>
            <CyberTable
              label={`${team.team_ref} nodes`}
              head={["Role", "Kind", "Planned IP"]}
            >
              {team.nodes.map((n) => (
                <tr key={n.name}>
                  <td className="mono">{n.role}</td>
                  <td className="muted">{n.kind}</td>
                  <td className="mono muted">{n.ip}</td>
                </tr>
              ))}
            </CyberTable>
          </CyberCard>
        ))}
      </div>

      <CyberCard heading="Decision">
        <CyberInput
          label="Reason / note (recorded in the audit ledger)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="optional justification"
        />
        <div className="env-actions" style={{ marginTop: 10 }}>
          {submitAllowed && (
            <CyberButton
              variant="secondary"
              disabled={action.busy}
              onClick={() => action.run(() => api.submitPlan(p.id), () => plan.reload())}
            >
              Submit for approval
            </CyberButton>
          )}
          <CyberButton
            variant="ok"
            disabled={action.busy || !decideAllowed}
            title={
              decideAllowed
                ? APPROVAL_RECORDS_ONLY_NOTE
                : `Available when awaiting approval — current: ${planStatusLabel(p.status)}`
            }
            onClick={() =>
              action.run(
                () => api.approvePlan(p.id, reason),
                () => navigate(`/exercises/${exerciseId}`),
              )
            }
          >
            Approve (records decision)
          </CyberButton>
          <CyberButton
            variant="danger"
            disabled={action.busy || !decideAllowed}
            title={
              decideAllowed
                ? "Records a rejection pinned to this plan."
                : `Available when awaiting approval — current: ${planStatusLabel(p.status)}`
            }
            onClick={() => action.run(() => api.rejectPlan(p.id, reason), () => plan.reload())}
          >
            Reject
          </CyberButton>
        </div>
        {p.approved_content_hash && (
          <p className="env-note">
            Decision recorded — pinned to{" "}
            <HashChip value={p.approved_content_hash} digits={16} />. Approval
            itself deployed nothing; deployment is a separate action on the
            exercise page.
          </p>
        )}
      </CyberCard>

      <p className="env-note">
        <Link to={`/exercises/${exerciseId}`}>← Back to exercise</Link>
      </p>
    </div>
  );
}
