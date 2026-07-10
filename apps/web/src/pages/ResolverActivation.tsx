import "./readonly-ops.css";

import { useState } from "react";

import { api } from "../api/client";
import type { ResolverActivation as Authorization } from "../api/types";
import {
  AccessChain,
  CyberButton,
  CyberCard,
  CyberInput,
  EmptyState,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  useAction,
} from "../components/ui";
import { RiveSealedLock } from "../components/rive/wrappers";
import { useAsync } from "../hooks";
import {
  READONLY_COMMON_CODES,
  RESOLVER_INTRO,
  RESOLVER_KILL_SWITCH_STEPS,
  resolverAuthBadgeState,
  resolverGates,
} from "./readonly-ops";
import {
  API_ERROR_TEXT,
  RESOLVER_ACTIVATION_SCOPE_NOTICE,
  RESOLVER_ACTIVATION_SEALED_NOTICE,
  evidenceSummary,
  statusLabel,
} from "./resolver-activation";

const RESOLVER_CODES = { ...READONLY_COMMON_CODES, ...API_ERROR_TEXT };

function AuthorizationCard({
  auth,
  onChange,
}: {
  auth: Authorization;
  onChange: () => void;
}) {
  const action = useAction({ codeText: RESOLVER_CODES });
  const summary = evidenceSummary(auth);
  const run = (fn: () => Promise<unknown>) => action.run(fn, onChange);

  return (
    <CyberCard surface="raised" style={{ marginTop: 10 }}>
      <div className="rops-detail-head">
        <div className="rops-expiry">
          <StatusBadge state={resolverAuthBadgeState(auth)} domain="authorization" />
          <span className="mono">{statusLabel(auth.status)}</span>
        </div>
        <span className="muted">
          evidence {summary.verified}/{summary.total} verified · v
          {auth.authorization_version}
        </span>
      </div>

      {auth.evidence.length > 0 && (
        <div className="rops-evidence">
          {auth.evidence.map((e, i) => (
            <div className="rops-evidence__row" key={`${e.kind}-${i}`}>
              <span className="rops-evidence__kind mono">{e.kind}</span>
              <StatusBadge state={e.status} domain="evidence" />
            </div>
          ))}
        </div>
      )}

      {action.error && (
        <div className="error-box" role="alert" style={{ marginTop: 10 }}>
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}

      <div className="rops-actions">
        {auth.status === "draft" && (
          <CyberButton
            variant="ok"
            size="sm"
            disabled={action.busy}
            title="Recording approval requires a separate permission; it does not activate the resolver."
            onClick={() => run(() => api.approveResolverActivation(auth.id))}
          >
            Approve (separate permission)
          </CyberButton>
        )}
        {(auth.status === "draft" || auth.status === "approved") && (
          <CyberButton
            variant="danger"
            size="sm"
            disabled={action.busy}
            onClick={() => run(() => api.revokeResolverActivation(auth.id))}
          >
            Revoke
          </CyberButton>
        )}
        {auth.status === "approved" && (
          <span className="rops-resp">Sealed — not active</span>
        )}
      </div>
    </CyberCard>
  );
}

export function ResolverActivation() {
  const [targetId, setTargetId] = useState("");
  const authorizations = useAsync<Authorization[]>(
    () => (targetId ? api.listResolverActivations(targetId) : Promise.resolve([])),
    [targetId],
  );

  const authList = authorizations.data ?? null;
  // Posture gates reflect the newest authorization's real state (or none).
  const newest = authList && authList.length > 0 ? authList[0] : null;
  const gates = resolverGates(newest);

  return (
    <div className="rops">
      <div className="rops-head">
        <h1>Resolver Activation Posture</h1>
        <p className="rops-intro">
          Read-only view of the resolver activation contract. Activation is never
          performed from this interface.
        </p>
      </div>
      <SafetyNotice role="note" tone="danger">
        {RESOLVER_ACTIVATION_SEALED_NOTICE}
      </SafetyNotice>

      <div className="rops-grid">
        <CyberCard heading="Cumulative activation gates">
          <div className="rops-detail-head">
            <p className="rops-note" style={{ margin: 0 }}>{RESOLVER_INTRO}</p>
            {/* The resolver is the sealed shipped default; the lock stays
                sealed even when an authorization is approved (a decision is not
                activation). */}
            <RiveSealedLock sealed label="Resolver" size={26} />
          </div>
          <AccessChain
            links={gates.map((g) => ({
              id: g.id,
              title: g.title,
              state: g.state,
              status: g.status,
              body: g.body,
            }))}
            footer={RESOLVER_ACTIVATION_SCOPE_NOTICE}
          />
        </CyberCard>

        <div style={{ display: "grid", gap: 14 }}>
          <CyberCard surface="well" heading="What this page never does">
            <ul className="rops-list">
              <li>Offers no enable switch, credential field, or endpoint editor.</li>
              <li>Renders no backend hostname, port, token, or secret-reference value.</li>
              <li>
                Never implies authorization alone enables resolution, or that
                resolver availability authorizes collection.
              </li>
            </ul>
          </CyberCard>

          <CyberCard surface="well" heading="Rollback / kill-switch posture">
            <p className="rops-note">
              Documented, not executable from here. Each step is independently
              sufficient to stop resolution.
            </p>
            <ol className="rops-list">
              {RESOLVER_KILL_SWITCH_STEPS.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </CyberCard>
        </div>
      </div>

      <CyberCard heading="Activation authorizations">
        <label className="rops-note" htmlFor="resolver-target-id">
          Execution target id
        </label>
        <CyberInput
          id="resolver-target-id"
          mono
          value={targetId}
          onChange={(e) => setTargetId(e.target.value.trim())}
          placeholder="execution target uuid"
        />
        {authorizations.loading && !authorizations.data && <Skeleton lines={2} />}
        {authorizations.error && (
          <div className="error-box">Authorizations could not be loaded.</div>
        )}
        {targetId && authList && authList.length === 0 && !authorizations.loading && (
          <EmptyState title="No resolver-activation authorizations">
            None recorded for this target. Nothing here is sealed by error — a
            sealed resolver is the shipped default.
          </EmptyState>
        )}
        {(authList ?? []).map((auth) => (
          <AuthorizationCard
            key={auth.id}
            auth={auth}
            onChange={() => authorizations.reload()}
          />
        ))}
      </CyberCard>
    </div>
  );
}
