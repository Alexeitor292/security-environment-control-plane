import "./readonly-ops.css";

import { api } from "../api/client";
import type { PreflightSubstrate } from "../api/types";
import {
  CyberButton,
  CyberCard,
  EmptyState,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  useAction,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  CREDENTIAL_UNAVAILABLE_NOTICE,
  QUEUE_CREATES_NO_EVIDENCE_NOTICE,
  READONLY_COMMON_CODES,
  preflightAuthorizationView,
  preflightHistoryRows,
} from "./readonly-ops";
import {
  API_ERROR_TEXT,
  AUTHORIZATION_SEPARATION_NOTICE,
  QUEUED_NOTICE,
  READONLY_ONLY_LABEL,
  READY_SCOPE_NOTICE,
  canQueuePreflight,
  readinessFactRows,
  usableAuthorization,
} from "./readonly-preflight";

const PREFLIGHT_CODES = { ...READONLY_COMMON_CODES, ...API_ERROR_TEXT };

function SubstratePanel({ substrate }: { substrate: PreflightSubstrate }) {
  const auths = useAsync(() => api.listPreflightAuthorizations(substrate.id), [substrate.id]);
  const preflights = useAsync(() => api.listReadonlyPreflights(substrate.id), [substrate.id]);
  const action = useAction({ codeText: PREFLIGHT_CODES });

  const authList = auths.data ?? null;
  const usable = usableAuthorization(authList ?? []);
  const rows = preflightHistoryRows(preflights.data ?? null);

  const run = (fn: () => Promise<unknown>) =>
    action.run(fn, () => {
      auths.reload();
      preflights.reload();
    });

  return (
    <CyberCard>
      <div className="rops-detail-head">
        <div>
          <h3 className="mono">{substrate.alias}</h3>
          <div className="rops-sub">Eligible Proxmox staging substrate</div>
        </div>
      </div>
      <SafetyNotice role="note" tone="warn">
        {READONLY_ONLY_LABEL}
      </SafetyNotice>

      <div className="rops-grid">
        <CyberCard surface="well" heading="Authorization posture">
          <p className="rops-note">{AUTHORIZATION_SEPARATION_NOTICE}</p>
          {auths.loading && !auths.data ? (
            <Skeleton lines={3} />
          ) : authList === null ? (
            <p className="muted">Authorizations unavailable.</p>
          ) : authList.length === 0 ? (
            <EmptyState title="No authorization yet">
              Create a short-lived read-only authorization to permit queueing a
              GET-only preflight.
            </EmptyState>
          ) : (
            authList.map((a) => {
              const view = preflightAuthorizationView(a);
              return (
                <div key={a.id} style={{ marginBottom: 10 }}>
                  <KeyValueList
                    items={[
                      {
                        key: "State",
                        value: (
                          <span className="rops-expiry">
                            {/* Computed state, not raw status: a short-lived
                                authz can stay status=approved past expiry —
                                the badge must read "expired" (danger), not
                                a green "approved". */}
                            <StatusBadge state={view.state} domain="authorization" />
                            <span className="muted">{view.stateLabel}</span>
                          </span>
                        ),
                      },
                      { key: "Version", value: view.versionLabel },
                      { key: "Scope", value: view.scope },
                      {
                        key: "Expiry",
                        value:
                          view.state === "approved"
                            ? `in ${view.remainingMinutes} min · ${new Date(view.expiry).toLocaleTimeString()}`
                            : new Date(view.expiry).toLocaleString(),
                      },
                      ...(a.approved_at
                        ? [{ key: "Approved", value: new Date(a.approved_at).toLocaleString() }]
                        : []),
                    ]}
                  />
                </div>
              );
            })
          )}
        </CyberCard>

        <CyberCard surface="well" heading="Actions">
          <div className="rops-actions" style={{ marginTop: 0, borderTop: "none", paddingTop: 0 }}>
            <CyberButton
              variant="secondary"
              size="sm"
              disabled={action.busy}
              onClick={() => run(() => api.createPreflightAuthorization(substrate.id))}
            >
              Create read-only authorization
            </CyberButton>
            {(authList ?? [])
              .filter((a) => a.status === "draft")
              .map((a) => (
                <CyberButton
                  key={a.id}
                  variant="ok"
                  size="sm"
                  disabled={action.busy}
                  onClick={() => run(() => api.approvePreflightAuthorization(a.id))}
                >
                  Approve authorization
                </CyberButton>
              ))}
            {(authList ?? [])
              .filter((a) => a.status === "approved")
              .map((a) => (
                <CyberButton
                  key={a.id}
                  variant="danger"
                  size="sm"
                  disabled={action.busy}
                  onClick={() => run(() => api.revokePreflightAuthorization(a.id))}
                >
                  Revoke authorization
                </CyberButton>
              ))}
            <CyberButton
              variant="secondary"
              size="sm"
              disabled={action.busy || !canQueuePreflight(usable)}
              title={
                canQueuePreflight(usable)
                  ? READONLY_ONLY_LABEL
                  : "Requires an approved, unexpired read-only authorization."
              }
              onClick={() => run(() => api.queueReadonlyPreflight(usable!.id))}
            >
              Queue read-only preflight
            </CyberButton>
          </div>
          <p className="rops-note">{QUEUE_CREATES_NO_EVIDENCE_NOTICE}</p>
        </CyberCard>
      </div>

      {action.error && (
        <div className="error-box" role="alert" style={{ marginTop: 10 }}>
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}

      <CyberCard surface="well" heading="Preflight queue & history" style={{ marginTop: 12 }}>
        {preflights.loading && !preflights.data ? (
          <Skeleton lines={3} />
        ) : preflights.data === null ? (
          <p className="muted">Preflight history unavailable.</p>
        ) : rows.length === 0 ? (
          <EmptyState title="No preflights recorded">
            Queueing a preflight asks a worker to verify the authorization and run
            only approved GET-only reads. It records no readiness evidence by itself.
          </EmptyState>
        ) : (
          <ul className="rops-history">
            {rows.map((row) => {
              const pf = preflights.data!.find((p) => p.id === row.id)!;
              return (
                <li className="rops-history__row" key={row.id}>
                  <div className="rops-history__head">
                    <StatusBadge state={row.status} domain="preflight" />
                    {pf.outcome_code ? (
                      <StatusBadge state={pf.outcome_code} domain="preflight-outcome" />
                    ) : (
                      <span className="muted">{row.outcome}</span>
                    )}
                    {row.workerOwned && (
                      <span className="badge accent">worker-owned</span>
                    )}
                    <span className="rops-history__time mono">
                      {row.createdAt.slice(0, 19).replace("T", " ")} UTC
                    </span>
                  </div>
                  {row.workerOwned && (
                    <p className="rops-history__note">{QUEUED_NOTICE}</p>
                  )}
                  {row.expectedSealed && (
                    <p className="rops-history__note">{CREDENTIAL_UNAVAILABLE_NOTICE}</p>
                  )}
                  {row.ready && (
                    <>
                      <p className="rops-history__note">{READY_SCOPE_NOTICE}</p>
                      <ul className="rops-facts">
                        {readinessFactRows(pf).map((r) => (
                          <li key={r.key} className="mono">
                            {r.key}: {r.value}
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </CyberCard>
    </CyberCard>
  );
}

export function ReadonlyPreflight() {
  const substrates = useAsync(() => api.preflightSubstrates(), []);
  return (
    <div className="rops">
      <div className="rops-head">
        <h1>Read-Only Staging Preflight</h1>
        <p className="rops-intro">
          On an eligible Proxmox staging substrate, create and approve a short-lived
          read-only authorization, then queue a preflight. {READONLY_ONLY_LABEL}
        </p>
      </div>
      {substrates.loading && !substrates.data && <Skeleton lines={4} />}
      {substrates.error && (
        <div className="error-box">Eligible substrates could not be loaded.</div>
      )}
      {substrates.data && substrates.data.length === 0 && (
        <EmptyState title="No eligible staging substrates">
          A substrate becomes eligible after its target is onboarded and granted
          staging-substrate eligibility.
        </EmptyState>
      )}
      {(substrates.data ?? []).map((s) => (
        <SubstratePanel key={s.id} substrate={s} />
      ))}
    </div>
  );
}
