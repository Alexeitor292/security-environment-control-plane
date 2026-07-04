import { useState } from "react";

import { ApiClientError, api } from "../api/client";
import type { PreflightSubstrate, ReadonlyPreflight } from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";
import {
  AUTHORIZATION_SEPARATION_NOTICE,
  GENERIC_API_ERROR_TEXT,
  QUEUED_NOTICE,
  READONLY_ONLY_LABEL,
  READY_SCOPE_NOTICE,
  apiErrorText,
  canQueuePreflight,
  isQueuedOrRunning,
  outcomeLabel,
  readinessFactRows,
  usableAuthorization,
} from "./readonly-preflight";

/** Map any thrown error to FIXED safe text from the closed error code — never a backend message. */
function safeErrorText(e: unknown): string {
  if (e instanceof ApiClientError) return apiErrorText(e.code);
  return GENERIC_API_ERROR_TEXT;
}

function SafetyBanner() {
  return (
    <div className="dev-banner" role="note">
      {READONLY_ONLY_LABEL}
    </div>
  );
}

function SubstratePanel({ substrate }: { substrate: PreflightSubstrate }) {
  const auths = useAsync(() => api.listPreflightAuthorizations(substrate.id), [substrate.id]);
  const preflights = useAsync(() => api.listReadonlyPreflights(substrate.id), [substrate.id]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const usable = usableAuthorization(auths.data ?? []);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      auths.reload();
      preflights.reload();
    } catch (e) {
      setError(safeErrorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <header className="row">
        <h3 className="mono">{substrate.alias}</h3>
      </header>
      <SafetyBanner />
      <p className="muted">{AUTHORIZATION_SEPARATION_NOTICE}</p>

      <div className="actions">
        <button
          disabled={busy}
          onClick={() => run(() => api.createPreflightAuthorization(substrate.id))}
          title="Create a short-lived read-only authorization (draft)"
        >
          Create read-only authorization
        </button>
        {(auths.data ?? [])
          .filter((a) => a.status === "draft")
          .map((a) => (
            <button
              key={a.id}
              disabled={busy}
              onClick={() => run(() => api.approvePreflightAuthorization(a.id))}
            >
              Approve authorization
            </button>
          ))}
        {(auths.data ?? [])
          .filter((a) => a.status === "approved")
          .map((a) => (
            <button
              key={a.id}
              disabled={busy}
              onClick={() => run(() => api.revokePreflightAuthorization(a.id))}
            >
              Revoke authorization
            </button>
          ))}
        <button
          disabled={busy || !canQueuePreflight(usable)}
          onClick={() => run(() => api.queueReadonlyPreflight(usable!.id))}
          title={READONLY_ONLY_LABEL}
        >
          Read-Only Staging Preflight
        </button>
      </div>
      {error && <div className="error">{error}</div>}

      <h4>Preflights</h4>
      {(preflights.data ?? []).length === 0 && <p className="muted">No preflights yet.</p>}
      {(preflights.data ?? []).map((pf: ReadonlyPreflight) => (
        <div key={pf.id} className="row">
          <StatusBadge state={pf.status} />
          <span className="mono">{outcomeLabel(pf.outcome_code)}</span>
          {isQueuedOrRunning(pf.status) && <span className="muted">{QUEUED_NOTICE}</span>}
          {pf.outcome_code === "ready" && (
            <div>
              <p className="muted">{READY_SCOPE_NOTICE}</p>
              <ul>
                {readinessFactRows(pf).map((r) => (
                  <li key={r.key} className="mono">
                    {r.key}: {r.value}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ))}
    </section>
  );
}

export function ReadonlyPreflight() {
  const substrates = useAsync(() => api.preflightSubstrates(), []);
  return (
    <div className="page">
      <h1>Read-Only Staging Preflight</h1>
      <p className="muted">
        On an eligible Proxmox staging substrate, create + approve a short-lived read-only
        authorization, then queue a preflight. {READONLY_ONLY_LABEL}
      </p>
      {substrates.loading && <div>Loading…</div>}
      {substrates.error && <div className="error">{substrates.error}</div>}
      {(substrates.data ?? []).length === 0 && !substrates.loading && (
        <p className="muted">No eligible staging substrates.</p>
      )}
      {(substrates.data ?? []).map((s) => (
        <SubstratePanel key={s.id} substrate={s} />
      ))}
    </div>
  );
}
