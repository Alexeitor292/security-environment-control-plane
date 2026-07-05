import { useState } from "react";

import { ApiClientError, api } from "../api/client";
import type { ResolverActivation as Authorization } from "../api/types";
import { StatusBadge } from "../components/StatusBadge";
import { useAsync } from "../hooks";
import {
  GENERIC_API_ERROR_TEXT,
  RESOLVER_ACTIVATION_SCOPE_NOTICE,
  RESOLVER_ACTIVATION_SEALED_NOTICE,
  apiErrorText,
  evidenceSummary,
  statusLabel,
} from "./resolver-activation";

/** Map any thrown error to FIXED safe text from the closed error code — never a backend message. */
function safeErrorText(e: unknown): string {
  if (e instanceof ApiClientError) return apiErrorText(e.code);
  return GENERIC_API_ERROR_TEXT;
}

function AuthorizationCard({ auth, onChange }: { auth: Authorization; onChange: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const summary = evidenceSummary(auth);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChange();
    } catch (e) {
      setError(safeErrorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="row">
      <StatusBadge state={auth.status} />
      <span className="mono">{statusLabel(auth.status)}</span>
      <span className="muted">
        evidence {summary.verified}/{summary.total} verified · v{auth.authorization_version}
      </span>
      {auth.status === "draft" && (
        <button disabled={busy} onClick={() => run(() => api.approveResolverActivation(auth.id))}>
          Approve (separate permission)
        </button>
      )}
      {(auth.status === "draft" || auth.status === "approved") && (
        <button disabled={busy} onClick={() => run(() => api.revokeResolverActivation(auth.id))}>
          Revoke
        </button>
      )}
      {auth.status === "approved" && <span className="muted">Sealed — not active</span>}
      {error && <div className="error">{error}</div>}
    </div>
  );
}

export function ResolverActivation() {
  const [targetId, setTargetId] = useState("");
  const authorizations = useAsync<Authorization[]>(
    () => (targetId ? api.listResolverActivations(targetId) : Promise.resolve([])),
    [targetId],
  );

  return (
    <div className="page">
      <h1>Resolver Activation Authorization</h1>
      <div className="dev-banner" role="note">
        {RESOLVER_ACTIVATION_SEALED_NOTICE}
      </div>
      <p className="muted">{RESOLVER_ACTIVATION_SCOPE_NOTICE}</p>

      <label className="row">
        Execution target id:
        <input
          className="mono"
          value={targetId}
          onChange={(e) => setTargetId(e.target.value.trim())}
          placeholder="execution target uuid"
        />
      </label>

      {authorizations.loading && <div>Loading…</div>}
      {authorizations.error && <div className="error">{authorizations.error}</div>}
      {(authorizations.data ?? []).length === 0 && !authorizations.loading && (
        <p className="muted">No resolver-activation authorizations for this target.</p>
      )}
      {(authorizations.data ?? []).map((auth) => (
        <AuthorizationCard key={auth.id} auth={auth} onChange={() => authorizations.reload()} />
      ))}
    </div>
  );
}
