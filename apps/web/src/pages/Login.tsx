// Sign-in page (ADR-018 / OIDC-B). Truthfully represents the active authentication mode: real SSO
// (Authorization Code + PKCE) in OIDC mode, or the clearly-labeled development fallback locally. It
// shows NO issuer internals, client id, token, claim, or backend error — only bounded, safe copy.

import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import type { AuthMode } from "../api/types";
import { AuthLoading } from "../auth/AuthLoading";
import { useAuth } from "../auth/AuthProvider";
import { authErrorCopy } from "../auth/errorCopy";
import { sanitizeReturnPath } from "../auth/session";

/** Pure presentational sign-in view (no context) — statically testable per the repo convention. */
export function LoginView({
  mode,
  errorText,
  busy,
  onOidcSignin,
  onDevContinue,
}: {
  mode: AuthMode;
  errorText: string | null;
  busy: boolean;
  onOidcSignin: () => void;
  onDevContinue: () => void;
}) {
  return (
    <div className="layout">
      <main className="content" style={{ maxWidth: 480, margin: "10vh auto" }}>
        <div className="panel">
          <h2>Sign in</h2>
          {mode === "dev_fallback" ? (
            <>
              <div className="error-box">
                Development only — this is not production authentication.
              </div>
              <p className="muted">
                In local development the API authenticates you as the seeded dev-admin principal (no
                token is issued).
              </p>
              {errorText && (
                <div className="error-box" role="alert">
                  {errorText}
                </div>
              )}
              <button disabled={busy} onClick={onDevContinue}>
                Continue as dev-admin
              </button>
            </>
          ) : (
            <>
              <p className="muted">
                Your identity is verified by your organization&rsquo;s single sign-on provider.
              </p>
              {errorText && (
                <div className="error-box" role="alert">
                  {errorText}
                </div>
              )}
              <button disabled={busy} onClick={onOidcSignin}>
                {busy ? "Redirecting…" : "Sign in with SSO"}
              </button>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export function Login() {
  const { status, mode, login, continueAsDevFallback, error } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);

  const returnTo = sanitizeReturnPath((location.state as { from?: unknown } | null)?.from);

  // An authenticated user visiting /login is sent to their sanitized destination.
  useEffect(() => {
    if (status === "authenticated") navigate(returnTo, { replace: true });
  }, [status, returnTo, navigate]);

  if (status === "initializing") return <AuthLoading label="Checking your session…" />;

  return (
    <LoginView
      mode={mode ?? "oidc"}
      errorText={authErrorCopy(error)}
      busy={busy}
      onOidcSignin={() => {
        setBusy(true);
        login(returnTo);
      }}
      onDevContinue={() => {
        setBusy(true);
        void continueAsDevFallback();
      }}
    />
  );
}
