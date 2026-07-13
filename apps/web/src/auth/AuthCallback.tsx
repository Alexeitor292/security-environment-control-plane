// OIDC redirect callback route (ADR-018 / OIDC-B). Processes exactly ONE authorization callback (the
// OIDC library validates state + nonce and completes the PKCE code exchange), then navigates with
// `replace` to the sanitized return path — removing the code/state query parameters from history.
// Any failure (invalid/replayed callback, token error, /api/v1/me failure) falls closed to /login.

import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

import { AuthLoading } from "./AuthLoading";
import { useAuth } from "./AuthProvider";

export function AuthCallback() {
  const { completeCallback } = useAuth();
  const navigate = useNavigate();
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return; // process the callback exactly once (guards against replay/StrictMode)
    ran.current = true;
    let active = true;
    void (async () => {
      const target = await completeCallback();
      if (!active) return;
      navigate(target ?? "/login", { replace: true });
    })();
    return () => {
      active = false;
    };
  }, [completeCallback, navigate]);

  return <AuthLoading label="Completing sign-in…" />;
}
