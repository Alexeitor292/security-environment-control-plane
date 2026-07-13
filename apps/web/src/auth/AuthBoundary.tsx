// Route guard (ADR-018 / OIDC-B). Renders protected children ONLY when authenticated; while
// authentication is resolving it shows a safe status screen (so no protected content and no domain
// API calls occur before auth is established); when unauthenticated it redirects to /login, carrying
// the attempted (sanitized) path via router state so a successful login can return there.

import type { ReactNode } from "react";
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { AuthLoading } from "./AuthLoading";
import { useAuth } from "./AuthProvider";
import { sanitizeReturnPath } from "./session";

export function AuthBoundary({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (status === "unauthenticated" || status === "error") {
      const from = sanitizeReturnPath(location.pathname + location.search);
      navigate("/login", { replace: true, state: { from } });
    }
  }, [status, location.pathname, location.search, navigate]);

  if (status === "authenticated") return <>{children}</>;
  return (
    <AuthLoading
      label={status === "initializing" ? "Checking your session…" : "Redirecting to sign-in…"}
    />
  );
}
