// Frontend-only authentication state types (ADR-018 / OIDC-B). API response types (AuthConfig,
// AuthMode, Principal) live in ../api/types.

import type { AuthConfig, AuthMode, Principal } from "../api/types";

export type { AuthConfig, AuthMode };

export type AuthStatus = "initializing" | "unauthenticated" | "authenticated" | "error";

// Bounded, content-free error categories surfaced to the UI. Never a token/claim/provider detail.
export type AuthErrorCategory =
  | "authentication_required"
  | "callback_invalid"
  | "authentication_unavailable"
  | "session_expired"
  | "configuration_invalid";

export interface AuthContextValue {
  status: AuthStatus;
  mode: AuthMode | null;
  /** The DB-backed identity from /api/v1/me — the ONLY authority for shell/user/permission display.
   *  Never derived from token claims. */
  principal: Principal | null;
  error: AuthErrorCategory | null;
  /** Begin an interactive OIDC Authorization Code + PKCE login (full-page redirect). The optional
   *  return path is sanitized and carried through the OIDC `state` so it survives the redirect. */
  login: (returnTo?: string) => void;
  /** Dev-fallback only: activate the seeded dev principal (no token). */
  continueAsDevFallback: () => Promise<void>;
  /** Complete the authorization callback exactly once. Resolves the sanitized return path on
   *  success, or null on any failure (state/nonce/PKCE/token/me error) — fails closed. */
  completeCallback: () => Promise<string | null>;
  /** Clear local session and (OIDC) invoke the provider end-session endpoint when available. */
  logout: () => Promise<void>;
}
