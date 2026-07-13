// OIDC orchestration seam + pure helpers (ADR-018 / OIDC-B).
//
// The React AuthProvider drives a real oidc-client-ts `UserManager`, but the security-relevant
// decisions are pure and testable in the node test env through this narrow `OidcClient` interface
// (a structural subset of `UserManager`, satisfiable by a fake).

import { ApiClientError } from "../api/client";
import { AuthConfigError } from "./config";
import type { AuthErrorCategory } from "./types";

/** A structural subset of oidc-client-ts `User` (access_token + expiry + custom state). */
export interface OidcUser {
  access_token: string;
  id_token?: string;
  expired?: boolean;
  expires_at?: number;
  /** The custom state we attached at signinRedirect (carries the sanitized return path). */
  state?: unknown;
}

/** Extract the sanitized return path carried through the OIDC `state`, defaulting to "/". */
export function returnPathFromState(state: unknown, sanitize: (raw: unknown) => string): string {
  if (state !== null && typeof state === "object" && "returnTo" in state) {
    return sanitize((state as { returnTo?: unknown }).returnTo);
  }
  return sanitize(undefined);
}

/** A structural subset of oidc-client-ts `UserManager` — enough to orchestrate the flow. */
export interface OidcClient {
  signinRedirect(args?: { state?: unknown }): Promise<void>;
  signinRedirectCallback(url?: string): Promise<OidcUser>;
  signoutRedirect(args?: { id_token_hint?: string }): Promise<void>;
  getUser(): Promise<OidcUser | null>;
  removeUser(): Promise<void>;
}

/** The current access token, or null when there is no user or it has expired. Never returns an
 *  expired token — access-token expiry requires a fresh interactive login (no silent renewal). */
export function accessTokenOf(user: OidcUser | null): string | null {
  if (!user || user.expired) return null;
  return typeof user.access_token === "string" && user.access_token.length > 0
    ? user.access_token
    : null;
}

/**
 * A minimal, refresh-token-free projection of the OIDC user that SECP retains (ADR-018). Explicitly
 * copies ONLY the fields the app uses — the access token (for API calls), the id token (only as the
 * logout hint), expiry, and the round-tripped `state` — so a `refresh_token` from the provider
 * response is never carried into application/controller state, context, or logs.
 */
export function projectUser(user: OidcUser | null): OidcUser | null {
  if (!user) return null;
  return {
    access_token: user.access_token,
    id_token: user.id_token,
    expired: user.expired,
    expires_at: user.expires_at,
    state: user.state,
  };
}

/** Resolve the stored session user (refresh-token-free projection), treating an expired user as
 *  absent. The stored value is already refresh-token-sanitized by the user store; projecting here is
 *  defense in depth for the in-memory copy. */
export async function resolveUser(client: OidcClient): Promise<OidcUser | null> {
  const user = await client.getUser();
  return user && !user.expired ? projectUser(user) : null;
}

/**
 * Map any authentication failure to a bounded, content-free category. Never inspects or returns a
 * token, claim, provider body, or raw library message.
 */
export function authErrorCategory(err: unknown): AuthErrorCategory {
  if (err instanceof AuthConfigError) return "configuration_invalid";
  if (err instanceof ApiClientError) {
    if (err.status === 401) return "session_expired";
    if (err.status === 503 || err.code === "authentication_unavailable") {
      return "authentication_unavailable";
    }
    if (err.status === 0 || err.code === "api_unreachable") return "authentication_unavailable";
  }
  return "callback_invalid";
}
