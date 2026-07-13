// Build the oidc-client-ts settings for the PUBLIC browser Authorization Code + PKCE (S256) flow
// (ADR-018 / OIDC-B). Pure and deterministic given (config, origin, store).
//
// oidc-client-ts performs Authorization Code with PKCE **S256** whenever `response_type` is `code`
// (there is no plain-PKCE or implicit/hybrid path here). There is NO `client_secret` (a public
// client has none), NO `offline_access` (the scope is server-owned), NO automatic silent renewal in
// this slice, and storage is session-scoped only.

import { WebStorageStateStore, type UserManagerSettings } from "oidc-client-ts";

import type { AuthConfig } from "../api/types";
import { SanitizingUserStore } from "./userStore";

export function buildUserManagerSettings(
  config: AuthConfig,
  origin: string,
  store: Storage,
): UserManagerSettings {
  return {
    authority: config.issuer,
    client_id: config.client_id,
    redirect_uri: `${origin}${config.redirect_path}`,
    post_logout_redirect_uri: `${origin}${config.post_logout_redirect_path}`,
    response_type: "code", // Authorization Code — never token/id_token (implicit/hybrid)
    scope: config.scope, // server-owned "openid profile email"; excludes offline_access
    loadUserInfo: false, // /api/v1/me is authoritative for identity; never derive from claims
    automaticSilentRenew: false, // no silent renewal in this slice
    monitorSession: false,
    filterProtocolClaims: true,
    // Session-scoped stores only (survive the redirect round-trip; cleared with the tab/session).
    // The USER store strips refresh tokens before persisting (ADR-018); the transaction STATE store
    // (PKCE verifier / state / nonce) is a plain session store and stays separate + functional.
    userStore: new SanitizingUserStore(store),
    stateStore: new WebStorageStateStore({ store }),
  };
}
