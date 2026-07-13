// Narrow seam between the auth layer and the single API-client fetch core (ADR-018 / OIDC-B).
//
// The API client must attach `Authorization: Bearer <access-token>` to protected SECP API requests
// in OIDC mode, and MUST NOT in dev-fallback mode (no token) or on the public auth-config request.
// Rather than couple the client to React/oidc-client-ts, the auth layer registers a token *getter*
// here; the client reads it. No token is stored in this module — only a getter reference — and
// nothing is persisted. On an API 401 the client notifies the registered handler so the auth layer
// can clear the session and require a fresh interactive login.

type AccessTokenProvider = () => string | null;

let accessTokenProvider: AccessTokenProvider = () => null; // default: no bearer (dev fallback / anon)
let unauthorizedHandler: (() => void) | null = null;

/** Register the current access-token getter (OIDC mode). Returns null once the token is absent or
 *  expired, which suppresses the bearer header. */
export function setAccessTokenProvider(provider: AccessTokenProvider): void {
  accessTokenProvider = provider;
}

/** Remove the token getter (dev-fallback mode or logout) so requests carry no bearer. */
export function clearAccessTokenProvider(): void {
  accessTokenProvider = () => null;
}

/** The current access token, or null. Consumed only by the API-client fetch core. */
export function currentAccessToken(): string | null {
  return accessTokenProvider();
}

/** Register a handler invoked when a protected API request returns 401 (session expired/invalid). */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

/** Invoked by the API client on a 401. Idempotent from the client's perspective. */
export function notifyUnauthorized(): void {
  if (unauthorizedHandler) unauthorizedHandler();
}
