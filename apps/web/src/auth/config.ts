// Fetch + fail-closed validation of the public browser auth configuration (ADR-018 / OIDC-B).

import { api } from "../api/client";
import type { AuthConfig, AuthMode } from "../api/types";

const MODES: readonly AuthMode[] = ["dev_fallback", "oidc"];

// Keys that must NEVER appear in the public config. If the server (or a tampered response) ever
// includes anything secret-shaped, we reject the whole config rather than render or use it.
const FORBIDDEN_KEY_SUBSTRINGS = [
  "secret",
  "password",
  "token",
  "private",
  "certificate",
  "credential",
];

export class AuthConfigError extends Error {
  constructor() {
    super("configuration_invalid");
    this.name = "AuthConfigError";
  }
}

function requireString(value: unknown, { maxLen = 2048 } = {}): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLen) {
    throw new AuthConfigError();
  }
  return value;
}

function requireRelativePath(value: unknown): string {
  const path = requireString(value, { maxLen: 512 });
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("://")) {
    throw new AuthConfigError();
  }
  return path;
}

/**
 * Validate an untrusted auth-config object, failing closed (AuthConfigError → "configuration_invalid")
 * on any structural problem, any secret-shaped key, or a scope that requests offline_access. Returns
 * a typed AuthConfig on success. Never mutates and never logs the input.
 */
export function validateAuthConfig(raw: unknown): AuthConfig {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AuthConfigError();
  }
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    const lowered = key.toLowerCase();
    if (FORBIDDEN_KEY_SUBSTRINGS.some((needle) => lowered.includes(needle))) {
      throw new AuthConfigError();
    }
  }
  const mode = obj.mode;
  if (typeof mode !== "string" || !MODES.includes(mode as AuthMode)) {
    throw new AuthConfigError();
  }
  const scope = requireString(obj.scope);
  if (scope.split(/\s+/).includes("offline_access")) {
    throw new AuthConfigError(); // this slice never requests a long-lived refresh session
  }
  return {
    mode: mode as AuthMode,
    issuer: requireString(obj.issuer),
    client_id: requireString(obj.client_id),
    audience: requireString(obj.audience),
    scope,
    redirect_path: requireRelativePath(obj.redirect_path),
    post_logout_redirect_path: requireRelativePath(obj.post_logout_redirect_path),
  };
}

/** Fetch the public auth config (no Authorization header) and validate it fail-closed. */
export async function loadAuthConfig(): Promise<AuthConfig> {
  return validateAuthConfig(await api.authConfig());
}
