// Refresh-token-free OIDC user store (ADR-018 / OIDC-B).
//
// oidc-client-ts serializes `refresh_token` into the persisted User whenever the provider returns one
// — and a normal authorization-code response MAY include a refresh token even without
// `offline_access`. SECP does not retain or use browser refresh tokens in this slice, so this
// sessionStorage-backed store strips `refresh_token` from any User value BEFORE it is persisted and
// re-sanitizes (or clears) any legacy/stale stored value on read. It wraps a standard
// WebStorageStateStore (no global monkey-patching) and leaves the OIDC authorization transaction
// state store separate and functional. It never logs or copies the original value.

import { WebStorageStateStore, type StateStore } from "oidc-client-ts";

const REFRESH_TOKEN_KEY = "refresh_token";

/**
 * Remove `refresh_token` from an oidc-client-ts User storage string (JSON). Preserves every other
 * field (access_token, id_token, expires_at, token_type, scope, profile, session_state). Fails
 * closed to "" on malformed input — it never returns, logs, or copies the original value.
 */
export function stripRefreshToken(value: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return ""; // malformed -> fail closed (persist no user)
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return "";
  }
  const record = parsed as Record<string, unknown>;
  if (REFRESH_TOKEN_KEY in record) delete record[REFRESH_TOKEN_KEY];
  return JSON.stringify(record);
}

export class SanitizingUserStore implements StateStore {
  private readonly inner: WebStorageStateStore;

  constructor(store: Storage) {
    this.inner = new WebStorageStateStore({ store });
  }

  async set(key: string, value: string): Promise<void> {
    const sanitized = stripRefreshToken(value);
    if (sanitized === "") {
      // Never persist an unsanitizable/malformed user (fail closed) — and never write the raw value.
      await this.inner.remove(key);
      return;
    }
    await this.inner.set(key, sanitized);
  }

  async get(key: string): Promise<string | null> {
    const raw = await this.inner.get(key);
    if (raw === null) return null;
    const sanitized = stripRefreshToken(raw);
    if (sanitized === "") {
      // A legacy/malformed stored user -> clear it and report no user (fail closed).
      await this.inner.remove(key);
      return null;
    }
    if (sanitized !== raw) {
      // A legacy stored user that still carried a refresh_token -> rewrite it in sanitized form.
      await this.inner.set(key, sanitized);
    }
    return sanitized;
  }

  async remove(key: string): Promise<string | null> {
    return this.inner.remove(key);
  }

  async getAllKeys(): Promise<string[]> {
    return this.inner.getAllKeys();
  }
}
