// Framework-agnostic authentication controller (ADR-018 / OIDC-B).
//
// Holds the entire browser-auth state machine with every side effect injected, so it is fully unit-
// testable in the repo's node test environment (no jsdom) with fakes. The React AuthProvider is a
// thin adapter over this. Identity always comes from the authoritative fetchMe (/api/v1/me), never
// from a token claim; no token is stored here beyond the getter registered with the API client.

import type { Principal } from "../api/types";
import type { OidcClient, OidcUser } from "./oidc";
import {
  accessTokenOf,
  authErrorCategory,
  projectUser,
  resolveUser,
  returnPathFromState,
} from "./oidc";
import { sanitizeReturnPath } from "./session";
import type { AuthConfig, AuthErrorCategory, AuthMode, AuthStatus } from "./types";

export interface AuthSnapshot {
  status: AuthStatus;
  mode: AuthMode | null;
  principal: Principal | null;
  error: AuthErrorCategory | null;
}

export interface AuthControllerDeps {
  loadConfig: () => Promise<AuthConfig>;
  /** Build the OIDC client for the resolved config (real: new UserManager(...); fake in tests). */
  createOidcClient: (config: AuthConfig) => OidcClient;
  /** Fetch the authoritative DB-backed identity (/api/v1/me). */
  fetchMe: () => Promise<Principal>;
  session: {
    isDevFallbackActive: () => boolean;
    setDevFallbackActive: (active: boolean) => void;
    clear: () => void;
  };
  tokenSeam: {
    setAccessTokenProvider: (provider: () => string | null) => void;
    clearAccessTokenProvider: () => void;
    setUnauthorizedHandler: (handler: (() => void) | null) => void;
  };
}

const INITIAL: AuthSnapshot = {
  status: "initializing",
  mode: null,
  principal: null,
  error: null,
};

export class AuthController {
  private snapshot: AuthSnapshot = INITIAL;
  private readonly listeners = new Set<() => void>();
  private client: OidcClient | null = null;
  private user: OidcUser | null = null;

  constructor(private readonly deps: AuthControllerDeps) {}

  getSnapshot = (): AuthSnapshot => this.snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  private set(next: AuthSnapshot): void {
    this.snapshot = next;
    for (const listener of this.listeners) listener();
  }

  // A protected API request returned 401: clear the session (never auto-replay the request).
  private onUnauthorized = (): void => {
    this.user = null;
    if (this.client) void this.client.removeUser().catch(() => {});
    this.deps.session.setDevFallbackActive(false);
    if (this.snapshot.status === "authenticated") {
      this.set({
        ...this.snapshot,
        status: "unauthenticated",
        principal: null,
        error: "session_expired",
      });
    }
  };

  /** Resolve the public config, wire the API-client seam, and establish the current session. */
  async init(): Promise<void> {
    this.deps.tokenSeam.setUnauthorizedHandler(this.onUnauthorized);
    let config: AuthConfig;
    try {
      config = await this.deps.loadConfig();
    } catch {
      this.set({ status: "error", mode: null, principal: null, error: "configuration_invalid" });
      return;
    }

    if (config.mode === "oidc") {
      let client: OidcClient;
      try {
        client = this.deps.createOidcClient(config);
      } catch {
        this.set({ status: "error", mode: "oidc", principal: null, error: "configuration_invalid" });
        return;
      }
      this.client = client;
      this.deps.tokenSeam.setAccessTokenProvider(() => accessTokenOf(this.user));
      try {
        const user = await resolveUser(client);
        this.user = user;
        if (user) {
          const principal = await this.deps.fetchMe();
          this.set({ status: "authenticated", mode: "oidc", principal, error: null });
        } else {
          this.set({ status: "unauthenticated", mode: "oidc", principal: null, error: null });
        }
      } catch {
        this.user = null;
        await client.removeUser().catch(() => {});
        this.set({ status: "unauthenticated", mode: "oidc", principal: null, error: null });
      }
    } else {
      // dev_fallback: no token; the backend authenticates a no-Authorization request.
      this.deps.tokenSeam.clearAccessTokenProvider();
      if (this.deps.session.isDevFallbackActive()) {
        try {
          const principal = await this.deps.fetchMe();
          this.set({ status: "authenticated", mode: "dev_fallback", principal, error: null });
        } catch {
          this.deps.session.setDevFallbackActive(false);
          this.set({
            status: "unauthenticated",
            mode: "dev_fallback",
            principal: null,
            error: null,
          });
        }
      } else {
        this.set({
          status: "unauthenticated",
          mode: "dev_fallback",
          principal: null,
          error: null,
        });
      }
    }
  }

  login(returnTo?: string): void {
    if (!this.client) return;
    void this.client
      .signinRedirect({ state: { returnTo: sanitizeReturnPath(returnTo) } })
      .catch(() => {
        this.set({ ...this.snapshot, error: "authentication_unavailable" });
      });
  }

  async continueAsDevFallback(): Promise<void> {
    this.deps.session.setDevFallbackActive(true);
    try {
      const principal = await this.deps.fetchMe();
      this.set({ status: "authenticated", mode: "dev_fallback", principal, error: null });
    } catch {
      this.deps.session.setDevFallbackActive(false);
      this.set({
        ...this.snapshot,
        status: "unauthenticated",
        principal: null,
        error: "authentication_required",
      });
    }
  }

  async completeCallback(): Promise<string | null> {
    const client = this.client;
    if (!client) {
      this.set({ ...this.snapshot, status: "error", error: "callback_invalid" });
      return null;
    }
    try {
      const user = await client.signinRedirectCallback(); // validates state + nonce + PKCE
      // Immediately discard the refresh_token (and anything else) by retaining only the projection.
      const projected = projectUser(user);
      this.user = projected;
      const principal = await this.deps.fetchMe();
      this.set({ status: "authenticated", mode: "oidc", principal, error: null });
      return returnPathFromState(projected?.state ?? null, sanitizeReturnPath);
    } catch (err) {
      this.user = null;
      await client.removeUser().catch(() => {});
      this.set({
        status: "unauthenticated",
        mode: "oidc",
        principal: null,
        error: authErrorCategory(err),
      });
      return null;
    }
  }

  async logout(): Promise<{ redirected: boolean }> {
    const client = this.client;
    this.user = null;
    this.deps.session.clear();
    this.deps.session.setDevFallbackActive(false);
    // Emit unauthenticated BEFORE any provider redirect so a bfcache/back-button-restored snapshot
    // can never render authenticated content (the token getter already returns null).
    this.set({
      status: "unauthenticated",
      mode: this.snapshot.mode,
      principal: null,
      error: null,
    });
    if (client) {
      const user = await client.getUser().catch(() => null);
      await client.removeUser().catch(() => {});
      try {
        // The ID token is used ONLY as the end-session hint, never sent to the SECP API.
        await client.signoutRedirect(user?.id_token ? { id_token_hint: user.id_token } : undefined);
        return { redirected: true };
      } catch {
        /* no end-session endpoint — local logout already reflected above */
      }
    }
    return { redirected: false };
  }

  dispose(): void {
    this.deps.tokenSeam.setUnauthorizedHandler(null);
    this.listeners.clear();
  }
}
