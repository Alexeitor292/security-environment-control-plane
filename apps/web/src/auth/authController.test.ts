import { describe, expect, it } from "vitest";

import type { Principal } from "../api/types";
import { AuthController } from "./authController";
import type { AuthControllerDeps } from "./authController";
import type { AuthConfig } from "./types";
import type { OidcClient, OidcUser } from "./oidc";

const PRINCIPAL: Principal = {
  user_id: "u1",
  organization_id: "o1",
  email: "alice@dev.test",
  permissions: ["audit:read"],
  is_dev_fallback: false,
};

const OIDC_CONFIG: AuthConfig = {
  mode: "oidc",
  issuer: "https://idp.test/realms/secp",
  client_id: "secp-web",
  audience: "secp-api",
  scope: "openid profile email",
  redirect_path: "/auth/callback",
  post_logout_redirect_path: "/login",
};
const DEV_CONFIG: AuthConfig = { ...OIDC_CONFIG, mode: "dev_fallback" };

interface FakeClient extends OidcClient {
  readonly calls: string[];
  readonly signinArgs: unknown[];
}

function fakeClient(opts: {
  user?: OidcUser | null;
  callbackUser?: OidcUser;
  callbackThrows?: boolean | (() => boolean);
  signoutThrows?: boolean;
} = {}): FakeClient {
  const calls: string[] = [];
  const signinArgs: unknown[] = [];
  let current = opts.user ?? null;
  let callbackCount = 0;
  return {
    calls,
    signinArgs,
    signinRedirect: async (args) => {
      calls.push("signinRedirect");
      signinArgs.push(args);
    },
    signinRedirectCallback: async () => {
      calls.push("signinRedirectCallback");
      callbackCount += 1;
      const shouldThrow =
        typeof opts.callbackThrows === "function" ? opts.callbackThrows() : opts.callbackThrows;
      if (shouldThrow || callbackCount > 1) {
        // A replayed callback (state already consumed) fails closed.
        throw new Error("invalid_grant");
      }
      return (
        opts.callbackUser ?? {
          access_token: "at",
          id_token: "it",
          expired: false,
          state: { returnTo: "/audit" },
        }
      );
    },
    signoutRedirect: async () => {
      calls.push("signoutRedirect");
      if (opts.signoutThrows) throw new Error("no end_session_endpoint");
    },
    getUser: async () => current,
    removeUser: async () => {
      calls.push("removeUser");
      current = null;
    },
  };
}

function makeDeps(over: Partial<AuthControllerDeps> = {}) {
  const flags = { dev: false, cleared: 0 };
  const seam: { provider: (() => string | null) | null; unauth: (() => void) | null } = {
    provider: null,
    unauth: null,
  };
  const deps: AuthControllerDeps = {
    loadConfig: over.loadConfig ?? (async () => OIDC_CONFIG),
    createOidcClient: over.createOidcClient ?? (() => fakeClient()),
    fetchMe: over.fetchMe ?? (async () => PRINCIPAL),
    session: over.session ?? {
      isDevFallbackActive: () => flags.dev,
      setDevFallbackActive: (a) => {
        flags.dev = a;
      },
      clear: () => {
        flags.cleared += 1;
      },
    },
    tokenSeam: over.tokenSeam ?? {
      setAccessTokenProvider: (fn) => {
        seam.provider = fn;
      },
      clearAccessTokenProvider: () => {
        seam.provider = null;
      },
      setUnauthorizedHandler: (fn) => {
        seam.unauth = fn;
      },
    },
  };
  return { deps, flags, seam };
}

describe("AuthController — OIDC mode init", () => {
  it("resolves an authenticated principal from a valid stored user (via /api/v1/me)", async () => {
    const client = fakeClient({ user: { access_token: "at", expired: false } });
    const { deps, seam } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot()).toMatchObject({ status: "authenticated", mode: "oidc" });
    expect(c.getSnapshot().principal).toEqual(PRINCIPAL);
    // the registered token provider returns the fresh access token
    expect(seam.provider?.()).toBe("at");
  });

  it("is unauthenticated when there is no stored user", async () => {
    const { deps } = makeDeps({ createOidcClient: () => fakeClient({ user: null }) });
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot().status).toBe("unauthenticated");
  });

  it("is unauthenticated (and clears the user) when /api/v1/me fails", async () => {
    const client = fakeClient({ user: { access_token: "at", expired: false } });
    const { deps } = makeDeps({
      createOidcClient: () => client,
      fetchMe: async () => {
        throw new Error("401");
      },
    });
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot().status).toBe("unauthenticated");
    expect(client.calls).toContain("removeUser");
  });

  it("fails closed to error when the config cannot be loaded", async () => {
    const { deps } = makeDeps({
      loadConfig: async () => {
        throw new Error("bad config");
      },
    });
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot()).toMatchObject({ status: "error", error: "configuration_invalid" });
  });
});

describe("AuthController — dev fallback mode init", () => {
  it("is unauthenticated until dev fallback is explicitly activated", async () => {
    const { deps } = makeDeps({ loadConfig: async () => DEV_CONFIG });
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot()).toMatchObject({ status: "unauthenticated", mode: "dev_fallback" });
  });

  it("authenticates when the dev flag is already active and /me succeeds", async () => {
    const { deps, flags } = makeDeps({ loadConfig: async () => DEV_CONFIG });
    flags.dev = true;
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot()).toMatchObject({ status: "authenticated", mode: "dev_fallback" });
  });

  it("clears no access token in dev mode (no bearer)", async () => {
    const { deps, seam } = makeDeps({ loadConfig: async () => DEV_CONFIG });
    const c = new AuthController(deps);
    await c.init();
    expect(seam.provider).toBeNull();
  });
});

describe("AuthController — login", () => {
  it("starts signinRedirect exactly once, carrying the sanitized return path in state", async () => {
    const client = fakeClient({ user: null });
    const { deps } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    c.login("/audit");
    c.login("/audit"); // a second call is a distinct redirect attempt; each delegates to the lib
    expect(client.calls.filter((x) => x === "signinRedirect")).toHaveLength(2);
    expect(client.signinArgs[0]).toEqual({ state: { returnTo: "/audit" } });
  });

  it("sanitizes an unsafe return path to '/' in the state", async () => {
    const client = fakeClient({ user: null });
    const { deps } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    c.login("https://evil.example");
    expect(client.signinArgs[0]).toEqual({ state: { returnTo: "/" } });
  });
});

describe("AuthController — callback", () => {
  it("completes the callback, authenticates, and returns the sanitized return path", async () => {
    const client = fakeClient({ user: null });
    const { deps } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    const target = await c.completeCallback();
    expect(target).toBe("/audit");
    expect(c.getSnapshot().status).toBe("authenticated");
  });

  it("fails closed on a replayed callback (state already consumed)", async () => {
    const client = fakeClient({ user: null });
    const { deps } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    expect(await c.completeCallback()).toBe("/audit");
    const replay = await c.completeCallback();
    expect(replay).toBeNull();
    expect(c.getSnapshot().status).toBe("unauthenticated");
  });

  it("returns null and stays unauthenticated on a callback error", async () => {
    const client = fakeClient({ user: null, callbackThrows: true });
    const { deps } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    expect(await c.completeCallback()).toBeNull();
    expect(c.getSnapshot()).toMatchObject({ status: "unauthenticated", error: "callback_invalid" });
  });
});

describe("AuthController — logout", () => {
  it("clears the session and redirects to the provider end-session when available", async () => {
    const client = fakeClient({ user: { access_token: "at", id_token: "it", expired: false } });
    const { deps, flags } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    const result = await c.logout();
    expect(result).toEqual({ redirected: true });
    expect(client.calls).toContain("removeUser");
    expect(client.calls).toContain("signoutRedirect");
    expect(flags.cleared).toBeGreaterThan(0);
  });

  it("falls back to a local logout when there is no end-session endpoint", async () => {
    const client = fakeClient({
      user: { access_token: "at", expired: false },
      signoutThrows: true,
    });
    const { deps } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    const result = await c.logout();
    expect(result).toEqual({ redirected: false });
    expect(c.getSnapshot()).toMatchObject({ status: "unauthenticated", principal: null });
  });
});

describe("AuthController — 401 handling", () => {
  it("clears an authenticated session on a 401 (no auto-replay), suppressing the token", async () => {
    const client = fakeClient({ user: { access_token: "at", expired: false } });
    const { deps, seam } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot().status).toBe("authenticated");
    // simulate the API client reporting a 401
    seam.unauth?.();
    expect(c.getSnapshot()).toMatchObject({ status: "unauthenticated", error: "session_expired" });
    expect(seam.provider?.()).toBeNull(); // no token after the session is cleared
  });
});

describe("AuthController — refresh-token elimination (OIDC-B / ADR-018)", () => {
  const RT = "REFRESH-SENTINEL-controller-7b2a";

  it("discards a refresh_token returned by the signinRedirectCallback User (Section 2 / 4B)", async () => {
    const cbUser = {
      access_token: "at",
      id_token: "it",
      expired: false,
      state: { returnTo: "/audit" },
      refresh_token: RT,
    } as unknown as OidcUser;
    const client = fakeClient({ user: null, callbackUser: cbUser });
    const { deps, seam } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();

    const target = await c.completeCallback();
    expect(target).toBe("/audit"); // login flow completes...
    expect(c.getSnapshot().status).toBe("authenticated"); // ...and /api/v1/me succeeds
    expect(seam.provider?.()).toBe("at"); // the API seam exposes only the access token

    // No refresh_token is retained anywhere reachable in the controller.
    const internal = c as unknown as { user: Record<string, unknown> | null };
    expect(internal.user).not.toBeNull();
    expect("refresh_token" in (internal.user as object)).toBe(false);
    expect(JSON.stringify(internal.user)).not.toContain(RT);
    expect(JSON.stringify(c.getSnapshot())).not.toContain(RT);
  });

  it("discards a refresh_token from a stale stored user on init / restoration (Section 2)", async () => {
    const stored = { access_token: "at", expired: false, refresh_token: RT } as unknown as OidcUser;
    const client = fakeClient({ user: stored });
    const { deps, seam } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    expect(c.getSnapshot().status).toBe("authenticated");
    const internal = c as unknown as { user: Record<string, unknown> | null };
    expect("refresh_token" in (internal.user as object)).toBe(false);
    expect(seam.provider?.()).toBe("at");
    expect(JSON.stringify(internal.user)).not.toContain(RT);
  });

  it("exposes no token fields at all through the React-facing snapshot", async () => {
    const client = fakeClient({ user: { access_token: "at", expired: false } });
    const { deps } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    const snap = c.getSnapshot() as unknown as Record<string, unknown>;
    expect(Object.keys(snap).sort()).toEqual(["error", "mode", "principal", "status"]);
    expect("refresh_token" in snap).toBe(false);
    expect("access_token" in snap).toBe(false);
  });

  it("clears the session on access-token expiry (401) rather than renewing it (Section 4D)", async () => {
    const client = fakeClient({ user: { access_token: "at", expired: false } });
    const { deps, seam } = makeDeps({ createOidcClient: () => client });
    const c = new AuthController(deps);
    await c.init();
    seam.unauth?.();
    expect(c.getSnapshot()).toMatchObject({ status: "unauthenticated", error: "session_expired" });
    expect(seam.provider?.()).toBeNull(); // expiry requires a fresh interactive login
    expect(client.calls).toContain("removeUser");
    expect(client.calls).not.toContain("signinSilent"); // no silent renewal / refresh grant
  });
});
