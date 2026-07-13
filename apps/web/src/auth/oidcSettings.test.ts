import { WebStorageStateStore } from "oidc-client-ts";
import { describe, expect, it } from "vitest";

import type { AuthConfig } from "../api/types";
import { buildUserManagerSettings } from "./oidcSettings";
import { SanitizingUserStore } from "./userStore";

const CONFIG: AuthConfig = {
  mode: "oidc",
  issuer: "https://idp.test/realms/secp",
  client_id: "secp-web",
  audience: "secp-api",
  scope: "openid profile email",
  redirect_path: "/auth/callback",
  post_logout_redirect_path: "/login",
};

function fakeStore(): Storage {
  const map = new Map<string, string>();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, String(v)),
    removeItem: (k) => void map.delete(k),
    clear: () => map.clear(),
    key: () => null,
    length: 0,
  } as Storage;
}

describe("buildUserManagerSettings — public Authorization Code + PKCE S256", () => {
  const settings = buildUserManagerSettings(CONFIG, "http://localhost:5173", fakeStore());
  const raw = settings as unknown as Record<string, unknown>;

  it("uses response_type=code (never token/id_token: no implicit/hybrid)", () => {
    expect(settings.response_type).toBe("code");
  });

  it("requests exactly 'openid profile email' with no offline_access", () => {
    expect(settings.scope).toBe("openid profile email");
    expect(settings.scope).not.toContain("offline_access");
  });

  it("derives exact redirect + post-logout URIs from the origin and fixed paths", () => {
    expect(settings.redirect_uri).toBe("http://localhost:5173/auth/callback");
    expect(settings.post_logout_redirect_uri).toBe("http://localhost:5173/login");
  });

  it("carries NO client secret (public client)", () => {
    expect("client_secret" in raw).toBe(false);
    expect(raw.client_secret).toBeUndefined();
  });

  it("does not enable PKCE-plain (oidc-client-ts uses S256 for the code flow)", () => {
    expect(raw.disablePKCE).not.toBe(true);
  });

  it("disables automatic silent renewal in this slice", () => {
    expect(settings.automaticSilentRenew).toBe(false);
  });

  it("stores the user via the refresh-token-sanitizing store and the transaction state in a plain session store", () => {
    // The USER store strips refresh tokens before persisting; the transaction STATE store
    // (PKCE verifier / state / nonce) stays a separate, plain session store.
    expect(settings.userStore).toBeInstanceOf(SanitizingUserStore);
    expect(settings.userStore).not.toBeInstanceOf(WebStorageStateStore);
    expect(settings.stateStore).toBeInstanceOf(WebStorageStateStore);
    expect(settings.stateStore).not.toBeInstanceOf(SanitizingUserStore);
  });

  it("uses the config issuer + public client id", () => {
    expect(settings.authority).toBe(CONFIG.issuer);
    expect(settings.client_id).toBe("secp-web");
  });
});
