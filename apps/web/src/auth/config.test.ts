import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthConfigError, loadAuthConfig, validateAuthConfig } from "./config";

const VALID = {
  mode: "oidc",
  issuer: "https://idp.test/realms/secp",
  client_id: "secp-web",
  audience: "secp-api",
  scope: "openid profile email",
  redirect_path: "/auth/callback",
  post_logout_redirect_path: "/login",
};

describe("validateAuthConfig — fails closed", () => {
  it("accepts a valid oidc config", () => {
    expect(validateAuthConfig(VALID).mode).toBe("oidc");
  });

  it("accepts dev_fallback mode", () => {
    expect(validateAuthConfig({ ...VALID, mode: "dev_fallback" }).mode).toBe("dev_fallback");
  });

  it("rejects an unknown mode (production can never become dev_fallback via a bad value)", () => {
    for (const mode of ["prod", "production", "", 1, null]) {
      expect(() => validateAuthConfig({ ...VALID, mode })).toThrow(AuthConfigError);
    }
  });

  it("rejects a non-object / array / null", () => {
    for (const bad of [null, 1, "x", []]) {
      expect(() => validateAuthConfig(bad)).toThrow(AuthConfigError);
    }
  });

  it("rejects any secret-shaped key", () => {
    for (const key of ["client_secret", "secret", "password", "private_key", "token", "credential"]) {
      expect(() => validateAuthConfig({ ...VALID, [key]: "x" })).toThrow(AuthConfigError);
    }
  });

  it("rejects a scope that requests offline_access", () => {
    expect(() => validateAuthConfig({ ...VALID, scope: "openid offline_access" })).toThrow(
      AuthConfigError,
    );
  });

  it("rejects a non-relative / protocol-relative / absolute callback path", () => {
    for (const path of ["auth/callback", "//evil", "https://evil/cb"]) {
      expect(() => validateAuthConfig({ ...VALID, redirect_path: path })).toThrow(AuthConfigError);
    }
  });

  it("rejects missing/empty required strings", () => {
    for (const key of ["issuer", "client_id", "audience", "scope"]) {
      expect(() => validateAuthConfig({ ...VALID, [key]: "" })).toThrow(AuthConfigError);
    }
  });
});

describe("loadAuthConfig — public fetch, no Authorization header", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("fetches /api/v1/auth/config and carries no Authorization header", async () => {
    const f = vi.fn(async () => ({
      ok: true,
      status: 200,
      statusText: "",
      text: async () => JSON.stringify(VALID),
    }));
    vi.stubGlobal("fetch", f);
    const cfg = await loadAuthConfig();
    expect(cfg.client_id).toBe("secp-web");
    const [url, init] = f.mock.calls[0] as unknown as [string, { headers?: Record<string, string> }];
    expect(String(url)).toContain("/api/v1/auth/config");
    expect(init.headers?.["Authorization"]).toBeUndefined();
  });
});
