import { afterEach, describe, expect, it, vi } from "vitest";

import { clearAccessTokenProvider, setAccessTokenProvider } from "../auth/apiAuth";
import { API_BASE, __setApiBaseResolutionForTests, api, resolveApiBase } from "./client";

// ADR-019 / OIDC-C: production locks the API base to ONE same-origin web/API deployment; development
// and node tests keep the explicit-override → window → deterministic-loopback behavior.

const PROD = { PROD: true };
const DEV = { PROD: false };
const win = (origin: string) => ({ location: { origin } });

describe("resolveApiBase — production same-origin", () => {
  it("production + no explicit base → window.location.origin", () => {
    expect(resolveApiBase(PROD, win("https://secp.example.com"))).toEqual({
      ok: true,
      base: "https://secp.example.com",
    });
  });

  it("production + exact same-origin explicit base → accepted (canonical window origin)", () => {
    expect(
      resolveApiBase(
        { ...PROD, VITE_API_BASE_URL: "https://secp.example.com" },
        win("https://secp.example.com"),
      ),
    ).toEqual({ ok: true, base: "https://secp.example.com" });
    // a trailing slash is still the same origin
    expect(
      resolveApiBase(
        { ...PROD, VITE_API_BASE_URL: "https://secp.example.com/" },
        win("https://secp.example.com"),
      ),
    ).toEqual({ ok: true, base: "https://secp.example.com" });
  });

  it("production + another host → refused", () => {
    expect(
      resolveApiBase(
        { ...PROD, VITE_API_BASE_URL: "https://api.other.example" },
        win("https://secp.example.com"),
      ),
    ).toEqual({ ok: false, base: null });
  });

  it("production + another scheme → refused", () => {
    expect(
      resolveApiBase(
        { ...PROD, VITE_API_BASE_URL: "http://secp.example.com" },
        win("https://secp.example.com"),
      ),
    ).toEqual({ ok: false, base: null });
  });

  it("production + another port → refused", () => {
    expect(
      resolveApiBase(
        { ...PROD, VITE_API_BASE_URL: "https://secp.example.com:8443" },
        win("https://secp.example.com"),
      ),
    ).toEqual({ ok: false, base: null });
  });

  it("production + path/query/fragment/userinfo → refused (unsafe override never silently ignored)", () => {
    for (const bad of [
      "https://secp.example.com/api",
      "https://secp.example.com/?x=1",
      "https://secp.example.com/#frag",
      "https://user:pass@secp.example.com",
      "not-a-url",
    ]) {
      expect(
        resolveApiBase({ ...PROD, VITE_API_BASE_URL: bad }, win("https://secp.example.com")),
      ).toEqual({ ok: false, base: null });
    }
  });

  it("production + no window → refused, never localhost", () => {
    expect(resolveApiBase(PROD, undefined)).toEqual({ ok: false, base: null });
    // even with an explicit localhost override, production with no window still fails closed
    expect(
      resolveApiBase({ ...PROD, VITE_API_BASE_URL: "http://localhost:8080" }, undefined),
    ).toEqual({ ok: false, base: null });
  });
});

describe("resolveApiBase — development / node", () => {
  it("uses an explicit cross-origin dev API base", () => {
    expect(
      resolveApiBase(
        { ...DEV, VITE_API_BASE_URL: "http://localhost:8080" },
        win("http://localhost:5173"),
      ),
    ).toEqual({ ok: true, base: "http://localhost:8080" });
  });

  it("uses the window origin when no explicit base", () => {
    expect(resolveApiBase(DEV, win("http://localhost:5173"))).toEqual({
      ok: true,
      base: "http://localhost:5173",
    });
  });

  it("falls back to a deterministic loopback with no window (node/SSR), never failing", () => {
    expect(resolveApiBase(DEV, undefined)).toEqual({ ok: true, base: "http://localhost:8080" });
    expect(resolveApiBase(undefined, undefined)).toEqual({ ok: true, base: "http://localhost:8080" });
  });
});

function mockFetch(status: number, body: unknown) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    text: async () => JSON.stringify(body),
  }));
}

describe("bearer token scoping (no cross-origin token leakage)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    clearAccessTokenProvider();
    __setApiBaseResolutionForTests(null);
  });

  it("attaches the bearer ONLY to the resolved API origin, on protected requests", async () => {
    setAccessTokenProvider(() => "tok-123");
    const f = mockFetch(200, {
      user_id: "u1",
      organization_id: "o1",
      email: "a@b.c",
      permissions: [],
      is_dev_fallback: false,
    });
    vi.stubGlobal("fetch", f);
    await api.me();
    const [url, init] = f.mock.calls[0] as unknown as [string, { headers: Record<string, string> }];
    expect(url.startsWith(API_BASE)).toBe(true);
    expect(init.headers["Authorization"]).toBe("Bearer tok-123");
  });

  it("never sends Authorization on the public auth-config request (credential-free)", async () => {
    setAccessTokenProvider(() => "tok-123");
    const f = mockFetch(200, {
      mode: "oidc",
      issuer: "https://idp.example.com/realms/secp",
      client_id: "secp-web",
      audience: "secp-api",
      scope: "openid profile email",
      redirect_path: "/auth/callback",
      post_logout_redirect_path: "/login",
    });
    vi.stubGlobal("fetch", f);
    await api.authConfig();
    const [, init] = f.mock.calls[0] as unknown as [string, { headers: Record<string, string> }];
    expect(init.headers["Authorization"]).toBeUndefined();
  });
});

describe("production fail-closed request behavior", () => {
  afterEach(() => {
    __setApiBaseResolutionForTests(null); // reset to the real (dev/test) resolution
    clearAccessTokenProvider();
    vi.unstubAllGlobals();
  });

  it("fails closed WITHOUT calling the token provider or fetching when the base is invalid", async () => {
    const tokenProvider = vi.fn(() => "tok-123");
    setAccessTokenProvider(tokenProvider);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    __setApiBaseResolutionForTests({ ok: false, base: null }); // simulate failed prod resolution
    await expect(api.me()).rejects.toMatchObject({ code: "configuration_invalid" });
    expect(tokenProvider).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("throws a closed, value-free error (no rejected override, no localhost) on failure", async () => {
    __setApiBaseResolutionForTests({ ok: false, base: null });
    await expect(api.me()).rejects.toMatchObject({ code: "configuration_invalid" });
    try {
      await api.me();
    } catch (e) {
      const err = e as { message: string };
      expect(err.message).not.toContain("localhost");
      expect(err.message).not.toContain("http");
    }
  });
});
