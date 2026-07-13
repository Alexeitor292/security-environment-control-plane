import { afterEach, describe, expect, it, vi } from "vitest";

import { clearAccessTokenProvider, setAccessTokenProvider, setUnauthorizedHandler } from "../auth/apiAuth";
import { api } from "./client";

function mockFetch(status: number, body?: unknown) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    text: async () => (body === undefined ? "" : JSON.stringify(body)),
  }));
}

function initOf(f: ReturnType<typeof mockFetch>): { headers: Record<string, string>; body?: string } {
  return (f.mock.calls[0] as unknown as [string, { headers: Record<string, string>; body?: string }])[1];
}

describe("API client bearer integration (ADR-018)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    clearAccessTokenProvider();
    setUnauthorizedHandler(null);
  });

  it("attaches Authorization: Bearer <token> to a protected request in OIDC mode", async () => {
    setAccessTokenProvider(() => "the-access-token");
    const f = mockFetch(200, { user_id: "u" });
    vi.stubGlobal("fetch", f);
    await api.me();
    const [url, init] = f.mock.calls[0] as unknown as [string, { headers: Record<string, string> }];
    expect(init.headers["Authorization"]).toBe("Bearer the-access-token");
    expect(String(url)).not.toContain("the-access-token"); // never in the URL
  });

  it("sends NO Authorization header when no token provider is set (dev fallback)", async () => {
    const f = mockFetch(200, { user_id: "u" });
    vi.stubGlobal("fetch", f);
    await api.me();
    expect(initOf(f).headers["Authorization"]).toBeUndefined();
  });

  it("sends NO Authorization header on the public auth-config request, even with a token set", async () => {
    setAccessTokenProvider(() => "the-access-token");
    const f = mockFetch(200, { mode: "oidc" });
    vi.stubGlobal("fetch", f);
    await api.authConfig();
    expect(initOf(f).headers["Authorization"]).toBeUndefined();
  });

  it("never places the token in the request body of a mutation", async () => {
    setAccessTokenProvider(() => "the-access-token");
    const f = mockFetch(201, {});
    vi.stubGlobal("fetch", f);
    await api.createTemplate({ name: "n", slug: "s" });
    const init = initOf(f);
    expect(init.headers["Authorization"]).toBe("Bearer the-access-token");
    expect(init.body ?? "").not.toContain("the-access-token");
  });

  it("invokes the unauthorized handler on 401 and does NOT auto-replay", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    const f = mockFetch(401, { error: { code: "unauthenticated" } });
    vi.stubGlobal("fetch", f);
    await expect(api.me()).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("does NOT invoke the unauthorized handler on 403 (session preserved)", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    const f = mockFetch(403, { error: { code: "forbidden" } });
    vi.stubGlobal("fetch", f);
    await expect(api.audit()).rejects.toMatchObject({ status: 403, code: "forbidden" });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("surfaces 503 authentication_unavailable with its code (not as invalid credentials)", async () => {
    const f = mockFetch(503, { error: { code: "authentication_unavailable" } });
    vi.stubGlobal("fetch", f);
    await expect(api.me()).rejects.toMatchObject({
      status: 503,
      code: "authentication_unavailable",
    });
  });
});
