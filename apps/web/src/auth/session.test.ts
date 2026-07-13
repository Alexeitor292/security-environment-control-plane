import { afterEach, describe, expect, it, vi } from "vitest";

import {
  clearAuthSession,
  isDevFallbackActive,
  sanitizeReturnPath,
  sessionStore,
  setDevFallbackActive,
} from "./session";

function fakeStorage(): Storage {
  const map = new Map<string, string>();
  return {
    getItem: (k) => (map.has(k) ? map.get(k)! : null),
    setItem: (k, v) => void map.set(k, String(v)),
    removeItem: (k) => void map.delete(k),
    clear: () => map.clear(),
    key: (i) => Array.from(map.keys())[i] ?? null,
    get length() {
      return map.size;
    },
  } as Storage;
}

describe("sanitizeReturnPath — closed against open redirects", () => {
  it("keeps a safe same-origin relative path", () => {
    expect(sanitizeReturnPath("/exercises")).toBe("/exercises");
    expect(sanitizeReturnPath("/templates/new")).toBe("/templates/new");
    expect(sanitizeReturnPath("/audit?exercise_id=abc")).toBe("/audit?exercise_id=abc");
  });

  it("rejects absolute, protocol-relative, and scheme URLs -> '/'", () => {
    for (const bad of [
      "https://evil.example/",
      "http://evil.example",
      "//evil.example",
      "//evil.example/path",
      "javascript:alert(1)",
      "data:text/html,x",
      "/\\evil.example",
      "/path\\to",
      "https:/evil",
      "/redirect?to=https://evil.example",
    ]) {
      // note: the last carries an embedded scheme -> rejected
      expect(sanitizeReturnPath(bad)).toBe("/");
    }
  });

  it("rejects auth-plumbing paths, control chars, non-strings, and overlong values", () => {
    expect(sanitizeReturnPath("/login")).toBe("/");
    expect(sanitizeReturnPath("/auth/callback")).toBe("/");
    expect(sanitizeReturnPath("/auth/callback?code=abc&state=xyz")).toBe("/");
    expect(sanitizeReturnPath("/auth/logout/callback")).toBe("/");
    expect(sanitizeReturnPath("/a\u0000b")).toBe("/");
    expect(sanitizeReturnPath(null)).toBe("/");
    expect(sanitizeReturnPath(undefined)).toBe("/");
    expect(sanitizeReturnPath(123)).toBe("/");
    expect(sanitizeReturnPath("/" + "x".repeat(600))).toBe("/");
    expect(sanitizeReturnPath("relative-no-slash")).toBe("/");
  });
});

describe("dev-fallback flag + storage seam (session-scoped only)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("degrades safely to closed defaults when sessionStorage is absent (node)", () => {
    expect(sessionStore()).toBeNull();
    expect(isDevFallbackActive()).toBe(false);
    // no throw when storage is unavailable
    setDevFallbackActive(true);
    clearAuthSession();
  });

  it("uses sessionStorage (never localStorage) for the dev-fallback flag", () => {
    const store = fakeStorage();
    vi.stubGlobal("sessionStorage", store);
    expect(isDevFallbackActive()).toBe(false);
    setDevFallbackActive(true);
    expect(isDevFallbackActive()).toBe(true);
    expect(store.getItem("secp.auth.devFallback")).toBe("1");
    clearAuthSession();
    expect(isDevFallbackActive()).toBe(false);
  });
});
