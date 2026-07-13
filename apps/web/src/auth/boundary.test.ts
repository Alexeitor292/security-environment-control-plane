// Static source-scan boundary tests for the auth layer (ADR-018 / OIDC-B). These pin the security
// invariants that can be checked structurally: session-only storage, no client secret, no
// implicit/password flow, no offline_access, no claim-derived identity, no infra imports, and a
// header-only bearer that never enters a URL.

import { describe, expect, it } from "vitest";

import RAW_CLIENT from "../api/client.ts?raw";
import RAW_PROVIDER from "./AuthProvider.tsx?raw";
import RAW_API_AUTH from "./apiAuth.ts?raw";
import RAW_CONTROLLER from "./authController.ts?raw";
import RAW_CONFIG from "./config.ts?raw";
import RAW_OIDC from "./oidc.ts?raw";
import RAW_SETTINGS from "./oidcSettings.ts?raw";
import RAW_SESSION from "./session.ts?raw";
import RAW_USERSTORE from "./userStore.ts?raw";

// Scan CODE only — descriptive comments legitimately mention the forbidden tokens (e.g. "never
// localStorage"); the invariants are about actual usage, so strip comments first.
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}
const CLIENT = code(RAW_CLIENT);
const PROVIDER = code(RAW_PROVIDER);
const API_AUTH = code(RAW_API_AUTH);
const CONTROLLER = code(RAW_CONTROLLER);
const CONFIG = code(RAW_CONFIG);
const OIDC = code(RAW_OIDC);
const SETTINGS = code(RAW_SETTINGS);
const SESSION = code(RAW_SESSION);
const USERSTORE = code(RAW_USERSTORE);

// The auth modules (excludes the router-glue components that legitimately import "./AuthProvider").
const CORE = [API_AUTH, CONTROLLER, CONFIG, OIDC, SETTINGS, SESSION, USERSTORE];
const ALL = [...CORE, PROVIDER];
const FORBIDDEN_IMPORT =
  /from\s+["'][^"']*(worker|provider|transport|opentofu|terraform|socket|subprocess|secret-resolver)[^"']*["']/i;

describe("auth storage boundary", () => {
  it("never uses localStorage / IndexedDB / cookies / service workers", () => {
    for (const src of [...ALL, CLIENT]) {
      expect(src).not.toContain("localStorage");
      expect(src).not.toContain("indexedDB");
      expect(src).not.toMatch(/document\.cookie/);
      expect(src).not.toContain("serviceWorker");
    }
  });

  it("references sessionStorage ONLY through the reviewed session seam", () => {
    for (const src of ALL) {
      if (src !== SESSION) expect(src).not.toContain("sessionStorage");
    }
    expect(SESSION).toContain("sessionStorage");
  });
});

describe("refresh-token elimination boundary (ADR-018)", () => {
  it("touches refresh_token ONLY in the sanitizing user store (to strip it)", () => {
    for (const src of ALL) {
      if (src !== USERSTORE) expect(src).not.toContain("refresh_token");
    }
    expect(USERSTORE).toContain("refresh_token"); // present ONLY to remove it before persisting
  });

  it("never initiates silent renewal or a refresh-token grant", () => {
    for (const src of ALL) {
      expect(src).not.toContain("signinSilent");
      expect(src).not.toContain("startSilentRenew");
      expect(src).not.toContain("useRefreshToken");
      expect(src).not.toContain("automaticSilentRenew: true");
    }
    // The settings builder pins silent renewal OFF.
    expect(SETTINGS).toContain("automaticSilentRenew: false");
  });
});

describe("auth flow boundary", () => {
  it("never requests offline_access (config.ts references it only to reject it)", () => {
    for (const src of [SETTINGS, CONTROLLER, PROVIDER, API_AUTH, OIDC, SESSION]) {
      expect(src).not.toContain("offline_access");
    }
    expect(CONFIG).toContain("offline_access"); // present ONLY in the rejection guard
  });

  it("uses Authorization Code (response_type code) — no implicit/hybrid/password grant/secret", () => {
    // The settings builder is the only place a flow/secret could be configured.
    expect(SETTINGS).toContain('response_type: "code"');
    expect(SETTINGS.toLowerCase()).not.toContain("client_secret");
    expect(SETTINGS).not.toContain('response_type: "token"');
    expect(SETTINGS).not.toContain('response_type: "id_token"');
    // No module implements a password / client-credentials / direct-access grant.
    for (const src of ALL) {
      expect(src).not.toContain("grant_type");
      expect(src).not.toContain("directAccessGrants");
    }
  });

  it("derives identity ONLY from /api/v1/me, never by decoding token claims", () => {
    for (const src of ALL) {
      for (const decodeish of ["jwtDecode", "decodeJwt", "jwt-decode", "atob(", "realm_access", "resource_access"]) {
        expect(src).not.toContain(decodeish);
      }
    }
  });

  it("imports no worker/provider/transport/infra module", () => {
    for (const src of CORE) expect(FORBIDDEN_IMPORT.test(src)).toBe(false);
  });
});

describe("bearer token placement", () => {
  it("attaches the bearer as a header only — never in a URL or query string", () => {
    expect(CLIENT).toContain('headers["Authorization"] = `Bearer');
    expect(CLIENT).not.toMatch(/searchParams[^\n]*[Tt]oken/);
    expect(CLIENT).not.toMatch(/[?&]access_token=/);
  });
});
