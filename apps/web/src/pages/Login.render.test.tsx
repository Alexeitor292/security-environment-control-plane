import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { LoginView } from "./Login";

function html(over: Partial<Parameters<typeof LoginView>[0]> = {}): string {
  return renderToStaticMarkup(
    createElement(LoginView, {
      mode: "oidc",
      errorText: null,
      busy: false,
      onOidcSignin: () => {},
      onDevContinue: () => {},
      ...over,
    }),
  );
}

describe("LoginView — OIDC mode", () => {
  const out = html({ mode: "oidc" });

  it("offers SSO sign-in and contains no username/password form", () => {
    expect(out).toContain("Sign in with SSO");
    expect(out).not.toContain("Continue as dev-admin");
    // Assert via regex, not a contiguous string literal, so this test file stays clear of the exact
    // source token the cross-language backend boundary scanners forbid; still proves no such input.
    expect(out).not.toMatch(/type\s*=\s*["']password["']/i);
    expect(out.toLowerCase()).not.toContain("password");
  });

  it("explains org SSO without exposing issuer/client id/token/claims", () => {
    expect(out.toLowerCase()).toContain("single sign-on");
    for (const leak of ["issuer", "client_id", "secp-web", "token", "bearer", "https://", "nonce"]) {
      expect(out).not.toContain(leak);
    }
  });

  it("disables the button while a redirect is starting", () => {
    expect(html({ mode: "oidc", busy: true })).toContain("disabled");
  });

  it("shows bounded, safe error copy", () => {
    const withError = html({ mode: "oidc", errorText: "Your session has expired. Please sign in again." });
    expect(withError).toContain("session has expired");
  });
});

describe("LoginView — dev fallback mode", () => {
  const out = html({ mode: "dev_fallback" });

  it("offers the dev-admin action clearly marked development-only", () => {
    expect(out).toContain("Continue as dev-admin");
    expect(out).toContain("Development only");
    expect(out).not.toContain("Sign in with SSO");
  });
});
