import { describe, expect, it } from "vitest";

import { ApiClientError } from "../api/client";
import { AuthConfigError } from "./config";
import type { OidcClient, OidcUser } from "./oidc";
import { accessTokenOf, authErrorCategory, resolveUser, returnPathFromState } from "./oidc";
import { sanitizeReturnPath } from "./session";

describe("accessTokenOf — never returns an expired token", () => {
  it("returns a fresh, non-empty access token", () => {
    expect(accessTokenOf({ access_token: "abc", expired: false })).toBe("abc");
  });
  it("returns null for expired, empty, or absent users", () => {
    expect(accessTokenOf({ access_token: "abc", expired: true })).toBeNull();
    expect(accessTokenOf({ access_token: "", expired: false })).toBeNull();
    expect(accessTokenOf(null)).toBeNull();
  });
});

function clientWithUser(user: OidcUser | null): OidcClient {
  return {
    getUser: async () => user,
    signinRedirect: async () => {},
    signinRedirectCallback: async () => ({ access_token: "x" }),
    signoutRedirect: async () => {},
    removeUser: async () => {},
  };
}

describe("resolveUser — expired user is treated as absent", () => {
  it("returns the user only when unexpired", async () => {
    expect(await resolveUser(clientWithUser({ access_token: "a", expired: false }))).not.toBeNull();
    expect(await resolveUser(clientWithUser({ access_token: "a", expired: true }))).toBeNull();
    expect(await resolveUser(clientWithUser(null))).toBeNull();
  });
});

describe("authErrorCategory — bounded categories only", () => {
  it("maps API + config errors without leaking detail", () => {
    expect(authErrorCategory(new ApiClientError(401, "unauthenticated", "x"))).toBe("session_expired");
    expect(authErrorCategory(new ApiClientError(503, "authentication_unavailable", "x"))).toBe(
      "authentication_unavailable",
    );
    expect(authErrorCategory(new ApiClientError(0, "api_unreachable", "x"))).toBe(
      "authentication_unavailable",
    );
    expect(authErrorCategory(new AuthConfigError())).toBe("configuration_invalid");
    expect(authErrorCategory(new Error("boom"))).toBe("callback_invalid");
    expect(authErrorCategory("secret-token-value")).toBe("callback_invalid");
  });
});

describe("returnPathFromState — sanitizes the OIDC-carried return path", () => {
  it("extracts a safe path, rejecting external targets", () => {
    expect(returnPathFromState({ returnTo: "/audit" }, sanitizeReturnPath)).toBe("/audit");
    expect(returnPathFromState({ returnTo: "https://evil.example" }, sanitizeReturnPath)).toBe("/");
    expect(returnPathFromState({ returnTo: "//evil" }, sanitizeReturnPath)).toBe("/");
    expect(returnPathFromState(null, sanitizeReturnPath)).toBe("/");
    expect(returnPathFromState({}, sanitizeReturnPath)).toBe("/");
    expect(returnPathFromState("nope", sanitizeReturnPath)).toBe("/");
  });
});
