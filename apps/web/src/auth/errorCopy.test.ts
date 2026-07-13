import { describe, expect, it } from "vitest";

import { AUTH_ERROR_COPY, authErrorCopy } from "./errorCopy";
import type { AuthErrorCategory } from "./types";

const CATEGORIES: AuthErrorCategory[] = [
  "authentication_required",
  "callback_invalid",
  "authentication_unavailable",
  "session_expired",
  "configuration_invalid",
];

describe("auth error copy — bounded and leak-free", () => {
  it("has safe copy for every category and never leaks sensitive terms", () => {
    for (const category of CATEGORIES) {
      const text = AUTH_ERROR_COPY[category];
      expect(text.length).toBeGreaterThan(5);
      for (const leak of ["token", "claim", "code", "state", "nonce", "verifier", "bearer", "jwt"]) {
        expect(text.toLowerCase()).not.toContain(leak);
      }
    }
  });

  it("returns null when there is no error category", () => {
    expect(authErrorCopy(null)).toBeNull();
  });
});
