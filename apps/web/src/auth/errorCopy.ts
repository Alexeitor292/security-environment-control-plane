// Bounded, safe user-facing copy for authentication error categories (ADR-018 / OIDC-B).
// Never reveals a token, claim, code, state, nonce, provider detail, or raw exception.

import type { AuthErrorCategory } from "./types";

export const AUTH_ERROR_COPY: Record<AuthErrorCategory, string> = {
  authentication_required: "Please sign in to continue.",
  callback_invalid: "Sign-in could not be completed. Please try signing in again.",
  authentication_unavailable:
    "The sign-in service is temporarily unavailable. Please try again shortly.",
  session_expired: "Your session has expired. Please sign in again.",
  configuration_invalid:
    "Authentication is not configured correctly. Please contact your administrator.",
};

export function authErrorCopy(category: AuthErrorCategory | null): string | null {
  return category ? AUTH_ERROR_COPY[category] : null;
}
