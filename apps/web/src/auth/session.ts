// Session-scoped browser storage seam + return-path sanitization (ADR-018 / OIDC-B).
//
// This is the ONLY SECP module permitted to touch web storage, and it uses sessionStorage
// EXCLUSIVELY — never localStorage, IndexedDB, cookies, or a service worker. Access tokens are never
// written here; the reviewed OIDC library owns the transient authorization state (PKCE verifier,
// state, nonce, and the session-scoped user) through the same sessionStorage seam. Everything is
// wrapped so unit tests (node env, no window) and any SSR path degrade safely to a closed default.

const DEV_FALLBACK_KEY = "secp.auth.devFallback";
const MAX_RETURN_PATH = 512;
// Never return to the auth plumbing itself (prevents loops / callback replay via returnTo).
const BLOCKED_RETURN_PATHS = new Set(["/login", "/auth/callback", "/auth/logout/callback"]);

function store(): Storage | null {
  try {
    return typeof sessionStorage !== "undefined" ? sessionStorage : null;
  } catch {
    return null; // storage disabled (private mode / SSR / tests without a stub)
  }
}

/** The sessionStorage instance for the reviewed OIDC library's state/user stores (or null). */
export function sessionStore(): Storage | null {
  return store();
}

function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Reduce an untrusted return target to a safe, same-origin relative application path. Anything that
 * could leave the origin, re-enter the auth plumbing, or is malformed collapses to the closed
 * fallback "/". Accepts only a single-leading-slash relative path (optionally with query/hash) that
 * is not one of the auth routes and is within a bounded length.
 */
export function sanitizeReturnPath(raw: unknown): string {
  if (typeof raw !== "string") return "/";
  const value = raw;
  if (value.length === 0 || value.length > MAX_RETURN_PATH) return "/";
  if (!value.startsWith("/")) return "/"; // absolute URLs, scheme-relative, javascript:/data: etc.
  if (value.startsWith("//")) return "/"; // protocol-relative //evil.com
  if (value.includes("\\")) return "/"; // backslash trickery
  if (value.includes("://")) return "/"; // embedded scheme
  if (hasControlChars(value)) return "/";
  const base = value.split("?")[0].split("#")[0];
  if (BLOCKED_RETURN_PATHS.has(base)) return "/";
  return value;
}

export function setDevFallbackActive(active: boolean): void {
  const s = store();
  if (!s) return;
  try {
    if (active) s.setItem(DEV_FALLBACK_KEY, "1");
    else s.removeItem(DEV_FALLBACK_KEY);
  } catch {
    /* ignore */
  }
}

export function isDevFallbackActive(): boolean {
  const s = store();
  if (!s) return false;
  try {
    return s.getItem(DEV_FALLBACK_KEY) === "1";
  } catch {
    return false;
  }
}

/** Clear SECP-owned session state (the dev-fallback flag). The OIDC library clears its own
 *  user/state stores separately on logout. */
export function clearAuthSession(): void {
  const s = store();
  if (!s) return;
  try {
    s.removeItem(DEV_FALLBACK_KEY);
  } catch {
    /* ignore */
  }
}
