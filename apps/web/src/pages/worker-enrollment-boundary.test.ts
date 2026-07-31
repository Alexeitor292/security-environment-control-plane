// Static architecture/security boundary tests for the worker-enrollment UI (SECP-PR5H-B1).
//
// The frontend surface must stay inside the three enrollment routes that take a browser principal.
// It must never call the worker-authenticated exchange routes, never call the sealed claim-only
// progression routes, never persist bearer-grade invitation material, and never reach an
// infrastructure module.

import { describe, expect, it } from "vitest";

import CLIENT from "../api/client.ts?raw";
import MAIN from "../main.tsx?raw";
import PAGE from "./WorkerEnrollment.tsx?raw";
import MODULE from "./worker-enrollment.ts?raw";

// Descriptive comments legitimately name the forbidden routes and tokens (that is the point of the
// documentation), so scan CODE only — the invariants are about actual usage.
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}
const CLIENT_CODE = code(CLIENT);
const PAGE_CODE = code(PAGE);
const MODULE_CODE = code(MODULE);

const FORBIDDEN_IMPORT =
  /from\s+["'][^"']*(worker\/|provider|transport|opentofu|terraform|socket|subprocess|secret-resolver)[^"']*["']/i;

// The reviewed auth seam. It is the app's identity provider context, not an infrastructure
// provider module, and it is the ONLY import allowed to contain "provider".
const AUTH_PROVIDER_IMPORT = /import \{ useAuth \} from "\.\.\/auth\/AuthProvider";/;

describe("enrollment UI import boundary", () => {
  it("imports no worker/provider/transport/infra module", () => {
    // Remove the one allowed occurrence first, so the scan still proves that no OTHER
    // provider/transport/worker path is imported.
    expect(FORBIDDEN_IMPORT.test(PAGE_CODE.replace(AUTH_PROVIDER_IMPORT, ""))).toBe(false);
    expect(FORBIDDEN_IMPORT.test(MODULE_CODE)).toBe(false);
  });

  it("reaches the identity provider only through the reviewed auth seam", () => {
    expect(AUTH_PROVIDER_IMPORT.test(PAGE_CODE)).toBe(true);
    // never the token/session internals
    expect(PAGE_CODE).not.toContain("apiAuth");
    expect(PAGE_CODE).not.toContain("authController");
    expect(PAGE_CODE).not.toContain("./auth/session");
  });
});

describe("enrollment client surface", () => {
  it("calls exactly the three principal-authenticated enrollment routes", () => {
    expect(CLIENT_CODE).toContain('"/api/v1/enrollment/invitations"');
    expect(CLIENT_CODE).toContain("`/api/v1/enrollment/${enrollmentId}`");
    expect(CLIENT_CODE).toContain("`/api/v1/enrollment/${enrollmentId}/revoke`");
  });

  // These are authenticated by the worker's own Ed25519 proof-of-possession, not by a browser
  // session. A browser must never attempt them.
  it("never calls the worker-authenticated exchange routes", () => {
    expect(CLIENT_CODE).not.toContain("/exchange/bind");
    expect(CLIENT_CODE).not.toContain("/exchange/result");
    expect(PAGE_CODE).not.toContain("exchange");
  });

  // Sealed closed and hidden from the schema; refused outright in production.
  // Matched as whole path templates — a bare "/bind" would also match the unrelated
  // read-only-bootstrap "binding-descriptor" route.
  it("never calls the sealed claim-only progression routes", () => {
    for (const step of ["bind", "offer", "result", "verify", "healthy"]) {
      const sealed = "`/api/v1/enrollment/${enrollmentId}/" + step + "`";
      expect(CLIENT_CODE, sealed).not.toContain(sealed);
    }
  });

  it("adds no PR5H enrollment method beyond create, status and revoke", () => {
    // Scoped to the supported-enrollment names: the unrelated SECP-B5 target-discovery client
    // methods (listDiscoveryEnrollments / getDiscoveryEnrollment) are a different concept that
    // merely shares the word, and are not in scope for this boundary.
    const methods = (CLIENT_CODE.match(/^ {2}([a-zA-Z]+):/gm) ?? []).filter(
      (m) => /Enrollment/.test(m) && !/Discovery/.test(m),
    );
    expect(methods.sort()).toEqual([
      "  createEnrollmentInvitation:",
      "  getEnrollmentStatus:",
      "  revokeEnrollment:",
    ]);
  });
});

describe("enrollment page I/O boundary", () => {
  it("performs no direct fetch — all I/O goes through the shared api client", () => {
    expect(PAGE_CODE).not.toMatch(/\bfetch\s*\(/);
    expect(PAGE_CODE).not.toContain("XMLHttpRequest");
    expect(PAGE_CODE).not.toContain("EventSource");
    expect(PAGE_CODE).not.toContain("WebSocket");
  });

  it("calls only the three supported client methods", () => {
    const calls = PAGE_CODE.match(/api\.[a-zA-Z]+/g) ?? [];
    expect([...new Set(calls)].sort()).toEqual([
      "api.createEnrollmentInvitation",
      "api.getEnrollmentStatus",
      "api.revokeEnrollment",
    ]);
  });

  // Bearer-grade material must not outlive the component, and must never enter a URL the browser
  // persists to history.
  it("persists nothing — no storage, no cookie, no history write", () => {
    for (const src of [PAGE_CODE, MODULE_CODE]) {
      expect(src).not.toContain("localStorage");
      expect(src).not.toContain("sessionStorage");
      expect(src).not.toContain("indexedDB");
      expect(src).not.toMatch(/document\.cookie/);
      expect(src).not.toContain("serviceWorker");
      expect(src).not.toContain("history.pushState");
      expect(src).not.toContain("history.replaceState");
      expect(src).not.toContain("useSearchParams");
    }
  });

  // client.ts is included deliberately, and it is the most important of the three: it is where the
  // successful invitation response exists as a live value (the parsed body, before any caller sees
  // it), so it is the one place a stray debug line would print the whole bearer-grade payload. It
  // is clean today — which is exactly the state that quietly stops being true, so it is pinned
  // rather than assumed. The shared client is scanned whole; the enrollment methods are not
  // separable from it for this property.
  it("never logs — the invitation must not reach a console sink", () => {
    for (const src of [PAGE_CODE, MODULE_CODE, CLIENT_CODE]) {
      expect(src).not.toMatch(/console\.\w+/);
    }
  });

  // The tab-local working set exists so an operator can watch several enrollments at once. It must
  // stay a MANUAL working set: a page that quietly re-read every tracked id on a timer would turn
  // an explicit operator action into background traffic against a route that costs the controller
  // a read per row, and would make the "Nothing polls" copy a lie.
  it("never refreshes on a timer — every read is an explicit operator action", () => {
    for (const src of [PAGE_CODE, MODULE_CODE]) {
      expect(src).not.toContain("setInterval");
      expect(src).not.toContain("setTimeout");
      expect(src).not.toContain("requestAnimationFrame");
      expect(src).not.toContain("requestIdleCallback");
    }
    // No effect at all, so there is no place for a fetch-on-mount to appear later either. The
    // page's only I/O is in click handlers.
    expect(PAGE_CODE).not.toContain("useEffect");
    expect(PAGE_CODE).not.toContain("useLayoutEffect");
  });

  it("renders no unescaped markup", () => {
    expect(PAGE_CODE).not.toContain("dangerouslySetInnerHTML");
  });

  /**
   * Every ClosedCodeError on this page is handed a literal empty message, so a backend string is
   * discarded STRUCTURALLY rather than filtered downstream.
   *
   * This is a source assertion on purpose, and it is the only place the property is falsifiable.
   * A rendered-output test cannot see it: `ClosedCodeError` resolves its copy from the code alone
   * and never reads `.message`, so switching these sites to `message: error.text` changes nothing
   * in the document — verified by mutation, which the render suite (correctly) did not catch. The
   * render suite proves the complementary half: real backend prose fed in as a fixture does not
   * reach the document. Together they cover both "the page does not pass it on" and "the page does
   * not render it".
   */
  it("passes a literal empty message at every closed-code error site", () => {
    const sites = PAGE_CODE.match(/error=\{\{[^}]*\}\}/g) ?? [];
    // Anti-vacuity: three error surfaces exist (create, look-up, revoke). A scan that found fewer
    // has stopped matching and must fail here rather than silently checking less.
    expect(sites).toHaveLength(3);
    for (const site of sites) {
      expect(site, site).toContain('message: ""');
      expect(site, site).toMatch(/^error=\{\{ code: \w+Error\.code, message: "" \}\}$/);
    }
  });

  // The hand-off block is now a machine-readable artefact the operator saves to a file. Serialising
  // it here rather than hand-assembling text is what keeps a multi-line value (a PEM) representable
  // and keeps the document parseable by `load_invitation_file`.
  it("serialises the hand-off block rather than concatenating it", () => {
    expect(MODULE_CODE).toContain("JSON.stringify(handoffPayload(invitation), null, 2)");
  });

  it("derives permissions from the server principal, never from a token claim", () => {
    expect(PAGE_CODE).toContain("resolveEnrollmentPermissions");
    for (const decodeish of ["jwtDecode", "decodeJwt", "atob(", "realm_access"]) {
      expect(PAGE_CODE, decodeish).not.toContain(decodeish);
    }
  });

  // The revoke request must carry the revision of an observed status, never a typed value.
  it("takes the revoke revision from the observed status only", () => {
    expect(PAGE_CODE).toContain("observed.revision");
    expect(PAGE_CODE).not.toMatch(/expected_revision:\s*Number\(/);
    expect(PAGE_CODE).not.toMatch(/parseInt/);
  });
});

describe("enrollment route registration", () => {
  it("registers the route inside the authenticated shell", () => {
    expect(MAIN).toContain('path: "worker-enrollment"');
    // It is a child of the AuthBoundary-wrapped layout, not a sibling public route.
    const authIndex = MAIN.indexOf("AuthBoundary");
    expect(MAIN.indexOf('path: "worker-enrollment"')).toBeGreaterThan(authIndex);
  });

  it("adds no public route", () => {
    const publicRoutes = MAIN.match(/path: "\/[a-z/-]*"/g) ?? [];
    expect(publicRoutes.sort()).toEqual(['path: "/"', 'path: "/auth/callback"', 'path: "/login"']);
  });
});
