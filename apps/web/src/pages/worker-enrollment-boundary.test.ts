// Static architecture/security boundary tests for the worker-enrollment UI (SECP-PR5H-B1).
//
// The frontend surface must stay inside the five enrollment routes that take a browser principal —
// create, status, list, revoke and operator-triggered recovery. It must never call the worker-authenticated exchange routes,
// never call the sealed claim-only progression routes, never persist bearer-grade invitation
// material, and never reach an infrastructure module.
//
// The surface is now two pages and a shared panel, so the properties that must hold for all of it
// are asserted over the SURFACE list below rather than over one file — a new page cannot escape
// them by being new.

import { describe, expect, it } from "vitest";

import { ENROLLMENT_CONTROLS } from "./worker-enrollment";
import CLIENT from "../api/client.ts?raw";
import HARNESS from "../dev/A11yHarness.tsx?raw";
import CONTRAST_PROBE from "../dev/contrast-probe.js?raw";
import MAIN from "../main.tsx?raw";
import VITE_CONFIG from "../../vite.config.ts?raw";
import PAGE from "./WorkerEnrollment.tsx?raw";
import MODULE from "./worker-enrollment.ts?raw";
import INVENTORY from "./EnrollmentInventory.tsx?raw";
import INVENTORY_MODULE from "./enrollment-inventory.ts?raw";
import PANEL from "./EnrollmentStatusPanel.tsx?raw";

// Descriptive comments legitimately name the forbidden routes and tokens (that is the point of the
// documentation), so scan CODE only — the invariants are about actual usage.
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}
const CLIENT_CODE = code(CLIENT);
const PAGE_CODE = code(PAGE);
const MODULE_CODE = code(MODULE);
const INVENTORY_CODE = code(INVENTORY);
const INVENTORY_MODULE_CODE = code(INVENTORY_MODULE);
const PANEL_CODE = code(PANEL);

/** Every source file that makes up the enrollment surface. Properties that must hold across the
 *  whole surface are asserted over this list, so adding a file cannot quietly escape them. */
const SURFACE = [
  ["WorkerEnrollment.tsx", PAGE_CODE],
  ["worker-enrollment.ts", MODULE_CODE],
  ["EnrollmentInventory.tsx", INVENTORY_CODE],
  ["enrollment-inventory.ts", INVENTORY_MODULE_CODE],
  ["EnrollmentStatusPanel.tsx", PANEL_CODE],
] as const;

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
  // Three of the five principal-authenticated routes, at their exact paths. The list route and the
  // operator recovery route have their own cases below, because each carries a property this one
  // does not check — org scope, and a revision-only body. Naming this "exactly the three routes"
  // was wrong in a way that mattered: it read as an exhaustive count while asserting a subset.
  it("calls the create, status and revoke routes at their exact paths", () => {
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

  // The list route. Org-scoped by the server; the client must send nothing that could widen it.
  it("calls the org-scoped list route without any organization parameter", () => {
    expect(CLIENT_CODE).toContain('"/api/v1/enrollment"');
    expect(CLIENT_CODE).not.toMatch(/organization_id|organisation|org_id|tenant/i);
  });

  // Operator-triggered recovery is the complement of the controller's scheduled expiry sweep and
  // the second (and last) operator write in the lifecycle. It is a real principal-authenticated
  // route, gated on enrollment:manage in the SERVICE layer, and it carries only a revision.
  it("calls the operator recovery route with a revision and nothing else", () => {
    expect(CLIENT_CODE).toContain("`/api/v1/enrollment/${enrollmentId}/recover`");
    // The refusal reason is server-owned. A caller-supplied reason would be free text crossing the
    // boundary into a bounded-code field.
    const site = CLIENT_CODE.slice(CLIENT_CODE.indexOf("markEnrollmentRecoveryRequired"));
    expect(site.slice(0, 320)).not.toMatch(/reason/);
  });

  it("adds no PR5H enrollment method beyond create, status, list, revoke and recover", () => {
    // Scoped to the supported-enrollment names: the unrelated SECP-B5 target-discovery client
    // methods (listDiscoveryEnrollments / getDiscoveryEnrollment) are a different concept that
    // merely shares the word, and are not in scope for this boundary.
    const methods = (CLIENT_CODE.match(/^ {2}([a-zA-Z]+):/gm) ?? []).filter(
      (m) => /Enrollment/.test(m) && !/Discovery/.test(m),
    );
    expect(methods.sort()).toEqual([
      "  createEnrollmentInvitation:",
      "  getEnrollmentStatus:",
      "  listEnrollments:",
      "  markEnrollmentRecoveryRequired:",
      "  revokeEnrollment:",
    ]);
  });
});

/**
 * The rendered control inventory and this file's client-method pin are two guards over one fact,
 * and they disagreed: `ENROLLMENT_CONTROLS` listed four available controls with no `recover` entry
 * while the client shipped `markEnrollmentRecoveryRequired` and the case above pinned five methods.
 * The wrong one was the guard an operator can actually read, under a heading that frames the list
 * as the controller's routes rather than a roadmap.
 *
 * Neither list is derived from the other — that is deliberate, because a derived list would agree
 * with a mistake as readily as with the truth. They are cross-checked instead, in both directions,
 * so a route added to one and not the other fails here rather than shipping as a false claim.
 */
describe("control inventory agrees with the client's enrollment surface", () => {
  /** `{enrollment_id}` and `${enrollmentId}` are the same path segment written two ways. */
  const canonical = (path: string) =>
    path.replace(/\{enrollment_id\}|\$\{enrollmentId\}/g, ":id");

  /** The route each AVAILABLE control names, keyed by control id. */
  const declared = new Map(
    ENROLLMENT_CONTROLS.filter((c) => c.available).map((c) => [
      c.id,
      canonical(c.detail.match(/\/api\/v1\/enrollment[^\s—]*/)?.[0] ?? ""),
    ]),
  );

  /** Every enrollment route literal the client actually issues. */
  const called = new Set(
    (CLIENT_CODE.match(/\/api\/v1\/enrollment[^"`]*/g) ?? []).map(canonical),
  );

  it("names a real route on every available control", () => {
    // Anti-vacuity: an extraction that silently matched nothing would make both directions below
    // trivially true, so the sets are pinned non-empty and at their expected size first.
    expect(declared.size).toBe(5);
    expect(called.size).toBe(5);
    for (const [id, path] of declared) {
      expect(path, `${id} declares no /api/v1/enrollment route`).not.toBe("");
    }
  });

  it("backs every available control with a route the client calls", () => {
    for (const [id, path] of declared) {
      expect([...called], `control "${id}" declares ${path}, which the client never calls`).toContain(
        path,
      );
    }
  });

  it("declares a control for every enrollment route the client calls", () => {
    const paths = [...declared.values()];
    for (const path of called) {
      expect(paths, `the client calls ${path} with no available control declaring it`).toContain(
        path,
      );
    }
  });
});

describe("enrollment page I/O boundary", () => {
  it("performs no direct fetch — all I/O goes through the shared api client", () => {
    for (const [name, src] of SURFACE) {
      expect(src, name).not.toMatch(/\bfetch\s*\(/);
      expect(src, name).not.toContain("XMLHttpRequest");
      expect(src, name).not.toContain("EventSource");
      expect(src, name).not.toContain("WebSocket");
    }
  });

  it("calls only the four supported client methods from the hand-off page", () => {
    const calls = PAGE_CODE.match(/api\.[a-zA-Z]+/g) ?? [];
    expect([...new Set(calls)].sort()).toEqual([
      "api.createEnrollmentInvitation",
      "api.getEnrollmentStatus",
      "api.markEnrollmentRecoveryRequired",
      "api.revokeEnrollment",
    ]);
  });

  // The inventory is a READ surface plus the one operator write that already exists. It must never
  // reach the create route: minting a bearer-grade invitation from a list page would put the
  // hand-off flow somewhere with no reveal gate and no one-time disclosure.
  it("calls only the read and the two operator writes from the inventory page", () => {
    const calls = INVENTORY_CODE.match(/api\.[a-zA-Z]+/g) ?? [];
    expect([...new Set(calls)].sort()).toEqual([
      "api.getEnrollmentStatus",
      "api.listEnrollments",
      "api.markEnrollmentRecoveryRequired",
      "api.revokeEnrollment",
    ]);
  });

  // The shared panel renders a record. It must stay presentational: a component that fetched would
  // issue a request from wherever it happens to be mounted, and both pages mount it.
  it("keeps the shared status panel free of I/O and of state", () => {
    expect(PANEL_CODE).not.toMatch(/\bapi\./);
    expect(PANEL_CODE).not.toContain("useState");
    expect(PANEL_CODE).not.toContain("useEffect");
  });

  // The keyset cursor is opaque and is echoed, never interpreted. Decoding it would couple the
  // browser to a server-side encoding and turn an opaque token into something a UI reasons about.
  it("never decodes or parses the pagination cursor", () => {
    for (const src of [INVENTORY_CODE, INVENTORY_MODULE_CODE]) {
      expect(src).not.toContain("atob");
      expect(src).not.toContain("JSON.parse");
      expect(src).not.toMatch(/cursor\.(split|slice|match|replace|substring)/);
    }
  });

  /**
   * The recovery cursor makes "continue past the unreadable row" possible, and that is precisely
   * where a client could start deciding which records an operator does not see. It must not.
   *
   * The rule the whole surface turns on: a SERVER-supplied position is not a client-side skip. So
   * the cursor may only ever arrive from a refusal and be echoed back — never built here, never
   * derived from a row, and never used to filter what has already been loaded.
   */
  it("never constructs a recovery position, only echoes the one it was given", () => {
    for (const src of [INVENTORY_CODE, INVENTORY_MODULE_CODE]) {
      // no encoding of a position
      expect(src).not.toContain("btoa");
      expect(src).not.toMatch(/encodeCursor|buildCursor|makeCursor/);
      // no assembling one out of the fields the server encodes into it
      expect(src).not.toMatch(/expires_at\s*\+|enrollment_id\s*\+/);
      // and no dropping rows to work around a bad one
      expect(src).not.toMatch(/\.filter\(\s*\(?\s*\w+\s*\)?\s*=>\s*\w+\.enrollment_id\s*!==/);
    }
    // The one legitimate read is a plain property access off the refusal.
    expect(INVENTORY_MODULE_CODE).toContain("recoveryCursor");
  });

  // Ordering comes from the controller and the cursor continues it. A client-side sort would put
  // the rows in an order the cursor does not continue, so paging would skip records.
  it("never re-sorts the server-ordered page", () => {
    for (const src of [INVENTORY_CODE, INVENTORY_MODULE_CODE]) {
      expect(src).not.toMatch(/\.sort\(/);
      expect(src).not.toMatch(/\.reverse\(/);
    }
  });

  // Bearer-grade material must not outlive the component, and must never enter a URL the browser
  // persists to history.
  it("persists nothing — no storage, no cookie, no history write", () => {
    for (const [, src] of SURFACE) {
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
    for (const [name, src] of [...SURFACE, ["client.ts", CLIENT_CODE] as const]) {
      expect(src, name).not.toMatch(/console\.\w+/);
    }
  });

  // The tab-local working set exists so an operator can watch several enrollments at once. It must
  // stay a MANUAL working set: a page that quietly re-read every tracked id on a timer would turn
  // an explicit operator action into background traffic against a route that costs the controller
  // a read per row, and would make the "Nothing polls" copy a lie.
  it("never refreshes on a timer — every read is an explicit operator action", () => {
    for (const [name, src] of SURFACE) {
      expect(src, name).not.toContain("setInterval");
      expect(src, name).not.toContain("setTimeout");
      expect(src, name).not.toContain("requestAnimationFrame");
      expect(src, name).not.toContain("requestIdleCallback");
    }
    // There IS one effect now — it moves focus after a dismissal, because a browser drops focus
    // to <body> when the focused control's card unmounts. So the blanket "no useEffect" ban was
    // replaced rather than deleted: what must never appear in an effect is I/O, since a
    // fetch-on-mount would make this page issue requests the operator never asked for.
    //
    // Same hardened-slice discipline as environment-publication-boundary: prove the anchor,
    // bound the slice, prove the slice has real content, and only then assert about it — a scan
    // that stops matching must fail loudly instead of scanning an empty string and passing.
    // Both pages hold exactly one effect and both move focus: the hand-off page after a dismissal
    // unmounts the focused control, the inventory after a selection renders a record below the
    // table. Each is asserted the same way and each must stay free of I/O.
    for (const [name, src] of [
      ["WorkerEnrollment.tsx", PAGE_CODE],
      ["EnrollmentInventory.tsx", INVENTORY_CODE],
    ] as const) {
      const effects = src.split("useEffect(").slice(1);
      expect(effects, `${name}: no effect found - re-anchor this scan`).toHaveLength(1);
      for (const body of effects) {
        const end = body.indexOf("}, [");
        expect(end, `${name}: unterminated effect - the slice would run to end of file`,
        ).toBeGreaterThan(-1);
        const block = body.slice(0, end);
        expect(block, `${name}: the effect slice is empty - the scan is not reading the body`,
        ).toContain("focus");
        expect(block, name).not.toMatch(/api\./);
        expect(block, name).not.toMatch(/setInterval|setTimeout|fetch\(/);
      }
      expect(src, name).not.toContain("useLayoutEffect");
    }
  });

  /**
   * The clipboard is a real exfiltration path for a capability, and exactly ONE surface may touch
   * it: the hand-off page, for the hand-off block, on an explicit operator action. The inventory
   * and the shared panel render only the bounded status projection and have no business there —
   * and if a copy affordance were ever added to a row, this is where it would be noticed.
   */
  it("touches the clipboard only on the hand-off page", () => {
    expect(PAGE_CODE).toContain("navigator.clipboard");
    for (const [name, src] of SURFACE) {
      if (name === "WorkerEnrollment.tsx") continue;
      expect(src, name).not.toContain("clipboard");
      expect(src, name).not.toContain("execCommand");
    }
  });

  /**
   * The invitation is a capability, not just data: the first valid binder wins. So the bearer
   * fields must not appear ANYWHERE outside the hand-off page — not in the inventory, not in the
   * shared panel, and not in either view model. The status projection deliberately carries none of
   * them, and this pins that no code path reintroduces one by name.
   */
  it("names no bearer-grade invitation field outside the hand-off surface", () => {
    const bearer = [
      "invitation_id",
      "controller_trust_anchor_hex",
      "controller_key_id",
      "transaction_id",
      "release_digest",
      "controller_origin",
    ];
    for (const [name, src] of SURFACE) {
      if (name === "WorkerEnrollment.tsx" || name === "worker-enrollment.ts") continue;
      for (const field of bearer) {
        expect(src, `${name}: ${field}`).not.toContain(field);
      }
      // ...and no route that could return one
      expect(src, name).not.toContain("createEnrollmentInvitation");
    }
  });

  it("renders no unescaped markup", () => {
    for (const [name, src] of SURFACE) {
      expect(src, name).not.toContain("dangerouslySetInnerHTML");
    }
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
    // Anti-vacuity: the expected count per file is pinned, so a scan that stopped matching — or a
    // file that grew an error surface without this test being looked at — fails loudly here rather
    // than silently checking less. Two on the hand-off page (create, look-up), one on the shared
    // panel (revoke), two on the inventory (list, re-read).
    const expected: ReadonlyArray<readonly [string, string, number]> = [
      // three: create, look-up, and a refused ROW refresh — which is its own surface on purpose,
      // so a row failure is not reported under the look-up control the operator never touched
      ["WorkerEnrollment.tsx", PAGE_CODE, 3],
      // two: revoke and operator-triggered recovery, the lifecycle's only operator writes
      ["EnrollmentStatusPanel.tsx", PANEL_CODE, 2],
      ["EnrollmentInventory.tsx", INVENTORY_CODE, 2],
    ];
    for (const [name, src, count] of expected) {
      const sites = src.match(/error=\{\{[^}]*\}\}/g) ?? [];
      expect(sites, name).toHaveLength(count);
      for (const site of sites) {
        expect(site, `${name}: ${site}`).toContain('message: ""');
        expect(site, `${name}: ${site}`).toMatch(
          /^error=\{\{ code: \w+Error\.code, message: "" \}\}$/,
        );
      }
    }
  });

  // The hand-off block is now a machine-readable artefact the operator saves to a file. Serialising
  // it here rather than hand-assembling text is what keeps the document parseable by
  // `load_invitation_file`, and what keeps it correct for any string the contract permits —
  // including one containing a newline, which a line-delimited block would split in two.
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

/**
 * The dev-only accessibility harness must stay dev-only.
 *
 * It is excluded from the shipped bundle by CONSTRUCTION — `vite build` takes `index.html` as its
 * only input — which is correct but was pinned by nothing: adding `rollupOptions.input`, or moving
 * `a11y-harness.html` into `public/`, would start shipping it without any test noticing. Keeping a
 * harness for repeatable verification and then leaving its own boundary unenforced would be the
 * exact failure this suite exists to prevent.
 *
 * These are static checks on the two mechanisms that would actually ship it. They do not replace
 * inspecting `dist/` after a build, which is also done; they make the regression fail in CI
 * instead of only under a human who remembers to look.
 */
describe("dev harness stays out of the product", () => {
  it("declares no extra build inputs, so index.html remains the only entry", () => {
    // Anti-vacuity: prove the config was really read before asserting about what it lacks.
    expect(VITE_CONFIG).toContain("defineConfig");
    expect(VITE_CONFIG).toContain("plugins");
    expect(VITE_CONFIG).not.toContain("rollupOptions");
    expect(VITE_CONFIG).not.toContain("rolldownOptions");
    expect(VITE_CONFIG).not.toContain("a11y-harness");
  });

  it("is not reachable from the application entry", () => {
    expect(MAIN).not.toContain("A11yHarness");
    expect(MAIN).not.toContain("dev/");
  });

  // Same property, same reasoning, for the real-DOM test harness: it pulls axe-core and a React
  // test root into the graph of anything that imports it, so it must stay reachable only from
  // test files. `vite build` takes index.html as its only input, which is what makes that true;
  // this pins that no product source has started importing it anyway.
  // The measured contrast probe is dev-only too, and it must stay a probe: it may READ computed
  // style, and it must never be wired into the product or reach for the API.
  it("keeps the contrast probe read-only and out of the product", () => {
    expect(MAIN).not.toContain("contrast-probe");
    for (const [name, src] of SURFACE) {
      expect(src, name).not.toContain("contrast-probe");
    }
    const probe = code(CONTRAST_PROBE);
    expect(probe).toContain("getComputedStyle");
    expect(probe).not.toMatch(/\bapi\./);
    expect(probe).not.toMatch(/\bfetch\s*\(/);
    expect(probe).not.toMatch(/\.(textContent|innerHTML|className)\s*=/);
  });

  it("keeps the real-DOM test harness out of every product source file", () => {
    for (const [name, src] of SURFACE) {
      expect(src, name).not.toContain("testing/dom-a11y");
      expect(src, name).not.toContain("axe-core");
    }
    expect(MAIN).not.toContain("testing/");
    expect(CLIENT_CODE).not.toContain("testing/");
  });

  /**
   * A harness fixture that drifts from the product is worse than no harness: a browser
   * accessibility pass reads live-region text off it, so the one string being verified by eye
   * becomes copy the product does not emit. That already happened once — the fixture kept "more
   * pages remain" after the product was corrected to "there may be more", because a cursor means
   * the page came back full, not that another row exists.
   *
   * Pinned as an exclusion rather than an equality: the fixture is allowed to say something the
   * product could say, and must never say something the product cannot.
   */
  it("uses live-region copy the product can actually emit", () => {
    // Comments legitimately explain the phrasing that was corrected away, so scan CODE only —
    // the same rule this file applies to forbidden routes and tokens.
    const harness = code(HARNESS);
    expect(harness).toContain("There may be more.");
    expect(harness).not.toMatch(/more pages remain/i);
    // Anti-vacuity, and the real assertion: every fixture notice ends the way the product ends.
    const notices = harness.match(/liveNotice: "[^"]*"/g) ?? [];
    expect(notices.length, "no liveNotice fixture found - re-anchor this scan").toBeGreaterThan(0);
    for (const notice of notices) {
      expect(notice, notice).toMatch(/(There may be more\.|No further pages\.)"$/);
    }
  });

  // The harness renders the shipped component; the moment it stops doing that it is a second
  // implementation whose findings say nothing about the product.
  it("renders the real component and models no controller behaviour", () => {
    expect(HARNESS).toContain("WorkerEnrollmentView");
    const code = HARNESS.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
    expect(code).not.toMatch(/\bapi\./);
    expect(code).not.toMatch(/\bfetch\s*\(/);
    expect(code).not.toContain("XMLHttpRequest");
  });
});

describe("enrollment route registration", () => {
  it("registers both routes inside the authenticated shell", () => {
    // It is a child of the AuthBoundary-wrapped layout, not a sibling public route.
    const authIndex = MAIN.indexOf("AuthBoundary");
    for (const path of ["worker-enrollment", "enrollment-inventory"]) {
      expect(MAIN, path).toContain(`path: "${path}"`);
      expect(MAIN.indexOf(`path: "${path}"`), path).toBeGreaterThan(authIndex);
    }
  });

  it("adds no public route", () => {
    const publicRoutes = MAIN.match(/path: "\/[a-z/-]*"/g) ?? [];
    expect(publicRoutes.sort()).toEqual(['path: "/"', 'path: "/auth/callback"', 'path: "/login"']);
  });
});
