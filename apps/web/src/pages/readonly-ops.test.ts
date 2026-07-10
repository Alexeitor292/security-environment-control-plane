import type {
  BootstrapSession,
  PreflightAuthorization,
  ReadonlyPreflight,
  ResolverActivation,
} from "../api/types";
import { resolveClosedCodeCopy } from "../components/ui/closed-code-error";
import {
  BOOTSTRAP_ERROR_TEXT,
  BOOTSTRAP_RESPONSIBILITY,
  CREDENTIAL_UNAVAILABLE_NOTICE,
  READONLY_COMMON_CODES,
  READY_TO_QUEUE_NOTICE,
  RESOLVER_INTRO,
  WORKER_BUNDLE_OWNERSHIP_NOTICE,
  bootstrapStepItems,
  preflightAuthorizationView,
  preflightHistoryRows,
  resolverAuthBadgeState,
  resolverGates,
} from "./readonly-ops";
import { API_ERROR_TEXT as PREFLIGHT_ERRORS } from "./readonly-preflight";
import { STEP_LABELS } from "./read-only-bootstrap";

const NOW = new Date("2026-07-10T12:00:00Z");

const auth = (
  status: string,
  expiry: string,
  version = 2,
): PreflightAuthorization =>
  ({
    id: `a-${status}`,
    status,
    authorization_expiry: expiry,
    authorization_version: version,
    created_at: "2026-07-10T10:00:00Z",
  }) as PreflightAuthorization;

const preflight = (
  created: string,
  status: ReadonlyPreflight["status"],
  outcome: ReadonlyPreflight["outcome_code"],
): ReadonlyPreflight =>
  ({ id: `p-${created}`, created_at: created, status, outcome_code: outcome }) as ReadonlyPreflight;

describe("preflightAuthorizationView", () => {
  it("shows approved+unexpired distinctly from expired and revoked", () => {
    expect(preflightAuthorizationView(auth("approved", "2026-07-10T12:26:00Z"), NOW)).toMatchObject(
      { state: "approved", stateLabel: "Approved", remainingMinutes: 26, scope: "GET-only readiness reads" },
    );
    expect(preflightAuthorizationView(auth("approved", "2026-07-10T11:00:00Z"), NOW)).toMatchObject(
      { state: "expired", stateLabel: "Expired", remainingMinutes: 0 },
    );
    expect(preflightAuthorizationView(auth("revoked", "2026-07-10T13:00:00Z"), NOW).state).toBe(
      "revoked",
    );
    expect(preflightAuthorizationView(auth("draft", "2026-07-10T13:00:00Z"), NOW).state).toBe(
      "draft",
    );
  });
});

describe("preflightHistoryRows", () => {
  it("distinguishes queued/running (worker-owned) from completed and ready", () => {
    const rows = preflightHistoryRows([
      preflight("2026-07-10T09:00:00Z", "queued", null),
      preflight("2026-07-10T11:00:00Z", "completed", "ready"),
      preflight("2026-07-10T10:00:00Z", "completed", "credential_unavailable"),
    ]);
    // newest first
    expect(rows[0]).toMatchObject({ status: "completed", ready: true, workerOwned: false });
    expect(rows[1]).toMatchObject({ outcome: "Credential unavailable", expectedSealed: true, ready: false });
    expect(rows[2]).toMatchObject({ status: "queued", workerOwned: true, ready: false });
  });

  it("returns nothing for an unavailable source (never a false empty)", () => {
    expect(preflightHistoryRows(null)).toEqual([]);
  });

  it("credential_unavailable copy frames the sealed result as expected and no-contact", () => {
    expect(CREDENTIAL_UNAVAILABLE_NOTICE).toContain("expected fail-closed");
    expect(CREDENTIAL_UNAVAILABLE_NOTICE).toContain("No endpoint was contacted");
  });
});

describe("resolverGates", () => {
  const activation = (status: string, evidence: { status: string }[] = []): ResolverActivation =>
    ({ id: "r1", status, authorization_version: 2, evidence }) as ResolverActivation;

  it("keeps resolver, worker activation, and collector sealed even for an approved authorization", () => {
    const gates = resolverGates(activation("approved", [{ status: "verified" }]));
    const byId = Object.fromEntries(gates.map((g) => [g.id, g]));
    expect(byId["authorization"].state).toBe("active");
    expect(byId["authorization"].status).toContain("sealed, not active");
    expect(byId["worker-activation"].state).toBe("sealed");
    expect(byId["resolver-backend"].state).toBe("sealed");
    expect(byId["resolver-backend"].status).toBe("Not configured");
    expect(byId["collector"].state).toBe("sealed");
    expect(byId["collector"].status).toBe("Never constructed");
  });

  it("renders zero/unknown accurately rather than fake completion", () => {
    const gates = resolverGates(null);
    const byId = Object.fromEntries(gates.map((g) => [g.id, g]));
    expect(byId["authorization"].status).toBe("None for this target");
    expect(byId["trust"].status).toBe("Not established");
    // Nothing is ever 'complete' from this interface.
    expect(gates.some((g) => g.state === "complete")).toBe(false);
  });

  it("intro states the gates are cumulative, independent, and non-activating", () => {
    expect(RESOLVER_INTRO).toContain("cumulative and independent");
    expect(RESOLVER_INTRO.toLowerCase()).toContain("performs no activation");
  });

  it("badge state reads expired for an approved authorization past expiry", () => {
    const past = { status: "approved", authorization_expiry: "2026-07-10T11:00:00Z" } as ResolverActivation;
    const future = { status: "approved", authorization_expiry: "2026-07-10T13:00:00Z" } as ResolverActivation;
    expect(resolverAuthBadgeState(past, NOW)).toBe("expired");
    expect(resolverAuthBadgeState(future, NOW)).toBe("approved");
    expect(resolverAuthBadgeState({ status: "revoked" } as ResolverActivation, NOW)).toBe("revoked");
  });
});

describe("bootstrapStepItems", () => {
  const session = (status: string): BootstrapSession =>
    ({ id: "s1", status }) as BootstrapSession;

  it("marks completed steps without implying discovery ran", () => {
    // status 'bound' -> currentStep 'run-discovery'
    const items = bootstrapStepItems(STEP_LABELS, session("bound"));
    expect(items.find((i) => i.id === "run-discovery")!.state).toBe("current");
    expect(items.find((i) => i.id === "create")!.state).toBe("complete");
    expect(READY_TO_QUEUE_NOTICE).toContain("not that discovery ran");
  });

  it("before any session, only the first step is current", () => {
    const items = bootstrapStepItems(STEP_LABELS, null);
    expect(items[0].state).toBe("current");
    expect(items.slice(1).every((i) => i.state === "blocked")).toBe(true);
  });

  it("labels responsibility owners and separates worker from app", () => {
    expect(BOOTSTRAP_RESPONSIBILITY.create).toBe("App");
    expect(BOOTSTRAP_RESPONSIBILITY["run-script"]).toBe("Human operator");
    expect(BOOTSTRAP_RESPONSIBILITY["run-discovery"]).toBe("Worker");
    expect(WORKER_BUNDLE_OWNERSHIP_NOTICE.toLowerCase()).toContain("worker");
    expect(WORKER_BUNDLE_OWNERSHIP_NOTICE).toContain("never handles worker private material");
    const items = bootstrapStepItems(STEP_LABELS, null);
    expect(items[1].label).toContain("Human operator");
  });
});

describe("closed-code maps", () => {
  it("map real codes to fixed copy and never the backend message", () => {
    const merged = { ...READONLY_COMMON_CODES, ...PREFLIGHT_ERRORS };
    const copy = resolveClosedCodeCopy(
      Object.assign(new Error("raw backend: bootstrap_session_not_found at :8006"), {
        code: "readonly_preflight_queue_conflict",
      }),
      merged,
    );
    expect(copy.text).toBe(PREFLIGHT_ERRORS.readonly_preflight_queue_conflict);
    expect(copy.text).not.toContain("8006");
  });

  it("maps the generic domain_error services actually raise, and grant-permission forbidden", () => {
    expect(
      resolveClosedCodeCopy(Object.assign(new Error("x"), { code: "domain_error" }), READONLY_COMMON_CODES).text,
    ).toBe(READONLY_COMMON_CODES.domain_error);
    expect(BOOTSTRAP_ERROR_TEXT.forbidden.toLowerCase()).toContain("staging_substrate:manage");
  });

  it("guards malformed and prototype-key codes", () => {
    expect(
      resolveClosedCodeCopy(Object.assign(new Error("x"), { code: "Trace at :9 !!" }), READONLY_COMMON_CODES).code,
    ).toBe("error");
    for (const code of ["constructor", "toString", "__proto__"]) {
      const copy = resolveClosedCodeCopy(Object.assign(new Error("x"), { code }), READONLY_COMMON_CODES);
      expect(typeof copy.text).toBe("string");
      expect(copy.text).not.toContain("function");
    }
  });

  it("keeps all fixed copy free of endpoints and secret material", () => {
    const all = [
      ...Object.values(READONLY_COMMON_CODES),
      ...Object.values(BOOTSTRAP_ERROR_TEXT),
      CREDENTIAL_UNAVAILABLE_NOTICE,
      RESOLVER_INTRO,
      READY_TO_QUEUE_NOTICE,
      WORKER_BUNDLE_OWNERSHIP_NOTICE,
    ];
    for (const text of all) {
      expect(text).not.toMatch(/:\/\//);
      expect(text).not.toMatch(/:\d{4,5}\b/);
      // No rendered private-key material (the phrase "never a private key" is
      // legitimate safety guidance, so match the PEM marker, not the words).
      expect(text).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
      expect(text.toLowerCase()).not.toContain("password");
    }
  });
});
