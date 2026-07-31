import { describe, expect, it } from "vitest";

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import {
  ENROLLMENT_CONTROLS,
  ENROLLMENT_FORWARD_STATES,
  MISSING_MANAGE_REASON,
  MISSING_READ_REASON,
  NOT_ESTABLISHED,
  TRACKED_FILTERS,
  TRACKED_FILTER_LABELS,
  TRACKED_LIMIT,
  TTL_MAX_SECONDS,
  addTracked,
  createGate,
  encodeIdempotencyKey,
  enrollmentEvidence,
  enrollmentStepItems,
  expiryView,
  filterTracked,
  handoffFields,
  handoffPayload,
  handoffText,
  isEnrollmentId,
  isIdempotencyKey,
  isPastExpiry,
  isTerminalState,
  lookupGate,
  parseEnrollmentId,
  parseTtlSeconds,
  recoveryView,
  removeTracked,
  resolveEnrollmentPermissions,
  revokeGate,
  shouldWarnManageWithoutRead,
  siteLabelOf,
  statusDetailRows,
  trackedFromInvitation,
  trackedFromStatus,
  trackedGroup,
  trackedSummary,
  validateSiteLabel,
  verificationContext,
  type TrackedEnrollment,
} from "./worker-enrollment";

const ID = "sha256:" + "a".repeat(64);

function invitation(over: Partial<EnrollmentInvitation> = {}): EnrollmentInvitation {
  return {
    enrollment_id: ID,
    invitation_id: "sha256:" + "b".repeat(64),
    controller_installation_id: "controller-aaaaaaaa",
    controller_key_id: "sha256:" + "c".repeat(64),
    controller_trust_anchor_hex: "d".repeat(64),
    controller_origin: "https://controller.example",
    release_digest: "sha256:" + "e".repeat(64),
    transaction_id: "txn-0123456789abcdef",
    deployment_site_label: "site-one",
    created_at: "2026-07-30T10:00:00+00:00",
    expires_at: "2026-07-30T11:00:00+00:00",
    state: "invited",
    revision: 0,
    ...over,
  };
}

function status(over: Partial<EnrollmentStatus> = {}): EnrollmentStatus {
  return {
    enrollment_id: ID,
    state: "invited",
    revision: 0,
    controller_installation_id: "controller-aaaaaaaa",
    controller_key_fingerprint: "cccccccccccc",
    worker_installation_id: "",
    worker_key_fingerprint: "",
    release_fingerprint: "eeeeeeeeeeee",
    offer_fingerprint: "",
    result_fingerprint: "",
    expires_at: "2026-07-30T11:00:00+00:00",
    updated_at: "2026-07-30T10:00:00+00:00",
    refusal_reason: "",
    deployment_site_label: "site-one",
    ...over,
  };
}

const NOW = Date.parse("2026-07-30T10:00:00+00:00");

// --------------------------------------------------------------------- id grammar

describe("enrollment id grammar", () => {
  it("accepts exactly sha256 + 64 lowercase hex", () => {
    expect(isEnrollmentId(ID)).toBe(true);
  });

  it("rejects wrong length, uppercase hex, and a missing prefix", () => {
    expect(isEnrollmentId("sha256:" + "a".repeat(63))).toBe(false);
    expect(isEnrollmentId("sha256:" + "a".repeat(65))).toBe(false);
    expect(isEnrollmentId("sha256:" + "A".repeat(64))).toBe(false);
    expect(isEnrollmentId("a".repeat(64))).toBe(false);
    expect(isEnrollmentId("sha512:" + "a".repeat(64))).toBe(false);
  });

  // The validated value is interpolated into a request path, so anything that could change the
  // path's shape must be refused before it reaches the client.
  it("rejects values carrying path, query or traversal characters", () => {
    for (const bad of [
      "sha256:" + "a".repeat(63) + "/",
      "../../api/v1/enrollment",
      "sha256:" + "a".repeat(64) + "?x=1",
      "sha256:" + "a".repeat(64) + "#frag",
      "sha256:" + "a".repeat(64) + "/revoke",
    ]) {
      expect(isEnrollmentId(bad), bad).toBe(false);
    }
  });

  it("forgives surrounding whitespace because ids are pasted, never typed", () => {
    const parsed = parseEnrollmentId(`  ${ID}\n`);
    expect(parsed.ok).toBe(true);
    expect(parsed.value).toBe(ID);
  });

  it("reports an empty id distinctly from a malformed one", () => {
    expect(parseEnrollmentId("   ").error).toBe("Enter an enrollment id.");
    expect(parseEnrollmentId("nope").error).toContain("64 hexadecimal");
  });
});

// --------------------------------------------------------------------- site label

describe("deployment site label", () => {
  it("accepts the backend grammar", () => {
    for (const good of ["site-one", "A", "a.b_c-d", "0" + "z".repeat(119)]) {
      expect(validateSiteLabel(good).ok, good).toBe(true);
    }
  });

  it("rejects a leading separator, over-length, and forbidden characters", () => {
    for (const bad of ["-site", ".site", "_site", "a".repeat(121), "a/b", "a:b", "a b", "a@b"]) {
      expect(validateSiteLabel(bad).ok, bad).toBe(false);
    }
  });

  it("rejects empty with its own message", () => {
    expect(validateSiteLabel("  ").error).toBe("Enter a deployment site label.");
  });
});

// --------------------------------------------------------------------- ttl

describe("invitation lifetime", () => {
  it("accepts the inclusive backend bounds", () => {
    expect(parseTtlSeconds("1")).toEqual({ ok: true, value: 1 });
    expect(parseTtlSeconds(String(TTL_MAX_SECONDS)).ok).toBe(true);
  });

  it("rejects zero, over-max, and anything not a whole number", () => {
    expect(parseTtlSeconds("0").ok).toBe(false);
    expect(parseTtlSeconds(String(TTL_MAX_SECONDS + 1)).ok).toBe(false);
    for (const bad of ["-1", "1.5", "1e3", "", "abc", " "]) {
      expect(parseTtlSeconds(bad).ok, bad).toBe(false);
    }
  });
});

// --------------------------------------------------------------------- idempotency key

describe("idempotency key encoding", () => {
  it("matches base64url on the standard vectors, unpadded", () => {
    const bytes = (s: string) => Uint8Array.from([...s].map((c) => c.charCodeAt(0)));
    expect(encodeIdempotencyKey(bytes("Man"))).toBe("TWFu");
    expect(encodeIdempotencyKey(bytes("Ma"))).toBe("TWE");
    expect(encodeIdempotencyKey(bytes("M"))).toBe("TQ");
  });

  it("uses the url-safe alphabet — never '+' or '/'", () => {
    const out = encodeIdempotencyKey(Uint8Array.from([0xff, 0xff, 0xff, 0xfb, 0xff]));
    expect(out).not.toContain("+");
    expect(out).not.toContain("/");
    expect(out).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("encodes 32 random-sized bytes inside the backend's 22-128 bound", () => {
    const key = encodeIdempotencyKey(new Uint8Array(32));
    expect(key).toHaveLength(43);
    expect(isIdempotencyKey(key)).toBe(true);
  });

  it("rejects keys outside the backend grammar", () => {
    expect(isIdempotencyKey("short")).toBe(false);
    expect(isIdempotencyKey("a".repeat(129))).toBe(false);
    expect(isIdempotencyKey("has spaces in it and is long enough")).toBe(false);
  });
});

// --------------------------------------------------------------------- lifecycle rail

describe("lifecycle rail", () => {
  it("marks earlier states complete and the reached state current", () => {
    const items = enrollmentStepItems("offer_transported");
    expect(items.map((i) => i.state)).toEqual([
      "complete",
      "complete",
      "current",
      "blocked",
      "blocked",
      "blocked",
    ]);
  });

  it("treats healthy as complete, not as an in-flight step", () => {
    const items = enrollmentStepItems("healthy");
    expect(items.every((i) => i.state === "complete")).toBe(true);
  });

  it("blocks every step for a terminal and names the terminal as the reason", () => {
    for (const terminal of ["refused", "recovery_required"]) {
      const items = enrollmentStepItems(terminal);
      expect(items.every((i) => i.state === "blocked"), terminal).toBe(true);
      expect(items[0].blockedReason, terminal).toBeTruthy();
    }
    expect(enrollmentStepItems("refused")[0].blockedReason).toContain("no worker enrolled");
  });

  // A backend that moved ahead of this build must not be rendered as though it were at step one.
  it("blocks everything for an unrecognised state rather than guessing a position", () => {
    const items = enrollmentStepItems("some_future_state");
    expect(items.every((i) => i.state === "blocked")).toBe(true);
    expect(items[0].blockedReason).toContain("does not recognise");
  });

  it("never offers a rail entry for the two terminals", () => {
    const ids = enrollmentStepItems("invited").map((i) => i.id);
    expect(ids).not.toContain("refused");
    expect(ids).not.toContain("recovery_required");
    expect(ids).toEqual([...ENROLLMENT_FORWARD_STATES]);
  });

  it("classifies the terminals", () => {
    expect(isTerminalState("refused")).toBe(true);
    expect(isTerminalState("recovery_required")).toBe(true);
    expect(isTerminalState("invited")).toBe(false);
    expect(isTerminalState("healthy")).toBe(false);
  });
});

// --------------------------------------------------------------------- expiry

describe("expiry view", () => {
  it("reports a coarse remaining duration", () => {
    expect(expiryView("2026-07-30T11:00:00+00:00", NOW).label).toBe("Expires in 1 hour");
    expect(expiryView("2026-07-30T10:00:30+00:00", NOW).label).toBe("Expires in 30 seconds");
    expect(expiryView("2026-07-30T10:05:00+00:00", NOW).label).toBe("Expires in 5 minutes");
    expect(expiryView("2026-07-30T11:30:00+00:00", NOW).label).toBe("Expires in 1 h 30 min");
  });

  it("treats the exact expiry instant as expired", () => {
    const view = expiryView("2026-07-30T10:00:00+00:00", NOW);
    expect(view.expired).toBe(true);
    expect(view.label).toBe("Expired");
  });

  it("never guesses when the timestamp will not parse", () => {
    const view = expiryView("not-a-time", NOW);
    expect(view.valid).toBe(false);
    expect(view.expired).toBe(false);
    expect(view.label).toBe("Expiry unavailable");
  });
});

// --------------------------------------------------------------------- hand-off

/**
 * Search a serialised artefact for a value the way JSON can legitimately encode it.
 *
 * `handoffText` is `JSON.stringify` output, so a value containing a real newline is emitted as the
 * two characters `\` and `n`. A naive `text.includes(value)` for a multi-line value therefore can
 * NEVER match — which makes `expect(text).not.toContain(value)` pass whether or not the value
 * leaked: an assertion that silently stopped testing anything, while still looking green. Every
 * exclusion below searches BOTH forms, and each exclusion block opens with a positive control
 * proving this same search can still find something that IS present.
 */
function jsonEncoded(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}
function appearsIn(serialised: string, value: string): boolean {
  return serialised.includes(value) || serialised.includes(jsonEncoded(value));
}

/**
 * A multi-line fixture, in the shape of the value most likely to be one in practice.
 *
 * No field on `EnrollmentInvitation` is multi-line today, and none is planned — the controller CA
 * reaches the worker through the CLI's own invitation file, not the API response. This fixture is
 * NOT anticipating a field. It exists because every hand-off field is typed as an unconstrained
 * server-chosen string: nothing in this contract forbids a newline, so the serialisation and every
 * assertion about it must be correct for one. The old line-delimited format was not.
 */
const PEM = "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n";

const HANDOFF_KEYS = [
  "enrollment_id",
  "invitation_id",
  "controller_installation_id",
  "controller_key_id",
  "controller_origin",
  "transaction_id",
  "release_digest",
  "expires_at",
];

describe("hand-off material", () => {
  it("is exactly the eight fields the shipped worker transport consumes", () => {
    expect(handoffFields(invitation()).map((f) => f.key)).toEqual(HANDOFF_KEYS);
  });

  // Replaces the previous "one stable key: value line per field" line assertions. Those pinned a
  // format; this pins the CONTRACT — the key set of the parsed document — which is strictly
  // stronger, because it is what `load_invitation_file` actually checks and it cannot be satisfied
  // by text that merely looks right.
  it("parses as JSON whose key set is exactly the hand-off contract", () => {
    expect(Object.keys(JSON.parse(handoffText(invitation())))).toEqual(HANDOFF_KEYS);
  });

  // apps/management/secp_management/enrollment_cli.py:_REQUIRED_INVITATION_KEYS. Emitting the
  // worker-facing name would produce a file load_invitation_file() refuses outright.
  it("uses the API's own field names so the shipped CLI parser reads the file unchanged", () => {
    const parsed = JSON.parse(handoffText(invitation()));
    expect(parsed.transaction_id).toBe("txn-0123456789abcdef");
    expect(Object.prototype.hasOwnProperty.call(parsed, "controller_transaction_id")).toBe(
      false,
    );
  });

  it("keeps the worker-facing name visible to humans through the label, not the key", () => {
    const field = handoffFields(invitation()).find((f) => f.key === "transaction_id");
    expect(field?.label).toBe("Controller transaction id");
  });

  it("emits every value as a string, which is what the parser requires", () => {
    const parsed = JSON.parse(handoffText(invitation()));
    for (const [key, value] of Object.entries(parsed)) expect(typeof value, key).toBe("string");
  });

  it("round-trips: parsing the block yields exactly the payload it was built from", () => {
    expect(JSON.parse(handoffText(invitation()))).toEqual(handoffPayload(invitation()));
  });

  it("carries a multi-line value intact, which the previous line-delimited format could not", () => {
    const text = handoffText(invitation({ controller_origin: PEM }));
    expect(() => JSON.parse(text)).not.toThrow();
    expect(JSON.parse(text).controller_origin).toBe(PEM);
    // The embedded newlines are escaped rather than breaking the document apart.
    expect(text).toContain("\\n");
  });

  // The enumeration is explicit ON PURPOSE. This is the test that fails if anyone replaces it with
  // Object.entries(invitation): a field added to the API type must not be able to auto-render into
  // a bearer-grade block that gets copied to a worker. Omission over leakage.
  it("never auto-renders a field that was added to the invitation type", () => {
    const withExtra = {
      ...invitation(),
      some_future_field: "FUTURE-VALUE-NOT-TO-BE-EMITTED",
    } as unknown as EnrollmentInvitation;
    const text = handoffText(withExtra);
    expect(Object.keys(JSON.parse(text))).toEqual(HANDOFF_KEYS);
    expect(appearsIn(text, "FUTURE-VALUE-NOT-TO-BE-EMITTED")).toBe(false);
  });

  // The block is bearer-grade: it carries what the worker needs and nothing more.
  it("omits the trust anchor, the site label and the server-owned lifecycle fields", () => {
    const text = handoffText(invitation());

    // POSITIVE CONTROL — asserted BEFORE the exclusions, using the identical search. If escaping
    // ever made `appearsIn` unable to match, this fails on its own control instead of leaving the
    // exclusions below green and vacuous.
    for (const present of Object.values(handoffPayload(invitation()))) {
      expect(appearsIn(text, present), present).toBe(true);
    }
    // The multi-line case specifically — the one the verbatim branch cannot find.
    expect(appearsIn(handoffText(invitation({ controller_origin: PEM })), PEM)).toBe(true);
    expect(handoffText(invitation({ controller_origin: PEM })).includes(PEM)).toBe(false);

    expect(appearsIn(text, "d".repeat(64))).toBe(false); // controller_trust_anchor_hex
    expect(appearsIn(text, "site-one")).toBe(false); // deployment_site_label
    expect(text).not.toContain("revision");
    expect(text).not.toContain("created_at");
  });
});

// --------------------------------------------------------------------- permissions

describe("permission resolution", () => {
  it("reads the two dedicated permissions and infers neither from the other", () => {
    expect(resolveEnrollmentPermissions(["enrollment:read"])).toEqual({
      read: true,
      manage: false,
    });
    expect(resolveEnrollmentPermissions(["enrollment:manage"])).toEqual({
      read: false,
      manage: true,
    });
    expect(resolveEnrollmentPermissions([])).toEqual({ read: false, manage: false });
    expect(resolveEnrollmentPermissions(null)).toEqual({ read: false, manage: false });
  });

  // Mirrors the backend's pinned decision that manage does not imply read.
  it("warns exactly when the principal can manage but not read", () => {
    expect(shouldWarnManageWithoutRead({ read: false, manage: true })).toBe(true);
    expect(shouldWarnManageWithoutRead({ read: true, manage: true })).toBe(false);
    expect(shouldWarnManageWithoutRead({ read: false, manage: false })).toBe(false);
    expect(shouldWarnManageWithoutRead({ read: true, manage: false })).toBe(false);
  });

  it("never infers enrollment permissions from a neighbouring capability", () => {
    const p = resolveEnrollmentPermissions([
      "worker_identity:manage",
      "worker_identity:approve",
      "target_discovery:manage",
      "enrollment:progress",
    ]);
    expect(p).toEqual({ read: false, manage: false });
  });
});

// --------------------------------------------------------------------- gates

const ALL = { read: true, manage: true };
const OK = { ok: true };
const BAD = { ok: false };

describe("action gates", () => {
  it("names the missing permission rather than silently disabling", () => {
    expect(createGate({ read: true, manage: false }, OK, OK, false).reason).toBe(
      MISSING_MANAGE_REASON,
    );
    expect(lookupGate({ read: false, manage: true }, OK, false).reason).toBe(
      MISSING_READ_REASON,
    );
    expect(revokeGate({ read: true, manage: false }, status(), false).reason).toBe(
      MISSING_MANAGE_REASON,
    );
  });

  it("checks permission before input, so a denied user is told the real reason", () => {
    const gate = createGate({ read: true, manage: false }, BAD, BAD, false);
    expect(gate.reason).toBe(MISSING_MANAGE_REASON);
  });

  it("blocks create on invalid input and while a request is in flight", () => {
    expect(createGate(ALL, BAD, OK, false).ok).toBe(false);
    expect(createGate(ALL, OK, BAD, false).ok).toBe(false);
    expect(createGate(ALL, OK, OK, true).ok).toBe(false);
    expect(createGate(ALL, OK, OK, false).ok).toBe(true);
  });

  it("blocks look-up on a malformed id", () => {
    expect(lookupGate(ALL, BAD, false).ok).toBe(false);
    expect(lookupGate(ALL, OK, false).ok).toBe(true);
  });

  // Revoke must carry the revision of a status we actually observed.
  it("refuses to revoke without an observed status", () => {
    const gate = revokeGate(ALL, null, false);
    expect(gate.ok).toBe(false);
    expect(gate.reason).toContain("Look up an enrollment");
  });

  it("refuses to revoke an already-terminal enrollment and says which terminal", () => {
    expect(revokeGate(ALL, status({ state: "refused" }), false).reason).toContain(
      "already refused",
    );
    expect(
      revokeGate(ALL, status({ state: "recovery_required" }), false).reason,
    ).toContain("requires recovery");
  });

  it("allows revoke on every live state", () => {
    for (const state of ENROLLMENT_FORWARD_STATES) {
      expect(revokeGate(ALL, status({ state }), false).ok, state).toBe(true);
    }
  });
});

// --------------------------------------------------------------------- status rows

describe("status detail rows", () => {
  it("says an unestablished fingerprint is not established, never blank", () => {
    const rows = statusDetailRows(status());
    const worker = rows.find((r) => r.key === "Worker key fingerprint");
    expect(worker?.value).toBe("Not established yet");
  });

  it("omits the refusal reason until there is one, then shows the bounded code", () => {
    expect(statusDetailRows(status()).some((r) => r.key === "Refusal reason")).toBe(false);
    const revoked = statusDetailRows(
      status({ state: "refused", refusal_reason: "operator_revoked" }),
    );
    expect(revoked.find((r) => r.key === "Refusal reason")?.value).toBe("operator_revoked");
  });

  it("renders identities only as short fingerprints, never a full digest", () => {
    // The enrollment id is deliberately a full sha256 content address — it is the public handle
    // you look the record up by. Every IDENTITY row, by contrast, must be a short non-reversible
    // fingerprint, so a full 64-hex value appearing in one would mean the projection changed.
    const rows = statusDetailRows(
      status({
        controller_key_fingerprint: "cccccccccccc",
        worker_key_fingerprint: "ffffffffffff",
        release_fingerprint: "eeeeeeeeeeee",
        offer_fingerprint: "111111111111",
        result_fingerprint: "222222222222",
      }),
    );
    for (const row of rows.filter((r) => r.key.includes("fingerprint"))) {
      expect(row.value, row.key).not.toMatch(/[0-9a-f]{64}/);
      expect(row.value.length, row.key).toBeLessThanOrEqual(20);
    }
    const values = rows.map((r) => r.value).join(" ");
    expect(values).not.toContain("BEGIN");
    expect(values).not.toContain("PRIVATE");
  });
});

// --------------------------------------------------------------------- evidence

describe("evidence chain", () => {
  it("reads the five projection fingerprints, in exchange order", () => {
    expect(enrollmentEvidence(status()).map((e) => e.field)).toEqual([
      "controller_key_fingerprint",
      "worker_key_fingerprint",
      "release_fingerprint",
      "offer_fingerprint",
      "result_fingerprint",
    ]);
  });

  // An unreached rung is not a failed check. Calling it one would invent a verdict the controller
  // never returned and would render a healthy in-flight enrollment as broken.
  it("never reports a rung as failed — only established or not yet established", () => {
    const all = [
      ...enrollmentEvidence(status()),
      ...enrollmentEvidence(
        status({
          worker_key_fingerprint: "ffffffffffff",
          offer_fingerprint: "111111111111",
          result_fingerprint: "222222222222",
        }),
      ),
      ...enrollmentEvidence(status({ state: "refused", refusal_reason: "operator_revoked" })),
    ];
    for (const item of all) {
      expect(["pass", "unverifiable"], item.field).toContain(item.status);
      expect(item.status, item.field).not.toBe("fail");
    }
  });

  it("marks a rung established exactly when its fingerprint is non-empty", () => {
    const items = enrollmentEvidence(status({ offer_fingerprint: "111111111111" }));
    const byField = Object.fromEntries(items.map((i) => [i.field, i]));
    expect(byField.controller_key_fingerprint.status).toBe("pass");
    expect(byField.offer_fingerprint.status).toBe("pass");
    expect(byField.worker_key_fingerprint.status).toBe("unverifiable");
    expect(byField.worker_key_fingerprint.value).toBe(NOT_ESTABLISHED);
    expect(byField.result_fingerprint.value).toBe(NOT_ESTABLISHED);
  });

  it("shows only short fingerprints — never a full digest, key or PEM", () => {
    const values = enrollmentEvidence(
      status({
        worker_key_fingerprint: "ffffffffffff",
        offer_fingerprint: "111111111111",
        result_fingerprint: "222222222222",
      }),
    ).map((i) => i.value);
    for (const value of values) {
      expect(value, value).not.toMatch(/[0-9a-f]{64}/);
      expect(value, value).not.toContain("BEGIN");
      expect(value, value).not.toContain("PRIVATE");
    }
  });
});

// --------------------------------------------------------------------- recovery

describe("recovery guidance", () => {
  const live = expiryView("2026-07-30T11:00:00+00:00", NOW);
  const gone = expiryView("2026-07-30T09:00:00+00:00", NOW);

  it("stays silent while an enrollment is live and in time", () => {
    for (const state of ENROLLMENT_FORWARD_STATES) {
      expect(recoveryView(state, live).needed, state).toBe(false);
    }
  });

  it("names both terminals and offers a new invitation, never a repair", () => {
    for (const terminal of ["refused", "recovery_required"]) {
      const view = recoveryView(terminal, live);
      expect(view.needed, terminal).toBe(true);
      expect(view.steps.join(" "), terminal).toContain("Create a new invitation");
      expect(view.steps.join(" "), terminal).toMatch(/cannot be resumed|no un-revoke route/);
    }
    expect(recoveryView("recovery_required", live).title).toContain("Recovery required");
    expect(recoveryView("refused", live).title).toContain("Refused");
  });

  // The page must not claim the controller has already swept a past-expiry enrollment: the sweep
  // is the controller's, and until it runs the record is still whatever it was.
  it("treats a past expiry as an observation, not as a lifecycle claim", () => {
    const view = recoveryView("worker_bound", gone);
    expect(view.needed).toBe(true);
    expect(view.title).toContain("Past its expiry");
    expect(view.steps.join(" ")).toContain("expiry sweep");
    expect(view.steps.join(" ")).toContain("cannot be extended");
    expect(view.title).not.toContain("Recovery required");
  });

  it("says nothing about expiry when the timestamp would not parse", () => {
    expect(recoveryView("invited", expiryView("not-a-time", NOW)).needed).toBe(false);
  });

  it("keeps the terminal guidance even once the expiry has also passed", () => {
    expect(recoveryView("refused", gone).title).toContain("Refused");
    expect(recoveryView("recovery_required", gone).title).toContain("Recovery required");
  });
});

// --------------------------------------------------------------------- verification context

describe("out-of-band verification context", () => {
  it("carries only controller and release identity — never the invitation's own ids", () => {
    const rows = verificationContext(invitation());
    expect(rows.map((r) => r.field)).toEqual([
      "controller_origin",
      "controller_installation_id",
      "controller_key_id",
      "controller_trust_anchor_hex",
      "release_digest",
    ]);
    const values = rows.map((r) => r.value).join(" ");
    // enrollment_id and invitation_id are what make the block a capability; neither is here.
    expect(values).not.toContain(ID);
    expect(values).not.toContain("b".repeat(64));
  });

  it("states what each value proves, so it is never a bare hash", () => {
    for (const row of verificationContext(invitation())) {
      expect(row.proves.length, row.field).toBeGreaterThan(20);
      expect(row.label.length, row.field).toBeGreaterThan(0);
    }
  });
});

// --------------------------------------------------------------------- control inventory

describe("control inventory", () => {
  const byId = Object.fromEntries(ENROLLMENT_CONTROLS.map((c) => [c.id, c]));

  it("offers exactly the four routes a browser principal may call", () => {
    const available = ENROLLMENT_CONTROLS.filter((c) => c.available).map((c) => c.id);
    expect(available.sort()).toEqual(["create", "list", "revoke", "status"]);
  });

  // Each available control names the route that backs it, so "available" can never drift into a
  // claim about a route the controller does not expose.
  it("names the backing route on every available control", () => {
    for (const control of ENROLLMENT_CONTROLS.filter((c) => c.available)) {
      expect(control.detail, control.id).toContain("/api/v1/enrollment");
      expect(control.detail, control.id).toMatch(/enrollment:(read|manage)/);
    }
  });

  // The list is org-scoped and carries no invitation material; both are stated, because both are
  // the properties an operator would otherwise have to assume.
  it("states the organization scope and the absence of invitation material on the list", () => {
    expect(byId.list.available).toBe(true);
    expect(byId.list.detail).toContain("Organization-scoped");
    expect(byId.list.detail).toContain("no invitation material");
  });

  // The deliverable: a control with no route is declared absent, never simulated.
  it("declares approval, hand-driving and re-issue as having no route", () => {
    for (const id of ["decide", "advance", "reissue"]) {
      expect(byId[id].available, id).toBe(false);
      expect(byId[id].detail.length, id).toBeGreaterThan(40);
    }
    expect(byId.decide.detail).toContain("no approval edge");
    // Re-issue is a DECISION, not a gap — the copy has to say so, or an operator reads it as
    // something that might arrive later and waits for it instead of revoking and recreating.
    expect(byId.reissue.detail).toContain("Decided, not missing");
    expect(byId.reissue.detail).toContain("Revoke and create a new invitation");
  });

  it("names revoke as the cancel, since there is no separate cancel route", () => {
    expect(byId.revoke.available).toBe(true);
    expect(byId.revoke.detail).toContain("no separate cancel route");
  });

  it("promises no future work in any detail line", () => {
    for (const control of ENROLLMENT_CONTROLS) {
      expect(control.detail, control.id).not.toMatch(/\b(yet|soon|coming|planned|will be)\b/i);
    }
  });
});

// --------------------------------------------------------------------- tab-local working set

describe("tab-local working set", () => {
  const entry = (id: string, over: Partial<TrackedEnrollment> = {}): TrackedEnrollment => ({
    enrollmentId: id,
    siteLabel: "site-one",
    createdAt: "2026-07-30T10:00:00+00:00",
    expiresAt: "2026-07-30T11:00:00+00:00",
    state: "invited",
    revision: 0,
    ...over,
  });

  it("puts a newly tracked enrollment first", () => {
    const list = addTracked(addTracked([], entry("a")), entry("b"));
    expect(list.map((e) => e.enrollmentId)).toEqual(["b", "a"]);
  });

  // A refresh must not make the row jump under the pointer that clicked it.
  it("updates an already-tracked enrollment in place, keeping its position", () => {
    const seeded = addTracked(addTracked([], entry("a")), entry("b"));
    const list = addTracked(seeded, entry("a", { state: "worker_bound", revision: 1 }));
    expect(list.map((e) => e.enrollmentId)).toEqual(["b", "a"]);
    expect(list[1].state).toBe("worker_bound");
    expect(list).toHaveLength(2);
  });

  it("stays bounded", () => {
    let list: TrackedEnrollment[] = [];
    for (let i = 0; i < TRACKED_LIMIT + 5; i += 1) list = addTracked(list, entry(`id-${i}`));
    expect(list).toHaveLength(TRACKED_LIMIT);
    expect(list[0].enrollmentId).toBe(`id-${TRACKED_LIMIT + 4}`);
  });

  // Revisions advance monotonically, so an older one is a late reply to an earlier request.
  it("discards a response that is older than the state already displayed", () => {
    const seeded = addTracked([], entry("a", { state: "verified", revision: 4 }));
    const list = addTracked(seeded, entry("a", { state: "worker_bound", revision: 1 }));
    expect(list[0].state).toBe("verified");
    expect(list[0].revision).toBe(4);
  });

  it("retains the site label and creation time a look-up cannot supply", () => {
    const created = addTracked([], trackedFromInvitation(invitation()));
    const refreshed = addTracked(
      created,
      trackedFromStatus(status({ state: "worker_bound", revision: 1 })),
    );
    expect(refreshed[0].siteLabel).toBe("site-one");
    expect(refreshed[0].createdAt).toBe("2026-07-30T10:00:00+00:00");
    expect(refreshed[0].state).toBe("worker_bound");
  });

  it("takes the site label from the status projection now that it carries one", () => {
    const list = addTracked([], trackedFromStatus(status()));
    expect(list[0].siteLabel).toBe("site-one");
    // Still not in the projection, and still not guessed.
    expect(list[0].createdAt).toBe("");
  });

  // A controller built before the projection carried the label returns a body without the key.
  // The row must then be blank rather than showing the string "undefined".
  it("leaves the site label blank when the projection does not carry one", () => {
    const older = status();
    delete (older as { deployment_site_label?: string }).deployment_site_label;
    expect(trackedFromStatus(older).siteLabel).toBe("");
    expect(siteLabelOf(older)).toBe("");
  });

  // A blank from a later observation must not erase a label the create response already gave this
  // tab: `addTracked` keeps what was genuinely observed.
  it("keeps a previously observed site label when a later status has none", () => {
    const withLabel = addTracked([], entry("a", { siteLabel: "site-one" }));
    const blank = { ...entry("a", { siteLabel: "", revision: 1, state: "worker_bound" }) };
    expect(addTracked(withLabel, blank)[0].siteLabel).toBe("site-one");
  });

  it("forgets an entry without touching the others", () => {
    const list = addTracked(addTracked([], entry("a")), entry("b"));
    expect(removeTracked(list, "b").map((e) => e.enrollmentId)).toEqual(["a"]);
    expect(removeTracked(list, "missing")).toHaveLength(2);
  });

  // The whole point of the entry shape: the working set could not leak the capability even if it
  // were persisted, which it is not.
  it("keeps no invitation material — only the handle, the labels and the observed state", () => {
    const tracked = trackedFromInvitation(invitation());
    expect(Object.keys(tracked).sort()).toEqual([
      "createdAt",
      "enrollmentId",
      "expiresAt",
      "revision",
      "siteLabel",
      "state",
    ]);
    // Derived from the hand-off artefact itself rather than restated, so a new hand-off field is
    // covered here the moment it exists. enrollment_id and expires_at are the two the working set
    // legitimately needs: one is the public handle you look a record up by, the other is shown as
    // the row's expiry.
    const serialised = JSON.stringify(tracked);
    const payload = handoffPayload(invitation());
    const allowed = new Set(["enrollment_id", "expires_at"]);
    const forbidden = Object.entries(payload).filter(([key]) => !allowed.has(key));
    expect(forbidden).toHaveLength(6); // anti-vacuity: 8 hand-off fields minus the 2 allowed
    for (const [key, value] of forbidden) {
      expect(appearsIn(serialised, value), key).toBe(false);
    }
    // Positive control for the same search, so an exclusion that can never match fails here.
    expect(appearsIn(serialised, payload.enrollment_id)).toBe(true);
    // ...and the trust anchor, which is not a hand-off field at all.
    expect(appearsIn(serialised, "d".repeat(64))).toBe(false);
  });
});

describe("working-set grouping and filters", () => {
  const entry = (id: string, state: string, expiresAt = "2026-07-30T11:00:00+00:00") => ({
    enrollmentId: id,
    siteLabel: "site-one",
    createdAt: "2026-07-30T10:00:00+00:00",
    expiresAt,
    state,
    revision: 0,
  });

  it("groups every forward state as pending except healthy", () => {
    for (const state of ENROLLMENT_FORWARD_STATES) {
      expect(trackedGroup(state), state).toBe(state === "healthy" ? "healthy" : "pending");
    }
  });

  it("groups both terminals as settled", () => {
    expect(trackedGroup("refused")).toBe("settled");
    expect(trackedGroup("recovery_required")).toBe("settled");
  });

  // A build older than the controller must not file a state it does not understand as progress.
  it("gives an unrecognised state its own group rather than folding it into pending", () => {
    expect(trackedGroup("some_future_state")).toBe("unknown");
  });

  it("filters to one group, and 'all' shows everything including the unrecognised", () => {
    const list = [
      entry("a", "invited"),
      entry("b", "healthy"),
      entry("c", "refused"),
      entry("d", "some_future_state"),
    ];
    expect(filterTracked(list, "pending").map((e) => e.enrollmentId)).toEqual(["a"]);
    expect(filterTracked(list, "healthy").map((e) => e.enrollmentId)).toEqual(["b"]);
    expect(filterTracked(list, "settled").map((e) => e.enrollmentId)).toEqual(["c"]);
    expect(filterTracked(list, "all")).toHaveLength(4);
    // The unrecognised entry is reachable from exactly one filter, and the summary counts it, so
    // it can never be silently invisible.
    expect(trackedSummary(list, NOW).unknown).toBe(1);
  });

  it("counts every group plus past-expiry, and the groups partition the list", () => {
    const list = [
      entry("a", "invited"),
      entry("b", "worker_bound", "2026-07-30T09:00:00+00:00"),
      entry("c", "healthy"),
      entry("d", "recovery_required"),
      entry("e", "some_future_state"),
    ];
    const summary = trackedSummary(list, NOW);
    expect(summary).toEqual({
      total: 5,
      pending: 2,
      healthy: 1,
      settled: 1,
      unknown: 1,
      pastExpiry: 1,
    });
    expect(summary.pending + summary.healthy + summary.settled + summary.unknown).toBe(
      summary.total,
    );
  });

  it("never calls a finished enrollment past expiry — the record is closed either way", () => {
    const old = "2026-07-30T09:00:00+00:00";
    expect(isPastExpiry(entry("a", "healthy", old), NOW)).toBe(false);
    expect(isPastExpiry(entry("b", "refused", old), NOW)).toBe(false);
    expect(isPastExpiry(entry("c", "recovery_required", old), NOW)).toBe(false);
    expect(isPastExpiry(entry("d", "invited", old), NOW)).toBe(true);
  });

  it("never guesses past-expiry from a timestamp it could not parse", () => {
    expect(isPastExpiry(entry("a", "invited", "not-a-time"), NOW)).toBe(false);
  });

  it("labels each filter without implying an operator decision", () => {
    for (const filter of TRACKED_FILTERS) {
      const label = TRACKED_FILTER_LABELS[filter];
      expect(label.length, filter).toBeGreaterThan(0);
      expect(label, filter).not.toMatch(/approv|reject|pending your|awaiting you/i);
    }
  });
});
