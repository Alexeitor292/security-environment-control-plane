import { describe, expect, it } from "vitest";

import type { EnrollmentInvitation, EnrollmentStatus } from "../api/types";
import {
  ENROLLMENT_FORWARD_STATES,
  MISSING_MANAGE_REASON,
  MISSING_READ_REASON,
  RECENT_LIMIT,
  TTL_MAX_SECONDS,
  addRecent,
  createGate,
  encodeIdempotencyKey,
  enrollmentStepItems,
  expiryView,
  handoffFields,
  handoffText,
  isEnrollmentId,
  isIdempotencyKey,
  isTerminalState,
  lookupGate,
  parseEnrollmentId,
  parseTtlSeconds,
  resolveEnrollmentPermissions,
  revokeGate,
  shouldWarnManageWithoutRead,
  statusDetailRows,
  validateSiteLabel,
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

describe("hand-off material", () => {
  it("is exactly the eight fields the shipped worker transport consumes", () => {
    expect(handoffFields(invitation()).map((f) => f.key)).toEqual([
      "enrollment_id",
      "invitation_id",
      "controller_installation_id",
      "controller_key_id",
      "controller_origin",
      "controller_transaction_id",
      "release_digest",
      "expires_at",
    ]);
  });

  // The block is bearer-grade: it carries what the worker needs and nothing more.
  it("omits the trust anchor, the site label and the server-owned lifecycle fields", () => {
    const text = handoffText(invitation());
    expect(text).not.toContain("d".repeat(64)); // controller_trust_anchor_hex
    expect(text).not.toContain("site-one"); // deployment_site_label
    expect(text).not.toContain("revision");
    expect(text).not.toContain("created_at");
  });

  it("renders one stable key: value line per field", () => {
    const lines = handoffText(invitation()).split("\n");
    expect(lines).toHaveLength(8);
    expect(lines[0]).toBe(`enrollment_id: ${ID}`);
    expect(lines[5]).toBe("controller_transaction_id: txn-0123456789abcdef");
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

// --------------------------------------------------------------------- recent list

describe("session-scoped recent list", () => {
  const entry = (id: string): Parameters<typeof addRecent>[1] => ({
    enrollmentId: id,
    siteLabel: "site-one",
    createdAt: "2026-07-30T10:00:00+00:00",
    expiresAt: "2026-07-30T11:00:00+00:00",
  });

  it("puts the newest first", () => {
    const list = addRecent(addRecent([], entry("a")), entry("b"));
    expect(list.map((e) => e.enrollmentId)).toEqual(["b", "a"]);
  });

  it("de-duplicates by enrollment id", () => {
    const list = addRecent(addRecent([], entry("a")), entry("a"));
    expect(list).toHaveLength(1);
  });

  it("stays bounded", () => {
    let list: ReturnType<typeof addRecent> = [];
    for (let i = 0; i < RECENT_LIMIT + 5; i += 1) list = addRecent(list, entry(`id-${i}`));
    expect(list).toHaveLength(RECENT_LIMIT);
    expect(list[0].enrollmentId).toBe(`id-${RECENT_LIMIT + 4}`);
  });

  it("keeps no invitation material — only what a look-up needs", () => {
    const list = addRecent([], entry("a"));
    expect(Object.keys(list[0]).sort()).toEqual([
      "createdAt",
      "enrollmentId",
      "expiresAt",
      "siteLabel",
    ]);
  });
});
