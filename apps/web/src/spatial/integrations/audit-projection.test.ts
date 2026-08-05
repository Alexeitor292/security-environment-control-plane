// The audit projection must not invent, coerce, or drop.
//
// These assertions are DIFFERENTIAL where it matters: the dangerous behaviours
// (coercing an unknown outcome to a known one, dropping an unrecognised row,
// rendering an unsourced field as an empty value) all produce output that looks
// correct. So each is asserted absent, against the real server vocabulary rather
// than against values this file invented.

import { describe, expect, it } from "vitest";

import {
  auditRow,
  auditRows,
  NOT_SUPPLIED,
  outcomeView,
  TONED_OUTCOMES,
} from "./audit-projection";

/**
 * Every outcome the control plane writes from production code, measured from
 * `services/` and `routers/` rather than assumed. Four have no tone.
 */
const SERVER_OUTCOMES = [
  "success",
  "denied",
  "failed",
  "revoked",
  "expired",
  "refused",
  "failure",
] as const;

function event(over: Partial<Record<string, unknown>> = {}) {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    action: "target.register",
    actor: "operator@example.test",
    created_at: "2026-08-05T12:00:00Z",
    data: {},
    outcome: "success",
    resource_id: "22222222-2222-2222-2222-222222222222",
    resource_type: "execution_target",
    ...over,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
}

describe("audit outcome projection", () => {
  it("carries every server outcome through verbatim", () => {
    // The load-bearing assertion. Not "the known ones survive" -- ALL of them,
    // including the four with no tone, must arrive unchanged.
    for (const raw of SERVER_OUTCOMES) {
      expect(auditRow(event({ outcome: raw })).outcome.raw).toBe(raw);
    }
  });

  it("tones only the three the surface has tones for", () => {
    for (const raw of SERVER_OUTCOMES) {
      const view = outcomeView(raw);
      const expected = (TONED_OUTCOMES as readonly string[]).includes(raw) ? raw : null;
      expect(view.toned, `${raw} tone`).toBe(expected);
    }
  });

  it("never coerces revoked, expired or refused into a toned outcome", () => {
    // Each of these has a plausible-looking wrong answer. `revoked -> failed`
    // asserts a different fact; `refused -> failed` is the unknown-versus-
    // negative collapse. Asserting the absence is the point -- a coercion would
    // still render a badge and still look right.
    for (const raw of ["revoked", "expired", "refused"] as const) {
      const view = auditRow(event({ outcome: raw })).outcome;
      expect(view.toned, `${raw} must not be toned`).toBeNull();
      expect(view.raw).toBe(raw);
      expect(view.raw).not.toBe("failed");
    }
  });

  it("keeps `failure` and `failed` distinct", () => {
    // Two spellings of one concept, written by different services. The ledger is
    // append-only, so both exist in it permanently and normalising here would
    // hide a data-quality defect from the only people who can fix it.
    expect(outcomeView("failure").raw).toBe("failure");
    expect(outcomeView("failure").toned).toBeNull();
    expect(outcomeView("failed").toned).toBe("failed");
  });

  it("drops no row, whatever the outcome says", () => {
    // Hiding an entry is the specific failure an audit page exists to prevent,
    // so an unrecognised outcome must never filter a row out.
    const rows = auditRows(SERVER_OUTCOMES.map((o) => event({ outcome: o })));
    expect(rows).toHaveLength(SERVER_OUTCOMES.length);
    expect(rows.map((r) => r.outcome.raw)).toEqual([...SERVER_OUTCOMES]);
  });

  it("survives an outcome nobody has written yet", () => {
    // The property that makes this projection durable: an eighth value is a
    // display question, not a correctness one.
    const view = auditRow(event({ outcome: "quarantined" })).outcome;
    expect(view.raw).toBe("quarantined");
    expect(view.toned).toBeNull();
  });
});

describe("unsourced and composed fields", () => {
  it("marks origin as not supplied rather than empty", () => {
    // "" and "not supplied" look identical on screen and mean different things.
    // A symbol cannot be mistaken for a value the control plane returned.
    const row = auditRow(event());
    expect(row.origin).toBe(NOT_SUPPLIED);
    expect(row.origin).not.toBe("");
    expect(typeof row.origin).not.toBe("string");
  });

  it("composes resource from type and id, and omits a null id cleanly", () => {
    expect(auditRow(event()).resource).toBe(
      "execution_target 22222222-2222-2222-2222-222222222222",
    );
    // An org-wide act has no resource id; the result must not read "type null".
    const orgWide = auditRow(event({ resource_id: null })).resource;
    expect(orgWide).toBe("execution_target");
    expect(orgWide).not.toContain("null");
    expect(orgWide).not.toContain("undefined");
  });

  it("reads time from created_at rather than inventing a clock", () => {
    expect(auditRow(event({ created_at: "2026-01-02T03:04:05Z" })).time).toBe(
      "2026-01-02T03:04:05Z",
    );
  });
});
