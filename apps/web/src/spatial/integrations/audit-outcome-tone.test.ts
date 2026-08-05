// The audit outcome vocabulary, read from the SERVICES THAT WRITE IT.
//
// WHY THIS TEST READS PYTHON.
//
// `AuditEventOut.outcome` is `str` on the wire -- no enum, nothing generated,
// nothing the OpenAPI client can narrow. So every frontend statement about which
// outcomes exist is a hand-copied list, and a test asserting that list against a
// constant in the same repository only restates it: both sides move together and
// the check can only say yes.
//
// The independent source of truth is the emitting call sites. `audit.record(...)`
// in `apps/api/secp_api/audit.py` is the ONLY writer of `AuditEvent` rows, so the
// set of `outcome=` literals passed to it is the vocabulary, measured rather than
// remembered. If a service starts writing an eighth value, this scan sees it on
// the commit that introduces it.
//
// #127 DOES NOT MAKE THIS REDUNDANT, and it will look as though it does. It
// lands an audit-outcome enum on the WRITE path, but `AuditEventOut.outcome`
// stays a bare `str` on the READ path deliberately: closed on write, open on
// read, so entries already in an append-only ledger round-trip rather than
// failing validation. The generated client therefore still cannot narrow this
// field after #127, and this scan is still the only thing measuring what the
// surface must be able to display.
//
// WHAT THE SCAN CANNOT SEE, STATED SO NOBODY READS MORE INTO IT.
//
//   * Two call sites forward a variable (`services/bootstrap_discovery.py`,
//     `services/worker_admission.py` both wrap `audit.record` in a helper taking
//     `outcome: str`). Their callers' literals are counted where those callers
//     call `audit.record` directly; where they call the helper, they are not.
//   * 78 call sites omit `outcome` entirely and take the `= "success"` default,
//     which is asserted separately below.
//
// So the discovered set is a LOWER BOUND on the vocabulary. That is the safe
// direction only because of the fallback rule asserted last: anything the design
// system has not been told about resolves to `unknown`, never to a healthy
// default. The scan protects the values we know; the fallback protects the rest.
//
// A NAME COLLISION THIS SCAN DELIBERATELY EXCLUDES. `readiness_models.py` also
// has an `outcome` column, with its own typed enums (`ready`, `attested`). It is
// a different concept that happens to share a field name, and a scan for bare
// `outcome=` literals across the API tree pulls both vocabularies into one list
// -- nine values across two concepts, which is how a reader concludes the audit
// ledger emits `attested`. Scoping to `audit.record(` call sites is what keeps
// the two apart.

import { describe, expect, it } from "vitest";

import { toneForState } from "../apps/prototype-suite/core/components/StatusBadge";

/** `@types/node` is not a dependency here; a computed specifier keeps `tsc` out of it. */
async function readBackend(): Promise<{ sources: string[]; auditPy: string }> {
  const fsSpecifier = "node:fs/promises";
  const fs = (await import(/* @vite-ignore */ fsSpecifier)) as {
    readdir: (p: string, o: { withFileTypes: true }) => Promise<
      { name: string; isDirectory: () => boolean }[]
    >;
    readFile: (p: string, enc: string) => Promise<string>;
  };

  const root = new URL("../../../../api/secp_api/", import.meta.url).pathname.replace(
    /^\/([A-Za-z]:)/,
    "$1",
  );

  const sources: string[] = [];
  async function walk(dir: string): Promise<void> {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      const full = `${dir}${entry.name}${entry.isDirectory() ? "/" : ""}`;
      if (entry.isDirectory()) await walk(full);
      else if (entry.name.endsWith(".py")) sources.push(await fs.readFile(full, "utf-8"));
    }
  }
  await walk(root);

  return { sources, auditPy: await fs.readFile(`${root}audit.py`, "utf-8") };
}

/**
 * Every `audit.record(...)` call, sliced by balancing parentheses from the open
 * paren. A line-based or fixed-window regex misses the many calls written across
 * six or more lines, and would under-report while looking like it worked.
 */
function auditRecordCalls(source: string): string[] {
  const spans: string[] = [];
  const opener = /audit\.record\s*\(/g;
  while (opener.exec(source) !== null) {
    let depth = 1;
    let i = opener.lastIndex;
    while (i < source.length && depth > 0) {
      if (source[i] === "(") depth += 1;
      else if (source[i] === ")") depth -= 1;
      i += 1;
    }
    spans.push(source.slice(opener.lastIndex, i - 1));
  }
  return spans;
}

interface Measured {
  readonly literals: Set<string>;
  readonly callSites: number;
  readonly defaulted: number;
  readonly auditPy: string;
}

async function measure(): Promise<Measured> {
  const { sources, auditPy } = await readBackend();
  const literals = new Set<string>();
  let callSites = 0;
  let defaulted = 0;

  for (const source of sources) {
    for (const span of auditRecordCalls(source)) {
      callSites += 1;
      const found = /outcome\s*=\s*["']([a-z_]+)["']/.exec(span);
      if (found) literals.add(found[1]);
      else if (!/outcome\s*=/.test(span)) defaulted += 1;
    }
  }
  return { literals, callSites, defaulted, auditPy };
}

describe("audit outcome vocabulary, measured from the emitting services", () => {
  it("finds the writers at all", async () => {
    // THE LOAD-BEARING PRECONDITION. Every assertion below is a statement about
    // a set this scan produced, so a scan that silently matches nothing turns
    // all of them green while measuring an empty repository -- a moved directory
    // or a renamed helper would read as "no problems found". Positive counts,
    // not merely an absence of failures.
    const { literals, callSites, defaulted } = await measure();
    expect(callSites, "audit.record call sites").toBeGreaterThan(50);
    expect(defaulted, "call sites relying on the success default").toBeGreaterThan(50);
    expect(literals.size, "distinct outcome literals").toBeGreaterThanOrEqual(7);
  });

  it("takes its default from the helper signature rather than assuming it", async () => {
    // 78 of the call sites write no outcome at all, so the default IS most of the
    // ledger. If it ever became something other than "success" this surface would
    // be toning the majority of rows from a value nobody passed.
    const { auditPy } = await measure();
    expect(auditPy).toMatch(/outcome:\s*str\s*=\s*"success"/);
  });

  it("tones no discovered outcome as healthy except success", async () => {
    // THE SAFETY PROPERTY, and the reason the vocabulary is measured rather than
    // listed. `STATE_TONE` is a global map keyed by bare strings shared across
    // every domain in the app, so a value added for some other surface -- an
    // authorization state, a range lifecycle state -- silently becomes the tone
    // for an audit outcome that happens to spell the same. `ok` is the only tone
    // that says "nothing to look at here", and only `success` is entitled to it.
    const { literals } = await measure();
    const healthy = [...literals].filter((raw) => toneForState(raw) === "ok");
    expect(healthy.sort()).toEqual(["success"]);
  });

  it("tones the four negative outcomes as error rather than as unknown", async () => {
    // The defect this test was written for. `revoked` and `expired` are outside
    // the migrated domain union, so the page derived their tone from that union
    // and rendered both in the neutral "we don't know" badge -- sitting grey in a
    // ledger where `failed` is red, which reads as less serious than it is.
    // The design system has always classified them; the page just was not asking.
    for (const raw of ["denied", "failed", "revoked", "expired"]) {
      expect(toneForState(raw), `${raw} tone`).toBe("error");
    }
  });

  it("leaves the two the design system was never told about neutral", async () => {
    // `refused` and `failure` genuinely have no entry. Neutral-with-a-question-
    // mark is the honest rendering: the word is shown, the colour claims nothing.
    for (const raw of ["refused", "failure"]) {
      expect(toneForState(raw), `${raw} tone`).toBe("unknown");
    }
  });

  it("resolves an outcome nobody has written yet to unknown, never to ok", async () => {
    // The fallback that makes the lower-bound scan safe. An eighth value is a
    // display question, not a correctness one -- provided it never lands on the
    // one tone that means "no need to look".
    for (const invented of ["quarantined", "embargoed", "chartreuse"]) {
      expect(toneForState(invented)).toBe("unknown");
      expect(toneForState(invented)).not.toBe("ok");
    }
  });
});
