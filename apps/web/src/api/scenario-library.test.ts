// The three dimensions a page has to pass, checked against the contract rather than asserted.
//
// Field coverage alone recommended Integrations twice and was wrong twice. These pin all three —
// field coverage, row reality, and the filter/layout fields — so a future page cannot be declared
// wireable on the strength of the one dimension that is easiest to measure.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  FILTER_FIELDS,
  SCENARIO_LIBRARY_ROUTE,
  SHIPPED_TEMPLATE_SLUGS,
  SOURCED_FIELDS,
  SPARE_WIRE_FIELDS,
  UNSOURCED_FIELDS,
} from "./scenario-library";
import { requirementFor } from "./route-permissions";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const contract = JSON.parse(
  readFileSync(join(REPO_ROOT, "contracts", "openapi", "openapi.json"), "utf8"),
) as { components: { schemas: Record<string, { properties?: Record<string, unknown> }> } };
const WIRE = new Set(Object.keys(contract.components.schemas.RangeTemplateOut.properties ?? {}));

describe("the field split is computed from the contract, not transcribed", () => {
  it("names a real wire field for every sourced view field", () => {
    for (const [view, wire] of Object.entries(SOURCED_FIELDS)) {
      // The mapping records prose for the widened one; take the leading identifier.
      const field = wire.split(" ")[0];
      expect(WIRE.has(field), `${view} claims to come from ${field}, which is not on the wire`).toBe(
        true,
      );
    }
  });

  it("accounts for every wire field exactly once — sourced or spare", () => {
    // Both directions. A wire field that is neither used nor declared spare is content nobody has
    // looked at, which is how `warning` would go missing quietly.
    const used = new Set(Object.values(SOURCED_FIELDS).map((wire) => wire.split(" ")[0]));
    const accounted = new Set([...used, ...SPARE_WIRE_FIELDS]);
    expect([...WIRE].filter((field) => !accounted.has(field))).toEqual([]);
    expect(SPARE_WIRE_FIELDS.filter((field) => !WIRE.has(field))).toEqual([]);
  });

  it("keeps sourced and unsourced disjoint and complete over the view", () => {
    const overlap = UNSOURCED_FIELDS.filter((field) => field in SOURCED_FIELDS);
    expect(overlap).toEqual([]);
    // 5 sourced + 9 unsourced = the 14 fields `Scenario` declares.
    expect(Object.keys(SOURCED_FIELDS).length + UNSOURCED_FIELDS.length).toBe(14);
  });

  it("is the one page where the wire offers MORE than the view", () => {
    // The property that earned this page its place at the front of the queue. Every other
    // integration measured so far has been a subtraction.
    expect(SPARE_WIRE_FIELDS.length).toBeGreaterThan(0);
  });
});

describe("row reality — the dimension a field count cannot see", () => {
  it("expects three templates, structurally rather than by deployment", () => {
    // `range_catalog.CATALOG` is a tuple of three declared in code, upserted by `sync_catalog` on
    // every read. A fresh database still has them. This is the difference from
    // `GET /api/v1/plugins`, which returns one row because one plugin registers itself.
    expect(SHIPPED_TEMPLATE_SLUGS).toHaveLength(3);
    expect(SHIPPED_TEMPLATE_SLUGS).toContain("web-breach-lab");
  });
});

describe("filters read published fields", () => {
  it("reads both filters off the wire, so neither summarises the loaded page", () => {
    // A filter over a field the wire does not carry can only offer the values present in the rows
    // already loaded — a summary of this page wearing the clothes of a filter over the whole set.
    for (const [filter, field] of Object.entries(FILTER_FIELDS)) {
      expect(WIRE.has(field), `the ${filter} filter reads ${field}, which is not published`).toBe(
        true,
      );
    }
  });
});

describe("permission", () => {
  it("is open, and open because the code says so", () => {
    // `del principal  # authentication only; the shipped catalog is not tenant data`. Recorded as
    // `open` rather than `unknown` on the strength of that line — the only route in the contract
    // that states its own reason for being ungated.
    expect(requirementFor(SCENARIO_LIBRARY_ROUTE)).toEqual({ state: "open" });
  });
});
