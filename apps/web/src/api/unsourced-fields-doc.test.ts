// The product-facing inventory stays in step with the map it is generated from.
//
// Checked here rather than by a CI step running the generator, on purpose: the generator imports
// a `.ts` module, and CI pins Node 22, where type stripping is not unflagged on every minor.
// Vitest handles TypeScript unconditionally, so the guard has no Node-version dependency — which
// is the same failure this repository just spent a day on, a check that only works on some
// machines.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ADAPTER_ENDPOINT_MAP, MISSING_SURFACES, unservedMethods } from "./adapter-endpoint-map";
import { renderAbsentEndpointsDoc, renderUnsourcedFieldsDoc } from "./unsourced-fields-doc";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const DOC = join(REPO_ROOT, "docs", "product", "unsourced-fields.md");

describe("docs/product/unsourced-fields.md", () => {
  it("is in step with the endpoint map", () => {
    expect(
      readFileSync(DOC, "utf8"),
      "the document is stale. Run: cd apps/web && npm run generate:unsourced-fields",
    ).toBe(renderUnsourcedFieldsDoc());
  });

  it("names every unsourced field the map records, and invents none", () => {
    // Both directions. A renderer that dropped a section would still produce a document that
    // matched itself; this ties the CONTENT to the map rather than to the last render.
    const doc = readFileSync(DOC, "utf8");
    const fields = ADAPTER_ENDPOINT_MAP.flatMap((m) => m.unsourcedFields);
    expect(fields.length).toBeGreaterThan(30);
    for (const field of fields) {
      expect(doc, `${field} is missing from the document`).toContain(`\`${field}\``);
    }
    for (const mapping of ADAPTER_ENDPOINT_MAP) {
      expect(doc, `${mapping.method} is missing from the document`).toContain(
        `\`${mapping.method}\``,
      );
    }
  });

  it("says plainly that a default is not one of the options", () => {
    // The sentence the whole document exists to deliver. If it is ever edited away, the inventory
    // becomes a list of gaps with no instruction about what to do at the pixel.
    const doc = readFileSync(DOC, "utf8");
    expect(doc).toContain("look identical on a screen and mean opposite things");
    expect(doc).toContain("Rendering it as a plausible default is the one option that is not");
  });
});

describe("docs/product/absent-endpoints.md", () => {
  const DOC = join(REPO_ROOT, "docs", "product", "absent-endpoints.md");

  it("is in step with the endpoint map", () => {
    expect(
      readFileSync(DOC, "utf8"),
      "the document is stale. Run: cd apps/web && npm run generate:api-docs",
    ).toBe(renderAbsentEndpointsDoc());
  });

  it("specifies every unserved method, and none that is served", () => {
    // Both directions again. A gap with no specification is a gap somebody has to re-derive; a
    // specification for a method that is now served is worse — it asks for work already done.
    const specified = MISSING_SURFACES.map((s) => s.method).sort();
    const unserved = unservedMethods()
      .map((m) => m.method)
      .filter((m) => m !== "listSecretRefs")
      .sort();
    // `listEvidence` and `listApprovals` are `shaped` — served, but only under a parent the
    // screen is trying to discover — so they are specified without being unserved.
    for (const method of unserved) {
      expect(specified, `${method} has no specification`).toContain(method);
    }
    // listSecretRefs is WITHHELD and must never acquire one.
    expect(specified).not.toContain("listSecretRefs");
  });

  it("names the scoping for every gap, since scoping is the recurring failure", () => {
    for (const surface of MISSING_SURFACES) {
      expect(surface.scoping.length, `${surface.method} has no scoping note`).toBeGreaterThan(30);
      expect(surface.unblocks.length, `${surface.method} says nothing about what it unblocks`)
        .toBeGreaterThan(30);
    }
  });

  it("keeps the access-profile note about public metadata only", () => {
    // The one gap whose implementation could leak credential material if specified carelessly.
    const access = MISSING_SURFACES.find((s) => s.method === "listAccessProfiles");
    expect(access?.unblocks).toMatch(/public metadata ONLY/i);
    expect(access?.unblocks).toContain("never be a profile a browser could use");
  });
});
