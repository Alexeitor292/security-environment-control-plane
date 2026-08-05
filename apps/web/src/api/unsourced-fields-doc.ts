// Render the product-facing inventory of fields the platform does not produce.
//
// PURE. No side effects, no filesystem, no `process.exitCode` — importing this module does
// nothing but define a function. That is not a style preference: the first version of this lived
// in the CLI script, whose `main()` ran at import time, so the test that imported it to compare
// against the committed document REGENERATED that document first and then compared it to itself.
// It passed a mutation that had genuinely landed. A guard that produces the thing it checks is a
// guard that can only say yes.
//
// The document is written by `scripts/generate-unsourced-fields.mjs` and held in step by
// `unsourced-fields-doc.test.ts`, which imports from HERE.

import { ADAPTER_ENDPOINT_MAP } from "./adapter-endpoint-map.ts";
import type { MappingStatus } from "./adapter-endpoint-map.ts";
// The .ts extension is explicit because this module is imported by BOTH vitest (bundler
// resolution, extension optional) and node (ESM, extension required). tsconfig sets
// allowImportingTsExtensions, so one spelling satisfies both.

const STATUS_HEADING: Record<MappingStatus, string> = {
  exact: "Served, and complete",
  shaped: "Served, with fields the platform does not produce",
  absent: "No endpoint at all",
  withheld: "Deliberately not served",
};

const ORDERED_STATUSES: readonly MappingStatus[] = ["exact", "shaped", "absent", "withheld"];
/** Most actionable first: the gaps somebody has to decide about come before the settled cases. */
const DISPLAY_ORDER: readonly MappingStatus[] = ["shaped", "absent", "withheld", "exact"];

export function renderUnsourcedFieldsDoc(): string {
  const byStatus = (status: MappingStatus) => ADAPTER_ENDPOINT_MAP.filter((m) => m.status === status);
  const totalUnsourced = ADAPTER_ENDPOINT_MAP.reduce(
    (n: number, m) => n + m.unsourcedFields.length,
    0,
  );

  const lines: string[] = [];
  lines.push("# What the designed experience assumes, and the platform does not produce");
  lines.push("");
  lines.push(
    "<!-- GENERATED FILE - DO NOT EDIT. Source: apps/web/src/api/adapter-endpoint-map.ts",
  );
  lines.push("     Regenerate: cd apps/web && npm run generate:unsourced-fields -->");
  lines.push("");
  lines.push(
    "The spatial frontend talks to the control plane through one interface of **" +
      `${ADAPTER_ENDPOINT_MAP.length} methods**. Resolving each against the routes the live ` +
      "application actually registers gives:",
  );
  lines.push("");
  lines.push("| | methods |");
  lines.push("| --- | --- |");
  for (const status of ORDERED_STATUSES) {
    lines.push(`| ${STATUS_HEADING[status]} | ${byStatus(status).length} |`);
  }
  lines.push("");
  lines.push(
    `Across them, **${totalUnsourced} distinct product fields have no source on the wire**. ` +
      "They are not bugs and they are not oversights in the frontend: they are places where the " +
      "designed experience describes something the platform does not measure.",
  );
  lines.push("");
  lines.push(
    "**Why this matters at the pixel.** A `0` for a cost and a `—` for \"not supplied\" look " +
      "identical on a screen and mean opposite things. Every field below has to render as an " +
      "absence, or be produced by the backend, or be dropped from the design. Rendering it as a " +
      "plausible default is the one option that is not available.",
  );
  lines.push("");
  lines.push(
    "Three kinds of decision are mixed together here and it is worth separating them: some of " +
      "these the control plane arguably **should** measure (a deployment's drift, a target's " +
      "capacity); some are **presentation** choices it should never own (a team's display " +
      "colour); and some describe a **product concept that does not exist yet** (score " +
      "components, event phases). Only the first kind is backend work.",
  );
  lines.push("");

  for (const status of DISPLAY_ORDER) {
    const group = byStatus(status);
    if (group.length === 0) continue;
    lines.push(`## ${STATUS_HEADING[status]}`);
    lines.push("");
    for (const mapping of group) {
      lines.push(`### \`${mapping.method}\``);
      lines.push("");
      lines.push(
        mapping.endpoints.length > 0
          ? mapping.endpoints.map((e) => `\`${e}\``).join(" · ")
          : "_No registered endpoint._",
      );
      lines.push("");
      lines.push(mapping.note);
      lines.push("");
      if (mapping.requires) {
        lines.push(`**What it would take:** ${mapping.requires}`);
        lines.push("");
      }
      if (mapping.unsourcedFields.length > 0) {
        lines.push("Fields with no source:");
        lines.push("");
        for (const field of mapping.unsourcedFields) lines.push(`- \`${field}\``);
        lines.push("");
      }
    }
  }
  return lines.join("\n") + "\n";
}
