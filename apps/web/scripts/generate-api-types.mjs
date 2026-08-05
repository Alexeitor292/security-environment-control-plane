/**
 * Generate the web app's transport types from the committed OpenAPI contract.
 *
 * THE GENERATED FILE IS NOT A TRANSCRIPTION. `contracts/openapi/openapi.json` is exported from
 * the live FastAPI application by `scripts/export_openapi.py`; this script turns that document
 * into TypeScript. Nothing here reads a Python source file and nothing here is written by hand,
 * so the two copies of the contract this repository used to carry are now one copy and a
 * derivation of it.
 *
 * Determinism is a requirement, not a nicety: `--check` compares BYTES, so any instability in the
 * generator turns the CI guard into a flake that reviewers learn to re-run until it passes.
 * `alphabetize` sorts the emitted types, the input document is already key-sorted by the exporter,
 * and the generator version is pinned exactly in package.json/package-lock.json.
 *
 *   node scripts/generate-api-types.mjs           # write src/api/generated/openapi.ts
 *   node scripts/generate-api-types.mjs --check    # fail if it is stale (writes nothing)
 */

import { readFile, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import openapiTS, { astToString } from "openapi-typescript";

const HERE = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(WEB_ROOT, "..", "..");
const DOCUMENT = resolve(REPO_ROOT, "contracts", "openapi", "openapi.json");
const OUTPUT = resolve(WEB_ROOT, "src", "api", "generated", "openapi.ts");

/**
 * Route prefixes the BROWSER CLIENT does not carry, and why.
 *
 * The committed document is the whole API and stays that way — the internal surfaces really are
 * part of the contract, and the workers and installers that call them need it. What ships into a
 * browser bundle is a narrower thing, and the line drawn here is one the repository already draws
 * and already enforces:
 *
 *   `/internal/` — `secp_api.main` registers the worker-admission and enrollment-signer readiness
 *   routers explicitly NOT under `/api/v1`. They are spoken over internal CA-pinned transports by
 *   a worker or a root installer. A browser has no business holding their request shapes.
 *
 *   `/api/v1/worker-identity` — the worker-identity REGISTRATION, approval, evidence and
 *   revocation interface. `apps/api/tests/test_resolution_lease_boundary.py` and
 *   `test_worker_identity_security.py` make this a hard boundary on frontend source: the browser
 *   may DISPLAY a `worker_identity_registration_id` (their pattern excepts exactly that field) but
 *   must carry no control interface for minting, approving or revoking a worker identity, and no
 *   `verification_anchor` surface. Those guards scan every `.ts` under `apps/web/src`, so they
 *   cover this generated file too — filtering here is what keeps them satisfied honestly, rather
 *   than shipping the types and hoping nobody imports them.
 *
 * Schemas become unreachable when their only referents are removed, and unreachable schemas are
 * pruned: a type is not excluded from the bundle by having no route left to reach it.
 */
const BROWSER_EXCLUDED_PREFIXES = ["/internal/", "/api/v1/worker-identity"];

const BANNER = `/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * Source of truth: contracts/openapi/openapi.json, exported from the live FastAPI application.
 * Regenerate with:  python scripts/export_openapi.py && (cd apps/web && npm run generate:api)
 *
 * Editing this file by hand re-creates exactly the defect it exists to remove: a second,
 * divergent copy of the API contract. CI regenerates it and fails on any difference.
 *
 * These are TRANSPORT types — the shapes that cross the wire. Presentation semantics (how an
 * operator should read a value) live in hand-written view models beside them, and the members
 * this document deliberately leaves opaque are narrowed in src/api/recorded.ts.
 *
 * This is the BROWSER surface, not the whole API. The internal worker/installer routes and the
 * worker-identity registration interface are excluded by design and their schemas are pruned —
 * see BROWSER_EXCLUDED_PREFIXES in scripts/generate-api-types.mjs for the boundary and the tests
 * that enforce it. Read contracts/openapi/openapi.json for the complete contract.
 */

/* eslint-disable */
`;

/** Every `$ref` target reachable from a value, transitively. */
function reachableSchemas(root, schemas) {
  const seen = new Set();
  const queue = [root];
  while (queue.length > 0) {
    const node = queue.pop();
    if (node === null || typeof node !== "object") continue;
    if (Array.isArray(node)) {
      queue.push(...node);
      continue;
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === "$ref" && typeof value === "string") {
        const name = value.replace("#/components/schemas/", "");
        if (!seen.has(name) && name in schemas) {
          seen.add(name);
          queue.push(schemas[name]);
        }
        continue;
      }
      queue.push(value);
    }
  }
  return seen;
}

/** The browser's slice of the contract: the permitted paths, and only the schemas they reach. */
export function browserDocument(document) {
  const paths = Object.fromEntries(
    Object.entries(document.paths).filter(
      ([path]) => !BROWSER_EXCLUDED_PREFIXES.some((prefix) => path.startsWith(prefix)),
    ),
  );
  const schemas = document.components?.schemas ?? {};
  const reachable = reachableSchemas(paths, schemas);
  return {
    ...document,
    paths,
    components: {
      ...document.components,
      schemas: Object.fromEntries(
        Object.entries(schemas).filter(([name]) => reachable.has(name)),
      ),
    },
  };
}

async function generate() {
  const raw = await readFile(DOCUMENT, "utf8");
  const document = browserDocument(JSON.parse(raw));
  const ast = await openapiTS(document, {
    // Root-level aliases: \`ProxmoxPlanOut\` rather than \`components["schemas"]["ProxmoxPlanOut"]\`.
    // A call site that reads well is a call site that gets used instead of re-typed by hand.
    rootTypes: true,
    rootTypesNoSchemaPrefix: true,
    alphabetize: true,
  });
  return BANNER + astToString(ast);
}

/**
 * Report where the two texts first diverge, with a little context either side.
 *
 * Deliberately not a full diff: this runs in CI on a ~10k-line generated file, and a complete
 * patch buries the one line that changed inside the thousands that did not.
 */
function firstDifference(committed, generated) {
  const a = committed.split("\n");
  const b = generated.split("\n");
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i += 1;
  const from = Math.max(0, i - 3);
  const window = (lines) =>
    lines
      .slice(from, i + 4)
      .map((line, offset) => `${String(from + offset + 1).padStart(6)}  ${line}`)
      .join("\n");
  return (
    `first difference at line ${i + 1} ` +
    `(committed has ${a.length} lines, regenerated has ${b.length})\n` +
    `--- committed\n${window(a)}\n` +
    `+++ regenerated\n${window(b)}`
  );
}

async function main() {
  const check = process.argv.includes("--check");
  const generated = await generate();

  if (!check) {
    await mkdir(dirname(OUTPUT), { recursive: true });
    await writeFile(OUTPUT, generated, "utf8");
    console.log("wrote apps/web/src/api/generated/openapi.ts");
    return 0;
  }

  if (!existsSync(OUTPUT)) {
    console.error(
      "Generated transport types are MISSING: apps/web/src/api/generated/openapi.ts does not exist.\n" +
        "Run: npm run generate:api",
    );
    return 1;
  }

  const committed = await readFile(OUTPUT, "utf8");
  if (committed !== generated) {
    console.error(
      "Generated transport types are STALE. They no longer match the committed OpenAPI contract.\n" +
        "Run: npm run generate:api  and commit the result.\n\n" +
        firstDifference(committed, generated),
    );
    return 1;
  }

  console.log("Generated transport types are in step with the OpenAPI contract.");
  return 0;
}

process.exitCode = await main();
