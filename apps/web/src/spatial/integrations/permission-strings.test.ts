// Every permission this frontend gates on must be one the server can grant.
//
// THE FAILURE THIS EXISTS FOR IS INVISIBLE, AND IT LOOKS LIKE SAFETY.
//
// `PermissionGate` and `useReaderQuery` take permission strings as free text.
// A string that is misspelled, invented, or renamed server-side is held by NO
// PRINCIPAL, because the list the gate checks against comes from the server's
// own enum by way of `GET /api/v1/me`. So the gate refuses -- for everyone,
// permanently. The page is simply never seen again.
//
// Nothing catches that on its own:
//
//   * It fails CLOSED, which is the direction we normally want, so no security
//     review flags it.
//   * `refused` is a legitimate rendering with legitimate copy, so the page
//     still looks deliberate rather than broken.
//   * The composition tests assert that state is REACHABLE, so they are green.
//   * Nobody notices in review, because a permission string is not obviously
//     spelled wrong -- it is obviously spelled the way you would guess.
//
// The live illustration: the server has `target:manage`,
// `target_discovery:approve` and `target_discovery:manage`, and **no
// `target:read`**. Anyone wiring the targets surface and reaching for the
// obvious string gates the page on a permission that cannot exist.
//
// WHY THIS READS PYTHON. Permissions are not in the OpenAPI document -- `/me`
// publishes them as `string[]`, so the generated client cannot narrow them and
// there is nothing to import. A hand-copied list of 45 values in this repo would
// share an origin with the code it checks and could only say yes. The server's
// `Permission` enum is the definition; this reads the definition.

import { describe, expect, it } from "vitest";

/** The frontend tree, raw. Same mechanism `security-claims.test.ts` uses. */
const SOURCES = import.meta.glob("../**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** `@types/node` is not a dependency here; a computed specifier keeps `tsc` out of it. */
async function serverPermissions(): Promise<Set<string>> {
  const specifier = "node:fs/promises";
  const fs = (await import(/* @vite-ignore */ specifier)) as {
    readFile: (p: string, enc: string) => Promise<string>;
  };
  const path = new URL("../../../../api/secp_api/enums.py", import.meta.url).pathname.replace(
    /^\/([A-Za-z]:)/,
    "$1",
  );
  const source = await fs.readFile(path, "utf-8");

  // The class body runs to the next top-level statement. Slicing on that rather
  // than reading to end-of-file keeps a later enum's members out of the set --
  // the same scoping mistake that made an audit-outcome scan report `attested`.
  const start = source.search(/^class Permission\b/m);
  expect(start, "the Permission enum must be findable").toBeGreaterThan(-1);
  const rest = source.slice(start);
  const end = rest.search(/\n(?=\S)(?!class Permission)/);
  const body = end === -1 ? rest : rest.slice(0, end);

  return new Set([...body.matchAll(/^\s+[a-z_0-9]+\s*=\s*"([^"]+)"/gm)].map((m) => m[1]));
}

interface Usage {
  readonly file: string;
  readonly permission: string;
}

/**
 * Permission strings written as literals at a `requires` site.
 *
 * A LOWER BOUND, deliberately. `requires: HELD` and `requires={perms}` pass a
 * variable and are invisible here, which is why the count assertion below exists
 * rather than a claim of completeness -- an under-counting scan that reported
 * "all clear" would be the same defect one level up.
 */
function declaredPermissions(): Usage[] {
  const usages: Usage[] = [];
  for (const [file, source] of Object.entries(SOURCES)) {
    for (const site of source.matchAll(/requires\s*[=:]\s*\{?\s*\[([^\]]*)\]/g)) {
      for (const literal of site[1].matchAll(/["']([^"']+)["']/g)) {
        usages.push({ file, permission: literal[1] });
      }
    }
  }
  return usages;
}

describe("permission strings are real server permissions", () => {
  it("reads the enum the server actually enforces on", async () => {
    // The precondition. Every assertion below is a statement about this set, so
    // a parse that silently produced nothing would turn them all green while
    // checking against an empty vocabulary.
    //
    // Cross-checked once against the definition itself: importing `Permission`
    // in Python yields 45 values, and this regex yields 45. Two readings of the
    // same file by different machinery agreeing is what makes the parse
    // trustworthy -- the bound below is what keeps it that way.
    const permissions = await serverPermissions();
    expect(permissions.size, "server permissions parsed").toBeGreaterThan(30);
    expect(permissions.has("audit:read")).toBe(true);
  });

  it("stops at the end of the enum instead of swallowing the file", async () => {
    // THE UNSAFE DIRECTION, and the only one that makes this guard lie.
    //
    // A parse that finds too FEW permissions flags valid strings and fails
    // loudly. A parse that finds too MANY accepts invalid ones silently -- and
    // `enums.py` is a large file of adjacent enums, so reading past the class
    // body collects 935 values instead of 45 and this guard would wave through
    // very nearly anything.
    //
    // Asserted as a specific member of a NEIGHBOURING enum rather than as a
    // count, because a count drifts every time someone adds a permission and
    // gets relaxed until it means nothing.
    const permissions = await serverPermissions();
    expect(permissions.size, "an over-running slice collects hundreds").toBeLessThan(200);
    expect(
      permissions.has("activation_dossier.approved"),
      "a value from the next enum in the same file must not be in scope",
    ).toBe(false);
  });

  it("finds the gates in the frontend tree at all", () => {
    const usages = declaredPermissions();
    expect(usages.length, "literal `requires` permissions found").toBeGreaterThan(0);
    expect(Object.keys(SOURCES).length, "spatial sources scanned").toBeGreaterThan(100);
  });

  it("gates on nothing the server cannot grant", async () => {
    // THE LOAD-BEARING ASSERTION. A string outside this set hides its surface
    // from every user, forever, while rendering a notice that looks deliberate.
    const permissions = await serverPermissions();
    const unknown = declaredPermissions().filter((u) => !permissions.has(u.permission));

    expect(
      unknown.map((u) => `${u.permission} (${u.file})`),
      "permission strings no principal can ever hold",
    ).toEqual([]);
  });

  it("does not accept the permission a targets surface would guess", async () => {
    // Pinned as a case rather than left implicit: `target:read` is the specific
    // wrong answer this guard was written after finding. The server grants
    // `target:manage` and two discovery permissions, and listing targets
    // requires none of them.
    const permissions = await serverPermissions();
    expect(permissions.has("target:read")).toBe(false);
    expect(permissions.has("target:manage")).toBe(true);
  });
});
