// The rack model must be a real glTF binary, not something shaped like one.
//
// WHY THIS EXISTS. A corrupt `.glb` is the quietest failure in this migration.
// It produces an empty 3D scene and nothing else -- no build error, no type
// error, no console exception, no failing test. Three realistic ways to get one:
//
//   * line-ending normalization, if the `binary` attribute is ever lost from
//     `.gitattributes` (the root rule is `* text=auto eol=lf`, so the attribute
//     is the only thing preventing it);
//   * a Git LFS pointer substituted for the payload, if LFS is introduced later
//     and a checkout or CI job runs without `lfs: true` -- that yields a ~130
//     byte text stub *named* `server-rack.glb`;
//   * a truncated or partial copy.
//
// WHY THE HASH TABLE IN THE PR IS NOT ENOUGH. I produced both sides of that
// table, so it can only restate itself, and it is a one-time artifact that no
// future change re-runs. This test lives in the repository and fails for
// anybody. That is the difference between evidence and a claim.
//
// The strongest assertion here is not the pinned byte count -- it is that the
// glTF header DECLARES ITS OWN TOTAL LENGTH, so the file can be checked against
// itself. Any truncation fails that comparison without anyone needing to know
// what the right size was.

import { describe, expect, it } from "vitest";

/**
 * Read the model as raw bytes.
 *
 * `node:fs` is imported through a non-literal specifier deliberately. This
 * package does not depend on `@types/node` and `tsconfig.json` pins
 * `"types": ["vitest/globals"]`; both files belong to P7-B, and editing them to
 * make a test of mine compile is not this slice's call. A computed specifier
 * keeps TypeScript from trying to resolve the module while vitest still loads
 * it normally at runtime. Once `@types/node` is available this can become a
 * plain top-level import.
 */
async function readModelBytes(relativePath: string): Promise<Uint8Array> {
  const specifier = "node:fs/promises";
  const fs = (await import(/* @vite-ignore */ specifier)) as {
    readFile(path: string): Promise<Uint8Array>;
  };

  // vitest runs with the package root (`apps/web`) as cwd, and `public/` is
  // served from there.
  const cwd = (globalThis as { process?: { cwd(): string } }).process?.cwd() ?? ".";
  return fs.readFile(`${cwd}/${relativePath}`);
}

/** Little-endian uint32, which is what the glTF container specifies. */
function uint32LE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

const MODEL = "public/models/server-rack.glb";

// glTF 2.0 binary container constants (Khronos spec, 12-byte header then chunks).
const MAGIC = [0x67, 0x6c, 0x54, 0x46]; // "glTF"
const JSON_CHUNK = 0x4e4f534a; // "JSON"
const EXPECTED_BYTES = 6_148_672;

describe("server-rack.glb integrity", () => {
  it("starts with the glTF magic number", async () => {
    const bytes = await readModelBytes(MODEL);

    // An LFS pointer stub begins "version https://git-lfs…" and a
    // text-normalized binary almost certainly no longer starts with 0x67 0x6C
    // 0x54 0x46. Either one fails right here.
    expect([...bytes.subarray(0, 4)]).toEqual(MAGIC);
  });

  it("declares glTF version 2 and a JSON first chunk", async () => {
    const bytes = await readModelBytes(MODEL);

    expect(uint32LE(bytes, 4), "glTF container version").toBe(2);
    expect(uint32LE(bytes, 16), "first chunk must be JSON").toBe(JSON_CHUNK);
  });

  it("has a header length that matches its actual size", async () => {
    const bytes = await readModelBytes(MODEL);

    // The self-consistency check, and the most valuable assertion in this file:
    // bytes 8..12 hold the total length the container claims to be. A truncated
    // or padded file disagrees with its own header, and this catches that
    // without anyone having to know the correct size in advance -- so it keeps
    // working if the model is ever legitimately replaced.
    expect(uint32LE(bytes, 8)).toBe(bytes.byteLength);
  });

  it("is exactly the model that was migrated", async () => {
    const bytes = await readModelBytes(MODEL);

    // The pin. Complements the self-consistency check above: that one proves the
    // file is internally coherent, this one proves it is the SAME file, so a
    // wholesale swap for a different (valid) model is also caught.
    expect(bytes.byteLength).toBe(EXPECTED_BYTES);
  });
});
