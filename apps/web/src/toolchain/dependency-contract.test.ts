// The dependency properties the React 19 + 3D upgrade has to keep true, checked mechanically.
//
// `npm ls react` showing one runtime is a fine thing to run by hand once. It is a poor thing to
// rely on, because the failure it catches — a transitive React 18 pulled in under a package whose
// peer range moved — arrives silently, on somebody else's `npm install`, months later, and shows
// up as hooks throwing "invalid hook call" rather than as anything resembling a dependency
// problem. So it is a test.
//
// These read the RESOLVED tree in node_modules, not package.json's ranges. A range says what would
// be acceptable; the tree says what is actually there, and only the second one ships.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// A STATIC import, and `semver` is a declared devDependency rather than something npm happens
// to hoist out of @typescript-eslint. A dynamic import of a transitively-present package is how
// a guard stops running without anyone noticing: the day hoisting changes it would throw at
// call time inside one test, and a static import fails the whole FILE loudly instead.
import { satisfies } from "semver";
import { describe, expect, it } from "vitest";

const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const NODE_MODULES = join(WEB_ROOT, "node_modules");

function readPackage(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8"));
}

const manifest = readPackage(join(WEB_ROOT, "package.json")) as {
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};

/** Every react package directory anywhere under node_modules — one per React runtime present. */
function findReactRuntimes(root: string, found: string[] = []): string[] {
  if (!existsSync(root)) return found;
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    if (!statSync(path).isDirectory()) continue;
    if (entry.startsWith("@")) {
      // Scope directory: its children are the packages.
      for (const scoped of readdirSync(path)) {
        const nested = join(path, scoped, "node_modules");
        if (existsSync(nested)) findReactRuntimes(nested, found);
      }
      continue;
    }
    if (entry === "react" && existsSync(join(path, "package.json"))) found.push(path);
    const nested = join(path, "node_modules");
    if (existsSync(nested)) findReactRuntimes(nested, found);
  }
  return found;
}

describe("exactly one React runtime", () => {
  it("resolves a single copy of react in the whole installed tree", () => {
    // Two copies means two module registries, so two sets of hook dispatchers. A component from
    // one and a hook from the other is the "invalid hook call" that costs an afternoon to find.
    const runtimes = findReactRuntimes(NODE_MODULES);
    const versions = runtimes.map((path) => (readPackage(join(path, "package.json")) as { version: string }).version);
    expect(runtimes, `react copies found:\n${runtimes.join("\n")}`).toHaveLength(1);
    expect(versions[0].startsWith("19.")).toBe(true);
  });

  it("resolves react-dom at the same version as react", () => {
    const react = (readPackage(join(NODE_MODULES, "react", "package.json")) as { version: string })
      .version;
    const reactDom = (
      readPackage(join(NODE_MODULES, "react-dom", "package.json")) as { version: string }
    ).version;
    expect(reactDom).toBe(react);
  });
});

describe("no production dependency is left behind on React 18", () => {
  it("every declared peer range accepts the installed react", () => {
    // The check the upgrade turns on. A dependency that peers `^18` only would still INSTALL —
    // npm warns and moves on — and would then either duplicate the runtime or run against a React
    // it was never tested with.
    const installed = (
      readPackage(join(NODE_MODULES, "react", "package.json")) as { version: string }
    ).version;

    const refused: string[] = [];
    for (const name of Object.keys(manifest.dependencies)) {
      const peer = (
        readPackage(join(NODE_MODULES, ...name.split("/"), "package.json")) as {
          peerDependencies?: Record<string, string>;
        }
      ).peerDependencies?.react;
      if (peer === undefined) continue;
      if (!satisfies(installed, peer)) refused.push(`${name} peers react ${peer}`);
    }
    expect(refused, `installed react is ${installed}`).toEqual([]);
  });

  it("notices when a peer range's UPPER bound would exclude the next react", () => {
    // `@react-three/fiber@9.7` peers `>=19 <19.3` — an upper bound, which is unusual and worth
    // knowing about. `package.json` asks for `^19.2.8`, so a future `npm install` (not `npm ci`,
    // which the lockfile pins) could resolve React 19.3 and put fiber outside its own peer range.
    //
    // This does not fail on that today, because it has not happened and pinning react to `~19.2.8`
    // to pre-empt it would diverge from the donor's pin for a problem nobody has. It fails if the
    // bound MOVES, so the day fiber widens or tightens it, somebody reads this comment.
    const fiber = readPackage(
      join(NODE_MODULES, "@react-three", "fiber", "package.json"),
    ) as { peerDependencies?: Record<string, string> };
    const peer = fiber.peerDependencies?.react ?? "";
    expect(peer).toBe(">=19 <19.3");
    expect(satisfies("19.3.0", peer)).toBe(false);
  });
});

describe("the pins the spatial frontend depends on", () => {
  // P7-C imports these at real call sites; they are declared here and nowhere else, because this
  // app has exactly one package.json and exactly one owner for it.
  it.each([
    ["three", "^0.185.1"],
    ["@react-three/fiber", "^9.7.0"],
    ["@react-three/drei", "^10.7.7"],
    ["@react-three/postprocessing", "^3.0.4"],
    ["postprocessing", "^6.39.4"],
    ["gsap", "^3.15.0"],
    ["react", "^19.2.8"],
    ["react-dom", "^19.2.8"],
  ])("declares %s at %s", (name, range) => {
    expect(manifest.dependencies[name]).toBe(range);
  });

  it("keeps react-router on 6.x — React Router 7 is not part of this upgrade", () => {
    // Deliberate. RR7 changes routing APIs across every page in the app; bundling that with a
    // React major would make a regression in either one impossible to bisect from the other.
    expect(manifest.dependencies["react-router-dom"]).toBe("^6.26.2");
    const installed = (
      readPackage(join(NODE_MODULES, "react-router-dom", "package.json")) as { version: string }
    ).version;
    expect(installed.startsWith("6.")).toBe(true);
  });

  it("keeps @xyflow/react at the version the existing topology views were built against", () => {
    expect(manifest.dependencies["@xyflow/react"]).toBe("^12.11.2");
  });
});
