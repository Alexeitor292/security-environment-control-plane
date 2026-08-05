// Every migrated page must still be reachable, and every route must still have a page.
//
// WHY THIS EXISTS. P7-C's acceptance is "no route or page missing". That was true
// at migration time and was verified against the donor tree by direct comparison
// -- but the donor lives outside this repository and will not exist in CI, so
// that comparison can never be re-run. Without a standing check, a page can be
// orphaned later (dropped from the router but left on disk) or a route can point
// at a page that was deleted, and nothing would notice: an unrouted page still
// compiles, still lints, and still typechecks. It is simply unreachable.
//
// WHAT MAKES THIS MORE THAN A RESTATEMENT. The check does not compare a list to
// a list I wrote. It cross-references two INDEPENDENT artifacts, maintained by
// different people for different reasons -- the set of page modules on disk, and
// the set of pages the route tables import -- and requires them to agree.
// Neither is derived from the other, so a mistake in either shows up as a
// disagreement.
//
// WHY `import.meta.glob` RATHER THAN `node:fs`. This package does not depend on
// `@types/node`, and `tsconfig.json` pins `"types": ["vitest/globals"]`. Both of
// those files belong to P7-B, so reaching into them to make a test compile is
// not this slice's call. Vite's glob is a first-class alternative that needs
// neither, and it resolves through the same module graph the application uses --
// which makes it a slightly better witness anyway.

import { describe, expect, it } from "vitest";

import RAW_DEPLOY_ROUTER from "./apps/deployments/DeploymentsApp.tsx?raw";
import RAW_SUITE_ROUTER from "./apps/prototype-suite/PrototypeSuiteApp.tsx?raw";

// Page modules on disk. `eager: false` keeps this a map of paths to loaders --
// the keys are all this needs, and it avoids importing 47 modules (and the
// three.js runtime behind some of them) just to count them.
const SUITE_PAGE_FILES = import.meta.glob("./apps/prototype-suite/core/features/**/*Page.tsx");
const DEPLOY_PAGE_FILES = import.meta.glob("./apps/deployments/prototype/features/**/*Page.tsx");

// The rack models, resolved through Vite exactly as the browser would resolve
// them. A missing or renamed file yields an empty map.
const MODELS = import.meta.glob("../../public/models/*.glb", { query: "?url", eager: true });

/** Bare component names from a set of `*Page.tsx` module paths. */
function pageNames(modules: Record<string, unknown>): string[] {
  return Object.keys(modules)
    .map((path) => path.split("/").pop()?.replace(/\.tsx$/, "") as string)
    .sort();
}

/** Page components a router actually imports, keyed on the MODULE name. */
function importedPages(routerSource: string): string[] {
  const names = new Set<string>();

  // The local binding may be renamed -- `SettingsPage` is imported as
  // `PlatformSettingsPage` -- so the module name is what must be compared.
  for (const m of routerSource.matchAll(/^import\s+\w+\s+from\s+["'][^"']*\/([\w/]*Page)["']/gm)) {
    names.add(m[1].split("/").pop() as string);
  }

  return [...names].sort();
}

/** Routes declared in a router file, by their `path` literal. */
function declaredRoutes(routerSource: string): string[] {
  return [...routerSource.matchAll(/path="([^"]*)"/g)].map((m) => m[1]);
}

describe("spatial migration completeness", () => {
  it("routes every page module in the prototype suite (no orphans, no dangling imports)", () => {
    const onDisk = pageNames(SUITE_PAGE_FILES);
    const routed = importedPages(RAW_SUITE_ROUTER);

    // Non-vacuity: a glob that matched nothing, or a regex that captured
    // nothing, would make the equality below pass while checking nothing at all.
    expect(onDisk.length).toBeGreaterThan(30);
    expect(routed.length).toBeGreaterThan(30);

    // Set equality both ways. `onDisk \ routed` catches a page that exists but is
    // unreachable; `routed \ onDisk` catches a route importing a deleted page.
    expect(routed).toEqual(onDisk);
  });

  it("routes every page module in the deployments sub-app", () => {
    const onDisk = pageNames(DEPLOY_PAGE_FILES);
    const routed = importedPages(RAW_DEPLOY_ROUTER);

    expect(onDisk.length).toBeGreaterThan(5);
    expect(routed).toEqual(onDisk);
  });

  it("keeps the full migrated route surface declared", () => {
    // Counts, not an enumeration: the identity of each path is already asserted
    // by the page cross-reference above, and duplicating the list here would be
    // the restatement this file is built to avoid. What a count adds is a
    // tripwire on silent REMOVAL -- deleting a route together with its page
    // keeps both sets equal above, and only the count notices.
    //
    // 41, not the donor's 42. The donor's secrets-management route under
    // `/platform`, and the page behind it, were removed deliberately: two
    // backend guards
    // (`test_openbao_resolver.py`, `test_resolver_activation_security.py`)
    // forbid any frontend reference to a secret-reading route, because secret
    // resolution in this product is sealed and worker-side and must not have a
    // browser surface at all. The donor was drawn as a mock without that
    // constraint. This count was lowered by one BECAUSE of that removal -- if it
    // ever needs lowering again, the reason must be equally explicit, since a
    // silently decremented number is how a missing page stops being noticed.
    expect(declaredRoutes(RAW_SUITE_ROUTER).length).toBe(41);
    expect(declaredRoutes(RAW_DEPLOY_ROUTER).length).toBe(11);
  });

  it("still contains the Three.js scene, its probes, and the animation modules", async () => {
    // The scene is the part of this migration most likely to be quietly replaced
    // by a placeholder, and the part where a placeholder is least visible in a
    // diff -- an empty <Canvas/> renders without erroring.
    const sources = import.meta.glob(
      ["./scene/**/*.tsx", "./components/ai-core/{AiCoreOrb,GradientOrb}.tsx"],
      { query: "?raw", import: "default", eager: true },
    ) as Record<string, string>;

    const required = [
      "EnrollmentScene",
      "CameraRig",
      "DatacenterEnvironment",
      "ServerLane",
      "ServerRack",
      "LocalContainerScene",
      "SceneReadyProbe",
      "SceneIntroCompletionProbe",
      "AiCoreOrb",
      "GradientOrb",
    ];

    for (const name of required) {
      const entry = Object.entries(sources).find(([path]) => path.endsWith(`/${name}.tsx`));
      expect(entry, `${name}.tsx must exist`).toBeTruthy();

      // Presence is not enough -- assert each still reaches the 3D/animation
      // runtime, so a file stubbed down to `return null` fails here.
      //
      // The R3F intrinsics (<group>, <mesh>, <pointLight>) count as reaching
      // that runtime: ServerLane.tsx composes the scene purely out of them and
      // imports none of the packages, because @react-three/fiber supplies those
      // elements through GLOBAL JSX augmentation rather than through an import.
      // Requiring an import here would have failed a file that is entirely 3D code.
      expect(entry?.[1], name).toMatch(
        /@react-three|from 'three'|from "three"|gsap|useFrame|shader|<(group|mesh|points|primitive|[a-z]+Light|[a-z]+Geometry|[a-z]+Material)[\s>]/,
      );
    }
  });

  it("resolves the scene's configured model URL to a model that Vite can serve", async () => {
    // Why this is worth asserting at all: a glTF binary that is missing,
    // renamed, or truncated produces an EMPTY SCENE AT RUNTIME and no other
    // symptom. No build error, no type error, nothing a conventional test sees.
    //
    // So rather than checking that some file mentions ".glb", this follows the
    // ACTUAL configured URL and requires Vite to resolve a real asset for it.
    const config = (await import("./scene/config/scene.ts?raw")).default;
    const url = /url:\s*'([^']+\.glb)'/.exec(config)?.[1];

    expect(url, "scene config must declare a .glb model url").toBeTruthy();

    const filename = (url as string).split("/").pop() as string;
    const resolved = Object.keys(MODELS).filter((p) => p.endsWith(`/${filename}`));

    expect(resolved, `${filename} must exist under public/models`).toHaveLength(1);
  });
});
