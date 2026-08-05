// Every migrated page must still be reachable, and every route must still have a page.
//
// WHY THIS EXISTS. P7-C's acceptance is "no route or page missing". That was true
// at migration time and was verified against the donor tree by direct comparison
// -- but the donor lives outside this repository and will not exist in CI, so
// that comparison cannot be re-run. Without a standing check, a page can be
// orphaned later (dropped from the router but left on disk) or a route can point
// at a page that was deleted, and nothing would notice: an unrouted page still
// compiles, still lints, and still typechecks. It is simply unreachable.
//
// WHAT MAKES THIS MORE THAN A RESTATEMENT. The check does not compare a list to
// a list I wrote. It cross-references two INDEPENDENT artifacts that are
// maintained by different people for different reasons -- the set of page
// modules on the filesystem, and the set of pages the route tables import -- and
// requires them to agree. Neither is derived from the other, so a mistake in
// either one shows up as a disagreement.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const SPATIAL = join(__dirname);

/** Every `*Page.tsx` module under a features directory, as a bare component name. */
function pageModules(root: string): string[] {
  const found: string[] = [];

  function walk(dir: string): void {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith("Page.tsx")) found.push(entry.replace(/\.tsx$/, ""));
    }
  }

  walk(root);
  return found.sort();
}

/** Page components a router actually imports. */
function importedPages(routerFile: string): string[] {
  const src = readFileSync(routerFile, "utf8");
  const names = new Set<string>();

  for (const m of src.matchAll(/^import\s+(\w+)\s+from\s+["'][^"']*\/([\w/]*Page)["']/gm)) {
    // The local binding may be renamed (`SettingsPage` is imported as
    // `PlatformSettingsPage`), so key on the MODULE name, not the binding.
    names.add(m[2].split("/").pop() as string);
  }

  return [...names].sort();
}

/** Routes declared in a router file, by their `path` literal. */
function declaredRoutes(routerFile: string): string[] {
  const src = readFileSync(routerFile, "utf8");
  return [...src.matchAll(/path="([^"]*)"/g)].map((m) => m[1]);
}

const SUITE_ROUTER = join(SPATIAL, "apps/prototype-suite/PrototypeSuiteApp.tsx");
const SUITE_FEATURES = join(SPATIAL, "apps/prototype-suite/core/features");
const DEPLOY_ROUTER = join(SPATIAL, "apps/deployments/DeploymentsApp.tsx");
const DEPLOY_FEATURES = join(SPATIAL, "apps/deployments/prototype/features");

describe("spatial migration completeness", () => {
  it("routes every page module in the prototype suite (no orphans, no dangling imports)", () => {
    const onDisk = pageModules(SUITE_FEATURES);
    const routed = importedPages(SUITE_ROUTER);

    // Non-vacuity: a bug in either helper that returned [] would make the
    // equality below pass while checking nothing at all.
    expect(onDisk.length).toBeGreaterThan(30);

    // Set equality both ways. `onDisk \ routed` catches a page that exists but
    // is unreachable; `routed \ onDisk` catches a route importing a deleted page.
    expect(routed).toEqual(onDisk);
  });

  it("routes every page module in the deployments sub-app", () => {
    const onDisk = pageModules(DEPLOY_FEATURES);
    const routed = importedPages(DEPLOY_ROUTER);

    expect(onDisk.length).toBeGreaterThan(5);
    expect(routed).toEqual(onDisk);
  });

  it("keeps the full migrated route surface declared", () => {
    // Counts, not an enumeration: the identity of each path is already asserted
    // by the page cross-reference above, and duplicating the list here would be
    // the restatement this file is built to avoid. What a count adds is a
    // tripwire on silent REMOVAL -- deleting a route while deleting its page
    // keeps both sets equal above, and only the count notices.
    expect(declaredRoutes(SUITE_ROUTER).length).toBe(42);
    expect(declaredRoutes(DEPLOY_ROUTER).length).toBe(11);
  });

  it("still contains the Three.js scene, its probes, and the animation modules", () => {
    // The scene is the part of this migration most likely to be quietly replaced
    // by a placeholder, and the part where a placeholder is least visible in a
    // diff -- an empty <Canvas/> renders without erroring.
    const files = [
      "scene/EnrollmentScene.tsx",
      "scene/components/CameraRig.tsx",
      "scene/components/DatacenterEnvironment.tsx",
      "scene/components/ServerLane.tsx",
      "scene/components/ServerRack.tsx",
      "scene/containers/LocalContainerScene.tsx",
      "scene/SceneReadyProbe.tsx",
      "scene/SceneIntroCompletionProbe.tsx",
      "components/ai-core/AiCoreOrb.tsx",
      "components/ai-core/GradientOrb.tsx",
    ];

    for (const rel of files) {
      const src = readFileSync(join(SPATIAL, rel), "utf8");
      // Presence is not enough -- assert each still reaches the 3D/animation
      // runtime, so a file stubbed down to a `return null` fails here.
      //
      // The R3F intrinsics (`<group>`, `<mesh>`, `<pointLight>`) count as
      // reaching that runtime: `ServerLane.tsx` composes the scene purely out of
      // them and imports none of the packages, because @react-three/fiber
      // supplies those elements through global JSX augmentation rather than
      // through an import. Requiring an import here would have failed a file
      // that is entirely 3D code.
      expect(src, rel).toMatch(
        /@react-three|from 'three'|from "three"|gsap|useFrame|shader|<(group|mesh|points|line|primitive|[a-z]+Light|[a-z]+Geometry|[a-z]+Material)[\s>]/,
      );
    }
  });

  it("resolves the scene's model URL to a real file of the expected size", () => {
    // The strongest available check on the 3D asset, and the reason it is worth
    // writing: a glTF binary that is missing, renamed, or truncated produces an
    // EMPTY SCENE AT RUNTIME and nothing else. No build error, no type error, no
    // console failure that a test would see. So rather than asserting that some
    // source file mentions ".glb", this follows the actual configured URL to the
    // actual file on disk and checks its byte count.
    const config = readFileSync(join(SPATIAL, "scene/config/scene.ts"), "utf8");
    const url = /url:\s*'([^']+\.glb)'/.exec(config)?.[1];

    expect(url, "scene config must declare a .glb model url").toBeTruthy();

    // `public/` is served at the web root, so a leading-slash URL maps there.
    const onDisk = join(SPATIAL, "../../public", url as string);
    const bytes = statSync(onDisk).size;

    // Pinned exactly. A partial copy or an LFS pointer stub (~130 bytes) would
    // still satisfy "file exists" and would still render nothing.
    expect(bytes).toBe(6_148_672);
  });
});
