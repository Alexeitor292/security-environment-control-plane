/**
 * DEV-ONLY behavioural harness for the migrated Three.js scene.
 *
 * WHY IT EXISTS. The dependency gate that landed React 19 and the 3D runtime
 * proved the STATIC half honestly and said so: the packages resolve, satisfy
 * their peers, typecheck against `@types/three`, and coexist with exactly one
 * React runtime. But nothing on that branch imported `three`,
 * `@react-three/fiber`, `@react-three/drei` or `gsap` at runtime, so fiber,
 * drei, glTF loading, animation cleanup and WebGL context cleanup were never
 * exercised. There was no WebGL context on that branch to leak.
 *
 * The vitest suite cannot close that gap either, and not for want of trying:
 * **jsdom has no WebGL**. `canvas.getContext("webgl2")` returns null there, so
 * `<Canvas>` cannot create a renderer and the scene cannot mount at all. A test
 * that mocked the context would be testing the mock. So the behavioural half is
 * verified where a real WebGL context exists — a browser — and this file is what
 * makes that repeatable rather than a one-off.
 *
 * WHY NOT THE REAL ROUTE. `/spatial` sits inside `AuthBoundary`, which needs
 * `/api/v1/auth/config` and `/api/v1/me`; reaching it would require a running
 * control plane. This harness mounts the shipped `EnrollmentScene` directly. No
 * router, no auth, no network beyond the model itself.
 *
 * HOW IT MEASURES. Everything is observed from OUTSIDE the product code, by
 * patching browser APIs before the first mount. No scene component is modified,
 * imported differently, or given a test-only prop — so what is measured is the
 * component as shipped, not a variant of it that exists to be measurable.
 *
 * IT IS NOT A SECOND IMPLEMENTATION. It renders `EnrollmentScene` and owns
 * nothing but a mount toggle. It models no scene behaviour.
 *
 * Excluded from the production bundle: `vite build` takes `index.html` as its
 * only input, so neither this module nor `scene-harness.html` is reachable from
 * the shipped app — the same guarantee `A11yHarness.tsx` relies on.
 *
 * StrictMode is deliberately ON, matching `main.tsx`, so every effect in the
 * scene tree mounts, unmounts and remounts on each pass. That is precisely what
 * catches a subscription released in the wrong place.
 */

import gsap from "gsap";
import { StrictMode, useCallback, useEffect, useState } from "react";
import ReactDOM from "react-dom/client";

import { EnrollmentScene } from "../spatial/scene/EnrollmentScene";

interface SceneProbe {
  /** Times the scene has been asked to mount. */
  mounts: number;
  /** Times `SceneReadyProbe` reported the scene ready. */
  ready: number;
  /** WebGL contexts handed out by the browser since the harness loaded. */
  contextsCreated: number;
  /** Contexts the browser forcibly reclaimed — non-zero means exhaustion. */
  contextsLost: number;
  /** Draw calls issued. Non-zero proves something actually rendered. */
  draws: number;
  /** gsap timelines currently attached to the global timeline. */
  gsapTimelines: () => number;
  /** Resource timings for the glTF model, proving it was really fetched. */
  modelLoads: () => { name: string; decodedBodySize: number }[];
  mount: () => void;
  unmount: () => void;
  /** Mount and unmount `n` times, awaiting readiness each time. */
  cycle: (n: number) => Promise<void>;
}

declare global {
  interface Window {
    __scene: SceneProbe;
  }
}

// --- instrumentation, installed before anything mounts -----------------------

const probe = {
  mounts: 0,
  ready: 0,
  contextsCreated: 0,
  contextsLost: 0,
  draws: 0,
};

const realGetContext = HTMLCanvasElement.prototype.getContext;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
HTMLCanvasElement.prototype.getContext = function (this: HTMLCanvasElement, ...args: any[]) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ctx = (realGetContext as any).apply(this, args);
  const kind = String(args[0] ?? "");
  if (ctx && (kind === "webgl" || kind === "webgl2" || kind === "experimental-webgl")) {
    probe.contextsCreated += 1;
    this.addEventListener("webglcontextlost", () => {
      probe.contextsLost += 1;
    });
  }
  return ctx;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
} as any;

// Draw-call counters. A render loop that keeps running after unmount keeps
// incrementing these, which is how a leaked `useFrame` subscription becomes
// visible from outside without inspecting fiber's internals.
for (const proto of [
  typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype : null,
  typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext.prototype : null,
]) {
  if (!proto) continue;
  for (const method of ["drawElements", "drawArrays"] as const) {
    const real = proto[method];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (proto as any)[method] = function (this: WebGLRenderingContext, ...args: any[]) {
      probe.draws += 1;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (real as any).apply(this, args);
    };
  }
}

// --- harness -----------------------------------------------------------------

function Harness() {
  const [mounted, setMounted] = useState(false);
  const [, force] = useState(0);

  const onReady = useCallback(() => {
    probe.ready += 1;
  }, []);

  useEffect(() => {
    window.__scene = {
      get mounts() {
        return probe.mounts;
      },
      get ready() {
        return probe.ready;
      },
      get contextsCreated() {
        return probe.contextsCreated;
      },
      get contextsLost() {
        return probe.contextsLost;
      },
      get draws() {
        return probe.draws;
      },
      gsapTimelines: () => gsap.globalTimeline.getChildren(true, true, false).length,
      modelLoads: () =>
        performance
          .getEntriesByType("resource")
          .filter((e) => e.name.endsWith(".glb"))
          .map((e) => ({
            name: e.name,
            decodedBodySize: (e as PerformanceResourceTiming).decodedBodySize,
          })),
      mount: () => {
        probe.mounts += 1;
        setMounted(true);
        force((n) => n + 1);
      },
      unmount: () => {
        setMounted(false);
        force((n) => n + 1);
      },
      cycle: async (n: number) => {
        for (let i = 0; i < n; i += 1) {
          window.__scene.mount();
          await new Promise((r) => setTimeout(r, 260));
          window.__scene.unmount();
          await new Promise((r) => setTimeout(r, 120));
        }
      },
    };
  }, []);

  return (
    <div style={{ position: "fixed", inset: 0, background: "#010611" }}>
      {mounted ? <EnrollmentScene active onReady={onReady} /> : null}
    </div>
  );
}

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Root element was not found.");

ReactDOM.createRoot(rootElement).render(
  <StrictMode>
    <Harness />
  </StrictMode>,
);
