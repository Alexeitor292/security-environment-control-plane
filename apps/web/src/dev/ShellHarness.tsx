/**
 * DEV-ONLY harness that mounts the migrated spatial shell exactly as the app
 * mounts it, for side-by-side comparison against the donor prototype.
 *
 * WHY NOT THE REAL ROUTE. `/spatial` renders inside `AuthBoundary`, which needs
 * `/api/v1/auth/config` and `/api/v1/me`; reaching it requires a running control
 * plane. That guard is verified separately and structurally by
 * `spatial/route-guard.test.ts`, which proves every mount of the workspace sits
 * inside the boundary. This harness therefore compares the SHELL, and states so
 * -- it is not evidence about the auth composition, and must not be read as any.
 *
 * WHAT IT RENDERS. `SpatialWorkspace`, unmodified: the same component the route
 * renders, which is `SecpShell` plus the prototype's global stylesheet. The
 * donor's own entry point is `App.tsx` rendering `<SecpShell />` with
 * `index.css` imported in `main.tsx`, so the two sides mount the same
 * composition and any difference on screen is a difference in the migrated code
 * rather than in how it was mounted.
 *
 * It models nothing and owns no state. StrictMode matches `main.tsx`; the donor
 * runs under StrictMode too, so neither side gets an easier ride.
 *
 * Excluded from the production bundle: `vite build` takes `index.html` as its
 * only input, so neither this module nor `shell-harness.html` is reachable from
 * the shipped app.
 */

import { StrictMode } from "react";
import ReactDOM from "react-dom/client";

import { SpatialWorkspace } from "../spatial/SpatialWorkspace";

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Root element was not found.");

ReactDOM.createRoot(rootElement).render(
  <StrictMode>
    <SpatialWorkspace />
  </StrictMode>,
);
