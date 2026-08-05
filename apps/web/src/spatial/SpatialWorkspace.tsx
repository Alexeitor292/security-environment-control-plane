/**
 * Mount point for the spatial shell inside the SECP application.
 *
 * This replaces the prototype's `src/App.tsx` + `src/main.tsx` pair, which
 * created their own React root and rendered `<SecpShell />` into a bare page
 * with no notion of who was looking at it. Here the shell renders only for an
 * authenticated principal, because the route that renders this component sits
 * inside `AuthBoundary`.
 *
 * WHY THIS IS NOT NESTED IN `App`
 *
 * `App` supplies `AppShell` -- the legacy sidebar/header chrome. The spatial
 * shell brings its own dock, notch and home stage and paints `position: fixed;
 * inset: 0`, so nesting the two would put two competing navigations on screen
 * and let the spatial surface cover the chrome it was nested inside. The
 * requirement is that the shell mount *inside the auth boundary*, which it
 * does; it is the chrome, not the authentication, that it stands apart from.
 *
 * WHY THE STYLESHEET IS IMPORTED HERE
 *
 * `spatial/index.css` is the prototype's global stylesheet: it sets `:root`
 * colour and font, `body { overflow: hidden }`, and a dark background on
 * `html, body, #root`. Those are deliberately global -- the product is
 * dark-only -- but they are not scoped, so importing them from a module that
 * the legacy pages also load would restyle those pages as a side effect. The
 * route that renders this component is code-split (see `main.tsx`), so the
 * stylesheet is fetched only once a user actually opens the spatial workspace.
 */

import { SecpShell } from './shell/SecpShell'
import './index.css'

export function SpatialWorkspace() {
  return <SecpShell />
}

export default SpatialWorkspace
