// Which permission each reader's route requires — from the call graph, not from the path.
//
// A surface that says "you need X to see this" is making a claim about the server. Wrong in the
// permissive direction it offers a control the server will refuse; wrong in the restrictive
// direction it hides a surface the operator is entitled to. And the answer is not guessable:
// `GET /api/v1/ranges` requires `exercise:operate`, `GET /api/v1/target-discovery/read-only-
// bootstrap/worker-nodes` requires `target_discovery:manage`, and `GET /api/v1/targets` requires
// nothing beyond authentication. Three routes, three unrelated answers, no pattern.
//
// `contracts/openapi/route-permissions.json` is produced by `scripts/resolve_route_permissions.py`
// walking route -> handler -> service -> `principal.require(Permission.X)`, and
// `tests/test_route_permissions.py` pins the answers that matter against hand reads. This module
// is the read side of that artifact; it transcribes nothing.

import permissions from "../../../../contracts/openapi/route-permissions.json";

/** `"GET /api/v1/ranges"` -> the permission names its call graph requires. */
export type RouteKey = string;

const TABLE = permissions as Record<RouteKey, { state: string; permissions: string[] }>;

/**
 * What a route requires — THREE states, and collapsing any two is a real defect.
 *
 * A discriminated union rather than `string[] | null`, because `null` and `[]` are one `??` away
 * from each other and mean opposite things. `owner-spatial-migration` is wiring `requires: []` for
 * a route this module would have returned `null` for; both are correct and they are not the same
 * claim, so the type makes them impossible to confuse at the call site.
 *
 *   requires  the call graph resolved a gate; render "you need X"
 *   open      somebody READ the code and there is no gate; the control is for everyone
 *   unknown   the walk found nothing, which is not the same as finding nothing there
 *
 * `unknown` must never render as `open`. That is precisely what a broken walk produces — every
 * route reporting no permission — and it shows every control to everyone.
 */
export type RouteRequirement =
  | { readonly state: "requires"; readonly permissions: readonly string[] }
  | { readonly state: "open" }
  | { readonly state: "unknown" };

export function requirementFor(route: RouteKey): RouteRequirement {
  const entry = TABLE[route];
  if (entry === undefined) return { state: "unknown" };
  if (entry.state === "requires" && entry.permissions.length > 0) {
    return { state: "requires", permissions: entry.permissions };
  }
  if (entry.state === "open") return { state: "open" };
  return { state: "unknown" };
}

/** Every route the artifact knows, for tests that assert coverage rather than sample it. */
export function knownRoutes(): readonly RouteKey[] {
  return Object.keys(TABLE);
}
