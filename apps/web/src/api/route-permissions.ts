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

const TABLE = permissions as Record<RouteKey, { permissions: string[] }>;

/**
 * What a route requires, or `null` when the resolver could not tell.
 *
 * `null` is NOT "requires nothing". The walk reaching no `require` and there being no gate are
 * different facts, and only one of them is safe to render — a client told "this needs nothing"
 * shows the control to everyone. `VERIFIED_UNGUARDED` in the Python test records the routes that
 * were read by hand and found genuinely open; everything else stays unknown here.
 */
export function permissionsFor(route: RouteKey): readonly string[] | null {
  const entry = TABLE[route];
  if (entry === undefined) return null;
  return entry.permissions.length > 0 ? entry.permissions : null;
}

/** Every route the artifact knows, for tests that assert coverage rather than sample it. */
export function knownRoutes(): readonly RouteKey[] {
  return Object.keys(TABLE);
}
