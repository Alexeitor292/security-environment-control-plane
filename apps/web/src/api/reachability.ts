// Can a client actually GET to this route, starting from nothing?
//
// WHY THIS IS COMPUTED AND NOT DECLARED. A route existing does not make it usable. An endpoint
// that needs `{manifest_id}` is only reachable if a client can obtain a manifest id, which is only
// true if the route yielding one is itself reachable, and so on. That is a graph question, and
// every time it has been treated as a lookup it has been answered wrongly — including twice while
// this file was being written:
//
//   * Checking `/api/v1/plans` for a collection route, finding none, and concluding plan ids are
//     unobtainable. They are: `GET /api/v1/exercises/{exercise_id}/plan` returns `PlanOut`, which
//     carries `id`, and exercises ARE enumerable. The chain is two hops, not zero.
//   * Keying reachability on the PARAMETER NAME. `/range-operations/{operation_id}` and
//     `/provisioning-operations/{operation_id}` share a parameter name and are different id
//     spaces entirely, so a range operation appeared to unlock a provisioning operation. One word,
//     two concepts — keyed on the space now, never the spelling.
//
// GET EDGES ONLY, and this is the load-bearing rule. `POST /api/v1/plans/{plan_id}/manifest`
// returns a `ManifestOut` and is the ONLY way into the manifest id space — every GET that yields a
// manifest id needs a manifest, a change-set, or a provisioning-operation id, and those three form
// a closed cycle with no GET entry. So a manifest is reachable only by CREATING one, and "you can
// have it if you make one" is not reachability for a surface whose job is to show what already
// exists. Traversing POST edges would report an approvals inbox as buildable when it is not.

import type { AdapterMethod } from "./adapter-endpoint-map.ts";

/** The minimal shape of the committed OpenAPI document this analysis reads. */
export interface ContractDocument {
  paths: Record<string, Record<string, unknown>>;
  components?: { schemas?: Record<string, { properties?: Record<string, unknown> }> };
}

/**
 * An ID SPACE: the path prefix that owns a kind of identifier.
 *
 * `/api/v1/manifests/{manifest_id}` consumes the space `api/v1/manifests`. Spaces are compared,
 * never parameter names — see the note above about `operation_id`.
 */
export type IdSpace = string;

export interface Reachability {
  /** Every id space the contract requires somewhere, with the key field its routes use. */
  readonly spaces: ReadonlyMap<IdSpace, string>;
  /** Space -> the GET route that first yields one, following only GET edges from a free route. */
  readonly producedBy: ReadonlyMap<IdSpace, string>;
  /** True when every space this path consumes can be obtained by reading. */
  isReachable(path: string): boolean;
  /** The spaces this path needs that nothing GET-reachable produces. */
  unreachableSpacesOf(path: string): readonly IdSpace[];
}

function segmentsOf(path: string): string[] {
  return path.split("/").filter(Boolean);
}

/** The spaces a path consumes: one per `{param}`, named by the segment before it. */
function consumedSpaces(path: string): IdSpace[] {
  const segments = segmentsOf(path);
  const spaces: IdSpace[] = [];
  segments.forEach((segment, index) => {
    if (segment.startsWith("{") && index > 0) spaces.push(segments.slice(0, index).join("/"));
  });
  return spaces;
}

function responseSchemaName(operation: unknown): string | null {
  const responses = (operation as { responses?: Record<string, unknown> })?.responses;
  if (!responses) return null;
  for (const code of ["200", "201"]) {
    const schema = (
      responses[code] as
        | { content?: { "application/json"?: { schema?: Record<string, unknown> } } }
        | undefined
    )?.content?.["application/json"]?.schema;
    if (!schema) continue;
    const ref = schema["$ref"] as string | undefined;
    if (ref) return ref.split("/").pop() ?? null;
    const items = schema["items"] as { $ref?: string } | undefined;
    if (items?.$ref) return items.$ref.split("/").pop() ?? null;
  }
  return null;
}

/**
 * Raised when the analysis cannot honestly answer.
 *
 * A traversal that silently stops finding edges reports EVERYTHING as unreachable, with total
 * confidence and no indication that anything went wrong — and the output of this module decides
 * whether backend routes get built, so a confident wrong answer here becomes a queue of gaps that
 * are not gaps. The failure mode is not "slightly off"; it is a document full of fabricated work.
 *
 * So the analysis refuses rather than guesses. Borrowed from #127's audit guard, which raised
 * rather than reporting green when its two counting methods disagreed: a verifier willing to say
 * "I cannot measure this" is worth more than one that always produces a number.
 */
export class ReachabilityUnmeasurable extends Error {
  constructor(reason: string) {
    super(
      `reachability cannot be measured: ${reason}. Refusing to report — every space would read ` +
        "as unreachable, which is indistinguishable from a real finding and would be acted on.",
    );
    this.name = "ReachabilityUnmeasurable";
  }
}

export function analyseReachability(document: ContractDocument): Reachability {
  const paths = Object.keys(document.paths);
  const schemas = document.components?.schemas ?? {};

  // Every space, and the key field its routes address it by (`manifest_id`, `slug`, ...).
  const spaces = new Map<IdSpace, string>();
  for (const path of paths) {
    const segments = segmentsOf(path);
    segments.forEach((segment, index) => {
      if (!segment.startsWith("{") || index === 0) return;
      const space = segments.slice(0, index).join("/");
      if (!spaces.has(space)) spaces.set(space, segment.slice(1, -1));
    });
  }

  // Key names used by more than one space. A bare field with one of these names identifies a
  // KIND of id, not a specific space, so it is not evidence for any of them.
  const keyCounts = new Map<string, number>();
  for (const key of spaces.values()) keyCounts.set(key, (keyCounts.get(key) ?? 0) + 1);
  const ambiguousKeys = new Set([...keyCounts].filter(([, n]) => n > 1).map(([k]) => k));

  /** Which spaces a GET on this path yields an identifier for. */
  const producedSpaces = (path: string): IdSpace[] => {
    const name = responseSchemaName(document.paths[path]?.["get"]);
    if (!name) return [];
    const properties = new Set(Object.keys(schemas[name]?.properties ?? {}));
    if (properties.size === 0) return [];
    // `AuditEventOut` -> `audit-event`. The schema's own noun, used to decide WHICH space a bare
    // `id` belongs to. Without this the third clause below matched any schema with an `id` against
    // every space whose plural happened to fit, and `GET /api/v1/audit` appeared to unlock the
    // entire API — the same shape of error as keying on the parameter name, one layer in.
    const schemaNoun = name
      .replace(/(Out|Detail|Summary)$/, "")
      .replace(/(?<!^)(?=[A-Z])/g, "-")
      .toLowerCase();
    // The space this route is the COLLECTION of — the path as written, params included. Nested
    // spaces keep their parent parameter: `/api/v1/ranges/{range_id}/teams` is the space
    // `api/v1/ranges/{range_id}/teams`, not `api/v1/ranges/teams`. Stripping parameters here made
    // every nested collection fail to produce its own space, and the cross-check caught it by
    // reporting `listParticipants` as parent-unreachable when teams are perfectly enumerable
    // once a range is chosen.
    const ownPathSpace = segmentsOf(path).join("/");

    // A route NEVER produces a space it consumes. `GET /api/v1/manifests/{manifest_id}` returns a
    // manifest, but you had to know the manifest id to ask — an item read hands back what you
    // already had and bootstraps nothing. Without this, every `/X/{x_id}` route produced its own
    // space and the fixpoint declared the whole API reachable from itself.
    const selfConsumed = new Set(consumedSpaces(path));

    const yielded: IdSpace[] = [];
    for (const [space, key] of spaces) {
      if (selfConsumed.has(space)) continue;
      // Three ways a GET response hands a client an identifier for `space`:
      //
      //   1. it carries that space's KEY FIELD by name — `slug`, `manifest_id`. This is a plain
      //      cross-reference and the strongest signal.
      //   2. it carries a bare `id` and the route lives at that space — the ordinary item read.
      //   3. it carries a bare `id` and the SCHEMA is that space's item by name. This is what
      //      rescues plans: `PlanOut` from `/exercises/{id}/plan` is a plan, served elsewhere.
      // A bare reference field only counts when its name identifies ONE space. Seven key names
      // are shared in this contract — `operation_id` belongs to both `/provisioning-operations`
      // and `/range-operations`, `manifest_id` to both `/manifests` and `/provisioning-manifests`
      // — so a field called `operation_id` says an operation, not WHICH operation. Crediting it
      // to every candidate is how `ProxmoxCommandOut.operation_id` (a RANGE operation) appeared
      // to unlock provisioning operations, and through them manifests.
      //
      // Conservative on purpose. The optimistic error here reports a surface as buildable when it
      // is not, which sends a team to write a page against a route they cannot reach; the
      // pessimistic error reports a backend gap that turns out to be reachable, which costs a
      // conversation. An ambiguous reference is recorded as no evidence rather than as evidence
      // for all of them.
      const carriesKey = properties.has(key) && !ambiguousKeys.has(key);
      const isItemOfOwnPath = properties.has("id") && space === ownPathSpace;
      const isNamedItemOfSpace =
        properties.has("id") && space === `api/v1/${schemaNoun}s`;
      if (carriesKey || isItemOfOwnPath || isNamedItemOfSpace) yielded.push(space);
    }
    return yielded;
  };

  // Fixpoint over GET edges only, seeded by routes that consume nothing.
  const producedBy = new Map<IdSpace, string>();
  for (let changed = true; changed; ) {
    changed = false;
    for (const path of paths) {
      if (!("get" in (document.paths[path] ?? {}))) continue;
      if (!consumedSpaces(path).every((space) => producedBy.has(space))) continue;
      for (const space of producedSpaces(path)) {
        if (producedBy.has(space)) continue;
        producedBy.set(space, `GET ${path}`);
        changed = true;
      }
    }
  }

  // --- refuse rather than report a confident nothing -----------------------------------------
  //
  // Each of these means the analysis is not looking at what it thinks it is. None can be true of
  // a healthy contract, and all of them would otherwise produce "everything is unreachable".
  if (paths.length === 0) throw new ReachabilityUnmeasurable("the document declares no paths");
  if (Object.keys(schemas).length === 0) {
    throw new ReachabilityUnmeasurable("the document declares no component schemas");
  }
  if (spaces.size === 0) {
    throw new ReachabilityUnmeasurable("no path takes a parameter, so there are no id spaces");
  }
  // The seed. Every chain has to start at a route needing nothing; if not one of them yields an
  // identifier, no rule matched anything and the traversal never began.
  const seeds = paths.filter(
    (path) => "get" in (document.paths[path] ?? {}) && consumedSpaces(path).length === 0,
  );
  if (seeds.length === 0) {
    throw new ReachabilityUnmeasurable("no parameter-free GET route exists to start from");
  }
  if (producedBy.size === 0) {
    throw new ReachabilityUnmeasurable(
      `${seeds.length} parameter-free GET routes exist and none yields an identifier — the ` +
        "producer rules matched nothing, which is a rule failure and not an API without ids",
    );
  }

  return {
    spaces,
    producedBy,
    isReachable: (path) => consumedSpaces(path).every((space) => producedBy.has(space)),
    unreachableSpacesOf: (path) => consumedSpaces(path).filter((space) => !producedBy.has(space)),
  };
}

/**
 * Why a surface cannot be built. Same three members and spellings as
 * `spatial/integrations/query-state.ts`, so the document and the code a page branches on agree.
 */
export type UnavailableReason = "no-endpoint" | "parent-unreachable" | "parent-not-selected";

/**
 * Which side owns the fix. Mirrors `UNAVAILABLE_OWNER` in `spatial/integrations/query-state.ts`,
 * down to the `as const satisfies` form.
 *
 * `satisfies` rather than a type annotation, so a new reason without an owner is a BUILD ERROR
 * rather than a lookup that returns undefined at render time — and `as const` so the values stay
 * literal instead of widening to `string`. Copied deliberately: a third spelling of these
 * categories is the defect this program has hit repeatedly, and two modules that must agree
 * should fail to compile when they stop agreeing.
 */
export const REASON_OWNER = {
  "no-endpoint": "backend",
  "parent-unreachable": "backend",
  "parent-not-selected": "frontend",
} as const satisfies Record<UnavailableReason, "backend" | "frontend">;

export interface MethodAvailability {
  readonly method: AdapterMethod;
  readonly reason: UnavailableReason;
  /** For `parent-unreachable`: the spaces nothing GET-reachable produces. */
  readonly unreachableSpaces: readonly IdSpace[];
  /** For `parent-not-selected`: how a client obtains the id it needs. */
  readonly producingPath: string | null;
}

/**
 * Classify one adapter method by construction rather than by judgement.
 *
 * `no-endpoint` when nothing serves it. Otherwise the serving route needs ids: if any of them is
 * unobtainable by reading, `parent-unreachable` — a new COLLECTION route, backend work, and
 * distinctly not a request to rebuild the route that already serves. If all are obtainable, the
 * only thing missing is the operator choosing one: `parent-not-selected`, frontend work, no
 * backend ask at all. That last distinction is why this is computed: the two look identical from
 * a screen that has no data, and they go to different teams.
 */
export function classify(
  method: AdapterMethod,
  endpoints: readonly string[],
  reachability: Reachability,
): MethodAvailability {
  if (endpoints.length === 0) {
    return { method, reason: "no-endpoint", unreachableSpaces: [], producingPath: null };
  }
  const best = endpoints.find((path) => reachability.isReachable(path));
  if (best === undefined) {
    const unreachable = [...new Set(endpoints.flatMap((p) => reachability.unreachableSpacesOf(p)))];
    return { method, reason: "parent-unreachable", unreachableSpaces: unreachable, producingPath: null };
  }
  const needed = consumedSpaces(best);
  return {
    method,
    reason: "parent-not-selected",
    unreachableSpaces: [],
    producingPath:
      needed.map((space) => reachability.producedBy.get(space) ?? "?").join(" then ") || null,
  };
}
