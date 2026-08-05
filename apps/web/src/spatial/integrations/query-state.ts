// The seam between the control-plane reader and the spatial pages.
//
// WHY THIS EXISTS RATHER THAN AN ADAPTER. The migrated pages read through
// `ControlPlaneAdapter`, and #118 deliberately did not implement it: satisfying
// that interface requires inventing `Team.color`, `Deployment.costToDate` and
// the four `ScoreEntry` components, because no endpoint supplies them. **An
// interface that can only be implemented by fabricating is not a seam, it is a
// demand.** So pages move off it one query at a time, onto view types that name
// their absences — and this module is the shape they all move onto.
//
// FIVE STATES THAT MUST NOT COLLAPSE INTO EACH OTHER.
//
//   loading      the answer is not back yet
//   refused      the principal lacks the permission; the server would refuse
//   unavailable  no endpoint serves this, or its parent is unreachable
//   empty        the control plane answered, and the answer is nothing
//   failed       the request was made and did not succeed
//
// Every pair of these is a different fact, and the collapses are the dangerous
// part rather than the states:
//
//   * `refused` rendered as `empty` tells an operator there is nothing to see
//     when the truth is they are not allowed to see it. Same defect as
//     `refused -> failed` on an audit outcome: a permission answer displayed as
//     a data answer.
//   * `unavailable` rendered as `empty` claims the platform has no such records
//     when the platform simply has no route.
//   * `empty` rendered as `loading` never resolves.
//   * `failed` rendered as `empty` hides an outage behind a clean screen, which
//     is the worst of the five because it looks healthy.
//
// PROVENANCE IS PER QUERY, NOT PER PAGE. `AuditPage` is live on its action log
// and fixture on its evidence table. A page-level flag would have to guess which
// one it is describing; carrying it on the result means `ProvenanceBoundary`'s
// absorbing rule composes from facts rather than from an assumption.

import type { AdapterProvenance } from "./provenance";

/**
 * Why a surface has no data, when the reason is not an error.
 *
 * The three exist because they fund DIFFERENT WORK, and that is the whole value
 * of splitting them. Two are backend items and one is not — stated here rather
 * than in a document, so nobody decides from prose which team a gap belongs to.
 */
export type UnavailableReason =
  /**
   * No registered route serves this concept at all.
   *
   * FIX: a new route. BACKEND (P7-A). Example: no facet surface exists for the
   * distinct set of audit outcomes, so a filter can only offer what the loaded
   * page happens to contain.
   */
  | "no-endpoint"
  /**
   * A route exists, but nothing enumerates the id it requires.
   *
   * FIX: a new COLLECTION route so the parent can be listed. BACKEND (P7-A), and
   * a different ask from `no-endpoint` — the serving route already exists and
   * must not be rebuilt. Example: change-sets are served per manifest, and
   * nothing lists manifests; plans ARE reachable via exercises, so the chain
   * breaks at exactly one level.
   */
  | "parent-unreachable"
  /**
   * A route exists and the operator has not chosen the parent yet.
   *
   * FIX: a selection step. FRONTEND (P7-D) — no backend work at all. Example:
   * evidence is range-scoped and `GET /api/v1/ranges` exists, so the surface is
   * buildable behind a range picker.
   */
  | "parent-not-selected";

/**
 * Which side owns the fix for each reason.
 *
 * Exported so a surface can say who is blocked rather than only that it is
 * blocked, and so an inventory of backend gaps can be derived from live states
 * instead of maintained by hand.
 */
export const UNAVAILABLE_OWNER = {
  "no-endpoint": "backend",
  "parent-unreachable": "backend",
  "parent-not-selected": "frontend",
} as const satisfies Record<UnavailableReason, "backend" | "frontend">;

export type QueryState<T> =
  | { readonly status: "loading" }
  | { readonly status: "refused"; readonly requires: readonly string[] }
  | { readonly status: "unavailable"; readonly reason: UnavailableReason; readonly detail: string }
  | { readonly status: "empty"; readonly provenance: AdapterProvenance }
  | { readonly status: "failed"; readonly error: string }
  | {
      readonly status: "ready";
      readonly rows: readonly T[];
      readonly provenance: AdapterProvenance;
    };

export const loading = (): QueryState<never> => ({ status: "loading" });

export const refused = <T>(requires: readonly string[]): QueryState<T> => ({
  status: "refused",
  requires,
});

export const unavailable = <T>(reason: UnavailableReason, detail: string): QueryState<T> => ({
  status: "unavailable",
  reason,
  detail,
});

export const failed = <T>(error: string): QueryState<T> => ({ status: "failed", error });

/**
 * A served result. Zero rows becomes `empty` rather than `ready` with an empty
 * array, so a renderer cannot treat "nothing came back" and "we have not asked"
 * as the same branch by falling through on `rows.length`.
 */
export function served<T>(
  rows: readonly T[],
  provenance: AdapterProvenance,
): QueryState<T> {
  return rows.length === 0
    ? { status: "empty", provenance }
    : { status: "ready", rows, provenance };
}

/** Rows if the query produced any, otherwise none. Never invents a row. */
export function rowsOf<T>(state: QueryState<T>): readonly T[] {
  return state.status === "ready" ? state.rows : [];
}

/**
 * Whether this state represents data the control plane actually served.
 *
 * `empty` counts: the answer was nothing, and nothing is an answer. `refused`
 * and `unavailable` do not — no reading happened, so there is no provenance to
 * report and a badge derived from them would be describing data that does not
 * exist.
 */
export function provenanceOf<T>(state: QueryState<T>): AdapterProvenance | null {
  return state.status === "ready" || state.status === "empty" ? state.provenance : null;
}

/**
 * The page's provenance, folded from its queries, with FIXTURE ABSORBING.
 *
 * A page showing one live reading and one fixture panel is a fixture page. The
 * cautious claim wins, exactly as `combineProvenance` does per value in
 * `domain/proxmox/provenance.ts`. Queries that served nothing contribute
 * nothing — a refused query must not make a live page look fixture-backed, nor
 * the reverse.
 */
export function pageProvenance(
  states: readonly QueryState<unknown>[],
): AdapterProvenance | null {
  const seen = states.map(provenanceOf).filter((p): p is AdapterProvenance => p !== null);
  if (seen.length === 0) return null;
  return seen.includes("fixture") ? "fixture" : "live";
}
