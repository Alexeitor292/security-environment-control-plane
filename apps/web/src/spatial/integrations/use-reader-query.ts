// Running one reader call and reporting it as one of the five states.
//
// The seam (`query-state.ts`) defines the states; this is the only place that
// PRODUCES them, so the mapping from "what happened" to "which state" exists
// once rather than in every page.
//
// THE ORDER OF THE CHECKS IS THE DESIGN.
//
//   1. permission first — if the principal cannot hold the permission the server
//      requires, the request is not made at all. Not as an optimisation: firing
//      a request that is certain to 403 and then rendering the 403 as `failed`
//      would report a permission fact as an outage, which is the collapse the
//      five states exist to prevent.
//   2. availability second — a query whose endpoint does not exist, or whose
//      parent cannot be enumerated, is never dispatched either.
//   3. only then the request.
//
// A REJECTED PROMISE IS `failed`, NEVER `empty`. The catch branch cannot fall
// through to an empty array — that is the collapse that hides an outage behind a
// clean screen, and it is the easiest one to write by accident because
// `catch { setRows([]) }` looks like defensive coding.

import { useEffect, useState } from "react";

import { usePermissions, holdsAny } from "./principal";
import type { AdapterProvenance } from "./provenance";
import {
  failed,
  loading,
  refused,
  served,
  unavailable,
  type QueryState,
  type UnavailableReason,
} from "./query-state";

export interface ReaderQuery<T> {
  /** Permissions the SERVER requires. Empty means the route needs none. */
  readonly requires?: readonly string[];
  /** Set when no request can succeed, with the reason and a human detail. */
  readonly blocked?: { readonly reason: UnavailableReason; readonly detail: string };
  /** Where the rows come from, declared by the caller that chose the reader. */
  readonly provenance: AdapterProvenance;
  /** The call itself. Must reject on failure rather than returning nothing. */
  readonly run: () => Promise<readonly T[]>;
}

export function useReaderQuery<T>(query: ReaderQuery<T>, deps: readonly unknown[] = []): QueryState<T> {
  const held = usePermissions();
  const [state, setState] = useState<QueryState<T>>(loading);

  const requires = query.requires ?? [];
  const blocked = query.blocked;
  const permitted = holdsAny(held, requires);

  useEffect(() => {
    // 1. Permission. No request: a certain 403 rendered as `failed` would report
    //    a permission fact as an outage.
    if (!permitted) {
      setState(refused<T>(requires));
      return;
    }
    // 2. Availability. No request: there is nothing to call.
    if (blocked) {
      setState(unavailable<T>(blocked.reason, blocked.detail));
      return;
    }

    let cancelled = false;
    setState(loading);

    query
      .run()
      .then((rows) => {
        // `served` decides empty-vs-ready, so no caller can reintroduce the
        // collapse by testing `rows.length` itself.
        if (!cancelled) setState(served(rows, query.provenance));
      })
      .catch((err: unknown) => {
        // NEVER an empty list. An outage must not render as "nothing to see".
        if (!cancelled) {
          setState(failed<T>(err instanceof Error ? err.message : "request_failed"));
        }
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [permitted, blocked?.reason, blocked?.detail, query.provenance, ...deps]);

  return state;
}
