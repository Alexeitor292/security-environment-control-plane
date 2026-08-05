// Rendering the five states, once, so no page invents its own collapse.
//
// The seam refuses to hand out a value that permits the states to be confused;
// this refuses to render two of them the same way. Both are needed: a type can
// describe a distinction that every consumer is free to flatten, and a page that
// writes its own `if (!rows.length) return <Empty/>` flattens it below the seam.
//
// Each branch says something DIFFERENT to the operator, because each is a
// different fact about why there is nothing on screen:
//
//   refused      you are not permitted to see this — and which permission
//   unavailable  the platform does not serve this — and whether that is a
//                missing route or a parent you have not chosen
//   empty        the control plane answered, and the answer was nothing
//   failed       the request did not succeed — and what went wrong
//
// `empty` is the only one that means "there is nothing". The other three all
// mean "we did not get to look", and rendering them as emptiness tells an
// operator the system is quiet when it is blocked, broken, or forbidden.

import type { ReactNode } from "react";

import { EmptyState, ErrorState, LoadingState } from "../apps/prototype-suite/core/components";
import { UNAVAILABLE_OWNER, type QueryState } from "./query-state";

export function QueryStateView<T>({
  state,
  emptyTitle,
  emptyBody,
  surface,
  children,
}: {
  state: QueryState<T>;
  emptyTitle: string;
  emptyBody?: string;
  /** What the operator was trying to see, in their words. */
  surface: string;
  children: (rows: readonly T[]) => ReactNode;
}) {
  switch (state.status) {
    case "loading":
      return <LoadingState lines={6} />;

    case "refused":
      // A permission fact, not a data fact. Naming the permission makes it
      // actionable; "no results" would make it invisible.
      return (
        <EmptyState
          title={`${surface} is not available to you`}
          body={`Requires ${state.requires.join(" or ")}. The control plane decides this; the page reflects it.`}
        />
      );

    case "unavailable":
      // A statement about the platform, not about the records. The owner is
      // carried so the notice can say whether this waits on a route or on a
      // choice the operator has not made yet.
      return (
        <EmptyState
          title={
            UNAVAILABLE_OWNER[state.reason] === "frontend"
              ? `Choose a range to see ${surface.toLowerCase()}`
              : `${surface} is not served by the control plane yet`
          }
          body={state.detail}
        />
      );

    case "failed":
      // Never an empty state. An outage behind a clean screen looks healthy.
      return <ErrorState message={state.error} />;

    case "empty":
      return <EmptyState title={emptyTitle} body={emptyBody} />;

    case "ready":
      return <>{children(state.rows)}</>;
  }
}
