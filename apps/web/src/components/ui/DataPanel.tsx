import type { ReactNode } from "react";

import type { AsyncState } from "../../hooks";
import { EmptyState } from "./EmptyState";
import { Skeleton } from "./Skeleton";
import { resolvePanelState } from "./data-panel";

export interface DataPanelProps<T> {
  /** The useAsync result, passed through unchanged. */
  state: AsyncState<T>;
  /** Data present but nothing to show (e.g. empty list). */
  isEmpty?: (data: T) => boolean;
  /** Custom empty state (defaults to a generic EmptyState). */
  empty?: ReactNode;
  skeletonLines?: number;
  children: (data: T) => ReactNode;
}

/**
 * Standard render wrapper over the AsyncState contract: skeleton for
 * structural first loads only (cached data stays visible through reloads),
 * error box for failed loads, EmptyState for empty data, content otherwise.
 *
 * Load errors render AsyncState.error verbatim — parity with today's
 * .error-box pages. Note that for HTTP-level failures that string is the
 * backend envelope's message (useAsync flattens ApiClientError to a string,
 * losing the code), so this is NOT closed-code copy; making useAsync preserve
 * codes is a follow-up. Mutation errors should use ClosedCodeError +
 * useAction, which do preserve closed codes.
 */
export function DataPanel<T>({
  state,
  isEmpty,
  empty,
  skeletonLines,
  children,
}: DataPanelProps<T>) {
  const panelState = resolvePanelState({
    loading: state.loading,
    error: state.error,
    hasData: state.data !== null,
    isEmpty: state.data !== null && isEmpty ? isEmpty(state.data) : false,
  });
  if (panelState === "skeleton") {
    return (
      <>
        <span role="status" className="ui-sr-only">
          Loading
        </span>
        <Skeleton lines={skeletonLines} />
      </>
    );
  }
  if (panelState === "error") {
    return <div className="error-box">{state.error}</div>;
  }
  if (panelState === "empty") {
    return <>{empty ?? <EmptyState title="Nothing to show yet" />}</>;
  }
  return <>{children(state.data as T)}</>;
}
