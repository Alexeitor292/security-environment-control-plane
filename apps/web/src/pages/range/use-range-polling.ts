import { useEffect, useRef, useState } from "react";

import { useAsync, type AsyncState } from "../../hooks";

export interface PolledAsyncState<T> extends AsyncState<T> {
  /** True while a repeat interval is armed — drives the "live" indicator. */
  polling: boolean;
  /** Server responses observed since mount. Proves advance came from the backend. */
  refreshCount: number;
}

export interface PollOptions<T> {
  /**
   * Decide from the LAST SERVER RESPONSE whether to keep polling. Taking the decision from data
   * rather than from a caller flag is what stops a page polling forever after the range settles.
   */
  shouldPoll: (data: T | null) => boolean;
  intervalMs?: number;
}

const DEFAULT_INTERVAL_MS = 2500;

/**
 * `useAsync` plus a self-terminating refresh interval.
 *
 * The interval is armed only while `shouldPoll` accepts the most recent response, so a range that
 * has reached a settled phase stops generating traffic on its own. Each tick calls the same
 * `reload` the manual control uses — there is one fetch path, so what an operator sees advance is
 * always a fresh server read and never a client-side animation of expected progress.
 *
 * The timer is cleared on unmount and re-armed whenever the decision changes, so navigating away
 * mid-deploy leaves nothing running.
 */
export function usePolledAsync<T>(
  fn: () => Promise<T>,
  deps: unknown[],
  opts: PollOptions<T>,
): PolledAsyncState<T> {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const state = useAsync(fn, deps);
  const [refreshCount, setRefreshCount] = useState(0);
  const { data, reload } = state;
  const interval = opts.intervalMs ?? DEFAULT_INTERVAL_MS;

  // Read the predicate through a ref so a caller passing an inline arrow does not re-arm the timer
  // on every render.
  const shouldPollRef = useRef(opts.shouldPoll);
  shouldPollRef.current = opts.shouldPoll;

  const active = shouldPollRef.current(data);

  useEffect(() => {
    if (data !== null) setRefreshCount((n) => n + 1);
  }, [data]);

  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => {
      void reload();
    }, interval);
    return () => window.clearInterval(id);
  }, [active, interval, reload]);

  return { ...state, polling: active, refreshCount };
}
