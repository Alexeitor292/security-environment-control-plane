import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => Promise<T | null>;
}

/**
 * Minimal data-loading hook: runs `fn` on mount and exposes an awaitable reload.
 * Existing data stays visible while a refresh is in flight.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const seqRef = useRef(0);
  const mountedRef = useRef(true);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);

  const load = useCallback(async (): Promise<T | null> => {
    const seq = ++seqRef.current;
    const current = () => mountedRef.current && seqRef.current === seq;
    setLoading(true);
    setError(null);
    try {
      const d = await run();
      if (current()) setData(d);
      return d;
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (current()) setError(message);
      return null;
    } finally {
      if (current()) setLoading(false);
    }
  }, [run]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, loading, error, reload: load };
}
