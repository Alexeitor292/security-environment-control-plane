import { useCallback, useEffect, useRef, useState } from "react";

import {
  resolveClosedCodeCopy,
  type ClosedCodeCopy,
} from "./closed-code-error";

export interface ActionState {
  busy: boolean;
  /** Closed-code copy for the last failure - never a raw backend message. */
  error: ClosedCodeCopy | null;
  /** Run a mutation; `onDone` (typically a reload) fires only on success. */
  run: (
    fn: () => Promise<unknown>,
    onDone?: () => void | Promise<unknown>,
  ) => Promise<void>;
  clearError: () => void;
}

/**
 * Shared mutation wrapper replacing the per-page busy/setError/try/finally
 * boilerplate. Errors resolve through the closed-code map: pass the page's
 * own `codeText` for page-specific codes.
 */
export function useAction(opts?: {
  codeText?: Record<string, string>;
}): ActionState {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ClosedCodeCopy | null>(null);
  const codeText = opts?.codeText;

  // Mirror the useAsync active-flag pattern: only the latest run may write
  // state, and nothing (including onDone) fires after unmount.
  const seqRef = useRef(0);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const run = useCallback(
    async (
      fn: () => Promise<unknown>,
      onDone?: () => void | Promise<unknown>,
    ) => {
      const seq = ++seqRef.current;
      const current = () => mountedRef.current && seqRef.current === seq;
      setBusy(true);
      setError(null);
      try {
        await fn();
        if (current()) await onDone?.();
      } catch (e) {
        if (current()) setError(resolveClosedCodeCopy(e, codeText));
      } finally {
        if (current()) setBusy(false);
      }
    },
    [codeText],
  );

  const clearError = useCallback(() => setError(null), []);
  return { busy, error, run, clearError };
}
