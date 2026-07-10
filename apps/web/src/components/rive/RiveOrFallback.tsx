import { Suspense, lazy, useEffect, useState, type ReactNode } from "react";

import { usePrefersReducedMotion } from "../backgrounds/useAmbientMotion";

// The Rive runtime is heavy and optional. It is lazy-loaded so it is code-split
// out of the main bundle and only fetched when an animated (non-reduced-motion)
// wrapper actually mounts. The CSS/SVG fallback renders immediately and always
// remains as the ground truth — a missing or failed .riv never blanks the area.
const RiveCanvas = lazy(() => import("./RiveCanvas"));

export interface RiveOrFallbackProps {
  /** Public runtime path, e.g. /rive/sealed-lock.riv (may be absent). */
  src: string;
  stateMachine: string;
  /** Numeric/boolean inputs already mapped from real state (never raw backend
   *  strings). Applied to the Rive state machine when the runtime loads. */
  inputs?: Record<string, number | boolean>;
  /** Always-present static representation. Shown under reduced motion, before
   *  load, and permanently if the runtime or asset fails. */
  fallback: ReactNode;
  /** Accessible label lives on the fallback; the animated layer is decorative. */
  className?: string;
  width?: number;
  height?: number;
}

/**
 * Renders the static fallback, and — only when motion is allowed — attempts to
 * overlay the Rive animation. Any load/runtime failure is swallowed to the
 * fallback (no user-facing error text). Nothing here contains business logic.
 */
export function RiveOrFallback({
  src,
  stateMachine,
  inputs,
  fallback,
  className,
  width,
  height,
}: RiveOrFallbackProps) {
  const reduced = usePrefersReducedMotion();
  const [failed, setFailed] = useState(false);
  // Only attempt the runtime when motion is allowed and the asset hasn't failed.
  const tryAnimate = !reduced && !failed;

  useEffect(() => {
    setFailed(false);
  }, [src]);

  return (
    <span className={className} style={{ position: "relative", display: "inline-flex" }}>
      {fallback}
      {tryAnimate && (
        <Suspense fallback={null}>
          <RiveErrorBoundary onError={() => setFailed(true)}>
            <RiveCanvas
              src={src}
              stateMachine={stateMachine}
              inputs={inputs}
              width={width}
              height={height}
              onLoadError={() => setFailed(true)}
            />
          </RiveErrorBoundary>
        </Suspense>
      )}
    </span>
  );
}

import { Component } from "react";

/** Contains any render/runtime error from the Rive layer so only the fallback
 *  shows — never an error message. */
class RiveErrorBoundary extends Component<
  { children: ReactNode; onError: () => void },
  { crashed: boolean }
> {
  state = { crashed: false };
  static getDerivedStateFromError() {
    return { crashed: true };
  }
  componentDidCatch() {
    this.props.onError();
  }
  render() {
    return this.state.crashed ? null : this.props.children;
  }
}
