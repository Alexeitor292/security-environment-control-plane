import { useEffect, useRef, useState } from "react";

/** True when the user has requested reduced motion. Read synchronously on the
 *  first client render (lazy initializer) so the value is correct before any
 *  effect runs — this keeps reduced-motion users from ever mounting (and thus
 *  fetching) the lazy Rive runtime. SSR-safe. */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(
    () =>
      typeof window !== "undefined" &&
      !!window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  return reduced;
}

/**
 * Decorative-motion gate for a layer: returns a ref to attach and whether the
 * layer should currently animate. Animation runs only when the element is on
 * screen AND the document is visible AND reduced-motion is off — satisfying
 * the "pause offscreen / pause when hidden / honor reduced-motion" rules with
 * one hook. Callers add the `bg-paused` class when this returns false.
 */
export function useAmbientMotion<T extends HTMLElement>(): {
  ref: React.RefObject<T>;
  active: boolean;
} {
  const ref = useRef<T>(null);
  const reduced = usePrefersReducedMotion();
  const [onScreen, setOnScreen] = useState(true);
  const [docVisible, setDocVisible] = useState(true);

  useEffect(() => {
    const onVis = () => setDocVisible(!document.hidden);
    onVis();
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(
      (entries) => setOnScreen(entries.some((e) => e.isIntersecting)),
      { rootMargin: "64px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return { ref, active: !reduced && onScreen && docVisible };
}
