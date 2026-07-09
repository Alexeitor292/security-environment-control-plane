import clsx from "clsx";

/** Decorative cyber grid layer: token-driven hairline grid with soft radial
 *  accent glows. Pure CSS, static (no animation — nothing to reduce for
 *  prefers-reduced-motion), hidden from assistive technology. */
export function CyberGridBackground({ className }: { className?: string }) {
  return <div className={clsx("ui-cybergrid", className)} aria-hidden="true" />;
}
