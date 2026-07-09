import clsx from "clsx";

export interface SkeletonProps {
  lines?: number;
  className?: string;
}

/** Content-shaped loading placeholder: one gentle opacity pulse driven by the
 *  --motion-skeleton-pulse token (static under prefers-reduced-motion). Use
 *  only for structural first loads — never over cached data (DataPanel
 *  enforces this). */
export function Skeleton({ lines = 3, className }: SkeletonProps) {
  return (
    <div className={clsx("ui-skeleton", className)} aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="ui-skeleton__line" />
      ))}
    </div>
  );
}
