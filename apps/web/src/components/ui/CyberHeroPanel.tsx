import clsx from "clsx";
import type { ReactNode } from "react";

import { HolographicGlobePanel } from "../backgrounds/HolographicGlobePanel";
import { CyberGridBackground } from "./CyberGridBackground";

export interface CyberHeroPanelProps {
  heading: ReactNode;
  subheading?: ReactNode;
  /** Extra hero content below the headings (posture lines, chips). */
  children?: ReactNode;
  /** Decorative holographic globe posture. Omit for grid-only. Unknown values
   *  resolve to "ambient" (purely decorative — never a live claim). */
  globeState?: string;
  className?: string;
}

/** Hero command panel: glass surface over the cyber grid layer, with an
 *  optional decorative holographic globe. */
export function CyberHeroPanel({
  heading,
  subheading,
  children,
  globeState,
  className,
}: CyberHeroPanelProps) {
  return (
    <section className={clsx("ui-hero", className)}>
      <CyberGridBackground />
      {globeState !== undefined && (
        <HolographicGlobePanel state={globeState} className="ui-hero__globe" />
      )}
      <div className="ui-hero__content">
        <h2 className="ui-hero__heading">{heading}</h2>
        {subheading !== undefined && (
          <div className="ui-hero__subheading">{subheading}</div>
        )}
        {children}
      </div>
    </section>
  );
}
