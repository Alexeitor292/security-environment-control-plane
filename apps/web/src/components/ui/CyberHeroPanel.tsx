import clsx from "clsx";
import type { ReactNode } from "react";

import { CyberGridBackground } from "./CyberGridBackground";

export interface CyberHeroPanelProps {
  heading: ReactNode;
  subheading?: ReactNode;
  /** Extra hero content below the headings (posture lines, chips). */
  children?: ReactNode;
  className?: string;
}

/** Hero command panel: glass surface over the cyber grid layer. */
export function CyberHeroPanel({
  heading,
  subheading,
  children,
  className,
}: CyberHeroPanelProps) {
  return (
    <section className={clsx("ui-hero", className)}>
      <CyberGridBackground />
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
