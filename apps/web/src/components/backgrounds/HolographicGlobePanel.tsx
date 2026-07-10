import "./backgrounds.css";

import clsx from "clsx";

import { globeVisual, type GlobeVisual } from "../rive/rive-state";
import { useAmbientMotion } from "./useAmbientMotion";

export interface HolographicGlobePanelProps {
  /** Real posture; unknown resolves to decorative "ambient", never "active". */
  state?: string;
  className?: string;
}

const NODES: [number, number][] = [
  [96, 40], [150, 70], [70, 96], [180, 110], [110, 150], [60, 130], [156, 150],
];

/** Decorative wireframe infrastructure globe. Orbits spin only for ambient/
 *  active; sealed/authorized/degraded stay still — no false "live" activity.
 *  aria-hidden; content (title/description) is supplied by React elsewhere. */
export function HolographicGlobePanel({ state, className }: HolographicGlobePanelProps) {
  const visual: GlobeVisual = globeVisual(state ?? "ambient");
  const { ref, active } = useAmbientMotion<HTMLDivElement>();
  return (
    <div
      ref={ref}
      className={clsx("bg-layer", "bg-globe", !active && "bg-paused", className)}
      data-globe={visual}
      aria-hidden="true"
    >
      <svg
        className="bg-globe__svg"
        viewBox="0 0 240 200"
        role="presentation"
        focusable="false"
      >
        <g className="bg-globe__orbits">
          <ellipse className="bg-globe__orbit" cx="120" cy="100" rx="92" ry="34" />
          <ellipse className="bg-globe__orbit" cx="120" cy="100" rx="60" ry="88" />
          <ellipse className="bg-globe__orbit" cx="120" cy="100" rx="88" ry="70" />
        </g>
        <circle className="bg-globe__wire" cx="120" cy="100" r="80" />
        <path
          className="bg-globe__wire"
          d="M40 100 h160 M120 20 v160 M52 60 q68 30 136 0 M52 140 q68 -30 136 0"
        />
        {NODES.map(([x, y], i) => (
          <circle
            key={i}
            className={i === 2 ? "bg-globe__flare" : "bg-globe__node"}
            cx={x}
            cy={y}
            r={i === 2 ? 2.4 : 1.6}
          />
        ))}
        <path
          className="bg-globe__sweep bg-globe__orbit"
          d="M120 20 A80 80 0 0 1 200 100"
          opacity="0.25"
        />
      </svg>
    </div>
  );
}
