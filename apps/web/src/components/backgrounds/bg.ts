// Shared types + helpers for the cyber background system. Pure, tested.

export type BackgroundIntensity = "subtle" | "standard" | "hero";

export interface BackgroundBaseProps {
  intensity?: BackgroundIntensity;
  className?: string;
}

/** Resolve the intensity to a stable class suffix. Unknown values fall back
 *  to "subtle" — a background must never accidentally render at hero cost. */
export function intensityClass(intensity: BackgroundIntensity | undefined): string {
  switch (intensity) {
    case "hero":
      return "is-hero";
    case "standard":
      return "is-standard";
    case "subtle":
    default:
      return "is-subtle";
  }
}
