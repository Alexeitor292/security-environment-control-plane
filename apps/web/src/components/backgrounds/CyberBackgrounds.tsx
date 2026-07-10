import "./backgrounds.css";

import clsx from "clsx";

import { intensityClass, type BackgroundBaseProps } from "./bg";
import { useAmbientMotion } from "./useAmbientMotion";

/** Static (non-animated) CSS background layer. Decorative: aria-hidden and
 *  pointer-events:none via .bg-layer. */
function StaticLayer({
  variant,
  intensity,
  className,
}: BackgroundBaseProps & { variant: string }) {
  return (
    <div
      className={clsx("bg-layer", variant, intensityClass(intensity), className)}
      aria-hidden="true"
    />
  );
}

/** Animated CSS layer that pauses offscreen / when the document is hidden. */
function AmbientLayer({
  variant,
  intensity,
  className,
}: BackgroundBaseProps & { variant: string }) {
  const { ref, active } = useAmbientMotion<HTMLDivElement>();
  return (
    <div
      ref={ref}
      className={clsx(
        "bg-layer",
        variant,
        intensityClass(intensity),
        !active && "bg-paused",
        className,
      )}
      aria-hidden="true"
    />
  );
}

export function CyberGridBackground(props: BackgroundBaseProps) {
  return <StaticLayer variant="bg-grid" {...props} />;
}

export function BlueprintMeshBackground(props: BackgroundBaseProps) {
  return <StaticLayer variant="bg-blueprint" {...props} />;
}

export function ProviderMeshBackground(props: BackgroundBaseProps) {
  return <StaticLayer variant="bg-provider" {...props} />;
}

export function ThreatConstellationBackground(props: BackgroundBaseProps) {
  return <StaticLayer variant="bg-constellation" {...props} />;
}

export function TopologyGridBackground(props: BackgroundBaseProps) {
  return <StaticLayer variant="bg-topogrid" {...props} />;
}

export function CyberNoiseOverlay(props: BackgroundBaseProps) {
  return <StaticLayer variant="bg-noise" {...props} />;
}

export function PacketFlowBackground(props: BackgroundBaseProps) {
  return <AmbientLayer variant="bg-packet" {...props} />;
}

export function AmbientScanLines(props: BackgroundBaseProps) {
  return <AmbientLayer variant="bg-scanlines" {...props} />;
}
