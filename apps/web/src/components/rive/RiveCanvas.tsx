import { useEffect } from "react";
import { useRive } from "@rive-app/react-webgl2";

// The single module that imports the Rive runtime, so it is the only thing in
// the lazily-loaded chunk. It positions an absolutely-overlaid, decorative
// canvas above the fallback, applies mapped inputs imperatively, pauses when
// the tab is hidden, and reports load failure so the caller reverts to the
// fallback. No business logic lives here.

export interface RiveCanvasProps {
  src: string;
  stateMachine: string;
  inputs?: Record<string, number | boolean>;
  width?: number;
  height?: number;
  onLoadError: () => void;
}

export default function RiveCanvas({
  src,
  stateMachine,
  inputs,
  width,
  height,
  onLoadError,
}: RiveCanvasProps) {
  const { rive, RiveComponent } = useRive({
    src,
    stateMachines: stateMachine,
    autoplay: true,
    onLoadError,
  });

  const inputsKey = JSON.stringify(inputs ?? {});

  // Apply mapped inputs imperatively (values are already sanitized upstream).
  useEffect(() => {
    if (!rive || !inputs) return;
    let smInputs: { name: string; value: unknown }[] = [];
    try {
      smInputs = rive.stateMachineInputs(stateMachine) ?? [];
    } catch {
      return;
    }
    for (const si of smInputs) {
      if (si.name in inputs) {
        si.value = inputs[si.name];
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rive, stateMachine, inputsKey]);

  // Pause when the document is hidden to respect performance rules.
  useEffect(() => {
    if (!rive) return;
    const onVis = () => (document.hidden ? rive.pause() : rive.play());
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, [rive]);

  return (
    <span
      aria-hidden="true"
      style={{
        position: "absolute",
        inset: 0,
        width: width ?? "100%",
        height: height ?? "100%",
        pointerEvents: "none",
      }}
    >
      <RiveComponent style={{ width: "100%", height: "100%" }} />
    </span>
  );
}
