import "./backgrounds.css";

import clsx from "clsx";

import { useAmbientMotion } from "./useAmbientMotion";

export interface SealedVaultPanelProps {
  /** sealed shows the padlock with a gentle ring ripple; other values render
   *  the same static lock without the ripple (never "operational"). */
  state?: "sealed" | "static";
  className?: string;
}

/** Decorative sealed-vault motif (padlock in concentric rings). aria-hidden.
 *  The ripple animates only when on screen / visible / motion allowed. */
export function SealedVaultPanel({ state = "sealed", className }: SealedVaultPanelProps) {
  const { ref, active } = useAmbientMotion<HTMLDivElement>();
  const rippling = state === "sealed" && active;
  return (
    <div
      ref={ref}
      className={clsx("bg-layer", "bg-vault", className)}
      aria-hidden="true"
    >
      <svg
        className="bg-vault__svg"
        viewBox="0 0 120 120"
        role="presentation"
        focusable="false"
      >
        <circle className="bg-vault__ring" cx="60" cy="60" r="48" />
        <circle className="bg-vault__ring" cx="60" cy="60" r="38" />
        {rippling && (
          <circle className="bg-vault__ring bg-vault__ring--pulse" cx="60" cy="60" r="30" />
        )}
        <path
          className="bg-vault__shackle"
          d="M48 54 v-8 a12 12 0 0 1 24 0 v8"
          strokeWidth="3"
        />
        <rect
          className="bg-vault__body"
          x="42"
          y="54"
          width="36"
          height="28"
          rx="4"
          strokeWidth="2.5"
        />
      </svg>
    </div>
  );
}
