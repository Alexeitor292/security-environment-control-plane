export interface SecpMarkProps {
  size?: number;
}

/** SECP logo mark: hex/cube outline in the brand purple→cyan ramp. Pure SVG,
 *  colors driven by the design tokens via CSS custom properties. */
export function SecpMark({ size = 28 }: SecpMarkProps) {
  return (
    <svg
      className="shell-mark"
      width={size}
      height={size}
      viewBox="0 0 32 32"
      role="img"
      aria-label="SECP"
    >
      <defs>
        <linearGradient id="secp-mark-ramp" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="var(--accent-mark)" />
          <stop offset="100%" stopColor="var(--accent-brand)" />
        </linearGradient>
      </defs>
      {/* Outer hexagon */}
      <path
        d="M16 2.5 27.5 9v14L16 29.5 4.5 23V9L16 2.5Z"
        fill="none"
        stroke="url(#secp-mark-ramp)"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      {/* Inner cube: top face edges + vertical seam, reads as a sealed block */}
      <path
        d="M16 9.5 22 13v6.5L16 23l-6-3.5V13l6-3.5Z"
        fill="color-mix(in srgb, var(--accent-mark) 22%, transparent)"
        stroke="var(--accent-brand)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M10 13l6 3.5 6-3.5M16 16.5V23"
        fill="none"
        stroke="var(--accent-brand)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
    </svg>
  );
}
