import clsx from "clsx";
import type { ReactNode, SVGProps } from "react";

export interface SecpIconProps extends Omit<SVGProps<SVGSVGElement>, "children"> {
  size?: number;
  /** Accessible title. When set, the icon is exposed as img with this label;
   *  otherwise it is decorative (aria-hidden). */
  title?: string;
  className?: string;
}

/**
 * Base wrapper for the SECP custom icon set. Shared stroke language: 1.5
 * stroke, round joins, currentColor (recolors via CSS), 24-unit viewBox.
 * Icons remain recognizable without glow and honor forced-colors (currentColor
 * maps to system text). Decorative by default; pass `title` for a labeled icon.
 */
export function SecpIcon({
  size = 18,
  title,
  className,
  children,
  ...rest
}: SecpIconProps & { children: ReactNode }) {
  const decorative = !title;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={clsx("secp-icon", className)}
      role={decorative ? undefined : "img"}
      aria-hidden={decorative ? true : undefined}
      aria-label={decorative ? undefined : title}
      focusable="false"
      {...rest}
    >
      {title ? <title>{title}</title> : null}
      {children}
    </svg>
  );
}
