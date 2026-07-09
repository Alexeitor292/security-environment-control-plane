import { cva, type VariantProps } from "class-variance-authority";
import clsx from "clsx";
import type { HTMLAttributes, ReactNode } from "react";

const card = cva("ui-card", {
  variants: {
    surface: {
      panel: "ui-card--panel",
      raised: "ui-card--raised",
      well: "ui-card--well",
    },
    glow: {
      none: "",
      accent: "ui-card--glow-accent",
      brand: "ui-card--glow-brand",
      ok: "ui-card--glow-ok",
      danger: "ui-card--glow-danger",
    },
  },
  defaultVariants: { surface: "panel", glow: "none" },
});

export interface CyberCardProps
  extends HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof card> {
  /** Optional card heading, rendered as the panel h3. */
  heading?: ReactNode;
}

export function CyberCard({
  surface,
  glow,
  heading,
  className,
  children,
  ...rest
}: CyberCardProps) {
  return (
    <div className={clsx(card({ surface, glow }), className)} {...rest}>
      {heading !== undefined && <h3 className="ui-card__title">{heading}</h3>}
      {children}
    </div>
  );
}
