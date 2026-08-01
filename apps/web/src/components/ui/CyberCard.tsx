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
  /** Optional card heading, rendered as the panel title. */
  heading?: ReactNode;
  /**
   * Heading level for `heading`. Defaults to 3, which is what every card in the app has always
   * rendered, so this is additive and relabels nothing.
   *
   * It exists because a card sitting directly under a page `h1` produces an h1 -> h3 skip, which
   * an accessibility scan reports and a screen-reader user navigating by heading feels as a
   * missing level. A page that owns its outline can pass 2; one that nests cards inside a section
   * heading keeps the default.
   */
  headingLevel?: 2 | 3 | 4;
}

export function CyberCard({
  surface,
  glow,
  heading,
  headingLevel = 3,
  className,
  children,
  ...rest
}: CyberCardProps) {
  const Heading = `h${headingLevel}` as const;
  return (
    <div className={clsx(card({ surface, glow }), className)} {...rest}>
      {heading !== undefined && <Heading className="ui-card__title">{heading}</Heading>}
      {children}
    </div>
  );
}
