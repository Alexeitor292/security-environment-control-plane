import { cva, type VariantProps } from "class-variance-authority";
import clsx from "clsx";
import type { ButtonHTMLAttributes } from "react";

const button = cva("ui-btn", {
  variants: {
    variant: {
      primary: "ui-btn--primary",
      secondary: "ui-btn--secondary",
      outline: "ui-btn--outline",
      ghost: "ui-btn--ghost",
      ok: "ui-btn--ok",
      danger: "ui-btn--danger",
    },
    size: {
      sm: "ui-btn--sm",
      md: "",
    },
  },
  defaultVariants: { variant: "primary", size: "md" },
});

export interface CyberButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

export function CyberButton({
  variant,
  size,
  className,
  type,
  ...rest
}: CyberButtonProps) {
  return (
    <button
      type={type ?? "button"}
      className={clsx(button({ variant, size }), className)}
      {...rest}
    />
  );
}
