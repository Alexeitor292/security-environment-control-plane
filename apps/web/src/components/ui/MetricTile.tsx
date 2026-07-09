import clsx from "clsx";
import type { ReactNode } from "react";

export interface MetricTileProps {
  label: string;
  /** The headline value. Pass "—" (with a truthful detail line) when the
   *  source is unavailable — never a fabricated number. */
  value: ReactNode;
  detail?: ReactNode;
  tone?: "default" | "ok" | "warn" | "danger";
}

export function MetricTile({
  label,
  value,
  detail,
  tone = "default",
}: MetricTileProps) {
  return (
    <div className={clsx("ui-metric", tone !== "default" && `ui-metric--${tone}`)}>
      <div className="ui-metric__label">{label}</div>
      <div className="ui-metric__value">{value}</div>
      {detail !== undefined && <div className="ui-metric__detail">{detail}</div>}
    </div>
  );
}
