import clsx from "clsx";

import { truncateHash } from "./hash-chip";

export interface HashChipProps {
  /** Full hash / opaque id. The full value stays available via title. */
  value: string;
  digits?: number;
  className?: string;
}

/** Truncated hash/id chip — replaces the ad-hoc slice() expressions in page
 *  JSX with one tested truncation rule. */
export function HashChip({ value, digits, className }: HashChipProps) {
  return (
    <span className={clsx("ui-hashchip", "mono", className)} title={value}>
      {truncateHash(value, { digits })}
    </span>
  );
}
