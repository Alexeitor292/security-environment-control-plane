import "./ui.css";

import clsx from "clsx";

import {
  resolveStatusTone,
  statusDisplayLabel,
  type StatusDomain,
} from "./status-tone";

export interface StatusBadgeProps {
  state: string;
  /** Disambiguates statuses whose key exists in several unions with different
   *  meanings (e.g. plan "approved" is ok; lifecycle "approved" is accent).
   *  Without it, the legacy resolution order applies. */
  domain?: StatusDomain;
}

/** Unified status badge. Every known status union has an explicit tone map in
 *  status-tone.ts; unknown statuses render in the distinct "unknown" style —
 *  never silently as "pending". */
export function StatusBadge({ state, domain }: StatusBadgeProps) {
  const { tone, known } = resolveStatusTone(state, domain);
  return (
    <span
      className={clsx("badge", tone)}
      title={known ? undefined : "Unknown status — no tone mapping registered"}
    >
      {statusDisplayLabel(state)}
    </span>
  );
}
