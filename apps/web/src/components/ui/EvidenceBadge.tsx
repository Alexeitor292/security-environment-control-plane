import clsx from "clsx";
import { CheckCircle2, CircleDashed, HelpCircle, XCircle } from "lucide-react";
import type { ReactNode } from "react";

import { StatusBadge } from "./StatusBadge";

export interface EvidenceBadgeProps {
  /** Check name (e.g. no_route_to_protected) or human title. */
  title: string;
  /** Evidence verdict: pass | fail | unverifiable (closed backend values). */
  status: string;
  /** Explanation body — pass the backend's recorded detail verbatim. */
  detail?: ReactNode;
}

const ICON: Record<string, typeof CheckCircle2> = {
  pass: CheckCircle2,
  fail: XCircle,
  unverifiable: CircleDashed,
};

/** One evidence finding: verdict icon, check title, closed-status badge, and
 *  the recorded explanation. */
export function EvidenceBadge({ title, status, detail }: EvidenceBadgeProps) {
  // Own-property guard: a prototype-key status must never resolve an icon.
  const known = Object.prototype.hasOwnProperty.call(ICON, status);
  const Icon = known ? ICON[status] : HelpCircle;
  return (
    <div className={clsx("ui-evidence", `ui-evidence--${known ? status : "other"}`)}>
      <Icon className="ui-evidence__icon" size={15} aria-hidden />
      <div className="ui-evidence__body">
        <div className="ui-evidence__head">
          <span className="ui-evidence__title mono">{title}</span>
          <StatusBadge state={status} domain="evidence" />
        </div>
        {detail !== undefined && (
          <div className="ui-evidence__detail">{detail}</div>
        )}
      </div>
    </div>
  );
}
