import clsx from "clsx";
import { Info, ShieldAlert, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

export interface SafetyNoticeProps {
  /** ARIA semantics: "note" for static disclosures, "status" for polite live
   *  updates (queued/in-flight notices), "alert" for assertive failures. */
  role?: "note" | "status" | "alert";
  tone?: "info" | "warn" | "danger";
  children: ReactNode;
}

const ICON = { info: Info, warn: TriangleAlert, danger: ShieldAlert } as const;

/**
 * Closed-copy notice banner (unifies the .dev-banner / milestone-banner
 * dialects). Render the page's EXPORTED safety-copy constants as children —
 * never re-type safety language in JSX; the logic-module constants are the
 * tested source of truth.
 */
export function SafetyNotice({
  role = "note",
  tone = "warn",
  children,
}: SafetyNoticeProps) {
  const IconComponent = ICON[tone];
  return (
    <div className={clsx("ui-notice", `ui-notice--${tone}`)} role={role}>
      <IconComponent className="ui-notice__icon" size={14} aria-hidden />
      <div>{children}</div>
    </div>
  );
}
