import { ArrowRight } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export interface DecisionCardProps {
  /** Short kind chip: PLAN, LAB, ONBOARDING, DISCOVERY, DEPLOYMENT. */
  chip: string;
  title: ReactNode;
  meta?: ReactNode;
  /** Route of the surface where the decision is actually made. The card only
   *  navigates — it never approves anything itself. */
  href: string;
}

export function DecisionCard({ chip, title, meta, href }: DecisionCardProps) {
  return (
    <Link to={href} className="ui-decision">
      <span className="ui-decision__chip">{chip}</span>
      <span className="ui-decision__body">
        <span className="ui-decision__title">{title}</span>
        {meta !== undefined && <span className="ui-decision__meta">{meta}</span>}
      </span>
      <ArrowRight className="ui-decision__arrow" size={14} aria-hidden />
    </Link>
  );
}
