import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export interface ActionTileProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  href?: string;
  /** Truthful reason when the action's surface does not exist yet; renders
   *  the tile visibly disabled with the explanation. */
  unavailableReason?: string;
}

export function ActionTile({
  icon,
  title,
  description,
  href,
  unavailableReason,
}: ActionTileProps) {
  const body = (
    <>
      {icon !== undefined && (
        <span className="ui-action__icon" aria-hidden>
          {icon}
        </span>
      )}
      <span className="ui-action__body">
        <span className="ui-action__title">{title}</span>
        {description !== undefined && (
          <span className="ui-action__desc">{description}</span>
        )}
      </span>
    </>
  );
  if (!href) {
    return (
      <span className="ui-action ui-action--unavailable" title={unavailableReason}>
        {body}
        {unavailableReason && (
          <span className="ui-sr-only"> — {unavailableReason}</span>
        )}
      </span>
    );
  }
  return (
    <Link to={href} className="ui-action">
      {body}
    </Link>
  );
}
