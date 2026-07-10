import clsx from "clsx";
import { Check } from "lucide-react";

export interface StepRailItem {
  id: string;
  label: string;
  /** complete: earlier step, revisitable · current · available: reachable
   *  under the gating predicates · blocked: not reachable yet. */
  state: "complete" | "current" | "available" | "blocked";
  /** Why a blocked step is blocked (rendered for AT and on hover). */
  blockedReason?: string;
}

export interface StepRailProps {
  items: StepRailItem[];
  /** Called only for complete/available steps; blocked steps never navigate. */
  onSelect: (id: string) => void;
  "aria-label"?: string;
}

/** Vertical wizard step rail. Navigation is offered only where the caller's
 *  gating predicates permit it — a blocked step renders as a non-interactive
 *  explanation, never a shortcut. Completed means visited/satisfied, not
 *  approved or active. */
export function StepRail({
  items,
  onSelect,
  "aria-label": ariaLabel,
}: StepRailProps) {
  return (
    <ol className="ui-steprail" aria-label={ariaLabel}>
      {items.map((item, i) => {
        const clickable = item.state === "complete" || item.state === "available";
        const marker =
          item.state === "complete" ? (
            <Check size={12} aria-hidden />
          ) : (
            <span aria-hidden>{i + 1}</span>
          );
        const content = (
          <>
            <span className="ui-steprail__marker">{marker}</span>
            <span className="ui-steprail__label">{item.label}</span>
            {item.state === "complete" && (
              <span className="ui-sr-only"> — completed</span>
            )}
            {item.state === "blocked" && item.blockedReason && (
              <span className="ui-sr-only"> — {item.blockedReason}</span>
            )}
          </>
        );
        return (
          <li
            key={item.id}
            className={clsx("ui-steprail__item", `ui-steprail__item--${item.state}`)}
            aria-current={item.state === "current" ? "step" : undefined}
          >
            {clickable ? (
              <button
                type="button"
                className="ui-steprail__btn"
                onClick={() => onSelect(item.id)}
              >
                {content}
              </button>
            ) : (
              <span
                className="ui-steprail__btn"
                title={item.state === "blocked" ? item.blockedReason : undefined}
              >
                {content}
              </span>
            )}
          </li>
        );
      })}
    </ol>
  );
}
