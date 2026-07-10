import clsx from "clsx";
import type { ReactNode } from "react";

/** One gated link in the access chain. Each link is gated separately; no
 *  earlier link activates a later one. */
export interface AccessChainLink {
  id: string;
  title: string;
  /** complete: fully satisfied · active: satisfied but not yet operational
   *  or time-bound (e.g. approved-not-activated, expiring authorization) ·
   *  pending: not yet established · sealed: fail-closed by contract/default. */
  state: "complete" | "active" | "pending" | "sealed";
  /** Short status line (e.g. "v2 · approved · expires in 26m"). */
  status: string;
  /** Supporting body copy — pass exported safety constants verbatim. */
  body?: ReactNode;
}

export interface AccessChainProps {
  links: AccessChainLink[];
  /** Footer statement (e.g. that approval never activates live access). */
  footer?: ReactNode;
}

/** Vertical numbered chain making "configured ≠ authorized ≠ ready"
 *  physically visible. Purely presentational: states must be derived from
 *  real backend records by the caller. */
export function AccessChain({ links, footer }: AccessChainProps) {
  return (
    <div className="ui-chain">
      <ol className="ui-chain__list">
        {links.map((link, i) => (
          <li
            className={clsx("ui-chain__link", `ui-chain__link--${link.state}`)}
            key={link.id}
          >
            <span className="ui-chain__node" aria-hidden>
              {i + 1}
            </span>
            <div className="ui-chain__content">
              <div className="ui-chain__title">{link.title}</div>
              <div className="ui-chain__status">{link.status}</div>
              {link.body !== undefined && (
                <div className="ui-chain__body">{link.body}</div>
              )}
            </div>
          </li>
        ))}
      </ol>
      {footer !== undefined && <div className="ui-chain__footer">{footer}</div>}
    </div>
  );
}
