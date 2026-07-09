import type { ReactNode } from "react";

export interface EmptyStateProps {
  title: string;
  /** Supporting copy. For safety-relevant empty states, pass the exported
   *  logic-module constants rather than new inline strings. */
  children?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({ title, children, action }: EmptyStateProps) {
  return (
    <div className="ui-empty">
      <div className="ui-empty__title">{title}</div>
      {children !== undefined && (
        <div className="ui-empty__body">{children}</div>
      )}
      {action !== undefined && <div className="ui-empty__action">{action}</div>}
    </div>
  );
}
